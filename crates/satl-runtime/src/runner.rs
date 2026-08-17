// SPDX-License-Identifier: BSD-2-Clause
//! Injectable process execution for the external-command wrappers in this
//! crate (`ocijail`, `devfs`, `mount`/`umount`, `sysctl`).
//!
//! Same design as `satl-storage::zfs` (CLAUDE.md "External command wrappers"):
//! a local [`CommandRunner`] trait so command construction and output parsing
//! are unit-testable without privileges, plus a rendered-argv helper so every
//! error can carry the exact command line that ran. Deliberately duplicated
//! rather than shared: a common wrapper crate is a later refactor.
//!
//! On top of the zfs pattern this adds [`CommandRunner::run_with_stdio`]:
//! `ocijail create`/`exec` hand their own fds 0/1/2 to the container process
//! verbatim (docs/ocijail.md §3), so the runner must be able to spawn with
//! caller-supplied [`std::fs::File`] handles instead of capturing pipes.

use std::fmt::Write as _;
use std::fs::File;
use std::future::Future;
use std::io;
use std::path::Path;
use std::process::Stdio;

/// Captured result of running an external command to completion.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Exit code; `None` when the process was terminated by a signal.
    pub exit_code: Option<i32>,
    /// Raw stdout, lossily decoded as UTF-8. Empty when stdio was redirected.
    pub stdout: String,
    /// Raw stderr, lossily decoded as UTF-8. Empty when stdio was redirected.
    pub stderr: String,
}

impl CommandOutput {
    pub(crate) fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// One standard stream for a spawned container/exec process.
///
/// The handle is passed to the child verbatim (dup2 semantics): for
/// `ocijail create` this is how satld owns the container's log sinks for the
/// container's whole life (docs/ocijail.md §3).
#[derive(Debug)]
pub enum StdioSink {
    /// `/dev/null`.
    Null,
    /// A caller-opened file (log sink, pipe end wrapped as a `File`, ...).
    /// Open stderr sinks **read**+write: on a failed `create`/`exec` the
    /// wrapper reads the runtime's error text back out of the sink to embed
    /// it in the typed error (see `ocijail` module docs).
    File(File),
}

impl StdioSink {
    fn into_stdio(self) -> Stdio {
        match self {
            StdioSink::Null => Stdio::null(),
            StdioSink::File(file) => Stdio::from(file),
        }
    }
}

/// The three standard streams handed to `ocijail create`/`exec` — and thereby
/// to the container process itself (fd inheritance, docs/ocijail.md §3).
#[derive(Debug)]
pub struct CreateStdio {
    /// Container stdin; usually [`StdioSink::Null`].
    pub stdin: StdioSink,
    /// Container stdout; the per-task log sink.
    pub stdout: StdioSink,
    /// Container stderr; the per-task log sink. On a failed `create`, runtime
    /// error text lands *here*, not on a capturable pipe (docs/ocijail.md §3).
    pub stderr: StdioSink,
}

impl CreateStdio {
    /// All three streams to `/dev/null`.
    #[must_use]
    pub fn null() -> Self {
        Self {
            stdin: StdioSink::Null,
            stdout: StdioSink::Null,
            stderr: StdioSink::Null,
        }
    }
}

/// Executes external commands. The real implementation is [`SystemRunner`];
/// tests inject a recording mock so no privileges (or binaries) are needed to
/// exercise wrapper logic.
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args` to completion, capturing stdout and stderr.
    ///
    /// Capture uses pipes, so this must only run commands that do not leave
    /// background children sharing their stdio — an orphan holding the pipe
    /// write end would stall the drain-to-EOF forever. All plain ocijail
    /// subcommands (`start`/`state`/`kill`/`delete`/`list`/`features`)
    /// qualify; `create`/`exec` do not and go through
    /// [`CommandRunner::run_with_stdio`].
    ///
    /// # Errors
    ///
    /// [`io::Error`] when the process could not be spawned at all.
    fn run(
        &self,
        program: &Path,
        args: &[String],
    ) -> impl Future<Output = io::Result<CommandOutput>> + Send;

    /// Run `program` with `args`, wiring the child's fds 0/1/2 to `stdio`
    /// instead of capturing them. The returned [`CommandOutput`] therefore has
    /// empty `stdout`/`stderr`.
    ///
    /// # Errors
    ///
    /// [`io::Error`] when the process could not be spawned at all.
    fn run_with_stdio(
        &self,
        program: &Path,
        args: &[String],
        stdio: CreateStdio,
    ) -> impl Future<Output = io::Result<CommandOutput>> + Send;
}

/// [`CommandRunner`] that actually executes processes via [`tokio::process`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    async fn run(&self, program: &Path, args: &[String]) -> io::Result<CommandOutput> {
        let output = tokio::process::Command::new(program)
            .args(args)
            .output()
            .await?;
        Ok(CommandOutput {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    async fn run_with_stdio(
        &self,
        program: &Path,
        args: &[String],
        stdio: CreateStdio,
    ) -> io::Result<CommandOutput> {
        // NOT `.output()`: tokio's `output()` unconditionally replaces
        // stdout/stderr with pipes (tokio 1.53 `process/mod.rs`, unlike
        // `std`), which would (a) silently discard the caller's sinks and
        // (b) deadlock on `ocijail create` — the forked container process
        // holds the pipe write ends for its whole life, so the drain-to-EOF
        // in `output()` never finishes. `spawn()` + `wait()` honors the
        // configured stdio and only awaits the direct child's exit.
        let mut child = match tokio::process::Command::new(program)
            .args(args)
            .stdin(stdio.stdin.into_stdio())
            .stdout(stdio.stdout.into_stdio())
            .stderr(stdio.stderr.into_stdio())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                satl_metrics::record_command_failure_for(program);
                return Err(error);
            }
        };
        let status = child.wait().await?;
        let output = CommandOutput {
            exit_code: status.code(),
            stdout: String::new(),
            stderr: String::new(),
        };
        if !output.success() {
            satl_metrics::record_command_failure_for(program);
        }
        Ok(output)
    }
}

/// Render a program + args as a single shell-like command line for error
/// messages and logs. Arguments containing whitespace are quoted.
pub(crate) fn render_argv(program: &Path, args: &[String]) -> String {
    let mut line = program.display().to_string();
    for arg in args {
        line.push(' ');
        if arg.is_empty() || arg.chars().any(char::is_whitespace) {
            // Infallible: fmt::Write on String never errors.
            let _ = write!(line, "{arg:?}");
        } else {
            line.push_str(arg);
        }
    }
    line
}

// ---------------------------------------------------------------------------
// Test support: a CommandRunner that records argv and replays canned outputs.
// ---------------------------------------------------------------------------

/// Mock [`CommandRunner`] for unit tests: records every rendered argv and
/// pops pre-loaded responses in FIFO order. `run_with_stdio` can additionally
/// write canned bytes into the stderr sink to simulate the create-child
/// validation errors that land on the container's inherited fd 2.
#[cfg(test)]
pub(crate) struct MockRunner {
    responses: std::sync::Mutex<std::collections::VecDeque<MockResponse>>,
    calls: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
pub(crate) struct MockResponse {
    result: io::Result<CommandOutput>,
    /// Bytes `run_with_stdio` writes into the `stderr` sink before returning.
    stderr_sink_write: Option<String>,
}

#[cfg(test)]
impl MockRunner {
    pub(crate) fn new() -> Self {
        Self {
            responses: std::sync::Mutex::new(std::collections::VecDeque::new()),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn push_output(&self, exit_code: i32, stdout: &str, stderr: &str) {
        self.responses.lock().unwrap().push_back(MockResponse {
            result: Ok(CommandOutput {
                exit_code: Some(exit_code),
                stdout: stdout.to_owned(),
                stderr: stderr.to_owned(),
            }),
            stderr_sink_write: None,
        });
    }

    /// Response for a `run_with_stdio` call that also writes `sink_text` into
    /// the caller's stderr sink (as the ocijail create child would).
    pub(crate) fn push_stdio_output(&self, exit_code: i32, sink_text: &str) {
        self.responses.lock().unwrap().push_back(MockResponse {
            result: Ok(CommandOutput {
                exit_code: Some(exit_code),
                stdout: String::new(),
                stderr: String::new(),
            }),
            stderr_sink_write: Some(sink_text.to_owned()),
        });
    }

    pub(crate) fn push_spawn_error(&self, kind: io::ErrorKind, message: &str) {
        self.responses.lock().unwrap().push_back(MockResponse {
            result: Err(io::Error::new(kind, message.to_owned())),
            stderr_sink_write: None,
        });
    }

    /// Rendered command lines of every call made so far (both run flavors).
    pub(crate) fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn pop(&self, program: &Path, args: &[String]) -> MockResponse {
        self.calls.lock().unwrap().push(render_argv(program, args));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("MockRunner: unexpected call {}", render_argv(program, args)))
    }
}

#[cfg(test)]
impl CommandRunner for &MockRunner {
    async fn run(&self, program: &Path, args: &[String]) -> io::Result<CommandOutput> {
        self.pop(program, args).result
    }

    async fn run_with_stdio(
        &self,
        program: &Path,
        args: &[String],
        stdio: CreateStdio,
    ) -> io::Result<CommandOutput> {
        let response = self.pop(program, args);
        if let Some(text) = response.stderr_sink_write
            && let StdioSink::File(mut file) = stdio.stderr
        {
            use std::io::Write as _;
            file.write_all(text.as_bytes()).unwrap();
            file.flush().unwrap();
        }
        response.result
    }
}
