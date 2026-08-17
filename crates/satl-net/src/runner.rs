// SPDX-License-Identifier: BSD-2-Clause
//! Injectable process execution for the external command wrappers.
//!
//! Same pattern as `satl-storage::zfs` (CLAUDE.md, "External command
//! wrappers"): business logic never touches `Command::new` directly — every
//! wrapper ([`crate::ifconfig::Ifconfig`], [`crate::route::Route`],
//! [`crate::pf::PfCtl`]) is generic over a [`CommandRunner`] so argv
//! construction and output parsing are unit-testable without privileges.
//!
//! This trait is local to `satl-net` (crates do not share runner traits) and
//! differs from the storage one in a single way: it supports feeding the
//! child's stdin, which `pfctl -f -` needs.

use std::fmt;
use std::future::Future;
use std::io;
use std::path::Path;
use std::process::Stdio;

/// Captured result of running an external command to completion.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Exit code; `None` when the process was terminated by a signal.
    pub exit_code: Option<i32>,
    /// Raw stdout, lossily decoded as UTF-8.
    pub stdout: String,
    /// Raw stderr, lossily decoded as UTF-8.
    pub stderr: String,
}

impl CommandOutput {
    /// Whether the process exited with code 0.
    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Executes external commands. The real implementation is [`SystemRunner`];
/// tests inject a recording mock so no privileges (or FreeBSD binaries) are
/// needed to exercise wrapper logic.
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args` to completion, optionally writing `stdin`
    /// to the child's standard input, capturing stdout and stderr.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] when the process could not be spawned or fed
    /// at all (binary missing, permission denied, broken pipe, ...).
    fn run(
        &self,
        program: &Path,
        args: &[String],
        stdin: Option<&str>,
    ) -> impl Future<Output = io::Result<CommandOutput>> + Send;
}

/// [`CommandRunner`] that actually executes processes via [`tokio::process`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    async fn run(
        &self,
        program: &Path,
        args: &[String],
        stdin: Option<&str>,
    ) -> io::Result<CommandOutput> {
        let mut command = tokio::process::Command::new(program);
        command
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                satl_metrics::record_command_failure_for(program);
                return Err(error);
            }
        };
        if let Some(input) = stdin {
            use tokio::io::AsyncWriteExt as _;
            let mut handle = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("child stdin pipe missing despite Stdio::piped"))?;
            handle.write_all(input.as_bytes()).await?;
            // Drop closes the pipe so the child sees EOF.
            drop(handle);
        }
        let output = child.wait_with_output().await?;
        let output = CommandOutput {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        };
        if !output.success() {
            satl_metrics::record_command_failure_for(program);
        }
        Ok(output)
    }
}

/// A command that ran but did not succeed — the payload every wrapper error
/// carries so an operator sees exactly what was attempted and what it said.
#[derive(Debug, Clone)]
pub struct Failure {
    /// Full rendered command line.
    pub argv: String,
    /// Exit code; `None` when killed by a signal.
    pub exit_code: Option<i32>,
    /// Raw stderr from the command.
    pub stderr: String,
}

impl Failure {
    pub(crate) fn new(argv: String, output: &CommandOutput) -> Self {
        Self {
            argv,
            exit_code: output.exit_code,
            stderr: output.stderr.clone(),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{argv}` failed with {status}; stderr: {stderr}",
            argv = self.argv,
            status = render_exit(self.exit_code),
            stderr = render_raw(&self.stderr),
        )
    }
}

impl std::error::Error for Failure {}

pub(crate) fn render_exit(exit_code: Option<i32>) -> String {
    match exit_code {
        Some(code) => format!("exit code {code}"),
        None => "termination by signal".to_owned(),
    }
}

pub(crate) fn render_raw(raw: &str) -> String {
    let trimmed = raw.trim_end();
    if trimmed.is_empty() {
        "(empty)".to_owned()
    } else {
        format!("{trimmed:?}")
    }
}

/// Render a program + args as a single shell-like command line for error
/// messages and logs. Arguments containing whitespace are quoted.
pub(crate) fn render_argv(program: &Path, args: &[String]) -> String {
    use std::fmt::Write as _;
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

/// Mock [`CommandRunner`] for unit tests: records every rendered argv (plus
/// any stdin payload) and pops pre-loaded responses in FIFO order.
#[cfg(test)]
pub(crate) struct MockRunner {
    responses: std::sync::Mutex<std::collections::VecDeque<io::Result<CommandOutput>>>,
    calls: std::sync::Mutex<Vec<String>>,
    stdins: std::sync::Mutex<Vec<Option<String>>>,
}

#[cfg(test)]
impl MockRunner {
    pub(crate) fn new() -> Self {
        Self {
            responses: std::sync::Mutex::new(std::collections::VecDeque::new()),
            calls: std::sync::Mutex::new(Vec::new()),
            stdins: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn push_output(&self, exit_code: i32, stdout: &str, stderr: &str) {
        self.responses.lock().unwrap().push_back(Ok(CommandOutput {
            exit_code: Some(exit_code),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
        }));
    }

    pub(crate) fn push_ok(&self) {
        self.push_output(0, "", "");
    }

    pub(crate) fn push_spawn_error(&self, kind: io::ErrorKind, message: &str) {
        self.responses
            .lock()
            .unwrap()
            .push_back(Err(io::Error::new(kind, message.to_owned())));
    }

    /// Rendered command lines of every call made so far.
    pub(crate) fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    /// Stdin payloads passed to each call (index-aligned with [`Self::calls`]).
    pub(crate) fn stdins(&self) -> Vec<Option<String>> {
        self.stdins.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl CommandRunner for &MockRunner {
    async fn run(
        &self,
        program: &Path,
        args: &[String],
        stdin: Option<&str>,
    ) -> io::Result<CommandOutput> {
        self.calls.lock().unwrap().push(render_argv(program, args));
        self.stdins.lock().unwrap().push(stdin.map(str::to_owned));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("MockRunner: unexpected call {}", render_argv(program, args)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_rendering_quotes_whitespace_and_empty() {
        let argv = render_argv(
            Path::new("/sbin/ifconfig"),
            &[
                "epair0a".to_owned(),
                "description".to_owned(),
                "satl network".to_owned(),
                String::new(),
            ],
        );
        assert_eq!(
            argv,
            "/sbin/ifconfig epair0a description \"satl network\" \"\""
        );
    }

    #[test]
    fn failure_display_carries_argv_status_stderr() {
        let failure = Failure {
            argv: "/sbin/ifconfig satlnt-nope destroy".to_owned(),
            exit_code: Some(1),
            stderr: "ifconfig: interface satlnt-nope does not exist\n".to_owned(),
        };
        let text = failure.to_string();
        assert!(
            text.contains("/sbin/ifconfig satlnt-nope destroy"),
            "{text}"
        );
        assert!(text.contains("exit code 1"), "{text}");
        assert!(text.contains("does not exist"), "{text}");
    }

    #[test]
    fn failure_display_signal_and_empty_stderr() {
        let failure = Failure {
            argv: "/sbin/route -j 7 add default 10.88.0.1".to_owned(),
            exit_code: None,
            stderr: String::new(),
        };
        let text = failure.to_string();
        assert!(text.contains("termination by signal"), "{text}");
        assert!(text.contains("(empty)"), "{text}");
    }

    #[tokio::test]
    async fn system_runner_pipes_stdin_and_captures_output() {
        // `cat` is present on FreeBSD base; echoes stdin back on stdout.
        let output = SystemRunner
            .run(Path::new("/bin/cat"), &[], Some("pass in on lo0 all\n"))
            .await
            .unwrap();
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout, "pass in on lo0 all\n");
        assert_eq!(output.stderr, "");
    }

    #[tokio::test]
    async fn system_runner_spawn_error_for_missing_binary() {
        let err = SystemRunner
            .run(Path::new("/nonexistent/satlnt-binary"), &[], None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
