// SPDX-License-Identifier: BSD-2-Clause
//! Injectable process execution for the data plane's external command
//! wrappers.
//!
//! Same seam as `satl-net::runner` and `satl-storage::zfs` (CLAUDE.md,
//! "External command wrappers"): business logic never touches
//! `Command::new` directly — [`crate::vxlan::Vxlan`] and [`crate::arp::Arp`]
//! are generic over a [`CommandRunner`] so argv construction and output
//! parsing are unit-testable without privileges or a FreeBSD host.
//!
//! The trait is local to this crate, as it is in every other crate that has
//! one: sharing it would make `satl-overlay` depend on `satl-net` for a
//! twenty-line abstraction, and the two differ (that one feeds stdin for
//! `pfctl -f -`; nothing here needs stdin, so the parameter is absent).
//!
//! ## Why exit status is never enough here
//!
//! Both binaries this crate drives report success while having failed:
//!
//! - `ifconfig <vxlan> up` exits 0 for an interface the driver refused to
//!   initialize (`docs/vxlan.md` §2 point 5) — only `RUNNING` in the flag
//!   word says otherwise;
//! - `arp -s <off-link ip> <mac>` exits **0** and writes
//!   `arp: set: cannot locate <ip>` to stderr (measured on FreeBSD 15.1,
//!   `tests/fixtures/arp_set_cannot_locate.txt`; `docs/vxlan.md` §4 notes the
//!   message but not that the exit status is 0).
//!
//! So every wrapper here inspects stdout/stderr as well as the exit code, and
//! [`CommandOutput`] keeps all three.

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
    /// Run `program` with `args` to completion, capturing stdout and stderr.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] when the process could not be spawned at all
    /// (binary missing, permission denied, ...).
    fn run(
        &self,
        program: &Path,
        args: &[String],
    ) -> impl Future<Output = io::Result<CommandOutput>> + Send;
}

/// Executes a command that is **fed a request on stdin**, which
/// [`CommandRunner`] deliberately does not do (`stdin` is `/dev/null` there).
///
/// The one caller is [`crate::arphelper::ArpHelper`]: it re-executes `satld`
/// with a hidden subcommand and hands the child a whole batch of ARP work down
/// a pipe. Kept as its own trait rather than folded into [`CommandRunner`] so
/// none of the existing wrappers grow a parameter they have no use for.
pub trait PipedRunner: Send + Sync {
    /// Run `program` with `args`, write `stdin` to its standard input, close it,
    /// and capture the output.
    ///
    /// `timeout` is not optional and not advisory: the child holds a jail
    /// attachment, so a hung child is a leaked process. Implementations must
    /// kill it and report [`io::ErrorKind::TimedOut`].
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] when the process could not be spawned, could
    /// not be written to, or exceeded `timeout`.
    fn run_piped(
        &self,
        program: &Path,
        args: &[String],
        stdin: String,
        timeout: std::time::Duration,
    ) -> impl Future<Output = io::Result<CommandOutput>> + Send;
}

/// [`CommandRunner`] that actually executes processes via [`tokio::process`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    async fn run(&self, program: &Path, args: &[String]) -> io::Result<CommandOutput> {
        let output = tokio::process::Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;
        Ok(CommandOutput {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

impl PipedRunner for SystemRunner {
    async fn run_piped(
        &self,
        program: &Path,
        args: &[String],
        stdin: String,
        timeout: std::time::Duration,
    ) -> io::Result<CommandOutput> {
        let mut child = match tokio::process::Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                satl_metrics::record_command_failure_for(program);
                return Err(error);
            }
        };
        // Writing and waiting have to be concurrent: a child that answers
        // before reading all of stdin (or a request larger than the pipe
        // buffer) would deadlock a write-then-wait sequence.
        let mut pipe = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("the child was spawned without a stdin pipe"))?;
        let write = async move {
            use tokio::io::AsyncWriteExt as _;
            pipe.write_all(stdin.as_bytes()).await?;
            pipe.shutdown().await
        };
        let both = async { tokio::join!(write, child.wait_with_output()) };
        // A child that hangs is killed by `kill_on_drop` when this future is
        // dropped on timeout.
        let Ok((written, output)) = tokio::time::timeout(timeout, both).await else {
            satl_metrics::record_command_failure_for(program);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("the child did not finish within {timeout:?} and was killed"),
            ));
        };
        // A broken pipe here means the child exited early; its output is still
        // the interesting evidence, so it is reported rather than this error.
        if let Err(err) = written
            && err.kind() != io::ErrorKind::BrokenPipe
        {
            return Err(err);
        }
        let output = output?;
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

/// Mock [`CommandRunner`] for unit tests: records every rendered argv and pops
/// pre-loaded responses in FIFO order.
#[cfg(test)]
pub(crate) struct MockRunner {
    responses: std::sync::Mutex<std::collections::VecDeque<io::Result<CommandOutput>>>,
    calls: std::sync::Mutex<Vec<String>>,
    stdins: std::sync::Mutex<Vec<String>>,
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

    /// A process killed by a signal: no exit code at all.
    pub(crate) fn push_signalled(&self, stdout: &str, stderr: &str) {
        self.responses.lock().unwrap().push_back(Ok(CommandOutput {
            exit_code: None,
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
        }));
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

    /// What was fed to each [`PipedRunner::run_piped`] call, in order.
    pub(crate) fn stdins(&self) -> Vec<String> {
        self.stdins.lock().unwrap().clone()
    }

    fn record(&self, program: &Path, args: &[String]) -> io::Result<CommandOutput> {
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
        self.record(program, args)
    }
}

#[cfg(test)]
impl PipedRunner for &MockRunner {
    async fn run_piped(
        &self,
        program: &Path,
        args: &[String],
        stdin: String,
        _timeout: std::time::Duration,
    ) -> io::Result<CommandOutput> {
        self.stdins.lock().unwrap().push(stdin);
        self.record(program, args)
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
                "satl-vx4096".to_owned(),
                "description".to_owned(),
                "satl:vxlan:my net".to_owned(),
                String::new(),
            ],
        );
        assert_eq!(
            argv,
            "/sbin/ifconfig satl-vx4096 description \"satl:vxlan:my net\" \"\""
        );
    }

    #[test]
    fn failure_display_carries_argv_status_stderr() {
        let failure = Failure {
            argv: "/sbin/ifconfig satl-vx4096 destroy".to_owned(),
            exit_code: Some(1),
            stderr: "ifconfig: interface satl-vx4096 does not exist\n".to_owned(),
        };
        let text = failure.to_string();
        assert!(
            text.contains("/sbin/ifconfig satl-vx4096 destroy"),
            "{text}"
        );
        assert!(text.contains("exit code 1"), "{text}");
        assert!(text.contains("does not exist"), "{text}");
    }

    #[test]
    fn failure_display_signal_and_empty_stderr() {
        let failure = Failure {
            argv: "/usr/sbin/jexec j0 arp -an".to_owned(),
            exit_code: None,
            stderr: String::new(),
        };
        let text = failure.to_string();
        assert!(text.contains("termination by signal"), "{text}");
        assert!(text.contains("(empty)"), "{text}");
    }

    #[tokio::test]
    async fn system_runner_captures_output_and_status() {
        // `/usr/bin/true` and `/bin/echo` are in FreeBSD base.
        let output = SystemRunner
            .run(Path::new("/bin/echo"), &["satl".to_owned()])
            .await
            .unwrap();
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout, "satl\n");
        assert_eq!(output.stderr, "");
    }

    #[tokio::test]
    async fn system_runner_spawn_error_for_missing_binary() {
        let err = SystemRunner
            .run(Path::new("/nonexistent/satl-overlay-binary"), &[])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
