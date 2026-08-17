// SPDX-License-Identifier: BSD-2-Clause
//! Injectable process execution for this crate's external-command wrappers
//! ([`crate::rctl`]).
//!
//! Same design as `satl-storage::zfs` and `satl-net::runner` (CLAUDE.md,
//! "External command wrappers"): a crate-local [`CommandRunner`] trait so
//! command construction and output parsing are unit-testable without
//! privileges, plus a rendered-argv helper so every error carries the exact
//! command line that ran. Deliberately duplicated rather than shared — a
//! common wrapper crate is a later refactor, and the sibling crates each need
//! slightly different spawn shapes (stdin piping in `satl-net`, inherited fds
//! in `satl-runtime`).

use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::path::Path;

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
    pub(crate) fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Executes external commands. The real implementation is [`SystemRunner`];
/// tests inject a recording mock so no privileges (or binaries) are needed to
/// exercise wrapper logic.
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args` to completion, capturing stdout and stderr.
    ///
    /// # Errors
    ///
    /// [`io::Error`] when the process could not be spawned at all.
    fn run(
        &self,
        program: &Path,
        args: &[String],
    ) -> impl Future<Output = io::Result<CommandOutput>> + Send;
}

/// [`CommandRunner`] that actually executes processes via [`tokio::process`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    async fn run(&self, program: &Path, args: &[String]) -> io::Result<CommandOutput> {
        let output = match tokio::process::Command::new(program)
            .args(args)
            .output()
            .await
        {
            Ok(output) => output,
            Err(error) => {
                satl_metrics::record_command_failure_for(program);
                return Err(error);
            }
        };
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

/// Mock [`CommandRunner`] for unit tests: records every rendered argv and pops
/// pre-loaded responses in FIFO order.
#[cfg(test)]
pub(crate) struct MockRunner {
    responses: std::sync::Mutex<std::collections::VecDeque<io::Result<CommandOutput>>>,
    calls: std::sync::Mutex<Vec<String>>,
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
}

#[cfg(test)]
impl CommandRunner for &MockRunner {
    async fn run(&self, program: &Path, args: &[String]) -> io::Result<CommandOutput> {
        self.calls.lock().unwrap().push(render_argv(program, args));
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
    fn argv_rendering_quotes_whitespace_and_empty_args() {
        let argv = render_argv(
            Path::new("/usr/bin/rctl"),
            &["-a".to_owned(), "jail:t 1:pcpu:deny=50".to_owned()],
        );
        assert_eq!(argv, "/usr/bin/rctl -a \"jail:t 1:pcpu:deny=50\"");
        assert_eq!(
            render_argv(Path::new("/bin/x"), &[String::new()]),
            "/bin/x \"\""
        );
    }
}
