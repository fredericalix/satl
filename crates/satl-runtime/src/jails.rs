// SPDX-License-Identifier: BSD-2-Clause
//! Typed wrapper around `jls`(8): does a prison of this name still exist, and
//! has it started dying?
//!
//! ## Why the runtime needs this
//!
//! `ocijail delete` returns as soon as `jail_remove(2)` has been issued, and
//! the state db entry is gone with it — so ocijail can no longer answer any
//! question about that container. The prison, however, is not gone: it moves
//! to `DYING` and stays there until its last reference is released, and **a
//! dying prison still holds its root vnode**. That vnode is an active vnode in
//! the container's ZFS filesystem, so `unmount(2)` returns `EBUSY` and
//! `zfs destroy` fails with
//! `cannot unmount '<rootfs>': pool or dataset is busy`.
//!
//! Nothing in userland shows that reference: `fstat` lists no open file,
//! `procstat` finds no process, and no submount is left under the rootfs.
//! `jls`(8) is the only observer of it, which is why `satl-agent` polls this
//! wrapper while it waits for a rootfs to become destroyable rather than
//! counting attempts on a clock. What keeps a prison dying for up to a minute,
//! and the measurements behind that, are in `docs/jail-teardown.md`.
//!
//! ## Output contract (captured on FreeBSD 15.1, `tests/fixtures/`)
//!
//! `jls -d -h name dying` prints a header line (`name dying`) and then one row
//! per prison — `-d` includes the dying ones *in addition to* the live ones,
//! so the `dying` column, not the presence of a row, is what distinguishes
//! them. With no prisons at all it prints the header alone and exits 0
//! (`jls_name_dying_empty.txt`, captured on a node with no containers), so an
//! empty jail set is never an error.

use std::path::{Path, PathBuf};

use crate::runner::{CommandOutput, CommandRunner, SystemRunner, render_argv};

/// Default location of the `jls` binary on FreeBSD.
pub const DEFAULT_JLS_BINARY: &str = "/usr/sbin/jls";

/// What `jls` says about one prison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JailState {
    /// A live prison: processes may still be running in it.
    Active,
    /// `jail_remove(2)` has been issued; the prison is being torn down and
    /// still holds its root vnode.
    Dying,
}

impl JailState {
    /// Operator-facing name, as `jls -v` spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Dying => "DYING",
        }
    }
}

impl std::fmt::Display for JailState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Failure of a `jls`(8) invocation. Every variant carries the exact command
/// line that ran (CLAUDE.md, "External command wrappers").
#[derive(Debug, thiserror::Error)]
pub enum JailError {
    /// `jls` could not be executed at all.
    #[error("cannot run `{argv}`: {source}")]
    Spawn {
        /// Rendered command line.
        argv: String,
        /// Underlying spawn error.
        #[source]
        source: std::io::Error,
    },

    /// `jls` ran and failed.
    #[error("`{argv}` failed with exit code {exit_code:?}; stderr: {stderr:?}")]
    CommandFailed {
        /// Rendered command line.
        argv: String,
        /// Exit code, `None` when killed by a signal.
        exit_code: Option<i32>,
        /// Raw stderr.
        stderr: String,
    },

    /// `jls` printed something this parser does not understand.
    #[error("cannot parse the output of `{argv}` ({reason}) in line {line:?}")]
    UnexpectedOutput {
        /// Rendered command line.
        argv: String,
        /// What was wrong.
        reason: &'static str,
        /// The offending line.
        line: String,
    },
}

/// `jls -d -h name dying`: every prison, live or dying, with its name.
fn args_list() -> Vec<String> {
    ["-d", "-h", "name", "dying"]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect()
}

/// Parse the table `args_list` produces into `(name, state)` pairs.
///
/// The header is skipped by shape, not by position: a row is a name plus
/// `true`/`false`, and the header is the one line whose second field is
/// neither.
fn parse_list(stdout: &str) -> Result<Vec<(String, JailState)>, (&'static str, String)> {
    let mut jails = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(name), Some(dying)) = (fields.next(), fields.next()) else {
            return Err(("expected a name and a dying flag", line.to_owned()));
        };
        if fields.next().is_some() {
            return Err(("more fields than the two requested", line.to_owned()));
        }
        match dying {
            "true" => jails.push((name.to_owned(), JailState::Dying)),
            "false" => jails.push((name.to_owned(), JailState::Active)),
            // The header line: `name dying`.
            "dying" if name == "name" => {}
            _ => {
                return Err((
                    "the dying column is neither true nor false",
                    line.to_owned(),
                ));
            }
        }
    }
    Ok(jails)
}

/// Typed async wrapper around `jls`(8).
#[derive(Debug, Clone)]
pub struct Jails<R = SystemRunner> {
    binary: PathBuf,
    runner: R,
}

impl Jails<SystemRunner> {
    /// Wrapper executing the real binary at [`DEFAULT_JLS_BINARY`].
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for Jails<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner> Jails<R> {
    /// Wrapper using `runner` to execute commands (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_JLS_BINARY),
            runner,
        }
    }

    /// Override the binary path (tests).
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    async fn exec(&self, args: Vec<String>) -> Result<(String, CommandOutput), JailError> {
        let binary: &Path = &self.binary;
        let rendered = render_argv(binary, &args);
        let output = self
            .runner
            .run(binary, &args)
            .await
            .map_err(|source| JailError::Spawn {
                argv: rendered.clone(),
                source,
            })?;
        Ok((rendered, output))
    }

    /// Every prison on the host, dying ones included.
    ///
    /// # Errors
    ///
    /// [`JailError`] when `jls` cannot be run, fails, or prints an
    /// unrecognised table.
    pub async fn list(&self) -> Result<Vec<(String, JailState)>, JailError> {
        let (argv, output) = self.exec(args_list()).await?;
        if !output.success() {
            return Err(JailError::CommandFailed {
                argv,
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }
        parse_list(&output.stdout).map_err(|(reason, line)| JailError::UnexpectedOutput {
            argv,
            reason,
            line,
        })
    }

    /// The state of the prison named `name`, or `None` when no such prison
    /// exists any more.
    ///
    /// # Errors
    ///
    /// [`JailError`], as [`Jails::list`].
    pub async fn state(&self, name: &str) -> Result<Option<JailState>, JailError> {
        Ok(self
            .list()
            .await?
            .into_iter()
            .find(|(jail, _)| jail == name)
            .map(|(_, state)| state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    /// Captured on the dev host while a container's prison was dying: four
    /// live jails and one dying one.
    const FIXTURE_DYING: &str = include_str!("../tests/fixtures/jls_name_dying.txt");
    /// Captured on a node with no containers at all: the header alone.
    const FIXTURE_EMPTY: &str = include_str!("../tests/fixtures/jls_name_dying_empty.txt");

    #[test]
    fn list_argv_asks_for_dying_jails_and_the_two_columns() {
        assert_eq!(args_list(), ["-d", "-h", "name", "dying"]);
    }

    #[test]
    fn the_dying_column_is_what_separates_dying_from_live() {
        let jails = parse_list(FIXTURE_DYING).expect("fixture parses");
        assert_eq!(
            jails.len(),
            5,
            "the dying jail is listed alongside the live ones"
        );
        assert_eq!(
            jails
                .iter()
                .find(|(name, _)| name == "expm1-busy")
                .map(|(_, s)| *s),
            Some(JailState::Dying)
        );
        assert!(
            jails
                .iter()
                .filter(|(name, _)| name != "expm1-busy")
                .all(|(_, state)| *state == JailState::Active)
        );
    }

    #[test]
    fn no_jails_at_all_is_a_header_and_no_rows_not_an_error() {
        assert_eq!(parse_list(FIXTURE_EMPTY).expect("header only"), Vec::new());
        assert_eq!(parse_list("").expect("no output at all"), Vec::new());
    }

    #[test]
    fn an_unrecognised_table_is_reported_with_its_line() {
        let (reason, line) = parse_list("name dying\nweb maybe\n").expect_err("not a flag");
        assert_eq!(reason, "the dying column is neither true nor false");
        assert_eq!(line, "web maybe");
        let (reason, _) = parse_list("web\n").expect_err("one field");
        assert_eq!(reason, "expected a name and a dying flag");
        let (reason, _) = parse_list("web false 3\n").expect_err("three fields");
        assert_eq!(reason, "more fields than the two requested");
    }

    #[tokio::test]
    async fn state_finds_a_dying_prison_by_name() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_DYING, "");
        let jails = Jails::with_runner(&mock).with_binary("/usr/sbin/jls");
        assert_eq!(
            jails.state("expm1-busy").await.expect("state"),
            Some(JailState::Dying)
        );
        assert_eq!(mock.calls(), ["/usr/sbin/jls -d -h name dying"]);
    }

    #[tokio::test]
    async fn state_of_a_prison_that_is_gone_is_none() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_DYING, "");
        let jails = Jails::with_runner(&mock);
        assert_eq!(jails.state("nosuchtask").await.expect("state"), None);
    }

    #[tokio::test]
    async fn a_failed_invocation_carries_the_command_line() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "jls: unknown parameter: dying\n");
        let jails = Jails::with_runner(&mock).with_binary("/usr/sbin/jls");
        let error = jails.state("web").await.expect_err("must fail");
        let text = error.to_string();
        assert!(text.contains("/usr/sbin/jls -d -h name dying"), "{text}");
        assert!(text.contains("unknown parameter"), "{text}");
    }

    #[tokio::test]
    async fn a_missing_binary_is_a_spawn_error_with_the_command_line() {
        let mock = MockRunner::new();
        mock.push_spawn_error(std::io::ErrorKind::NotFound, "no such file");
        let jails = Jails::with_runner(&mock).with_binary("/nonexistent/jls");
        let error = jails.list().await.expect_err("must fail");
        assert!(error.to_string().contains("/nonexistent/jls"), "{error}");
    }
}
