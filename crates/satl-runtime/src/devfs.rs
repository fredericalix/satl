// SPDX-License-Identifier: BSD-2-Clause
//! SatL-owned devfs(8) ruleset management.
//!
//! Why SatL ships its own ruleset (docs/linuxulator.md "/dev: the ruleset
//! problem"): the stock jail ruleset 4 hides the global `shm` directory in
//! the devfs name tree, and devfs does not support `mkdir`, so ocijail's
//! attempt to create the `/dev/shm` tmpfs mountpoint fails with
//! `Operation not supported`. SatL's ruleset is the classic jail set
//! (includes 1–3) plus `shm` unhidden, which was proven to give the jail-safe
//! device list *and* let the `/dev/shm` tmpfs mount succeed.
//!
//! Ruleset number: `/etc/defaults/devfs.rules` reserves 1–4 and operator
//! rulesets in `devfs.rules(5)` conventionally stay small, so SatL claims
//! **5000** — the same "own your namespace" pattern as SatL's pf anchor. The
//! linuxulator experiments used 5001 precisely so a running satld's 5000 is
//! never touched.
//!
//! `ensure_ruleset` runs at satld startup (before any container with a devfs
//! mount is created); the ruleset lives in the kernel until reboot, so this
//! must be re-run on every daemon start.

use std::path::PathBuf;

use crate::runner::{CommandOutput, CommandRunner, SystemRunner, render_argv};

/// Default location of the `devfs` binary on FreeBSD.
pub const DEFAULT_DEVFS_BINARY: &str = "/sbin/devfs";

/// The devfs ruleset number SatL owns (see module docs for the choice).
pub const SATL_DEVFS_RULESET: u32 = 5000;

/// The rule bodies of SatL's ruleset, in installation order, exactly as
/// proven in docs/linuxulator.md:
/// includes of `devfsrules_hide_all` (1), `devfsrules_unhide_basic` (2),
/// `devfsrules_unhide_login` (3), then unhide `shm` and everything below it.
pub const SATL_DEVFS_RULES: [&[&str]; 5] = [
    &["include", "1"],
    &["include", "2"],
    &["include", "3"],
    &["path", "shm", "unhide"],
    &["path", "shm/*", "unhide"],
];

/// Error from a `devfs`(8) invocation. Every variant carries the full
/// command line; failures additionally carry exit status and raw stderr.
#[derive(Debug, thiserror::Error)]
pub enum DevfsError {
    /// The `devfs` binary could not be spawned.
    #[error("failed to spawn `{argv}`: {source}")]
    Spawn {
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The command ran but exited unsuccessfully.
    #[error("`{argv}` failed with {status}; stderr: {stderr}", status = render_exit(*exit_code), stderr = stderr.trim_end())]
    CommandFailed {
        /// Full rendered command line.
        argv: String,
        /// Exit code; `None` when killed by a signal.
        exit_code: Option<i32>,
        /// Raw stderr from the command.
        stderr: String,
    },
}

fn render_exit(exit_code: Option<i32>) -> String {
    match exit_code {
        Some(code) => format!("exit code {code}"),
        None => "termination by signal".to_owned(),
    }
}

/// What [`Devfs::ensure_ruleset`] had to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureOutcome {
    /// The ruleset already held exactly SatL's rules; nothing was changed.
    AlreadyCurrent,
    /// The ruleset was empty and the rules were installed.
    Installed,
    /// The ruleset held different rules; it was flushed and reinstalled.
    Reinstalled,
}

// ---------------------------------------------------------------------------
// Pure argv builders.
// ---------------------------------------------------------------------------

fn args_rule_show(ruleset: u32) -> Vec<String> {
    vec![
        "rule".to_owned(),
        "-s".to_owned(),
        ruleset.to_string(),
        "show".to_owned(),
    ]
}

fn args_rule_add(ruleset: u32, rule: &[&str]) -> Vec<String> {
    let mut args = vec![
        "rule".to_owned(),
        "-s".to_owned(),
        ruleset.to_string(),
        "add".to_owned(),
    ];
    args.extend(rule.iter().map(|word| (*word).to_owned()));
    args
}

fn args_rule_delset(ruleset: u32) -> Vec<String> {
    vec![
        "rule".to_owned(),
        "-s".to_owned(),
        ruleset.to_string(),
        "delset".to_owned(),
    ]
}

// ---------------------------------------------------------------------------
// Pure parser.
// ---------------------------------------------------------------------------

/// Parse `devfs rule -s N show` output into rule bodies, dropping the
/// auto-assigned leading rule numbers (`100 include 1` → `include 1`).
/// A ruleset that was never referenced shows as empty output, exit 0.
fn parse_rule_show(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| match line.split_once(' ') {
            Some((_number, body)) => body.trim().to_owned(),
            None => line.trim().to_owned(),
        })
        .collect()
}

/// The rule bodies `parse_rule_show` must report for a current ruleset.
fn expected_rule_bodies() -> Vec<String> {
    SATL_DEVFS_RULES.iter().map(|rule| rule.join(" ")).collect()
}

// ---------------------------------------------------------------------------
// The wrapper itself.
// ---------------------------------------------------------------------------

/// Typed async wrapper around `devfs`(8) rule management (root only).
#[derive(Debug, Clone)]
pub struct Devfs<R = SystemRunner> {
    binary: PathBuf,
    runner: R,
}

impl Devfs<SystemRunner> {
    /// Wrapper that executes the real binary at [`DEFAULT_DEVFS_BINARY`].
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for Devfs<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner> Devfs<R> {
    /// Wrapper using `runner` to execute commands (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_DEVFS_BINARY),
            runner,
        }
    }

    /// Override the path of the `devfs` binary.
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    async fn exec(&self, args: Vec<String>) -> Result<(String, CommandOutput), DevfsError> {
        let rendered = render_argv(&self.binary, &args);
        tracing::debug!(command = %rendered, "running devfs");
        let output = self
            .runner
            .run(&self.binary, &args)
            .await
            .map_err(|source| DevfsError::Spawn {
                argv: rendered.clone(),
                source,
            })?;
        Ok((rendered, output))
    }

    async fn exec_checked(&self, args: Vec<String>) -> Result<CommandOutput, DevfsError> {
        let (rendered, output) = self.exec(args).await?;
        if output.success() {
            Ok(output)
        } else {
            Err(DevfsError::CommandFailed {
                argv: rendered,
                exit_code: output.exit_code,
                stderr: output.stderr,
            })
        }
    }

    /// The current rule bodies of `ruleset` (empty if never referenced).
    pub async fn show_ruleset(&self, ruleset: u32) -> Result<Vec<String>, DevfsError> {
        let output = self.exec_checked(args_rule_show(ruleset)).await?;
        Ok(parse_rule_show(&output.stdout))
    }

    /// Idempotently install SatL's devfs ruleset ([`SATL_DEVFS_RULESET`]).
    ///
    /// - already exactly SatL's rules → no-op;
    /// - empty → install;
    /// - anything else (stale rules from an older satld) → flush (`delset`)
    ///   and reinstall, so the ruleset content is always exactly
    ///   [`SATL_DEVFS_RULES`].
    pub async fn ensure_ruleset(&self) -> Result<EnsureOutcome, DevfsError> {
        let current = self.show_ruleset(SATL_DEVFS_RULESET).await?;
        let expected = expected_rule_bodies();
        if current == expected {
            tracing::debug!(
                ruleset = SATL_DEVFS_RULESET,
                "devfs ruleset already current"
            );
            return Ok(EnsureOutcome::AlreadyCurrent);
        }
        let outcome = if current.is_empty() {
            EnsureOutcome::Installed
        } else {
            tracing::warn!(
                ruleset = SATL_DEVFS_RULESET,
                found = ?current,
                "devfs ruleset held unexpected rules; reinstalling"
            );
            self.exec_checked(args_rule_delset(SATL_DEVFS_RULESET))
                .await?;
            EnsureOutcome::Reinstalled
        };
        for rule in SATL_DEVFS_RULES {
            self.exec_checked(args_rule_add(SATL_DEVFS_RULESET, rule))
                .await?;
        }
        tracing::info!(
            ruleset = SATL_DEVFS_RULESET,
            ?outcome,
            "installed SatL devfs ruleset"
        );
        Ok(outcome)
    }

    /// Remove SatL's ruleset entirely (`devfs rule -s N delset`). Used by
    /// tests; satld itself leaves the ruleset in place.
    pub async fn remove_ruleset(&self, ruleset: u32) -> Result<(), DevfsError> {
        self.exec_checked(args_rule_delset(ruleset)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    const FIXTURE_SHOW_S4: &str = include_str!("../tests/fixtures/devfs_rule_show_s4.txt");
    const FIXTURE_SHOW_EMPTY: &str = include_str!("../tests/fixtures/devfs_rule_show_empty.txt");

    #[test]
    fn argv_builders() {
        assert_eq!(args_rule_show(5000), ["rule", "-s", "5000", "show"]);
        assert_eq!(
            args_rule_add(5000, &["include", "1"]),
            ["rule", "-s", "5000", "add", "include", "1"]
        );
        assert_eq!(
            args_rule_add(5000, &["path", "shm/*", "unhide"]),
            ["rule", "-s", "5000", "add", "path", "shm/*", "unhide"]
        );
        assert_eq!(args_rule_delset(5000), ["rule", "-s", "5000", "delset"]);
    }

    #[test]
    fn parse_show_output_of_stock_jail_ruleset() {
        // Real `devfs rule -s 4 show` output from the dev host.
        let bodies = parse_rule_show(FIXTURE_SHOW_S4);
        assert_eq!(
            bodies,
            [
                "include 1",
                "include 2",
                "include 3",
                "path fuse unhide",
                "path zfs unhide"
            ]
        );
    }

    #[test]
    fn parse_show_output_of_unreferenced_ruleset_is_empty() {
        // Real `devfs rule -s 5000 show` on a host where 5000 was never
        // referenced: exit 0, no output.
        assert!(parse_rule_show(FIXTURE_SHOW_EMPTY).is_empty());
    }

    #[tokio::test]
    async fn ensure_installs_into_empty_ruleset() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SHOW_EMPTY, ""); // show
        for _ in 0..SATL_DEVFS_RULES.len() {
            mock.push_output(0, "", ""); // each add
        }
        let devfs = Devfs::with_runner(&mock);
        assert_eq!(
            devfs.ensure_ruleset().await.unwrap(),
            EnsureOutcome::Installed
        );
        assert_eq!(
            mock.calls(),
            [
                "/sbin/devfs rule -s 5000 show",
                "/sbin/devfs rule -s 5000 add include 1",
                "/sbin/devfs rule -s 5000 add include 2",
                "/sbin/devfs rule -s 5000 add include 3",
                "/sbin/devfs rule -s 5000 add path shm unhide",
                "/sbin/devfs rule -s 5000 add path shm/* unhide",
            ]
        );
    }

    #[tokio::test]
    async fn ensure_is_a_noop_when_current() {
        let mock = MockRunner::new();
        let current = "100 include 1\n200 include 2\n300 include 3\n\
                       400 path shm unhide\n500 path shm/* unhide\n";
        mock.push_output(0, current, "");
        let devfs = Devfs::with_runner(&mock);
        assert_eq!(
            devfs.ensure_ruleset().await.unwrap(),
            EnsureOutcome::AlreadyCurrent
        );
        assert_eq!(mock.calls(), ["/sbin/devfs rule -s 5000 show"]);
    }

    #[tokio::test]
    async fn ensure_reinstalls_stale_rules() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SHOW_S4, ""); // wrong content
        mock.push_output(0, "", ""); // delset
        for _ in 0..SATL_DEVFS_RULES.len() {
            mock.push_output(0, "", "");
        }
        let devfs = Devfs::with_runner(&mock);
        assert_eq!(
            devfs.ensure_ruleset().await.unwrap(),
            EnsureOutcome::Reinstalled
        );
        let calls = mock.calls();
        assert_eq!(calls[1], "/sbin/devfs rule -s 5000 delset");
        assert_eq!(calls.len(), 2 + SATL_DEVFS_RULES.len());
    }

    /// Root-only (`make integration`): install SatL's ruleset in the real
    /// kernel, verify `devfs rule -s 5000 show` echoes exactly our rules,
    /// prove idempotency, then remove the ruleset again (zero kernel-state
    /// footprint; satld in production leaves it installed).
    #[tokio::test]
    #[ignore = "requires root and FreeBSD (run via make integration)"]
    async fn ensure_ruleset_for_real() {
        assert!(
            nix::unistd::geteuid().is_root(),
            "this #[ignore] test must run as root"
        );
        let devfs = Devfs::system();
        // First call: any outcome is legitimate (another integration test —
        // or a satld — may already have installed the ruleset); the
        // postcondition is what matters.
        devfs.ensure_ruleset().await.unwrap();
        assert_eq!(
            devfs.show_ruleset(SATL_DEVFS_RULESET).await.unwrap(),
            expected_rule_bodies()
        );
        // A repeat run is a no-op.
        assert_eq!(
            devfs.ensure_ruleset().await.unwrap(),
            EnsureOutcome::AlreadyCurrent
        );
        // From a removed (empty) ruleset, ensure performs a fresh install.
        devfs.remove_ruleset(SATL_DEVFS_RULESET).await.unwrap();
        assert!(
            devfs
                .show_ruleset(SATL_DEVFS_RULESET)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            devfs.ensure_ruleset().await.unwrap(),
            EnsureOutcome::Installed
        );
        assert_eq!(
            devfs.show_ruleset(SATL_DEVFS_RULESET).await.unwrap(),
            expected_rule_bodies()
        );
        // Cleanup: remove the ruleset from the kernel again.
        devfs.remove_ruleset(SATL_DEVFS_RULESET).await.unwrap();
        assert!(
            devfs
                .show_ruleset(SATL_DEVFS_RULESET)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn failure_carries_argv_status_stderr() {
        let mock = MockRunner::new();
        mock.push_output(
            1,
            "",
            "devfs rule: ioctl DEVFSIO_SUSE: Operation not permitted\n",
        );
        let devfs = Devfs::with_runner(&mock);
        let err = devfs.show_ruleset(5000).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/sbin/devfs rule -s 5000 show"), "{msg}");
        assert!(msg.contains("exit code 1"), "{msg}");
        assert!(msg.contains("Operation not permitted"), "{msg}");
    }
}
