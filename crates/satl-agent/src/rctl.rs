// SPDX-License-Identifier: BSD-2-Clause
//! Typed wrapper around `rctl`(8) — the FreeBSD equivalent of cgroup limits
//! (architecture §3: `TaskSpec.resources` maps to rctl rules, §8.3: degrade
//! gracefully when racct is off).
//!
//! Two rules per task, both scoped to the task's jail (the jail name is the
//! task ID, architecture §3):
//!
//! ```text
//! rctl -a jail:<name>:memoryuse:sigkill=<bytes>  # RSS is not deniable
//! rctl -a jail:<name>:pcpu:deny=<percent>        # percent of ONE core (throttle)
//! rctl -r jail:<name>                          # remove every rule for the jail
//! ```
//!
//! **racct gating (architecture §8.3, normative).** Resource accounting is a
//! boot-time tunable (`kern.racct.enable=1` in loader.conf). With it off,
//! every `rctl` invocation fails with
//! `RACCT/RCTL present, but disabled; enable using kern.racct.enable=1
//! tunable` — so SatL probes once at startup ([`racct_enabled`]) and, when
//! disabled, **accepts limits but does not enforce them**: no `rctl` process
//! is spawned at all and [`Rctl::apply_limits`] returns
//! [`LimitsOutcome::Skipped`], whose [`LimitsSkipped::note`] the controller
//! records in the task status message. Degrade, never crash — the dev host
//! runs with racct off and is never rebooted.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use satl_core::Id;

use crate::runner::{CommandRunner, SystemRunner, render_argv};

/// Default location of the `rctl` binary on FreeBSD.
pub const DEFAULT_RCTL_BINARY: &str = "/usr/bin/rctl";

/// Default location of the `sysctl` binary on FreeBSD.
pub const DEFAULT_SYSCTL_BINARY: &str = "/sbin/sysctl";

/// The sysctl that says whether resource accounting is compiled in *and*
/// enabled (a loader tunable — it cannot be turned on at runtime).
pub const RACCT_ENABLE_OID: &str = "kern.racct.enable";

/// Error from an `rctl`/`sysctl` invocation. Every variant carries the full
/// command line; command failures carry exit status and raw stderr.
#[derive(Debug, thiserror::Error)]
pub enum RctlError {
    /// The binary could not be spawned.
    #[error("failed to spawn `{argv}`: {source}")]
    Spawn {
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The command ran but exited unsuccessfully.
    #[error(
        "`{argv}` failed with {status}; stderr: {stderr}",
        status = match exit_code { Some(code) => format!("exit code {code}"), None => "termination by signal".to_owned() },
        stderr = if stderr.trim_end().is_empty() { "(empty)".to_owned() } else { format!("{:?}", stderr.trim_end()) },
    )]
    CommandFailed {
        /// Full rendered command line.
        argv: String,
        /// Exit code; `None` when killed by a signal.
        exit_code: Option<i32>,
        /// Raw stderr from the command.
        stderr: String,
    },

    /// The command succeeded but its output did not have the expected shape.
    /// Carries the full command line and the raw output — this is an SRE
    /// tool: an operator must be able to see exactly what was parsed.
    #[error("could not parse `{argv}` output ({reason}); raw output: {output:?}")]
    Parse {
        /// Full rendered command line.
        argv: String,
        /// What was expected and missing.
        reason: String,
        /// Raw stdout that failed to parse.
        output: String,
    },
}

/// Why resource limits were accepted but not enforced (architecture §8.3).
/// The controller copies [`LimitsSkipped::note`] into the reported task
/// status so `satl ps`/`docker inspect` show *why* `--memory`/`--cpus` had no
/// effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitsSkipped {
    /// Operator-facing explanation, ready to append to a status message.
    pub reason: String,
}

impl LimitsSkipped {
    /// The canonical racct-disabled marker.
    #[must_use]
    pub fn racct_disabled() -> Self {
        Self {
            reason: format!(
                "resource limits not enforced: {RACCT_ENABLE_OID}=0 on this node \
                 (set {RACCT_ENABLE_OID}=1 in loader.conf and reboot)"
            ),
        }
    }

    /// The explanation, as recorded in the task status message.
    #[must_use]
    pub fn note(&self) -> &str {
        &self.reason
    }
}

/// What [`Rctl::apply_limits`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitsOutcome {
    /// The task spec carries no limits; nothing to do on any host.
    NoLimits,
    /// Rules were installed.
    Applied {
        /// Memory cap in bytes, when set.
        memory_bytes: Option<i64>,
        /// CPU cap as rctl `pcpu` (percent of a single core), when set.
        pcpu: Option<i64>,
    },
    /// Limits were requested but not enforced (racct off) — degrade, don't
    /// crash (architecture §8.3).
    Skipped(LimitsSkipped),
}

/// Whether resource accounting is enabled on this host: `sysctl -n
/// kern.racct.enable` printing `1`.
///
/// A missing oid (racct not compiled in, `sysctl: unknown oid ...`, exit 1)
/// and a `0` value are both simply "disabled" — never an error, so a node
/// without racct still starts (architecture §8.3).
///
/// # Errors
///
/// [`RctlError::Spawn`] only when `sysctl` itself cannot be executed.
pub async fn racct_enabled<R: CommandRunner>(runner: &R) -> Result<bool, RctlError> {
    racct_enabled_at(runner, Path::new(DEFAULT_SYSCTL_BINARY)).await
}

/// [`racct_enabled`] against an explicit `sysctl` path (test seam).
///
/// # Errors
///
/// [`RctlError::Spawn`] only when `sysctl` itself cannot be executed.
pub async fn racct_enabled_at<R: CommandRunner>(
    runner: &R,
    sysctl: &Path,
) -> Result<bool, RctlError> {
    let args = args_racct_probe();
    let rendered = render_argv(sysctl, &args);
    tracing::debug!(command = %rendered, "probing racct availability");
    let output = runner
        .run(sysctl, &args)
        .await
        .map_err(|source| RctlError::Spawn {
            argv: rendered,
            source,
        })?;
    if !output.success() {
        tracing::warn!(
            oid = RACCT_ENABLE_OID,
            stderr = %output.stderr.trim_end(),
            "racct sysctl unavailable; resource limits will be accepted but not enforced"
        );
        return Ok(false);
    }
    Ok(parse_racct_enable(&output.stdout))
}

fn args_racct_probe() -> Vec<String> {
    vec!["-n".to_owned(), RACCT_ENABLE_OID.to_owned()]
}

/// Parse `sysctl -n kern.racct.enable` output. Anything that is not exactly
/// `1` counts as disabled.
fn parse_racct_enable(stdout: &str) -> bool {
    stdout.trim() == "1"
}

/// Whether an `rctl` failure means "the filter matched no rule".
///
/// rctl reports that as `No such process` (ESRCH) — captured verbatim:
/// `rctl: failed to remove rule 'jail:<id>': No such process`. Note what it
/// does *not* mean (measured 2026-08-17, cluster node1): a dead subject.
/// `rctl -r jail:<dead>` returns 0 and removes the rule; ESRCH is the
/// answer only once nothing is left to remove.
fn is_no_rule_matched(error: &RctlError) -> bool {
    matches!(
        error,
        RctlError::CommandFailed { stderr, .. } if stderr.contains("No such process")
    )
}

/// rctl rule for a jail's memory cap.
///
/// **The action is `sigkill`, not `deny`, and that is load-bearing.** `RSS`
/// (rctl's `memoryuse`) is not a deniable resource in the FreeBSD kernel —
/// `sys/kern/kern_racct.c` gives it `RACCT_RECLAIMABLE` only, with no
/// `RACCT_DENIABLE`. `rctl` nevertheless *accepts* `memoryuse:deny` (a special
/// case in `rctl_rule_add`, `sys/kern/kern_rctl.c`), so the rule installs
/// without error and then never denies anything: verified on FreeBSD 15.1, a
/// jail limited to `memoryuse:deny=64m` allocated 200 MB happily. With
/// `sigkill` the same allocation is killed.
///
/// Killing on excess is also the closer match to Docker, where exceeding
/// `--memory` gets the process OOM-killed by the cgroup rather than seeing
/// `malloc` fail.
fn rule_memoryuse(jail: &str, bytes: i64) -> String {
    format!("jail:{jail}:memoryuse:sigkill={bytes}")
}

/// rctl rule for a jail's CPU cap. `pcpu` is percent of a *single* core
/// (rctl(8)), so 2 cores is `200`.
///
/// `deny` here means "throttle": `RACCT_PCTCPU` feeds the scheduler through
/// `rctl_pcpu_available` rather than failing an allocation. Because the
/// accounting is a decaying average the cap is approached rather than
/// enforced instantly — measured on FreeBSD 15.1, a fixed CPU-bound workload
/// took 4.4 s unlimited and 10.5 s under `pcpu:deny=20`, the ratio widening
/// as the run gets longer.
fn rule_pcpu(jail: &str, pcpu: i64) -> String {
    format!("jail:{jail}:pcpu:deny={pcpu}")
}

/// Nanoseconds of CPU per one percent of a core.
const NANOS_PER_PERCENT: i64 = 10_000_000;

/// Convert `NanoCPUs` (billionths of a core, architecture §3) to rctl `pcpu`,
/// rounding **up** so a sub-percent request is never silently zero (a `pcpu`
/// of 0 would deny all CPU time).
#[must_use]
pub fn nano_cpus_to_pcpu(nano_cpus: i64) -> i64 {
    if nano_cpus <= 0 {
        return 0;
    }
    // ceil(nano_cpus / 1e9 * 100) == ceil(nano_cpus / 1e7). `i64::div_ceil`
    // is still unstable, and the input is positive here.
    (nano_cpus + NANOS_PER_PERCENT - 1) / NANOS_PER_PERCENT
}

/// The `rctl`(8) wrapper. Construct with the racct verdict from
/// [`racct_enabled`] — with racct off no `rctl` process is ever spawned.
#[derive(Debug, Clone)]
pub struct Rctl<R = SystemRunner> {
    runner: R,
    binary: PathBuf,
    racct_enabled: bool,
}

impl Rctl<SystemRunner> {
    /// Wrapper executing the real `rctl` binary.
    #[must_use]
    pub fn system(racct_enabled: bool) -> Self {
        Self::with_runner(SystemRunner, racct_enabled)
    }
}

/// A running jail's resource consumption, as read by [`Rctl::usage`].
///
/// Only the two series the metrics collector exports (`docs/roadmap.md` M6b):
/// `rctl -u` reports two dozen resources, the rest is noise at one read per
/// task per 20 s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RctlUsage {
    /// Accumulated CPU time, seconds (`cputime=`).
    pub cpu_seconds: i64,
    /// Current RSS, bytes (`memoryuse=`, de-humanized).
    pub memory_bytes: i64,
}

impl<R: CommandRunner> Rctl<R> {
    /// Read a jail's resource consumption: `rctl -hu jail:<name>`.
    ///
    /// Returns `Ok(None)` when there is nothing to report — racct disabled
    /// (no `rctl` process is spawned, same gate as every other method) or the
    /// jail vanished between the caller's listing and this read (teardown
    /// race, same `No such process` shape as [`Rctl::remove_limits`]).
    ///
    /// # Errors
    ///
    /// [`RctlError`] when the invocation fails for any other reason, or the
    /// output does not have the measured `resource=value` shape.
    #[tracing::instrument(skip(self), fields(jail = %jail_name))]
    pub async fn usage(&self, jail_name: &str) -> Result<Option<RctlUsage>, RctlError> {
        if !self.racct_enabled {
            return Ok(None);
        }
        let args = vec!["-hu".to_owned(), format!("jail:{jail_name}")];
        match self.run_query(&args).await {
            Ok(stdout) => match parse_usage(&stdout) {
                Some(usage) => Ok(Some(usage)),
                None => Err(RctlError::Parse {
                    argv: render_argv(&self.binary, &args),
                    reason: "no parseable cputime= and memoryuse= lines".to_owned(),
                    output: stdout,
                }),
            },
            Err(error) if is_no_rule_matched(&error) => {
                tracing::debug!("no usage to read; the jail is already gone");
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

/// Parse `rctl -hu jail:<name>` output into the two exported counters.
///
/// Measured shape (FreeBSD 15.1, fixture `rctl_hu_jail.txt`): one
/// `resource=value` line per resource, values humanized by `-h`
/// (`memoryuse=3192K`, `vmemoryuse=14M`) and plain when small. Returns `None`
/// when either exported key is absent or malformed; lines without the
/// `key=value` shape are skipped, not fatal.
fn parse_usage(stdout: &str) -> Option<RctlUsage> {
    let mut cpu_seconds = None;
    let mut memory_bytes = None;
    for line in stdout.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        match key {
            "cputime" => cpu_seconds = Some(value.parse::<i64>().ok()?),
            "memoryuse" => memory_bytes = Some(parse_humanized_bytes(value)?),
            _ => {}
        }
    }
    Some(RctlUsage {
        cpu_seconds: cpu_seconds?,
        memory_bytes: memory_bytes?,
    })
}

/// De-humanize an `rctl -h` value: plain integer, or one with a binary
/// suffix (`K`/`M`/`G`/`T` = powers of 1024, per `humanize_number`(3)).
fn parse_humanized_bytes(value: &str) -> Option<i64> {
    let (digits, scale) = match value.split_at_checked(value.len().saturating_sub(1))? {
        (number, "K") => (number, 1_i64 << 10),
        (number, "M") => (number, 1_i64 << 20),
        (number, "G") => (number, 1_i64 << 30),
        (number, "T") => (number, 1_i64 << 40),
        _ => (value, 1),
    };
    digits.parse::<i64>().ok()?.checked_mul(scale)
}

impl<R: CommandRunner> Rctl<R> {
    /// Wrapper with an injected [`CommandRunner`] (test seam).
    pub fn with_runner(runner: R, racct_enabled: bool) -> Self {
        Self {
            runner,
            binary: PathBuf::from(DEFAULT_RCTL_BINARY),
            racct_enabled,
        }
    }

    /// Override the path of the `rctl` binary.
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    /// Whether this node enforces limits at all.
    #[must_use]
    pub fn racct_enabled(&self) -> bool {
        self.racct_enabled
    }

    async fn run_rule(&self, args: Vec<String>) -> Result<(), RctlError> {
        let rendered = render_argv(&self.binary, &args);
        tracing::debug!(command = %rendered, "running rctl");
        let output = self
            .runner
            .run(&self.binary, &args)
            .await
            .map_err(|source| RctlError::Spawn {
                argv: rendered.clone(),
                source,
            })?;
        if output.success() {
            return Ok(());
        }
        Err(RctlError::CommandFailed {
            argv: rendered,
            exit_code: output.exit_code,
            stderr: output.stderr,
        })
    }

    /// `run_rule`'s twin for reads: same error discipline, but the stdout is
    /// the point of the call.
    async fn run_query(&self, args: &[String]) -> Result<String, RctlError> {
        let rendered = render_argv(&self.binary, args);
        tracing::debug!(command = %rendered, "querying rctl");
        let output = self
            .runner
            .run(&self.binary, args)
            .await
            .map_err(|source| RctlError::Spawn {
                argv: rendered.clone(),
                source,
            })?;
        if output.success() {
            return Ok(output.stdout);
        }
        Err(RctlError::CommandFailed {
            argv: rendered,
            exit_code: output.exit_code,
            stderr: output.stderr,
        })
    }

    /// Install the task's resource limits on its jail.
    ///
    /// `None` limits are simply not installed. With racct disabled nothing is
    /// executed and [`LimitsOutcome::Skipped`] is returned (architecture
    /// §8.3) — the caller records the note in the task status.
    ///
    /// # Errors
    ///
    /// [`RctlError`] when an `rctl` invocation fails on a racct-enabled host.
    #[tracing::instrument(skip(self), fields(jail = %jail_name))]
    pub async fn apply_limits(
        &self,
        jail_name: &str,
        memory_bytes: Option<i64>,
        nano_cpus: Option<i64>,
    ) -> Result<LimitsOutcome, RctlError> {
        let memory = memory_bytes.filter(|bytes| *bytes > 0);
        let pcpu = nano_cpus.filter(|nanos| *nanos > 0).map(nano_cpus_to_pcpu);
        if memory.is_none() && pcpu.is_none() {
            return Ok(LimitsOutcome::NoLimits);
        }
        if !self.racct_enabled {
            let skipped = LimitsSkipped::racct_disabled();
            tracing::warn!(
                memory_bytes = ?memory,
                pcpu = ?pcpu,
                reason = %skipped.note(),
                "resource limits accepted but not enforced"
            );
            return Ok(LimitsOutcome::Skipped(skipped));
        }
        if let Some(bytes) = memory {
            self.run_rule(vec!["-a".to_owned(), rule_memoryuse(jail_name, bytes)])
                .await?;
        }
        if let Some(pcpu) = pcpu {
            self.run_rule(vec!["-a".to_owned(), rule_pcpu(jail_name, pcpu)])
                .await?;
        }
        tracing::info!(memory_bytes = ?memory, pcpu = ?pcpu, "resource limits applied");
        Ok(LimitsOutcome::Applied {
            memory_bytes: memory,
            pcpu,
        })
    }

    /// Remove every rctl rule attached to the task's jail. No-op with racct
    /// disabled (nothing was ever installed).
    ///
    /// Called while the jail is still alive (the controller's
    /// `remove_inner`), so the rules normally go with their container. They
    /// survive the jail's death when removal was interrupted or skipped,
    /// and `rctl -r` on the dead subject still works — reaping those is the
    /// startup purge's job ([`Rctl::purge_orphan_rules`], driven from
    /// satld's reconciliation pass).
    ///
    /// # Errors
    ///
    /// [`RctlError`] when the `rctl` invocation fails.
    #[tracing::instrument(skip(self), fields(jail = %jail_name))]
    pub async fn remove_limits(&self, jail_name: &str) -> Result<(), RctlError> {
        if !self.racct_enabled {
            return Ok(());
        }
        match self
            .run_rule(vec!["-r".to_owned(), format!("jail:{jail_name}")])
            .await
        {
            Ok(()) => {
                tracing::debug!("resource limits removed");
                Ok(())
            }
            // `rctl -r jail:<name>` fails with "No such process" when the
            // filter matches no rule — the rules are already gone, which is
            // all this call wanted. Surfacing that as an error logged two
            // ERRORs on every container removal and reported the cleanup as
            // failed (the reconciliation cleaner's half-created task may
            // have no rules at all).
            Err(error) if is_no_rule_matched(&error) => {
                tracing::debug!("no resource limits to remove; no rule matched the jail");
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

/// Parse `rctl` (no arguments) output: one rule per line, no header
/// (fixture `rctl_list.txt`, captured on FreeBSD 15.1). Blank lines are
/// dropped; anything else is returned verbatim — distinguishing subjects is
/// [`orphan_satl_jail_rules`]' job.
fn parse_rule_list(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The jail name a rule line applies to, when its subject is a jail:
/// `jail:<name>:<resource>:<action>=<value>`. `None` for every other
/// subject class (`user:`, `process:`, `loginclass:`, ...) and for lines
/// without a resource part.
fn jail_subject(rule: &str) -> Option<&str> {
    let (name, resource) = rule.strip_prefix("jail:")?.split_once(':')?;
    (!name.is_empty() && !resource.is_empty()).then_some(name)
}

/// The SatL-owned jail subjects in `rules` that have no live prison: the
/// names to hand to `rctl -r`.
///
/// **Safety-critical: only SatL's own shape is ever selected.** A subject
/// qualifies only if its name is exactly the task-id shape (25 lowercase
/// base36 characters, [`Id`]'s own validation) — another tool may manage
/// its own jails' rules, and `ghosttest`, `www` or a near-miss length must
/// never be touched, however dead the jail. Dying prisons count as live:
/// their rules become purgeable once the prison is fully gone, and a later
/// pass (or the next startup) reaps them.
fn orphan_satl_jail_rules(rules: &[String], live: &BTreeSet<String>) -> Vec<String> {
    let mut orphans = BTreeSet::new();
    for rule in rules {
        let Some(name) = jail_subject(rule) else {
            continue;
        };
        if name.parse::<Id>().is_err() {
            continue;
        }
        if live.contains(name) {
            continue;
        }
        orphans.insert(name.to_owned());
    }
    orphans.into_iter().collect()
}

impl<R: CommandRunner> Rctl<R> {
    /// Every rule installed on the host: `rctl` with no arguments, one rule
    /// per line. Empty with racct disabled — no rule can exist then, and no
    /// `rctl` process is spawned (same gate as every other method).
    ///
    /// # Errors
    ///
    /// [`RctlError`] when the invocation fails on a racct-enabled host.
    #[tracing::instrument(skip(self))]
    pub async fn list_rules(&self) -> Result<Vec<String>, RctlError> {
        if !self.racct_enabled {
            return Ok(Vec::new());
        }
        let stdout = self.run_query(&[]).await?;
        Ok(parse_rule_list(&stdout))
    }

    /// Remove the rules of every SatL-owned jail subject that has no live
    /// prison, and return the purged jail names.
    ///
    /// Rules survive their jail's death (a crash, an interrupted teardown,
    /// a `reset.sh` older than the sweep there), and nothing else ever
    /// removes them. Measured on FreeBSD 15.1: `rctl -r jail:<dead>`
    /// returns 0 and drops the rules — the old belief that only a reboot
    /// purged them was wrong, and `No such process` is what a filter
    /// matching *no rule* returns, not what a dead subject returns.
    ///
    /// `live` is every prison name `jls` still knows (dying included).
    /// Which subjects are eligible at all is [`orphan_satl_jail_rules`]' —
    /// SatL-shaped names only, never a third party's.
    ///
    /// Warn-not-fail: one subject refusing removal is logged and skipped,
    /// it does not fail the pass.
    ///
    /// # Errors
    ///
    /// [`RctlError`] when the rules cannot be listed at all; the caller
    /// degrades that to a warning and tries again on the next pass.
    #[tracing::instrument(skip(self))]
    pub async fn purge_orphan_rules(
        &self,
        live: &BTreeSet<String>,
    ) -> Result<Vec<String>, RctlError> {
        let orphans = orphan_satl_jail_rules(&self.list_rules().await?, live);
        let mut purged = Vec::new();
        for name in orphans {
            match self.remove_limits(&name).await {
                Ok(()) => {
                    tracing::debug!(jail = %name, "purged the rctl rules of a dead jail");
                    purged.push(name);
                }
                Err(error) => {
                    tracing::warn!(jail = %name, %error, "cannot purge an orphan's rctl rules");
                }
            }
        }
        Ok(purged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    const FIXTURE_ENABLED: &str = include_str!("../tests/fixtures/sysctl_racct_enabled.txt");
    const FIXTURE_DISABLED: &str = include_str!("../tests/fixtures/sysctl_racct_disabled.txt");
    const FIXTURE_UNKNOWN_OID: &str =
        include_str!("../tests/fixtures/sysctl_racct_unknown_oid.txt");
    /// What `rctl` prints when racct is off — the failure this module exists
    /// to avoid ever hitting.
    const FIXTURE_RCTL_DISABLED: &str = include_str!("../tests/fixtures/rctl_usage.txt");

    const JAIL: &str = "1hvy0lj3x0b883f8e30fyp217";

    // ---- pure conversions --------------------------------------------------

    #[test]
    fn nano_cpus_convert_to_pcpu_of_a_single_core() {
        assert_eq!(nano_cpus_to_pcpu(1_000_000_000), 100);
        assert_eq!(nano_cpus_to_pcpu(2_000_000_000), 200);
        assert_eq!(nano_cpus_to_pcpu(500_000_000), 50);
        assert_eq!(nano_cpus_to_pcpu(1_500_000_000), 150);
        // Rounds up: a tiny request must never become "deny all CPU".
        assert_eq!(nano_cpus_to_pcpu(1), 1);
        assert_eq!(nano_cpus_to_pcpu(10_000_001), 2);
        assert_eq!(nano_cpus_to_pcpu(0), 0);
        assert_eq!(nano_cpus_to_pcpu(-5), 0);
    }

    #[test]
    fn rule_syntax_matches_rctl_grammar() {
        assert_eq!(
            rule_memoryuse(JAIL, 536_870_912),
            format!("jail:{JAIL}:memoryuse:sigkill=536870912")
        );
        assert_eq!(rule_pcpu(JAIL, 200), format!("jail:{JAIL}:pcpu:deny=200"));
    }

    // ---- sysctl probe against real captured output -------------------------

    #[test]
    fn racct_enable_parser_accepts_only_one() {
        assert!(parse_racct_enable(FIXTURE_ENABLED));
        assert!(!parse_racct_enable(FIXTURE_DISABLED));
        assert!(!parse_racct_enable(""));
        assert!(!parse_racct_enable("2\n"));
    }

    #[tokio::test]
    async fn racct_probe_builds_expected_argv_and_reads_one() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_ENABLED, "");
        assert!(racct_enabled(&&mock).await.unwrap());
        assert_eq!(mock.calls(), ["/sbin/sysctl -n kern.racct.enable"]);
    }

    #[tokio::test]
    async fn racct_probe_reads_zero_as_disabled() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_DISABLED, "");
        assert!(!racct_enabled(&&mock).await.unwrap());
    }

    #[tokio::test]
    async fn unknown_oid_is_disabled_not_an_error() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_UNKNOWN_OID);
        assert!(!racct_enabled(&&mock).await.unwrap());
    }

    #[tokio::test]
    async fn sysctl_spawn_failure_reports_the_command_line() {
        let mock = MockRunner::new();
        mock.push_spawn_error(std::io::ErrorKind::NotFound, "no such file");
        let err = racct_enabled(&&mock).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/sbin/sysctl -n kern.racct.enable"), "{msg}");
        assert!(msg.contains("no such file"), "{msg}");
    }

    // ---- apply/remove argv -------------------------------------------------

    #[tokio::test]
    async fn apply_limits_installs_both_rules_in_order() {
        let mock = MockRunner::new();
        mock.push_ok();
        mock.push_ok();
        let rctl = Rctl::with_runner(&mock, true);
        let outcome = rctl
            .apply_limits(JAIL, Some(536_870_912), Some(2_000_000_000))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            LimitsOutcome::Applied {
                memory_bytes: Some(536_870_912),
                pcpu: Some(200),
            }
        );
        assert_eq!(
            mock.calls(),
            [
                format!("/usr/bin/rctl -a jail:{JAIL}:memoryuse:sigkill=536870912"),
                format!("/usr/bin/rctl -a jail:{JAIL}:pcpu:deny=200"),
            ]
        );
    }

    #[tokio::test]
    async fn apply_limits_installs_only_what_is_set() {
        let mock = MockRunner::new();
        mock.push_ok();
        let rctl = Rctl::with_runner(&mock, true);
        let outcome = rctl
            .apply_limits(JAIL, None, Some(500_000_000))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            LimitsOutcome::Applied {
                memory_bytes: None,
                pcpu: Some(50)
            }
        );
        assert_eq!(
            mock.calls(),
            [format!("/usr/bin/rctl -a jail:{JAIL}:pcpu:deny=50")]
        );
    }

    #[tokio::test]
    async fn no_limits_runs_nothing_even_with_racct_on() {
        let mock = MockRunner::new();
        let rctl = Rctl::with_runner(&mock, true);
        assert_eq!(
            rctl.apply_limits(JAIL, None, None).await.unwrap(),
            LimitsOutcome::NoLimits
        );
        assert_eq!(
            rctl.apply_limits(JAIL, Some(0), Some(0)).await.unwrap(),
            LimitsOutcome::NoLimits
        );
        assert!(mock.calls().is_empty());
    }

    /// Architecture §8.3: racct off ⇒ accept, don't enforce, don't crash —
    /// and never spawn `rctl` (it would fail with the fixture's message).
    #[tokio::test]
    async fn racct_disabled_skips_without_running_rctl() {
        assert!(
            FIXTURE_RCTL_DISABLED.contains("but disabled"),
            "fixture drifted: {FIXTURE_RCTL_DISABLED}"
        );
        let mock = MockRunner::new();
        let rctl = Rctl::with_runner(&mock, false);
        let outcome = rctl
            .apply_limits(JAIL, Some(536_870_912), Some(1_000_000_000))
            .await
            .unwrap();
        match outcome {
            LimitsOutcome::Skipped(skipped) => {
                assert!(skipped.note().contains("kern.racct.enable"), "{skipped:?}");
                assert!(skipped.note().contains("loader.conf"), "{skipped:?}");
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
        rctl.remove_limits(JAIL).await.unwrap();
        assert!(mock.calls().is_empty(), "no rctl process may be spawned");
    }

    #[tokio::test]
    async fn remove_limits_drops_every_rule_of_the_jail() {
        let mock = MockRunner::new();
        mock.push_ok();
        let rctl = Rctl::with_runner(&mock, true);
        rctl.remove_limits(JAIL).await.unwrap();
        assert_eq!(mock.calls(), [format!("/usr/bin/rctl -r jail:{JAIL}")]);
    }

    /// The reconciliation cleaner can run on a task whose rules were never
    /// installed or are already gone; rctl then answers `No such process`
    /// (a filter matching no rule — measured: a dead *subject* with rules
    /// still installed answers 0 instead). That is not a failure: treating
    /// it as one logged two ERRORs on every container removal and reported
    /// the whole cleanup as failed.
    #[tokio::test]
    async fn removing_limits_of_a_vanished_jail_succeeds() {
        let mock = MockRunner::new();
        mock.push_output(
            1,
            "",
            &format!("rctl: failed to remove rule 'jail:{JAIL}': No such process\n"),
        );
        let rctl = Rctl::with_runner(&mock, true);
        rctl.remove_limits(JAIL)
            .await
            .expect("a missing jail is not an error");
    }

    #[tokio::test]
    async fn removing_limits_still_reports_other_failures() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "rctl: some other problem\n");
        let rctl = Rctl::with_runner(&mock, true);
        let err = rctl.remove_limits(JAIL).await.unwrap_err();
        assert!(err.to_string().contains("some other problem"));
    }

    // ---- usage read ---------------------------------------------------------

    /// Real captured output (FreeBSD 15.1, racct on, jail under CPU load):
    /// `rctl -hu jail:<name>` — humanized values (`3192K`, `14M`) included.
    const FIXTURE_USAGE: &str = include_str!("../tests/fixtures/rctl_hu_jail.txt");

    #[test]
    fn usage_parser_reads_the_two_exported_counters() {
        let usage = parse_usage(FIXTURE_USAGE).expect("fixture must parse");
        assert_eq!(usage.cpu_seconds, 1);
        assert_eq!(usage.memory_bytes, 3192 * 1024);
    }

    #[test]
    fn humanized_bytes_cover_plain_and_suffixed_values() {
        assert_eq!(parse_humanized_bytes("0"), Some(0));
        assert_eq!(parse_humanized_bytes("42"), Some(42));
        assert_eq!(parse_humanized_bytes("3192K"), Some(3192 * 1024));
        assert_eq!(parse_humanized_bytes("14M"), Some(14 * 1024 * 1024));
        assert_eq!(parse_humanized_bytes("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_humanized_bytes("junk"), None);
        assert_eq!(parse_humanized_bytes(""), None);
        assert_eq!(parse_humanized_bytes("K"), None);
    }

    #[test]
    fn usage_parser_rejects_output_without_the_keys() {
        assert_eq!(parse_usage("nonsense\n"), None);
        assert_eq!(
            parse_usage("cputime=3\n"),
            None,
            "memoryuse is required too"
        );
        assert_eq!(parse_usage("cputime=lots\nmemoryuse=1G\n"), None);
    }

    #[tokio::test]
    async fn usage_queries_the_jail_and_parses() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_USAGE, "");
        let rctl = Rctl::with_runner(&mock, true);
        let usage = rctl.usage(JAIL).await.unwrap().expect("a live jail");
        assert_eq!(usage.cpu_seconds, 1);
        assert_eq!(usage.memory_bytes, 3192 * 1024);
        assert_eq!(mock.calls(), [format!("/usr/bin/rctl -hu jail:{JAIL}")]);
    }

    #[tokio::test]
    async fn usage_runs_nothing_with_racct_off() {
        let mock = MockRunner::new();
        let rctl = Rctl::with_runner(&mock, false);
        assert_eq!(rctl.usage(JAIL).await.unwrap(), None);
        assert!(mock.calls().is_empty(), "no rctl process may be spawned");
    }

    /// The jail can vanish between the collector's listing and the read; a
    /// missing subject (`No such process`) is an empty result, not an error.
    #[tokio::test]
    async fn usage_of_a_vanished_jail_is_none_not_an_error() {
        let mock = MockRunner::new();
        mock.push_output(
            1,
            "",
            &format!(
                "rctl: failed to show resource consumption for 'jail:{JAIL}': No such process\n"
            ),
        );
        let rctl = Rctl::with_runner(&mock, true);
        assert_eq!(rctl.usage(JAIL).await.unwrap(), None);
    }

    /// A parse failure must carry the argv and the raw output (CLAUDE.md).
    #[tokio::test]
    async fn usage_parse_error_carries_command_line_and_raw_output() {
        let mock = MockRunner::new();
        mock.push_output(0, "garbage\n", "");
        let rctl = Rctl::with_runner(&mock, true);
        let err = rctl.usage(JAIL).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("-hu"), "{msg}");
        assert!(msg.contains("garbage"), "{msg}");
    }

    #[tokio::test]
    async fn rctl_failure_carries_argv_status_and_stderr() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_RCTL_DISABLED);
        let rctl = Rctl::with_runner(&mock, true);
        let err = rctl.apply_limits(JAIL, Some(1024), None).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&format!(
                "/usr/bin/rctl -a jail:{JAIL}:memoryuse:sigkill=1024"
            )),
            "{msg}"
        );
        assert!(msg.contains("exit code 1"), "{msg}");
        assert!(msg.contains("but disabled"), "{msg}");
    }

    // ---- rule listing and the orphan purge ---------------------------------

    /// Real captured output (FreeBSD 15.1, racct on, cluster node1,
    /// 2026-08-17): `rctl` with no arguments prints one rule per line, no
    /// header. At capture time `jail:1hvy0lj3x0b883f8e30fyp217` was already
    /// dead — its rule survived the jail, the orphan this purge exists for —
    /// while `jail:ghosttest` was a live third-party jail and `user:freebsd`
    /// a non-jail subject; both must always be left alone.
    const FIXTURE_LIST: &str = include_str!("../tests/fixtures/rctl_list.txt");

    /// SatL-shaped (25-char base36) and live at capture time.
    const LIVE_JAIL: &str = "24ceq6bf9xx2dzm0e4bcccwe6";
    /// SatL-shaped and already dead at capture time.
    const DEAD_JAIL: &str = "1hvy0lj3x0b883f8e30fyp217";

    #[test]
    fn rule_list_parser_returns_every_rule_line() {
        let rules = parse_rule_list(FIXTURE_LIST);
        assert_eq!(rules.len(), 5, "five rules, no header line: {rules:?}");
        assert_eq!(rules[0], "user:freebsd:maxproc:deny=100");
        assert_eq!(
            rules[4],
            format!("jail:{LIVE_JAIL}:memoryuse:sigkill=268435456")
        );
        assert_eq!(parse_rule_list(""), Vec::<String>::new());
        assert_eq!(parse_rule_list("\n  \n"), Vec::<String>::new());
    }

    #[tokio::test]
    async fn list_rules_runs_bare_rctl_and_parses() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_LIST, "");
        let rctl = Rctl::with_runner(&mock, true);
        let rules = rctl.list_rules().await.unwrap();
        assert_eq!(rules.len(), 5);
        assert_eq!(mock.calls(), ["/usr/bin/rctl"]);
    }

    #[tokio::test]
    async fn list_rules_runs_nothing_with_racct_off() {
        let mock = MockRunner::new();
        let rctl = Rctl::with_runner(&mock, false);
        assert_eq!(rctl.list_rules().await.unwrap(), Vec::<String>::new());
        assert!(mock.calls().is_empty(), "no rctl process may be spawned");
    }

    /// The safety-critical property, pinned: a subject that is not a
    /// 25-char base36 jail name is NEVER selected, however dead it is —
    /// another tool may manage its own jails' rules.
    #[test]
    fn orphan_filter_never_selects_third_party_subjects() {
        let rules = parse_rule_list(FIXTURE_LIST);
        // Nobody is live: every SatL-shaped subject is an orphan, and the
        // third-party ones must still not appear.
        let orphans = orphan_satl_jail_rules(&rules, &BTreeSet::new());
        assert!(
            orphans.iter().all(|name| name.parse::<Id>().is_ok()),
            "only SatL-shaped names may be selected: {orphans:?}"
        );
        for third_party in ["ghosttest", "freebsd"] {
            assert!(
                !orphans.iter().any(|name| name == third_party),
                "third-party subject {third_party:?} selected: {orphans:?}"
            );
        }
        assert!(orphans.contains(&DEAD_JAIL.to_owned()));
        assert!(orphans.contains(&LIVE_JAIL.to_owned()));
    }

    #[test]
    fn orphan_filter_rejects_near_miss_shapes() {
        let rules = vec![
            "jail:ghosttest:memoryuse:sigkill=1".to_owned(),
            "jail:www:pcpu:deny=50".to_owned(),
            // 24 and 26 chars: close, but not the task-id shape.
            "jail:1hvy0lj3x0b883f8e30fyp21:memoryuse:sigkill=1".to_owned(),
            "jail:1hvy0lj3x0b883f8e30fyp2172:memoryuse:sigkill=1".to_owned(),
            // Uppercase is not base36.
            "jail:1HVY0LJ3X0B883F8E30FYP217:memoryuse:sigkill=1".to_owned(),
            // Not a jail subject at all.
            "user:1hvy0lj3x0b883f8e30fyp217:maxproc:deny=10".to_owned(),
            "process:1234:memoryuse:sigkill=1".to_owned(),
            // No resource part: not a rule line.
            "jail:1hvy0lj3x0b883f8e30fyp217".to_owned(),
        ];
        assert_eq!(
            orphan_satl_jail_rules(&rules, &BTreeSet::new()),
            Vec::<String>::new()
        );
    }

    #[test]
    fn orphan_filter_keeps_the_live_and_dedups_the_dead() {
        let rules = parse_rule_list(FIXTURE_LIST);
        let live = BTreeSet::from([LIVE_JAIL.to_owned()]);
        // LIVE_JAIL has two rules in the fixture; DEAD_JAIL one. The live
        // jail's rules stay; the dead one is selected exactly once.
        assert_eq!(orphan_satl_jail_rules(&rules, &live), [DEAD_JAIL]);
    }

    #[tokio::test]
    async fn purge_removes_a_dead_satl_jails_rules_and_reports_it() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_LIST, "");
        mock.push_ok();
        let rctl = Rctl::with_runner(&mock, true);
        let live = BTreeSet::from([LIVE_JAIL.to_owned()]);
        let purged = rctl.purge_orphan_rules(&live).await.unwrap();
        assert_eq!(purged, [DEAD_JAIL.to_owned()]);
        assert_eq!(
            mock.calls(),
            [
                "/usr/bin/rctl".to_owned(),
                format!("/usr/bin/rctl -r jail:{DEAD_JAIL}"),
            ]
        );
    }

    /// Warn-not-fail: one subject refusing removal must not keep the other
    /// orphans listed, and is not an error of the pass.
    #[tokio::test]
    async fn purge_continues_past_a_failed_removal() {
        let second_dead = "0hvy0lj3x0b883f8e30fyp217";
        let listing =
            format!("jail:{DEAD_JAIL}:memoryuse:sigkill=1\njail:{second_dead}:pcpu:deny=50\n");
        let mock = MockRunner::new();
        mock.push_output(0, &listing, "");
        // Subjects are purged in sorted order, so this failure is
        // second_dead's removal; DEAD_JAIL's must still run and succeed.
        mock.push_output(1, "", "rctl: some kernel refusal\n");
        mock.push_ok();
        let rctl = Rctl::with_runner(&mock, true);
        let purged = rctl.purge_orphan_rules(&BTreeSet::new()).await.unwrap();
        assert_eq!(purged, [DEAD_JAIL.to_owned()]);
        assert_eq!(
            mock.calls(),
            [
                "/usr/bin/rctl".to_owned(),
                format!("/usr/bin/rctl -r jail:{second_dead}"),
                format!("/usr/bin/rctl -r jail:{DEAD_JAIL}"),
            ]
        );
    }

    /// A listing that cannot be produced (racct raced off, permission
    /// problem) fails the pass; the caller degrades it to a warning.
    #[tokio::test]
    async fn purge_reports_a_listing_failure() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "rctl: some failure\n");
        let rctl = Rctl::with_runner(&mock, true);
        let err = rctl.purge_orphan_rules(&BTreeSet::new()).await.unwrap_err();
        assert!(err.to_string().contains("some failure"), "{err}");
    }

    #[tokio::test]
    async fn purge_runs_nothing_with_racct_off() {
        let mock = MockRunner::new();
        let rctl = Rctl::with_runner(&mock, false);
        assert_eq!(
            rctl.purge_orphan_rules(&BTreeSet::new()).await.unwrap(),
            Vec::<String>::new()
        );
        assert!(mock.calls().is_empty(), "no rctl process may be spawned");
    }
}
