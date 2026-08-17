// SPDX-License-Identifier: BSD-2-Clause
//! Docker HEALTHCHECK semantics for tasks (architecture §8.2), with the probe
//! running as `ocijail exec` inside the task's jail.
//!
//! Two halves, deliberately separated: everything that *decides* is a pure
//! function over probe outcomes ([`HealthTracker`]), and everything that
//! *executes* is the loop in [`Prober`] plus the [`ProbeRunner`] it drives.
//! The decision half is what has to match Docker exactly, so it is unit-tested
//! on its own.
//!
//! # What Docker actually does (moby `daemon/health.go`, read not remembered)
//!
//! - Defaults when the spec leaves a field unset: `interval` 30 s, `timeout`
//!   30 s, `retries` 3 (any value <= 0), `start_period` 0.
//! - The **first probe runs one interval after the container starts** — there
//!   is no probe at t=0. During the start period, while the container has
//!   never yet been healthy, Docker probes on the shorter `start_interval`
//!   (default 5 s) instead.
//! - A probe's result is its exit status: 0 is healthy, anything else is a
//!   failure. A probe that cannot be run at all, or that outlives `timeout`,
//!   is recorded as a failure with exit code `-1`
//!   ([`PROBE_UNRUNNABLE_EXIT_CODE`]) and the reason as its output.
//! - `retries` consecutive failures make the container **unhealthy**; a single
//!   success resets the streak and makes it **healthy** immediately.
//! - The health status starts as **starting**, and failures do not count
//!   toward the streak while it is `starting` *and* the probe began inside
//!   `start_period`. Once the container has been healthy once, `start_period`
//!   no longer protects it.
//! - `State.Health` carries the status, the failing streak and a bounded log
//!   of the last [`MAX_LOG_ENTRIES`] probe results, each with start/end time,
//!   exit code and up to [`MAX_OUTPUT_LEN`] bytes of output.
//!
//! # What SatL adds, because a task is not a container
//!
//! Health **gates `RUNNING`** (invariant #2's state machine is the spine): a
//! task with a healthcheck stays `STARTING` until its first probe succeeds, so
//! the embedded DNS responder — which only answers with `RUNNING` tasks — never
//! hands traffic to a container that has not passed a probe, and a rolling
//! update that waits for observed `RUNNING` waits for health for free. That is
//! SwarmKit's own model: its controller's `Start` blocks on the container
//! becoming healthy and returns `ErrContainerUnhealthy` if it goes unhealthy
//! first (SWK §15.2), and its `Wait` fails the task when a healthy container
//! later turns unhealthy. `satl_agent::controller` implements both, and the
//! restart supervisor replaces the failed task — there is no second
//! replacement path here.
//!
//! Health is **node-local and ephemeral** (invariant #1: a worker holds only
//! executor state): it lives in the [`HealthRegistry`] the executor owns, is
//! rebuilt from probes after a restart, and never enters the store. `satl ps`
//! and `satl inspect` read it from there; `docker service ps` shows no health
//! either.
//!
//! # Killing a probe that outlives its timeout
//!
//! A probe is `ocijail exec --detach --pid-file` (docs/ocijail.md §4.1), so the
//! probe process is not satld's child and its exit is harvested with the same
//! kqueue `NOTE_EXIT` watch as a container's. When the timeout fires the pid is
//! `SIGKILL`ed, not abandoned: a probe left running inside the jail holds
//! whatever the probe opened, and a container whose network stack still has TCP
//! control blocks in it keeps its prison `DYING` — and its rootfs busy — for
//! 2 x MSL (`docs/jail-teardown.md`). The in-flight pid is therefore shared
//! with [`Prober::stop`], which kills it before the jail is deleted rather than
//! dropping the future and hoping.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use satl_core::HealthConfig;
use satl_runtime::{CreateStdio, ExecSpec, Ocijail, StdioSink};
use tracing::Instrument as _;

/// Failure to set a probe up. Probe *results* are never errors — a probe that
/// cannot run is a failed probe (Docker's exit code `-1`) — so this covers only
/// the one thing that happens before any probe: recovering the container's own
/// `process` object.
#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    /// The bundle's `config.json` could not be read.
    #[error(
        "task {task_id}: cannot read the OCI bundle config at {path} to build a health probe: {source}"
    )]
    ReadConfig {
        /// The task being probed.
        task_id: String,
        /// The `config.json` path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The bundle's `config.json` did not parse.
    #[error("task {task_id}: the OCI bundle config at {path} does not parse: {reason}")]
    ParseConfig {
        /// The task being probed.
        task_id: String,
        /// The `config.json` path.
        path: PathBuf,
        /// Parser complaint.
        reason: String,
    },
}

/// Just enough of `config.json` to recover the container's `process` object.
#[derive(Debug, serde::Deserialize)]
struct BundleProcess {
    process: ExecSpec,
}

/// Build the probe's `process` object from the container's own `config.json`.
///
/// A Docker healthcheck probe is an exec that inherits the container's
/// environment, working directory and user, and the truthful source for those
/// three is the bundle SatL created the jail from — not the task spec, which
/// carries neither the image's env nor the resolved user. Reading it back also
/// means a probe works after a `satld` restart, where the controller adopts a
/// jail it never planned (architecture §7.2).
///
/// The argv is replaced per probe by [`ProbeRunner::probe`].
///
/// # Errors
///
/// [`HealthError`] when `config.json` cannot be read or parsed.
pub async fn probe_process(task_id: &str, bundle_dir: &Path) -> Result<ExecSpec, HealthError> {
    let path = bundle_dir.join("config.json");
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|source| HealthError::ReadConfig {
            task_id: task_id.to_owned(),
            path: path.clone(),
            source,
        })?;
    let config: BundleProcess =
        serde_json::from_slice(&bytes).map_err(|error| HealthError::ParseConfig {
            task_id: task_id.to_owned(),
            path: path.clone(),
            reason: error.to_string(),
        })?;
    let mut process = config.process;
    // A probe never gets a pty, whatever the container asked for.
    process.terminal = false;
    Ok(process)
}

/// Docker's default probe interval (`defaultProbeInterval`).
///
/// Defined in `satl_core::defaults` rather than here, because the
/// published-service defaults ([`satl_core::harden_published_probe`],
/// `docs/api-compat.md` #125) are expressed against it and two copies of a
/// number are one too many.
pub const DEFAULT_INTERVAL: Duration = satl_core::defaults::PROBE_INTERVAL;

/// Docker's default per-probe timeout (`defaultProbeTimeout`).
pub const DEFAULT_TIMEOUT: Duration = satl_core::defaults::PROBE_TIMEOUT;

/// Docker's default probe interval *during* the start period
/// (`defaultStartInterval`). Not configurable here — see
/// `docs/api-compat.md` #90.
pub const DEFAULT_START_INTERVAL: Duration = Duration::from_secs(5);

/// Docker's default retry count (`defaultProbeRetries`), used whenever the
/// spec asks for 0.
pub const DEFAULT_RETRIES: u32 = satl_core::defaults::PROBE_RETRIES;

/// How many probe results `State.Health.Log` keeps (`maxLogEntries`).
pub const MAX_LOG_ENTRIES: usize = 5;

/// How many bytes of a probe's output are kept (`maxOutputLen`).
pub const MAX_OUTPUT_LEN: usize = 4096;

/// Exit code Docker records for a probe that could not be run or that
/// exceeded its timeout.
pub const PROBE_UNRUNNABLE_EXIT_CODE: i32 = -1;

/// The shell a `CMD-SHELL` probe runs through (Docker's `getShell` on any
/// non-Windows platform).
pub const PROBE_SHELL: [&str; 2] = ["/bin/sh", "-c"];

/// `SIGKILL`, sent to a probe that outlived its timeout.
const SIGKILL: i32 = 9;

/// How long to wait for a killed probe to actually disappear before giving up
/// on observing it (the kill is a SIGKILL, so this is a formality that must
/// nevertheless not hang the prober).
const KILL_CONFIRM_WAIT: Duration = Duration::from_secs(2);

/// Docker's three health states (`State.Health.Status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// No probe has succeeded yet. Docker's `starting`; in SatL this is also
    /// exactly the window in which the task stays `STARTING`.
    Starting,
    /// The last probe succeeded.
    Healthy,
    /// `retries` consecutive probes failed outside the start period.
    Unhealthy,
}

impl HealthStatus {
    /// Docker's spelling, as it appears in `State.Health.Status` and in the
    /// `Status` column suffix.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
        }
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One probe result — Docker's `HealthcheckResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    /// When the probe was started.
    pub start: SystemTime,
    /// When its outcome was known.
    pub end: SystemTime,
    /// The probe's exit status, or [`PROBE_UNRUNNABLE_EXIT_CODE`] when it
    /// could not be run or timed out.
    pub exit_code: i32,
    /// Up to [`MAX_OUTPUT_LEN`] bytes of the probe's combined output (or the
    /// reason it produced none).
    pub output: String,
}

impl ProbeResult {
    /// Docker's only question about a result: was the exit status 0?
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }

    /// A result standing in for a probe that never ran (or never finished),
    /// with `reason` as its output — Docker's exit code `-1` case.
    #[must_use]
    pub fn unrunnable(start: SystemTime, end: SystemTime, reason: String) -> Self {
        Self {
            start,
            end,
            exit_code: PROBE_UNRUNNABLE_EXIT_CODE,
            output: truncate_output(reason),
        }
    }
}

/// Keep at most [`MAX_OUTPUT_LEN`] bytes, never splitting a UTF-8 character.
fn truncate_output(mut output: String) -> String {
    if output.len() <= MAX_OUTPUT_LEN {
        return output;
    }
    let mut cut = MAX_OUTPUT_LEN;
    while cut > 0 && !output.is_char_boundary(cut) {
        cut -= 1;
    }
    output.truncate(cut);
    output
}

/// Docker's `State.Health` for one task: node-local, ephemeral, never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskHealth {
    /// Current status.
    pub status: HealthStatus,
    /// Consecutive failures so far (reset by any success).
    pub failing_streak: u32,
    /// The last [`MAX_LOG_ENTRIES`] probe results, oldest first.
    pub log: Vec<ProbeResult>,
}

impl Default for TaskHealth {
    fn default() -> Self {
        Self {
            status: HealthStatus::Starting,
            failing_streak: 0,
            log: Vec::new(),
        }
    }
}

/// A healthcheck resolved into the values the prober actually uses: Docker's
/// defaults applied, and `test` reduced to the argv to exec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSettings {
    /// The probe's argv inside the jail (already shell-wrapped for
    /// `CMD-SHELL`).
    pub argv: Vec<String>,
    /// Time between probes.
    pub interval: Duration,
    /// Per-probe timeout.
    pub timeout: Duration,
    /// Consecutive failures needed to become unhealthy (never 0).
    pub retries: u32,
    /// Window after the container started in which failures do not count.
    pub start_period: Duration,
}

/// What a [`HealthConfig`] resolves to. Docker treats a healthcheck it cannot
/// understand exactly like no healthcheck at all (a warning and nothing else),
/// so the caller must be able to tell the two apart to log that warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResolution {
    /// No healthcheck: absent, `["NONE"]`, empty, or a `CMD`/`CMD-SHELL` with
    /// nothing to run.
    Disabled,
    /// `test[0]` is not one Docker defines. Docker warns and runs no probe.
    Unknown {
        /// The unrecognized `test[0]`.
        kind: String,
    },
    /// A healthcheck to run.
    Enabled(ProbeSettings),
}

impl ProbeSettings {
    /// Resolve a [`HealthConfig`] the way Docker's `getProbe` +
    /// `timeoutWithDefault` do.
    #[must_use]
    pub fn resolve(config: &HealthConfig) -> ProbeResolution {
        let Some((kind, rest)) = config.test.split_first() else {
            return ProbeResolution::Disabled;
        };
        let shell = match kind.as_str() {
            // Docker: `""` means "inherit from the image", which for a task
            // spec means nothing to run.
            "NONE" | "" => return ProbeResolution::Disabled,
            "CMD" => false,
            "CMD-SHELL" => true,
            other => {
                return ProbeResolution::Unknown {
                    kind: other.to_owned(),
                };
            }
        };
        // `["CMD"]` / `["CMD-SHELL"]` with nothing after it: nothing to exec.
        if rest.is_empty() {
            return ProbeResolution::Disabled;
        }
        let mut argv = Vec::with_capacity(rest.len() + PROBE_SHELL.len());
        if shell {
            argv.extend(PROBE_SHELL.iter().map(|word| (*word).to_owned()));
        }
        argv.extend(rest.iter().cloned());
        ProbeResolution::Enabled(Self {
            argv,
            interval: positive_or(config.interval, DEFAULT_INTERVAL),
            timeout: positive_or(config.timeout, DEFAULT_TIMEOUT),
            retries: if config.retries == 0 {
                DEFAULT_RETRIES
            } else {
                config.retries
            },
            start_period: config.start_period.unwrap_or(Duration::ZERO),
        })
    }
}

/// Docker's `timeoutWithDefault`: a zero or absent duration means the default.
fn positive_or(value: Option<Duration>, default: Duration) -> Duration {
    match value {
        Some(value) if value > Duration::ZERO => value,
        _ => default,
    }
}

// ---------------------------------------------------------------------------
// The decision half: a pure fold of probe outcomes (Docker's
// `handleProbeResult` + `monitor`'s `getInterval`).
// ---------------------------------------------------------------------------

/// A status change produced by [`HealthTracker::record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthTransition {
    /// Status before the probe.
    pub from: HealthStatus,
    /// Status after it.
    pub to: HealthStatus,
}

/// Folds probe results into a [`TaskHealth`]. No I/O, no clock of its own —
/// every time it needs comes from the caller, so the whole Docker rule set is
/// exercised by table-driven unit tests.
#[derive(Debug, Clone)]
pub struct HealthTracker {
    settings: ProbeSettings,
    /// When the container was started, i.e. the origin of `start_period`.
    started_at: SystemTime,
    health: TaskHealth,
}

impl HealthTracker {
    /// A tracker for a container started at `started_at`.
    #[must_use]
    pub fn new(settings: ProbeSettings, started_at: SystemTime) -> Self {
        Self {
            settings,
            started_at,
            health: TaskHealth::default(),
        }
    }

    /// The health as it stands.
    #[must_use]
    pub fn health(&self) -> &TaskHealth {
        &self.health
    }

    /// The resolved settings this tracker was built with.
    #[must_use]
    pub fn settings(&self) -> &ProbeSettings {
        &self.settings
    }

    /// Record one probe result, returning the status change if there was one.
    ///
    /// Docker's `handleProbeResult`, rule for rule: the log is bounded, a
    /// success clears the streak and makes the container healthy at once, and a
    /// failure only counts toward the streak unless the container has never
    /// been healthy *and* the probe started inside `start_period`.
    pub fn record(&mut self, result: ProbeResult) -> Option<HealthTransition> {
        let from = self.health.status;
        if self.health.log.len() >= MAX_LOG_ENTRIES {
            let drop = self.health.log.len() + 1 - MAX_LOG_ENTRIES;
            self.health.log.drain(..drop);
        }
        let success = result.is_success();
        let in_start_period = self.within_start_period(result.start);
        self.health.log.push(result);
        // dockerd counts every probe and every failure under its own names;
        // a dashboard diffing SatL against Docker must see the same shape.
        satl_metrics::record_health_check(!success);

        if success {
            self.health.failing_streak = 0;
            self.health.status = HealthStatus::Healthy;
        } else if from == HealthStatus::Starting && in_start_period {
            // Inside the start period and never yet healthy: the failure is
            // recorded in the log but does not count against `retries`.
        } else {
            self.health.failing_streak = self.health.failing_streak.saturating_add(1);
            if self.health.failing_streak >= self.settings.retries {
                self.health.status = HealthStatus::Unhealthy;
            }
        }
        let to = self.health.status;
        (from != to).then_some(HealthTransition { from, to })
    }

    /// How long to wait before the next probe (Docker's `getInterval`).
    ///
    /// The start period gets the shorter start interval while the container has
    /// never been healthy, so a slow starter is not held back by a long
    /// `interval`. Docker uses its configurable `start_interval` here; SatL
    /// uses `min(interval, 5 s)` because the spec carries no such field
    /// (`docs/api-compat.md` #90) — never slower than what the operator asked
    /// for.
    #[must_use]
    pub fn next_delay(&self, now: SystemTime) -> Duration {
        if self.health.status == HealthStatus::Starting && self.within_start_period(now) {
            return self.settings.interval.min(DEFAULT_START_INTERVAL);
        }
        self.settings.interval
    }

    /// Whether `when` falls inside the start period.
    fn within_start_period(&self, when: SystemTime) -> bool {
        if self.settings.start_period.is_zero() {
            return false;
        }
        when.duration_since(self.started_at)
            .is_ok_and(|elapsed| elapsed < self.settings.start_period)
    }
}

// ---------------------------------------------------------------------------
// The node-local registry `satl ps` / `satl inspect` read.
// ---------------------------------------------------------------------------

/// Every task's health on this node.
///
/// Node-local by construction (invariant #1): the executor owns one, the
/// prober writes into it, the REST backend reads from it, and nothing
/// serializes it anywhere. A task with no entry has no healthcheck (or has not
/// started yet), which renders as no `State.Health` at all — exactly what
/// Docker does for a container without a HEALTHCHECK.
#[derive(Debug, Default)]
pub struct HealthRegistry {
    tasks: Mutex<BTreeMap<String, TaskHealth>>,
}

impl HealthRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// One task's health, if it has a healthcheck running on this node.
    #[must_use]
    pub fn get(&self, task_id: &str) -> Option<TaskHealth> {
        self.lock().get(task_id).cloned()
    }

    /// Publish `health` for `task_id`.
    pub fn set(&self, task_id: &str, health: TaskHealth) {
        self.lock().insert(task_id.to_owned(), health);
    }

    /// Forget a task (its prober stopped, or the task was removed).
    pub fn clear(&self, task_id: &str) {
        self.lock().remove(task_id);
    }

    /// How many tasks are tracked (tests, and the leftovers audit).
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether nothing is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The lock is only ever held for a map operation, never across an await.
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, TaskHealth>> {
        self.tasks
            .lock()
            // A poisoned lock means a panic while holding it, which cannot
            // happen for a map insert/remove; recover rather than propagate a
            // panic into an unrelated task.
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

// ---------------------------------------------------------------------------
// The execution half: one probe attempt, and the loop that schedules them.
// ---------------------------------------------------------------------------

/// Runs one probe attempt and guarantees nothing survives it.
///
/// A seam rather than a free function so the scheduling loop — intervals, the
/// start period, the stop path — is unit-testable against a fake without root,
/// a jail or an image.
pub trait ProbeRunner: Send + Sync + 'static {
    /// Run the probe once, bounded by `settings.timeout`. Never returns before
    /// the probe process is gone: a probe that outlives the timeout is killed.
    fn probe(
        &self,
        settings: &ProbeSettings,
    ) -> impl std::future::Future<Output = ProbeResult> + Send;

    /// Kill the probe that is in flight right now, if any.
    ///
    /// Called by [`Prober::stop`] before the jail is deleted: the probe's
    /// future is *not* simply dropped, because dropping it would leave the
    /// process running inside the jail (it is not our child).
    fn kill_in_flight(&self);
}

/// The production [`ProbeRunner`]: `ocijail exec --detach` into the task's
/// jail, exit harvested by kqueue `NOTE_EXIT`, output captured to a file.
#[derive(Debug)]
pub struct OcijailProbeRunner {
    ocijail: Ocijail,
    /// Jail name = task id (the pinned M1 contract).
    jail_id: String,
    /// The container's own `process` object, argv replaced per probe: a probe
    /// runs with the container's env, cwd and user, as Docker's does.
    process: ExecSpec,
    /// `<state_dir>/health/<task_id>`: the probe's pid file and output sink.
    dir: PathBuf,
    /// The probe currently running, for [`ProbeRunner::kill_in_flight`].
    in_flight: Arc<Mutex<Option<i32>>>,
}

impl OcijailProbeRunner {
    /// A runner for `jail_id`, executing `process` (argv replaced per probe)
    /// and keeping its scratch files in `dir`.
    #[must_use]
    pub fn new(ocijail: Ocijail, jail_id: String, process: ExecSpec, dir: PathBuf) -> Self {
        Self {
            ocijail,
            jail_id,
            process,
            dir,
            in_flight: Arc::new(Mutex::new(None)),
        }
    }

    fn set_in_flight(&self, pid: Option<i32>) {
        *self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = pid;
    }

    fn in_flight_pid(&self) -> Option<i32> {
        *self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Open the per-probe output sink, truncated: only the last probe's output
    /// is ever of interest, and the file must be readable so its content can be
    /// read back into the health log.
    async fn open_output(&self) -> std::io::Result<std::fs::File> {
        tokio::fs::create_dir_all(&self.dir).await?;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(self.dir.join("probe.out"))
    }

    /// Read back what the probe wrote, bounded.
    async fn read_output(path: PathBuf) -> String {
        match tokio::fs::read(&path).await {
            Ok(bytes) => truncate_output(String::from_utf8_lossy(&bytes).into_owned()),
            Err(error) => {
                tracing::debug!(path = %path.display(), %error, "cannot read probe output");
                String::new()
            }
        }
    }
}

/// `SIGKILL` a probe that outlived its timeout and wait (briefly) for it to be
/// gone.
///
/// The confirmation is the point: the reason a timed-out probe is killed rather
/// than abandoned is that a process left inside a jail keeps whatever it opened
/// open, and a container whose VNET still holds TCP control blocks keeps its
/// prison dying — and its rootfs busy — for 2 x MSL
/// (`docs/jail-teardown.md`). "Sent a signal" is not evidence; the process
/// being gone is.
async fn kill_probe(pid: i32) {
    match satl_runtime::signal_process(pid, SIGKILL) {
        Ok(true) => {
            let watched =
                tokio::time::timeout(KILL_CONFIRM_WAIT, satl_runtime::wait_for_exit(pid)).await;
            match watched {
                Ok(Ok(_)) => tracing::debug!(probe_pid = pid, "timed-out probe was killed"),
                Ok(Err(error)) => {
                    tracing::debug!(probe_pid = pid, %error, "cannot watch the killed probe");
                }
                Err(_elapsed) => tracing::warn!(
                    probe_pid = pid,
                    "a health probe is still there 2s after it was killed"
                ),
            }
        }
        Ok(false) => {
            tracing::debug!(probe_pid = pid, "timed-out probe was already gone");
        }
        Err(error) => tracing::warn!(probe_pid = pid, %error, "cannot kill a timed-out probe"),
    }
}

impl ProbeRunner for OcijailProbeRunner {
    async fn probe(&self, settings: &ProbeSettings) -> ProbeResult {
        let start = SystemTime::now();
        let unrunnable = |reason: String| ProbeResult::unrunnable(start, SystemTime::now(), reason);

        let output_file = match self.open_output().await {
            Ok(file) => file,
            Err(error) => {
                return unrunnable(format!("cannot open the probe output file: {error}"));
            }
        };
        let stderr_sink = match output_file.try_clone() {
            Ok(clone) => clone,
            Err(error) => {
                return unrunnable(format!("cannot duplicate the probe output file: {error}"));
            }
        };
        let stdio = CreateStdio {
            stdin: StdioSink::Null,
            stdout: StdioSink::File(output_file),
            stderr: StdioSink::File(stderr_sink),
        };
        let out_path = self.dir.join("probe.out");
        let pid_file = self.dir.join("probe.pid");
        // A stale pid file must never be mistaken for this probe's.
        let _ = tokio::fs::remove_file(&pid_file).await;

        let mut process = self.process.clone();
        process.args = settings.argv.clone();
        let pid = match self
            .ocijail
            .exec_detached(&self.jail_id, &process, stdio, &pid_file)
            .await
        {
            Ok(pid) => pid,
            Err(error) => {
                // Docker records a probe it could not run as exit code -1 with
                // the reason as output; the argv and stderr are in `error`.
                return unrunnable(format!("health check could not be run: {error}"));
            }
        };
        self.set_in_flight(Some(pid));
        let watched =
            tokio::time::timeout(settings.timeout, satl_runtime::wait_for_exit(pid)).await;
        let result = match watched {
            Ok(Ok(status)) => {
                self.set_in_flight(None);
                let output = Self::read_output(out_path).await;
                ProbeResult {
                    start,
                    end: SystemTime::now(),
                    exit_code: probe_exit_code(status),
                    output,
                }
            }
            Ok(Err(error)) => {
                self.set_in_flight(None);
                unrunnable(format!("cannot harvest the probe exit status: {error}"))
            }
            Err(_elapsed) => {
                // Docker's exact wording for this case.
                kill_probe(pid).await;
                self.set_in_flight(None);
                unrunnable(format!(
                    "Health check exceeded timeout ({})",
                    go_duration(settings.timeout)
                ))
            }
        };
        let _ = tokio::fs::remove_file(&pid_file).await;
        result
    }

    fn kill_in_flight(&self) {
        let Some(pid) = self.in_flight_pid() else {
            return;
        };
        match satl_runtime::signal_process(pid, SIGKILL) {
            Ok(killed) => tracing::debug!(
                probe_pid = pid,
                killed,
                "killed the in-flight health probe before tearing the task down"
            ),
            Err(error) => tracing::warn!(
                probe_pid = pid,
                %error,
                "cannot kill the in-flight health probe"
            ),
        }
        self.set_in_flight(None);
    }
}

/// The exit status a probe result carries: the code when it exited, the
/// shell's `128 + signal` when it was killed, and Docker's `-1` when nothing
/// could be harvested.
fn probe_exit_code(status: satl_runtime::ExitStatus) -> i32 {
    match (status.code, status.signal) {
        (Some(code), _) => code,
        (_, Some(signal)) => 128 + signal,
        _ => PROBE_UNRUNNABLE_EXIT_CODE,
    }
}

/// How long [`Prober::stop`] waits for the loop to finish after it has been
/// told to stop and its in-flight probe has been killed. Generous enough to
/// cover a probe that is mid-exec, short enough not to stall the assignment
/// stream (a removal is applied inline on it).
const STOP_WAIT: Duration = Duration::from_secs(5);

/// The per-task health prober: one tokio task looping probe attempts, keeping
/// the [`HealthRegistry`] current and publishing every status change on a watch
/// channel the controller waits on.
#[derive(Debug)]
pub struct Prober<P: ProbeRunner> {
    task_id: String,
    runner: Arc<P>,
    status: tokio::sync::watch::Receiver<HealthStatus>,
    stop: tokio::sync::watch::Sender<bool>,
    /// `None` once [`Prober::stop`] has joined the loop; the [`Drop`] impl
    /// needs the handle to be takeable, and a type with a `Drop` impl cannot
    /// have a field moved out of it.
    join: Option<tokio::task::JoinHandle<()>>,
}

impl<P: ProbeRunner> Drop for Prober<P> {
    /// A prober that is dropped rather than stopped — the daemon shutdown path
    /// drops the controller without removing its tasks, because a running jail
    /// is meant to survive a `satld` restart — must still not leave a probe
    /// process inside that jail. Killing is a syscall, so it can be done here;
    /// the loop is then aborted, since nothing will read its results.
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.runner.kill_in_flight();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

impl<P: ProbeRunner> Prober<P> {
    /// Start probing `task_id`. `started_at` is when the container was
    /// started: the origin of `start_period`.
    pub fn spawn(
        task_id: String,
        runner: P,
        settings: ProbeSettings,
        started_at: SystemTime,
        registry: Arc<HealthRegistry>,
    ) -> Self {
        let (status_tx, status) = tokio::sync::watch::channel(HealthStatus::Starting);
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let runner = Arc::new(runner);
        // A root span on purpose. The prober is spawned from inside the
        // controller's `task_step{step="start"}` span but outlives it by the
        // whole life of the container, so inheriting it would attribute a
        // health change half an hour later to a `start` that finished long ago
        // and break grep-by-step (CLAUDE.md observability).
        let span = tracing::info_span!(parent: None, "health", task_id = %task_id);
        let join = tokio::spawn(
            run_prober(
                task_id.clone(),
                Arc::clone(&runner),
                settings,
                started_at,
                registry,
                status_tx,
                stop_rx,
            )
            .instrument(span),
        );
        Self {
            task_id,
            runner,
            status,
            stop,
            join: Some(join),
        }
    }

    /// The last published status.
    #[must_use]
    pub fn status(&self) -> HealthStatus {
        *self.status.borrow()
    }

    /// Wait until the health status leaves `starting` — the gate `start` gets
    /// its verdict from. `None` means the prober task itself is gone, which is
    /// a bug and must be reported rather than waited on forever.
    pub async fn wait_until_decided(&mut self) -> Option<HealthStatus> {
        self.status
            .wait_for(|status| *status != HealthStatus::Starting)
            .await
            .ok()
            .map(|status| *status)
    }

    /// Wait until the task is `unhealthy` (it already passed a probe once).
    /// `None` means the prober task is gone.
    pub async fn wait_until_unhealthy(&mut self) -> Option<()> {
        self.status
            .wait_for(|status| *status == HealthStatus::Unhealthy)
            .await
            .ok()
            .map(|_| ())
    }

    /// Stop probing, killing whatever probe is in flight **before** returning.
    ///
    /// Order matters: the flag first (so the loop cannot start another probe),
    /// then the kill (so the current one dies now rather than at its timeout),
    /// then the join. Dropping the loop's future instead would leave a probe
    /// process inside a jail that is about to be deleted, which is how a prison
    /// ends up dying for 2 x MSL with the rootfs busy (`docs/jail-teardown.md`).
    ///
    /// The registry entry is deliberately **kept**: a task that failed its
    /// healthcheck must still be able to show why in `satl inspect`. The
    /// controller clears it when the task is removed.
    pub async fn stop(mut self) {
        let _ = self.stop.send(true);
        self.runner.kill_in_flight();
        let Some(join) = self.join.take() else {
            return;
        };
        match tokio::time::timeout(STOP_WAIT, join).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(task_id = %self.task_id, %error, "the health prober panicked");
            }
            Err(_elapsed) => tracing::warn!(
                task_id = %self.task_id,
                "the health prober did not stop within 5s; abandoning it"
            ),
        }
    }
}

/// The prober loop. Docker's `monitor`: wait an interval, probe, fold the
/// result in, publish.
async fn run_prober<P: ProbeRunner>(
    task_id: String,
    runner: Arc<P>,
    settings: ProbeSettings,
    started_at: SystemTime,
    registry: Arc<HealthRegistry>,
    status: tokio::sync::watch::Sender<HealthStatus>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut tracker = HealthTracker::new(settings, started_at);
    // Publish "starting" at once: a task being probed must be visible as such
    // before its first probe, not only after it.
    registry.set(&task_id, tracker.health().clone());
    tracing::info!(
        interval_ms = u64::try_from(tracker.settings().interval.as_millis()).unwrap_or(u64::MAX),
        timeout_ms = u64::try_from(tracker.settings().timeout.as_millis()).unwrap_or(u64::MAX),
        retries = tracker.settings().retries,
        start_period_ms =
            u64::try_from(tracker.settings().start_period.as_millis()).unwrap_or(u64::MAX),
        "health probing started"
    );
    loop {
        let delay = tracker.next_delay(SystemTime::now());
        tokio::select! {
            _ = stop.changed() => break,
            () = tokio::time::sleep(delay) => {}
        }
        if *stop.borrow_and_update() {
            break;
        }
        let result = runner.probe(tracker.settings()).await;
        // A stop that arrived while the probe ran: its result is about a task
        // that is being torn down, so do not fold it in.
        if *stop.borrow_and_update() {
            break;
        }
        let exit_code = result.exit_code;
        let transition = tracker.record(result);
        let health = tracker.health().clone();
        registry.set(&task_id, health.clone());
        match transition {
            Some(HealthTransition { from, to }) if to == HealthStatus::Unhealthy => {
                tracing::warn!(
                    %from,
                    to = %to,
                    streak = health.failing_streak,
                    exit_code,
                    "task health changed: the healthcheck failed too many times"
                );
            }
            Some(HealthTransition { from, to }) => {
                tracing::info!(
                    %from,
                    to = %to,
                    streak = health.failing_streak,
                    exit_code,
                    "task health changed"
                );
            }
            None => tracing::debug!(
                status = %health.status,
                streak = health.failing_streak,
                exit_code,
                "health probe finished"
            ),
        }
        // Send unconditionally: the controller waits on a predicate, not on a
        // change, so a re-published identical status costs nothing and a lost
        // one would hang a start.
        if status.send(health.status).is_err() {
            // Every receiver is gone: the controller dropped its prober
            // without stopping it. Keep probing (the registry is still read by
            // `satl ps`) but say so, because it means a stop path was missed.
            tracing::debug!("nobody is listening for health changes any more");
        }
    }
    tracing::debug!("health probing stopped");
}

/// Render a duration the way Go's `%v` does for the durations Docker prints
/// (`2s`, `1m30s`, `500ms`) — the timeout message is compared against Docker's
/// verbatim, so its formatting matters.
fn go_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    if secs == 0 {
        return format!("{}ms", duration.as_millis());
    }
    let fraction = if millis == 0 {
        String::new()
    } else {
        format!(".{millis:03}")
    };
    if secs >= 60 {
        format!("{}m{}{fraction}s", secs / 60, secs % 60)
    } else {
        format!("{secs}{fraction}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `config.json` captured from this host's running `satld`
    /// (`/var/db/satl/bundles/<task>/config.json`), with a `process.user`
    /// block added so the inheritance of uid/gid is covered too.
    const FIXTURE_BUNDLE: &str = include_str!("../tests/fixtures/bundle_config.json");

    fn config(test: &[&str]) -> HealthConfig {
        HealthConfig {
            test: test.iter().map(|word| (*word).to_owned()).collect(),
            interval: None,
            timeout: None,
            retries: 0,
            start_period: None,
        }
    }

    fn enabled(config: &HealthConfig) -> ProbeSettings {
        match ProbeSettings::resolve(config) {
            ProbeResolution::Enabled(settings) => settings,
            other => panic!("expected an enabled probe, got {other:?}"),
        }
    }

    // ---- probe argv (Docker's CMD / CMD-SHELL forms) ----------------------

    /// `CMD` execs the argv as given: no shell, no word splitting.
    #[test]
    fn cmd_execs_the_argv_verbatim() {
        let settings = enabled(&config(&["CMD", "/bin/test", "-f", "/tmp/ready"]));
        assert_eq!(settings.argv, ["/bin/test", "-f", "/tmp/ready"]);
    }

    /// `CMD-SHELL` runs through `/bin/sh -c`, exactly as Docker's `getShell`
    /// does on every non-Windows platform.
    #[test]
    fn cmd_shell_runs_through_the_shell() {
        let settings = enabled(&config(&["CMD-SHELL", "test -f /tmp/ready || exit 1"]));
        assert_eq!(
            settings.argv,
            ["/bin/sh", "-c", "test -f /tmp/ready || exit 1"]
        );
    }

    /// Docker keeps every element after `CMD-SHELL`, so `$0` and friends
    /// behave as they do there.
    #[test]
    fn cmd_shell_keeps_extra_words_as_shell_arguments() {
        let settings = enabled(&config(&["CMD-SHELL", "echo \"$0\"", "probe"]));
        assert_eq!(settings.argv, ["/bin/sh", "-c", "echo \"$0\"", "probe"]);
    }

    #[test]
    fn none_empty_and_argument_less_forms_are_no_healthcheck() {
        for test in [
            vec![],
            vec!["NONE"],
            vec![""],
            vec!["CMD"],
            vec!["CMD-SHELL"],
        ] {
            let config = config(&test);
            assert_eq!(
                ProbeSettings::resolve(&config),
                ProbeResolution::Disabled,
                "{test:?}"
            );
        }
    }

    /// The control plane decides whether a *published* service has a probe at
    /// all, and it must not disagree with the resolver that actually runs one:
    /// a service warned about as unprobed that then gets probed (or the
    /// reverse) would be a lie in the operator's face. `HealthConfig::probes`
    /// is the cheap predicate; this pins the two together over one table.
    #[test]
    fn probes_agrees_with_the_resolver() {
        for test in [
            vec!["CMD", "/bin/true"],
            vec!["CMD-SHELL", "test -f /tmp/ready"],
            vec!["CMD-SHELL", "echo \"$0\"", "probe"],
            vec![],
            vec!["NONE"],
            vec![""],
            vec!["CMD"],
            vec!["CMD-SHELL"],
            vec!["cmd", "/bin/true"],
            vec!["HTTP-GET", "/healthz"],
        ] {
            let config = config(&test);
            let resolved = matches!(ProbeSettings::resolve(&config), ProbeResolution::Enabled(_));
            assert_eq!(
                config.probes(),
                resolved,
                "HealthConfig::probes and ProbeSettings::resolve disagree on {test:?}"
            );
        }
    }

    /// Docker warns and runs no probe for an unrecognized type; the caller
    /// needs to tell that apart from "no healthcheck" to log the warning.
    #[test]
    fn an_unknown_probe_type_is_reported_not_guessed() {
        assert_eq!(
            ProbeSettings::resolve(&config(&["HTTP-GET", "/healthz"])),
            ProbeResolution::Unknown {
                kind: "HTTP-GET".to_owned()
            }
        );
    }

    // ---- defaults (moby `daemon/health.go`) ------------------------------

    #[test]
    fn unset_fields_take_dockers_defaults() {
        let settings = enabled(&config(&["CMD", "/bin/true"]));
        assert_eq!(settings.interval, DEFAULT_INTERVAL);
        assert_eq!(settings.timeout, DEFAULT_TIMEOUT);
        assert_eq!(settings.retries, DEFAULT_RETRIES);
        assert_eq!(settings.start_period, Duration::ZERO);
    }

    #[test]
    fn zero_durations_and_zero_retries_also_mean_the_default() {
        let mut config = config(&["CMD", "/bin/true"]);
        config.interval = Some(Duration::ZERO);
        config.timeout = Some(Duration::ZERO);
        config.retries = 0;
        let settings = enabled(&config);
        assert_eq!(settings.interval, DEFAULT_INTERVAL);
        assert_eq!(settings.timeout, DEFAULT_TIMEOUT);
        assert_eq!(settings.retries, DEFAULT_RETRIES);
    }

    #[test]
    fn explicit_values_are_kept() {
        let mut config = config(&["CMD", "/bin/true"]);
        config.interval = Some(Duration::from_millis(250));
        config.timeout = Some(Duration::from_secs(3));
        config.retries = 2;
        config.start_period = Some(Duration::from_secs(30));
        let settings = enabled(&config);
        assert_eq!(settings.interval, Duration::from_millis(250));
        assert_eq!(settings.timeout, Duration::from_secs(3));
        assert_eq!(settings.retries, 2);
        assert_eq!(settings.start_period, Duration::from_secs(30));
    }

    // ---- the retries / start_period state machine -------------------------

    /// t=0 for every tracker test below: the tracker only ever compares
    /// instants, so any fixed origin does.
    fn epoch() -> SystemTime {
        SystemTime::UNIX_EPOCH
    }

    fn settings(retries: u32, start_period: Duration) -> ProbeSettings {
        ProbeSettings {
            argv: vec!["/bin/true".to_owned()],
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            retries,
            start_period,
        }
    }

    /// A probe result that started `at` seconds after the container did.
    fn probe(at_secs: u64, exit_code: i32) -> ProbeResult {
        let start = epoch() + Duration::from_secs(at_secs);
        ProbeResult {
            start,
            end: start + Duration::from_millis(10),
            exit_code,
            output: String::new(),
        }
    }

    #[test]
    fn a_fresh_tracker_is_starting_with_no_streak() {
        let tracker = HealthTracker::new(settings(3, Duration::ZERO), epoch());
        assert_eq!(tracker.health().status, HealthStatus::Starting);
        assert_eq!(tracker.health().failing_streak, 0);
        assert!(tracker.health().log.is_empty());
    }

    /// The first success is what the RUNNING gate waits for, and it arrives on
    /// the first passing probe — not after `retries` of them.
    #[test]
    fn the_first_success_is_healthy_at_once() {
        let mut tracker = HealthTracker::new(settings(3, Duration::ZERO), epoch());
        assert_eq!(
            tracker.record(probe(1, 0)),
            Some(HealthTransition {
                from: HealthStatus::Starting,
                to: HealthStatus::Healthy
            })
        );
        assert_eq!(tracker.health().failing_streak, 0);
    }

    /// `retries` consecutive failures, and not one fewer, make a task unhealthy.
    #[test]
    fn retries_consecutive_failures_are_needed_to_become_unhealthy() {
        let mut tracker = HealthTracker::new(settings(3, Duration::ZERO), epoch());
        assert_eq!(tracker.record(probe(1, 1)), None);
        assert_eq!(tracker.health().status, HealthStatus::Starting);
        assert_eq!(tracker.health().failing_streak, 1);
        assert_eq!(tracker.record(probe(2, 1)), None);
        assert_eq!(tracker.health().failing_streak, 2);
        assert_eq!(
            tracker.record(probe(3, 1)),
            Some(HealthTransition {
                from: HealthStatus::Starting,
                to: HealthStatus::Unhealthy
            })
        );
        assert_eq!(tracker.health().failing_streak, 3);
    }

    /// A single success resets the streak, so failures must be *consecutive*.
    #[test]
    fn one_success_resets_the_streak() {
        let mut tracker = HealthTracker::new(settings(3, Duration::ZERO), epoch());
        tracker.record(probe(1, 1));
        tracker.record(probe(2, 1));
        tracker.record(probe(3, 0));
        assert_eq!(tracker.health().status, HealthStatus::Healthy);
        assert_eq!(tracker.health().failing_streak, 0);
        tracker.record(probe(4, 1));
        tracker.record(probe(5, 1));
        assert_eq!(
            tracker.health().status,
            HealthStatus::Healthy,
            "two failures after a success must not reach a retries=3 verdict"
        );
        assert_eq!(tracker.health().failing_streak, 2);
        assert_eq!(
            tracker.record(probe(6, 1)),
            Some(HealthTransition {
                from: HealthStatus::Healthy,
                to: HealthStatus::Unhealthy
            }),
            "and the third one does"
        );
    }

    /// Docker's start-period rule: while the container has never been healthy,
    /// failures inside the period are logged but do not count.
    #[test]
    fn failures_inside_the_start_period_do_not_count() {
        let mut tracker = HealthTracker::new(settings(2, Duration::from_secs(10)), epoch());
        for at in 1..=5 {
            assert_eq!(tracker.record(probe(at, 1)), None, "probe at {at}s");
            assert_eq!(tracker.health().failing_streak, 0, "probe at {at}s");
            assert_eq!(tracker.health().status, HealthStatus::Starting);
        }
        // The log still holds them: an operator has to see why it is not up.
        assert_eq!(tracker.health().log.len(), MAX_LOG_ENTRIES);
        // Past the period they count, and two of them are a verdict.
        assert_eq!(tracker.record(probe(11, 1)), None);
        assert_eq!(tracker.health().failing_streak, 1);
        assert_eq!(
            tracker.record(probe(12, 1)),
            Some(HealthTransition {
                from: HealthStatus::Starting,
                to: HealthStatus::Unhealthy
            })
        );
    }

    /// The start period protects a container that has *never* been healthy
    /// only. Once one probe passed, a failure counts even inside the window —
    /// this is the rule most easily got wrong, and Docker checks the status
    /// before it checks the clock.
    #[test]
    fn the_start_period_stops_protecting_once_healthy() {
        let mut tracker = HealthTracker::new(settings(2, Duration::from_mins(1)), epoch());
        tracker.record(probe(1, 0));
        assert_eq!(tracker.health().status, HealthStatus::Healthy);
        tracker.record(probe(2, 1));
        assert_eq!(tracker.health().failing_streak, 1);
        assert_eq!(
            tracker.record(probe(3, 1)),
            Some(HealthTransition {
                from: HealthStatus::Healthy,
                to: HealthStatus::Unhealthy
            }),
            "still inside the start period, but no longer starting"
        );
    }

    /// A probe that timed out or could not be run is a failure like any other
    /// (Docker records it as exit code -1).
    #[test]
    fn an_unrunnable_probe_counts_as_a_failure() {
        let mut tracker = HealthTracker::new(settings(1, Duration::ZERO), epoch());
        let start = epoch();
        let result = ProbeResult::unrunnable(
            start,
            start + Duration::from_secs(2),
            "Health check exceeded timeout (2s)".to_owned(),
        );
        assert!(!result.is_success());
        assert_eq!(result.exit_code, PROBE_UNRUNNABLE_EXIT_CODE);
        assert_eq!(
            tracker.record(result),
            Some(HealthTransition {
                from: HealthStatus::Starting,
                to: HealthStatus::Unhealthy
            })
        );
    }

    #[test]
    fn the_log_keeps_the_last_five_results_oldest_first() {
        let mut tracker = HealthTracker::new(settings(99, Duration::ZERO), epoch());
        for at in 1..=8 {
            tracker.record(probe(at, i32::try_from(at).unwrap()));
        }
        let log = &tracker.health().log;
        assert_eq!(log.len(), MAX_LOG_ENTRIES);
        assert_eq!(
            log.iter().map(|entry| entry.exit_code).collect::<Vec<_>>(),
            [4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn probe_output_is_truncated_on_a_character_boundary() {
        let long = "a".repeat(MAX_OUTPUT_LEN + 100);
        assert_eq!(truncate_output(long).len(), MAX_OUTPUT_LEN);
        // A multi-byte character straddling the limit is dropped whole rather
        // than cut in half.
        let mut multibyte = "b".repeat(MAX_OUTPUT_LEN - 1);
        multibyte.push('e');
        multibyte.push('e');
        let truncated = truncate_output(multibyte);
        assert!(truncated.len() <= MAX_OUTPUT_LEN);
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    // ---- probe scheduling -------------------------------------------------

    /// Docker's `getInterval`: the start period probes on the shorter start
    /// interval while the container has never been healthy, then settles on the
    /// configured interval.
    #[test]
    fn the_start_period_probes_more_often_than_the_interval() {
        let mut settings = settings(3, Duration::from_mins(1));
        settings.interval = Duration::from_secs(30);
        let mut tracker = HealthTracker::new(settings, epoch());
        assert_eq!(
            tracker.next_delay(epoch() + Duration::from_secs(1)),
            DEFAULT_START_INTERVAL
        );
        // Past the start period: the configured interval.
        assert_eq!(
            tracker.next_delay(epoch() + Duration::from_secs(61)),
            Duration::from_secs(30)
        );
        // Healthy inside the period: also the configured interval.
        tracker.record(probe(1, 0));
        assert_eq!(
            tracker.next_delay(epoch() + Duration::from_secs(2)),
            Duration::from_secs(30)
        );
    }

    /// An interval shorter than the start interval is never slowed down by it.
    #[test]
    fn a_short_interval_wins_over_the_start_interval() {
        let mut settings = settings(3, Duration::from_mins(1));
        settings.interval = Duration::from_millis(200);
        let tracker = HealthTracker::new(settings, epoch());
        assert_eq!(
            tracker.next_delay(epoch() + Duration::from_secs(1)),
            Duration::from_millis(200)
        );
    }

    #[test]
    fn with_no_start_period_the_interval_applies_from_the_first_probe() {
        let tracker = HealthTracker::new(settings(3, Duration::ZERO), epoch());
        assert_eq!(tracker.next_delay(epoch()), Duration::from_secs(1));
    }

    // ---- the timeout message ----------------------------------------------

    /// The timeout message is Docker's, including Go's duration formatting.
    #[test]
    fn the_timeout_message_matches_dockers() {
        assert_eq!(go_duration(Duration::from_secs(30)), "30s");
        assert_eq!(go_duration(Duration::from_secs(90)), "1m30s");
        assert_eq!(go_duration(Duration::from_millis(1500)), "1.500s");
        assert_eq!(go_duration(Duration::from_millis(250)), "250ms");
        let result = ProbeResult::unrunnable(
            epoch(),
            epoch(),
            format!(
                "Health check exceeded timeout ({})",
                go_duration(Duration::from_secs(2))
            ),
        );
        assert_eq!(result.output, "Health check exceeded timeout (2s)");
    }

    #[test]
    fn a_signal_death_is_reported_as_128_plus_signal() {
        assert_eq!(
            probe_exit_code(satl_runtime::ExitStatus {
                code: Some(3),
                signal: None
            }),
            3
        );
        assert_eq!(
            probe_exit_code(satl_runtime::ExitStatus {
                code: None,
                signal: Some(9)
            }),
            137
        );
        assert_eq!(
            probe_exit_code(satl_runtime::ExitStatus::unknown()),
            PROBE_UNRUNNABLE_EXIT_CODE
        );
    }

    // ---- the registry ------------------------------------------------------

    #[test]
    fn the_registry_holds_health_per_task_and_forgets_on_demand() {
        let registry = HealthRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.get("t1"), None);
        let health = TaskHealth {
            status: HealthStatus::Healthy,
            ..TaskHealth::default()
        };
        registry.set("t1", health.clone());
        assert_eq!(registry.get("t1"), Some(health));
        assert_eq!(registry.len(), 1);
        registry.clear("t1");
        assert!(registry.is_empty());
    }

    // ---- the probe process, from a real bundle config ---------------------

    /// A probe inherits the container's env, cwd and user from the bundle the
    /// jail was created with, so it runs in the same place as the workload.
    #[tokio::test]
    async fn the_probe_process_is_the_containers_own() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("config.json"), FIXTURE_BUNDLE)
            .await
            .unwrap();
        let process = probe_process("t1", dir.path()).await.unwrap();
        assert_eq!(process.cwd, "/srv");
        assert_eq!(
            process.env,
            ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
        );
        let user = process.user.expect("the container's user");
        assert_eq!((user.uid, user.gid), (80, 80));
        assert_eq!(user.additional_gids, [0]);
        assert!(!process.terminal, "a probe never gets a pty");
        // The argv is the container's until the prober replaces it per probe.
        assert_eq!(process.args[0], "/usr/local/sbin/nginx");
    }

    // ---- killing a probe: a real process, really killed -------------------

    /// The kill path, exercised against a real process (unprivileged: no jail
    /// needed to prove that a pid we did not fork dies and is *observed* to
    /// die).
    #[tokio::test]
    async fn a_timed_out_probe_is_killed_and_confirmed_gone() {
        use std::os::unix::process::ExitStatusExt as _;

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("/bin/sleep");
        let pid = i32::try_from(child.id()).unwrap();
        assert!(satl_runtime::signal_process(pid, 0).unwrap(), "alive first");
        kill_probe(pid).await;
        // The kqueue watch never reaps (satl_runtime::exit docs): in production
        // init reaps the reparented probe, in this test the process is our own
        // child, so reap it here and check *how* it died.
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(SIGKILL), "{status:?}");
    }

    // ---- the prober loop --------------------------------------------------

    /// A [`ProbeRunner`] that hands out scripted results, counts calls, and can
    /// pretend to hang until it is killed.
    #[derive(Debug)]
    struct FakeRunner {
        /// Exit codes to return, in order; the last one repeats forever.
        codes: Vec<i32>,
        calls: std::sync::atomic::AtomicUsize,
        /// When set, a probe blocks until `kill_in_flight` is called.
        hangs: bool,
        killed: Arc<tokio::sync::Notify>,
        kills: std::sync::atomic::AtomicUsize,
    }

    impl FakeRunner {
        fn new(codes: &[i32]) -> Self {
            Self {
                codes: codes.to_vec(),
                calls: std::sync::atomic::AtomicUsize::new(0),
                hangs: false,
                killed: Arc::new(tokio::sync::Notify::new()),
                kills: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn hanging() -> Self {
            Self {
                hangs: true,
                ..Self::new(&[0])
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn kill_count(&self) -> usize {
            self.kills.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl ProbeRunner for FakeRunner {
        async fn probe(&self, _settings: &ProbeSettings) -> ProbeResult {
            let nth = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let start = SystemTime::now();
            if self.hangs {
                // A probe that only ends when it is killed, as a timed-out one
                // does; never a bare sleep, so the test cannot pass on a timer.
                self.killed.notified().await;
                return ProbeResult::unrunnable(
                    start,
                    SystemTime::now(),
                    "killed while in flight".to_owned(),
                );
            }
            let code = *self
                .codes
                .get(nth)
                .or_else(|| self.codes.last())
                .unwrap_or(&0);
            ProbeResult {
                start,
                end: SystemTime::now(),
                exit_code: code,
                output: String::new(),
            }
        }

        fn kill_in_flight(&self) {
            self.kills.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.killed.notify_waiters();
        }
    }

    fn fast_settings(retries: u32) -> ProbeSettings {
        ProbeSettings {
            argv: vec!["/bin/true".to_owned()],
            interval: Duration::from_millis(20),
            timeout: Duration::from_secs(1),
            retries,
            start_period: Duration::ZERO,
        }
    }

    /// The gate's happy path: `starting` is published before any probe runs,
    /// and the first success is what releases it.
    #[tokio::test]
    async fn the_loop_publishes_starting_first_then_healthy() {
        let registry = Arc::new(HealthRegistry::new());
        let mut prober = Prober::spawn(
            "t1".to_owned(),
            FakeRunner::new(&[0]),
            fast_settings(3),
            SystemTime::now(),
            Arc::clone(&registry),
        );
        assert_eq!(prober.status(), HealthStatus::Starting);
        assert_eq!(
            prober.wait_until_decided().await,
            Some(HealthStatus::Healthy)
        );
        let health = registry.get("t1").expect("health published");
        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.failing_streak, 0);
        assert_eq!(health.log.len(), 1);
        prober.stop().await;
    }

    /// The loop folds failures the way the tracker says, and the verdict
    /// reaches the controller through the watch channel.
    #[tokio::test]
    async fn the_loop_reaches_unhealthy_after_retries_failures() {
        let registry = Arc::new(HealthRegistry::new());
        let mut prober = Prober::spawn(
            "t2".to_owned(),
            FakeRunner::new(&[1]),
            fast_settings(2),
            SystemTime::now(),
            Arc::clone(&registry),
        );
        assert_eq!(
            prober.wait_until_decided().await,
            Some(HealthStatus::Unhealthy)
        );
        let health = registry.get("t2").expect("health published");
        assert_eq!(health.failing_streak, 2);
        prober.stop().await;
        // The entry survives the prober: `satl inspect` on a failed task must
        // still show why it failed.
        assert_eq!(
            registry.get("t2").map(|health| health.status),
            Some(HealthStatus::Unhealthy)
        );
    }

    /// `stop` kills the probe that is in flight instead of dropping its future,
    /// and returns promptly — the whole point being that no probe process is
    /// left inside a jail that is about to be deleted.
    #[tokio::test]
    async fn stopping_the_prober_kills_the_probe_in_flight() {
        let registry = Arc::new(HealthRegistry::new());
        let prober = Prober::spawn(
            "t3".to_owned(),
            FakeRunner::hanging(),
            fast_settings(3),
            SystemTime::now(),
            Arc::clone(&registry),
        );
        // Let the loop get into its probe.
        let runner = Arc::clone(&prober.runner);
        for _ in 0..100 {
            if runner.call_count() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(runner.call_count(), 1, "the probe should be in flight");
        let started = std::time::Instant::now();
        prober.stop().await;
        // At least once by `stop`; the `Drop` impl kills again on the way out,
        // which in production is a no-op (`ESRCH`).
        assert!(
            runner.kill_count() >= 1,
            "the in-flight probe was not killed"
        );
        assert!(
            started.elapsed() < STOP_WAIT,
            "stop waited {:?}, which means it timed out rather than killing",
            started.elapsed()
        );
        // And nothing probes any more.
        let before = runner.call_count();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            runner.call_count(),
            before,
            "the loop kept probing after stop"
        );
    }

    /// A prober that is *dropped* rather than stopped still kills its probe:
    /// the daemon-shutdown path drops the controller without removing the task,
    /// and the jail survives that restart — a probe process left inside it
    /// would not be reaped by anything until the jail is finally deleted.
    #[tokio::test]
    async fn dropping_the_prober_also_kills_the_probe_in_flight() {
        let registry = Arc::new(HealthRegistry::new());
        let prober = Prober::spawn(
            "t4".to_owned(),
            FakeRunner::hanging(),
            fast_settings(3),
            SystemTime::now(),
            Arc::clone(&registry),
        );
        let runner = Arc::clone(&prober.runner);
        for _ in 0..100 {
            if runner.call_count() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(runner.call_count(), 1, "the probe should be in flight");
        drop(prober);
        assert_eq!(runner.kill_count(), 1);
        let before = runner.call_count();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(runner.call_count(), before, "the loop was not aborted");
    }

    #[tokio::test]
    async fn a_missing_or_broken_bundle_config_is_a_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = probe_process("t1", dir.path()).await.unwrap_err();
        assert!(matches!(error, HealthError::ReadConfig { .. }), "{error:?}");
        tokio::fs::write(dir.path().join("config.json"), b"{\"process\": 7}")
            .await
            .unwrap();
        let error = probe_process("t1", dir.path()).await.unwrap_err();
        assert!(
            matches!(error, HealthError::ParseConfig { .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains("config.json"), "{error}");
    }
}
