// SPDX-License-Identifier: BSD-2-Clause
//! The per-task controller (architecture §8.2, SWK §15.2): the only place
//! that touches a task's node-local resources.
//!
//! Lifecycle, and what each step owns:
//!
//! | Step | Work |
//! |---|---|
//! | `prepare` | resolve/pull image → apply layers → volumes/binds → clone rootfs → write bundle + open logs → `ocijail create` → rctl limits |
//! | `start` | attach the VNET epair → publish host ports → `ocijail start` → harvest pid/jid |
//! | `wait` | block on the kqueue exit watch armed at create time |
//! | `shutdown` | stop signal → grace period → SIGKILL → unpublish ports |
//! | `remove` | unpublish, detach, `ocijail delete` (+ mount sweep), destroy the clone, drop bundle/logs, drop rctl rules |
//!
//! **Re-entrancy is a hard requirement** (architecture §8.2/§7.2): after an
//! agent restart the controller is re-driven from the persisted status, so
//! every step probes before it acts and adopts what already exists. `remove`
//! is additionally the reconciliation cleaner: each of its steps tolerates
//! "already gone", so it can be run against a task that never got past
//! `prepare`.
//!
//! **Exit codes** come from a kqueue `NOTE_EXIT` watch armed immediately
//! after `ocijail create` and *before* `start` — ocijail reports no exit
//! status anywhere and the container process is init's child, not ours
//! (docs/ocijail.md §1.4/§1.6).
//!
//! **Health gates `RUNNING`** (architecture §8.2, [`crate::health`]). With a
//! healthcheck configured, `start` releases the container and then *blocks on
//! the first probe verdict*: the task stays `STARTING` until a probe succeeds,
//! so nothing that keys on observed `RUNNING` — the DNS responder, a rolling
//! update's promotion — can see a container that has not passed one. If the
//! task goes `unhealthy` instead (`retries` consecutive failures outside
//! `start_period`), or the container dies first, `start` fails and the task is
//! `FAILED`. `wait` keeps watching: a task that was healthy and later goes
//! unhealthy is stopped and reported `FAILED` through the same status path, so
//! the existing restart supervisor — and nothing else — replaces it. Both
//! rules are SwarmKit's own (SWK §15.2: `Start` waits for healthy and returns
//! `ErrContainerUnhealthy`, `Wait` fails on a later unhealthy).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use satl_core::{
    ContainerStatus, PortConfig, PortStatus, PublishMode, Task, defaults::STOP_GRACE_PERIOD,
};
use satl_image::{ImageReference, PulledImage};
use satl_net::{PortPublish, TaskAttachment};
use satl_runtime::{
    CreateStdio, ImagePlatform, Runtime as _, RuntimeStatus, StdioSink, wait_for_exit,
};
use satl_storage::LayerSource;
use tracing::Instrument as _;

use crate::bundle::{self, PlanError};
use crate::error::ControllerError;
use crate::executor::Executor;
use crate::health::{
    HealthStatus, OcijailProbeRunner, ProbeResolution, ProbeSettings, Prober, TaskHealth,
};
use crate::rctl::LimitsOutcome;

/// How long to wait for a container to die after `SIGKILL` before giving up
/// and letting `remove`'s `jail_remove(2)` finish the job (docs/ocijail.md
/// §4.3: delete kills everything left in the jail anyway).
const SIGKILL_WAIT: Duration = Duration::from_secs(5);

/// `SIGTERM`, the default stop signal (SWK §3.6 / Docker `STOPSIGNAL`).
const SIGTERM: i32 = 15;

/// `SIGKILL`, sent when the grace period expires.
const SIGKILL: i32 = 9;

/// Pause between attempts to destroy a container rootfs whose jail is still
/// `DYING` (see [`Controller::destroy_rootfs`]).
const ROOTFS_BUSY_RETRY: Duration = Duration::from_millis(250);

/// Backstop on the wait for a dying jail — **not** the thing that makes the
/// wait long enough.
///
/// What the wait is keyed on is the prison itself (see
/// [`Controller::destroy_rootfs`]); this only bounds how long one `remove`
/// sits there, and that bound is set by where `remove` runs, not by the
/// kernel: the agent applies a removal **inline on the assignment stream**
/// (`satl_dispatcher::agent::apply_diff` awaits `remove_task`), so every
/// second spent here is a second in which this node applies no other
/// assignment — including the network teardown ordered after the task in the
/// same batch. Waiting out a kernel timer of a minute or more (measured: 58 s
/// typical, 77 s worst, `docs/jail-teardown.md`) is therefore not an option
/// however patient we are willing to be.
///
/// So the budget stays at the order of magnitude the removal path already
/// cost, and running out of it is no longer a leak: the dataset is handed to
/// `satld`'s periodic sweep, which is level-triggered, runs off the assignment
/// path, and destroys it as soon as the prison is gone.
const ROOTFS_BUSY_BUDGET: Duration = Duration::from_secs(30);

/// How long to keep retrying a busy rootfs whose prison is **already gone**.
///
/// With no prison there is no known reason for the filesystem to be busy, so
/// this is deliberately short: a few retries to cover the instant between the
/// prison disappearing and the last unmount succeeding, and then a report. It
/// is the case that should reach an operator, because it is the one nobody has
/// explained yet.
const ROOTFS_UNEXPLAINED_BUSY: Duration = Duration::from_secs(5);

/// Whether a rootfs destroy failed only because the filesystem is still mounted.
///
/// Matched structurally on the failed `zfs` invocation and then on the message
/// `zfs`(8) itself prints, the same way `satl-net` recognises "does not exist" —
/// the alternative is treating every destroy failure as transient, which would
/// turn a genuinely stuck dataset into a five-second stall and a lie.
fn is_unmount_busy(error: &satl_storage::ContainerFsError) -> bool {
    matches!(
        error,
        satl_storage::ContainerFsError::Zfs(satl_storage::ZfsError::CommandFailed { stderr, .. })
            if stderr.contains("pool or dataset is busy")
    )
}

/// How a container terminated, as harvested by the exit watch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitOutcome {
    /// Exit code, when it exited normally.
    pub code: Option<i32>,
    /// Terminating signal, when it was killed.
    pub signal: Option<i32>,
    /// Set when the exit status could not be harvested at all (the process
    /// was already reaped, or the kqueue watch itself failed).
    pub unharvestable: Option<String>,
}

impl ExitOutcome {
    /// Successful termination: exited with code 0.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.code == Some(0)
    }

    /// Operator-facing description for the task status.
    #[must_use]
    pub fn describe(&self) -> String {
        match (self.code, self.signal, &self.unharvestable) {
            (Some(code), _, _) => format!("container exited with code {code}"),
            (_, Some(signal), _) => format!("container was killed by signal {signal}"),
            (_, _, Some(reason)) => reason.clone(),
            _ => "container terminated".to_owned(),
        }
    }

    /// The exit code to record in [`ContainerStatus::exit_code`]. A signal
    /// death is reported as `128 + signal` (Docker/shell convention).
    #[must_use]
    pub fn exit_code(&self) -> Option<i64> {
        match (self.code, self.signal) {
            (Some(code), _) => Some(i64::from(code)),
            (_, Some(signal)) => Some(128 + i64::from(signal)),
            _ => None,
        }
    }

    fn from_status(status: satl_runtime::ExitStatus) -> Self {
        if status.is_unknown() {
            return Self {
                code: None,
                signal: None,
                unharvestable: Some(
                    "container exit status could not be harvested (the process was already \
                     reaped before the exit watch attached)"
                        .to_owned(),
                ),
            };
        }
        Self {
            code: status.code,
            signal: status.signal,
            unharvestable: None,
        }
    }
}

/// One controller drives one task (SWK §15.2). Not object-safe (async
/// methods); [`crate::do_step`] stays generic over it, which also makes the
/// state machine testable against a mock.
pub trait TaskController: Send {
    /// Create everything needed for [`TaskController::start`] to be
    /// immediate. Idempotent — re-running it adopts what exists.
    fn prepare(&mut self) -> impl std::future::Future<Output = Result<(), ControllerError>> + Send;

    /// Start the workload; returns once the container process has been
    /// released (ocijail `start` does not wait for the exec).
    fn start(&mut self) -> impl std::future::Future<Output = Result<(), ControllerError>> + Send;

    /// Block until the container terminates.
    fn wait(
        &mut self,
    ) -> impl std::future::Future<Output = Result<ExitOutcome, ControllerError>> + Send;

    /// Adopt a new definition of the same task. Only the desired state, the
    /// annotations and — since M6g — the resources can change on a live task
    /// (the hot resize re-applies rctl to the running jail); the rest of the
    /// spec is immutable (architecture §4 rule 4).
    fn update(&mut self, task: Task);

    /// Graceful stop: stop signal, grace period, then `SIGKILL`.
    fn shutdown(&mut self)
    -> impl std::future::Future<Output = Result<(), ControllerError>> + Send;

    /// Release every resource this controller created.
    fn remove(&mut self) -> impl std::future::Future<Output = Result<(), ControllerError>> + Send;

    /// Jail id / pid / exit code known so far (SWK §15.2 `ContainerStatuser`).
    fn container_status(&self) -> Option<ContainerStatus>;

    /// Host ports currently bound for this task (SWK §15.2 `PortStatuser`).
    fn port_status(&self) -> Vec<PortStatus>;

    /// Extra text appended to reported status messages — currently the
    /// rctl-degradation note (architecture §8.3).
    fn status_note(&self) -> Option<&str>;
}

/// Which arm of the health gate in [`Controller::await_first_healthy`] won.
enum Gate {
    /// The prober reached a verdict (or died: `None`).
    Decided(Option<HealthStatus>),
    /// The container terminated before any probe succeeded.
    Exited(ExitOutcome),
}

/// Which arm of [`Controller::wait_inner`] won.
enum Waited {
    /// The container terminated.
    Exited(ExitOutcome),
    /// A healthy container went unhealthy.
    Unhealthy,
    /// The prober task ended without a verdict (agent bug).
    ProberGone,
}

/// A cancel-safe handle on the kqueue exit watch armed at create time.
#[derive(Debug, Clone)]
struct ExitWatch {
    rx: tokio::sync::watch::Receiver<Option<ExitOutcome>>,
}

impl ExitWatch {
    /// Arm `NOTE_EXIT` on `pid`. Must be called before `ocijail start`
    /// (docs/ocijail.md §1.4).
    fn arm(pid: i32) -> Self {
        let (tx, rx) = tokio::sync::watch::channel(None);
        tokio::spawn(async move {
            let outcome = match wait_for_exit(pid).await {
                Ok(status) => ExitOutcome::from_status(status),
                Err(error) => {
                    tracing::error!(pid, %error, "exit watch failed");
                    ExitOutcome {
                        code: None,
                        signal: None,
                        unharvestable: Some(error.to_string()),
                    }
                }
            };
            // A dropped receiver means the controller went away first.
            let _ = tx.send(Some(outcome));
        });
        Self { rx }
    }

    /// Wait for the container to die. Cancel-safe and repeatable: the value
    /// stays set once observed.
    async fn wait(&mut self) -> ExitOutcome {
        match self.rx.wait_for(Option::is_some).await {
            // Infallible: the guard only resolves on a `Some` value.
            Ok(value) => value.clone().unwrap_or_else(|| ExitOutcome {
                code: None,
                signal: None,
                unharvestable: Some("exit watch produced no outcome".to_owned()),
            }),
            // Sender dropped without sending: the watcher task was cancelled
            // (runtime shutdown).
            Err(_) => ExitOutcome {
                code: None,
                signal: None,
                unharvestable: Some("exit watch task ended before the container did".to_owned()),
            },
        }
    }
}

/// Node-local state a controller accumulates as it drives its task.
#[derive(Debug, Default)]
struct Local {
    /// Container rootfs (the ZFS clone mountpoint).
    rootfs: Option<PathBuf>,
    /// Container process pid, from ocijail's `--pid-file`.
    pid: Option<i32>,
    /// The jail's jid, from `ocijail state`'s injected annotation.
    jid: Option<i32>,
    /// Exit watch, armed at create time.
    exit_watch: Option<ExitWatch>,
    /// Harvested termination.
    exit: Option<ExitOutcome>,
    /// Network plumbing.
    attachment: Option<TaskAttachment>,
    /// Host ports actually published.
    ports: Vec<PortStatus>,
    /// rctl degradation note (architecture §8.3).
    limits_note: Option<String>,
    /// A hot resize (M6g) arrived while the container was up: the next
    /// `wait` pass re-applies rctl to the live jail.
    pending_resize: bool,
    /// The healthcheck prober, once the container has been started (or
    /// adopted). `None` means this task has no healthcheck — or one SatL
    /// could not understand, which Docker also treats as none.
    prober: Option<Prober<OcijailProbeRunner>>,
    /// When the container was started on this node: the origin of
    /// `start_period`.
    started_at: Option<SystemTime>,
}

/// The task controller. See the module docs.
pub struct Controller {
    executor: Arc<Executor>,
    task: Task,
    /// Container ID = task ID = jail name (pinned M1 contract).
    id: String,
    local: Local,
}

impl std::fmt::Debug for Controller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controller")
            .field("id", &self.id)
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl Controller {
    /// A controller for `task`. Use [`Executor::controller`].
    #[must_use]
    pub fn new(executor: Arc<Executor>, task: Task) -> Self {
        let id = task.id.as_str().to_owned();
        Self {
            executor,
            task,
            id,
            local: Local::default(),
        }
    }

    /// The task this controller drives.
    #[must_use]
    pub fn task(&self) -> &Task {
        &self.task
    }

    /// The task's network plumbing, once [`TaskController::start`] attached
    /// it. `satl-api` reads the address from here for
    /// `NetworkSettings.IPAddress`.
    #[must_use]
    pub fn attachment(&self) -> Option<&TaskAttachment> {
        self.local.attachment.as_ref()
    }

    /// The container rootfs (the ZFS clone mountpoint), once known.
    #[must_use]
    pub fn rootfs(&self) -> Option<&std::path::Path> {
        self.local.rootfs.as_deref()
    }

    /// Re-arm the exit watch on a pid that survived a daemon restart
    /// (architecture §7.2: a running jail is re-attached, not restarted).
    pub fn reattach_running(&mut self, pid: i32) {
        self.local.pid = Some(pid);
        self.local.exit_watch = Some(ExitWatch::arm(pid));
        tracing::info!(task_id = %self.id, pid, "re-armed exit watch on adopted container");
    }

    /// Record the network attachment discovered by startup reconciliation.
    pub fn reattach_network(&mut self, attachment: TaskAttachment) {
        self.local.attachment = Some(attachment);
    }

    // ---- prepare ---------------------------------------------------------

    async fn resolve_image(&self) -> Result<PulledImage, ControllerError> {
        let spec = &self.task.spec.container;
        let reference = ImageReference::parse(&spec.image)?;
        if let Some(local) = self.executor.images().resolve(&reference).await? {
            tracing::debug!(image = %local.reference, platform = %local.platform, "image already present");
            return Ok(local);
        }
        if spec.pull_options.is_some() {
            // Decoding `X-Registry-Auth` is satl-api's job and per-task
            // credentials ride the dispatcher's secret assignments (M2).
            tracing::warn!(
                image = %spec.image,
                "task carries pull credentials; the executor pulls anonymously"
            );
        }
        let policy = self.executor.platform_policy(spec.platform.as_ref());
        let pulled = self
            .executor
            .images()
            .pull(&reference, &policy, None)
            .await
            .map_err(image_error)?;
        Ok(pulled)
    }

    async fn apply_layers(&self, image: &PulledImage) -> Result<PathBuf, ControllerError> {
        let mut sources = Vec::with_capacity(image.layers.len());
        for layer in &image.layers {
            sources.push(LayerSource {
                diff_id: layer.diff_id.as_str().to_owned(),
                blob_path: self.executor.images().blob_path(&layer.blob_digest),
                compression: storage_compression(layer.compression()?),
            });
        }
        let top = self.executor.layers().apply_image(&sources).await?;
        // The container rootfs is a clone of `<layers_root>/<top>@final`.
        self.ensure_container_fs(&top).await
    }

    /// Clone the writable layer, adopting an existing clone (re-entrancy).
    ///
    /// This check is **not** the whole guard, and must not be mistaken for
    /// one: it is a check-then-act, so two prepares racing over the same task
    /// both see the dataset absent and both go on to clone. The atomic half
    /// lives in [`ContainerFsStore::create`], which treats "dataset already
    /// exists" as success when the existing dataset's origin proves it is this
    /// task's own. Measured: a rolling update rolled back six slots because
    /// the loser of exactly this race reported a fatal task failure
    /// (decision log, 2026-08-25).
    async fn ensure_container_fs(
        &self,
        top: &satl_storage::ChainId,
    ) -> Result<PathBuf, ControllerError> {
        let dataset = self.executor.container_dataset(&self.id);
        if self.executor.zfs().dataset_exists(&dataset).await? {
            let mountpoint = self.executor.zfs().mountpoint_of(&dataset).await?;
            tracing::info!(dataset = %dataset, mountpoint = %mountpoint.display(),
                "adopting existing container rootfs");
            return Ok(mountpoint);
        }
        let mountpoint = self
            .executor
            .container_fs()
            .create(&self.id, top, &self.executor.datasets().layers_root)
            .await?;
        Ok(mountpoint)
    }

    /// Give the container a `/etc/resolv.conf`, as Docker does.
    ///
    /// Without one a container resolves nothing: it can reach an address but
    /// not a name, which looks like broken networking rather than missing
    /// configuration. It is written into the writable layer rather than
    /// bind-mounted, so it stays per-container and never touches the image.
    ///
    /// Three sources, in this precedence:
    ///
    /// 1. the task's own `dns_config` when the caller passed `--dns` — an
    ///    explicit operator instruction outranks service discovery, as it does
    ///    in Docker;
    /// 2. **this node's gateway on each overlay network the task attaches
    ///    to**, which is where the embedded responder listens (architecture
    ///    §11.5, `docs/vxlan.md` §8). The gateway is per node, so a container
    ///    always talks to the responder on its *own* host;
    /// 3. a copy of the host's file, for a task on no overlay (Docker's
    ///    default, and the M1 behaviour).
    ///
    /// Best-effort by design: an image with no `/etc`, or an unreadable host
    /// file, costs name resolution — never the container's start.
    async fn write_resolv_conf(&self, rootfs: &std::path::Path) {
        let content = match self.task.spec.container.dns_config.as_ref() {
            Some(dns) if !dns.nameservers.is_empty() => render_resolv_conf(dns),
            _ => match self.overlay_resolv_conf().await {
                Some(rendered) => rendered,
                None => match tokio::fs::read_to_string("/etc/resolv.conf").await {
                    Ok(host) => host,
                    Err(error) => {
                        tracing::warn!(task_id = %self.id, %error,
                        "cannot read the host /etc/resolv.conf; container will not resolve names");
                        return;
                    }
                },
            },
        };
        let etc = rootfs.join("etc");
        if let Err(error) = tokio::fs::create_dir_all(&etc).await {
            tracing::warn!(task_id = %self.id, %error, path = %etc.display(),
                "cannot create /etc in the container rootfs; skipping resolv.conf");
            return;
        }
        let path = etc.join("resolv.conf");
        if let Err(error) = tokio::fs::write(&path, content).await {
            tracing::warn!(task_id = %self.id, %error, path = %path.display(),
                "cannot write the container resolv.conf; container will not resolve names");
        }
    }

    /// The overlay responder's `resolv.conf` for this task, when the daemon
    /// wired an overlay programmer and this task is on an overlay network.
    async fn overlay_resolv_conf(&self) -> Option<String> {
        let overlay = self.executor.overlay()?;
        let rendered = overlay.resolv_conf(&self.task).await?;
        tracing::debug!(
            task_id = %self.id,
            "container resolv.conf points at this node's overlay responder"
        );
        Some(rendered)
    }

    /// Create named volumes and validate bind sources, returning the volume
    /// name → host path map the bundle planner needs.
    async fn ensure_mount_sources(&self) -> Result<BTreeMap<String, PathBuf>, ControllerError> {
        let mut volumes = BTreeMap::new();
        for mount in &self.task.spec.container.mounts {
            match mount.kind {
                satl_core::MountType::Volume => {
                    let Some(name) = mount.source.clone() else {
                        return Err(PlanError::MissingMountSource {
                            task_id: self.id.clone(),
                            kind: "volume",
                            target: mount.target.clone(),
                        }
                        .into());
                    };
                    let path = self.executor.volumes().ensure(&name).await?;
                    volumes.insert(name, path);
                }
                satl_core::MountType::Bind => {
                    let Some(source) = mount.source.clone() else {
                        return Err(PlanError::MissingMountSource {
                            task_id: self.id.clone(),
                            kind: "bind",
                            target: mount.target.clone(),
                        }
                        .into());
                    };
                    if !tokio::fs::try_exists(&source).await.unwrap_or(false) {
                        return Err(ControllerError::BindSourceMissing {
                            task_id: self.id.clone(),
                            host_path: source,
                            target: mount.target.clone(),
                        });
                    }
                }
                satl_core::MountType::Tmpfs => {}
            }
        }
        Ok(volumes)
    }

    /// Open (creating) the per-task log sinks. Opened read+write and seeked
    /// to the end: `satl-runtime` reads create-time runtime errors back out
    /// of the stderr sink (docs/ocijail.md §3), and a re-entrant prepare must
    /// append rather than truncate.
    async fn open_log_sinks(&self) -> Result<CreateStdio, ControllerError> {
        let dir = self.executor.log_dir(&self.id);
        let io_err = |path: PathBuf, source: std::io::Error| ControllerError::Io {
            task_id: self.id.clone(),
            what: "opening the task log sink",
            path,
            source,
        };
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|source| io_err(dir.clone(), source))?;
        let open = |path: PathBuf| -> Result<StdioSink, ControllerError> {
            use std::io::Seek as _;
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .map_err(|source| io_err(path.clone(), source))?;
            file.seek(std::io::SeekFrom::End(0))
                .map_err(|source| io_err(path, source))?;
            Ok(StdioSink::File(file))
        };
        Ok(CreateStdio {
            stdin: StdioSink::Null,
            stdout: open(dir.join("stdout.log"))?,
            stderr: open(dir.join("stderr.log"))?,
        })
    }

    /// Adopt a container ocijail already knows about (re-entrant prepare, or
    /// a `satld` restart). Returns the adopted container's runtime status,
    /// `None` when there is nothing to adopt.
    async fn adopt_created(&mut self) -> Result<Option<RuntimeStatus>, ControllerError> {
        let state = match self.executor.runtime().state(&self.id).await {
            Ok(state) => state,
            Err(error) if error.is_not_found() => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        self.local.jid = state.jid();
        if let Some(pid) = state.pid {
            self.local.pid = Some(pid);
            if self.local.exit_watch.is_none() {
                self.local.exit_watch = Some(ExitWatch::arm(pid));
            }
        }
        if self.local.rootfs.is_none() {
            let dataset = self.executor.container_dataset(&self.id);
            if self.executor.zfs().dataset_exists(&dataset).await? {
                self.local.rootfs = Some(self.executor.zfs().mountpoint_of(&dataset).await?);
            }
        }
        tracing::info!(
            status = ?state.status,
            pid = ?state.pid,
            jid = ?self.local.jid,
            "adopting container already known to ocijail"
        );
        Ok(Some(state.status))
    }

    async fn apply_limits(&mut self) -> Result<(), ControllerError> {
        let limits = self.task.spec.resources.limits.unwrap_or_default();
        let outcome = self
            .executor
            .rctl()
            .apply_limits(&self.id, Some(limits.memory_bytes), Some(limits.nano_cpus))
            .await?;
        if let LimitsOutcome::Skipped(skipped) = outcome {
            self.local.limits_note = Some(skipped.note().to_owned());
        }
        Ok(())
    }

    /// Re-apply the task's limits to its live jail after a hot resize (M6g).
    ///
    /// The old rules go first: `rctl -a` stacks same-subject rules instead of
    /// replacing them (measured on 15.1: two `memoryuse:sigkill` rules
    /// coexisted after two adds), so re-adding without removing would leave
    /// the *older* cap armed alongside the new one. The gap between remove
    /// and add is accepted — a resize is an operator act, not a race worth
    /// serializing the data path for.
    ///
    /// A memory shrink below the jail's current usage is a `sigkill` rule
    /// already under the watermark (`rctl.rs` documents why the action is
    /// sigkill): the kill that follows would look like a crash, so say so
    /// loudly before arming it. With racct off there is no usage to compare
    /// and `apply_limits` degrades as at prepare.
    async fn reapply_limits_if_resized(&mut self) -> Result<(), ControllerError> {
        if !self.local.pending_resize {
            return Ok(());
        }
        self.local.pending_resize = false;
        let limits = self.task.spec.resources.limits.unwrap_or_default();
        if limits.memory_bytes > 0
            && let Some(usage) = self.executor.rctl().usage(&self.id).await?
            && limits.memory_bytes < usage.memory_bytes
        {
            tracing::warn!(
                memory_bytes = limits.memory_bytes,
                memoryuse = usage.memory_bytes,
                "hot resize shrinks memory below current usage: the sigkill \
                 rule is armed under the watermark and the kernel may kill \
                 the jail at any time"
            );
        }
        self.executor.rctl().remove_limits(&self.id).await?;
        self.apply_limits().await?;
        tracing::info!(limits = ?limits, "hot resize applied to the live jail");
        Ok(())
    }

    async fn prepare_inner(&mut self) -> Result<(), ControllerError> {
        if let Some(status) = self.adopt_created().await? {
            // Everything before `ocijail create` already happened — except,
            // possibly, the payload writes that come *after* it: a daemon
            // killed between `create` (which mounts the secrets tmpfs) and
            // the writes leaves a created jail with empty payload files.
            // Rewriting is idempotent, so an adopted, not-yet-started
            // container always gets a fresh set (invariant #7: the payloads
            // were re-fetched into memory from the session's COMPLETE
            // snapshot, never from this node's disk).
            if status == RuntimeStatus::Created {
                self.rematerialize_dependencies().await?;
            }
            return Ok(());
        }
        // Dependencies first: a task whose secrets have not arrived yet must
        // not pull or clone anything — the error is retryable and the next
        // attempt starts clean.
        let (secrets, configs) = self.resolved_dependencies()?;
        let image = self.resolve_image().await?;
        let platform = bundle::image_platform(&self.id, &image.platform)?;
        if platform == ImagePlatform::Linux && !self.executor.host().linux_emulation {
            return Err(ControllerError::LinuxEmulationUnavailable {
                task_id: self.id.clone(),
                image: image.reference.clone(),
            });
        }
        let rootfs = self.apply_layers(&image).await?;
        self.local.rootfs = Some(rootfs.clone());
        // After the clone rather than inside it, so an *adopted* rootfs gets a
        // current file too: this node's overlay gateway can differ from the one
        // the previous process wrote (the allocator releases a node's gateway
        // when it runs no more tasks on the network and hands out a fresh one
        // later), and a container pointed at the old address resolves nothing.
        self.write_resolv_conf(&rootfs).await;
        let volumes = self.ensure_mount_sources().await?;
        let bundle_dir = self.executor.bundle_dir(&self.id);
        let payload_total: u64 = secrets
            .iter()
            .map(|secret| secret.spec.data().len() as u64)
            .sum();
        let deps = bundle::plan_dependencies(
            &self.id,
            &self.task.spec.container,
            &rootfs,
            &bundle_dir,
            payload_total,
        )?;
        let spec = bundle::plan_bundle(&self.task, &image, rootfs, &volumes, &deps)?;

        tokio::fs::create_dir_all(&bundle_dir)
            .await
            .map_err(|source| ControllerError::Io {
                task_id: self.id.clone(),
                what: "creating the OCI bundle directory",
                path: bundle_dir.clone(),
                source,
            })?;
        // Config payloads are the nullfs mount sources, so they must exist
        // before `create` performs the mounts. Configs only — a secret
        // payload never lands outside the tmpfs (invariant #7).
        self.write_payload_files(
            deps.config_files.clone(),
            configs
                .iter()
                .map(|config| config.spec.data().to_vec())
                .collect(),
        )
        .await?;
        let stdio = self.open_log_sinks().await?;

        let created = self
            .executor
            .runtime()
            .create(&self.id, &bundle_dir, &spec, None, stdio)
            .await?;
        self.local.pid = Some(created.pid);
        // Arm before `start` — the container may exit immediately after it
        // execs (docs/ocijail.md §1.4).
        self.local.exit_watch = Some(ExitWatch::arm(created.pid));
        // Secret payloads go in *after* create mounted the tmpfs and before
        // start releases the container (invariant #7).
        self.write_payload_files(
            deps.secret_files.clone(),
            secrets
                .iter()
                .map(|secret| secret.spec.data().to_vec())
                .collect(),
        )
        .await?;
        self.apply_limits().await?;
        Ok(())
    }

    /// Resolve every secret/config the task references from the node's
    /// in-memory dependency store. A missing object is a **retryable** error:
    /// the dispatcher ships dependencies before dependents, so a gap only
    /// exists mid-resync.
    #[allow(clippy::type_complexity)]
    fn resolved_dependencies(
        &self,
    ) -> Result<(Vec<Arc<satl_core::Secret>>, Vec<Arc<satl_core::Config>>), ControllerError> {
        let store = self.executor.dependencies();
        let spec = &self.task.spec.container;
        let mut secrets = Vec::with_capacity(spec.secrets.len());
        for reference in &spec.secrets {
            secrets.push(store.secret(&reference.secret_id).ok_or_else(|| {
                ControllerError::DependencyNotDelivered {
                    task_id: self.id.clone(),
                    kind: "secret",
                    name: reference.secret_name.clone(),
                }
            })?);
        }
        let mut configs = Vec::with_capacity(spec.configs.len());
        for reference in &spec.configs {
            configs.push(store.config(&reference.config_id).ok_or_else(|| {
                ControllerError::DependencyNotDelivered {
                    task_id: self.id.clone(),
                    kind: "config",
                    name: reference.config_name.clone(),
                }
            })?);
        }
        Ok((secrets, configs))
    }

    /// Write payload files off the async runtime (`spawn_blocking` — the
    /// writes are small but chown/chmod are blocking syscalls).
    async fn write_payload_files(
        &self,
        files: Vec<bundle::PayloadFile>,
        payloads: Vec<Vec<u8>>,
    ) -> Result<(), ControllerError> {
        if files.is_empty() {
            return Ok(());
        }
        let task_id = self.id.clone();
        tokio::task::spawn_blocking(move || crate::materialize::write_payloads(&files, &payloads))
            .await
            .map_err(|join| ControllerError::Io {
                task_id: task_id.clone(),
                what: "materializing dependency payloads",
                path: PathBuf::new(),
                source: std::io::Error::other(join),
            })?
            .map_err(|source| ControllerError::PayloadWrite { task_id, source })
    }

    /// Re-write every payload file of an adopted, created-but-not-started
    /// container (the daemon may have died between `create` and the payload
    /// writes). Idempotent; payloads come from the dependency store, which
    /// the session refilled from its COMPLETE snapshot.
    async fn rematerialize_dependencies(&mut self) -> Result<(), ControllerError> {
        let spec = &self.task.spec.container;
        if spec.secrets.is_empty() && spec.configs.is_empty() {
            return Ok(());
        }
        let Some(rootfs) = self.local.rootfs.clone() else {
            // A created jail without its dataset cannot start anyway; the
            // runtime will fail the step with the real diagnosis.
            tracing::warn!(
                task_id = %self.id,
                "adopted a created container with no rootfs; skipping payload rewrite"
            );
            return Ok(());
        };
        let (secrets, configs) = self.resolved_dependencies()?;
        let payload_total: u64 = secrets
            .iter()
            .map(|secret| secret.spec.data().len() as u64)
            .sum();
        let bundle_dir = self.executor.bundle_dir(&self.id);
        let deps = bundle::plan_dependencies(
            &self.id,
            &self.task.spec.container,
            &rootfs,
            &bundle_dir,
            payload_total,
        )?;
        tracing::info!(
            task_id = %self.id,
            secrets = deps.secret_files.len(),
            configs = deps.config_files.len(),
            "rewriting dependency payloads of an adopted created container"
        );
        self.write_payload_files(
            deps.config_files.clone(),
            configs
                .iter()
                .map(|config| config.spec.data().to_vec())
                .collect(),
        )
        .await?;
        self.write_payload_files(
            deps.secret_files.clone(),
            secrets
                .iter()
                .map(|secret| secret.spec.data().to_vec())
                .collect(),
        )
        .await
    }

    // ---- start -----------------------------------------------------------

    /// Host-mode published ports of this task, as pf rdr targets.
    fn host_ports(&self, task_ip: std::net::Ipv4Addr) -> (Vec<PortPublish>, Vec<PortStatus>) {
        let ports: Vec<&PortConfig> = self
            .task
            .endpoint
            .iter()
            .flat_map(|endpoint| &endpoint.ports)
            .filter(|port| port.publish_mode == PublishMode::Host && port.published_port != 0)
            .collect();
        let publishes = ports
            .iter()
            .map(|port| PortPublish {
                proto: port.protocol,
                host_port: port.published_port,
                task_ip,
                task_port: port.target_port,
            })
            .collect();
        let status = ports.iter().map(|port| (*port).clone()).collect();
        (publishes, status)
    }

    /// Drop any epair left behind by an interrupted attach so the fresh
    /// attach below cannot leak one (CLAUDE.md: epairs leak when teardown is
    /// interrupted).
    async fn discard_stale_attachment(&self) -> Result<(), ControllerError> {
        let owned = self.executor.network().list_owned().await?;
        let stale: Vec<String> = owned
            .into_iter()
            .filter_map(|iface| match iface.kind {
                satl_net::OwnedKind::Task { task_id } if task_id == self.id => Some(iface.name),
                _ => None,
            })
            .collect();
        for name in stale {
            let Some(peer) = epair_peer(&name) else {
                continue;
            };
            tracing::warn!(iface = %name, "discarding epair left by an interrupted attach");
            let attachment = TaskAttachment {
                epair_a: name,
                epair_b: peer,
                ip: std::net::Ipv4Addr::UNSPECIFIED,
                gateway: std::net::Ipv4Addr::UNSPECIFIED,
            };
            self.executor
                .network()
                .detach_task(&self.id, &attachment)
                .await?;
        }
        Ok(())
    }

    async fn start_inner(&mut self) -> Result<(), ControllerError> {
        if self.local.attachment.is_none() {
            self.discard_stale_attachment().await?;
            let attachment = self
                .executor
                .network()
                .attach_task(&self.id, &self.id)
                .await?;
            self.local.attachment = Some(attachment);
        }
        // Infallible: just assigned above.
        let ip = self
            .local
            .attachment
            .as_ref()
            .map_or(std::net::Ipv4Addr::UNSPECIFIED, |a| a.ip);
        let (publishes, status) = self.host_ports(ip);
        // A proxy-mode service (M6e) never gets a pf redirect: the userspace
        // proxy binds the published port and an rdr rule would win the race
        // for the packet. The port sweep's level pass routes the task to the
        // proxy instead.
        let proxy_mode =
            satl_core::defaults::proxy_protocol_enabled(&self.task.service_annotations.labels);
        if !publishes.is_empty() && !proxy_mode {
            self.executor
                .network()
                .publish_ports(&self.id, publishes)
                .await?;
        }
        self.local.ports = status;

        // Overlay attachments come after the node-local one and **before**
        // `ocijail start`. After, because the node-local bridge is where the
        // default route, NAT and published ports live and an overlay
        // attachment deliberately installs no default route of its own — two
        // would race (`satl_net::OverlayAttach::default_route`). Before the
        // start, because a container that runs first would bind and dial on a
        // network that is not there yet, and a broken overlay is silent
        // (`docs/vxlan.md` §6).
        if let Some(overlay) = self.executor.overlay() {
            overlay.attach(&self.task, &self.id).await?;
        }

        // A start that fails past the overlay attach must release it: the
        // task is FAILED from here, its overlay addresses are freed with it
        // (SWK §9.4) and a replacement on another node can inherit one within
        // seconds — the same window the detach in `wait_inner` closes for a
        // container that dies while RUNNING. Waiting for the manager-ordered
        // removal is what black-holed replacements ("endpoint X is both local
        // and remote").
        if let Err(error) = self.start_container().await {
            self.detach_overlay().await;
            return Err(error);
        }
        Ok(())
    }

    /// The part of `start` that runs once the networks are attached: release
    /// the container, harvest its pid/jid and hold the health gate.
    async fn start_container(&mut self) -> Result<(), ControllerError> {
        let state = self.executor.runtime().state(&self.id).await?;
        if state.status == RuntimeStatus::Created {
            self.executor.runtime().start(&self.id).await?;
            self.local.started_at = Some(SystemTime::now());
        } else {
            tracing::info!(status = ?state.status, "container already started");
        }
        // Re-read so the reported pid/jid are the post-start truth.
        let state = self.executor.runtime().state(&self.id).await?;
        self.local.jid = state.jid();
        if let Some(pid) = state.pid {
            self.local.pid = Some(pid);
        }
        // The health gate (see the module docs): with a healthcheck, `start`
        // does not return — and the task therefore does not reach RUNNING —
        // until a probe has passed.
        self.ensure_prober().await?;
        self.await_first_healthy().await?;
        Ok(())
    }

    // ---- health ----------------------------------------------------------

    /// This task's healthcheck, with Docker's defaults applied, or `None` when
    /// it has none. An unrecognized `test[0]` is a warning and no healthcheck,
    /// as in Docker (`crate::health`).
    fn probe_settings(&self) -> Option<ProbeSettings> {
        let config = self.task.spec.container.healthcheck.as_ref()?;
        match ProbeSettings::resolve(config) {
            ProbeResolution::Enabled(settings) => Some(settings),
            ProbeResolution::Disabled => None,
            ProbeResolution::Unknown { kind } => {
                tracing::warn!(
                    task_id = %self.id,
                    probe_kind = %kind,
                    "unknown healthcheck type (expected CMD or CMD-SHELL); this task is not probed"
                );
                None
            }
        }
    }

    /// Start probing, unless this task has no healthcheck or is already being
    /// probed. Idempotent, like every other controller step: a re-entrant
    /// `start`, or a `wait` on a container adopted after a `satld` restart,
    /// both land here.
    async fn ensure_prober(&mut self) -> Result<(), ControllerError> {
        if self.local.prober.is_some() {
            return Ok(());
        }
        let Some(settings) = self.probe_settings() else {
            return Ok(());
        };
        let bundle_dir = self.executor.bundle_dir(&self.id);
        // The container's own process object: a probe runs with its env, cwd
        // and user (Docker's exec-based probe does the same).
        let process = crate::health::probe_process(&self.id, &bundle_dir).await?;
        let runner = OcijailProbeRunner::new(
            self.executor.runtime().ocijail().clone(),
            self.id.clone(),
            process,
            self.executor.health_dir(&self.id),
        );
        let started_at = *self.local.started_at.get_or_insert_with(SystemTime::now);
        self.local.prober = Some(Prober::spawn(
            self.id.clone(),
            runner,
            settings,
            started_at,
            Arc::clone(self.executor.health()),
        ));
        Ok(())
    }

    /// Stop probing and make sure no probe process is left inside the jail.
    async fn stop_prober(&mut self) {
        if let Some(prober) = self.local.prober.take() {
            prober.stop().await;
        }
    }

    /// This task's health as the registry has it.
    #[must_use]
    pub fn health(&self) -> Option<TaskHealth> {
        self.executor.health().get(&self.id)
    }

    /// The health gate: block until the first probe verdict.
    ///
    /// Returns `Ok(())` when the task is healthy. Everything else is a terminal
    /// failure of `start`, because a container that cannot pass a probe must not
    /// be reported `RUNNING`:
    ///
    /// - `unhealthy` (`retries` consecutive failures outside `start_period`):
    ///   the container is stopped and the task fails, as SwarmKit's controller
    ///   does (`ErrContainerUnhealthy`);
    /// - the container exited before any probe succeeded: fail with what the
    ///   exit watch harvested, which is far more useful than "unhealthy";
    /// - the prober itself is gone: an internal failure, reported rather than
    ///   waited on forever.
    async fn await_first_healthy(&mut self) -> Result<(), ControllerError> {
        let Local {
            prober, exit_watch, ..
        } = &mut self.local;
        let Some(prober) = prober.as_mut() else {
            return Ok(());
        };
        tracing::info!(task_id = %self.id, "waiting for the first healthcheck probe to pass");
        let gate = match exit_watch.as_mut() {
            // The container may die while we wait; that is a failure of the
            // start, not an eternal wait for a probe that will never run.
            Some(watch) => tokio::select! {
                decided = prober.wait_until_decided() => Gate::Decided(decided),
                exit = watch.wait() => Gate::Exited(exit),
            },
            None => Gate::Decided(prober.wait_until_decided().await),
        };
        match gate {
            Gate::Decided(Some(HealthStatus::Healthy)) => {
                tracing::info!(task_id = %self.id, "the container passed its first healthcheck");
                Ok(())
            }
            Gate::Decided(Some(HealthStatus::Unhealthy)) => Err(self.fail_unhealthy().await),
            // `wait_until_decided` only resolves on a decision or a dead prober.
            Gate::Decided(Some(HealthStatus::Starting) | None) => {
                self.stop_prober().await;
                Err(ControllerError::HealthProberGone {
                    task_id: self.id.clone(),
                })
            }
            Gate::Exited(exit) => {
                self.local.exit = Some(exit.clone());
                // Symmetric with `wait_inner`'s exit arm: the container is
                // terminal, so its overlay plumbing is torn down now, not at
                // task removal.
                self.detach_overlay().await;
                self.stop_prober().await;
                Err(ControllerError::ExitedBeforeHealthy {
                    task_id: self.id.clone(),
                    detail: exit.describe(),
                })
            }
        }
    }

    /// Stop an unhealthy container and produce the failure to report.
    ///
    /// The container is stopped here rather than left running: it is about to be
    /// reported `FAILED`, the DNS responder has already stopped answering with
    /// it, and leaving a container that fails its own healthcheck holding a
    /// published port until the manager gets round to ordering a removal is
    /// worse than the shutdown's cost. The replacement is still the
    /// orchestrator's job — this path creates nothing.
    async fn fail_unhealthy(&mut self) -> ControllerError {
        let health = self.health().unwrap_or_default();
        let last_exit_code = health.log.last().map_or(0, |result| result.exit_code);
        tracing::warn!(
            task_id = %self.id,
            streak = health.failing_streak,
            exit_code = last_exit_code,
            "the container is unhealthy; stopping it and failing the task so it can be replaced"
        );
        self.stop_prober().await;
        if let Err(error) = self.shutdown_inner().await {
            tracing::warn!(
                task_id = %self.id,
                %error,
                "stopping the unhealthy container failed; reporting the failure anyway"
            );
        }
        ControllerError::Unhealthy {
            task_id: self.id.clone(),
            streak: health.failing_streak,
            exit_code: last_exit_code,
        }
    }

    // ---- shutdown --------------------------------------------------------

    fn stop_signal(&self) -> i32 {
        self.task
            .spec
            .container
            .stop_signal
            .as_deref()
            .and_then(signal_number)
            .unwrap_or(SIGTERM)
    }

    fn grace_period(&self) -> Duration {
        self.task
            .spec
            .container
            .stop_grace_period
            .unwrap_or(STOP_GRACE_PERIOD)
    }

    /// Send `signal`, tolerating a container ocijail no longer knows.
    async fn signal(&self, signal: i32) -> Result<(), ControllerError> {
        match self.executor.runtime().kill(&self.id, signal).await {
            Ok(()) => Ok(()),
            Err(error) if error.is_not_found() => {
                tracing::debug!(%error, "container already gone; nothing to signal");
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn shutdown_inner(&mut self) -> Result<(), ControllerError> {
        // Nothing may probe a container that is being stopped: a probe in
        // flight when the jail is deleted is a process inside a dying prison
        // (`docs/jail-teardown.md`), and its verdict is meaningless anyway.
        self.stop_prober().await;
        if let Some(exit) = self.local.exit.clone() {
            tracing::debug!("container already terminated: {}", exit.describe());
        } else if self.local.exit_watch.is_some() || self.local.pid.is_some() {
            let signal = self.stop_signal();
            let grace = self.grace_period();
            self.signal(signal).await?;
            let mut exit = self.await_exit(grace).await;
            if exit.is_none() {
                tracing::warn!(
                    grace_secs = grace.as_secs(),
                    "stop grace period expired; sending SIGKILL"
                );
                self.signal(SIGKILL).await?;
                exit = self.await_exit(SIGKILL_WAIT).await;
            }
            if let Some(exit) = exit {
                tracing::info!("shutdown complete: {}", exit.describe());
                self.local.exit = Some(exit);
            } else {
                tracing::warn!(
                    "container did not die after SIGKILL; jail_remove at delete will reap it"
                );
            }
        }
        self.executor.network().unpublish_ports(&self.id).await?;
        self.local.ports.clear();
        self.detach_overlay().await;
        Ok(())
    }

    // ---- wait ------------------------------------------------------------

    /// Block until the container terminates **or** its healthcheck gives up.
    ///
    /// The health arm is what makes an unhealthy *running* task fail: a task
    /// that was healthy and then fails `retries` probes in a row is stopped and
    /// reported `FAILED` through this ordinary status path, so the restart
    /// supervisor replaces it exactly as it does for a non-zero exit. SwarmKit's
    /// `Wait` does the same with `ErrContainerUnhealthy` (SWK §15.2).
    ///
    /// A task adopted after a `satld` restart (architecture §7.2) has no prober
    /// yet — it never went through `start` in this process — so this is also
    /// where health monitoring resumes.
    async fn wait_inner(&mut self) -> Result<ExitOutcome, ControllerError> {
        self.reapply_limits_if_resized().await?;
        self.ensure_prober().await?;
        let waited = {
            let Local {
                exit_watch, prober, ..
            } = &mut self.local;
            let Some(watch) = exit_watch.as_mut() else {
                return Err(ControllerError::NoExitWatch {
                    task_id: self.id.clone(),
                });
            };
            match prober.as_mut() {
                None => Waited::Exited(watch.wait().await),
                Some(prober) => tokio::select! {
                    exit = watch.wait() => Waited::Exited(exit),
                    unhealthy = prober.wait_until_unhealthy() => match unhealthy {
                        Some(()) => Waited::Unhealthy,
                        None => Waited::ProberGone,
                    },
                },
            }
        };
        match waited {
            Waited::Exited(exit) => {
                self.local.exit = Some(exit.clone());
                self.detach_overlay().await;
                Ok(exit)
            }
            Waited::Unhealthy => Err(self.fail_unhealthy().await),
            Waited::ProberGone => {
                self.stop_prober().await;
                Err(ControllerError::HealthProberGone {
                    task_id: self.id.clone(),
                })
            }
        }
    }

    /// Detach the task's overlay plumbing once its container is terminal.
    ///
    /// The allocator frees a terminal task's addresses (SWK §9.4) and a
    /// replacement can receive the same one within seconds, so the epair and
    /// the node-local attachment state cannot wait for the task's *removal*:
    /// a lingering attachment claims an address that by then belongs to
    /// another task — measured on the cluster as the mesh black-holing
    /// replacements ("endpoint X is both local and remote"). The jail and
    /// rootfs stay for `logs`/`inspect`; only the network plumbing goes.
    /// Idempotent with the removal path's own detach.
    async fn detach_overlay(&self) {
        if let Some(overlay) = self.executor.overlay() {
            overlay.detach(&self.task.id).await;
        }
    }

    /// Wait up to `timeout` for the exit watch to fire.
    async fn await_exit(&mut self, timeout: Duration) -> Option<ExitOutcome> {
        let watch = self.local.exit_watch.as_mut()?;
        tokio::time::timeout(timeout, watch.wait()).await.ok()
    }

    // ---- remove ----------------------------------------------------------

    /// Best-effort resolution of the rootfs for the mount-leak sweep. A
    /// missing dataset means there is nothing mounted under it.
    async fn rootfs_for_sweep(&self) -> PathBuf {
        if let Some(rootfs) = &self.local.rootfs {
            return rootfs.clone();
        }
        let dataset = self.executor.container_dataset(&self.id);
        match self.executor.zfs().dataset_exists(&dataset).await {
            Ok(true) => self
                .executor
                .zfs()
                .mountpoint_of(&dataset)
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(%error, "cannot resolve container rootfs for the mount sweep");
                    PathBuf::from("/nonexistent")
                }),
            _ => PathBuf::from("/nonexistent"),
        }
    }

    /// Destroy the epair, whether or not this controller created it.
    async fn detach_network(&mut self) -> Result<(), ControllerError> {
        let attachment = match self.local.attachment.take() {
            Some(attachment) => Some(attachment),
            None => self.discover_attachment().await,
        };
        let Some(attachment) = attachment else {
            return Ok(());
        };
        self.executor
            .network()
            .detach_task(&self.id, &attachment)
            .await?;
        Ok(())
    }

    /// `ocijail delete --force` plus the mount-leak sweep, tolerating a
    /// container ocijail never knew (docs/ocijail.md §4.3 idempotency trap).
    async fn delete_jail(&self) -> Result<(), ControllerError> {
        let rootfs = self.rootfs_for_sweep().await;
        match self
            .executor
            .runtime()
            .delete(&self.id, &rootfs, true)
            .await
        {
            Ok(report) => {
                if !report.leaked_mounts_cleaned.is_empty() {
                    tracing::warn!(
                        mounts = ?report.leaked_mounts_cleaned,
                        "swept mounts ocijail delete leaked"
                    );
                }
                Ok(())
            }
            Err(error) if error.is_not_found() => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Destroy the writable layer if it is still there, waiting out the prison
    /// that still holds it.
    ///
    /// A jail does not disappear the instant `ocijail delete` returns: it goes
    /// to `DYING` until its last reference is released, and **a dying prison
    /// still holds its root vnode**, which is an active vnode in the
    /// container's own filesystem. So `unmount(2)` refuses and `zfs destroy`
    /// fails with `cannot unmount '<rootfs>': pool or dataset is busy`.
    ///
    /// Nothing in userland shows that reference (`fstat` lists no file, no
    /// process is left in the jail, ocijail's `delete` reports no leaked
    /// mount), so the only observer is `jls`(8) — and it is exact: in all eight
    /// measured runs that were busy at all, the destroy succeeded in the *same*
    /// 250 ms sample in which the prison stopped being listed. The prison's
    /// disappearance is therefore the signal this waits on, not a count of
    /// attempts:
    ///
    /// ```text
    /// +00.00s  jail=DYING  vnodes=2  fstat=0  -> pool or dataset is busy
    /// +57.75s  jail=-      vnodes=2  fstat=0  -> destroyed
    /// ```
    ///
    /// How long that takes is set by the kernel, not by us: a VNET prison
    /// cannot finish dying while its network stack still holds TCP control
    /// blocks, so a container that had a live connection keeps its rootfs busy
    /// for up to 2 x MSL (58 s typical, 77 s when the epair was destroyed
    /// first and the FIN had nowhere to go; proven by setting `msl` inside the
    /// jail's own VNET, which moved the window to 4 s). That is why a bigger
    /// retry budget was never the answer: 30 s was not "nearly enough", it was
    /// on the wrong side of a kernel timer, and no budget that fits on the
    /// assignment path can be on the right side of it.
    ///
    /// Exhausting [`ROOTFS_BUSY_BUDGET`] is therefore a **deferral**, not a
    /// failure: the dataset is left to `satld`'s periodic dataset sweep, which
    /// is level-triggered, runs off this path and destroys it as soon as the
    /// prison is gone — no restart, no operator.
    async fn destroy_rootfs(&self) -> Result<(), ControllerError> {
        let dataset = self.executor.container_dataset(&self.id);
        let started = tokio::time::Instant::now();
        let mut announced = false;
        let mut jail_gone_since: Option<tokio::time::Instant> = None;
        loop {
            if !self.executor.zfs().dataset_exists(&dataset).await? {
                return Ok(());
            }
            let error = match self.executor.container_fs().destroy(&self.id).await {
                Ok(()) => {
                    if announced {
                        tracing::info!(
                            task_id = %self.id,
                            %dataset,
                            waited_ms = started.elapsed().as_millis(),
                            "destroyed the container rootfs once its jail had \
                             finished dying"
                        );
                    }
                    return Ok(());
                }
                Err(error) if is_unmount_busy(&error) => error,
                Err(error) => return Err(error.into()),
            };

            let jail = self.jail_state().await;
            if let Some(state) = jail {
                jail_gone_since = None;
                // Once at info, then debug: an operator has to see that this
                // happens at all, without a line every 250 ms.
                if announced {
                    tracing::debug!(task_id = %self.id, jail_state = %state, "still busy");
                } else {
                    announced = true;
                    tracing::info!(
                        task_id = %self.id,
                        %dataset,
                        jail_state = %state,
                        "the container rootfs is still mounted because its jail has not \
                         finished dying; waiting for that jail to go"
                    );
                }
            } else {
                // No prison, still busy: not the case we understand. Give it a
                // few moments in case the unmount is simply a beat behind, then
                // stop waiting on a signal that will never come.
                let since = *jail_gone_since.get_or_insert_with(tokio::time::Instant::now);
                if since.elapsed() >= ROOTFS_UNEXPLAINED_BUSY {
                    self.defer_rootfs(&dataset, started, None, &error);
                    return Ok(());
                }
            }

            if started.elapsed() >= ROOTFS_BUSY_BUDGET {
                self.defer_rootfs(&dataset, started, jail, &error);
                return Ok(());
            }
            tokio::time::sleep(ROOTFS_BUSY_RETRY).await;
        }
    }

    /// The state of this task's prison, or `None` when there is none left.
    ///
    /// A `jls` that cannot run is reported and treated as "no prison": the
    /// wait then falls back to its short unexplained-busy path rather than
    /// sitting on a signal it cannot read.
    async fn jail_state(&self) -> Option<satl_runtime::JailState> {
        match self.executor.jails().state(&self.id).await {
            Ok(state) => state,
            Err(error) => {
                tracing::warn!(
                    task_id = %self.id,
                    %error,
                    "cannot ask jls whether this task's jail is still dying"
                );
                None
            }
        }
    }

    /// Hand a rootfs that is still busy to the node's periodic sweep.
    ///
    /// One warn line, carrying the identifiers an operator greps by and the
    /// `zfs` invocation that failed. Deliberately **not** an error: the removal
    /// has done everything it can, and the dataset is now the sweep's business
    /// (`crate::reconcile` in `satld`). Reporting it as a failed cleanup step
    /// would put an ERROR in the log for a node that is converging perfectly
    /// well, which is the same disservice as an ERROR for an empty state db.
    fn defer_rootfs(
        &self,
        dataset: &str,
        started: tokio::time::Instant,
        jail: Option<satl_runtime::JailState>,
        error: &satl_storage::ContainerFsError,
    ) {
        tracing::warn!(
            task_id = %self.id,
            dataset = %dataset,
            waited_ms = started.elapsed().as_millis(),
            jail_state = jail.map_or("gone", satl_runtime::JailState::as_str),
            %error,
            "the container rootfs is still busy; deferring it to the periodic \
             dataset sweep, which will destroy it once it can"
        );
    }

    /// Remove a task directory, tolerating "already gone".
    async fn remove_dir(&self, dir: PathBuf) -> Result<(), ControllerError> {
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(ControllerError::Io {
                task_id: self.id.clone(),
                what: "removing a task directory",
                path: dir,
                source,
            }),
        }
    }

    async fn remove_inner(&mut self) -> Result<(), ControllerError> {
        // Every step tolerates "already gone" and none of them short-circuits
        // the rest: this doubles as the reconciliation cleaner for
        // half-created tasks. The first failure is returned once everything
        // that could be cleaned has been.
        // Before anything else: no health probe may be running inside a jail
        // that is about to be deleted.
        self.stop_prober().await;
        self.executor.health().clear(&self.id);

        let mut first_error: Option<ControllerError> = None;
        let mut record = |step: &'static str, result: Result<(), ControllerError>| {
            if let Err(error) = result {
                tracing::error!(step, %error, "task cleanup step failed");
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        };

        let unpublished = self.executor.network().unpublish_ports(&self.id).await;
        record("unpublish-ports", unpublished.map_err(Into::into));
        // Overlay epairs first: they are members of the overlay bridge, and the
        // network's own teardown (the dispatcher's `remove_network`, ordered
        // after this task by `ObjectRef::teardown_rank`) must find nothing of
        // this task left on it.
        if let Some(overlay) = self.executor.overlay() {
            overlay.detach(&self.task.id).await;
        }
        let detached = self.detach_network().await;
        record("detach-network", detached);
        // Limits BEFORE the jail out of cleanliness, not necessity: the rules
        // survive the jail's death, and `rctl -r` on a dead subject still
        // works (measured), so a rule set orphaned here anyway is reaped by
        // the startup purge (satld's reconciliation pass). Removing them
        // while the subject is alive keeps the common case immediate.
        let limits_removed = self.executor.rctl().remove_limits(&self.id).await;
        record("remove-limits", limits_removed.map_err(Into::into));
        let deleted = self.delete_jail().await;
        record("delete-jail", deleted);
        let destroyed = self.destroy_rootfs().await;
        record("destroy-rootfs", destroyed);
        let bundle_removed = self.remove_dir(self.executor.bundle_dir(&self.id)).await;
        record("remove-bundle", bundle_removed);
        let logs_removed = self.remove_dir(self.executor.log_dir(&self.id)).await;
        record("remove-logs", logs_removed);
        let health_removed = self.remove_dir(self.executor.health_dir(&self.id)).await;
        record("remove-health", health_removed);

        self.local.rootfs = None;
        self.local.exit_watch = None;
        self.local.ports.clear();
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Find an epair still tagged with this task (interrupted teardown).
    async fn discover_attachment(&self) -> Option<TaskAttachment> {
        let owned = self.executor.network().list_owned().await.ok()?;
        let name = owned.into_iter().find_map(|iface| match iface.kind {
            satl_net::OwnedKind::Task { task_id } if task_id == self.id => Some(iface.name),
            _ => None,
        })?;
        let peer = epair_peer(&name)?;
        Some(TaskAttachment {
            epair_a: name,
            epair_b: peer,
            ip: std::net::Ipv4Addr::UNSPECIFIED,
            gateway: std::net::Ipv4Addr::UNSPECIFIED,
        })
    }

    fn span(&self, step: &'static str) -> tracing::Span {
        tracing::info_span!(
            "task_step",
            step,
            task_id = %self.id,
            service = %self.task.service_annotations.name,
        )
    }
}

impl TaskController for Controller {
    async fn prepare(&mut self) -> Result<(), ControllerError> {
        let span = self.span("prepare");
        self.prepare_inner().instrument(span).await
    }

    async fn start(&mut self) -> Result<(), ControllerError> {
        let span = self.span("start");
        self.start_inner().instrument(span).await
    }

    fn update(&mut self, task: Task) {
        debug_assert_eq!(
            task.id, self.task.id,
            "controller retargeted to another task"
        );
        if task.spec.resources != self.task.spec.resources {
            tracing::info!(
                limits = ?task.spec.resources.limits,
                reservations = ?task.spec.resources.reservations,
                "hot resize: rctl limits will be re-applied to the live jail"
            );
            self.local.pending_resize = true;
        }
        self.task = task;
    }

    async fn wait(&mut self) -> Result<ExitOutcome, ControllerError> {
        if let Some(exit) = &self.local.exit {
            return Ok(exit.clone());
        }
        let span = self.span("wait");
        self.wait_inner().instrument(span).await
    }

    async fn shutdown(&mut self) -> Result<(), ControllerError> {
        let span = self.span("shutdown");
        self.shutdown_inner().instrument(span).await
    }

    async fn remove(&mut self) -> Result<(), ControllerError> {
        let span = self.span("remove");
        self.remove_inner().instrument(span).await
    }

    fn container_status(&self) -> Option<ContainerStatus> {
        // Nothing to report until a jail exists (SWK §15.4 only harvests for
        // active states anyway).
        if self.local.pid.is_none() && self.local.exit.is_none() && self.local.jid.is_none() {
            return None;
        }
        Some(ContainerStatus {
            jail_id: Some(self.id.clone()),
            pid: self.local.pid.map(i64::from),
            exit_code: self.local.exit.as_ref().and_then(ExitOutcome::exit_code),
        })
    }

    fn port_status(&self) -> Vec<PortStatus> {
        self.local.ports.clone()
    }

    fn status_note(&self) -> Option<&str> {
        self.local.limits_note.as_deref()
    }
}

/// The other end of an epair, by name (`epair3a` ⇄ `epair3b`).
fn epair_peer(name: &str) -> Option<String> {
    let (base, last) = name.split_at(name.len().checked_sub(1)?);
    match last {
        "a" => Some(format!("{base}b")),
        "b" => Some(format!("{base}a")),
        _ => None,
    }
}

/// Map a `STOPSIGNAL` string to its FreeBSD signal number. Accepts numeric
/// values, `SIGTERM` and bare `TERM` (ocijail itself only takes numbers —
/// docs/ocijail.md §4.2 — so all naming is resolved here).
fn signal_number(name: &str) -> Option<i32> {
    let trimmed = name.trim();
    if let Ok(number) = trimmed.parse::<i32>() {
        return (number > 0 && number < 128).then_some(number);
    }
    let upper = trimmed.to_ascii_uppercase();
    let bare = upper.strip_prefix("SIG").unwrap_or(&upper);
    // sys/signal.h numbering (FreeBSD 15.1); the set Docker images use.
    let number = match bare {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" | "IOT" => 6,
        "EMT" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "BUS" => 10,
        "SEGV" => 11,
        "SYS" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "URG" => 16,
        "STOP" => 17,
        "TSTP" => 18,
        "CONT" => 19,
        "CHLD" => 20,
        "TTIN" => 21,
        "TTOU" => 22,
        "IO" => 23,
        "XCPU" => 24,
        "XFSZ" => 25,
        "VTALRM" => 26,
        "PROF" => 27,
        "WINCH" => 28,
        "INFO" => 29,
        "USR1" => 30,
        "USR2" => 31,
        _ => return None,
    };
    Some(number)
}

/// Map the image pipeline's layer compression onto the storage crate's.
fn storage_compression(
    compression: satl_image::LayerCompression,
) -> satl_storage::LayerCompression {
    match compression {
        satl_image::LayerCompression::None => satl_storage::LayerCompression::None,
        satl_image::LayerCompression::Gzip => satl_storage::LayerCompression::Gzip,
        satl_image::LayerCompression::Zstd => satl_storage::LayerCompression::Zstd,
    }
}

/// Registry/transport failures are worth retrying; everything else about an
/// image is a definition problem (SWK §15.4 `Temporary`).
/// Render a `resolv.conf` from an explicit `--dns` configuration.
fn render_resolv_conf(dns: &satl_core::DnsConfig) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    for server in &dns.nameservers {
        let _ = writeln!(out, "nameserver {server}");
    }
    if !dns.search.is_empty() {
        let _ = writeln!(out, "search {}", dns.search.join(" "));
    }
    for option in &dns.options {
        let _ = writeln!(out, "options {option}");
    }
    out
}

fn image_error(error: satl_image::ImageError) -> ControllerError {
    // Audit N3: a 404 on the manifest GET is the locally-built-image case —
    // the task landed on a node whose store lacks the image. Name that and
    // the fix instead of leaving a bare `HTTP 404 MANIFEST_UNKNOWN`.
    if let satl_image::ImageError::RegistryStatus {
        registry,
        repository,
        context,
        status: 404,
        ..
    } = &error
        && let Some(reference) = context.strip_prefix("GET manifest ")
    {
        return ControllerError::ManifestUnknown {
            registry: registry.clone(),
            repository: repository.clone(),
            reference: reference.to_owned(),
        };
    }
    let temporary = matches!(
        &error,
        satl_image::ImageError::Http { .. }
            | satl_image::ImageError::TokenFetch { .. }
            | satl_image::ImageError::RegistryStatus {
                status: 408 | 429 | 500..=599,
                ..
            }
    );
    let error = ControllerError::from(error);
    if temporary { error.temporary() } else { error }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a still-mounted filesystem is worth retrying. Everything else must
    /// surface at once: a five-second stall followed by the same error is worse
    /// than the error.
    #[test]
    fn only_a_busy_unmount_is_treated_as_not_yet() {
        let zfs_failure = |stderr: &str| {
            satl_storage::ContainerFsError::Zfs(satl_storage::ZfsError::CommandFailed {
                argv: "/sbin/zfs destroy -r zroot/satl/containers/abc".to_owned(),
                exit_code: Some(1),
                stderr: stderr.to_owned(),
            })
        };
        // Verbatim from the cluster VMs, where a jail still in DYING state kept
        // the clone mounted.
        assert!(is_unmount_busy(&zfs_failure(
            "cannot unmount '/var/db/satl/containers/abc': pool or dataset is busy"
        )));
        // Not transient: a real dependency, a missing dataset, a bad name.
        assert!(!is_unmount_busy(&zfs_failure(
            "cannot destroy 'zroot/satl/containers/abc': filesystem has children"
        )));
        assert!(!is_unmount_busy(&zfs_failure(
            "cannot open 'zroot/satl/containers/abc': dataset does not exist"
        )));
        assert!(!is_unmount_busy(
            &satl_storage::ContainerFsError::InvalidTaskId {
                task_id: "../escape".to_owned(),
                reason: "must start with an ASCII letter or digit".to_owned(),
            }
        ));
    }

    #[test]
    fn resolv_conf_renders_nameservers_search_and_options() {
        let dns = satl_core::DnsConfig {
            nameservers: vec!["10.0.0.1".to_owned(), "8.8.8.8".to_owned()],
            search: vec!["example.com".to_owned(), "lan".to_owned()],
            options: vec!["ndots:2".to_owned()],
        };
        assert_eq!(
            render_resolv_conf(&dns),
            "nameserver 10.0.0.1\nnameserver 8.8.8.8\nsearch example.com lan\noptions ndots:2\n"
        );
    }

    #[test]
    fn resolv_conf_omits_empty_sections() {
        let dns = satl_core::DnsConfig {
            nameservers: vec!["1.1.1.1".to_owned()],
            search: Vec::new(),
            options: Vec::new(),
        };
        assert_eq!(render_resolv_conf(&dns), "nameserver 1.1.1.1\n");
    }

    #[test]
    fn epair_peers_flip_the_last_character_only() {
        assert_eq!(epair_peer("epair0a").as_deref(), Some("epair0b"));
        assert_eq!(epair_peer("epair12b").as_deref(), Some("epair12a"));
        assert_eq!(epair_peer("bridge0"), None);
        assert_eq!(epair_peer(""), None);
    }

    #[test]
    fn stop_signal_names_resolve_to_freebsd_numbers() {
        for (name, number) in [
            ("SIGTERM", 15),
            ("TERM", 15),
            ("term", 15),
            ("SIGKILL", 9),
            ("SIGUSR1", 30),
            ("SIGWINCH", 28),
            ("3", 3),
        ] {
            assert_eq!(signal_number(name), Some(number), "{name}");
        }
        assert_eq!(signal_number("SIGNOPE"), None);
        assert_eq!(signal_number("0"), None);
        assert_eq!(signal_number("999"), None);
    }

    #[test]
    fn exit_outcomes_describe_and_encode_the_docker_way() {
        let ok = ExitOutcome {
            code: Some(0),
            signal: None,
            unharvestable: None,
        };
        assert!(ok.is_success());
        assert_eq!(ok.exit_code(), Some(0));

        let failed = ExitOutcome {
            code: Some(42),
            signal: None,
            unharvestable: None,
        };
        assert!(!failed.is_success());
        assert_eq!(failed.exit_code(), Some(42));
        assert!(failed.describe().contains("code 42"));

        let killed = ExitOutcome {
            code: None,
            signal: Some(9),
            unharvestable: None,
        };
        assert!(!killed.is_success());
        // Docker/shell convention: 128 + signal.
        assert_eq!(killed.exit_code(), Some(137));
        assert!(killed.describe().contains("signal 9"));

        let unknown = ExitOutcome::from_status(satl_runtime::ExitStatus::unknown());
        assert!(!unknown.is_success());
        assert_eq!(unknown.exit_code(), None);
        assert!(unknown.describe().contains("already reaped"), "{unknown:?}");
    }

    #[test]
    fn image_transport_failures_are_retryable_and_definitions_are_not() {
        let transient = image_error(satl_image::ImageError::RegistryStatus {
            registry: "r".to_owned(),
            repository: "x".to_owned(),
            context: "GET manifest".to_owned(),
            status: 503,
            body: String::new(),
        });
        assert!(transient.is_temporary(), "{transient}");

        let terminal = image_error(satl_image::ImageError::RegistryStatus {
            registry: "r".to_owned(),
            repository: "x".to_owned(),
            context: "GET manifest".to_owned(),
            status: 404,
            body: String::new(),
        });
        assert!(!terminal.is_temporary(), "{terminal}");

        let bad_reference = image_error(satl_image::ImageError::InvalidReference {
            input: "@@".to_owned(),
            reason: "nope".to_owned(),
        });
        assert!(!bad_reference.is_temporary(), "{bad_reference}");
    }

    /// Audit N3: a 404 `MANIFEST_UNKNOWN` on the manifest GET is the signature
    /// of a locally-built image whose task landed on a node whose store
    /// lacks it. The status error must say so and name the fix.
    #[test]
    fn a_manifest_unknown_pull_names_the_node_local_cause_and_the_fix() {
        let error = image_error(satl_image::ImageError::RegistryStatus {
            registry: "node1:5000".to_owned(),
            repository: "web".to_owned(),
            context: "GET manifest latest".to_owned(),
            status: 404,
            body: r#"{"errors":[{"code":"MANIFEST_UNKNOWN"}]}"#.to_owned(),
        });
        let text = error.to_string();
        assert!(text.contains("no such manifest"), "{text}");
        assert!(text.contains("node1:5000"), "{text}");
        assert!(text.contains("web"), "{text}");
        assert!(text.contains("latest"), "{text}");
        // The actionable hint, one ASCII sentence.
        assert!(text.contains("another node's local store"), "{text}");
        assert!(text.contains("satl push"), "{text}");
        assert!(text.is_ascii(), "{text}");
        // Still terminal: retrying a missing manifest just delays the verdict.
        assert!(!error.is_temporary(), "{error}");
    }

    /// Every other pull failure keeps its current message (audit N3 touches
    /// only the manifest-unknown case).
    #[test]
    fn other_pull_failures_keep_their_messages() {
        // A 404 that is not a manifest fetch (here: a missing blob) keeps the
        // raw registry message, no node-locality hint.
        let blob = image_error(satl_image::ImageError::RegistryStatus {
            registry: "node1:5000".to_owned(),
            repository: "web".to_owned(),
            context: "GET blob sha256:abc".to_owned(),
            status: 404,
            body: String::new(),
        });
        let text = blob.to_string();
        assert!(text.contains("HTTP 404"), "{text}");
        assert!(!text.contains("satl push"), "{text}");

        // Auth failures are untouched.
        let auth = image_error(satl_image::ImageError::Unauthorized {
            registry: "node1:5000".to_owned(),
            repository: "web".to_owned(),
            reason: "credentials rejected after auth challenge".to_owned(),
            challenge: None,
        });
        let text = auth.to_string();
        assert!(text.contains("authentication failed"), "{text}");
        assert!(!text.contains("satl push"), "{text}");

        // Transport failures stay retryable and untouched.
        let transport = image_error(satl_image::ImageError::RegistryStatus {
            registry: "node1:5000".to_owned(),
            repository: "web".to_owned(),
            context: "GET manifest latest".to_owned(),
            status: 502,
            body: String::new(),
        });
        assert!(transport.is_temporary(), "{transport}");
        assert!(transport.to_string().contains("HTTP 502"), "{transport}");
    }

    #[tokio::test]
    async fn exit_watch_is_repeatable_and_cancel_safe() {
        let (tx, rx) = tokio::sync::watch::channel(None);
        let mut watch = ExitWatch { rx };
        // Cancelling a wait must not consume the outcome.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), watch.wait())
                .await
                .is_err()
        );
        tx.send(Some(ExitOutcome {
            code: Some(7),
            signal: None,
            unharvestable: None,
        }))
        .unwrap();
        assert_eq!(watch.wait().await.code, Some(7));
        assert_eq!(watch.wait().await.code, Some(7));
    }

    // ---- the overlay detach on a failed start -------------------------------

    use crate::executor::{Datasets, ExecutorParts, LinuxEmulation};
    use crate::overlay::TaskOverlay;
    use satl_net::{NetworkManager, NetworkManagerConfig, PfMode};
    use satl_runtime::{ExecSpec, Jails, OcijailRuntime};
    use satl_storage::{ContainerFsStore, LayerStore, VolumeStore, Zfs};

    /// A [`TaskOverlay`] that records the tasks `detach` was called for.
    #[derive(Default)]
    struct RecordingOverlay {
        detached: std::sync::Mutex<Vec<satl_core::Id>>,
    }

    #[async_trait::async_trait]
    impl TaskOverlay for RecordingOverlay {
        async fn resolv_conf(&self, _task: &Task) -> Option<String> {
            None
        }

        async fn attach(
            &self,
            _task: &Task,
            _jail: &str,
        ) -> Result<(), crate::overlay::OverlayError> {
            Ok(())
        }

        async fn detach(&self, task_id: &satl_core::Id) {
            self.detached
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(task_id.clone());
        }
    }

    /// The cheapest real [`Executor`]: every subsystem constructed over a
    /// tempdir and none of them ever driven — the test fabricates the
    /// controller's post-start local state directly.
    fn test_executor(dir: &std::path::Path, overlay: Arc<RecordingOverlay>) -> Arc<Executor> {
        let datasets = Datasets {
            root: "zroot/satl-test".to_owned(),
            layers_root: "zroot/satl-test/layers".to_owned(),
            containers_root: "zroot/satl-test/containers".to_owned(),
            volumes_root: "zroot/satl-test/volumes".to_owned(),
        };
        Arc::new(Executor::new(ExecutorParts {
            images: satl_image::ImageStore::open(dir.join("images")).expect("image store"),
            layers: LayerStore::new(Zfs::system(), datasets.layers_root.clone()),
            container_fs: ContainerFsStore::new(Zfs::system(), datasets.containers_root.clone()),
            volumes: VolumeStore::new(Zfs::system(), datasets.volumes_root.clone()),
            zfs: Zfs::system(),
            network: Arc::new(
                NetworkManager::open(NetworkManagerConfig {
                    state_dir: dir.join("net"),
                    pf_mode: PfMode::Disabled,
                    ..NetworkManagerConfig::default()
                })
                .expect("network manager"),
            ),
            runtime: OcijailRuntime::system(dir.join("ocijail"), dir.join("scratch")),
            jails: Jails::system(),
            rctl: crate::rctl::Rctl::system(false),
            state_dir: dir.to_path_buf(),
            datasets,
            linux: LinuxEmulation::new(false),
            racct_enabled: false,
            overlay: Some(overlay),
            dependencies: Arc::new(crate::deps::DependencyStore::new()),
        }))
    }

    /// A container that dies before its first probe verdict must release its
    /// overlay attachment at once, not at task removal.
    ///
    /// The allocator frees a terminal task's addresses (SWK §9.4) and the
    /// replacement — possibly on another node — can inherit one within
    /// seconds; an attachment kept until the manager-ordered removal made
    /// this node go on claiming the address, the endpoint read "both local
    /// and remote" and the FDB pass refused to program it, which the mesh
    /// showed as ~1/3 of the traffic lost. `wait_inner`'s exit arm got its
    /// detach in 678fecf; the health gate's exit arm, where a task that dies
    /// *before* its first probe lands, had none.
    #[tokio::test]
    async fn a_container_that_dies_before_its_first_probe_detaches_the_overlay() {
        let dir = tempfile::tempdir().expect("tempdir");
        let overlay = Arc::new(RecordingOverlay::default());
        let executor = test_executor(dir.path(), Arc::clone(&overlay));
        let mut controller = executor.controller(crate::testing::task());

        // The post-`ocijail start` local state, fabricated: a prober whose
        // first probe is one interval away, so nothing runs during the test,
        // and an exit watch that has already fired.
        let settings = ProbeSettings {
            argv: vec!["true".to_owned()],
            interval: Duration::from_hours(1),
            timeout: Duration::from_secs(1),
            retries: 3,
            start_period: Duration::ZERO,
        };
        let process = ExecSpec {
            terminal: false,
            user: None,
            args: vec!["/bin/true".to_owned()],
            env: Vec::new(),
            cwd: "/".to_owned(),
        };
        let task_id = controller.task().id.clone();
        controller.local.prober = Some(Prober::spawn(
            task_id.as_str().to_owned(),
            OcijailProbeRunner::new(
                executor.runtime().ocijail().clone(),
                task_id.as_str().to_owned(),
                process,
                dir.path().join("health"),
            ),
            settings,
            SystemTime::now(),
            Arc::clone(executor.health()),
        ));
        let (tx, rx) = tokio::sync::watch::channel(None);
        tx.send(Some(ExitOutcome {
            code: Some(1),
            signal: None,
            unharvestable: None,
        }))
        .expect("the receiver is alive");
        controller.local.exit_watch = Some(ExitWatch { rx });

        let error = controller
            .await_first_healthy()
            .await
            .expect_err("a dead container cannot pass the health gate");
        assert!(
            matches!(error, ControllerError::ExitedBeforeHealthy { .. }),
            "{error}"
        );
        assert_eq!(
            controller
                .local
                .exit
                .as_ref()
                .and_then(ExitOutcome::exit_code),
            Some(1)
        );
        assert_eq!(
            *overlay.detached.lock().expect("not poisoned"),
            [task_id],
            "the health gate's exit arm must detach the overlay, as wait_inner's does"
        );
    }

    /// The prepare gate (`host().linux_emulation`) and image selection
    /// (`platform_policy`) must read the linuxulator flag live through the
    /// shared handle: `kldload linux` after satld started takes effect
    /// without a daemon restart, and unloading it stops new linux/* tasks.
    #[test]
    fn host_facts_and_platform_policy_read_the_linux_handle_live() {
        let dir = tempfile::tempdir().expect("tempdir");
        let executor = test_executor(dir.path(), Arc::new(RecordingOverlay::default()));
        let linux = executor.linux();
        let linux_only = [satl_image::Platform::new("linux", "amd64")];

        assert!(!executor.host().linux_emulation);
        assert!(
            executor
                .platform_policy(None)
                .select(&linux_only, "img")
                .is_err(),
            "without the linuxulator a linux-only index must not resolve"
        );

        linux.set(true);
        assert!(executor.host().linux_emulation);
        assert!(
            executor
                .platform_policy(None)
                .select(&linux_only, "img")
                .is_ok(),
            "after set(true) the linux/amd64 fallback must be selectable"
        );

        linux.set(false);
        assert!(!executor.host().linux_emulation);
        assert!(
            executor
                .platform_policy(None)
                .select(&linux_only, "img")
                .is_err(),
            "after set(false) new linux/* selections must be refused again"
        );
    }
}
