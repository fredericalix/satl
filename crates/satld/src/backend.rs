// SPDX-License-Identifier: BSD-2-Clause
//! [`DaemonBackend`] — the daemon side of the Docker REST API
//! (`satl_api::Backend`).
//!
//! Everything Docker-shaped (status codes, JSON, framing) lives in
//! `satl-api`; everything here is SatL semantics, and the rules are short:
//!
//! - **every mutation goes through the leader's store** (invariant #1),
//!   forwarded over `Control.ProposeActions` when this manager is a follower
//!   (architecture §6.5). There is
//!   no side channel: the backend never calls the orchestrator, the
//!   scheduler, the dispatcher or the worker to make something happen. It
//!   writes intent into the store and the loops do their jobs.
//! - **a container is a Task of a single-replica anonymous service**
//!   (invariant #2), so `docker create` writes a *Service* and the container
//!   ID is the ID of the task the orchestrator then creates.
//! - handlers stay thin: read a view, build actions, propose, render.
//!
//! ## Why `create_container` waits for the orchestrator
//!
//! `POST /containers/create` must answer with the container ID, which is the
//! task ID — but the API is not allowed to invent one. Task creation belongs
//! to the replicated orchestrator (architecture §5 step 2): it owns slot
//! numbering, the spec snapshot, `spec_version`, and the `satl.autostart`
//! contract that decides whether a new task is born desired-`READY`
//! (`docker create`) or desired-`RUNNING` (`docker run`). A backend that
//! wrote the task itself would be a second writer of the same object, would
//! race the orchestrator's own reconcile pass into a duplicate task, and
//! would have to re-implement rules that exist exactly once today.
//!
//! So the backend proposes the Service, then *watches the store* for the task
//! the orchestrator creates for it, bounded by [`CREATE_TIMEOUT`]. On a
//! single node this is one Raft round-trip plus one orchestrator pass —
//! milliseconds. If it times out (no leader, orchestrator wedged), the
//! service is rolled back and the client gets a 500 that says what did not
//! happen, rather than a container ID that does not exist.
//!
//! ## Optimistic concurrency
//!
//! Store objects carry `meta.version`; a write built from a stale read is
//! rejected as a sequence conflict (architecture §3). Every mutating handler
//! therefore goes through [`DaemonBackend::propose_from_view`], which rebuilds
//! its actions from a fresh view and retries a bounded number of times — the
//! same pattern the orchestration loops use.

pub mod events;
pub mod exec;
pub mod logs;
pub mod names;
pub mod networks;
pub mod prune;
pub mod secrets;
pub mod swarm;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use futures_util::stream::{BoxStream, StreamExt as _};
use satl_agent::Executor;
use satl_api::model::{
    BackendError, ChangeOutcome, ConfigCreated, ContainerConfig, ContainerHealth,
    ContainerHealthLog, ContainerInspect, ContainerRuntimeState, ContainerSummary, Counts,
    CreateContainerOptions, CreateNetworkOptions, CreateVolumeOptions, CreatedContainer,
    EventMessage, ExecConfig, ExecId, ExecInspect, ExecStream, ExposedPort, HostConfig,
    ImageConfigDoc, ImageInspect, ImageSummary, LogFrame, LogOptions, NetworkConnectOptions,
    NetworkCreated, NetworkDetail, NetworkDisconnectOptions, NetworkSettings, NetworkSummary,
    NodeDetail, NodeSpecUpdate, NodeSummary, PortMapping, ProgressDetail, PrunedContainers,
    PrunedImages, PrunedNetworks, PrunedVolumes, PullProgressLine, RegistryAuth, Result,
    SecretCreated, ServiceCreateOptions, ServiceCreated, ServiceDetail, ServiceSummary,
    ServiceUpdateOptions, SwarmDetail, SwarmInitOptions, SwarmInitResult, SwarmJoinOptions,
    SwarmStatus, TaskDetail, TaskFilters, TaskSummary, TokenRole, VolumeInfo, WaitCondition,
    WaitResult,
};
use satl_cluster::{ClusterStore, ForwardError, ProposalRejection, StoreView};
use satl_core::{
    Annotations, ContainerSpec, DesiredState, EndpointMode, EndpointSpec, Id, Meta, ObjectKind,
    Placement, ResourceRequirements, Resources, Service, ServiceMode, ServiceSpec, StoreAction,
    StoreObject, Task, TaskSpec, TaskState, Version,
};
use satl_image::{ImageError, ImageReference, PullProgress};
use satl_net::{LocalIpam, SubnetV4};
use tokio::sync::broadcast::error::RecvError;

use crate::node::NodeRuntime;

/// How long `create_container` waits for the orchestrator to create the task
/// backing the service it just wrote.
pub const CREATE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long `remove_container` waits for the task to actually disappear
/// before answering anyway (removal is asynchronous: the agent stops the
/// container, then the reaper deletes the object).
pub const REMOVE_TIMEOUT: Duration = Duration::from_secs(30);

/// Attempts a mutating handler makes before giving up on optimistic
/// concurrency.
const MAX_PROPOSE_ATTEMPTS: u32 = 5;

/// Capacity of the daemon's own event channel (image events).
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Exit code reported when a container's real one could not be harvested.
const UNKNOWN_EXIT_CODE: i64 = 255;

/// The Docker REST API, backed by the cluster store and the node runtime.
pub struct DaemonBackend {
    /// The cluster, read through a slot rather than held directly: `swarm
    /// join` replaces the whole cluster runtime underneath a live daemon
    /// (`crate::cluster`), and a backend holding a stale `ClusterStore` would
    /// keep answering from the cluster this node just left.
    cluster: Arc<crate::cluster::ClusterSlot>,
    executor: Arc<Executor>,
    /// The node's local task DB — what a worker's container surface answers
    /// from (a worker holds no store; its records are its assignments).
    task_db: satl_agent::TaskDb,
    state_dir: std::path::PathBuf,
    net_state_dir: std::path::PathBuf,
    net_pool: SubnetV4,
    network_name: String,
    execs: exec::ExecRegistry,
    /// Dataset names, for the reclamation `satl system prune` does: the layer
    /// GC reads clone origins across the whole SatL tree and measures volumes by
    /// dataset, and re-deriving those names here is how two spellings of the
    /// same path start to disagree.
    datasets: satl_agent::Datasets,
    /// Events that do not come from the store (image pulls).
    local_events: tokio::sync::broadcast::Sender<EventMessage>,
}

impl std::fmt::Debug for DaemonBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonBackend")
            .field("state_dir", &self.state_dir)
            .field("execs", &self.execs)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Construction and shared helpers
// ---------------------------------------------------------------------------

impl DaemonBackend {
    /// Build the backend from the cluster slot and the node runtime.
    #[must_use]
    pub fn new(cluster: Arc<crate::cluster::ClusterSlot>, node: &NodeRuntime) -> Self {
        let (local_events, _) = tokio::sync::broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            cluster,
            executor: Arc::clone(&node.executor),
            task_db: node.task_db.clone(),
            state_dir: node.state_dir.clone(),
            net_state_dir: node.net_state_dir.clone(),
            net_pool: node.net_pool,
            network_name: node.network_name.clone(),
            execs: exec::ExecRegistry::new(),
            datasets: node.datasets.clone(),
            local_events,
        }
    }

    /// The current cluster snapshot.
    ///
    /// `None` only between process start and the first bring-up, which the
    /// REST server is not yet accepting connections during — so this is a
    /// "cannot happen" that is answered rather than asserted.
    fn cluster(&self) -> Result<Arc<crate::cluster::ClusterCore>> {
        self.cluster.get().ok_or_else(|| {
            BackendError::internal("this node has no cluster runtime; satld must be restarted")
        })
    }

    /// The manager half of the cluster, or Docker's worker refusal.
    ///
    /// This is the one seam through which every cluster-scoped endpoint
    /// answers a worker: 503 with moby's own `errNoManager` sentence, exactly
    /// what `docker service ls` gets on a Docker worker.
    fn manager(&self) -> Result<crate::cluster::ManagerCore> {
        Self::manager_of(self.cluster()?.as_ref())
    }

    /// [`Self::manager`] for a snapshot the caller already holds.
    pub(crate) fn manager_of(
        cluster: &crate::cluster::ClusterCore,
    ) -> Result<crate::cluster::ManagerCore> {
        cluster
            .manager
            .clone()
            .ok_or_else(BackendError::not_a_swarm_manager)
    }

    /// The replicated store of the cluster this node currently belongs to,
    /// or Docker's worker refusal on a node holding none.
    fn store(&self) -> Result<ClusterStore> {
        Ok(self.manager()?.store)
    }

    /// This node's tasks as its local task DB records them (status merged:
    /// the persisted status is canonical, architecture §7.2) — the container
    /// surface a worker serves `ps`/`inspect`/`logs`/`exec` from.
    async fn local_tasks(&self) -> Result<Vec<Task>> {
        self.task_db
            .list()
            .await
            .map(|records| {
                let mut tasks: Vec<Task> = records
                    .into_iter()
                    .map(|record| {
                        let mut task = record.task;
                        task.status = record.status;
                        task
                    })
                    .collect();
                tasks.sort_by(|a, b| a.id.cmp(&b.id));
                tasks
            })
            .map_err(|error| {
                BackendError::internal(format!("cannot read this node's local task db: {error}"))
            })
    }

    /// One local task by id, id prefix or container name — the worker-side
    /// counterpart of [`names::resolve_task`].
    async fn local_task(&self, reference: &str) -> Result<Task> {
        let tasks = self.local_tasks().await?;
        names::resolve_local(&tasks, reference)
    }

    /// Rebuild `build`'s actions from a fresh store view and propose them on
    /// the cluster leader — forwarding when this node is not it (architecture
    /// §6.5) — retrying sequence conflicts (§3, optimistic concurrency).
    ///
    /// An empty action list means "nothing to do": the value is returned
    /// without touching the store, which is how the lifecycle handlers report
    /// [`ChangeOutcome::Unchanged`].
    async fn propose_from_view<T, F>(&self, what: &'static str, build: F) -> Result<T>
    where
        F: Fn(&StoreView<'_>) -> Result<(Vec<StoreAction>, T)>,
    {
        for attempt in 1..=MAX_PROPOSE_ATTEMPTS {
            // Scope the view: its guard is !Send and must not cross an await.
            let (actions, value) = {
                let store = self.store()?;
                let view = store.view();
                build(&view)?
            };
            if actions.is_empty() {
                return Ok(value);
            }
            let manager = self.manager()?;
            match manager
                .leader
                .propose(actions, satl_cluster::forward::local_identity())
                .await
            {
                Ok(_) => return Ok(value),
                Err(ForwardError::Rejected(ProposalRejection::SequenceConflict { .. })) => {
                    tracing::debug!(
                        what,
                        attempt,
                        "sequence conflict; retrying from a fresh view"
                    );
                }
                Err(err) => return Err(swarm::forward_error(what, &manager, &err)),
            }
        }
        Err(BackendError::conflict(format!(
            "cannot {what}: the object kept changing underneath ({MAX_PROPOSE_ATTEMPTS} attempts)"
        )))
    }

    /// The IPAM state as the network manager last persisted it.
    ///
    /// Read-only: the authoritative copy lives in the network manager the
    /// executor owns, which writes it atomically on every allocation, so a
    /// second reader always sees a consistent snapshot. Opening it does
    /// blocking file I/O, hence `spawn_blocking`.
    async fn ipam(&self) -> Option<LocalIpam> {
        let dir = self.net_state_dir.clone();
        let pool = self.net_pool;
        match tokio::task::spawn_blocking(move || LocalIpam::open_with_pool(dir, pool)).await {
            Ok(Ok(ipam)) => Some(ipam),
            Ok(Err(error)) => {
                tracing::warn!(%error, "cannot read the node IPAM state");
                None
            }
            Err(error) => {
                tracing::warn!(%error, "IPAM read task failed");
                None
            }
        }
    }

    /// The address allocated to `task_id` on the node-local network.
    fn address_of(&self, ipam: Option<&LocalIpam>, task_id: &Id) -> Option<Ipv4Addr> {
        ipam?.address_of(&self.network_name, task_id.as_str())
    }

    /// Image reference → the platform that image was pulled for, used to fill
    /// the PLATFORM column (see [`resolved_platform`]). A store read failure
    /// only costs the column, so it degrades to an empty map.
    async fn image_platforms(&self) -> BTreeMap<String, satl_core::Platform> {
        match self.executor.images().list().await {
            Ok(images) => images
                .into_iter()
                .map(|image| {
                    (
                        image.reference,
                        satl_core::Platform {
                            os: image.platform.os,
                            arch: image.platform.architecture,
                        },
                    )
                })
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "cannot read image platforms for the container list");
                BTreeMap::new()
            }
        }
    }

    /// The per-task log directory (`<state_dir>/logs/<task id>`).
    fn log_dir(&self, task_id: &Id) -> std::path::PathBuf {
        self.executor.log_dir(task_id.as_str())
    }

    /// Wait until `predicate` holds for the task, or the deadline passes.
    ///
    /// `timeout` of `None` waits indefinitely — `POST /containers/{id}/wait`
    /// has no deadline of its own; the client hanging up drops this future.
    /// Returns the last observed task (`None` once it is gone from the store)
    /// and whether the predicate was satisfied. Watching starts *before* the
    /// first read, so a transition between the two cannot be missed.
    async fn watch_task(
        &self,
        task_id: &Id,
        timeout: Option<Duration>,
        predicate: impl Fn(Option<&Task>) -> bool,
    ) -> (Option<Task>, bool) {
        let Ok(store) = self.store() else {
            return (None, false);
        };
        let mut events = store.watch();
        let deadline = timeout.map(|timeout| tokio::time::Instant::now() + timeout);
        let mut last: Option<Task> = None;
        loop {
            // Scope the view: its guard is !Send and must not cross an await.
            let current = {
                let view = store.view();
                view.task(task_id).map(|task| (*task).clone())
            };
            if predicate(current.as_ref()) {
                return (current, true);
            }
            if current.is_some() {
                last = current;
            }
            let received = match deadline {
                None => events.recv().await,
                Some(deadline) => {
                    if tokio::time::Instant::now() >= deadline {
                        return (last, false);
                    }
                    match tokio::time::timeout_at(deadline, events.recv()).await {
                        Ok(received) => received,
                        Err(_elapsed) => return (last, false),
                    }
                }
            };
            match received {
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return (last, false),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Store object → API model
// ---------------------------------------------------------------------------

/// The runtime state Docker renders as `State`/`Status`.
///
/// `health` is this node's view of the task's healthcheck ([`local_health`]),
/// which is `None` for a task without one and for a task running on another
/// node: health is node-local and never enters the store (invariant #1,
/// `docs/api-compat.md` #87).
#[must_use]
pub fn runtime_state(task: &Task, health: Option<ContainerHealth>) -> ContainerRuntimeState {
    let container = task.status.container.as_ref();
    let state = task.status.state;
    ContainerRuntimeState {
        health,
        task_state: state,
        desired_state: task.desired_state,
        exit_code: container.and_then(|container| container.exit_code),
        error: task.status.err.clone(),
        // The task carries one timestamp — the last transition. That *is*
        // the start time while the task runs and the finish time once it
        // stopped, which is exactly where Docker uses each of them.
        //
        // `STARTING` counts as started: it maps to Docker's `running` state
        // (docs/api-compat.md #2) and it is where a health-gated task waits for
        // its first probe (#87), which can be a while — a "running" container
        // with Go's zero `StartedAt` would render as a bare `Up` with no
        // duration for all of it.
        started_at: (state >= TaskState::Starting).then(|| {
            if state == TaskState::Starting || state == TaskState::Running {
                task.status.timestamp
            } else {
                task.meta.created_at
            }
        }),
        finished_at: state.is_terminal().then_some(task.status.timestamp),
        pid: container.and_then(|container| container.pid),
    }
}

/// This node's health for a task, in the API model.
///
/// Node-local by construction: the prober writes into the executor's registry
/// and nothing serializes it. On a manager listing the whole cluster, tasks
/// placed elsewhere therefore carry no `State.Health` — the honest answer, since
/// only the node running a container probes it.
fn local_health(registry: &satl_agent::HealthRegistry, task: &Task) -> Option<ContainerHealth> {
    let health = registry.get(task.id.as_str())?;
    Some(ContainerHealth {
        status: health.status.as_str().to_owned(),
        failing_streak: health.failing_streak,
        log: health
            .log
            .into_iter()
            .map(|result| ContainerHealthLog {
                start: result.start,
                end: result.end,
                exit_code: result.exit_code,
                output: result.output,
            })
            .collect(),
    })
}

/// Host port bindings currently in effect for a task.
fn port_mappings(task: &Task) -> Vec<PortMapping> {
    task.status
        .port_status
        .iter()
        .map(|port| PortMapping::from_port_config(port, Some("0.0.0.0".to_owned())))
        .collect()
}

/// The ports a container declares it listens on (`ExposedPorts`).
fn exposed_ports(task: &Task) -> Vec<ExposedPort> {
    task.endpoint
        .iter()
        .flat_map(|endpoint| endpoint.spec.ports.iter())
        .map(|port| ExposedPort {
            port: port.target_port,
            protocol: port.protocol,
        })
        .collect()
}

/// One row of `docker ps`.
/// The platform a task actually runs on.
///
/// `spec.platform` only carries what the *caller requested* (`--platform`), so
/// it is empty for the common case. The platform that matters operationally is
/// the one selected when the image was resolved — notably whether a
/// `linux/amd64` image is running under the linuxulator — so fall back to the
/// pulled image's platform (architecture §9: `satl ps`/`satl images` show a
/// PLATFORM column).
///
/// The map is keyed on the **canonical** reference, because that is how the
/// image store keys its records, so the raw spec string goes through
/// [`satl_image::canonical_key`] before the lookup. The honest-empty cases —
/// the image was never pulled on this node, the image was removed, the task
/// runs on another node — stay empty on purpose; persisting the resolved
/// platform on the task is deliberately out of scope, task specs are
/// immutable (api-compat #30).
fn resolved_platform(
    task: &Task,
    images: &BTreeMap<String, satl_core::Platform>,
) -> Option<satl_core::Platform> {
    task.spec.container.platform.clone().or_else(|| {
        images
            .get(&satl_image::canonical_key(&task.spec.container.image))
            .cloned()
    })
}

fn container_summary(
    task: &Task,
    ip: Option<Ipv4Addr>,
    network: &str,
    platform: Option<satl_core::Platform>,
    health: Option<ContainerHealth>,
) -> ContainerSummary {
    let spec = &task.spec.container;
    let mut command = spec.command.clone();
    command.extend(spec.args.iter().cloned());
    ContainerSummary {
        id: task.id.to_string(),
        name: names::container_name(task),
        image: spec.image.clone(),
        image_id: String::new(),
        command,
        created: task.meta.created_at,
        state: runtime_state(task, health),
        ports: port_mappings(task),
        labels: spec.labels.clone(),
        mounts: spec.mounts.clone(),
        network_name: network.to_owned(),
        ip_address: ip.map(|ip| ip.to_string()),
        platform,
    }
}

/// The `docker inspect` document for a task.
fn container_inspect(
    task: &Task,
    ip: Option<Ipv4Addr>,
    subnet: Option<SubnetV4>,
    network: &str,
    platform: Option<satl_core::Platform>,
    health: Option<ContainerHealth>,
) -> ContainerInspect {
    let spec = &task.spec.container;
    let (path, args) = match (spec.command.first(), spec.args.first()) {
        (Some(entrypoint), _) => (
            entrypoint.clone(),
            spec.command[1..]
                .iter()
                .chain(spec.args.iter())
                .cloned()
                .collect(),
        ),
        (None, Some(command)) => (command.clone(), spec.args[1..].to_vec()),
        (None, None) => (String::new(), Vec::new()),
    };
    let limits = task.spec.resources.limits.unwrap_or_default();
    ContainerInspect {
        id: task.id.to_string(),
        name: names::container_name(task),
        created: task.meta.created_at,
        image: spec.image.clone(),
        image_id: String::new(),
        path,
        args,
        state: runtime_state(task, health),
        config: ContainerConfig {
            hostname: spec.hostname.clone(),
            user: spec.user.clone(),
            env: spec.env.clone(),
            cmd: spec.args.clone(),
            entrypoint: spec.command.clone(),
            working_dir: spec.dir.clone(),
            labels: spec.labels.clone(),
            tty: spec.tty,
            open_stdin: spec.open_stdin,
            image: spec.image.clone(),
            exposed_ports: exposed_ports(task),
        },
        host_config: HostConfig {
            binds: Vec::new(),
            tmpfs: BTreeMap::new(),
            port_bindings: port_mappings(task),
            memory: limits.memory_bytes,
            nano_cpus: limits.nano_cpus,
            restart_policy: task.spec.restart,
            auto_remove: false,
            network_mode: network.to_owned(),
        },
        network: NetworkSettings {
            network_name: network.to_owned(),
            network_id: None,
            ip_address: ip.map(|ip| ip.to_string()),
            ip_prefix_len: subnet.map_or(0, SubnetV4::prefix_len),
            gateway: subnet.map(|subnet| subnet.gateway().to_string()),
            mac_address: None,
            ports: port_mappings(task),
        },
        mounts: spec.mounts.clone(),
        platform,
        jail_id: task
            .status
            .container
            .as_ref()
            .and_then(|container| container.jail_id.clone()),
        restart_count: 0,
    }
}

/// Whether a container shows up in `docker ps` without `--all`.
fn is_running(task: &Task) -> bool {
    matches!(task.status.state, TaskState::Starting | TaskState::Running)
}

/// Whether stopping this container would do anything — Docker's "is it
/// running?" test, which drives three answers at once: `stop` reports `304`
/// when it is false, `kill` reports `409`, and `rm` does *not* demand
/// `--force`.
///
/// A container nobody started yet counts as not running even though its task
/// is alive: `desired_state` is still `READY` (the `satl.autostart` contract),
/// which is exactly Docker's `created`. A container being started counts as
/// running from the moment `start` raised the desired state, so a `stop`
/// racing a slow `prepare` still stops it.
fn is_stoppable(task: &Task) -> bool {
    task.desired_state >= DesiredState::Running
        && task.desired_state < DesiredState::Shutdown
        && !task.status.state.is_terminal()
}

/// The repository part of a canonical reference (`registry/name:tag` →
/// `registry/name`).
fn repository_of(reference: &str) -> &str {
    match reference.rsplit_once(':') {
        Some((repository, tag)) if !tag.contains('/') => repository,
        _ => reference,
    }
}

/// One row of `docker images`.
fn image_summary(image: &satl_image::PulledImage, containers: i64) -> ImageSummary {
    let digest = image.manifest_digest.to_string();
    ImageSummary {
        id: digest.clone(),
        parent_id: String::new(),
        repo_tags: vec![image.reference.clone()],
        repo_digests: vec![format!("{}@{digest}", repository_of(&image.reference))],
        created: image.created,
        size: image
            .layers
            .iter()
            .map(|layer| i64::try_from(layer.size).unwrap_or(i64::MAX))
            .sum(),
        shared_size: 0,
        labels: BTreeMap::new(),
        containers,
        platform: Some(satl_core::Platform {
            os: image.platform.os.clone(),
            arch: image.platform.architecture.clone(),
        }),
    }
}

/// A pull progress event, as Docker's `JSONMessage`.
fn pull_line(progress: &PullProgress) -> PullProgressLine {
    match progress {
        PullProgress::Resolving { reference } => {
            PullProgressLine::status(format!("Pulling from {reference}"))
        }
        PullProgress::Resolved {
            manifest_digest,
            platform,
        } => PullProgressLine::status(format!("Digest: {manifest_digest} ({platform})")),
        PullProgress::LayerStarted { digest, size } => PullProgressLine {
            status: "Downloading".to_owned(),
            id: Some(short_digest(&digest.to_string())),
            progress_detail: Some(ProgressDetail {
                current: Some(0),
                total: Some(*size),
            }),
            progress: None,
            error: None,
        },
        PullProgress::LayerAlreadyPresent { digest } => PullProgressLine {
            status: "Already exists".to_owned(),
            id: Some(short_digest(&digest.to_string())),
            ..PullProgressLine::default()
        },
        PullProgress::LayerDone { digest } => PullProgressLine {
            status: "Download complete".to_owned(),
            id: Some(short_digest(&digest.to_string())),
            ..PullProgressLine::default()
        },
        PullProgress::Complete { manifest_digest } => {
            PullProgressLine::status(format!("Digest: {manifest_digest}"))
        }
    }
}

/// Docker's 12-character layer id.
fn short_digest(digest: &str) -> String {
    let hex = digest.rsplit(':').next().unwrap_or(digest);
    hex.chars().take(12).collect()
}

// ---------------------------------------------------------------------------
// Create: options → ServiceSpec
// ---------------------------------------------------------------------------

/// Build the anonymous single-replica service backing one container.
///
/// The `satl.autostart = "false"` label is the contract with the orchestrator
/// (`satl_orchestrator::AUTOSTART_LABEL`): tasks are born desired-`READY`,
/// i.e. Docker's `created`, and `start_container` promotes them.
#[must_use]
pub fn service_spec(name: String, options: &CreateContainerOptions) -> ServiceSpec {
    let limits = match (options.memory, options.nano_cpus) {
        (None, None) => None,
        (memory, nano_cpus) => Some(Resources {
            nano_cpus: nano_cpus.unwrap_or(0),
            memory_bytes: memory.unwrap_or(0),
        }),
    };
    ServiceSpec {
        annotations: Annotations {
            name,
            labels: BTreeMap::from([(
                satl_orchestrator::AUTOSTART_LABEL.to_owned(),
                "false".to_owned(),
            )]),
        },
        task: TaskSpec {
            container: ContainerSpec {
                image: options.image.clone(),
                labels: options.labels.clone(),
                command: options.entrypoint.clone(),
                args: options.cmd.clone(),
                hostname: options.hostname.clone(),
                env: options.env.clone(),
                dir: options.working_dir.clone(),
                user: options.user.clone(),
                groups: Vec::new(),
                tty: options.tty,
                open_stdin: false,
                read_only: false,
                stop_signal: None,
                stop_grace_period: None,
                healthcheck: None,
                hosts: Vec::new(),
                dns_config: None,
                mounts: options.mounts(),
                secrets: Vec::new(),
                configs: Vec::new(),
                pull_options: None,
                platform: options.platform.clone(),
            },
            resources: ResourceRequirements {
                limits,
                reservations: None,
            },
            restart: options.restart_policy,
            placement: Placement::default(),
            networks: Vec::new(),
            force_update: 0,
        },
        mode: ServiceMode::Replicated { replicas: 1 },
        update: None,
        rollback: None,
        endpoint: Some(EndpointSpec {
            mode: EndpointMode::DnsRR,
            ports: options.port_configs(),
        }),
    }
}

/// The endpoint a freshly created container service starts with.
///
/// `Service.endpoint` is normally allocator-written (SWK §9), and M3's real
/// allocator will own this. It is filled here because M1's allocator is a
/// no-op and **host-mode ports need no allocation**: the client named the
/// host port itself (architecture §11.4 — host mode is "bound only on nodes
/// running a task; no central allocation"). Without it the port never reaches
/// the task (`Task.endpoint.ports` is what the controller publishes from) and
/// `-p` would silently do nothing.
///
/// Ports asking for a *dynamic* host port (`published_port == 0`) are left
/// out: those genuinely need an allocator, and `create_warnings` says so.
#[must_use]
pub fn initial_endpoint(spec: &EndpointSpec) -> satl_core::Endpoint {
    satl_core::Endpoint {
        ports: spec
            .ports
            .iter()
            .filter(|port| {
                port.publish_mode == satl_core::PublishMode::Host && port.published_port != 0
            })
            .cloned()
            .collect(),
        spec: spec.clone(),
    }
}

/// Non-fatal notes about options SatL accepts but does not fully honour in
/// M1 (each one is recorded in `docs/api-compat.md`).
fn create_warnings(options: &CreateContainerOptions) -> Vec<String> {
    let mut warnings = Vec::new();
    if options.auto_remove {
        warnings.push(
            "HostConfig.AutoRemove is recorded but not acted on: the container is not \
             removed when it exits"
                .to_owned(),
        );
    }
    if options
        .port_bindings
        .iter()
        .any(|binding| binding.host_port == 0)
    {
        warnings.push(
            "a published port with no host port is not allocated: publish an explicit \
             host port (-p 8080:80)"
                .to_owned(),
        );
    }
    // Deliberately *not* warned about here: a published container with no
    // healthcheck. Every container has none -- `POST /containers/create` does
    // not read Docker's `Config.Healthcheck` at all (`service_spec` below sets
    // `healthcheck: None`, `docs/api-compat.md` #127) and `satl run` has no
    // `--health-cmd` to offer -- so the warning would fire on `satl run -d -p
    // 8080:80 <image>`, the most common command on a one-node install, with no
    // way for the operator to comply. A warning nobody can act on is how a
    // warning that matters gets ignored. The service path warns instead, where
    // a healthcheck *can* be declared, and what a published container without
    // one means is documented (`docs/operations.md`, "Published ports and
    // healthchecks").
    warnings
}

// ---------------------------------------------------------------------------
// The trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl satl_api::Backend for DaemonBackend {
    #[tracing::instrument(skip_all, fields(image = %options.image, name = ?options.name))]
    async fn create_container(&self, options: CreateContainerOptions) -> Result<CreatedContainer> {
        let name = {
            let store = self.store()?;
            let view = store.view();
            match &options.name {
                Some(name) => {
                    if let Some(existing) = view.service_by_name(name) {
                        return Err(BackendError::conflict(format!(
                            "Conflict. The container name \"/{name}\" is already in use by \
                             container \"{}\". You have to remove (or rename) that container \
                             to be able to reuse that name.",
                            existing.id
                        )));
                    }
                    name.clone()
                }
                None => names::generate_name(|candidate| view.service_by_name(candidate).is_some()),
            }
        };

        let spec = service_spec(name.clone(), &options);
        let endpoint = spec.endpoint.as_ref().map(initial_endpoint);
        let service = Service {
            id: Id::generate(),
            meta: Meta::new(),
            spec,
            endpoint,
            spec_version: satl_core::Version(0),
            previous_spec: None,
            update_status: None,
        };
        let service_id = service.id.clone();

        // Watch before writing: the orchestrator may create the task before
        // `propose` even returns. The task event arrives through raft
        // replication, so watching the local store is valid on a follower too.
        let mut events = self.store()?.watch();
        self.propose_via_leader(
            "create the container's service",
            vec![StoreAction::Create(StoreObject::Service(service))],
        )
        .await?;
        tracing::info!(service_id = %service_id, name = %name, "container service created");

        let deadline = tokio::time::Instant::now() + CREATE_TIMEOUT;
        loop {
            let task_id = {
                let store = self.store()?;
                let view = store.view();
                names::tasks_of(&view, &service_id)
                    .first()
                    .map(|task| task.id.clone())
            };
            if let Some(task_id) = task_id {
                tracing::info!(
                    container = %task_id,
                    service_id = %service_id,
                    name = %name,
                    "container created"
                );
                return Ok(CreatedContainer {
                    id: task_id.to_string(),
                    warnings: create_warnings(&options),
                });
            }
            match tokio::time::timeout_at(deadline, events.recv()).await {
                Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
                Ok(Err(RecvError::Closed)) | Err(_) => break,
            }
        }

        // No task appeared: roll the service back so a wedged control plane
        // does not leave a phantom container behind.
        tracing::error!(
            service_id = %service_id,
            timeout_s = CREATE_TIMEOUT.as_secs(),
            "the orchestrator did not create a task for this service; rolling back"
        );
        if let Err(error) = self
            .propose_via_leader(
                "roll the container's service back",
                vec![StoreAction::Remove {
                    kind: ObjectKind::Service,
                    id: service_id.clone(),
                }],
            )
            .await
        {
            tracing::error!(service_id = %service_id, %error, "rolling the service back failed");
        }
        Err(BackendError::internal(format!(
            "the orchestrator did not create a task for container {name} within \
             {}s; the container was not created",
            CREATE_TIMEOUT.as_secs()
        )))
    }

    #[tracing::instrument(skip_all, fields(container = %id))]
    async fn start_container(&self, id: &str) -> Result<ChangeOutcome> {
        self.propose_from_view("start the container", |view| {
            let (task, service) = names::resolve(view, id)?;
            if task.status.state.is_terminal() || task.desired_state >= DesiredState::Shutdown {
                // A task is one-shot and is never re-executed (architecture
                // §4 rule 4); restarting means a *new* task, hence a new
                // container ID, which Docker's API cannot express. Recorded
                // in docs/api-compat.md.
                return Err(BackendError::conflict(format!(
                    "container {} has already run and cannot be started again: a SatL task is \
                     one-shot, so create a new container instead (satl run)",
                    names::container_name(&task)
                )));
            }
            if task.desired_state >= DesiredState::Running {
                return Ok((Vec::new(), ChangeOutcome::Unchanged));
            }

            let mut actions = Vec::new();
            if let Some(service) = service {
                let autostart = service
                    .spec
                    .annotations
                    .labels
                    .get(satl_orchestrator::AUTOSTART_LABEL)
                    .map(String::as_str);
                if autostart != Some("true") {
                    let mut updated = (*service).clone();
                    updated.spec.annotations.labels.insert(
                        satl_orchestrator::AUTOSTART_LABEL.to_owned(),
                        "true".to_owned(),
                    );
                    updated.meta.updated_at = SystemTime::now();
                    actions.push(StoreAction::Update(StoreObject::Service(updated)));
                }
            }
            let mut updated = (*task).clone();
            updated.desired_state = DesiredState::Running;
            updated.meta.updated_at = SystemTime::now();
            tracing::info!(
                task_id = %task.id,
                service_id = ?task.service_id,
                from = %task.desired_state,
                to = %DesiredState::Running,
                "starting container"
            );
            actions.push(StoreAction::Update(StoreObject::Task(updated)));
            Ok((actions, ChangeOutcome::Changed))
        })
        .await
    }

    #[tracing::instrument(skip_all, fields(container = %id, timeout = ?timeout))]
    async fn stop_container(&self, id: &str, timeout: Option<Duration>) -> Result<ChangeOutcome> {
        if timeout.is_some() {
            // The stop grace period lives in the (immutable) task spec, so a
            // per-request timeout cannot be honoured. Recorded in
            // docs/api-compat.md.
            tracing::debug!("ignoring the per-request stop timeout; using the task's grace period");
        }
        self.propose_from_view("stop the container", |view| {
            let (task, _) = names::resolve(view, id)?;
            if !is_stoppable(&task) {
                return Ok((Vec::new(), ChangeOutcome::Unchanged));
            }
            Ok((
                vec![shutdown_action(&task, "stopping container")],
                ChangeOutcome::Changed,
            ))
        })
        .await
    }

    #[tracing::instrument(skip_all, fields(container = %id, signal = %signal))]
    async fn kill_container(&self, id: &str, signal: &str) -> Result<()> {
        // M1 maps kill onto the graceful shutdown path: the controller sends
        // the task's stop signal, waits out the grace period and then
        // SIGKILLs. The requested signal is not forwarded. Recorded in
        // docs/api-compat.md.
        tracing::info!("kill mapped onto the graceful shutdown path");
        self.propose_from_view("kill the container", |view| {
            let (task, _) = names::resolve(view, id)?;
            if !is_stoppable(&task) {
                return Err(BackendError::conflict(format!(
                    "Cannot kill container: {}: Container {} is not running",
                    id, task.id
                )));
            }
            Ok((vec![shutdown_action(&task, "killing container")], ()))
        })
        .await
    }

    #[tracing::instrument(skip_all, fields(container = %id, force, remove_volumes))]
    async fn remove_container(&self, id: &str, force: bool, remove_volumes: bool) -> Result<()> {
        if remove_volumes {
            // M1 volumes are named-only: `docker create -v /data` produces an
            // anonymous volume the daemon does not create yet, so there is
            // nothing for `?v=1` to remove. Recorded in docs/api-compat.md.
            tracing::debug!("?v=1 has no effect: anonymous volumes are not created");
        }
        let task_id: Id = self
            .propose_from_view("remove the container", |view| {
                let (task, service) = names::resolve(view, id)?;
                if is_stoppable(&task) && !force {
                    return Err(BackendError::conflict(format!(
                        "You cannot remove a running container {}. Stop the container before \
                         attempting removal or force remove",
                        task.id
                    )));
                }
                let mut actions = Vec::new();
                if task.desired_state < DesiredState::Remove {
                    let mut updated = (*task).clone();
                    updated.desired_state = DesiredState::Remove;
                    updated.meta.updated_at = SystemTime::now();
                    tracing::info!(
                        task_id = %task.id,
                        service_id = ?task.service_id,
                        from = %task.desired_state,
                        to = %DesiredState::Remove,
                        force,
                        "removing container"
                    );
                    actions.push(StoreAction::Update(StoreObject::Task(updated)));
                }
                // Delete the service too, or the orchestrator would refill
                // the slot the moment the reaper frees it.
                if let Some(service) = service {
                    actions.push(StoreAction::Remove {
                        kind: ObjectKind::Service,
                        id: service.id.clone(),
                    });
                }
                Ok((actions, task.id.clone()))
            })
            .await?;

        self.execs.forget_container(&task_id);
        // Best effort: the agent still has to stop the container and the
        // reaper to delete the object. Answering before that is fine (Docker
        // does the same), but waiting makes `rm` followed by `ps` coherent.
        let (_, gone) = self
            .watch_task(&task_id, Some(REMOVE_TIMEOUT), |task| task.is_none())
            .await;
        if !gone {
            tracing::warn!(
                task_id = %task_id,
                timeout_s = REMOVE_TIMEOUT.as_secs(),
                "the container is still being removed; its resources are released asynchronously"
            );
        }
        Ok(())
    }

    async fn list_containers(&self, all: bool) -> Result<Vec<ContainerSummary>> {
        let ipam = self.ipam().await;
        let platforms = self.image_platforms().await;
        // A manager lists from the store (the newest task per slot, exactly
        // what Docker shows); a worker lists what it runs — its local task
        // records, which is what `docker ps` on a Docker worker shows too.
        let tasks: Vec<Task> = match Self::manager_of(self.cluster()?.as_ref()) {
            Ok(manager) => {
                let view = manager.store.view();
                names::visible_containers(&view)
                    .into_iter()
                    .map(|(_, task)| (*task).clone())
                    .collect()
            }
            Err(_) => self.local_tasks().await?,
        };
        let mut summaries: Vec<ContainerSummary> = tasks
            .into_iter()
            .filter(|task| all || is_running(task))
            .map(|task| {
                let ip = self.address_of(ipam.as_ref(), &task.id);
                let platform = resolved_platform(&task, &platforms);
                container_summary(
                    &task,
                    ip,
                    &self.network_name,
                    platform,
                    local_health(self.executor.health(), &task),
                )
            })
            .collect();
        // Newest first, as Docker lists them.
        summaries.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.id.cmp(&b.id)));
        Ok(summaries)
    }

    async fn inspect_container(&self, id: &str) -> Result<ContainerInspect> {
        let ipam = self.ipam().await;
        let platforms = self.image_platforms().await;
        let task: Task = match Self::manager_of(self.cluster()?.as_ref()) {
            Ok(manager) => {
                let view = manager.store.view();
                (*names::resolve_task(&view, id)?).clone()
            }
            Err(_) => self.local_task(id).await?,
        };
        let ip = self.address_of(ipam.as_ref(), &task.id);
        let subnet = ipam
            .as_ref()
            .and_then(|ipam| ipam.subnet(&self.network_name));
        let platform = resolved_platform(&task, &platforms);
        let health = local_health(self.executor.health(), &task);
        Ok(container_inspect(
            &task,
            ip,
            subnet,
            &self.network_name,
            platform,
            health,
        ))
    }

    #[tracing::instrument(skip_all, fields(container = %id, ?condition))]
    async fn wait_container(&self, id: &str, condition: WaitCondition) -> Result<WaitResult> {
        let done = |task: Option<&Task>| match (condition, task) {
            (WaitCondition::Removed, task) => task.is_none(),
            (_, None) => true,
            (_, Some(task)) => task.status.state.is_terminal(),
        };
        // A worker has no store watch; its local task DB is the record, so
        // the wait polls it (the record's status is this node's own report,
        // updated on every transition).
        if Self::manager_of(self.cluster()?.as_ref()).is_err() {
            let task_id = self.local_task(id).await?.id;
            let last = loop {
                let current = self
                    .task_db
                    .get(&task_id)
                    .await
                    .map_err(|error| {
                        BackendError::internal(format!("cannot read the local task db: {error}"))
                    })?
                    .map(|record| {
                        let mut task = record.task;
                        task.status = record.status;
                        task
                    });
                if done(current.as_ref()) {
                    break current;
                }
                tokio::time::sleep(LOCAL_WAIT_POLL).await;
            };
            return Ok(wait_result(&task_id, last));
        }

        let task_id = {
            let store = self.store()?;
            let view = store.view();
            names::resolve_task(&view, id)?.id.clone()
        };
        // No deadline: Docker's wait blocks until the container exits. The
        // client's disconnect cancels this future.
        let (last, _) = self.watch_task(&task_id, None, done).await;
        Ok(wait_result(&task_id, last))
    }

    #[tracing::instrument(skip_all, fields(container = %id, follow = options.follow, tail = ?options.tail))]
    async fn container_logs(
        &self,
        id: &str,
        options: LogOptions,
    ) -> Result<BoxStream<'static, LogFrame>> {
        if options.since.is_some() {
            // Log files carry raw bytes, with no per-line timestamps to
            // filter on. Recorded in docs/api-compat.md.
            tracing::debug!("ignoring ?since= on logs: SatL stores raw container output");
        }
        // A worker resolves and follows from its local task DB: the record's
        // status is this node's own report, so "finished" needs no store. The
        // probe is a small synchronous read, polled once per follow round.
        if Self::manager_of(self.cluster()?.as_ref()).is_err() {
            let task_id = self.local_task(id).await?.id;
            let dir = self.log_dir(&task_id);
            let db = self.task_db.clone();
            let watched = task_id.clone();
            let finished = Arc::new(move || {
                db.get_blocking(&watched)
                    .is_none_or(|record| record.status.state.is_terminal())
            });
            return Ok(logs::stream(&dir, options, finished));
        }
        let task_id = {
            let store = self.store()?;
            let view = store.view();
            names::resolve_task(&view, id)?.id.clone()
        };
        let dir = self.log_dir(&task_id);
        let store = self.store()?;
        let watched = task_id.clone();
        let finished = Arc::new(move || {
            let view = store.view();
            view.task(&watched)
                .is_none_or(|task| task.status.state.is_terminal())
        });
        Ok(logs::stream(&dir, options, finished))
    }

    #[tracing::instrument(skip_all, fields(image = %reference, platform = ?platform))]
    async fn pull_image(
        &self,
        reference: &str,
        auth: Option<RegistryAuth>,
        platform: Option<satl_core::Platform>,
    ) -> Result<BoxStream<'static, PullProgressLine>> {
        let parsed = ImageReference::parse(reference).map_err(|err| {
            BackendError::invalid(format!("invalid reference {reference}: {err}"))
        })?;
        let policy = self.executor.platform_policy(platform.as_ref());
        let auth = auth.map(|auth| satl_image::RegistryAuth {
            username: auth.username,
            password: auth.password,
        });

        let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();
        let (lines_tx, lines_rx) = tokio::sync::mpsc::unbounded_channel::<PullProgressLine>();
        let executor = Arc::clone(&self.executor);
        let events = self.local_events.clone();
        let canonical = parsed.canonical();

        tokio::spawn(async move {
            let pull = tokio::spawn(async move {
                executor
                    .images()
                    .pull_with_progress(&parsed, &policy, auth, Some(progress_tx))
                    .await
            });
            // The progress sender is dropped when the pull returns, so this
            // loop ends exactly once, after the last progress event.
            while let Some(progress) = progress_rx.recv().await {
                let _ = lines_tx.send(pull_line(&progress));
            }
            let final_line = match pull.await {
                Ok(Ok(image)) => {
                    tracing::info!(
                        image = %image.reference,
                        platform = %image.platform,
                        layers = image.layers.len(),
                        "image pulled"
                    );
                    let _ = events.send(events::image_pull(&image.reference));
                    PullProgressLine::status(format!(
                        "Status: Downloaded newer image for {}",
                        image.reference
                    ))
                }
                Ok(Err(error)) => {
                    tracing::warn!(image = %canonical, %error, "image pull failed");
                    PullProgressLine {
                        error: Some(error.to_string()),
                        status: error.to_string(),
                        ..PullProgressLine::default()
                    }
                }
                Err(error) => {
                    tracing::error!(image = %canonical, %error, "the image pull task failed");
                    PullProgressLine {
                        error: Some(error.to_string()),
                        status: error.to_string(),
                        ..PullProgressLine::default()
                    }
                }
            };
            let _ = lines_tx.send(final_line);
        });

        Ok(futures_util::stream::unfold(lines_rx, |mut rx| async move {
            rx.recv().await.map(|line| (line, rx))
        })
        .boxed())
    }

    async fn list_images(&self) -> Result<Vec<ImageSummary>> {
        let images = self
            .executor
            .images()
            .list()
            .await
            .map_err(|err| BackendError::internal(format!("cannot list images: {err}")))?;
        // The in-use counts come from the store on a manager and from the
        // local task set on a worker — the image list itself is node-local
        // either way.
        //
        // Keyed on the **canonical** reference, because that is how the store
        // keys its records: a spec that says `alpine` has to count against the
        // record `docker.io/library/alpine:latest`, and keying on the raw spec
        // string made `Containers` read 0 for exactly the images most likely
        // to be in use. Same comparison `image_claims` makes for the removal
        // conflict, so the column and the 409 cannot disagree.
        let in_use: BTreeMap<String, i64> = {
            let mut counts: BTreeMap<String, i64> = BTreeMap::new();
            let mut count = |image: &str| {
                *counts.entry(satl_image::canonical_key(image)).or_default() += 1;
            };
            match Self::manager_of(self.cluster()?.as_ref()) {
                Ok(manager) => {
                    let view = manager.store.view();
                    for task in view.tasks() {
                        count(&task.spec.container.image);
                    }
                }
                Err(_) => {
                    for task in self.local_tasks().await? {
                        count(&task.spec.container.image);
                    }
                }
            }
            counts
        };
        Ok(images
            .iter()
            .map(|image| {
                let containers = in_use.get(&image.reference).copied().unwrap_or(0);
                image_summary(image, containers)
            })
            .collect())
    }

    /// `DELETE /images/{name}`: forget one record, then reclaim.
    ///
    /// Body in `backend/prune.rs`, beside the sweeps it drives — the removal
    /// and the prune run the same reclamation and decide "in use" with the
    /// same function, so the two cannot disagree.
    #[tracing::instrument(skip_all, fields(image = %reference, force, noprune))]
    async fn remove_image(
        &self,
        reference: &str,
        force: bool,
        noprune: bool,
    ) -> Result<PrunedImages> {
        let report = self.remove_image_impl(reference, force, noprune).await?;
        tracing::info!(
            items = report.deleted.len(),
            deferred = report.deferred.len(),
            space_reclaimed = report.space_reclaimed,
            "image removed"
        );
        Ok(report)
    }

    /// `GET /images/{name}/json`: the inspect document, aggregated by image
    /// ID.
    #[tracing::instrument(skip_all, fields(image = %reference))]
    async fn inspect_image(&self, reference: &str) -> Result<ImageInspect> {
        let target = self.resolve_image_target(reference).await?;
        let images = self
            .executor
            .images()
            .list()
            .await
            .map_err(|err| BackendError::internal(format!("cannot list images: {err}")))?;
        // The store is keyed by reference, so one image is however many
        // records share its manifest digest; Docker's document is one per
        // image, listing them all (api-compat 160).
        let mut members: Vec<&satl_image::PulledImage> = images
            .iter()
            .filter(|image| image.manifest_digest.as_str() == target.id)
            .collect();
        members.sort_by(|a, b| a.reference.cmp(&b.reference));
        let first = members
            .first()
            .ok_or_else(|| BackendError::not_found(format!("No such image: {reference}")))?;

        Ok(ImageInspect {
            id: target.id.clone(),
            repo_tags: members
                .iter()
                .map(|image| image.reference.clone())
                .collect(),
            repo_digests: members
                .iter()
                .map(|image| format!("{}@{}", repository_of(&image.reference), target.id))
                .collect(),
            created: first.created,
            size: first
                .layers
                .iter()
                .map(|layer| i64::try_from(layer.size).unwrap_or(i64::MAX))
                .sum(),
            config: ImageConfigDoc {
                env: first.config.env.clone(),
                entrypoint: first.config.entrypoint.clone(),
                cmd: first.config.cmd.clone(),
                working_dir: first.config.working_dir.clone().unwrap_or_default(),
                user: first.config.user.clone().unwrap_or_default(),
                exposed_ports: first.config.exposed_ports.clone(),
            },
            rootfs_layers: first
                .layers
                .iter()
                .map(|layer| layer.diff_id.to_string())
                .collect(),
            platform: Some(satl_core::Platform {
                os: first.platform.os.clone(),
                arch: first.platform.architecture.clone(),
            }),
        })
    }

    /// `POST /images/{name}/tag`: one more local reference to the same image.
    /// Node-local, like the store it writes — tagging on one manager does not
    /// tag on the others, same as a pull.
    #[tracing::instrument(skip_all, fields(source = %source, target = %target))]
    async fn tag_image(&self, source: &str, target: &str) -> Result<()> {
        let parse = |input: &str| {
            ImageReference::parse(input)
                .map_err(|err| BackendError::invalid(format!("invalid reference {input}: {err}")))
        };
        let source = parse(source)?;
        let target = parse(target)?;
        self.executor
            .images()
            .tag(&source, &target)
            .await
            .map_err(|err| match err {
                ImageError::NotFound { .. } => BackendError::not_found(err.to_string()),
                err => BackendError::internal(format!("cannot tag {source}: {err}")),
            })?;
        let _ = self
            .local_events
            .send(events::image_tag(&target.canonical()));
        Ok(())
    }

    // -- prune --------------------------------------------------------------
    //
    // Bodies in `backend/prune.rs`, which also carries the reasoning about what
    // is cluster-wide and what is node-local.

    #[tracing::instrument(skip_all)]
    async fn prune_containers(&self) -> Result<PrunedContainers> {
        self.prune_containers_impl().await
    }

    #[tracing::instrument(skip_all, fields(all))]
    async fn prune_images(&self, all: bool) -> Result<PrunedImages> {
        self.prune_images_impl(all).await
    }

    #[tracing::instrument(skip_all)]
    async fn prune_networks(&self) -> Result<PrunedNetworks> {
        self.prune_networks_impl().await
    }

    #[tracing::instrument(skip_all)]
    async fn prune_volumes(&self) -> Result<PrunedVolumes> {
        self.prune_volumes_impl().await
    }

    #[tracing::instrument(skip_all, fields(container = %container))]
    async fn create_exec(&self, container: &str, config: ExecConfig) -> Result<ExecId> {
        // Exec is entirely node-local (`ocijail exec`), so a worker serves it
        // from its own task records.
        let task: Task = match Self::manager_of(self.cluster()?.as_ref()) {
            Ok(manager) => {
                let view = manager.store.view();
                (*names::resolve_task(&view, container)?).clone()
            }
            Err(_) => self.local_task(container).await?,
        };
        if task.status.state != TaskState::Running {
            return Err(BackendError::conflict(format!(
                "Container {} is not running",
                task.id
            )));
        }
        self.execs.create(&task, config)
    }

    #[tracing::instrument(skip_all, fields(exec = %exec_id))]
    async fn start_exec(&self, exec_id: &str) -> Result<ExecStream> {
        self.execs.start(
            exec_id,
            Arc::clone(&self.executor),
            &self.state_dir.join("scratch"),
        )
    }

    async fn inspect_exec(&self, exec_id: &str) -> Result<ExecInspect> {
        self.execs.inspect(exec_id)
    }

    #[tracing::instrument(skip_all, fields(volume = %options.name))]
    async fn create_volume(&self, options: CreateVolumeOptions) -> Result<VolumeInfo> {
        if !options.driver.is_empty() && options.driver != "local" {
            return Err(BackendError::invalid(format!(
                "unknown volume driver {:?}: SatL volumes are ZFS datasets, driver \"local\"",
                options.driver
            )));
        }
        if !options.labels.is_empty() || !options.driver_opts.is_empty() {
            // Volume metadata has no home in M1 (a volume is a bare dataset).
            // Recorded in docs/api-compat.md.
            tracing::debug!("volume labels and driver options are not persisted");
        }
        let name = if options.name.trim().is_empty() {
            Id::generate().to_string()
        } else {
            options.name.clone()
        };
        let mountpoint = self
            .executor
            .volumes()
            .ensure(&name)
            .await
            .map_err(|err| volume_error(&name, &err))?;
        tracing::info!(volume = %name, mountpoint = %mountpoint.display(), "volume ready");
        Ok(VolumeInfo {
            name,
            driver: "local".to_owned(),
            mountpoint: mountpoint.display().to_string(),
            created_at: None,
            labels: options.labels,
            options: options.driver_opts,
        })
    }

    async fn list_volumes(&self) -> Result<Vec<VolumeInfo>> {
        let volumes = self
            .executor
            .volumes()
            .list()
            .await
            .map_err(|err| BackendError::internal(format!("cannot list volumes: {err}")))?;
        Ok(volumes
            .into_iter()
            .map(|volume| VolumeInfo {
                name: volume.name,
                driver: "local".to_owned(),
                mountpoint: volume.mountpoint.display().to_string(),
                created_at: None,
                labels: BTreeMap::new(),
                options: BTreeMap::new(),
            })
            .collect())
    }

    #[tracing::instrument(skip_all, fields(volume = %name, force))]
    async fn remove_volume(&self, name: &str, force: bool) -> Result<()> {
        match self.executor.volumes().remove(name).await {
            Ok(()) => {
                tracing::info!("volume removed");
                Ok(())
            }
            Err(satl_storage::VolumeStoreError::NotFound { .. }) if force => Ok(()),
            Err(err) => Err(volume_error(name, &err)),
        }
    }

    // -- networks -----------------------------------------------------------
    //
    // Bodies in `backend/networks.rs`, for the same reason the cluster ones
    // live in `backend/swarm.rs`.

    async fn list_networks(&self) -> Result<Vec<NetworkSummary>> {
        self.list_networks_impl()
    }

    async fn inspect_network(&self, id_or_name: &str) -> Result<NetworkDetail> {
        self.inspect_network_impl(id_or_name)
    }

    async fn create_network(&self, options: CreateNetworkOptions) -> Result<NetworkCreated> {
        self.create_network_impl(options).await
    }

    async fn remove_network(&self, id_or_name: &str) -> Result<()> {
        self.remove_network_impl(id_or_name).await
    }

    async fn connect_network(
        &self,
        id_or_name: &str,
        options: NetworkConnectOptions,
    ) -> Result<()> {
        self.connect_network_impl(id_or_name, &options)
    }

    async fn disconnect_network(
        &self,
        id_or_name: &str,
        options: NetworkDisconnectOptions,
    ) -> Result<()> {
        self.disconnect_network_impl(id_or_name, &options)
    }

    async fn events(&self, since: Option<SystemTime>) -> Result<BoxStream<'static, EventMessage>> {
        if since.is_some() {
            // The watch feed is not resumable in M1 and no history is kept.
            // Recorded in docs/api-compat.md.
            tracing::debug!("ignoring ?since= on /events: SatL keeps no event history");
        }
        // A worker has no store watch: it serves its local events (image
        // pulls) only. Recorded in docs/api-compat.md — Docker's worker
        // emits local container events too; SatL's task transitions are
        // store writes and therefore manager-side.
        let Ok(manager) = Self::manager_of(self.cluster()?.as_ref()) else {
            let local =
                futures_util::stream::unfold(self.local_events.subscribe(), |mut rx| async move {
                    loop {
                        match rx.recv().await {
                            Ok(event) => return Some((event, rx)),
                            Err(RecvError::Lagged(_)) => {}
                            Err(RecvError::Closed) => return None,
                        }
                    }
                });
            return Ok(local.boxed());
        };
        let store_events =
            futures_util::stream::unfold(manager.store.watch(), |mut rx| async move {
                loop {
                    match rx.recv().await {
                        Ok(event) => {
                            if let Some(message) = events::from_store_event(&event) {
                                return Some((message, rx));
                            }
                        }
                        Err(RecvError::Lagged(missed)) => {
                            tracing::warn!(missed, "event stream lagged; some events were dropped");
                        }
                        Err(RecvError::Closed) => return None,
                    }
                }
            });
        let local =
            futures_util::stream::unfold(self.local_events.subscribe(), |mut rx| async move {
                loop {
                    match rx.recv().await {
                        Ok(event) => return Some((event, rx)),
                        Err(RecvError::Lagged(_)) => {}
                        Err(RecvError::Closed) => return None,
                    }
                }
            });
        Ok(futures_util::stream::select(store_events, local).boxed())
    }

    async fn system_counts(&self) -> Result<Counts> {
        let images = match self.executor.images().list().await {
            Ok(images) => i64::try_from(images.len()).unwrap_or(i64::MAX),
            Err(error) => {
                tracing::warn!(%error, "cannot count images");
                0
            }
        };
        // Same source split as `list_containers`: /info must answer on a
        // worker, with that worker's own containers.
        let tasks: Vec<Task> = match Self::manager_of(self.cluster()?.as_ref()) {
            Ok(manager) => {
                let view = manager.store.view();
                names::visible_containers(&view)
                    .into_iter()
                    .map(|(_, task)| (*task).clone())
                    .collect()
            }
            Err(_) => self.local_tasks().await?,
        };
        let running = tasks.iter().filter(|task| is_running(task)).count();
        let total = tasks.len();
        Ok(Counts {
            containers: i64::try_from(total).unwrap_or(i64::MAX),
            containers_running: i64::try_from(running).unwrap_or(i64::MAX),
            containers_paused: 0,
            containers_stopped: i64::try_from(total - running).unwrap_or(i64::MAX),
            images,
        })
    }

    // -- cluster ------------------------------------------------------------
    //
    // The bodies live in `backend/swarm.rs`; these are the trait's shape.
    // Keeping them apart is what stops this file from doubling in length and
    // keeps the cluster rules (leader forwarding, membership two-phase order,
    // dirty-state refusal) readable as one document.

    async fn swarm_init(&self, options: SwarmInitOptions) -> Result<SwarmInitResult> {
        self.swarm_init_impl(&options).await
    }

    async fn swarm_join(&self, options: SwarmJoinOptions) -> Result<()> {
        self.swarm_join_impl(options).await
    }

    async fn swarm_leave(&self, force: bool) -> Result<()> {
        self.swarm_leave_impl(force).await
    }

    async fn swarm_inspect(&self) -> Result<SwarmDetail> {
        self.swarm_inspect_impl()
    }

    async fn swarm_rotate_token(&self, role: TokenRole) -> Result<SwarmDetail> {
        self.swarm_rotate_token_impl(role).await
    }

    async fn swarm_set_autolock(&self, enabled: bool) -> Result<SwarmDetail> {
        self.swarm_set_autolock_impl(enabled).await
    }

    async fn swarm_unlock_key(&self) -> Result<String> {
        self.swarm_unlock_key_impl()
    }

    async fn swarm_rotate_unlock_key(&self) -> Result<SwarmDetail> {
        self.swarm_rotate_unlock_key_impl().await
    }

    async fn swarm_rotate_ca(&self, force_rotate: u64) -> Result<SwarmDetail> {
        self.swarm_rotate_ca_impl(force_rotate).await
    }

    async fn swarm_status(&self) -> Result<SwarmStatus> {
        self.swarm_status_impl()
    }

    async fn list_nodes(&self) -> Result<Vec<NodeSummary>> {
        self.list_nodes_impl()
    }

    async fn inspect_node(&self, id_or_name: &str) -> Result<NodeDetail> {
        self.inspect_node_impl(id_or_name)
    }

    async fn update_node(&self, id: &str, version: Version, spec: NodeSpecUpdate) -> Result<()> {
        self.update_node_impl(id, version, spec).await
    }

    async fn remove_node(&self, id: &str, force: bool) -> Result<()> {
        self.remove_node_impl(id, force).await
    }

    async fn create_service(&self, options: ServiceCreateOptions) -> Result<ServiceCreated> {
        self.create_service_impl(options).await
    }

    async fn list_services(&self) -> Result<Vec<ServiceSummary>> {
        self.list_services_impl()
    }

    async fn inspect_service(&self, id_or_name: &str) -> Result<ServiceDetail> {
        self.inspect_service_impl(id_or_name)
    }

    async fn update_service(
        &self,
        id: &str,
        version: Version,
        options: ServiceUpdateOptions,
    ) -> Result<Vec<String>> {
        self.update_service_impl(id, version, options).await
    }

    async fn remove_service(&self, id_or_name: &str) -> Result<()> {
        self.remove_service_impl(id_or_name).await
    }

    async fn list_tasks(&self, filters: TaskFilters) -> Result<Vec<TaskSummary>> {
        self.list_tasks_impl(&filters)
    }

    async fn inspect_task(&self, id: &str) -> Result<TaskDetail> {
        self.inspect_task_impl(id)
    }

    async fn create_secret(&self, spec: satl_core::SecretSpec) -> Result<SecretCreated> {
        self.create_secret_impl(spec).await
    }

    async fn list_secrets(&self) -> Result<Vec<satl_core::Secret>> {
        self.list_secrets_impl()
    }

    async fn inspect_secret(&self, id_or_name: &str) -> Result<satl_core::Secret> {
        self.inspect_secret_impl(id_or_name)
    }

    async fn remove_secret(&self, id_or_name: &str) -> Result<()> {
        self.remove_secret_impl(id_or_name).await
    }

    async fn create_config(&self, spec: satl_core::ConfigSpec) -> Result<ConfigCreated> {
        self.create_config_impl(spec).await
    }

    async fn list_configs(&self) -> Result<Vec<satl_core::Config>> {
        self.list_configs_impl()
    }

    async fn inspect_config(&self, id_or_name: &str) -> Result<satl_core::Config> {
        self.inspect_config_impl(id_or_name)
    }

    async fn remove_config(&self, id_or_name: &str) -> Result<()> {
        self.remove_config_impl(id_or_name).await
    }
}

/// Poll interval of the worker-side `wait` (a worker has no store watch; its
/// local task DB is the record).
const LOCAL_WAIT_POLL: Duration = Duration::from_millis(500);

/// The `POST /containers/{id}/wait` document for the last observed task
/// (`None` once it is gone).
fn wait_result(task_id: &Id, last: Option<Task>) -> WaitResult {
    let Some(task) = last else {
        return WaitResult {
            status_code: 0,
            error: Some("container was removed before it could be waited on".to_owned()),
        };
    };
    let status_code = match task.status.container.as_ref().and_then(|c| c.exit_code) {
        Some(code) => code,
        None if task.status.state == TaskState::Complete => 0,
        None => UNKNOWN_EXIT_CODE,
    };
    tracing::info!(task_id = %task_id, state = %task.status.state, status_code, "wait finished");
    WaitResult {
        status_code,
        error: task.status.err.clone(),
    }
}

/// Raise a task's desired state to `SHUTDOWN` (stop and kill share this).
fn shutdown_action(task: &Task, what: &str) -> StoreAction {
    let mut updated = task.clone();
    updated.desired_state = DesiredState::Shutdown;
    updated.meta.updated_at = SystemTime::now();
    tracing::info!(
        task_id = %task.id,
        service_id = ?task.service_id,
        from = %task.desired_state,
        to = %DesiredState::Shutdown,
        "{what}"
    );
    StoreAction::Update(StoreObject::Task(updated))
}

/// Map a volume-store failure onto Docker's error shapes.
fn volume_error(name: &str, err: &satl_storage::VolumeStoreError) -> BackendError {
    match err {
        satl_storage::VolumeStoreError::NotFound { .. } => {
            BackendError::not_found(format!("get {name}: no such volume"))
        }
        satl_storage::VolumeStoreError::InUse { .. } => {
            BackendError::conflict(format!("remove {name}: volume is in use: {err}"))
        }
        satl_storage::VolumeStoreError::InvalidName { .. } => {
            BackendError::invalid(err.to_string())
        }
        satl_storage::VolumeStoreError::Zfs(_) => BackendError::internal(err.to_string()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use satl_core::{TaskStatus, Version};

    use super::*;

    /// A task spec with nothing set, for tests that only care about identity.
    pub(crate) fn empty_task_spec() -> TaskSpec {
        service_spec(
            "test".to_owned(),
            &CreateContainerOptions {
                image: "img".to_owned(),
                ..CreateContainerOptions::default()
            },
        )
        .task
    }

    /// A task of a service called `service`, as the orchestrator would build
    /// it.
    pub(crate) fn sample_task(service: &str) -> Task {
        let id = Id::generate();
        Task {
            annotations: Annotations {
                name: format!("{service}.1.{id}"),
                labels: BTreeMap::new(),
            },
            meta: Meta::new(),
            spec: empty_task_spec(),
            spec_version: Some(Version(1)),
            service_id: Some(Id::generate()),
            slot: 1,
            node_id: None,
            service_annotations: Annotations {
                name: service.to_owned(),
                labels: BTreeMap::new(),
            },
            status: TaskStatus::new(TaskState::New, "created"),
            desired_state: DesiredState::Ready,
            networks: Vec::new(),
            endpoint: None,
            job_iteration: None,
            id,
        }
    }

    fn options(edit: impl FnOnce(&mut CreateContainerOptions)) -> CreateContainerOptions {
        let mut options = CreateContainerOptions {
            image: "nginx:1.27".to_owned(),
            ..CreateContainerOptions::default()
        };
        edit(&mut options);
        options
    }

    #[test]
    fn the_service_spec_is_a_single_replica_created_container() {
        let spec = service_spec("web".to_owned(), &options(|_| {}));
        assert_eq!(spec.annotations.name, "web");
        assert_eq!(spec.mode, ServiceMode::Replicated { replicas: 1 });
        assert_eq!(
            spec.annotations
                .labels
                .get(satl_orchestrator::AUTOSTART_LABEL)
                .map(String::as_str),
            Some("false"),
            "a created container must not start on its own"
        );
        assert_eq!(
            satl_orchestrator::initial_desired_state(&spec),
            DesiredState::Ready
        );
        assert_eq!(spec.task.container.image, "nginx:1.27");
        assert!(spec.task.resources.limits.is_none());
    }

    #[test]
    fn entrypoint_and_cmd_map_onto_command_and_args() {
        let spec = service_spec(
            "web".to_owned(),
            &options(|o| {
                o.entrypoint = vec!["/bin/sh".to_owned()];
                o.cmd = vec!["-c".to_owned(), "echo hi".to_owned()];
            }),
        );
        assert_eq!(spec.task.container.command, ["/bin/sh"]);
        assert_eq!(spec.task.container.args, ["-c", "echo hi"]);
    }

    #[test]
    fn resource_limits_are_only_set_when_asked_for() {
        let spec = service_spec("web".to_owned(), &options(|o| o.memory = Some(512)));
        assert_eq!(
            spec.task.resources.limits,
            Some(Resources {
                nano_cpus: 0,
                memory_bytes: 512
            })
        );
        let spec = service_spec("web".to_owned(), &options(|o| o.nano_cpus = Some(1_500)));
        assert_eq!(
            spec.task.resources.limits,
            Some(Resources {
                nano_cpus: 1_500,
                memory_bytes: 0
            })
        );
    }

    #[test]
    fn published_ports_land_on_the_endpoint_spec() {
        let spec = service_spec(
            "web".to_owned(),
            &options(|o| {
                o.port_bindings = vec![satl_api::model::PortMapping {
                    host_ip: None,
                    host_port: 8080,
                    container_port: 80,
                    protocol: satl_core::PortProtocol::Tcp,
                }];
            }),
        );
        let endpoint = spec.endpoint.expect("an endpoint spec");
        assert_eq!(endpoint.ports.len(), 1);
        assert_eq!(endpoint.ports[0].published_port, 8080);
        assert_eq!(endpoint.ports[0].target_port, 80);
        assert_eq!(endpoint.ports[0].publish_mode, satl_core::PublishMode::Host);
    }

    #[test]
    fn the_platform_column_falls_back_to_the_pulled_image() {
        // The spec spells the image informally; the image store keys its
        // records on the canonical reference. The lookup must bridge the two
        // (it did not until 2026-08-23, and this test failed against that
        // code).
        let mut task = sample_task("web");
        task.spec.container.image = "alpine".to_owned();
        assert_eq!(
            task.spec.container.platform, None,
            "no --platform requested"
        );
        let images = BTreeMap::from([(
            "docker.io/library/alpine:latest".to_owned(),
            satl_core::Platform {
                os: "linux".to_owned(),
                arch: "amd64".to_owned(),
            },
        )]);
        let resolved = resolved_platform(&task, &images).expect("a resolved platform");
        assert_eq!(resolved.os, "linux");
        assert_eq!(resolved.arch, "amd64");
    }

    #[test]
    fn an_explicit_platform_request_wins_over_the_image() {
        let mut task = sample_task("web");
        task.spec.container.image = "alpine".to_owned();
        task.spec.container.platform = Some(satl_core::Platform {
            os: "freebsd".to_owned(),
            arch: "arm64".to_owned(),
        });
        let images = BTreeMap::from([(
            "docker.io/library/alpine:latest".to_owned(),
            satl_core::Platform {
                os: "linux".to_owned(),
                arch: "amd64".to_owned(),
            },
        )]);
        let resolved = resolved_platform(&task, &images).expect("a resolved platform");
        assert_eq!(resolved.os, "freebsd");
        assert_eq!(resolved.arch, "arm64");
    }

    #[test]
    fn an_unknown_image_leaves_the_platform_empty() {
        let task = sample_task("web");
        assert!(resolved_platform(&task, &BTreeMap::new()).is_none());
    }

    #[test]
    fn an_unparsable_image_leaves_the_platform_empty() {
        // An input that will not parse keys as itself, so the fallback arm
        // misses cleanly: the store can hold no record under such a key.
        let mut task = sample_task("web");
        task.spec.container.image = "NOT AN IMAGE reference".to_owned();
        let images = BTreeMap::from([(
            "docker.io/library/alpine:latest".to_owned(),
            satl_core::Platform {
                os: "linux".to_owned(),
                arch: "amd64".to_owned(),
            },
        )]);
        assert!(resolved_platform(&task, &images).is_none());
    }

    #[test]
    fn the_initial_endpoint_carries_explicit_host_ports_only() {
        let spec = EndpointSpec {
            mode: EndpointMode::DnsRR,
            ports: vec![
                satl_core::PortConfig {
                    name: String::new(),
                    protocol: satl_core::PortProtocol::Tcp,
                    target_port: 80,
                    published_port: 8080,
                    publish_mode: satl_core::PublishMode::Host,
                },
                // Dynamic host port: needs an allocator, not shipped in M1.
                satl_core::PortConfig {
                    name: String::new(),
                    protocol: satl_core::PortProtocol::Tcp,
                    target_port: 443,
                    published_port: 0,
                    publish_mode: satl_core::PublishMode::Host,
                },
                // Ingress: centrally allocated, M6.
                satl_core::PortConfig {
                    name: String::new(),
                    protocol: satl_core::PortProtocol::Tcp,
                    target_port: 9000,
                    published_port: 9000,
                    publish_mode: satl_core::PublishMode::Ingress,
                },
            ],
        };
        let endpoint = initial_endpoint(&spec);
        assert_eq!(endpoint.spec, spec, "the spec is carried verbatim");
        assert_eq!(endpoint.ports.len(), 1);
        assert_eq!(endpoint.ports[0].published_port, 8080);
        assert_eq!(endpoint.ports[0].target_port, 80);
    }

    #[test]
    fn warnings_name_the_options_m1_does_not_honour() {
        assert!(create_warnings(&options(|_| {})).is_empty());
        let warnings = create_warnings(&options(|o| o.auto_remove = true));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("AutoRemove"), "{warnings:?}");

        let warnings = create_warnings(&options(|o| {
            o.port_bindings = vec![satl_api::model::PortMapping {
                host_ip: None,
                host_port: 0,
                container_port: 80,
                protocol: satl_core::PortProtocol::Tcp,
            }];
        }));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("host port"), "{warnings:?}");
    }

    /// A published container is **not** warned about having no healthcheck,
    /// even though it never has one: `satl run` has no flag to add one, so the
    /// warning would fire on the commonest command of all with no way to
    /// comply. The consequence is documented instead (api-compat #127).
    #[test]
    fn a_published_container_carries_no_healthcheck_and_no_warning_about_it() {
        let published = options(|o| {
            o.port_bindings = vec![satl_api::model::PortMapping {
                host_ip: None,
                host_port: 8080,
                container_port: 80,
                protocol: satl_core::PortProtocol::Tcp,
            }];
        });
        assert!(create_warnings(&published).is_empty());
        // The spec really carries no healthcheck: nothing gates this port.
        assert!(
            service_spec("web".to_owned(), &published)
                .task
                .container
                .healthcheck
                .is_none()
        );
        // And the port is published all the same, which is the whole point of
        // the deviation entry.
        assert_eq!(
            service_spec("web".to_owned(), &published)
                .published_ports()
                .len(),
            1
        );
    }

    #[test]
    fn runtime_state_reports_start_and_finish_where_docker_uses_them() {
        let mut task = sample_task("web");
        let state = runtime_state(&task, None);
        assert_eq!(state.task_state, TaskState::New);
        assert!(state.started_at.is_none());
        assert!(state.finished_at.is_none());

        // A health-gated task waits in STARTING, which Docker renders as
        // `running`: it must carry a start time too, or `docker ps` shows a
        // running container with no uptime for the whole gate.
        task.status = TaskStatus::new(TaskState::Starting, "starting");
        let state = runtime_state(&task, None);
        assert_eq!(state.started_at, Some(task.status.timestamp));
        assert!(state.finished_at.is_none());

        task.status = TaskStatus::new(TaskState::Running, "started");
        let state = runtime_state(&task, None);
        assert_eq!(state.started_at, Some(task.status.timestamp));
        assert!(state.finished_at.is_none());

        task.status = TaskStatus::new(TaskState::Failed, "failed");
        task.status.container = Some(satl_core::ContainerStatus {
            jail_id: Some(task.id.as_str().to_owned()),
            pid: Some(9),
            exit_code: Some(3),
        });
        let state = runtime_state(&task, None);
        assert_eq!(state.finished_at, Some(task.status.timestamp));
        assert_eq!(state.exit_code, Some(3));
        assert_eq!(state.pid, Some(9));
    }

    #[test]
    fn only_starting_and_running_containers_are_listed_without_all() {
        let mut task = sample_task("web");
        for state in [TaskState::Starting, TaskState::Running] {
            task.status = TaskStatus::new(state, "x");
            assert!(is_running(&task), "{state}");
        }
        for state in [
            TaskState::New,
            TaskState::Ready,
            TaskState::Complete,
            TaskState::Failed,
            TaskState::Shutdown,
        ] {
            task.status = TaskStatus::new(state, "x");
            assert!(!is_running(&task), "{state}");
        }
    }

    #[test]
    fn a_created_container_is_not_stoppable_but_a_started_one_is() {
        let mut task = sample_task("web");
        // `docker create`: desired READY, nothing to stop.
        task.desired_state = DesiredState::Ready;
        for state in [TaskState::New, TaskState::Preparing, TaskState::Ready] {
            task.status = TaskStatus::new(state, "x");
            assert!(!is_stoppable(&task), "created/{state}");
        }

        // `docker start`: desired RUNNING, stoppable from that moment on —
        // including while it is still preparing.
        task.desired_state = DesiredState::Running;
        for state in [
            TaskState::Assigned,
            TaskState::Preparing,
            TaskState::Ready,
            TaskState::Starting,
            TaskState::Running,
        ] {
            task.status = TaskStatus::new(state, "x");
            assert!(is_stoppable(&task), "started/{state}");
        }

        // Already terminal, or already stopping: nothing to do.
        for state in [TaskState::Complete, TaskState::Failed, TaskState::Shutdown] {
            task.status = TaskStatus::new(state, "x");
            assert!(!is_stoppable(&task), "terminal/{state}");
        }
        task.status = TaskStatus::new(TaskState::Running, "x");
        for desired in [DesiredState::Shutdown, DesiredState::Remove] {
            task.desired_state = desired;
            assert!(!is_stoppable(&task), "desired/{desired}");
        }
    }

    #[test]
    fn inspect_splits_the_entrypoint_from_its_arguments() {
        let mut task = sample_task("web");
        task.spec.container.command = vec!["/bin/sh".to_owned(), "-l".to_owned()];
        task.spec.container.args = vec!["-c".to_owned(), "true".to_owned()];
        let inspect = container_inspect(&task, None, None, "satl", None, None);
        assert_eq!(inspect.path, "/bin/sh");
        assert_eq!(inspect.args, ["-l", "-c", "true"]);

        // No entrypoint: the command's first word is the path.
        task.spec.container.command.clear();
        let inspect = container_inspect(&task, None, None, "satl", None, None);
        assert_eq!(inspect.path, "-c");
        assert_eq!(inspect.args, ["true"]);

        task.spec.container.args.clear();
        let inspect = container_inspect(&task, None, None, "satl", None, None);
        assert_eq!(inspect.path, "");
        assert!(inspect.args.is_empty());
    }

    #[test]
    fn inspect_carries_the_task_address_and_its_subnet() {
        let task = sample_task("web");
        let subnet: SubnetV4 = "10.88.0.0/24".parse().expect("a subnet");
        let inspect = container_inspect(
            &task,
            Some(Ipv4Addr::new(10, 88, 0, 5)),
            Some(subnet),
            "satl",
            None,
            None,
        );
        assert_eq!(inspect.network.ip_address.as_deref(), Some("10.88.0.5"));
        assert_eq!(inspect.network.ip_prefix_len, 24);
        assert_eq!(inspect.network.gateway.as_deref(), Some("10.88.0.1"));
        assert_eq!(inspect.network.network_name, "satl");
    }

    #[test]
    fn repository_strips_only_a_real_tag() {
        assert_eq!(
            repository_of("docker.io/library/nginx:1.27"),
            "docker.io/library/nginx"
        );
        assert_eq!(repository_of("127.0.0.1:5000/app"), "127.0.0.1:5000/app");
        assert_eq!(
            repository_of("127.0.0.1:5000/app:latest"),
            "127.0.0.1:5000/app"
        );
    }

    #[test]
    fn digests_are_shortened_the_way_docker_shows_layers() {
        assert_eq!(
            short_digest("sha256:0123456789abcdef0123456789abcdef"),
            "0123456789ab"
        );
        assert_eq!(short_digest("abc"), "abc");
    }
}
