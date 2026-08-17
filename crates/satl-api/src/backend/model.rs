// SPDX-License-Identifier: BSD-2-Clause
//! Plain data types exchanged with the [`Backend`](super::Backend).
//!
//! Deliberately free of any HTTP/axum type: the daemon implements the backend
//! against these, and this crate alone knows how to render them as Docker
//! Engine API documents. Domain types come from `satl-core` wherever one
//! exists ([`Mount`], [`PortProtocol`], [`RestartPolicy`], [`TaskState`], …) so
//! the daemon never re-models what the cluster store already holds.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use futures_util::stream::BoxStream;
use satl_core::{
    Availability, ClusterSpec, DesiredState, JoinTokens, Mount, Network, NetworkSpec, Node,
    NodeRole, Platform, PortConfig, PortProtocol, PublishMode, RestartPolicy, Service, ServiceSpec,
    Task, TaskState, Version,
};
use tokio::sync::oneshot;

/// Result alias for every [`Backend`](super::Backend) method.
pub type Result<T> = std::result::Result<T, BackendError>;

/// Failure of a backend operation, mapped to Docker's HTTP status codes by
/// the API layer: `NotFound` → 404, `Conflict` → 409, `InvalidParameter` →
/// 400, `NotImplemented` → 501, `Unavailable` → 503, `Internal` → 500. Every
/// body is Docker's `{"message": "..."}` envelope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// No such container/image/volume/exec instance.
    #[error("{0}")]
    NotFound(String),

    /// The object exists but is in the wrong state for this operation
    /// (already running, still in use, name taken, …).
    #[error("{0}")]
    Conflict(String),

    /// The request was understood but its parameters are unusable.
    #[error("{0}")]
    InvalidParameter(String),

    /// A Docker feature SatL does not implement (yet).
    #[error("{0}")]
    NotImplemented(String),

    /// The daemon cannot serve this request in its current state — Docker's
    /// `errdefs.Unavailable` family, most prominently every swarm-scoped call
    /// on a node that is not a manager (moby `daemon/cluster/errors.go` →
    /// `api/server/httpstatus`: 503).
    #[error("{0}")]
    Unavailable(String),

    /// Anything else — the daemon must have logged the detail already.
    #[error("{0}")]
    Internal(String),
}

/// Docker's refusal for a swarm-scoped call on a worker, verbatim from moby
/// `daemon/cluster/cluster.go` (`errNoManager`, the active-worker arm). The
/// wording is a compatibility surface: scripts and humans both match on it.
pub const NOT_A_SWARM_MANAGER: &str = "This node is not a swarm manager. Worker nodes can't be \
     used to view or modify cluster state. Please run this command on a manager node or promote \
     the current node to a manager.";

impl BackendError {
    /// `404 Not Found`.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    /// `409 Conflict`.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    /// `400 Bad Request`.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidParameter(message.into())
    }

    /// `501 Not Implemented`.
    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self::NotImplemented(message.into())
    }

    /// `503 Service Unavailable`.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable(message.into())
    }

    /// The Docker-shaped refusal every cluster-scoped endpoint answers on a
    /// worker node ([`NOT_A_SWARM_MANAGER`], 503).
    #[must_use]
    pub fn not_a_swarm_manager() -> Self {
        Self::Unavailable(NOT_A_SWARM_MANAGER.to_owned())
    }

    /// `500 Internal Server Error`.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

// ---------------------------------------------------------------------------
// Containers — create
// ---------------------------------------------------------------------------

/// Everything `POST /containers/create` asks for, already validated and
/// normalized (see `crate::convert`).
///
/// A SatL "container" is a Task of a single-replica anonymous service
/// (invariant #2), so these options are the raw material for a `ServiceSpec`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateContainerOptions {
    /// Requested container name (`?name=`), i.e. the service name; `None`
    /// lets the daemon generate one.
    pub name: Option<String>,
    /// Image reference as the client wrote it.
    pub image: String,
    /// `Cmd`: arguments to the entrypoint (or the command, when no entrypoint
    /// is given).
    pub cmd: Vec<String>,
    /// `Entrypoint` override; empty means "use the image's".
    pub entrypoint: Vec<String>,
    /// `Env`, as `KEY=VALUE` strings.
    pub env: Vec<String>,
    /// `WorkingDir`; `None` means "use the image's".
    pub working_dir: Option<String>,
    /// `User` (`<user>` or `<user>:<group>`).
    pub user: Option<String>,
    /// `Hostname` inside the jail.
    pub hostname: Option<String>,
    /// `Tty`.
    pub tty: bool,
    /// `Labels`.
    pub labels: BTreeMap<String, String>,
    /// `ExposedPorts`, declaration only (no host binding).
    pub exposed_ports: Vec<ExposedPort>,
    /// `HostConfig.Binds` with a host path source (nullfs bind mounts) and
    /// named-volume binds; kind-tagged as `satl-core` mounts.
    pub binds: Vec<Mount>,
    /// `Volumes`: anonymous volumes (`Mount { kind: Volume, source: None }`).
    pub volumes: Vec<Mount>,
    /// `HostConfig.Tmpfs`.
    pub tmpfs: Vec<Mount>,
    /// `HostConfig.PortBindings`, flattened.
    pub port_bindings: Vec<PortMapping>,
    /// `HostConfig.Memory` in bytes; `None` when unset (0).
    pub memory: Option<i64>,
    /// `HostConfig.NanoCpus`; `None` when unset (0).
    pub nano_cpus: Option<i64>,
    /// `HostConfig.RestartPolicy`, translated to SatL's task restart policy.
    pub restart_policy: RestartPolicy,
    /// `?platform=os/arch`; `None` lets the image's manifest decide.
    pub platform: Option<Platform>,
    /// `HostConfig.AutoRemove`.
    pub auto_remove: bool,
}

impl CreateContainerOptions {
    /// All mounts in one list — binds, anonymous volumes, then tmpfs — in the
    /// `satl-core` shape a `ContainerSpec` expects.
    #[must_use]
    pub fn mounts(&self) -> Vec<Mount> {
        let mut mounts =
            Vec::with_capacity(self.binds.len() + self.volumes.len() + self.tmpfs.len());
        mounts.extend(self.binds.iter().cloned());
        mounts.extend(self.volumes.iter().cloned());
        mounts.extend(self.tmpfs.iter().cloned());
        mounts
    }

    /// Published ports as `satl-core` [`PortConfig`]s (always host-published
    /// in M1 — there is no ingress mesh yet).
    #[must_use]
    pub fn port_configs(&self) -> Vec<PortConfig> {
        self.port_bindings
            .iter()
            .map(PortMapping::to_port_config)
            .collect()
    }
}

/// A port the image declares it listens on (`ExposedPorts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExposedPort {
    /// Port inside the jail.
    pub port: u16,
    /// Transport protocol.
    pub protocol: PortProtocol,
}

/// One `HostConfig.PortBindings` entry: a host binding for a container port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    /// Host address to bind on; `None` means every address (`0.0.0.0`).
    pub host_ip: Option<String>,
    /// Host port; 0 means "pick a free one".
    pub host_port: u16,
    /// Port inside the jail.
    pub container_port: u16,
    /// Transport protocol.
    pub protocol: PortProtocol,
}

impl PortMapping {
    /// The `satl-core` view of this mapping (host publish mode).
    #[must_use]
    pub fn to_port_config(&self) -> PortConfig {
        PortConfig {
            name: String::new(),
            protocol: self.protocol,
            target_port: self.container_port,
            published_port: self.host_port,
            publish_mode: PublishMode::Host,
        }
    }

    /// Rebuilds a mapping from an allocated [`PortConfig`] (the daemon's
    /// direction: store object → API document).
    #[must_use]
    pub fn from_port_config(port: &PortConfig, host_ip: Option<String>) -> Self {
        Self {
            host_ip,
            host_port: port.published_port,
            container_port: port.target_port,
            protocol: port.protocol,
        }
    }
}

/// Result of `POST /containers/create`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreatedContainer {
    /// The new container ID — the Task ID (25-char base36).
    pub id: String,
    /// Non-fatal notes shown by the client.
    pub warnings: Vec<String>,
}

/// Whether a lifecycle call actually changed anything; Docker answers `204`
/// for a change and `304` when the container was already in the target state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeOutcome {
    /// The container moved (start/stop was performed).
    Changed,
    /// Already started/stopped — nothing to do.
    Unchanged,
}

// ---------------------------------------------------------------------------
// Containers — read
// ---------------------------------------------------------------------------

/// Runtime state of a task, in `satl-core` terms; the API derives Docker's
/// `State`/`Status` strings from it (`crate::render`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRuntimeState {
    /// Observed task state (agent-reported).
    pub task_state: TaskState,
    /// Desired state (manager-written).
    pub desired_state: DesiredState,
    /// Exit code once the task terminated.
    pub exit_code: Option<i64>,
    /// Failure detail for `Failed`/`Rejected` tasks.
    pub error: Option<String>,
    /// When the jail was started.
    pub started_at: Option<SystemTime>,
    /// When the jail's main process exited.
    pub finished_at: Option<SystemTime>,
    /// PID of the jail's main process while it runs.
    pub pid: Option<i64>,
    /// Healthcheck state, when the task has a healthcheck **and** runs on the
    /// node answering the request: health is node-local and never enters the
    /// store (invariant #1), so a manager listing another node's tasks reports
    /// none (`docs/api-compat.md` #87).
    pub health: Option<ContainerHealth>,
}

/// Docker's `State.Health` for one container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHealth {
    /// `starting`, `healthy` or `unhealthy`.
    pub status: String,
    /// Consecutive probe failures so far.
    pub failing_streak: u32,
    /// The last few probe results, oldest first.
    pub log: Vec<ContainerHealthLog>,
}

/// One probe result in [`ContainerHealth::log`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHealthLog {
    /// When the probe started.
    pub start: SystemTime,
    /// When it finished.
    pub end: SystemTime,
    /// Its exit code; `-1` when it could not be run or timed out.
    pub exit_code: i32,
    /// Up to 4096 bytes of its output.
    pub output: String,
}

impl Default for ContainerRuntimeState {
    fn default() -> Self {
        Self {
            task_state: TaskState::New,
            desired_state: DesiredState::Running,
            exit_code: None,
            error: None,
            started_at: None,
            finished_at: None,
            pid: None,
            health: None,
        }
    }
}

/// One row of `GET /containers/json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSummary {
    /// Container ID (= Task ID).
    pub id: String,
    /// Container name (= service name), without Docker's leading `/`.
    pub name: String,
    /// Image reference as requested.
    pub image: String,
    /// Resolved image ID (`sha256:…`).
    pub image_id: String,
    /// Entrypoint + arguments; rendered as one string.
    pub command: Vec<String>,
    /// Creation timestamp.
    pub created: SystemTime,
    /// Task state, rendered into `State`/`Status`.
    pub state: ContainerRuntimeState,
    /// Host port bindings currently in effect.
    pub ports: Vec<PortMapping>,
    /// Container labels.
    pub labels: BTreeMap<String, String>,
    /// Mounts, in `satl-core` form.
    pub mounts: Vec<Mount>,
    /// Network name the task is attached to.
    pub network_name: String,
    /// Address on that network.
    pub ip_address: Option<String>,
    /// Resolved image platform — a SatL extension (`PLATFORM` column).
    pub platform: Option<Platform>,
}

/// `GET /containers/{id}/json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInspect {
    /// Container ID (= Task ID).
    pub id: String,
    /// Container name (= service name), without the leading `/`.
    pub name: String,
    /// Creation timestamp.
    pub created: SystemTime,
    /// Image reference as requested.
    pub image: String,
    /// Resolved image ID (`sha256:…`).
    pub image_id: String,
    /// Resolved entrypoint binary.
    pub path: String,
    /// Arguments to `path`.
    pub args: Vec<String>,
    /// Task state.
    pub state: ContainerRuntimeState,
    /// The container-level configuration this task runs with.
    pub config: ContainerConfig,
    /// Host-level knobs SatL honours.
    pub host_config: HostConfig,
    /// Addresses and published ports.
    pub network: NetworkSettings,
    /// Mounts, in `satl-core` form.
    pub mounts: Vec<Mount>,
    /// Resolved image platform — a SatL extension.
    pub platform: Option<Platform>,
    /// Jail ID (`jls -j <id>`) — a SatL extension, `None` before creation.
    pub jail_id: Option<String>,
    /// How many times the restart supervisor replaced this task.
    pub restart_count: u64,
}

/// `Config` section of a container inspect document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerConfig {
    /// Hostname inside the jail.
    pub hostname: Option<String>,
    /// User the entrypoint runs as.
    pub user: Option<String>,
    /// Environment, `KEY=VALUE`.
    pub env: Vec<String>,
    /// Command arguments.
    pub cmd: Vec<String>,
    /// Entrypoint override.
    pub entrypoint: Vec<String>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// Labels.
    pub labels: BTreeMap<String, String>,
    /// Whether a TTY was requested.
    pub tty: bool,
    /// Whether stdin is kept open.
    pub open_stdin: bool,
    /// Image reference.
    pub image: String,
    /// Declared ports.
    pub exposed_ports: Vec<ExposedPort>,
}

/// `HostConfig` subset SatL implements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostConfig {
    /// `Binds`, as the client wrote them (`src:dst[:ro]`).
    pub binds: Vec<String>,
    /// `Tmpfs`: mount point → mount options.
    pub tmpfs: BTreeMap<String, String>,
    /// Host port bindings.
    pub port_bindings: Vec<PortMapping>,
    /// Memory limit in bytes, 0 when unlimited.
    pub memory: i64,
    /// CPU limit in billionths of a core, 0 when unlimited.
    pub nano_cpus: i64,
    /// Restart policy, in `satl-core` form.
    pub restart_policy: RestartPolicy,
    /// Whether the container is removed once it exits.
    pub auto_remove: bool,
    /// Network mode (`bridge` or a SatL network name).
    pub network_mode: String,
}

/// `NetworkSettings` subset SatL implements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkSettings {
    /// Name of the attached network.
    pub network_name: String,
    /// ID of the attached network.
    pub network_id: Option<String>,
    /// Address inside the network.
    pub ip_address: Option<String>,
    /// Prefix length of the network's subnet.
    pub ip_prefix_len: u8,
    /// Default gateway inside the network.
    pub gateway: Option<String>,
    /// MAC address of the jail-side epair.
    pub mac_address: Option<String>,
    /// Host port bindings.
    pub ports: Vec<PortMapping>,
}

/// `?condition=` of `POST /containers/{id}/wait`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WaitCondition {
    /// Return as soon as the container is not running (Docker's default).
    #[default]
    NotRunning,
    /// Wait for the *next* exit, even if the container already exited once.
    NextExit,
    /// Wait until the container is removed.
    Removed,
}

/// Result of `POST /containers/{id}/wait`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WaitResult {
    /// Exit code of the container's main process.
    pub status_code: i64,
    /// Wait error, if the container could not be waited on.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

/// `GET /containers/{id}/logs` query, validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Docker's log query genuinely is a bag of independent flags.
#[allow(clippy::struct_excessive_bools)]
pub struct LogOptions {
    /// Keep the stream open and follow new output.
    pub follow: bool,
    /// Include stdout.
    pub stdout: bool,
    /// Include stderr.
    pub stderr: bool,
    /// Only the last N lines; `None` means "all".
    pub tail: Option<u64>,
    /// Prefix every frame payload with an RFC 3339 nanosecond timestamp.
    pub timestamps: bool,
    /// Only output produced at or after this instant.
    pub since: Option<SystemTime>,
}

impl Default for LogOptions {
    fn default() -> Self {
        Self {
            follow: false,
            stdout: true,
            stderr: true,
            tail: None,
            timestamps: false,
            since: None,
        }
    }
}

/// Which standard stream a chunk of output came from. The numeric values are
/// Docker's multiplexed-frame stream bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogStream {
    /// Standard output.
    Stdout = 1,
    /// Standard error.
    Stderr = 2,
}

impl LogStream {
    /// The stream byte used in the 8-byte frame header.
    #[must_use]
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// One chunk of container (or exec) output, before framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFrame {
    /// Originating stream.
    pub stream: LogStream,
    /// When the chunk was produced (used when `timestamps=1`).
    pub timestamp: SystemTime,
    /// Raw payload bytes, exactly as the process wrote them.
    pub data: Bytes,
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

/// Decoded `X-Registry-Auth` header (Docker's base64url JSON `AuthConfig`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryAuth {
    /// Registry username.
    pub username: String,
    /// Registry password or token.
    pub password: String,
    /// Base64 `user:password`, when the client sent that form instead.
    pub auth: String,
    /// Registry the credentials belong to.
    pub server_address: String,
    /// `OAuth2` identity token.
    pub identity_token: String,
    /// Bearer registry token.
    pub registry_token: String,
    /// Account e-mail (legacy field).
    pub email: String,
}

/// One line of a `POST /images/create` progress stream (Docker's
/// `JSONMessage`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullProgressLine {
    /// Human-readable status (`Pulling from library/nginx`, `Download
    /// complete`, …).
    pub status: String,
    /// Layer/blob this line is about.
    pub id: Option<String>,
    /// Byte counters for progress bars.
    pub progress_detail: Option<ProgressDetail>,
    /// Pre-rendered progress bar, as Docker sends it.
    pub progress: Option<String>,
    /// Fatal error; the client aborts the pull when it sees this.
    pub error: Option<String>,
}

impl PullProgressLine {
    /// A plain status line.
    pub fn status(status: impl Into<String>) -> Self {
        Self {
            status: status.into(),
            ..Self::default()
        }
    }
}

/// Byte counters inside a [`PullProgressLine`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProgressDetail {
    /// Bytes transferred so far.
    pub current: Option<u64>,
    /// Total bytes, when known.
    pub total: Option<u64>,
}

/// One row of `GET /images/json`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageSummary {
    /// Image ID (`sha256:…`).
    pub id: String,
    /// Parent image ID, empty for OCI images pulled by SatL.
    pub parent_id: String,
    /// `repository:tag` strings.
    pub repo_tags: Vec<String>,
    /// `repository@digest` strings.
    pub repo_digests: Vec<String>,
    /// Creation timestamp from the image config.
    pub created: Option<SystemTime>,
    /// Total on-disk size in bytes.
    pub size: i64,
    /// Bytes shared with other images.
    pub shared_size: i64,
    /// Image labels.
    pub labels: BTreeMap<String, String>,
    /// Number of containers using this image.
    pub containers: i64,
    /// Image platform — a SatL extension (`PLATFORM` column).
    pub platform: Option<Platform>,
}

// ---------------------------------------------------------------------------
// Exec
// ---------------------------------------------------------------------------

/// Identifier of an exec instance, returned by
/// [`create_exec`](super::Backend::create_exec).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecId(String);

impl ExecId {
    /// Wraps an identifier string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ExecId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `POST /containers/{id}/exec` body, validated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
// Docker's exec config is a bag of independent attach flags.
#[allow(clippy::struct_excessive_bools)]
pub struct ExecConfig {
    /// Command and arguments.
    pub cmd: Vec<String>,
    /// Extra environment, `KEY=VALUE`.
    pub env: Vec<String>,
    /// Working directory inside the jail.
    pub working_dir: Option<String>,
    /// User to run as.
    pub user: Option<String>,
    /// Whether stdin is attached (accepted, then discarded in M1).
    pub attach_stdin: bool,
    /// Whether stdout is streamed back.
    pub attach_stdout: bool,
    /// Whether stderr is streamed back.
    pub attach_stderr: bool,
}

/// A started exec instance: its output frames plus its eventual exit code.
pub struct ExecStream {
    /// Multiplexed output of the exec'd process.
    pub frames: BoxStream<'static, LogFrame>,
    /// Resolves once the process exits.
    pub exit: oneshot::Receiver<i64>,
}

impl std::fmt::Debug for ExecStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecStream").finish_non_exhaustive()
    }
}

/// `GET /exec/{id}/json`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
// Mirrors Docker's ExecInspect, which is likewise flag-heavy.
#[allow(clippy::struct_excessive_bools)]
pub struct ExecInspect {
    /// Exec instance ID.
    pub id: String,
    /// Container the exec belongs to.
    pub container_id: String,
    /// Whether the process is still running.
    pub running: bool,
    /// Exit code once it finished.
    pub exit_code: Option<i64>,
    /// PID inside the jail.
    pub pid: Option<i64>,
    /// The command being run.
    pub cmd: Vec<String>,
    /// Whether a TTY was requested (always false in M1).
    pub tty: bool,
    /// Whether stdin was attached.
    pub open_stdin: bool,
    /// Whether stdout was attached.
    pub open_stdout: bool,
    /// Whether stderr was attached.
    pub open_stderr: bool,
}

// ---------------------------------------------------------------------------
// Volumes
// ---------------------------------------------------------------------------

/// `POST /volumes/create` body, validated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateVolumeOptions {
    /// Volume name; empty means "generate one".
    pub name: String,
    /// Driver name — SatL only has `local` (ZFS datasets).
    pub driver: String,
    /// Driver options.
    pub driver_opts: BTreeMap<String, String>,
    /// Volume labels.
    pub labels: BTreeMap<String, String>,
}

/// One volume, as returned by create/list/inspect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeInfo {
    /// Volume name.
    pub name: String,
    /// Driver name (`local`).
    pub driver: String,
    /// Host mountpoint (the ZFS dataset's mountpoint).
    pub mountpoint: String,
    /// Creation timestamp.
    pub created_at: Option<SystemTime>,
    /// Volume labels.
    pub labels: BTreeMap<String, String>,
    /// Driver options.
    pub options: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// Networks (M3)
// ---------------------------------------------------------------------------

/// `POST /networks/create`, validated and converted.
///
/// Carries the store object's spec, like [`ServiceCreateOptions`]: everything
/// Docker's `NetworkCreate` body can express that SatL honours is already in
/// [`NetworkSpec`], and everything it cannot is rejected by
/// `crate::convert::cluster` before this type exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateNetworkOptions {
    /// The desired state of the network. An empty `annotations.name` asks the
    /// daemon to generate one, as `POST /containers/create` does.
    pub spec: NetworkSpec,
}

/// Result of `POST /networks/create`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkCreated {
    /// The new network ID.
    pub id: String,
    /// A non-fatal note shown by the client (Docker's single `Warning`).
    pub warning: String,
}

/// One row of `GET /networks`.
///
/// Carries the store object plus the one thing that cannot be read off it
/// without knowing *which node is answering*: this node's gateway address.
/// An overlay has one gateway per participating node
/// (`Network.node_gateways`), because a single shared address on one L2 segment
/// is a duplicate address (`docs/vxlan.md` §8) — so "the" gateway in a Docker
/// document is necessarily local, and the daemon is the only layer that knows
/// its own node ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSummary {
    /// The network object as held in the Raft store.
    pub network: Network,
    /// The gateway address this node holds on it; `None` when this node runs no
    /// task on the network.
    pub gateway: Option<String>,
}

/// `GET /networks/{id}` — the same document as a list row, plus the attached
/// tasks Docker renders as `Containers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDetail {
    /// The network object as held in the Raft store.
    pub network: Network,
    /// The gateway address this node holds on it (see [`NetworkSummary`]).
    pub gateway: Option<String>,
    /// Tasks attached to the network, cluster-wide.
    pub endpoints: Vec<NetworkEndpointInfo>,
}

/// One attached task, as `GET /networks/{id}` reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkEndpointInfo {
    /// Task ID — Docker's container ID, and the key of the `Containers` map.
    pub task_id: String,
    /// Task name (`<service>.<slot>.<id>`).
    pub name: String,
    /// The task's address on the network, in CIDR form.
    pub address: String,
    /// The task's MAC on the network. Derived from the address by both ends of
    /// the overlay (`satl_core::MacAddr::from_ipv4`), never allocated.
    pub mac_address: String,
}

/// `POST /networks/{id}/connect` body, validated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkConnectOptions {
    /// Container (= task ID, ID prefix or name) to attach.
    pub container: String,
    /// Extra DNS names for the container on that network
    /// (`EndpointConfig.Aliases`).
    pub aliases: Vec<String>,
}

/// `POST /networks/{id}/disconnect` body, validated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkDisconnectOptions {
    /// Container (= task ID, ID prefix or name) to detach.
    pub container: String,
    /// Detach even if the container is not running (Docker's `Force`).
    pub force: bool,
}

// ---------------------------------------------------------------------------
// Events / system
// ---------------------------------------------------------------------------

/// One `GET /events` message (Docker's event model).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventMessage {
    /// Object kind: `container`, `image`, `volume`, `network`, …
    pub kind: String,
    /// What happened: `create`, `start`, `die`, `destroy`, `pull`, …
    pub action: String,
    /// Who it happened to.
    pub actor: EventActor,
    /// Docker's event scope: `local` or `swarm`.
    pub scope: String,
    /// When it happened.
    pub time: SystemTime,
}

/// The `Actor` of an [`EventMessage`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventActor {
    /// Object ID (container ID, image reference, volume name, …).
    pub id: String,
    /// Free-form attributes (`name`, `image`, labels, `exitCode`, …).
    pub attributes: BTreeMap<String, String>,
}

/// What one `POST /containers/prune` reclaimed.
///
/// `space_reclaimed` is the bytes the removed containers' writable layers held.
/// It can be **short of the truth on purpose**: a container rootfs cannot be
/// destroyed while its jail is still dying (`docs/jail-teardown.md`), so what
/// prune reports is what was measured before removal, and the node's periodic
/// sweep is what actually frees it moments later.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrunedContainers {
    /// IDs of the containers removed.
    pub deleted: Vec<String>,
    /// Bytes their writable layers held.
    pub space_reclaimed: u64,
}

/// One line of `POST /images/prune`'s `ImagesDeleted`, in Docker's two shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageDeleted {
    /// A reference stopped pointing at an image (`Untagged`).
    Untagged(String),
    /// Content that nothing reaches any more was deleted (`Deleted`): a layer
    /// dataset, a blob, a manifest or a config.
    Deleted(String),
}

/// What one `POST /images/prune` reclaimed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrunedImages {
    /// What was untagged and what was deleted, in that order.
    pub deleted: Vec<ImageDeleted>,
    /// Bytes freed: layer datasets plus content-store files.
    pub space_reclaimed: u64,
    /// Layer chains that were unreferenced on this pass but not on the previous
    /// one, so nothing was done to them. Reported, not silent: an operator who
    /// runs prune twice and sees a different number should be able to find out
    /// why (`docs/operations.md`).
    pub deferred: Vec<String>,
}

/// What one `POST /networks/prune` reclaimed. No `SpaceReclaimed`: Docker's
/// network prune has none either, because a network is not disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrunedNetworks {
    /// Names of the networks removed.
    pub deleted: Vec<String>,
}

/// What one `POST /volumes/prune` reclaimed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrunedVolumes {
    /// Names of the volumes removed.
    pub deleted: Vec<String>,
    /// Bytes their datasets held.
    pub space_reclaimed: u64,
}

/// Object counts served by `GET /info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Containers in any state.
    pub containers: i64,
    /// Containers currently running.
    pub containers_running: i64,
    /// Containers currently paused (always 0 — jails are not paused in v1).
    pub containers_paused: i64,
    /// Containers created or exited.
    pub containers_stopped: i64,
    /// Images in the content store.
    pub images: i64,
}

/// Grace period a stop request grants before the jail is killed, when the
/// client did not send `?t=`.
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Swarm (M2)
// ---------------------------------------------------------------------------

/// `POST /swarm/init` body, validated.
///
/// SatL nodes bootstrap a single-node cluster at first start (architecture
/// §1.2), so this call *re-initializes* the local cluster rather than creating
/// one from nothing — the deviation is recorded in `docs/api-compat.md`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SwarmInitOptions {
    /// `AdvertiseAddr`: the address other nodes dial; `None` lets the daemon
    /// pick one from its interfaces.
    pub advertise_addr: Option<String>,
    /// `ListenAddr`: the address the control plane binds.
    pub listen_addr: Option<String>,
    /// `ForceNewCluster`: keep the store, discard the Raft membership.
    pub force_new_cluster: bool,
    /// `AutoLockManagers`: lock the managers' keys behind an unlock key.
    pub auto_lock: bool,
}

/// Result of `POST /swarm/init`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SwarmInitResult {
    /// ID of the node that is now a manager.
    pub node_id: String,
}

/// `POST /swarm/join` body, validated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SwarmJoinOptions {
    /// `RemoteAddrs`: manager endpoints to try, in order.
    pub remote_addrs: Vec<String>,
    /// `JoinToken`: decides the role the node joins with (architecture §12.2).
    pub join_token: String,
    /// `AdvertiseAddr`.
    pub advertise_addr: Option<String>,
    /// `ListenAddr`.
    pub listen_addr: Option<String>,
}

/// `GET /swarm` — the cluster object as an operator sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmDetail {
    /// Cluster object ID.
    pub cluster_id: String,
    /// Creation timestamp.
    pub created_at: SystemTime,
    /// Last update timestamp.
    pub updated_at: SystemTime,
    /// Store version (Raft index) of the cluster object, used for optimistic
    /// concurrency on `POST /swarm/update`.
    pub version: Version,
    /// Current join tokens.
    pub join_tokens: JoinTokens,
    /// Root CA certificate, PEM-encoded; empty until the CA is initialized.
    /// Two concatenated certificates (old + new) while a root rotation is in
    /// flight.
    pub root_ca_cert_pem: String,
    /// Whether a root CA rotation is in flight (`RootRotationInProgress` on
    /// the wire).
    pub root_rotation_in_progress: bool,
    /// Cluster-wide settings.
    pub spec: ClusterSpec,
}

/// Which join token `POST /swarm/update` rotates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRole {
    /// The token that joins a node as a worker.
    Worker,
    /// The token that joins a node as a manager.
    Manager,
}

impl TokenRole {
    /// The role name as Docker spells it (`worker`, `manager`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Manager => "manager",
        }
    }
}

impl std::fmt::Display for TokenRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Docker's `LocalNodeState` for the `Swarm` section of `GET /info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LocalNodeState {
    /// The node is not part of a cluster.
    #[default]
    Inactive,
    /// A join is in flight.
    Pending,
    /// The node is a live cluster member.
    Active,
    /// The cluster state could not be determined; see
    /// [`SwarmStatus::error`].
    Error,
    /// The store is encrypted and locked. SatL never reports this on `/info`:
    /// a locked manager serves only `POST /swarm/unlock` and `/_ping` until
    /// it is unlocked (satld's locked listener), so this router never runs.
    Locked,
}

impl LocalNodeState {
    /// The state name as Docker spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Error => "error",
            Self::Locked => "locked",
        }
    }
}

impl std::fmt::Display for LocalNodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One entry of `GET /info`'s `Swarm.RemoteManagers`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagerPeer {
    /// Node ID of the manager.
    pub node_id: String,
    /// Address its control plane is reachable on.
    pub addr: String,
}

/// Live cluster state for `GET /info`'s `Swarm` section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SwarmStatus {
    /// This node's ID, empty when the node is not a member.
    pub node_id: String,
    /// This node's advertised address.
    pub node_addr: String,
    /// Docker's `LocalNodeState`.
    pub local_node_state: LocalNodeState,
    /// Whether this node runs the control plane (is a manager).
    pub control_available: bool,
    /// Cluster error string, empty when healthy.
    pub error: String,
    /// Known manager endpoints.
    pub remote_managers: Vec<ManagerPeer>,
    /// Total members; only meaningful on a manager.
    pub nodes: i64,
    /// Manager members; only meaningful on a manager.
    pub managers: i64,
}

// ---------------------------------------------------------------------------
// Nodes (M2)
// ---------------------------------------------------------------------------

/// One row of `GET /nodes`.
///
/// Carries the store object itself: `satl-core` already models everything
/// Docker's `Node` document holds, so the daemon never re-shapes it (the
/// rendering lives in `crate::render`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSummary {
    /// The node object as held in the Raft store.
    pub node: Node,
}

impl From<Node> for NodeSummary {
    fn from(node: Node) -> Self {
        Self { node }
    }
}

/// `GET /nodes/{id}` — Docker serves the same document as a list row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDetail {
    /// The node object as held in the Raft store.
    pub node: Node,
}

impl From<Node> for NodeDetail {
    fn from(node: Node) -> Self {
        Self { node }
    }
}

/// `POST /nodes/{id}/update` body: the **complete** replacement spec, as
/// Docker's clients send it (read-modify-write against `?version=`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSpecUpdate {
    /// Operator-assigned name; `None` when the field was left empty.
    pub name: Option<String>,
    /// Operator-assigned labels (placement constraints read these).
    pub labels: BTreeMap<String, String>,
    /// Desired role.
    pub role: NodeRole,
    /// Scheduling availability.
    pub availability: Availability,
}

// ---------------------------------------------------------------------------
// Services (M2)
// ---------------------------------------------------------------------------

/// `POST /services/create`, validated and converted.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceCreateOptions {
    /// The desired state of the service.
    pub spec: ServiceSpec,
    /// Decoded `X-Registry-Auth`, used for the initial image pull.
    pub registry_auth: Option<RegistryAuth>,
}

/// Result of `POST /services/create`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceCreated {
    /// The new service ID.
    pub id: String,
    /// Non-fatal notes shown by the client.
    pub warnings: Vec<String>,
}

/// Task counts backing Docker's `ServiceStatus` (the `REPLICAS` column).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServiceTaskCounts {
    /// Tasks currently running.
    pub running: u64,
    /// Tasks the orchestrator wants running.
    pub desired: u64,
    /// Tasks that ran to completion (jobs; always 0 in v1).
    pub completed: u64,
}

/// One row of `GET /services`.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceSummary {
    /// The service object as held in the Raft store.
    pub service: Service,
    /// Replica counts for `ServiceStatus`.
    pub tasks: ServiceTaskCounts,
}

/// `GET /services/{id}`.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceDetail {
    /// The service object as held in the Raft store.
    pub service: Service,
}

/// `POST /services/{id}/update` body, validated and converted.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceUpdateOptions {
    /// The complete new spec (Docker's clients read-modify-write).
    pub spec: ServiceSpec,
    /// `?rollback=previous`: swap back to the previous spec instead.
    pub rollback: bool,
    /// Decoded `X-Registry-Auth` for the new image.
    pub registry_auth: Option<RegistryAuth>,
}

// ---------------------------------------------------------------------------
// Tasks (M2)
// ---------------------------------------------------------------------------

/// `GET /tasks?filters=`, parsed. Empty members mean "no restriction"; a
/// non-empty member matches any of its values (Docker's OR-within-a-key,
/// AND-across-keys semantics).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskFilters {
    /// `id` — task ID or unambiguous prefix.
    pub ids: Vec<String>,
    /// `name` — task name (`<service>.<slot>.<id>`) or prefix.
    pub names: Vec<String>,
    /// `service` — service ID or name.
    pub services: Vec<String>,
    /// `node` — node ID or hostname.
    pub nodes: Vec<String>,
    /// `desired-state` — one of `ready`, `running`, `shutdown`.
    pub desired_states: Vec<DesiredState>,
    /// `label` — key, with an optional exact value.
    pub labels: BTreeMap<String, Option<String>>,
}

impl TaskFilters {
    /// Whether no filter at all was requested.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
            && self.names.is_empty()
            && self.services.is_empty()
            && self.nodes.is_empty()
            && self.desired_states.is_empty()
            && self.labels.is_empty()
    }
}

/// One row of `GET /tasks`.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskSummary {
    /// The task object as held in the Raft store.
    pub task: Task,
}

impl From<Task> for TaskSummary {
    fn from(task: Task) -> Self {
        Self { task }
    }
}

/// `GET /tasks/{id}`.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskDetail {
    /// The task object as held in the Raft store.
    pub task: Task,
}

impl From<Task> for TaskDetail {
    fn from(task: Task) -> Self {
        Self { task }
    }
}

// ---------------------------------------------------------------------------
// M5 — secrets / configs
// ---------------------------------------------------------------------------

/// Result of `POST /secrets/create`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretCreated {
    /// The new secret's ID.
    pub id: String,
}

/// Result of `POST /configs/create`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigCreated {
    /// The new config's ID.
    pub id: String,
}
