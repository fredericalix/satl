// SPDX-License-Identifier: BSD-2-Clause
//! Docker Engine API wire types (v1.43 shapes).
//!
//! Field names serialize exactly as Docker emits them (`PascalCase` plus
//! Docker's irregular spellings such as `MinAPIVersion`, `OSType`, `NCPU`,
//! `ImageID`, `HostIp`). Request bodies are deliberately permissive — Docker
//! clients send a great many fields SatL ignores — and are turned into
//! backend model types by `crate::convert`; response documents are built by
//! `crate::render`.

use std::collections::BTreeMap;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

/// Docker error envelope: every non-2xx response body is `{"message": "..."}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Human-readable error message.
    pub message: String,
}

/// Builds a Docker-shaped error response (`{"message": ...}`) with `status`.
pub(crate) fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            message: message.into(),
        }),
    )
        .into_response()
}

/// `GET /version` response body (Docker `SystemVersion`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VersionResponse {
    /// Product platform (`{"Name": "SatL"}`).
    pub platform: PlatformInfo,
    /// Per-component version reports; SatL reports a single `Engine` entry.
    pub components: Vec<ComponentVersion>,
    /// SatL release version.
    pub version: String,
    /// Docker Engine API version implemented.
    pub api_version: String,
    /// Minimum negotiable Docker Engine API version.
    #[serde(rename = "MinAPIVersion")]
    pub min_api_version: String,
    /// Git commit the daemon was built from.
    pub git_commit: String,
    /// Operating system (`freebsd`).
    pub os: String,
    /// CPU architecture, Docker-style (`amd64`, `arm64`).
    pub arch: String,
    /// Kernel version string.
    pub kernel_version: String,
    /// Build timestamp, RFC 3339.
    pub build_time: String,
}

/// `Platform` section of [`VersionResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PlatformInfo {
    /// Product name (`SatL`).
    pub name: String,
}

/// One entry of the `Components` list in [`VersionResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ComponentVersion {
    /// Component name (`Engine`).
    pub name: String,
    /// Component version.
    pub version: String,
    /// Engine build details.
    pub details: EngineDetails,
}

/// `Details` section of the `Engine` component in [`VersionResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EngineDetails {
    /// Docker Engine API version implemented.
    pub api_version: String,
    /// CPU architecture, Docker-style.
    pub arch: String,
    /// Build timestamp, RFC 3339.
    pub build_time: String,
    /// Git commit the daemon was built from.
    pub git_commit: String,
    /// Kernel version string.
    pub kernel_version: String,
    /// Minimum negotiable Docker Engine API version.
    #[serde(rename = "MinAPIVersion")]
    pub min_api_version: String,
    /// Operating system (`freebsd`).
    pub os: String,
}

/// `GET /info` response body — the minimal coherent v1.43 `SystemInfo` shape
/// SatL serves in M0.
///
/// Container/image counts are hard zeros until the container and image stores
/// exist (M1), and [`InfoResponse::swarm`] is a static "inactive" placeholder
/// until it is wired to the real cluster state in a later M0 step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InfoResponse {
    /// Unique daemon/node identifier.
    #[serde(rename = "ID")]
    pub id: String,
    /// Node hostname.
    pub name: String,
    /// Number of logical CPUs.
    #[serde(rename = "NCPU")]
    pub ncpu: i64,
    /// Total physical memory in bytes.
    pub mem_total: i64,
    /// Operating system name, e.g. `FreeBSD`.
    pub operating_system: String,
    /// Operating system release, e.g. `15.1-RELEASE`.
    #[serde(rename = "OSVersion")]
    pub os_version: String,
    /// Operating system family (`freebsd`).
    #[serde(rename = "OSType")]
    pub os_type: String,
    /// CPU architecture, Docker-style.
    pub architecture: String,
    /// SatL daemon version.
    pub server_version: String,
    /// Storage driver — always `zfs` (ZFS is mandatory in SatL).
    pub driver: String,
    /// Total number of containers (0 until M1).
    pub containers: i64,
    /// Number of running containers (0 until M1).
    pub containers_running: i64,
    /// Number of paused containers (0 until M1).
    pub containers_paused: i64,
    /// Number of stopped containers (0 until M1).
    pub containers_stopped: i64,
    /// Number of images (0 until M1).
    pub images: i64,
    /// Swarm status section: live cluster state from
    /// [`Backend::swarm_status`](crate::Backend::swarm_status), or the static
    /// identity `satld` injected while the backend is unwired.
    pub swarm: SwarmInfoResponse,
    /// Daemon warnings for the client to display.
    pub warnings: Vec<String>,
}

/// The `Swarm` section as it is **served** in [`InfoResponse`].
///
/// Built either from live cluster state
/// ([`Backend::swarm_status`](crate::Backend::swarm_status)) or from the
/// static [`SwarmInfo`] the daemon injected at startup. `Nodes`/`Managers`
/// are Docker's manager-only counters and are omitted when zero.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SwarmInfoResponse {
    /// Node identifier within the cluster.
    #[serde(rename = "NodeID")]
    pub node_id: String,
    /// Address advertised to other cluster members.
    pub node_addr: String,
    /// Docker `LocalNodeState`.
    pub local_node_state: String,
    /// Whether this node is a manager.
    pub control_available: bool,
    /// Cluster error string, empty when healthy.
    pub error: String,
    /// Known manager endpoints; `null` when none are known.
    pub remote_managers: Option<Vec<RemoteManagerWire>>,
    /// Total cluster members; omitted on workers.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub nodes: i64,
    /// Manager members; omitted on workers.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub managers: i64,
}

/// One entry of `Swarm.RemoteManagers`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RemoteManagerWire {
    /// Manager node ID.
    #[serde(rename = "NodeID")]
    pub node_id: String,
    /// Address its control plane is reachable on.
    pub addr: String,
}

/// The static `Swarm` identity `satld` injects into
/// [`ApiState::new`](crate::ApiState::new).
///
/// It is what `GET /info` serves until the daemon's backend can report live
/// cluster state; from then on the live
/// [`SwarmStatus`](crate::model::SwarmStatus) wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SwarmInfo {
    /// Node identifier within the cluster.
    #[serde(rename = "NodeID")]
    pub node_id: String,
    /// Address advertised to other cluster members.
    pub node_addr: String,
    /// Docker `LocalNodeState`: `inactive`, `pending`, `active`, `error` or
    /// `locked`.
    pub local_node_state: String,
    /// Whether this node is a manager.
    pub control_available: bool,
    /// Cluster error string, empty when healthy.
    pub error: String,
    /// Known manager endpoints; `null` while the swarm section is inactive.
    pub remote_managers: Option<Vec<serde_json::Value>>,
}

impl SwarmInfo {
    /// The static "swarm inactive" placeholder served in M0.
    #[must_use]
    pub fn inactive() -> Self {
        Self {
            node_id: String::new(),
            node_addr: String::new(),
            local_node_state: "inactive".to_owned(),
            control_available: false,
            error: String::new(),
            remote_managers: None,
        }
    }
}

// ---------------------------------------------------------------------------
// M1 — request bodies
// ---------------------------------------------------------------------------

/// A Docker `StrSlice`: JSON accepts either a single string or an array of
/// strings for `Cmd` and `Entrypoint`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum StringOrList {
    /// A bare string — a shell-style single argument.
    One(String),
    /// The usual exec-form list.
    Many(Vec<String>),
}

impl StringOrList {
    /// Normalizes to a list.
    #[must_use]
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

/// `POST /containers/create` body (Docker's `Config` + `HostConfig`).
///
/// Every field is optional: clients omit what they do not use, and SatL
/// ignores what it cannot honour (rejecting only the options whose silent
/// omission would change the container's security or resource behaviour —
/// see `crate::convert`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ContainerCreateBody {
    /// Hostname inside the container.
    pub hostname: Option<String>,
    /// Domain name (ignored — jails carry a single hostname).
    pub domainname: Option<String>,
    /// User to run as.
    pub user: Option<String>,
    /// Keep stdin open.
    pub open_stdin: bool,
    /// Attach stdin (interactive run).
    pub attach_stdin: bool,
    /// Allocate a pseudo-TTY.
    pub tty: bool,
    /// Ports the image declares (`{"80/tcp": {}}`).
    pub exposed_ports: BTreeMap<String, serde_json::Value>,
    /// Environment, `KEY=VALUE`.
    pub env: Option<Vec<String>>,
    /// Command / arguments.
    pub cmd: Option<StringOrList>,
    /// Entrypoint override.
    pub entrypoint: Option<StringOrList>,
    /// Image reference.
    pub image: Option<String>,
    /// Anonymous volumes (`{"/data": {}}`).
    pub volumes: BTreeMap<String, serde_json::Value>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// Labels.
    pub labels: Option<BTreeMap<String, String>>,
    /// Stop signal (accepted, applied by the runtime).
    pub stop_signal: Option<String>,
    /// Stop grace period in seconds.
    pub stop_timeout: Option<i64>,
    /// Host-level options.
    pub host_config: Option<HostConfigBody>,
}

/// `HostConfig` section of [`ContainerCreateBody`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct HostConfigBody {
    /// `src:dst[:ro]` bind/volume mounts.
    pub binds: Vec<String>,
    /// `--mount` style mounts (rejected in M1 when non-empty).
    pub mounts: Vec<serde_json::Value>,
    /// tmpfs mount point → options.
    pub tmpfs: BTreeMap<String, String>,
    /// Host bindings: `"80/tcp"` → list of host addresses/ports.
    pub port_bindings: BTreeMap<String, Option<Vec<PortBindingBody>>>,
    /// Memory limit in bytes.
    pub memory: i64,
    /// Memory + swap limit (rejected when set: FreeBSD accounts swap
    /// separately).
    pub memory_swap: i64,
    /// CPU limit in billionths of a core.
    pub nano_cpus: i64,
    /// Relative CPU weight (rejected: use `NanoCpus`).
    pub cpu_shares: i64,
    /// CFS quota (rejected: use `NanoCpus`).
    pub cpu_quota: i64,
    /// CPU set (rejected in M1).
    pub cpuset_cpus: String,
    /// Restart policy.
    pub restart_policy: Option<RestartPolicyBody>,
    /// Remove the container once it exits.
    pub auto_remove: bool,
    /// Network mode.
    pub network_mode: String,
    /// Run privileged (rejected — jails have no equivalent).
    pub privileged: bool,
    /// Linux capabilities to add (rejected).
    pub cap_add: Vec<String>,
    /// Linux capabilities to drop (rejected).
    pub cap_drop: Vec<String>,
    /// Security options, e.g. seccomp/apparmor (rejected).
    pub security_opt: Vec<String>,
    /// Device mappings (rejected).
    pub devices: Vec<serde_json::Value>,
    /// cgroup parent (rejected).
    pub cgroup_parent: String,
    /// Kernel parameters (rejected).
    pub sysctls: BTreeMap<String, String>,
    /// Resource ulimits (rejected — rctl covers memory/cpu in M1).
    pub ulimits: Vec<serde_json::Value>,
    /// PID namespace (rejected).
    pub pid_mode: String,
    /// IPC namespace (rejected).
    pub ipc_mode: String,
    /// UTS namespace (rejected).
    #[serde(rename = "UTSMode")]
    pub uts_mode: String,
    /// User namespace (rejected).
    pub userns_mode: String,
    /// `/dev/shm` size (rejected — no tmpfs `/dev/shm` in jails).
    pub shm_size: i64,
    /// Runtime name (only SatL's own runtime is accepted).
    pub runtime: String,
}

/// One host binding inside `HostConfig.PortBindings`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct PortBindingBody {
    /// Host address to bind on; empty means every address.
    #[serde(rename = "HostIp")]
    pub host_ip: String,
    /// Host port as a string (Docker's wire form); empty means "auto".
    pub host_port: String,
}

/// `HostConfig.RestartPolicy`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RestartPolicyBody {
    /// `""`/`no`, `always`, `unless-stopped` or `on-failure`.
    pub name: String,
    /// Attempt cap for `on-failure`.
    pub maximum_retry_count: u64,
}

/// `POST /containers/{id}/exec` body.
// Docker's exec config is a bag of independent attach flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ExecCreateBody {
    /// Command and arguments.
    pub cmd: Option<StringOrList>,
    /// Extra environment.
    pub env: Option<Vec<String>>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// User to run as.
    pub user: Option<String>,
    /// Allocate a TTY (rejected in M1).
    pub tty: bool,
    /// Attach stdin (accepted, then discarded).
    pub attach_stdin: bool,
    /// Stream stdout back.
    pub attach_stdout: bool,
    /// Stream stderr back.
    pub attach_stderr: bool,
    /// Run privileged (rejected).
    pub privileged: bool,
    /// Detach key sequence (ignored — SatL never attaches a TTY).
    pub detach_keys: Option<String>,
}

/// `POST /exec/{id}/start` body.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ExecStartBody {
    /// Run without streaming output back (rejected in M1).
    pub detach: bool,
    /// Allocate a TTY (rejected in M1).
    pub tty: bool,
}

/// A `bool` field that clients may send as `null`.
///
/// Docker's newer API versions model several `NetworkCreate` booleans as `*bool`
/// and marshal the unset ones as `null` (`EnableIPv6` since 1.47,
/// `CheckDuplicate` once deprecated). A plain `bool` field would fail to
/// deserialize and turn a perfectly ordinary `docker network create` into a 400
/// about malformed JSON.
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// `POST /networks/create` body.
///
/// Every field is accepted on the wire and then judged in
/// `crate::convert::cluster`: rejecting in the converter rather than by
/// omission is what makes "SatL cannot honour this" a 400 with a reason instead
/// of a silently different network.
// Docker's field names one-for-one; grouping the flags would break the shape.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NetworkCreateBody {
    /// Network name.
    pub name: String,
    /// Deprecated in Docker, accepted and ignored: SatL always enforces name
    /// uniqueness.
    #[serde(deserialize_with = "null_as_default")]
    pub check_duplicate: bool,
    /// Driver name (`bridge`, `overlay`).
    pub driver: Option<String>,
    /// Requested scope; SatL derives it from the driver.
    pub scope: Option<String>,
    /// No external connectivity (rejected).
    #[serde(deserialize_with = "null_as_default")]
    pub internal: bool,
    /// Standalone containers may attach (rejected).
    #[serde(deserialize_with = "null_as_default")]
    pub attachable: bool,
    /// This is the routing-mesh ingress network.
    #[serde(deserialize_with = "null_as_default")]
    pub ingress: bool,
    /// A configuration-only network (rejected).
    #[serde(deserialize_with = "null_as_default")]
    pub config_only: bool,
    /// Take the configuration from another network (rejected).
    pub config_from: Option<NetworkConfigFromWire>,
    /// Addressing.
    #[serde(rename = "IPAM")]
    pub ipam: Option<IpamWire>,
    /// Enable IPv6 (rejected).
    #[serde(rename = "EnableIPv6", deserialize_with = "null_as_default")]
    pub enable_ipv6: bool,
    /// Driver options; SatL reads only `encrypted` (overlay driver only) —
    /// any other key is a 400.
    pub options: BTreeMap<String, String>,
    /// Labels.
    pub labels: BTreeMap<String, String>,
}

/// `POST /networks/{id}/connect` body.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NetworkConnectBody {
    /// Container to attach.
    pub container: String,
    /// Per-endpoint settings; only `Aliases` is honoured.
    pub endpoint_config: Option<EndpointConfigWire>,
}

/// `EndpointConfig` of a connect body.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct EndpointConfigWire {
    /// Extra DNS names on the network.
    #[serde(deserialize_with = "null_as_default")]
    pub aliases: Vec<String>,
    /// Static addressing (rejected: the cluster allocator owns addresses).
    #[serde(rename = "IPAMConfig")]
    pub ipam_config: Option<serde_json::Value>,
    /// Legacy container links (rejected).
    #[serde(deserialize_with = "null_as_default")]
    pub links: Vec<String>,
    /// Per-endpoint driver options (rejected).
    #[serde(deserialize_with = "null_as_default")]
    pub driver_opts: BTreeMap<String, String>,
}

/// `POST /networks/{id}/disconnect` body.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NetworkDisconnectBody {
    /// Container to detach.
    pub container: String,
    /// Detach even when the container is not running.
    #[serde(deserialize_with = "null_as_default")]
    pub force: bool,
}

/// `POST /volumes/create` body.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct VolumeCreateBody {
    /// Volume name; empty asks the daemon to generate one.
    pub name: String,
    /// Driver name (`local`).
    pub driver: Option<String>,
    /// Driver options.
    pub driver_opts: BTreeMap<String, String>,
    /// Labels.
    pub labels: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// M1 — response documents
// ---------------------------------------------------------------------------

/// `POST /containers/create` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerCreateResponse {
    /// New container ID (= Task ID).
    pub id: String,
    /// Non-fatal notes.
    pub warnings: Vec<String>,
}

/// One entry of `GET /containers/json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerSummaryResponse {
    /// Container ID.
    pub id: String,
    /// Names, each with Docker's leading `/`.
    pub names: Vec<String>,
    /// Image reference.
    pub image: String,
    /// Resolved image ID.
    #[serde(rename = "ImageID")]
    pub image_id: String,
    /// Entrypoint and arguments, joined.
    pub command: String,
    /// Creation time, unix seconds.
    pub created: i64,
    /// Published ports.
    pub ports: Vec<PortSummary>,
    /// Labels.
    pub labels: BTreeMap<String, String>,
    /// Docker container state (`created`, `running`, `exited`, `dead`, …).
    pub state: String,
    /// Human-readable status (`Up 3 minutes`, `Exited (0) 2 minutes ago`).
    pub status: String,
    /// Host config subset Docker's CLI reads.
    pub host_config: SummaryHostConfig,
    /// Network attachments.
    pub network_settings: SummaryNetworkSettings,
    /// Mounts.
    pub mounts: Vec<MountPoint>,
    /// Resolved image platform, `os/arch` — **SatL extension**.
    pub platform: Option<String>,
}

/// `Ports` entry of a container summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PortSummary {
    /// Host address the port is bound on.
    #[serde(rename = "IP", skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Port inside the container.
    pub private_port: u16,
    /// Port on the host, absent when unpublished.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    /// `tcp` or `udp`.
    #[serde(rename = "Type")]
    pub kind: String,
}

/// `HostConfig` subset of a container summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SummaryHostConfig {
    /// Network mode.
    pub network_mode: String,
}

/// `NetworkSettings` subset of a container summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SummaryNetworkSettings {
    /// Network name → endpoint.
    pub networks: BTreeMap<String, EndpointSettings>,
}

/// One network attachment of a container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EndpointSettings {
    /// Network ID.
    #[serde(rename = "NetworkID")]
    pub network_id: String,
    /// Address on the network.
    #[serde(rename = "IPAddress")]
    pub ip_address: String,
    /// Prefix length of the network's subnet.
    #[serde(rename = "IPPrefixLen")]
    pub ip_prefix_len: u8,
    /// Gateway address.
    pub gateway: String,
    /// MAC address of the container-side interface.
    pub mac_address: String,
}

/// One `Mounts` entry (summary and inspect share this shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MountPoint {
    /// `bind`, `volume` or `tmpfs`.
    #[serde(rename = "Type")]
    pub kind: String,
    /// Volume name, for `volume` mounts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Host path (bind) or dataset mountpoint (volume).
    pub source: String,
    /// Path inside the container.
    pub destination: String,
    /// Mount mode as written by the client.
    pub mode: String,
    /// Whether the mount is writable.
    #[serde(rename = "RW")]
    pub rw: bool,
    /// Mount propagation — always empty on FreeBSD (nullfs has none).
    pub propagation: String,
}

/// `GET /containers/{id}/json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerInspectResponse {
    /// Container ID.
    pub id: String,
    /// Creation time, RFC 3339 nanoseconds.
    pub created: String,
    /// Resolved entrypoint binary.
    pub path: String,
    /// Arguments to `Path`.
    pub args: Vec<String>,
    /// Runtime state.
    pub state: ContainerStateResponse,
    /// Image ID the container runs.
    pub image: String,
    /// Name, with Docker's leading `/`.
    pub name: String,
    /// Restart count.
    pub restart_count: u64,
    /// Storage driver — always `zfs`.
    pub driver: String,
    /// Resolved platform, `os/arch` — **SatL extension** (Docker sends
    /// `Platform` as a bare OS string).
    pub platform: String,
    /// Jail ID — **SatL extension**.
    #[serde(rename = "JailID", skip_serializing_if = "Option::is_none")]
    pub jail_id: Option<String>,
    /// Host configuration.
    pub host_config: InspectHostConfig,
    /// Container configuration.
    pub config: InspectConfig,
    /// Addresses and published ports.
    pub network_settings: InspectNetworkSettings,
    /// Mounts.
    pub mounts: Vec<MountPoint>,
}

/// `State` section of a container inspect document.
// Docker's container state document is a bag of independent flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerStateResponse {
    /// Docker state name.
    pub status: String,
    /// Whether the container is running.
    pub running: bool,
    /// Always false — jails are not paused in v1.
    pub paused: bool,
    /// Whether a restart is in flight.
    pub restarting: bool,
    /// Always false — FreeBSD has no OOM killer flag of this kind.
    #[serde(rename = "OOMKilled")]
    pub oom_killed: bool,
    /// Whether the container is in the `dead` state.
    pub dead: bool,
    /// PID of the main process, 0 when not running.
    pub pid: i64,
    /// Exit code, 0 while running.
    pub exit_code: i64,
    /// Failure detail, empty when healthy.
    pub error: String,
    /// Start time, RFC 3339 nanoseconds (Go's zero time when never started).
    pub started_at: String,
    /// Exit time, RFC 3339 nanoseconds (Go's zero time when still running).
    pub finished_at: String,
    /// Healthcheck state, absent when the task has no healthcheck or does not
    /// run on the node answering (health is node-local — `docs/api-compat.md`
    /// #87).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<ContainerHealthResponse>,
}

/// `State.Health` of a container inspect document (Docker's `Health`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerHealthResponse {
    /// `starting`, `healthy` or `unhealthy`.
    pub status: String,
    /// Consecutive probe failures so far.
    pub failing_streak: u32,
    /// The last few probe results, oldest first.
    pub log: Vec<HealthLogEntryResponse>,
}

/// One `State.Health.Log` entry (Docker's `HealthcheckResult`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HealthLogEntryResponse {
    /// When the probe started, RFC 3339 nanoseconds.
    pub start: String,
    /// When it finished, RFC 3339 nanoseconds.
    pub end: String,
    /// The probe's exit code; `-1` when it could not be run or timed out.
    pub exit_code: i32,
    /// Up to 4096 bytes of the probe's output.
    pub output: String,
}

/// `Config` section of a container inspect document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InspectConfig {
    /// Hostname inside the jail.
    pub hostname: String,
    /// User the entrypoint runs as.
    pub user: String,
    /// Whether stdin is kept open.
    pub open_stdin: bool,
    /// Whether a TTY was requested.
    pub tty: bool,
    /// Declared ports (`{"80/tcp": {}}`).
    pub exposed_ports: BTreeMap<String, serde_json::Value>,
    /// Environment.
    pub env: Vec<String>,
    /// Command arguments.
    pub cmd: Option<Vec<String>>,
    /// Entrypoint.
    pub entrypoint: Option<Vec<String>>,
    /// Image reference.
    pub image: String,
    /// Working directory.
    pub working_dir: String,
    /// Labels.
    pub labels: BTreeMap<String, String>,
}

/// `HostConfig` section of a container inspect document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InspectHostConfig {
    /// Binds as written by the client.
    pub binds: Vec<String>,
    /// tmpfs mounts.
    pub tmpfs: BTreeMap<String, String>,
    /// Host port bindings.
    pub port_bindings: BTreeMap<String, Vec<PortBindingBody>>,
    /// Restart policy.
    pub restart_policy: RestartPolicyResponse,
    /// Remove on exit.
    pub auto_remove: bool,
    /// Network mode.
    pub network_mode: String,
    /// Memory limit in bytes.
    pub memory: i64,
    /// CPU limit in billionths of a core.
    pub nano_cpus: i64,
}

/// `RestartPolicy` as served back by inspect.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RestartPolicyResponse {
    /// Policy name.
    pub name: String,
    /// Attempt cap.
    pub maximum_retry_count: u64,
}

/// `NetworkSettings` section of a container inspect document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InspectNetworkSettings {
    /// Bridge name — empty (SatL names its bridge per network).
    pub bridge: String,
    /// Published ports; `null` when nothing is published.
    pub ports: Option<BTreeMap<String, Option<Vec<PortBindingBody>>>>,
    /// Address of the container.
    #[serde(rename = "IPAddress")]
    pub ip_address: String,
    /// Prefix length of the network's subnet.
    #[serde(rename = "IPPrefixLen")]
    pub ip_prefix_len: u8,
    /// Gateway address.
    pub gateway: String,
    /// MAC address of the container-side epair.
    pub mac_address: String,
    /// Network name → endpoint.
    pub networks: BTreeMap<String, EndpointSettings>,
}

/// `POST /containers/{id}/wait` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WaitResponse {
    /// Exit code of the container's main process.
    pub status_code: i64,
    /// Wait error, `null` on success.
    pub error: Option<WaitError>,
}

/// `Error` member of a [`WaitResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WaitError {
    /// Failure detail.
    pub message: String,
}

/// One entry of `GET /images/json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageSummaryResponse {
    /// Image ID (`sha256:…`).
    pub id: String,
    /// Parent image ID.
    pub parent_id: String,
    /// `repository:tag` strings.
    pub repo_tags: Vec<String>,
    /// `repository@digest` strings.
    pub repo_digests: Vec<String>,
    /// Creation time, unix seconds.
    pub created: i64,
    /// On-disk size in bytes.
    pub size: i64,
    /// Bytes shared with other images.
    pub shared_size: i64,
    /// Deprecated alias of `Size`, kept for older clients.
    pub virtual_size: i64,
    /// Labels; `null` when the image has none (Docker's shape).
    pub labels: Option<BTreeMap<String, String>>,
    /// Containers using this image, `-1` when not counted.
    pub containers: i64,
    /// Image platform, `os/arch` — **SatL extension**.
    pub platform: Option<String>,
}

/// One line of a `POST /images/create` progress stream (Docker's
/// `JSONMessage`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsonMessage {
    /// Human-readable status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Layer/blob the line is about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Byte counters.
    #[serde(rename = "progressDetail", skip_serializing_if = "Option::is_none")]
    pub progress_detail: Option<JsonProgressDetail>,
    /// Pre-rendered progress bar.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<String>,
    /// Fatal error message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Structured form of `error`.
    #[serde(rename = "errorDetail", skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<JsonErrorDetail>,
}

/// `progressDetail` of a [`JsonMessage`].
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct JsonProgressDetail {
    /// Bytes transferred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<u64>,
    /// Total bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

/// `errorDetail` of a [`JsonMessage`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsonErrorDetail {
    /// Failure detail.
    pub message: String,
}

/// `POST /containers/{id}/exec` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCreateResponse {
    /// Exec instance ID.
    pub id: String,
}

/// `GET /exec/{id}/json`.
// Mirrors Docker's ExecInspect, which is likewise flag-heavy.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecInspectResponse {
    /// Exec instance ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// Container the exec belongs to.
    #[serde(rename = "ContainerID")]
    pub container_id: String,
    /// Whether the process is still running.
    pub running: bool,
    /// Exit code, 0 while running.
    pub exit_code: i64,
    /// PID inside the jail, 0 when unknown.
    pub pid: i64,
    /// Whether stdin was attached.
    pub open_stdin: bool,
    /// Whether stdout was attached.
    pub open_stdout: bool,
    /// Whether stderr was attached.
    pub open_stderr: bool,
    /// Whether the instance can be removed (always true).
    pub can_remove: bool,
    /// Detach key sequence — always empty.
    pub detach_keys: String,
    /// The process being run.
    pub process_config: ProcessConfig,
}

/// `ProcessConfig` of an exec inspect document (lower-case keys, as Docker
/// serializes them).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    /// Whether a TTY was requested.
    pub tty: bool,
    /// The command.
    pub entrypoint: String,
    /// Its arguments.
    pub arguments: Vec<String>,
    /// Whether the exec is privileged (always false).
    pub privileged: bool,
    /// User the process runs as.
    pub user: String,
}

/// One volume, as served by create/inspect and inside a volume list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumeResponse {
    /// Volume name.
    pub name: String,
    /// Driver name.
    pub driver: String,
    /// Host mountpoint.
    pub mountpoint: String,
    /// Creation time, RFC 3339 nanoseconds.
    pub created_at: String,
    /// Driver status — always empty for the ZFS local driver.
    pub status: BTreeMap<String, serde_json::Value>,
    /// Labels.
    pub labels: BTreeMap<String, String>,
    /// Always `local` — volumes are node-local in v1.
    pub scope: String,
    /// Driver options.
    pub options: BTreeMap<String, String>,
}

/// Docker's `NetworkResource` (`GET /networks`, `GET /networks/{id}`,
/// `POST /networks/create`'s inspect-shaped siblings).
// Docker's flags one-for-one; folding them into enums would break the shape.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NetworkResponse {
    /// Network name.
    pub name: String,
    /// Network ID.
    #[serde(rename = "Id")]
    pub id: String,
    /// Creation time, RFC 3339 nanoseconds.
    pub created: String,
    /// `swarm` for overlay networks, `local` for node-local bridges.
    pub scope: String,
    /// Driver name (`bridge`, `overlay`).
    pub driver: String,
    /// Always false — SatL is IPv4-only in v1.
    #[serde(rename = "EnableIPv6")]
    pub enable_ipv6: bool,
    /// Addressing.
    #[serde(rename = "IPAM")]
    pub ipam: IpamWire,
    /// Always false — rejected at create time.
    pub internal: bool,
    /// Always false — rejected at create time.
    pub attachable: bool,
    /// Whether this is the routing-mesh ingress network.
    pub ingress: bool,
    /// Always empty — `ConfigFrom` is rejected at create time.
    pub config_from: NetworkConfigFromWire,
    /// Always false — `ConfigOnly` is rejected at create time.
    pub config_only: bool,
    /// Attached containers (= tasks), keyed by ID. Populated on inspect only.
    pub containers: BTreeMap<String, NetworkContainerWire>,
    /// Driver options: `{"encrypted": "true"}` on an encrypted overlay
    /// network, empty otherwise (Docker's inspect shape).
    pub options: BTreeMap<String, String>,
    /// Labels.
    pub labels: BTreeMap<String, String>,
    /// SatL extension: the VXLAN network identifier the allocator assigned
    /// (overlay networks only). Operator-visible because every vxlan(4)
    /// diagnostic on the box is keyed by it.
    #[serde(rename = "Vni", skip_serializing_if = "Option::is_none")]
    pub vni: Option<u32>,
}

/// `IPAM` of a network document, and the `IPAM` member of a create body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct IpamWire {
    /// IPAM driver; SatL has one, `default`.
    pub driver: String,
    /// IPAM driver options (rejected when non-empty).
    #[serde(deserialize_with = "null_as_default")]
    pub options: BTreeMap<String, String>,
    /// Subnet configuration; SatL supports at most one entry.
    #[serde(deserialize_with = "null_as_default")]
    pub config: Vec<IpamConfigWire>,
}

/// One entry of `IPAM.Config`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct IpamConfigWire {
    /// Subnet in CIDR form.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subnet: String,
    /// Sub-range addresses are allocated from.
    #[serde(rename = "IPRange", skip_serializing_if = "String::is_empty")]
    pub ip_range: String,
    /// Gateway address. On an overlay this is **this node's** gateway, not a
    /// cluster-wide one (`docs/api-compat.md`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub gateway: String,
}

/// `ConfigFrom` of a network document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NetworkConfigFromWire {
    /// Name of the network the configuration comes from.
    pub network: String,
}

/// One entry of a network document's `Containers` map.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NetworkContainerWire {
    /// Container (= task) name.
    pub name: String,
    /// Endpoint ID. SatL has no separate endpoint object, so this is the task
    /// ID — the same value as the map key.
    #[serde(rename = "EndpointID")]
    pub endpoint_id: String,
    /// MAC address, derived from the IPv4 address.
    pub mac_address: String,
    /// Address in CIDR form.
    #[serde(rename = "IPv4Address")]
    pub ipv4_address: String,
    /// Always empty — no IPv6.
    #[serde(rename = "IPv6Address")]
    pub ipv6_address: String,
}

/// `POST /networks/create` response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkCreateResponse {
    /// The new network's ID.
    #[serde(rename = "Id")]
    pub id: String,
    /// Non-fatal note; empty when there is none.
    pub warning: String,
}

/// `GET /volumes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumeListResponse {
    /// The volumes.
    pub volumes: Vec<VolumeResponse>,
    /// Daemon warnings.
    pub warnings: Vec<String>,
}

/// `POST /containers/prune` response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainersPruneResponse {
    /// IDs of the containers removed.
    pub containers_deleted: Vec<String>,
    /// Bytes freed.
    pub space_reclaimed: u64,
}

/// One entry of `ImagesDeleted`. Exactly one field is ever set, which is
/// Docker's shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageDeleteResponseItem {
    /// A reference that stopped pointing at an image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub untagged: Option<String>,
    /// Content that was deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<String>,
}

/// `POST /images/prune` response.
///
/// `Deferred` is SatL's addition (api-compat 131): layer chains that looked
/// unreferenced on this pass but had not on the previous one, so nothing was
/// done to them. Docker has no equivalent because it has no two-pass rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImagesPruneResponse {
    /// What was untagged and what was deleted.
    pub images_deleted: Vec<ImageDeleteResponseItem>,
    /// Bytes freed.
    pub space_reclaimed: u64,
    /// Layer chains awaiting a second agreeing pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deferred: Vec<String>,
}

/// `POST /networks/prune` response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworksPruneResponse {
    /// Names of the networks removed.
    pub networks_deleted: Vec<String>,
}

/// `POST /volumes/prune` response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumesPruneResponse {
    /// Names of the volumes removed.
    pub volumes_deleted: Vec<String>,
    /// Bytes freed.
    pub space_reclaimed: u64,
}

/// One `GET /events` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventResponse {
    /// Object kind (`container`, `image`, `volume`, `network`).
    #[serde(rename = "Type")]
    pub kind: String,
    /// What happened.
    pub action: String,
    /// Who it happened to.
    pub actor: EventActorResponse,
    /// `local` or `swarm`.
    #[serde(rename = "scope")]
    pub scope: String,
    /// Event time, unix seconds.
    #[serde(rename = "time")]
    pub time: i64,
    /// Event time, unix nanoseconds.
    #[serde(rename = "timeNano")]
    pub time_nano: i64,
}

/// `Actor` of an [`EventResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventActorResponse {
    /// Object ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// Free-form attributes.
    pub attributes: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// M2 — cluster wire types
// ---------------------------------------------------------------------------
//
// Docker's Go types are shared between requests and responses (every field
// `omitempty`), so the types below are too: `#[serde(default)]` makes them
// permissive to parse, `skip_serializing_if` keeps rendered documents free of
// the members SatL never fills. Durations are Go `time.Duration`s — plain
// **nanosecond** integers on the wire.

/// Object version envelope (`{"Index": 42}`), Docker's optimistic-concurrency
/// token.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ObjectVersionWire {
    /// Store version of the object.
    pub index: u64,
}

/// `POST /swarm/init` body.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SwarmInitBody {
    /// Address the control plane binds (`0.0.0.0:2377`).
    pub listen_addr: String,
    /// Address other nodes dial.
    pub advertise_addr: String,
    /// Address the data plane (VXLAN) binds; accepted, unused in M2.
    pub data_path_addr: String,
    /// UDP port of the data plane; rejected when it is not SatL's.
    pub data_path_port: u32,
    /// Keep the store, discard the Raft membership.
    pub force_new_cluster: bool,
    /// Lock the manager keys behind an unlock key (`--autolock`).
    pub auto_lock_managers: bool,
    /// Initial availability of this node.
    pub availability: String,
    /// Address pools overlay subnets are carved from.
    pub default_addr_pool: Vec<String>,
    /// Prefix length of subnets carved from the pools.
    pub subnet_size: u32,
    /// Initial cluster spec; accepted, ignored (SatL applies its defaults).
    pub spec: Option<serde_json::Value>,
}

/// `POST /swarm/join` body.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SwarmJoinBody {
    /// Address the control plane binds.
    pub listen_addr: String,
    /// Address other nodes dial.
    pub advertise_addr: String,
    /// Address the data plane binds; accepted, unused in M2.
    pub data_path_addr: String,
    /// Manager endpoints to try, in order.
    pub remote_addrs: Vec<String>,
    /// The token that decides the joining role.
    pub join_token: String,
    /// Initial availability of this node.
    pub availability: String,
}

/// `POST /swarm/update` body: the full cluster spec, as Docker's clients
/// read-modify-write it. SatL accepts it and applies only the token rotations
/// requested in the query string.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SwarmSpecBody {
    /// Cluster name (always `default` in SatL).
    pub name: String,
    /// Cluster labels.
    pub labels: BTreeMap<String, String>,
    /// Manager-key locking (`AutoLockManagers`).
    pub encryption_config: Option<EncryptionConfigWire>,
    /// CA settings; a `ForceRotate` greater than the stored value starts a
    /// root CA rotation.
    #[serde(rename = "CAConfig")]
    pub ca_config: Option<CaConfigWire>,
}

/// `EncryptionConfig` of a cluster spec.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct EncryptionConfigWire {
    /// Whether manager keys are locked at rest.
    pub auto_lock_managers: bool,
}

/// `POST /swarm/unlock` body — the only call a locked manager answers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct UnlockKeyBody {
    /// The base64 unlock key.
    pub unlock_key: String,
}

/// `GET /swarm/unlockkey` response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct UnlockKeyResponse {
    /// The current unlock key, base64; empty while autolock is off.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub unlock_key: String,
}

/// `GET /swarm` — Docker's `Swarm` document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SwarmResponse {
    /// Cluster object ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// Store version.
    pub version: ObjectVersionWire,
    /// Creation time, RFC 3339 nanoseconds.
    pub created_at: String,
    /// Last update time, RFC 3339 nanoseconds.
    pub updated_at: String,
    /// Cluster settings.
    pub spec: SwarmSpecWire,
    /// Root CA material.
    #[serde(rename = "TLSInfo")]
    pub tls_info: TlsInfoWire,
    /// Whether a root CA rotation is in flight (always false in M2).
    pub root_rotation_in_progress: bool,
    /// Address pools overlay subnets are carved from.
    pub default_addr_pool: Vec<String>,
    /// Prefix length of subnets carved from the pools.
    pub subnet_size: u32,
    /// UDP port of the VXLAN data plane.
    pub data_path_port: u32,
    /// The two join tokens.
    pub join_tokens: JoinTokensWire,
}

/// `Spec` of a [`SwarmResponse`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SwarmSpecWire {
    /// Cluster name.
    pub name: String,
    /// Cluster labels.
    pub labels: BTreeMap<String, String>,
    /// Task history retention (SatL keeps SwarmKit's default).
    pub orchestration: OrchestrationConfigWire,
    /// Raft tuning.
    pub raft: RaftConfigWire,
    /// Dispatcher tuning.
    pub dispatcher: DispatcherConfigWire,
    /// Certificate authority tuning.
    #[serde(rename = "CAConfig")]
    pub ca_config: CaConfigWire,
    /// Defaults stamped into task specs (empty in v1).
    pub task_defaults: TaskDefaultsWire,
    /// Manager-key locking (always off).
    pub encryption_config: EncryptionConfigWire,
}

/// `Orchestration` of a cluster spec.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct OrchestrationConfigWire {
    /// Terminated tasks kept per slot.
    pub task_history_retention_limit: i64,
}

/// `Raft` of a cluster spec.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RaftConfigWire {
    /// Snapshot every this many applied entries.
    pub snapshot_interval: u64,
    /// Log entries kept for slow followers.
    pub log_entries_for_slow_followers: u64,
    /// Election timeout in ticks.
    pub election_tick: u32,
    /// Heartbeat interval in ticks.
    pub heartbeat_tick: u32,
}

/// `Dispatcher` of a cluster spec.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct DispatcherConfigWire {
    /// Heartbeat period dictated to agents, in nanoseconds.
    pub heartbeat_period: i64,
}

/// `CAConfig` of a cluster spec.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct CaConfigWire {
    /// Validity of issued node certificates, in nanoseconds.
    pub node_cert_expiry: i64,
    /// Root-rotation counter: a `POST /swarm/update` carrying a value
    /// greater than the stored one starts a root CA rotation (docker's
    /// `docker swarm ca --rotate` semantics).
    pub force_rotate: u64,
}

/// `TaskDefaults` of a cluster spec — empty in v1 (SwarmKit's only member is
/// the default log driver, which lands with the log broker).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TaskDefaultsWire {}

/// Root CA material. SatL fills `TrustRoot` only — the issuer members are
/// DER blobs SatL has no use for (deviation in `docs/api-compat.md`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TlsInfoWire {
    /// Root CA certificate, PEM-encoded.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub trust_root: String,
}

/// The two join tokens.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct JoinTokensWire {
    /// Token that joins a node as a worker.
    pub worker: String,
    /// Token that joins a node as a manager.
    pub manager: String,
}

// ---------------------------------------------------------------------------
// M2 — nodes
// ---------------------------------------------------------------------------

/// Docker's `Node` document (`GET /nodes`, `GET /nodes/{id}`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NodeResponse {
    /// Node ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// Store version.
    pub version: ObjectVersionWire,
    /// Creation time, RFC 3339 nanoseconds.
    pub created_at: String,
    /// Last update time, RFC 3339 nanoseconds.
    pub updated_at: String,
    /// Operator intent.
    pub spec: NodeSpecWire,
    /// Self-reported facts.
    pub description: NodeDescriptionWire,
    /// Observed liveness.
    pub status: NodeStatusWire,
    /// Raft-member status; `null` on workers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager_status: Option<ManagerStatusWire>,
}

/// `Spec` of a node — also the `POST /nodes/{id}/update` body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NodeSpecWire {
    /// Operator-assigned name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Operator-assigned labels.
    pub labels: BTreeMap<String, String>,
    /// `worker` or `manager`.
    pub role: String,
    /// `active`, `pause` or `drain`.
    pub availability: String,
}

/// `Description` of a node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NodeDescriptionWire {
    /// Kernel hostname.
    pub hostname: String,
    /// Native platform.
    pub platform: PlatformWire,
    /// Schedulable capacity.
    pub resources: ResourcesWire,
    /// Engine version and labels.
    pub engine: EngineDescriptionWire,
}

/// An `os/arch` pair, in Docker's spelling.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct PlatformWire {
    /// CPU architecture (`amd64`, `arm64`).
    pub architecture: String,
    /// Operating system (`freebsd`, `linux`).
    #[serde(rename = "OS")]
    pub os: String,
}

/// Compute/memory quantities (node capacity, task limits and reservations).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ResourcesWire {
    /// CPU in billionths of a core.
    #[serde(rename = "NanoCPUs")]
    pub nano_cpus: i64,
    /// Memory in bytes.
    pub memory_bytes: i64,
}

/// `Engine` of a node description.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct EngineDescriptionWire {
    /// `satld` version.
    pub engine_version: String,
    /// Engine labels from the node's config file.
    pub labels: BTreeMap<String, String>,
    /// Engine plugins — always empty (SatL has no plugin system).
    pub plugins: Vec<serde_json::Value>,
}

/// `Status` of a node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NodeStatusWire {
    /// `unknown`, `down`, `ready` or `disconnected`.
    pub state: String,
    /// Human-readable note on the state.
    pub message: String,
    /// The node's advertised address.
    pub addr: String,
}

/// `ManagerStatus` of a manager node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ManagerStatusWire {
    /// Whether this member currently leads.
    pub leader: bool,
    /// `unknown`, `unreachable` or `reachable`.
    pub reachability: String,
    /// Address the Raft transport dials.
    pub addr: String,
}

// ---------------------------------------------------------------------------
// M2 — services
// ---------------------------------------------------------------------------

/// Docker's `Service` document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ServiceResponse {
    /// Service ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// Store version.
    pub version: ObjectVersionWire,
    /// Creation time, RFC 3339 nanoseconds.
    pub created_at: String,
    /// Last update time, RFC 3339 nanoseconds.
    pub updated_at: String,
    /// Desired state.
    pub spec: ServiceSpecWire,
    /// Spec before the last update, kept for rollback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_spec: Option<ServiceSpecWire>,
    /// Allocated endpoint (published ports).
    pub endpoint: EndpointWire,
    /// Progress of a rolling update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_status: Option<UpdateStatusWire>,
    /// Replica counts; only sent when `?status=` was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_status: Option<ServiceStatusWire>,
}

/// `ServiceStatus`: the numbers behind `satl service ls`' `REPLICAS` column.
// The shared `Tasks` suffix is Docker's wire spelling, not a naming slip.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ServiceStatusWire {
    /// Tasks currently running.
    pub running_tasks: u64,
    /// Tasks the orchestrator wants running.
    pub desired_tasks: u64,
    /// Tasks that ran to completion.
    pub completed_tasks: u64,
}

/// `UpdateStatus` of a service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct UpdateStatusWire {
    /// `updating`, `paused`, `completed`, `rollback_started`, …
    pub state: String,
    /// When the update began, RFC 3339 nanoseconds.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub started_at: String,
    /// When it reached a final state, RFC 3339 nanoseconds.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub completed_at: String,
    /// Human-readable progress note.
    pub message: String,
}

/// `POST /services/create` and `POST /services/{id}/update` body — also the
/// `Spec` of a rendered service.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ServiceSpecWire {
    /// Service name.
    pub name: String,
    /// Service labels.
    pub labels: BTreeMap<String, String>,
    /// Template every task is stamped from.
    pub task_template: TaskTemplateWire,
    /// Replication mode.
    pub mode: ServiceModeWire,
    /// Rolling-update settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_config: Option<UpdateConfigWire>,
    /// Settings used when rolling back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_config: Option<UpdateConfigWire>,
    /// Deprecated service-level networks; folded into the task template.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<NetworkAttachmentConfigWire>,
    /// Resolution mode and published ports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_spec: Option<EndpointSpecWire>,
}

/// `TaskTemplate` of a service spec.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TaskTemplateWire {
    /// What runs inside the jail.
    pub container_spec: ContainerSpecWire,
    /// Limits and reservations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirementsWire>,
    /// Restart policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<TaskRestartPolicyWire>,
    /// Scheduling constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placement: Option<PlacementWire>,
    /// Networks the tasks attach to.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<NetworkAttachmentConfigWire>,
    /// Bump to force a rolling restart without a spec change.
    pub force_update: u64,
    /// Runtime name; only `container` (the default) is accepted.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub runtime: String,
    /// Per-service log driver — rejected (the log broker lands in M4/M5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_driver: Option<serde_json::Value>,
}

/// `ContainerSpec` of a task template.
// Docker's container spec genuinely is a bag of independent flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ContainerSpecWire {
    /// Image reference.
    pub image: String,
    /// Container labels.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Entrypoint override.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    /// Arguments to the entrypoint.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Hostname inside the jail.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    /// Environment, `KEY=VALUE`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Working directory.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub dir: String,
    /// User to run as.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user: String,
    /// Supplementary groups.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Allocate a TTY.
    #[serde(rename = "TTY")]
    pub tty: bool,
    /// Keep stdin open.
    pub open_stdin: bool,
    /// Mount the root filesystem read-only.
    pub read_only: bool,
    /// Filesystem mounts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountWire>,
    /// Signal used to stop the task.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stop_signal: String,
    /// Grace period before `SIGKILL`, in nanoseconds.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub stop_grace_period: i64,
    /// Docker `HEALTHCHECK` semantics.
    #[serde(alias = "HealthCheck", skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<HealthcheckWire>,
    /// Extra `/etc/hosts` entries.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Resolver configuration.
    #[serde(rename = "DNSConfig", skip_serializing_if = "Option::is_none")]
    pub dns_config: Option<DnsConfigWire>,
    /// Secret references, materialized under `/run/secrets` (M5).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretReferenceWire>,
    /// Config references, materialized as files (M5).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub configs: Vec<ConfigReferenceWire>,
    /// Linux privilege block — rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges: Option<serde_json::Value>,
    /// Inject an init process — rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<bool>,
    /// Windows isolation mode — rejected.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub isolation: String,
    /// Per-container sysctls — rejected.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub sysctls: BTreeMap<String, String>,
    /// Linux capabilities to add — rejected.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capability_add: Vec<String>,
    /// Linux capabilities to drop — rejected.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capability_drop: Vec<String>,
    /// Resource ulimits — rejected.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ulimits: Vec<serde_json::Value>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

/// One `Mounts` entry of a container spec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct MountWire {
    /// `bind`, `volume` or `tmpfs`.
    #[serde(rename = "Type")]
    pub kind: String,
    /// Host path (bind) or volume name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    /// Path inside the jail.
    pub target: String,
    /// Mount read-only.
    pub read_only: bool,
    /// Mount consistency — rejected (no FreeBSD equivalent).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub consistency: String,
    /// Bind-specific options — rejected (propagation has no equivalent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_options: Option<serde_json::Value>,
    /// Volume-specific options — rejected in M2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_options: Option<serde_json::Value>,
    /// tmpfs-specific options — rejected in M2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmpfs_options: Option<serde_json::Value>,
}

/// `Healthcheck` of a container spec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct HealthcheckWire {
    /// Probe command (`["CMD", …]` or `["CMD-SHELL", …]`).
    pub test: Vec<String>,
    /// Time between probes, in nanoseconds.
    pub interval: i64,
    /// Per-probe timeout, in nanoseconds.
    pub timeout: i64,
    /// Consecutive failures before the task is unhealthy.
    pub retries: u32,
    /// Startup period during which failures don't count, in nanoseconds.
    pub start_period: i64,
}

/// `DNSConfig` of a container spec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct DnsConfigWire {
    /// Nameserver addresses.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nameservers: Vec<String>,
    /// Search domains.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub search: Vec<String>,
    /// `resolv.conf` options.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

/// `Resources` of a task template.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ResourceRequirementsWire {
    /// Hard caps, enforced via rctl(8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<LimitWire>,
    /// Scheduler-side reservations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservations: Option<ResourcesWire>,
}

/// `Limits` of a task template: [`ResourcesWire`] plus Docker's `Pids` cap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct LimitWire {
    /// CPU in billionths of a core.
    #[serde(rename = "NanoCPUs")]
    pub nano_cpus: i64,
    /// Memory in bytes.
    pub memory_bytes: i64,
    /// Process cap — rejected (no rctl mapping in M2).
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub pids: i64,
}

/// `RestartPolicy` of a task template (nanosecond durations, unlike the
/// container `HostConfig.RestartPolicy`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TaskRestartPolicyWire {
    /// `none`, `on-failure` or `any`.
    pub condition: String,
    /// Delay before a replacement starts, in nanoseconds.
    pub delay: i64,
    /// Maximum attempts; 0 means unlimited.
    pub max_attempts: u64,
    /// Window the attempts are counted over, in nanoseconds.
    pub window: i64,
}

/// `Placement` of a task template.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct PlacementWire {
    /// Constraint expressions.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<String>,
    /// Spread preferences — only `spread` is honoured (M7d); anything else is
    /// a 400 at the conversion layer.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub preferences: Vec<PlacementPreferenceWire>,
    /// Per-node cap on tasks of the same service.
    pub max_replicas: u64,
    /// Platforms the image supports.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<PlatformWire>,
}

/// One `Placement.Preferences` entry. Only `Spread` is honoured.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct PlacementPreferenceWire {
    /// Spread across a descriptor's values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spread: Option<SpreadPreferenceWire>,
}

/// `Spread`: balance the service's tasks across this descriptor's values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SpreadPreferenceWire {
    /// `node.id`, `node.hostname`, `node.labels.<key>` or `engine.labels.<key>`.
    pub spread_descriptor: String,
}

/// One `Networks` entry of a task template.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NetworkAttachmentConfigWire {
    /// Network name or ID.
    pub target: String,
    /// Extra DNS names on that network.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

/// `Mode` of a service spec: exactly one member is set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ServiceModeWire {
    /// A fixed number of replicas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicated: Option<ReplicatedModeWire>,
    /// One task per schedulable node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global: Option<GlobalModeWire>,
    /// Run-to-completion replicas (Docker's `ReplicatedJob`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicated_job: Option<ReplicatedJobModeWire>,
    /// Run-to-completion per eligible node (Docker's `GlobalJob`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_job: Option<GlobalModeWire>,
}

/// `Replicated` of a service mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ReplicatedModeWire {
    /// Desired replica count; `null` means 1 (Docker's default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u64>,
}

/// `ReplicatedJob` of a service mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ReplicatedJobModeWire {
    /// Upper bound on simultaneously live tasks; `null` means 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent: Option<u64>,
    /// How many clean exits finish the job; `null` means 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_completions: Option<u64>,
}

/// `Global` of a service mode — Docker's empty object.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct GlobalModeWire {}

/// `UpdateConfig` / `RollbackConfig` of a service spec.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct UpdateConfigWire {
    /// Slots updated concurrently; 0 means unlimited.
    pub parallelism: u64,
    /// Pause between batches, in nanoseconds.
    pub delay: i64,
    /// `pause`, `continue` or `rollback`.
    pub failure_action: String,
    /// Failure-observation window after a task starts, in nanoseconds.
    pub monitor: i64,
    /// Tolerated fraction of failed tasks.
    pub max_failure_ratio: f32,
    /// `stop-first` or `start-first`.
    pub order: String,
}

/// `EndpointSpec` of a service spec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct EndpointSpecWire {
    /// `vip` (rejected) or `dnsrr`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mode: String,
    /// Ports to publish.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortConfigWire>,
}

/// Allocator-written `Endpoint` of a service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct EndpointWire {
    /// The spec this endpoint was allocated from.
    pub spec: EndpointSpecWire,
    /// Allocated ports.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortConfigWire>,
    /// Virtual IPs — always empty (SatL resolves services via DNS only).
    #[serde(rename = "VirtualIPs", skip_serializing_if = "Vec::is_empty")]
    pub virtual_ips: Vec<serde_json::Value>,
}

/// One published port.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct PortConfigWire {
    /// Optional user-facing name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// `tcp` or `udp`.
    pub protocol: String,
    /// Port the task listens on.
    pub target_port: u32,
    /// Externally published port; 0 asks for an automatic assignment.
    pub published_port: u32,
    /// `ingress` or `host`.
    pub publish_mode: String,
}

/// `POST /services/create` response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceCreateResponse {
    /// The new service ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// Non-fatal notes.
    pub warnings: Option<Vec<String>>,
}

/// `POST /services/{id}/update` response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceUpdateResponse {
    /// Non-fatal notes.
    pub warnings: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// M2 — tasks
// ---------------------------------------------------------------------------

/// Docker's `Task` document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TaskResponse {
    /// Task ID — also the jail name.
    #[serde(rename = "ID")]
    pub id: String,
    /// Store version.
    pub version: ObjectVersionWire,
    /// Creation time, RFC 3339 nanoseconds.
    pub created_at: String,
    /// Last update time, RFC 3339 nanoseconds.
    pub updated_at: String,
    /// Task name, `<service>.<slot>.<task id>`.
    pub name: String,
    /// Task labels.
    pub labels: BTreeMap<String, String>,
    /// The spec snapshot this task runs.
    pub spec: TaskTemplateWire,
    /// Owning service.
    #[serde(rename = "ServiceID")]
    pub service_id: String,
    /// Replica slot, 0 for global tasks.
    pub slot: u64,
    /// The node this task is bound to.
    #[serde(rename = "NodeID")]
    pub node_id: String,
    /// Observed status.
    pub status: TaskStatusWire,
    /// Target state.
    pub desired_state: String,
    /// Allocated network attachments.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub networks_attachments: Vec<NetworkAttachmentWire>,
}

/// `Status` of a task.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TaskStatusWire {
    /// When this status was produced, RFC 3339 nanoseconds.
    pub timestamp: String,
    /// Observed state.
    pub state: String,
    /// Human-readable note on the transition.
    pub message: String,
    /// Failure detail for `failed`/`rejected` tasks.
    #[serde(rename = "Err", skip_serializing_if = "String::is_empty")]
    pub err: String,
    /// Jail-level runtime status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_status: Option<TaskContainerStatusWire>,
    /// Host-level bound ports.
    pub port_status: TaskPortStatusWire,
}

/// `ContainerStatus` of a task status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TaskContainerStatusWire {
    /// The jail name — SatL's equivalent of Docker's container ID.
    #[serde(rename = "ContainerID")]
    pub container_id: String,
    /// PID of the jail's main process.
    #[serde(rename = "PID")]
    pub pid: i64,
    /// Exit code once the task terminated.
    pub exit_code: i64,
}

/// `PortStatus` of a task status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TaskPortStatusWire {
    /// Bound ports.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortConfigWire>,
}

/// One allocated network attachment of a task.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NetworkAttachmentWire {
    /// The attached network.
    pub network: NetworkRefWire,
    /// Addresses allocated on it, in CIDR form.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
}

/// The `Network` member of a task's attachment — SatL fills the ID only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NetworkRefWire {
    /// Network ID.
    #[serde(rename = "ID")]
    pub id: String,
}

// ---------------------------------------------------------------------------
// M5 — secrets / configs
// ---------------------------------------------------------------------------
//
// Same conventions as the M2 cluster types above: one shape per Docker Go
// type, permissive to parse (`#[serde(default)]`), free of empty members when
// rendered (`skip_serializing_if`). Payloads travel base64-encoded in `Data`,
// exactly as Docker's `SecretSpec`/`ConfigSpec` carry them.
//
// `Data` is an `Option<String>` rather than a `String` because the two states
// are different requests: a create with no `Data` at all is a client error
// (there is nothing to store), while a *rendered* secret deliberately carries
// no `Data` key at all — a secret payload never leaves the store through the
// API (invariant #7).

/// `SecretSpec`: the document `POST /secrets/create` takes and every secret
/// response echoes back — minus `Data`, which is never rendered.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SecretSpecWire {
    /// Secret name (unique across the cluster).
    pub name: String,
    /// Free-form labels.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Base64-encoded payload. Required on create, never rendered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// External secret driver — rejected (no driver plugins).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<serde_json::Value>,
    /// Templating driver — rejected (no template engine).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub templating: Option<serde_json::Value>,
}

/// `ConfigSpec`: like [`SecretSpecWire`] without `Driver` — Docker's config
/// object has `Templating` but no driver plugins.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ConfigSpecWire {
    /// Config name (unique across the cluster).
    pub name: String,
    /// Free-form labels.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Base64-encoded payload. Required on create, rendered back on read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Templating driver — rejected (no template engine).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub templating: Option<serde_json::Value>,
}

/// Docker's `Secret` document (`GET /secrets`, `GET /secrets/{id}`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SecretResponse {
    /// Secret ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// Store version.
    pub version: ObjectVersionWire,
    /// Creation time, RFC 3339 nanoseconds.
    pub created_at: String,
    /// Last update time, RFC 3339 nanoseconds.
    pub updated_at: String,
    /// The spec, always without its payload.
    pub spec: SecretSpecWire,
}

/// Docker's `Config` document (`GET /configs`, `GET /configs/{id}`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ConfigResponse {
    /// Config ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// Store version.
    pub version: ObjectVersionWire,
    /// Creation time, RFC 3339 nanoseconds.
    pub created_at: String,
    /// Last update time, RFC 3339 nanoseconds.
    pub updated_at: String,
    /// The spec, payload included (a config is not a secret).
    pub spec: ConfigSpecWire,
}

/// Docker's `IDResponse`: the answer to `POST /secrets/create` and `POST
/// /configs/create`. Spelled `ID`, like [`ServiceCreateResponse`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct IdResponse {
    /// The new object's ID.
    #[serde(rename = "ID")]
    pub id: String,
}

/// One `Secrets` entry of a container spec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SecretReferenceWire {
    /// Where and how the payload is materialized. Docker's CLI omits it on
    /// the short `--secret name` form; the converter then defaults it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileTargetWire>,
    /// ID of the referenced secret; may be empty, in which case the daemon
    /// resolves `SecretName`.
    #[serde(rename = "SecretID")]
    pub secret_id: String,
    /// Name of the referenced secret.
    pub secret_name: String,
}

/// One `Configs` entry of a container spec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ConfigReferenceWire {
    /// Where and how the payload is materialized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileTargetWire>,
    /// ID of the referenced config; may be empty, in which case the daemon
    /// resolves `ConfigName`.
    #[serde(rename = "ConfigID")]
    pub config_id: String,
    /// Name of the referenced config.
    pub config_name: String,
}

/// `File` of a secret/config reference.
///
/// `Mode` is a Go `os.FileMode`, i.e. a **decimal** integer on the wire: the
/// default `0o444` is sent and rendered as `292`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct FileTargetWire {
    /// File name, relative for a secret (under `/run/secrets`), absolute or
    /// relative for a config.
    pub name: String,
    /// Owning user, numeric.
    #[serde(rename = "UID")]
    pub uid: String,
    /// Owning group, numeric.
    #[serde(rename = "GID")]
    pub gid: String,
    /// Permission bits (decimal on the wire).
    pub mode: u32,
}

/// Docker's own defaults for an omitted `File`: `root:root`, mode `0444`
/// (`cli/command/service/opts.go`).
impl Default for FileTargetWire {
    fn default() -> Self {
        Self {
            name: String::new(),
            uid: "0".to_owned(),
            gid: "0".to_owned(),
            mode: DEFAULT_FILE_MODE,
        }
    }
}

/// Mode a file target gets when the client sends none: `0o444`, i.e. `292`.
pub const DEFAULT_FILE_MODE: u32 = 0o444;
