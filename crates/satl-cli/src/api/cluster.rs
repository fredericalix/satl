// SPDX-License-Identifier: BSD-2-Clause
//! Wire types for the cluster endpoints (`/swarm`, `/nodes`, `/services`,
//! `/tasks`).
//!
//! Same conventions as the parent module: deserialization is lenient (missing
//! fields and explicit `null`s become defaults, unknown fields are ignored) so
//! a newer daemon never breaks `satl`, and serialization skips empties so the
//! request-body goldens stay close to what the docker CLI sends.
//!
//! [`ServiceSpec`] is used in **both** directions: `satl service update` and
//! `satl service scale` read the current spec, change one field and send the
//! whole document back, exactly as `docker service update` does.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::null_as_default;

/// Object version envelope (`{"Index": 42}`) — the optimistic-concurrency
/// token every cluster update must echo back in `?version=`.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ObjectVersion {
    /// Store version of the object.
    #[serde(default, deserialize_with = "null_as_default")]
    pub index: u64,
}

// ---------------------------------------------------------------------------
// /info and /swarm
// ---------------------------------------------------------------------------

/// `GET /info`, as the CLI reads it.
///
/// Grown additively, one field at a time, as verbs needed them: the cluster
/// verbs read `Swarm` and `ServerVersion`, `satl system prune` reads `Name`,
/// and `satl info` reads the rest. Every field defaults, so a daemon that
/// serves fewer of them still parses.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SystemInfo {
    /// Cluster membership of this node.
    #[serde(default, deserialize_with = "null_as_default")]
    pub swarm: SwarmInfo,
    /// Daemon version, used as the local node's `ENGINE VERSION`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub server_version: String,
    /// Unique daemon identifier.
    #[serde(default, deserialize_with = "null_as_default", rename = "ID")]
    pub id: String,
    /// The node's hostname -- what every node-local statement names.
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    /// Logical CPUs.
    #[serde(default, deserialize_with = "null_as_default", rename = "NCPU")]
    pub ncpu: i64,
    /// Physical memory, bytes.
    #[serde(default, deserialize_with = "null_as_default")]
    pub mem_total: i64,
    /// Operating system family (`FreeBSD`).
    #[serde(default, deserialize_with = "null_as_default")]
    pub operating_system: String,
    /// Operating system release (`15.1-RELEASE`).
    #[serde(default, deserialize_with = "null_as_default", rename = "OSVersion")]
    pub os_version: String,
    /// Docker's `OSType` (`freebsd`).
    #[serde(default, deserialize_with = "null_as_default", rename = "OSType")]
    pub os_type: String,
    /// CPU architecture, Docker-style.
    #[serde(default, deserialize_with = "null_as_default")]
    pub architecture: String,
    /// Storage driver -- always `zfs` (invariant #5).
    #[serde(default, deserialize_with = "null_as_default")]
    pub driver: String,
    /// Total containers on this node.
    #[serde(default, deserialize_with = "null_as_default")]
    pub containers: i64,
    /// Running containers.
    #[serde(default, deserialize_with = "null_as_default")]
    pub containers_running: i64,
    /// Paused containers.
    #[serde(default, deserialize_with = "null_as_default")]
    pub containers_paused: i64,
    /// Stopped containers.
    #[serde(default, deserialize_with = "null_as_default")]
    pub containers_stopped: i64,
    /// Images in this node's store.
    #[serde(default, deserialize_with = "null_as_default")]
    pub images: i64,
    /// Daemon warnings meant for the operator.
    #[serde(default, deserialize_with = "null_as_default")]
    pub warnings: Vec<String>,
}

/// `Swarm` section of `GET /info`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SwarmInfo {
    /// This node's ID; empty when it is not a member.
    #[serde(default, deserialize_with = "null_as_default", rename = "NodeID")]
    pub node_id: String,
    /// The address this node advertises.
    #[serde(default, deserialize_with = "null_as_default")]
    pub node_addr: String,
    /// `inactive`, `pending`, `active`, `error` or `locked`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub local_node_state: String,
    /// Whether this node runs the control plane.
    #[serde(default, deserialize_with = "null_as_default")]
    pub control_available: bool,
    /// Total cluster members; only a manager serves it — a worker reports
    /// zero because it genuinely does not know (`SwarmInfoResponse.Nodes`).
    #[serde(default, deserialize_with = "null_as_default")]
    pub nodes: i64,
    /// Manager members; manager-only, zero on a worker, same reason.
    #[serde(default, deserialize_with = "null_as_default")]
    pub managers: i64,
    /// Cluster error string, empty when healthy.
    #[serde(default, deserialize_with = "null_as_default")]
    pub error: String,
    /// Known manager endpoints; the daemon sends `null` when none are known.
    #[serde(default, deserialize_with = "null_as_default")]
    pub remote_managers: Vec<RemoteManager>,
}

/// One entry of [`SwarmInfo::remote_managers`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RemoteManager {
    /// Manager node ID.
    #[serde(default, deserialize_with = "null_as_default", rename = "NodeID")]
    pub node_id: String,
    /// The address its control plane answers on.
    #[serde(default, deserialize_with = "null_as_default")]
    pub addr: String,
}

/// `GET /swarm`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Swarm {
    /// Cluster ID.
    #[serde(default, deserialize_with = "null_as_default", rename = "ID")]
    pub id: String,
    /// Store version, echoed back on `POST /swarm/update?version=`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub version: ObjectVersion,
    /// The two join tokens.
    #[serde(default, deserialize_with = "null_as_default")]
    pub join_tokens: JoinTokens,
    /// Cluster spec, resent verbatim when rotating a token, with
    /// `CAConfig.ForceRotate` bumped when rotating the root CA.
    #[serde(default, deserialize_with = "null_as_default")]
    pub spec: serde_json::Value,
    /// Root CA material (`TLSInfo.TrustRoot` is the PEM trust bundle).
    #[serde(default, deserialize_with = "null_as_default", rename = "TLSInfo")]
    pub tls_info: TlsInfo,
    /// Whether a root CA rotation is in flight.
    #[serde(default, deserialize_with = "null_as_default")]
    pub root_rotation_in_progress: bool,
}

/// `TLSInfo` of a swarm document.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TlsInfo {
    /// The root CA bundle, PEM: one certificate, or two while a root
    /// rotation is in flight.
    #[serde(default, deserialize_with = "null_as_default")]
    pub trust_root: String,
}

/// The two join tokens of a cluster.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct JoinTokens {
    /// Token that joins a node as a worker.
    #[serde(default, deserialize_with = "null_as_default")]
    pub worker: String,
    /// Token that joins a node as a manager.
    #[serde(default, deserialize_with = "null_as_default")]
    pub manager: String,
}

/// Body of `POST /swarm/init`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SwarmInitBody {
    /// `--listen-addr`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub listen_addr: String,
    /// `--advertise-addr`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub advertise_addr: String,
    /// `--force-new-cluster`.
    pub force_new_cluster: bool,
    /// `--autolock`.
    #[serde(skip_serializing_if = "is_false")]
    pub auto_lock_managers: bool,
}

/// Body of `POST /swarm/unlock`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct UnlockKeyBody {
    /// The base64 unlock key (`--key`, or one line of stdin).
    pub unlock_key: String,
}

/// Body of `GET /swarm/unlockkey`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct UnlockKeyResponse {
    /// The current unlock key, base64.
    #[serde(default, deserialize_with = "null_as_default")]
    pub unlock_key: String,
}

/// Body of `POST /swarm/join`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SwarmJoinBody {
    /// `--listen-addr`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub listen_addr: String,
    /// `--advertise-addr`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub advertise_addr: String,
    /// The manager addresses to try.
    pub remote_addrs: Vec<String>,
    /// `--token`.
    pub join_token: String,
}

// ---------------------------------------------------------------------------
// /nodes
// ---------------------------------------------------------------------------

/// One entry of `GET /nodes`, and the body of `GET /nodes/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Node {
    /// Node ID.
    #[serde(default, deserialize_with = "null_as_default", rename = "ID")]
    pub id: String,
    /// Store version, echoed back on `POST /nodes/{id}/update?version=`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub version: ObjectVersion,
    /// Operator intent.
    #[serde(default, deserialize_with = "null_as_default")]
    pub spec: NodeSpec,
    /// Self-reported facts.
    #[serde(default, deserialize_with = "null_as_default")]
    pub description: NodeDescription,
    /// Observed liveness.
    #[serde(default, deserialize_with = "null_as_default")]
    pub status: NodeStatus,
    /// Raft-member status; absent on workers.
    #[serde(default, deserialize_with = "null_as_default")]
    pub manager_status: Option<ManagerStatus>,
}

impl Node {
    /// What the `HOSTNAME` column shows: the hostname the node's agent
    /// reported, and nothing else.
    ///
    /// It used to prefer `spec.name` — the operator-assigned label — which is
    /// **not** docker's rule and actively misleads: on the first 3-node
    /// cluster the bootstrap node had a `spec.name` from its configuration
    /// (`node1`) while its peers had none, so a column headed HOSTNAME showed
    /// a config label for one node and real hostnames for the other two.
    /// `docker node ls` renders `Description.Hostname`; `Spec.Name` is a
    /// separate optional field it does not display at all.
    ///
    /// Empty until the node's agent has registered once — a node whose agent
    /// never connected genuinely has no hostname to show.
    pub fn display_name(&self) -> &str {
        &self.description.hostname
    }
}

/// `Spec` of a node — also the body of `POST /nodes/{id}/update`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct NodeSpec {
    /// Operator-assigned name.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub name: String,
    /// Operator-assigned labels.
    #[serde(default, deserialize_with = "null_as_default")]
    pub labels: BTreeMap<String, String>,
    /// `worker` or `manager`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub role: String,
    /// `active`, `pause` or `drain`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub availability: String,
}

/// `Description` of a node.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NodeDescription {
    /// Kernel hostname.
    #[serde(default, deserialize_with = "null_as_default")]
    pub hostname: String,
    /// Native platform.
    #[serde(default, deserialize_with = "null_as_default")]
    pub platform: NodePlatform,
    /// Schedulable capacity.
    #[serde(default, deserialize_with = "null_as_default")]
    pub resources: NodeResources,
    /// Engine version and labels.
    #[serde(default, deserialize_with = "null_as_default")]
    pub engine: NodeEngine,
}

/// `Platform` of a node description.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NodePlatform {
    /// CPU architecture.
    #[serde(default, deserialize_with = "null_as_default")]
    pub architecture: String,
    /// Operating system.
    #[serde(default, deserialize_with = "null_as_default", rename = "OS")]
    pub os: String,
}

/// `Resources` of a node description.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NodeResources {
    /// CPU in billionths of a core.
    #[serde(default, deserialize_with = "null_as_default", rename = "NanoCPUs")]
    pub nano_cpus: i64,
    /// Memory in bytes.
    #[serde(default, deserialize_with = "null_as_default")]
    pub memory_bytes: i64,
}

/// `Engine` of a node description.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NodeEngine {
    /// `satld` version — the `ENGINE VERSION` column.
    #[serde(default, deserialize_with = "null_as_default")]
    pub engine_version: String,
}

/// `Status` of a node.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NodeStatus {
    /// `unknown`, `down`, `ready` or `disconnected`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub state: String,
    /// Human-readable note on the state.
    #[serde(default, deserialize_with = "null_as_default")]
    pub message: String,
    /// The node's advertised address.
    #[serde(default, deserialize_with = "null_as_default")]
    pub addr: String,
}

/// `ManagerStatus` of a manager node.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ManagerStatus {
    /// Whether this member currently leads.
    #[serde(default, deserialize_with = "null_as_default")]
    pub leader: bool,
    /// `unknown`, `unreachable` or `reachable`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub reachability: String,
    /// Address the Raft transport dials.
    #[serde(default, deserialize_with = "null_as_default")]
    pub addr: String,
}

// ---------------------------------------------------------------------------
// /services
// ---------------------------------------------------------------------------

/// One entry of `GET /services`, and the body of `GET /services/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Service {
    /// Service ID.
    #[serde(default, deserialize_with = "null_as_default", rename = "ID")]
    pub id: String,
    /// Store version, echoed back on `POST /services/{id}/update?version=`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub version: ObjectVersion,
    /// Desired state.
    #[serde(default, deserialize_with = "null_as_default")]
    pub spec: ServiceSpec,
    /// Allocated endpoint.
    #[serde(default, deserialize_with = "null_as_default")]
    pub endpoint: ServiceEndpoint,
    /// Replica counts; only sent for `GET /services?status=true`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub service_status: Option<ServiceStatus>,
}

/// `ServiceStatus` — the numbers behind the `REPLICAS` column.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceStatus {
    /// Tasks currently running.
    #[serde(default, deserialize_with = "null_as_default")]
    pub running_tasks: u64,
    /// Tasks the orchestrator wants running.
    #[serde(default, deserialize_with = "null_as_default")]
    pub desired_tasks: u64,
}

/// `Endpoint` of a service.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceEndpoint {
    /// Allocated ports.
    #[serde(default, deserialize_with = "null_as_default")]
    pub ports: Vec<PortConfig>,
}

/// A service spec — sent on create/update, read back on inspect.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceSpec {
    /// Service name.
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    /// Service labels.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub labels: BTreeMap<String, String>,
    /// Template every task is stamped from.
    #[serde(default, deserialize_with = "null_as_default")]
    pub task_template: TaskTemplate,
    /// Replication mode.
    #[serde(default, deserialize_with = "null_as_default")]
    pub mode: ServiceMode,
    /// Rolling-update settings.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub update_config: Option<UpdateConfig>,
    /// Settings used when rolling *back*, which are a separate policy: a
    /// rollback of a failed update runs under these, not under `UpdateConfig`.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub rollback_config: Option<UpdateConfig>,
    /// Resolution mode and published ports.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub endpoint_spec: Option<EndpointSpec>,
}

/// `TaskTemplate` of a service spec — also a task's `Spec`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct TaskTemplate {
    /// What runs inside the jail.
    #[serde(default, deserialize_with = "null_as_default")]
    pub container_spec: ContainerSpec,
    /// Limits and reservations.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub resources: Option<ResourceRequirements>,
    /// Restart policy.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub restart_policy: Option<TaskRestartPolicy>,
    /// Scheduling constraints.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub placement: Option<Placement>,
    /// Networks the tasks attach to.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub networks: Vec<NetworkAttachmentConfig>,
    /// Everything the daemon sent that this CLI has no flag for, carried
    /// through untouched (`ForceUpdate`, `Runtime`, …). See [`ContainerSpec`].
    #[serde(flatten, skip_serializing_if = "serde_json::Map::is_empty")]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// `ContainerSpec` of a task template.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerSpec {
    /// Image reference.
    #[serde(default, deserialize_with = "null_as_default")]
    pub image: String,
    /// Container labels.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub labels: BTreeMap<String, String>,
    /// Entrypoint override.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub command: Vec<String>,
    /// Arguments to the entrypoint — where `satl service create`'s positional
    /// command lands, as docker does it.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub args: Vec<String>,
    /// Environment, `KEY=VALUE`.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub env: Vec<String>,
    /// Working directory.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub dir: String,
    /// User to run as.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub user: String,
    /// Hostname inside the jail.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub hostname: String,
    /// Filesystem mounts; carried through untouched on update.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub mounts: Vec<serde_json::Value>,
    /// Secrets the task gets, each delivered as one file (invariant 7: tmpfs
    /// only, never the worker's disk).
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub secrets: Vec<SecretReference>,
    /// Configs the task gets, each delivered as one file.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub configs: Vec<ConfigReference>,
    /// Every other key the daemon sent, carried through untouched.
    ///
    /// `satl service update` is a read-edit-write of the stored spec, so a key
    /// this struct does not name is a key the next update **deletes**. That is
    /// how a `Healthcheck` would disappear the moment somebody changed the
    /// image — and with it the health gate that makes a rolling update safe
    /// (api-compat 87). Naming each field instead would mean this list has to be
    /// extended every time the daemon learns one; a catch-all cannot be
    /// forgotten. Every key the daemon *renders* it also *accepts* (both
    /// directions share `ServiceSpecWire`), so echoing them back is safe.
    #[serde(flatten, skip_serializing_if = "serde_json::Map::is_empty")]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// `Resources` of a task template.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ResourceRequirements {
    /// Hard caps.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub limits: Option<Resources>,
    /// Scheduler-side reservations.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub reservations: Option<Resources>,
}

/// Compute/memory quantities.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Resources {
    /// CPU in billionths of a core.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        rename = "NanoCPUs",
        skip_serializing_if = "is_zero_i64"
    )]
    pub nano_cpus: i64,
    /// Memory in bytes.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "is_zero_i64"
    )]
    pub memory_bytes: i64,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_false(value: &bool) -> bool {
    !*value
}

/// `RestartPolicy` of a task template (nanosecond durations).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct TaskRestartPolicy {
    /// `none`, `on-failure` or `any`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub condition: String,
    /// Delay before a replacement starts, in nanoseconds.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "is_zero_i64"
    )]
    pub delay: i64,
    /// Maximum attempts; 0 means unlimited.
    #[serde(default, deserialize_with = "null_as_default")]
    pub max_attempts: u64,
    /// Every other key the daemon sent (`Window`), carried through untouched —
    /// see [`ContainerSpec`]'s `rest`.
    #[serde(flatten, skip_serializing_if = "serde_json::Map::is_empty")]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// `Placement` of a task template.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Placement {
    /// Constraint expressions.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub constraints: Vec<String>,
    /// Per-node cap on tasks of the same service.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "is_zero_u64"
    )]
    pub max_replicas: u64,
    /// Soft placement preferences (`spread=<descriptor>`), Docker's shape.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub preferences: Vec<PlacementPreference>,
    /// Every other key the daemon sent, carried through untouched — see
    /// [`ContainerSpec`]'s `rest`.
    #[serde(flatten, skip_serializing_if = "serde_json::Map::is_empty")]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// One `Placement.Preferences` entry (only `Spread` exists).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct PlacementPreference {
    /// Spread across a descriptor's values.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub spread: Option<SpreadPreference>,
}

/// `Spread`: balance the service's tasks across this descriptor's values.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SpreadPreference {
    /// `node.id`, `node.hostname`, `node.labels.<key>` or `engine.labels.<key>`.
    pub spread_descriptor: String,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

/// One `Networks` entry of a task template.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkAttachmentConfig {
    /// Network name or ID.
    #[serde(default, deserialize_with = "null_as_default")]
    pub target: String,
    /// Extra DNS names for the task on that network, resolved exactly like a
    /// service name (`satl-overlay::endpoints`). Empty for `--network`, and the
    /// compose service's own name for `satl compose`, which is what lets a
    /// namespaced service still answer to the hostname the compose file uses.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub aliases: Vec<String>,
}

/// `Mode` of a service spec: exactly one member is set.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceMode {
    /// A fixed number of replicas.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub replicated: Option<ReplicatedMode>,
    /// One task per schedulable node.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub global: Option<GlobalMode>,
    /// Run-to-completion replicas (Docker's `ReplicatedJob`).
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub replicated_job: Option<ReplicatedJobMode>,
    /// Run-to-completion per eligible node (Docker's `GlobalJob`).
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub global_job: Option<GlobalMode>,
}

impl ServiceMode {
    /// A replicated mode with `replicas` tasks.
    pub fn replicated(replicas: u64) -> Self {
        Self {
            replicated: Some(ReplicatedMode {
                replicas: Some(replicas),
            }),
            ..Self::default()
        }
    }

    /// The global mode.
    pub fn global() -> Self {
        Self {
            global: Some(GlobalMode {}),
            ..Self::default()
        }
    }

    /// A replicated job running `total` completions, at most `concurrent`
    /// live at once; `None` lets the daemon default either to 1.
    pub fn replicated_job(concurrent: Option<u64>, total: Option<u64>) -> Self {
        Self {
            replicated_job: Some(ReplicatedJobMode {
                max_concurrent: concurrent,
                total_completions: total,
            }),
            ..Self::default()
        }
    }

    /// The global-job mode: one run to completion per eligible node.
    pub fn global_job() -> Self {
        Self {
            global_job: Some(GlobalMode {}),
            ..Self::default()
        }
    }

    /// Docker's `MODE` column: `replicated`, `global`, `replicated-job` or
    /// `global-job`.
    pub fn name(&self) -> &'static str {
        if self.global.is_some() {
            "global"
        } else if self.replicated_job.is_some() {
            "replicated-job"
        } else if self.global_job.is_some() {
            "global-job"
        } else {
            "replicated"
        }
    }

    /// Desired replica count, or `None` for a global service or a job (a job
    /// has no replica count; its completions are the `REPLICAS` cell's,
    /// computed by the daemon).
    pub fn replicas(&self) -> Option<u64> {
        Some(self.replicated?.replicas.unwrap_or(1))
    }
}

/// `Replicated` of a service mode.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ReplicatedMode {
    /// Desired replica count.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub replicas: Option<u64>,
}

/// `ReplicatedJob` of a service mode.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ReplicatedJobMode {
    /// Upper bound on simultaneously live tasks; absent means 1.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_concurrent: Option<u64>,
    /// How many clean exits finish the job; absent means 1.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub total_completions: Option<u64>,
}

/// `Global` of a service mode — Docker's empty object.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalMode {}

/// `UpdateConfig` of a service spec — and, in `RollbackConfig`, of a rollback.
///
/// **Every field Docker has, on purpose.** `satl service update` reads the
/// stored spec, edits it and posts it back, so a field missing from this struct
/// is not merely unreadable: it is *erased* on the next update, and the daemon
/// fills the hole with a default. That is how an operator adjusting parallelism
/// used to lose their own `failure_action: rollback` — automatic rollback
/// silently turned off by a change to something else.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateConfig {
    /// Slots updated concurrently; 0 means all at once.
    #[serde(default, deserialize_with = "null_as_default")]
    pub parallelism: u64,
    /// Pause between batches, in nanoseconds.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "is_zero_i64"
    )]
    pub delay: i64,
    /// `pause`, `continue` or `rollback` (a rollback's own may not be
    /// `rollback`).
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub failure_action: String,
    /// Failure-observation window after each task starts, in nanoseconds.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "is_zero_i64"
    )]
    pub monitor: i64,
    /// Fraction of failed tasks tolerated, 0 to 1.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "is_zero_f32"
    )]
    pub max_failure_ratio: f32,
    /// `stop-first` or `start-first`.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub order: String,
}

impl UpdateConfig {
    /// The policy a service gets when it had none at all and one flag asks for
    /// one: Docker's own documented defaults (`docker service create --help`,
    /// verified against docker 29.4.2).
    ///
    /// `parallelism` has to be spelled out because 0 is *meaningful* to the
    /// daemon ("update every slot at once"), so leaving it unset would turn a
    /// lone `--update-monitor 10s` into a wholesale restart. `monitor` is left
    /// at 0 on purpose — the daemon reads 0 as "the default window" (5 s,
    /// api-compat 51), which keeps that number in one place.
    #[must_use]
    pub fn docker_defaults() -> Self {
        Self {
            parallelism: 1,
            delay: 0,
            failure_action: "pause".to_owned(),
            monitor: 0,
            max_failure_ratio: 0.0,
            order: "stop-first".to_owned(),
        }
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_zero_f32(value: &f32) -> bool {
    *value == 0.0
}

/// `EndpointSpec` of a service spec.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct EndpointSpec {
    /// Ports to publish.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ports: Vec<PortConfig>,
    /// Every other key the daemon sent (`Mode`), carried through untouched —
    /// see [`ContainerSpec`]'s `rest`.
    #[serde(flatten, skip_serializing_if = "serde_json::Map::is_empty")]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// One published port.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct PortConfig {
    /// `tcp` or `udp`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub protocol: String,
    /// Port the task listens on.
    #[serde(default, deserialize_with = "null_as_default")]
    pub target_port: u32,
    /// Externally published port; 0 asks for an automatic assignment.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "is_zero_u32"
    )]
    pub published_port: u32,
    /// `ingress` or `host`.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub publish_mode: String,
    /// Every other key the daemon sent (`Name`), carried through untouched —
    /// see [`ContainerSpec`]'s `rest`.
    #[serde(flatten, skip_serializing_if = "serde_json::Map::is_empty")]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

/// Response of `POST /services/create`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceCreateResponse {
    /// The new service ID.
    #[serde(default, deserialize_with = "null_as_default", rename = "ID")]
    pub id: String,
    /// Non-fatal notes.
    #[serde(default, deserialize_with = "null_as_default")]
    pub warnings: Vec<String>,
}

/// Response of `POST /services/{id}/update`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceUpdateResponse {
    /// Non-fatal notes.
    #[serde(default, deserialize_with = "null_as_default")]
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// /tasks
// ---------------------------------------------------------------------------

/// One entry of `GET /tasks`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Task {
    /// Task ID.
    #[serde(default, deserialize_with = "null_as_default", rename = "ID")]
    pub id: String,
    /// Task name, `<service>.<slot>.<task id>`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    /// The spec snapshot this task runs.
    #[serde(default, deserialize_with = "null_as_default")]
    pub spec: TaskTemplate,
    /// Owning service.
    #[serde(default, deserialize_with = "null_as_default", rename = "ServiceID")]
    pub service_id: String,
    /// Replica slot, 0 for global tasks.
    #[serde(default, deserialize_with = "null_as_default")]
    pub slot: u64,
    /// The node this task is bound to.
    #[serde(default, deserialize_with = "null_as_default", rename = "NodeID")]
    pub node_id: String,
    /// Observed status.
    #[serde(default, deserialize_with = "null_as_default")]
    pub status: TaskStatus,
    /// Target state.
    #[serde(default, deserialize_with = "null_as_default")]
    pub desired_state: String,
}

/// `Status` of a task.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TaskStatus {
    /// When this status was produced, RFC 3339.
    #[serde(default, deserialize_with = "null_as_default")]
    pub timestamp: String,
    /// Observed state.
    #[serde(default, deserialize_with = "null_as_default")]
    pub state: String,
    /// Human-readable note on the transition.
    #[serde(default, deserialize_with = "null_as_default")]
    pub message: String,
    /// Failure detail for `failed`/`rejected` tasks.
    #[serde(default, deserialize_with = "null_as_default", rename = "Err")]
    pub err: String,
    /// Host-level bound ports.
    #[serde(default, deserialize_with = "null_as_default")]
    pub port_status: TaskPortStatus,
}

/// `PortStatus` of a task status.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TaskPortStatus {
    /// Bound ports.
    #[serde(default, deserialize_with = "null_as_default")]
    pub ports: Vec<PortConfig>,
}

// ---------------------------------------------------------------------------
// /secrets and /configs
// ---------------------------------------------------------------------------

/// `Spec` of a secret — and the body of `POST /secrets/create`.
///
/// `Data` is the base64 (standard alphabet, padded) payload, and it only ever
/// travels *outwards*: the daemon never sends it back, and nothing in the CLI
/// renders this field. [`fmt::Debug`] is written by hand for that reason — a
/// derived one would put the payload in every error context and every
/// `{:?}` in a test failure.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SecretSpec {
    /// Secret name.
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    /// Operator-assigned labels.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub labels: BTreeMap<String, String>,
    /// Base64-encoded payload; empty on everything the daemon returns.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub data: String,
}

impl fmt::Debug for SecretSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretSpec")
            .field("name", &self.name)
            .field("labels", &self.labels)
            .field("data", &Redacted(self.data.len()))
            .finish()
    }
}

/// Stand-in for a secret payload in `Debug` output: its length, never its
/// bytes.
struct Redacted(usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} base64 characters redacted>", self.0)
    }
}

/// One entry of `GET /secrets`, and the body of `GET /secrets/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Secret {
    /// Secret ID. The daemon spells it `ID`; `Id` is accepted too, because
    /// docker's own API is inconsistent about the two across endpoints.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        rename = "ID",
        alias = "Id"
    )]
    pub id: String,
    /// Store version.
    #[serde(default, deserialize_with = "null_as_default")]
    pub version: ObjectVersion,
    /// Creation timestamp, RFC 3339.
    #[serde(default, deserialize_with = "null_as_default")]
    pub created_at: String,
    /// Last-update timestamp, RFC 3339.
    #[serde(default, deserialize_with = "null_as_default")]
    pub updated_at: String,
    /// Name and labels; never the payload.
    #[serde(default, deserialize_with = "null_as_default")]
    pub spec: SecretSpec,
}

/// `Spec` of a config — and the body of `POST /configs/create`.
///
/// The twin of [`SecretSpec`], with one deliberate difference: a config is not
/// a secret, so `GET /configs/{id}` *does* return its `Data`, and the field is
/// kept so `satl config inspect`'s passthrough stays faithful. No `satl`
/// column ever renders it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ConfigSpec {
    /// Config name.
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    /// Operator-assigned labels.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub labels: BTreeMap<String, String>,
    /// Base64-encoded payload.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub data: String,
}

/// One entry of `GET /configs`, and the body of `GET /configs/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    /// Config ID.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        rename = "ID",
        alias = "Id"
    )]
    pub id: String,
    /// Store version.
    #[serde(default, deserialize_with = "null_as_default")]
    pub version: ObjectVersion,
    /// Creation timestamp, RFC 3339.
    #[serde(default, deserialize_with = "null_as_default")]
    pub created_at: String,
    /// Last-update timestamp, RFC 3339.
    #[serde(default, deserialize_with = "null_as_default")]
    pub updated_at: String,
    /// Name, labels and — on inspect — the payload.
    #[serde(default, deserialize_with = "null_as_default")]
    pub spec: ConfigSpec,
}

/// Response of `POST /secrets/create` and `POST /configs/create`: the new
/// object's ID and nothing else.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IdResponse {
    /// The ID the daemon assigned.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        rename = "ID",
        alias = "Id"
    )]
    pub id: String,
}

/// One `Secrets` entry of a [`ContainerSpec`]: which secret, and the file it
/// becomes inside the task.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SecretReference {
    /// Where the payload lands.
    #[serde(default, deserialize_with = "null_as_default")]
    pub file: FileTarget,
    /// Store ID of the secret. The CLI resolves the name to an ID before
    /// sending, as docker's own client does.
    #[serde(default, deserialize_with = "null_as_default", rename = "SecretID")]
    pub secret_id: String,
    /// Name the operator asked for, kept for `service inspect`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub secret_name: String,
}

/// One `Configs` entry of a [`ContainerSpec`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ConfigReference {
    /// Where the payload lands.
    #[serde(default, deserialize_with = "null_as_default")]
    pub file: FileTarget,
    /// Store ID of the config.
    #[serde(default, deserialize_with = "null_as_default", rename = "ConfigID")]
    pub config_id: String,
    /// Name the operator asked for.
    #[serde(default, deserialize_with = "null_as_default")]
    pub config_name: String,
}

/// `File` of a secret/config reference: the file a delivered payload becomes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct FileTarget {
    /// File name; relative names are rooted by the daemon (`/run/secrets` for
    /// a secret, `/` for a config).
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    /// Owning user inside the task.
    #[serde(default, deserialize_with = "null_as_default", rename = "UID")]
    pub uid: String,
    /// Owning group inside the task.
    #[serde(default, deserialize_with = "null_as_default", rename = "GID")]
    pub gid: String,
    /// Permission bits — **decimal** on the wire, as docker sends them:
    /// `0o444` travels as `292`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub mode: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_specs_round_trip_through_the_daemon_shape() {
        let json = r#"{
            "Name": "web",
            "Labels": {"tier": "front"},
            "TaskTemplate": {
                "ContainerSpec": {"Image": "nginx:1.27", "Env": ["A=1"], "Args": ["-g"]},
                "Resources": {"Limits": {"NanoCPUs": 1500000000, "MemoryBytes": 536870912}},
                "RestartPolicy": {"Condition": "any", "Delay": 5000000000, "MaxAttempts": 0},
                "Placement": {"Constraints": ["node.labels.zone == a"], "MaxReplicas": 2},
                "Networks": [{"Target": "backend", "Aliases": []}],
                "ForceUpdate": 0,
                "Runtime": "container"
            },
            "Mode": {"Replicated": {"Replicas": 3}},
            "UpdateConfig": {"Parallelism": 2, "Delay": 10000000000},
            "EndpointSpec": {"Ports": [
                {"Protocol": "tcp", "TargetPort": 80, "PublishedPort": 8080, "PublishMode": "ingress"}
            ]}
        }"#;
        let spec: ServiceSpec = serde_json::from_str(json).expect("daemon spec parses");
        assert_eq!(spec.name, "web");
        assert_eq!(spec.mode.replicas(), Some(3));
        assert_eq!(spec.task_template.container_spec.image, "nginx:1.27");
        assert_eq!(
            spec.task_template
                .resources
                .and_then(|r| r.limits)
                .map(|l| l.memory_bytes),
            Some(536_870_912)
        );
        assert_eq!(
            spec.task_template
                .placement
                .as_ref()
                .expect("placement")
                .constraints,
            ["node.labels.zone == a"]
        );

        // What we send back keeps every field we read.
        let back: ServiceSpec =
            serde_json::from_str(&serde_json::to_string(&spec).expect("serializable"))
                .expect("re-parses");
        assert_eq!(back, spec);
    }

    #[test]
    fn missing_and_null_fields_read_as_defaults() {
        let node: Node = serde_json::from_str(
            r#"{"ID":"abc","Spec":null,"Description":null,"Status":null,"ManagerStatus":null}"#,
        )
        .expect("tolerant");
        assert_eq!(node.id, "abc");
        assert!(node.spec.role.is_empty());
        assert!(node.manager_status.is_none());
        assert!(node.display_name().is_empty());

        let service: Service =
            serde_json::from_str(r#"{"ID":"s","ServiceStatus":null}"#).expect("tolerant");
        assert!(service.service_status.is_none());
        assert_eq!(service.spec.mode.name(), "replicated");

        let task: Task = serde_json::from_str("{}").expect("tolerant");
        assert!(task.status.state.is_empty());
    }

    #[test]
    fn service_mode_helpers_match_docker() {
        assert_eq!(ServiceMode::replicated(3).replicas(), Some(3));
        assert_eq!(ServiceMode::replicated(3).name(), "replicated");
        assert_eq!(ServiceMode::global().replicas(), None);
        assert_eq!(ServiceMode::global().name(), "global");
        assert_eq!(
            serde_json::to_string(&ServiceMode::global()).expect("serializable"),
            r#"{"Global":{}}"#
        );
        assert_eq!(
            serde_json::to_string(&ServiceMode::replicated(2)).expect("serializable"),
            r#"{"Replicated":{"Replicas":2}}"#
        );
        assert_eq!(
            ServiceMode::replicated_job(Some(2), Some(5)).name(),
            "replicated-job"
        );
        assert_eq!(ServiceMode::replicated_job(None, None).replicas(), None);
        assert_eq!(ServiceMode::global_job().name(), "global-job");
        assert_eq!(
            serde_json::to_string(&ServiceMode::replicated_job(Some(2), Some(5)))
                .expect("serializable"),
            r#"{"ReplicatedJob":{"MaxConcurrent":2,"TotalCompletions":5}}"#
        );
        assert_eq!(
            serde_json::to_string(&ServiceMode::global_job()).expect("serializable"),
            r#"{"GlobalJob":{}}"#
        );
        // The daemon's spelling parses back, with absent knobs staying absent.
        let parsed: ServiceMode =
            serde_json::from_str(r#"{"ReplicatedJob":{"TotalCompletions":4}}"#).expect("parses");
        assert_eq!(parsed, ServiceMode::replicated_job(None, Some(4)));
    }

    /// The HOSTNAME column shows the reported hostname and ignores
    /// `spec.name`, which is an operator label docker does not display here.
    /// Regression test: preferring `spec.name` made one node in a real
    /// cluster show its config label under a column headed HOSTNAME.
    #[test]
    fn node_display_name_is_the_reported_hostname_only() {
        let mut node = Node {
            description: NodeDescription {
                hostname: "alpha".to_owned(),
                ..NodeDescription::default()
            },
            ..Node::default()
        };
        assert_eq!(node.display_name(), "alpha");
        node.spec.name = "primary".to_owned();
        assert_eq!(node.display_name(), "alpha", "spec.name must not win");
    }

    #[test]
    fn node_display_name_is_empty_before_the_agent_reports() {
        let node = Node {
            spec: NodeSpec {
                name: "primary".to_owned(),
                ..NodeSpec::default()
            },
            ..Node::default()
        };
        assert_eq!(node.display_name(), "");
    }

    #[test]
    fn a_secret_spec_carries_the_payload_out_and_nothing_back() {
        let spec = SecretSpec {
            name: "site-cert".to_owned(),
            labels: BTreeMap::from([("env".to_owned(), "prod".to_owned())]),
            data: "aGVsbG8=".to_owned(),
        };
        assert_eq!(
            serde_json::to_string(&spec).expect("serializable"),
            r#"{"Name":"site-cert","Labels":{"env":"prod"},"Data":"aGVsbG8="}"#
        );

        // What the daemon returns: an ID (either spelling), timestamps, and a
        // spec without `Data`.
        let secret: Secret = serde_json::from_str(
            r#"{"Id":"1abc","Version":{"Index":4},"CreatedAt":"2026-02-02T02:40:00Z",
                "UpdatedAt":"2026-02-02T02:41:00Z","Spec":{"Name":"site-cert","Labels":null}}"#,
        )
        .expect("tolerant");
        assert_eq!(secret.id, "1abc");
        assert_eq!(secret.version.index, 4);
        assert_eq!(secret.spec.name, "site-cert");
        assert!(secret.spec.data.is_empty());
    }

    /// A payload must not reach a log line, an error context or a test failure
    /// through `{:?}`.
    #[test]
    fn debugging_a_secret_spec_never_shows_the_payload() {
        let spec = SecretSpec {
            name: "site-cert".to_owned(),
            labels: BTreeMap::new(),
            data: "c3VwZXItc2VjcmV0".to_owned(),
        };
        let rendered = format!("{spec:?}");
        assert!(!rendered.contains("c3VwZXItc2VjcmV0"), "{rendered}");
        assert!(
            rendered.contains("16 base64 characters redacted"),
            "{rendered}"
        );
        assert!(rendered.contains("site-cert"), "{rendered}");
    }

    #[test]
    fn secret_and_config_references_ride_on_the_container_spec() {
        let json = r#"{
            "Image": "nginx:1.27",
            "Secrets": [{"File": {"Name": "site.pem", "UID": "0", "GID": "0", "Mode": 292},
                         "SecretID": "1abc", "SecretName": "site-cert"}],
            "Configs": [{"File": {"Name": "/etc/nginx/nginx.conf", "UID": "80", "GID": "80",
                                  "Mode": 420},
                         "ConfigID": "2def", "ConfigName": "nginx-conf"}]
        }"#;
        let spec: ContainerSpec = serde_json::from_str(json).expect("daemon shape parses");
        assert_eq!(spec.secrets[0].secret_id, "1abc");
        assert_eq!(spec.secrets[0].file.mode, 0o444);
        assert_eq!(spec.configs[0].file.name, "/etc/nginx/nginx.conf");
        assert_eq!(spec.configs[0].file.mode, 0o644);
        // Named fields leave the `rest` catch-all, so an update sends them once.
        assert!(!spec.rest.contains_key("Secrets"));
        assert!(!spec.rest.contains_key("Configs"));
        let back: ContainerSpec =
            serde_json::from_str(&serde_json::to_string(&spec).expect("serializable"))
                .expect("re-parses");
        assert_eq!(back, spec);
    }

    #[test]
    fn a_create_response_accepts_both_id_spellings() {
        let lower: IdResponse = serde_json::from_str(r#"{"Id":"1abc"}"#).expect("tolerant");
        let upper: IdResponse = serde_json::from_str(r#"{"ID":"1abc"}"#).expect("tolerant");
        assert_eq!(lower.id, "1abc");
        assert_eq!(upper.id, "1abc");
        assert!(
            serde_json::from_str::<IdResponse>("{}")
                .expect("tolerant")
                .id
                .is_empty()
        );
    }

    #[test]
    fn init_and_join_bodies_omit_what_was_not_asked_for() {
        assert_eq!(
            serde_json::to_string(&SwarmInitBody::default()).expect("serializable"),
            r#"{"ForceNewCluster":false}"#
        );
        let join = SwarmJoinBody {
            remote_addrs: vec!["10.2.0.11:2377".to_owned()],
            join_token: "SATL-1-worker".to_owned(),
            advertise_addr: "10.2.0.13".to_owned(),
            listen_addr: String::new(),
        };
        assert_eq!(
            serde_json::to_string(&join).expect("serializable"),
            r#"{"AdvertiseAddr":"10.2.0.13","RemoteAddrs":["10.2.0.11:2377"],"JoinToken":"SATL-1-worker"}"#
        );
    }
}
