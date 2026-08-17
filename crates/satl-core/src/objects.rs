// SPDX-License-Identifier: BSD-2-Clause
//! The seven store object types (architecture §3, SWK §3): `Cluster`,
//! `Node`, `Service`, `Task`, `Network`, `Secret`, `Config`, plus their spec
//! and status types.
//!
//! Every object is an envelope `{ id, meta, spec, ...runtime state }`. Specs
//! are user intent; everything else is written by the control plane. Spec
//! shapes follow SwarmKit with the FreeBSD adaptations listed in
//! architecture §3 (no Linux privilege blocks, rctl-backed resources,
//! resolved image platform on the container spec).

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::defaults::{
    HEARTBEAT_PERIOD, MAX_CONFIG_SIZE, MAX_SECRET_SIZE, RAFT_SLOW_FOLLOWER_ENTRIES,
    RAFT_SNAPSHOT_INTERVAL, RESTART_DELAY, UPDATE_MONITOR,
};
use crate::error::ValidationError;
use crate::id::Id;
use crate::meta::{Meta, Version};
use crate::state::{DesiredState, TaskStatus};

// ---------------------------------------------------------------------------
// Common
// ---------------------------------------------------------------------------

/// User-visible name and labels carried by every spec (SWK §3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Annotations {
    /// Object name (validated by [`crate::naming`]).
    pub name: String,
    /// Free-form labels.
    pub labels: BTreeMap<String, String>,
}

/// An OS/architecture pair, e.g. `freebsd`/`amd64` (architecture §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    /// Operating system, e.g. `freebsd` or `linux`.
    pub os: String,
    /// CPU architecture, e.g. `amd64` or `arm64`.
    pub arch: String,
}

/// Compute/memory quantities used for both node capacity and task
/// limits/reservations; mapped to rctl(8) rules on FreeBSD (architecture §3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resources {
    /// CPU in billionths of a core (1 core = `1_000_000_000`).
    pub nano_cpus: i64,
    /// Memory in bytes.
    pub memory_bytes: i64,
}

// ---------------------------------------------------------------------------
// Cluster
// ---------------------------------------------------------------------------

/// Singleton cluster object, named `default` (architecture §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cluster {
    /// Object ID.
    pub id: Id,
    /// Version/timestamps envelope.
    pub meta: Meta,
    /// Cluster-wide settings.
    pub spec: ClusterSpec,
    /// Current join tokens; rotation regenerates the secret part.
    pub join_tokens: JoinTokens,
    /// Certificates barred from the cluster: CN (node ID) to expiry; pruned
    /// after expiry plus a grace period (architecture §12.3).
    pub blacklisted_certs: BTreeMap<String, SystemTime>,
    /// Root CA certificate (PEM). Placeholder — M2 (embedded CA) fills it.
    ///
    /// This is the cluster's **trust bundle**: what joiners download, what
    /// the join-token digest pins, what the dispatcher pushes to workers and
    /// what every node installs as its TLS trust anchors. Exactly one root
    /// certificate, except while a rotation is in flight
    /// ([`Cluster::root_rotation`]), when it carries old + new.
    pub root_ca_cert: Option<Vec<u8>>,
    /// Root CA key, encrypted at rest. Placeholder — M2 (embedded CA) fills it.
    ///
    /// The key of the root that **signs**. During a rotation the signer is
    /// the new root ([`RootRotation::encrypted_new_root_key`]), not this one.
    pub encrypted_root_ca_key: Option<Vec<u8>>,
    /// Root CA rotation in flight, if any (architecture §12.3, SWK §16.5).
    /// `None` outside a rotation. All rotation state lives here so a
    /// leadership change mid-rotation resumes from the store.
    #[serde(default)]
    pub root_rotation: Option<RootRotation>,
}

/// State of an in-flight root CA rotation (architecture §12.3, SWK §16.5).
///
/// While this is present on the [`Cluster`] object:
/// - node certificates are signed by the **new** root's key, with
///   [`RootRotation::cross_signed_cert`] appended so the chain validates
///   against the old root too;
/// - [`Cluster::root_ca_cert`] holds the transitional two-root bundle;
/// - the leader's rotation reconciler marks unconverged nodes
///   [`CertificateStatus::Rotate`] and, once every node's certificate is
///   issued under the new root, atomically installs the new root alone and
///   clears this field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRotation {
    /// The new root certificate (PEM). Self-signed; becomes
    /// [`Cluster::root_ca_cert`] when the rotation completes.
    pub new_root_cert: Vec<u8>,
    /// The new root's private key (PEM), protected — like the old one — by
    /// the raft log's at-rest encryption (architecture §12.4).
    pub encrypted_new_root_key: Vec<u8>,
    /// The new root's certificate re-signed by the **old** root's key (PEM):
    /// same subject, same public key, issuer = old root. Appended to every
    /// leaf issued during the rotation, so the leaf chains to the old trust
    /// anchor (via this) and to the new one (directly) at the same time.
    pub cross_signed_cert: Vec<u8>,
    /// When the rotation was started (proposer clock, informational).
    pub started_at: SystemTime,
}

/// User-tunable cluster settings (SWK §3.8, minus Docker-specific blocks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterSpec {
    /// Name (locked to `default`) and labels.
    pub annotations: Annotations,
    /// Raft tuning.
    pub raft: RaftConfig,
    /// Dispatcher tuning.
    pub dispatcher: DispatcherConfig,
    /// Certificate authority tuning.
    pub ca: CaConfig,
    /// Defaults applied to task specs at task creation.
    pub task_defaults: TaskDefaults,
    /// Address pools overlay subnets are carved from (architecture §11.3).
    pub default_address_pool: Vec<String>,
    /// Prefix length of subnets carved from the default pool.
    pub subnet_size: u8,
    /// Manager autolock (SWK §12.4, Docker's
    /// `EncryptionConfig.AutoLockManagers`): when set, every manager seals
    /// its DEK with [`ClusterSpec::unlock_key`] and boots locked until the
    /// key is presented.
    #[serde(default)]
    pub autolock: bool,
    /// The unlock key (base64 of 32 random bytes), stored **only** here —
    /// inside the DEK-encrypted store. The circularity is Docker's own: the
    /// key is readable from the store only after unlocking, and a locked
    /// store opens only with it. `None` while autolock is off.
    ///
    /// It is never rendered into any API document (the wire spec is built
    /// field by field); `GET /swarm/unlockkey` is the only reader.
    #[serde(default)]
    pub unlock_key: Option<String>,
}

/// Raft tuning knobs (architecture §6.3, §15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftConfig {
    /// Snapshot every this many applied entries.
    pub snapshot_interval: u64,
    /// Log entries kept after compaction for slow followers.
    pub log_entries_for_slow_followers: u64,
    /// Heartbeat interval in ticks.
    pub heartbeat_tick: u32,
    /// Election timeout in ticks.
    pub election_tick: u32,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            snapshot_interval: RAFT_SNAPSHOT_INTERVAL,
            log_entries_for_slow_followers: RAFT_SLOW_FOLLOWER_ENTRIES,
            // Architecture §15: heartbeat/election ticks 1 / 10.
            heartbeat_tick: 1,
            election_tick: 10,
        }
    }
}

/// Dispatcher tuning (architecture §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatcherConfig {
    /// Heartbeat period dictated to agents.
    pub heartbeat_period: Duration,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            heartbeat_period: HEARTBEAT_PERIOD,
        }
    }
}

/// Certificate authority tuning (architecture §12.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaConfig {
    /// Validity of issued node certificates.
    pub node_cert_expiry: Duration,
    /// Root-rotation counter, mirroring Docker's `CAConfig.ForceRotate`
    /// (SWK §6.6): a `POST /swarm/update` whose spec carries a value greater
    /// than the stored one starts a root CA rotation (architecture §12.3).
    /// Monotonic; never decremented.
    #[serde(default)]
    pub force_rotate: u64,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            // Architecture §15: node cert validity 90 days.
            node_cert_expiry: Duration::from_hours(90 * 24),
            force_rotate: 0,
        }
    }
}

/// Defaults baked into task specs at task creation (SWK §3.8).
///
/// Empty for now: SwarmKit's only member is the default log driver, which
/// lands with the log broker (M4/M5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDefaults {}

/// The two join tokens; the token used at join determines the node's role
/// (architecture §12.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinTokens {
    /// Token that joins a node as a worker.
    pub worker: String,
    /// Token that joins a node as a manager.
    pub manager: String,
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// One cluster member (architecture §3). Node objects are born at
/// certificate issuance (architecture §12.2), never by the dispatcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// Object ID — also the certificate CN (architecture §12.1).
    pub id: Id,
    /// Version/timestamps envelope.
    pub meta: Meta,
    /// Desired role, availability, labels.
    pub spec: NodeSpec,
    /// Self-reported facts, refreshed by the agent (architecture §8.3);
    /// absent until the first dispatcher session registers.
    pub description: Option<NodeDescription>,
    /// Observed liveness, maintained by the dispatcher.
    pub status: NodeStatus,
    /// Raft-member status; present only on managers.
    pub manager_status: Option<ManagerStatus>,
    /// TLS certificate issuance state. Placeholder — M2 (embedded CA) fills
    /// the semantics.
    pub certificate_status: CertificateStatus,
    /// Digest (base36 SHA-256) of the root CA certificate that signed this
    /// node's current certificate — recorded by the `NodeCA` at issuance and
    /// by a manager's own renewal loop. What the rotation reconciler reads to
    /// decide whether a node has converged on a new root (architecture
    /// §12.3). `None` on a node whose certificate predates the field; the
    /// reconciler treats that as "unknown, re-issue".
    #[serde(default)]
    pub certificate_issuer: Option<String>,
}

/// Operator intent for a node (SWK §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSpec {
    /// Optional operator-assigned name (defaults to the hostname in UIs).
    pub name: Option<String>,
    /// Operator-assigned labels (used by placement constraints).
    pub labels: BTreeMap<String, String>,
    /// Desired role; reconciled via certificate renewal (architecture §12.3).
    pub role: NodeRole,
    /// Scheduling availability.
    pub availability: Availability,
}

/// A node's cluster role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Runs tasks only.
    Worker,
    /// Participates in Raft and may lead the control plane.
    Manager,
}

/// Whether a node accepts new tasks (SWK §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    /// Schedulable.
    Active,
    /// No new tasks; existing tasks untouched.
    Pause,
    /// No new tasks; existing tasks evicted and rescheduled.
    Drain,
}

/// Facts a node reports about itself (architecture §8.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDescription {
    /// Kernel hostname.
    pub hostname: String,
    /// Native platform, e.g. `freebsd`/`amd64`.
    pub platform: Platform,
    /// Schedulable capacity.
    pub resources: Resources,
    /// Engine version and labels.
    pub engine: EngineDescription,
    /// Whether the linuxulator is available (`linux.ko` loaded) — drives
    /// platform filtering for `linux/*` images.
    pub linux_emulation: bool,
    /// Whether `kern.racct.enable=1`; when false, resource limits are
    /// accepted but not enforced (architecture §8.3).
    pub racct_enabled: bool,
    /// This node's own address on the underlay — the data plane — as a bare
    /// address with **no port** (`10.2.0.5`).
    ///
    /// It is what peers point a VXLAN tunnel at (architecture §11.2: "node VTEP
    /// address = the node's advertise address on the private underlay"), and it
    /// is here, among the facts a node reports about *itself*, for one reason: no
    /// other node can know it. The alternatives are all inferences —
    /// [`ManagerStatus::addr`] is a raft address a worker never has, and
    /// [`NodeStatus::addr`] is the address the dispatcher saw the agent connect
    /// *from*, which is only the underlay address for as long as agents happen
    /// to reach their managers over the underlay. A VTEP guessed wrong does not
    /// fail loudly — the tunnel comes up, the interface reports `RUNNING`, and
    /// traffic goes nowhere (the same shape as the M2 bug where raft membership
    /// carried a node name instead of an address and the cluster looked
    /// healthy). So the node answers for itself, from its own configuration
    /// (`advertise_addr` in `satld.toml`, port stripped).
    ///
    /// `None` on a node whose agent has not registered since this field
    /// existed; `#[serde(default)]` so a snapshot or log entry written before it
    /// still loads, and the node fills it in on its next registration.
    #[serde(default)]
    pub data_addr: Option<String>,
}

/// Engine (satld) information within a node description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineDescription {
    /// satld version string.
    pub version: String,
    /// Engine labels from the node's config file.
    pub labels: BTreeMap<String, String>,
}

/// Observed node liveness, maintained by the dispatcher (SWK §13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    /// Liveness state.
    pub state: NodeState,
    /// Human-readable note on the state.
    pub message: String,
    /// The node's advertised address, as observed at session registration.
    pub addr: String,
}

/// Node liveness states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    /// No session has ever registered.
    Unknown,
    /// Heartbeat TTL expired.
    Down,
    /// Session registered and heartbeating.
    Ready,
    /// Session invalidated (e.g. leadership change grace expired).
    Disconnected,
}

/// Raft-member status carried by manager nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagerStatus {
    /// Raft member ID (random u64, never reused — architecture §6.6).
    pub raft_id: u64,
    /// Address the Raft transport dials.
    pub addr: String,
    /// Whether this member currently leads.
    pub leader: bool,
    /// Peer-observed reachability of this member.
    pub reachability: Reachability,
}

/// Reachability of a Raft member as observed by its peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    /// Not yet determined.
    Unknown,
    /// Health checks fail.
    Unreachable,
    /// Health checks pass.
    Reachable,
}

/// TLS certificate issuance state for a node.
///
/// Placeholder enum — M2 (embedded CA, architecture §12) fills the issuance
/// flow that drives these transitions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    /// No issuance information yet.
    #[default]
    Unknown,
    /// A signing request is queued.
    Pending,
    /// A certificate has been issued.
    Issued,
    /// The certificate must be re-issued (CA rotation).
    Rotate,
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// A user-declared workload (architecture §3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Service {
    /// Object ID.
    pub id: Id,
    /// Version/timestamps envelope.
    pub meta: Meta,
    /// Desired state.
    pub spec: ServiceSpec,
    /// Allocator-written endpoint (ports/DNS); `None` until allocated.
    pub endpoint: Option<Endpoint>,
    /// Version of [`Service::spec`] alone — bumped by the state machine only
    /// when an update actually changes the spec (SWK §4.1).
    ///
    /// **Not** `meta.version`, and that distinction is the whole point.
    /// `meta.version` moves on every write to the object, including the ones
    /// the rolling updater makes to its own [`Service::update_status`]. A
    /// dirtiness check against `meta.version` would therefore mark every task
    /// dirty on every updater tick and roll the service forever.
    ///
    /// Stamped in the FSM next to `meta.version` rather than by the proposer:
    /// both replicas apply the same old and new object at the same log index,
    /// so the result is deterministic, and no caller can forget it.
    ///
    /// [`Task::spec_version`] records the value a task was stamped from, which
    /// makes equality a **fast path for "clean" only**: equal versions prove a
    /// task is up to date and let the deep comparison be skipped, while
    /// unequal versions prove nothing on their own — a `None` on a task
    /// written before this field existed, or a spec that changed and changed
    /// back, both land there — so the deep comparison decides. Reading it the
    /// other way round (unequal ⇒ dirty) is the mistake to avoid.
    #[serde(default)]
    pub spec_version: Version,
    /// Spec before the last update, kept for rollback (SWK §4.1).
    pub previous_spec: Option<ServiceSpec>,
    /// Progress of an in-flight or finished rolling update.
    pub update_status: Option<UpdateStatus>,
}

/// Desired state of a service (SWK §3.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceSpec {
    /// Name (service naming rules) and labels.
    pub annotations: Annotations,
    /// Template every task of this service is stamped from.
    pub task: TaskSpec,
    /// Replication mode.
    pub mode: ServiceMode,
    /// Rolling-update settings; defaults per SWK §3.9 when `None`.
    pub update: Option<UpdateConfig>,
    /// Settings used when rolling back; defaults mirror `update`.
    pub rollback: Option<UpdateConfig>,
    /// Resolution mode and published ports.
    pub endpoint: Option<EndpointSpec>,
}

/// Service replication mode (SWK §3.4).
///
/// The two job modes are run-to-completion (SWK §3.4's `ReplicatedJob` and
/// `GlobalJob`): a task that exits cleanly is a success and is never
/// restarted, a failed one is retried within the restart policy's budget, and
/// a spec update re-runs the job. [`ServiceMode::is_job`] is the predicate
/// every keep-alive loop uses to stay away from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceMode {
    /// A fixed number of replicas, slot-numbered 1..N.
    Replicated {
        /// Desired replica count.
        replicas: u64,
    },
    /// One task per schedulable node.
    Global,
    /// `total_completions` runs to a clean exit, at most `max_concurrent`
    /// live at a time; both default to 1 (Docker's `ReplicatedJob`).
    ReplicatedJob {
        /// Upper bound on simultaneously live tasks.
        max_concurrent: Option<u64>,
        /// How many clean exits finish the job.
        total_completions: Option<u64>,
    },
    /// One run to completion per eligible node (Docker's `GlobalJob`).
    GlobalJob,
}

impl ServiceMode {
    /// Whether the service runs to completion rather than being kept alive —
    /// the boundary between [`crate::ServiceMode::ReplicatedJob`] /
    /// [`crate::ServiceMode::GlobalJob`] and the two keep-alive modes.
    #[must_use]
    pub fn is_job(&self) -> bool {
        matches!(self, Self::ReplicatedJob { .. } | Self::GlobalJob)
    }
}

/// Rolling-update settings (SWK §3.4, defaults §3.9).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Slots updated concurrently; 0 means unlimited.
    pub parallelism: u64,
    /// Pause between batches.
    pub delay: Duration,
    /// What to do when the failure ratio is exceeded.
    pub failure_action: FailureAction,
    /// Failure-observation window after a task starts.
    pub monitor: Duration,
    /// Tolerated fraction of failed tasks, 0.0..=1.0.
    pub max_failure_ratio: f32,
    /// Whether the old task stops before the new one starts.
    pub order: UpdateOrder,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            // SWK §3.9: parallelism 1, failure action pause, order stop-first.
            parallelism: 1,
            delay: Duration::ZERO,
            failure_action: FailureAction::Pause,
            monitor: UPDATE_MONITOR,
            max_failure_ratio: 0.0,
            order: UpdateOrder::StopFirst,
        }
    }
}

/// Reaction to exceeding `max_failure_ratio` during an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureAction {
    /// Halt the update; a later update resumes it.
    Pause,
    /// Keep updating regardless.
    Continue,
    /// Swap back to `previous_spec` and update in reverse.
    Rollback,
}

/// Task replacement order during updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateOrder {
    /// Stop the old task, then start the replacement.
    StopFirst,
    /// Start the replacement, then stop the old task.
    StartFirst,
}

/// Progress of a rolling update (SWK §7.3; state flow in architecture §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateStatus {
    /// Where the update currently stands.
    pub state: UpdateStateKind,
    /// When the update began.
    pub started_at: Option<SystemTime>,
    /// When the update reached a final state.
    pub completed_at: Option<SystemTime>,
    /// Human-readable progress note.
    pub message: String,
}

/// States of a rolling update. Rollbacks never roll back: a failed rollback
/// pauses (architecture §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStateKind {
    /// Update in progress.
    Updating,
    /// All slots updated and monitored successfully.
    Completed,
    /// Halted by failures (or operator) mid-update.
    Paused,
    /// Failure ratio exceeded with `failure_action = rollback`.
    RollbackStarted,
    /// Rollback finished successfully.
    RollbackCompleted,
    /// Rollback itself hit the failure ratio and halted.
    RollbackPaused,
}

// ---------------------------------------------------------------------------
// Task
// ---------------------------------------------------------------------------

/// One execution unit: one-shot, effectively immutable, never moved between
/// nodes (architecture §4, SWK §4.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    /// Object ID — also the jail name (architecture §3).
    pub id: Id,
    /// Version/timestamps envelope.
    pub meta: Meta,
    /// Spec snapshot copied from the service at task creation; never mutated.
    pub spec: TaskSpec,
    /// The service spec version this task derives from (not comparable to
    /// `Service.meta.version` — SWK §4.1).
    pub spec_version: Option<Version>,
    /// Owning service; `None` for future standalone attachments.
    pub service_id: Option<Id>,
    /// Replica slot, 1..N; 0 for global (node-bound) tasks, which use the
    /// node ID as their slot in task names (SWK §4.5).
    pub slot: u64,
    /// The node this task is bound to, once scheduled.
    pub node_id: Option<Id>,
    /// Runtime-chosen name and labels for this task.
    pub annotations: Annotations,
    /// Copy of the owning service's name/labels (not propagated into jails).
    pub service_annotations: Annotations,
    /// Observed status, reported by the agent.
    pub status: TaskStatus,
    /// Target state, written only by manager components; never decreases.
    pub desired_state: DesiredState,
    /// Allocator-written per-network attachments.
    pub networks: Vec<NetworkAttachment>,
    /// Copy of the service's endpoint at allocation time.
    pub endpoint: Option<Endpoint>,
    /// Reserved from SwarmKit's task model (SWK §7.8): SwarmKit re-runs an
    /// updated job by bumping a job iteration; SatL re-runs from
    /// [`Service::spec_version`] instead, so this stays `None`.
    pub job_iteration: Option<u64>,
}

/// Template for a task (SWK §3.5, FreeBSD adaptations per architecture §3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskSpec {
    /// What to run — SatL supports exactly one runtime: containers as jails.
    pub container: ContainerSpec,
    /// Resource limits and reservations.
    pub resources: ResourceRequirements,
    /// Restart policy applied by the restart supervisor — and, for a job
    /// service, by the jobs loop, which owns job tasks' lifecycle.
    pub restart: RestartPolicy,
    /// Scheduling constraints and platform requirements.
    pub placement: Placement,
    /// Networks this task attaches to.
    pub networks: Vec<NetworkAttachmentConfig>,
    /// User-bumped counter: any change makes every task dirty and triggers a
    /// rolling restart (SWK §3.5).
    pub force_update: u64,
}

/// Limits and reservations for a task (architecture §3: rctl-backed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRequirements {
    /// Hard caps, enforced via rctl(8).
    pub limits: Option<Resources>,
    /// Scheduler-side reservations counted against node capacity.
    pub reservations: Option<Resources>,
}

/// Restart policy (SWK §3.5, semantics §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestartPolicy {
    /// When replacements are created.
    pub condition: RestartCondition,
    /// Delay before starting a replacement.
    pub delay: Duration,
    /// Maximum restart attempts; 0 means unlimited.
    pub max_attempts: u64,
    /// Sliding window `max_attempts` is counted over; zero means unbounded.
    pub window: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            // SWK §3.9: condition any, delay 5 s.
            condition: RestartCondition::Any,
            delay: RESTART_DELAY,
            max_attempts: 0,
            window: Duration::ZERO,
        }
    }
}

/// When the restart supervisor replaces a stopped task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartCondition {
    /// Never restart.
    None,
    /// Restart only on non-zero exit.
    OnFailure,
    /// Restart on any termination.
    Any,
}

/// Scheduling requirements (SWK §3.5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    /// Constraint expressions, e.g. `node.labels.zone == a` (SWK §8.7).
    pub constraints: Vec<String>,
    /// Per-node cap on tasks of the same service; 0 means uncapped.
    pub max_replicas: u64,
    /// Platforms the image supports; empty means no platform restriction.
    pub platforms: Vec<Platform>,
    /// Soft placement preferences (M7d); applied in order after the fault
    /// penalty and before the per-service spread. `#[serde(default)]` so a
    /// spec written before the field existed still loads.
    #[serde(default)]
    pub preferences: Vec<PlacementPreference>,
}

/// One soft placement preference (SWK §3.5). Only `spread` exists — it is
/// Docker's only strategy, and the API layer refuses anything else.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementPreference {
    /// Spread tasks across the values of this descriptor.
    pub spread: Option<SpreadPreference>,
}

/// `spread=<descriptor>`: balance a service's tasks across the descriptor's
/// values (`node.id`, `node.hostname`, `node.labels.<key>`,
/// `engine.labels.<key>`). Nodes missing the key form one empty-value group.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpreadPreference {
    /// The descriptor whose values define the groups.
    pub spread_descriptor: String,
}

/// A task's request to join a network (SWK §3.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAttachmentConfig {
    /// Network name or ID.
    pub target: String,
    /// Extra DNS names for this task on that network.
    pub aliases: Vec<String>,
}

// ---------------------------------------------------------------------------
// ContainerSpec
// ---------------------------------------------------------------------------

/// What runs inside the jail (SWK §3.6, FreeBSD-adapted per architecture §3:
/// Linux/Windows privilege blocks dropped for v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerSpec {
    /// Image reference, e.g. `registry.example.com/app:1.2`.
    pub image: String,
    /// Labels applied to the container.
    pub labels: BTreeMap<String, String>,
    /// Entrypoint override; empty means use the image's.
    pub command: Vec<String>,
    /// Arguments to the entrypoint.
    pub args: Vec<String>,
    /// Hostname inside the jail; `None` defaults to the task name.
    pub hostname: Option<String>,
    /// Environment as `KEY=VALUE` pairs.
    pub env: Vec<String>,
    /// Working directory; `None` means the image's.
    pub dir: Option<String>,
    /// User (`<user>` or `<user>:<group>`); `None` means the image's.
    pub user: Option<String>,
    /// Supplementary groups.
    pub groups: Vec<String>,
    /// Allocate a TTY.
    pub tty: bool,
    /// Keep stdin open.
    pub open_stdin: bool,
    /// Mount the root filesystem read-only.
    pub read_only: bool,
    /// Signal used to stop the task; `None` means SIGTERM.
    pub stop_signal: Option<String>,
    /// Grace period between stop signal and SIGKILL; `None` means the
    /// default ([`crate::defaults::STOP_GRACE_PERIOD`]).
    pub stop_grace_period: Option<Duration>,
    /// Docker-semantics healthcheck (probes run via `ocijail exec` — M4).
    pub healthcheck: Option<HealthConfig>,
    /// Extra `/etc/hosts` entries, in `IP hostname [aliases...]` order.
    pub hosts: Vec<String>,
    /// DNS resolver configuration for the jail.
    pub dns_config: Option<DnsConfig>,
    /// Filesystem mounts.
    pub mounts: Vec<Mount>,
    /// Secrets materialized in the per-task tmpfs (architecture §12.4).
    pub secrets: Vec<SecretReference>,
    /// Configs materialized as files.
    pub configs: Vec<ConfigReference>,
    /// Pull-time options.
    pub pull_options: Option<PullOptions>,
    /// Resolved image platform — tells the executor whether to build a
    /// linuxulator jail (architecture §3).
    pub platform: Option<Platform>,
}

/// Docker HEALTHCHECK semantics (SWK §3.6; execution lands in M4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Probe command, Docker forms: `["CMD", ...]` or `["CMD-SHELL", ...]`.
    pub test: Vec<String>,
    /// Time between probes; `None` means the engine default.
    pub interval: Option<Duration>,
    /// Per-probe timeout; `None` means the engine default.
    pub timeout: Option<Duration>,
    /// Consecutive failures before the task is unhealthy.
    pub retries: u32,
    /// Startup period during which failures don't count.
    pub start_period: Option<Duration>,
}

/// Jail resolver configuration (SWK §3.6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Nameserver addresses.
    pub nameservers: Vec<String>,
    /// Search domains.
    pub search: Vec<String>,
    /// `resolv.conf` options.
    pub options: Vec<String>,
}

/// A filesystem mount into the jail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mount {
    /// Mount flavor.
    #[serde(rename = "type")]
    pub kind: MountType,
    /// Host path (bind) or volume name; `None` for tmpfs.
    pub source: Option<String>,
    /// Path inside the jail.
    pub target: String,
    /// Mount read-only.
    pub read_only: bool,
}

/// Supported mount flavors (architecture §3; no npipe/CSI on FreeBSD).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountType {
    /// Host path bind mount (nullfs).
    Bind,
    /// Named node-local volume (architecture §3: not cluster objects in v1).
    Volume,
    /// In-memory filesystem.
    Tmpfs,
}

/// A task's reference to a secret, delivered via tmpfs only (invariant #7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretReference {
    /// ID of the referenced secret.
    pub secret_id: Id,
    /// Name of the referenced secret at spec time.
    pub secret_name: String,
    /// Where and how the payload is materialized.
    pub file: FileTarget,
}

/// A task's reference to a config, materialized as a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigReference {
    /// ID of the referenced config.
    pub config_id: Id,
    /// Name of the referenced config at spec time.
    pub config_name: String,
    /// Where and how the payload is materialized.
    pub file: FileTarget,
}

/// File placement for a secret/config payload inside the jail (SWK §3.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTarget {
    /// File name under the target directory (e.g. `/var/run/secrets/<name>`).
    pub name: String,
    /// Owning user (name or numeric string).
    pub uid: String,
    /// Owning group (name or numeric string).
    pub gid: String,
    /// Permission bits, e.g. `0o444`.
    pub mode: u32,
}

/// Image pull options (SWK §3.6). Credentials are per-request and never
/// persisted by the daemon (architecture §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullOptions {
    /// Docker-style `X-Registry-Auth` payload for the pull.
    pub registry_auth: String,
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/// A user- or system-created network (architecture §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    /// Object ID.
    pub id: Id,
    /// Version/timestamps envelope.
    pub meta: Meta,
    /// Desired state.
    pub spec: NetworkSpec,
    /// Allocator-assigned VXLAN network identifier (overlay networks only).
    pub vni: Option<u32>,
    /// Allocator-assigned VXLAN VTEP UDP port (encrypted overlay networks
    /// only), from
    /// [`OVERLAY_VXLAN_PORT_RANGE`](crate::defaults::OVERLAY_VXLAN_PORT_RANGE).
    ///
    /// FreeBSD's SPD matches neither the VNI nor a hashed source port, so
    /// per-network `IPsec` keys need per-network UDP ports: when the network is
    /// encrypted, both ends' VTEPs bind this port
    /// (`vxlanlocalport`/`vxlanremoteport` on `ifconfig vxlan`). Like [`Network::vni`],
    /// it is a network property, cluster-wide, assigned by the allocator.
    /// `None` for unencrypted networks and until the allocator's first pass.
    ///
    /// `default` so a snapshot or log entry written before per-network ports
    /// existed still loads; the allocator fills it in on its next pass.
    #[serde(default)]
    pub vxlan_port: Option<u16>,
    /// Allocator-assigned subnet in CIDR form.
    pub subnet: Option<String>,
    /// Gateway addresses this network has on each participating node.
    ///
    /// An overlay network has **no single gateway**: the address is the
    /// containers' default route and the address their DNS responder binds to,
    /// so it must live on an interface — every participating node's own bridge.
    /// One shared address would be a duplicate address on one L2 segment
    /// (`docs/vxlan.md` §8: `arp: 10.99.0.1 is using my IP address`, and the
    /// wrong node's responder answering), so each node gets one of its own
    /// (SWK §9.1's "one attachment per overlay network in use on that node",
    /// reduced to an address).
    ///
    /// Keyed by node ID, valued as a bare IPv4 address — the prefix length is
    /// [`Network::subnet`]'s. Allocated on demand from the network's own subnet
    /// when the node's first task attaches, released when it runs no more —
    /// except on the **ingress network** (M6d), whose participant set is every
    /// node (SWK §9.1's load-balancer attachment): there each node gets its
    /// gateway at allocation time and keeps it.
    /// `.1` is never handed out: it stays reserved so that an operator reading
    /// `10.100.0.1` in a subnet is not looking at one arbitrary node's address
    /// (architecture §11.3).
    ///
    /// `default` so a snapshot or log entry written when this was one
    /// cluster-wide `gateway` still loads; the allocator fills it in on its next
    /// pass.
    #[serde(default)]
    pub node_gateways: BTreeMap<Id, String>,
    /// The data-plane keyring. Empty for unencrypted networks; populated by
    /// the leader for `encrypted` ones (rotation in task 2, distribution in
    /// task 3). Nodes accepting the network's traffic hold every key; only
    /// the primary is used for emission.
    ///
    /// `default` so a snapshot or log entry written before data-plane
    /// encryption existed still loads, with an empty keyring.
    #[serde(default)]
    pub keys: Vec<NetworkKey>,
    /// Wall-clock time of the last keyring change — generation or one
    /// rotation phase. The leader's phase decisions derive from it, never
    /// from in-memory timers, so a leadership change mid-rotation resumes
    /// from store state alone (SWK §7.9).
    ///
    /// `default`/`None` on objects written before this field existed; the
    /// keyring loop treats an unknown age on a non-empty ring as overdue
    /// and converges it on its next pass.
    #[serde(default)]
    pub keys_updated_at: Option<SystemTime>,
}

/// The default ingress network's name (Docker's own).
pub const INGRESS_NETWORK_NAME: &str = "ingress";

impl Network {
    /// The default ingress network (SWK §9.3, M6d), as the allocator creates
    /// it when a cluster has none — Docker's hidden `ingress` network's shape:
    /// overlay-backed, not user-attachable, and marked `ingress`, which is
    /// what makes every node a participant (the per-node load-balancer
    /// attachment, SWK §9.1), not just the ones running a task.
    ///
    /// The allocator assigns its VNI and subnet (from the cluster default
    /// pool) on a later pass, and every node a gateway address.
    #[must_use]
    pub fn default_ingress() -> Self {
        Self {
            id: Id::generate(),
            meta: Meta::new(),
            spec: NetworkSpec {
                annotations: Annotations {
                    name: INGRESS_NETWORK_NAME.to_owned(),
                    labels: BTreeMap::new(),
                },
                driver: NetworkDriver::Overlay,
                ipam: None,
                internal: false,
                attachable: false,
                ingress: true,
                // The ingress network is never encrypted: its assignment is
                // broadcast to every node (SWK §9.1: every node is a mesh load
                // balancer, task or not), so a keyring on it would leave the
                // participant-only boundary the dispatcher keeps for every
                // other network.
                encrypted: false,
            },
            vni: None,
            vxlan_port: None,
            subnet: None,
            node_gateways: BTreeMap::new(),
            keys: Vec::new(),
            keys_updated_at: None,
        }
    }
}

/// Desired state of a network (SWK §3.8, reduced to SatL's two drivers).
// Independent on/off flags; folding them into an enum would invent states
// that cannot co-occur on the wire but can in the store.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSpec {
    /// Name (network naming rules) and labels.
    pub annotations: Annotations,
    /// Which data plane backs this network.
    pub driver: NetworkDriver,
    /// User-requested addressing; allocator fills the gaps.
    pub ipam: Option<IpamConfig>,
    /// No external (NAT) connectivity.
    pub internal: bool,
    /// Standalone containers may attach (API compat; attachment API deferred).
    pub attachable: bool,
    /// This is the routing-mesh ingress network.
    pub ingress: bool,
    /// Encrypt the data plane between nodes (`IPsec` ESP/AES-128-GCM over
    /// VXLAN, Docker's `--opt encrypted`). Overlay networks only; the API
    /// rejects the flag on a bridge network.
    ///
    /// `default` so a spec written before the flag existed still loads from a
    /// log entry or snapshot (precedent: [`Network::node_gateways`]).
    #[serde(default)]
    pub encrypted: bool,
}

/// One overlay data-plane key (AES-128-GCM, RFC 4106). Distributed only to
/// nodes participating in the network (task 3); rotated by the leader
/// (task 2).
///
/// Stored on the [`Network`] object, so it is encrypted at rest for free: the
/// whole raft log is XChaCha20-Poly1305. The payload convention matches
/// [`SecretSpec`]'s: raw bytes, never a base64 string of bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkKey {
    /// Random tag identifying the key; SPIs are derived from it (FNV-1a,
    /// libnetwork-style).
    pub tag: u32,
    /// The 16-byte AES key.
    pub key: [u8; 16],
    /// Only the primary key is used for emission; all keys are accepted on
    /// reception.
    pub primary: bool,
}

impl fmt::Debug for NetworkKey {
    /// Never prints the key material — same rule as [`SecretSpec`]: keys must
    /// not leak into logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkKey")
            .field("tag", &self.tag)
            .field("key", &format_args!("<redacted, {} bytes>", self.key.len()))
            .field("primary", &self.primary)
            .finish()
    }
}

/// Network data planes supported by SatL (architecture §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDriver {
    /// Node-local bridge(4) network (architecture §11.1).
    Bridge,
    /// Cluster-wide VXLAN overlay (architecture §11.2).
    Overlay,
}

/// User-requested IPAM parameters (architecture §11.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpamConfig {
    /// Subnet in CIDR form; `None` lets the allocator pick one.
    pub subnet: Option<String>,
    /// Gateway address the operator asked for.
    ///
    /// On an overlay network there is no single gateway to name
    /// ([`Network::node_gateways`]), so the request is honoured the only way it
    /// still means something: the address is **reserved** and handed to no node
    /// and no task.
    pub gateway: Option<String>,
    /// Sub-range tasks are allocated from.
    pub ip_range: Option<String>,
}

/// A task's allocated attachment to one network (SWK §4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAttachment {
    /// The attached network.
    pub network_id: Id,
    /// Addresses allocated to this task on that network (CIDR form).
    pub addresses: Vec<String>,
    /// DNS aliases for this task on that network.
    pub aliases: Vec<String>,
}

// ---------------------------------------------------------------------------
// Secret / Config
// ---------------------------------------------------------------------------

/// A sensitive blob, encrypted at rest in the Raft store and delivered into
/// jails via tmpfs only (architecture §12.4, invariant #7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret {
    /// Object ID.
    pub id: Id,
    /// Version/timestamps envelope.
    pub meta: Meta,
    /// Name, labels, payload.
    pub spec: SecretSpec,
}

/// Secret payload and annotations. Constructed via [`SecretSpec::new`] to
/// enforce the size limit; the `Debug` impl redacts the payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretSpec {
    /// Name (secret naming rules) and labels.
    pub annotations: Annotations,
    /// The sensitive payload. Private: read via [`SecretSpec::data`].
    data: Vec<u8>,
}

impl SecretSpec {
    /// Creates a spec, enforcing `1 <= len < MAX_SECRET_SIZE` (SWK §3.8).
    pub fn new(annotations: Annotations, data: Vec<u8>) -> Result<Self, ValidationError> {
        let spec = Self { annotations, data };
        spec.validate()?;
        Ok(spec)
    }

    /// Re-checks invariants — use after deserializing from untrusted input,
    /// which bypasses [`SecretSpec::new`].
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.data.is_empty() || self.data.len() >= MAX_SECRET_SIZE {
            return Err(ValidationError::SecretDataSize {
                size: self.data.len(),
                max: MAX_SECRET_SIZE,
            });
        }
        Ok(())
    }

    /// The sensitive payload.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Debug for SecretSpec {
    /// Never prints the payload — secrets must not leak into logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretSpec")
            .field("annotations", &self.annotations)
            .field(
                "data",
                &format_args!("<redacted, {} bytes>", self.data.len()),
            )
            .finish()
    }
}

/// A non-sensitive blob distributed to tasks (architecture §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Object ID.
    pub id: Id,
    /// Version/timestamps envelope.
    pub meta: Meta,
    /// Name, labels, payload.
    pub spec: ConfigSpec,
}

/// Config payload and annotations. Constructed via [`ConfigSpec::new`] to
/// enforce the size limit.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSpec {
    /// Name (config naming rules) and labels.
    pub annotations: Annotations,
    /// The payload. Private: read via [`ConfigSpec::data`].
    data: Vec<u8>,
}

impl ConfigSpec {
    /// Creates a spec, enforcing `1 <= len < MAX_CONFIG_SIZE` (SWK §3.8).
    pub fn new(annotations: Annotations, data: Vec<u8>) -> Result<Self, ValidationError> {
        let spec = Self { annotations, data };
        spec.validate()?;
        Ok(spec)
    }

    /// Re-checks invariants — use after deserializing from untrusted input,
    /// which bypasses [`ConfigSpec::new`].
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.data.is_empty() || self.data.len() >= MAX_CONFIG_SIZE {
            return Err(ValidationError::ConfigDataSize {
                size: self.data.len(),
                max: MAX_CONFIG_SIZE,
            });
        }
        Ok(())
    }

    /// The payload.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Debug for ConfigSpec {
    /// Prints the payload size, not the payload — configs can be a megabyte
    /// and would swamp logs (redacted for hygiene, not secrecy).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigSpec")
            .field("annotations", &self.annotations)
            .field("data", &format_args!("<{} bytes>", self.data.len()))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

/// Allocator-written endpoint state of a service (SWK §3.7).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// The spec this endpoint was allocated from.
    pub spec: EndpointSpec,
    /// Allocated ports (auto-assigned published ports filled in).
    pub ports: Vec<PortConfig>,
}

/// User-declared endpoint requirements (SWK §3.7).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointSpec {
    /// Resolution mode.
    pub mode: EndpointMode,
    /// Ports to publish.
    pub ports: Vec<PortConfig>,
}

/// Service resolution mode.
///
/// Only DNS round-robin exists in v1. A `vip` mode is *reserved* — FreeBSD
/// has no IPVS, and pf-based VIP load balancing is an M6 candidate
/// (architecture §11.5); the REST API rejects `vip` and the deviation is
/// recorded in `docs/api-compat.md`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointMode {
    /// DNS round-robin: the embedded resolver answers with healthy task IPs.
    #[default]
    DnsRR,
}

/// One published port (SWK §3.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortConfig {
    /// Optional user-facing name.
    pub name: String,
    /// Transport protocol.
    pub protocol: PortProtocol,
    /// Port the task listens on.
    pub target_port: u16,
    /// Externally published port; 0 means auto-assign from
    /// [`crate::defaults::INGRESS_PORT_RANGE`] (ingress mode only).
    pub published_port: u16,
    /// Where the published port is bound.
    pub publish_mode: PublishMode,
}

/// Transport protocols for published ports (no SCTP on SatL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl fmt::Display for PortProtocol {
    /// Matches the serde form and Docker's `<port>/<protocol>` notation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

/// Where a published port is bound (architecture §11.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishMode {
    /// Centrally allocated, and redirected **on each node that runs a task of
    /// the service, to that node's own task** — "ingress-lite".
    ///
    /// Deliberately less than Docker, where the same value means the routing
    /// mesh: every node in the swarm answers on the port and forwards
    /// internally, whether or not it runs a task. Here a node running no task
    /// of the service does not answer at all, and a node running several
    /// balances over its own with pf's `round-robin`. The full mesh is M6; the
    /// deviation is `docs/api-compat.md` #75, and the node-side machinery is
    /// `satld`'s port sweep over `satl_net`'s `satl/rdr` anchor.
    Ingress,
    /// Bound only on nodes running a task; no central allocation.
    Host,
}

#[cfg(test)]
mod tests {
    use crate::state::{TaskState, TaskStatus};

    use super::*;

    fn sample_container_spec() -> ContainerSpec {
        ContainerSpec {
            image: "registry.example.com/app:1.2".to_owned(),
            labels: BTreeMap::from([("tier".to_owned(), "web".to_owned())]),
            command: vec!["/usr/local/bin/app".to_owned()],
            args: vec!["--listen".to_owned(), "0.0.0.0:8080".to_owned()],
            hostname: None,
            env: vec!["RUST_LOG=info".to_owned()],
            dir: Some("/srv".to_owned()),
            user: Some("www:www".to_owned()),
            groups: vec![],
            tty: false,
            open_stdin: false,
            read_only: true,
            stop_signal: Some("SIGTERM".to_owned()),
            stop_grace_period: Some(Duration::from_secs(10)),
            healthcheck: Some(HealthConfig {
                test: vec!["CMD-SHELL".to_owned(), "app health".to_owned()],
                interval: Some(Duration::from_secs(5)),
                timeout: Some(Duration::from_secs(2)),
                retries: 3,
                start_period: Some(Duration::from_secs(15)),
            }),
            hosts: vec!["10.88.0.1 gateway".to_owned()],
            dns_config: Some(DnsConfig::default()),
            mounts: vec![Mount {
                kind: MountType::Tmpfs,
                source: None,
                target: "/tmp".to_owned(),
                read_only: false,
            }],
            secrets: vec![SecretReference {
                secret_id: Id::generate(),
                secret_name: "db.password".to_owned(),
                file: FileTarget {
                    name: "db_password".to_owned(),
                    uid: "0".to_owned(),
                    gid: "0".to_owned(),
                    mode: 0o400,
                },
            }],
            configs: vec![],
            pull_options: None,
            platform: Some(Platform {
                os: "freebsd".to_owned(),
                arch: "amd64".to_owned(),
            }),
        }
    }

    fn sample_task_spec() -> TaskSpec {
        TaskSpec {
            container: sample_container_spec(),
            resources: ResourceRequirements {
                limits: Some(Resources {
                    nano_cpus: 2_000_000_000,
                    memory_bytes: 512 * 1024 * 1024,
                }),
                reservations: None,
            },
            restart: RestartPolicy::default(),
            placement: Placement {
                constraints: vec!["node.labels.zone == a".to_owned()],
                max_replicas: 2,
                platforms: vec![],
                preferences: vec![],
            },
            networks: vec![NetworkAttachmentConfig {
                target: "backend".to_owned(),
                aliases: vec!["app".to_owned()],
            }],
            force_update: 0,
        }
    }

    fn sample_service() -> Service {
        Service {
            id: Id::generate(),
            meta: Meta::new(),
            spec: ServiceSpec {
                annotations: Annotations {
                    name: "web".to_owned(),
                    labels: BTreeMap::new(),
                },
                task: sample_task_spec(),
                mode: ServiceMode::Replicated { replicas: 3 },
                update: Some(UpdateConfig::default()),
                rollback: None,
                endpoint: Some(EndpointSpec {
                    mode: EndpointMode::DnsRR,
                    ports: vec![PortConfig {
                        name: "http".to_owned(),
                        protocol: PortProtocol::Tcp,
                        target_port: 8080,
                        published_port: 0,
                        publish_mode: PublishMode::Ingress,
                    }],
                }),
            },
            endpoint: None,
            spec_version: Version(0),
            previous_spec: None,
            update_status: None,
        }
    }

    fn sample_task(service: &Service) -> Task {
        Task {
            id: Id::generate(),
            meta: Meta::new(),
            spec: service.spec.task.clone(),
            spec_version: Some(Version(7)),
            service_id: Some(service.id.clone()),
            slot: 1,
            node_id: Some(Id::generate()),
            annotations: Annotations::default(),
            service_annotations: service.spec.annotations.clone(),
            status: TaskStatus::new(TaskState::New, "created"),
            desired_state: DesiredState::Running,
            networks: vec![NetworkAttachment {
                network_id: Id::generate(),
                addresses: vec!["10.100.0.5/24".to_owned()],
                aliases: vec![],
            }],
            endpoint: None,
            job_iteration: None,
        }
    }

    #[test]
    fn task_serde_roundtrip() {
        let service = sample_service();
        let task = sample_task(&service);
        let json = serde_json::to_string(&task).unwrap();
        let back: Task = serde_json::from_str(&json).unwrap();
        assert_eq!(task, back);
    }

    #[test]
    fn service_serde_roundtrip() {
        let service = sample_service();
        let json = serde_json::to_string(&service).unwrap();
        let back: Service = serde_json::from_str(&json).unwrap();
        assert_eq!(service, back);
    }

    #[test]
    fn mount_kind_serializes_as_type() {
        let mount = Mount {
            kind: MountType::Bind,
            source: Some("/data".to_owned()),
            target: "/data".to_owned(),
            read_only: true,
        };
        let json = serde_json::to_value(&mount).unwrap();
        assert_eq!(json["type"], "bind");
    }

    #[test]
    fn update_config_defaults_match_swarmkit() {
        let update = UpdateConfig::default();
        assert_eq!(update.parallelism, 1);
        assert_eq!(update.failure_action, FailureAction::Pause);
        assert_eq!(update.monitor, Duration::from_secs(5));
        assert_eq!(update.order, UpdateOrder::StopFirst);
    }

    #[test]
    fn restart_policy_defaults_match_swarmkit() {
        let restart = RestartPolicy::default();
        assert_eq!(restart.condition, RestartCondition::Any);
        assert_eq!(restart.delay, Duration::from_secs(5));
        assert_eq!(restart.max_attempts, 0);
    }

    #[test]
    fn secret_size_limits() {
        let annotations = Annotations {
            name: "s".to_owned(),
            labels: BTreeMap::new(),
        };
        assert!(SecretSpec::new(annotations.clone(), vec![1]).is_ok());
        assert!(SecretSpec::new(annotations.clone(), vec![0; MAX_SECRET_SIZE - 1]).is_ok());
        assert_eq!(
            SecretSpec::new(annotations.clone(), Vec::new()).unwrap_err(),
            ValidationError::SecretDataSize {
                size: 0,
                max: MAX_SECRET_SIZE,
            }
        );
        assert_eq!(
            SecretSpec::new(annotations, vec![0; MAX_SECRET_SIZE]).unwrap_err(),
            ValidationError::SecretDataSize {
                size: MAX_SECRET_SIZE,
                max: MAX_SECRET_SIZE,
            }
        );
    }

    #[test]
    fn config_size_limits() {
        let annotations = Annotations {
            name: "c".to_owned(),
            labels: BTreeMap::new(),
        };
        assert!(ConfigSpec::new(annotations.clone(), vec![1]).is_ok());
        assert!(ConfigSpec::new(annotations.clone(), vec![0; MAX_CONFIG_SIZE - 1]).is_ok());
        assert!(ConfigSpec::new(annotations.clone(), Vec::new()).is_err());
        assert_eq!(
            ConfigSpec::new(annotations, vec![0; MAX_CONFIG_SIZE]).unwrap_err(),
            ValidationError::ConfigDataSize {
                size: MAX_CONFIG_SIZE,
                max: MAX_CONFIG_SIZE,
            }
        );
    }

    #[test]
    fn secret_debug_never_prints_data() {
        let spec = SecretSpec::new(
            Annotations {
                name: "db.password".to_owned(),
                labels: BTreeMap::new(),
            },
            b"hunter2-hunter2".to_vec(),
        )
        .unwrap();
        let secret = Secret {
            id: Id::generate(),
            meta: Meta::new(),
            spec,
        };
        let debug = format!("{secret:?}");
        assert!(!debug.contains("hunter2"), "payload leaked: {debug}");
        assert!(debug.contains("redacted"), "{debug}");
        assert!(debug.contains("15 bytes"), "{debug}");
    }

    #[test]
    fn secret_validate_catches_deserialized_oversize() {
        let spec = SecretSpec {
            annotations: Annotations::default(),
            data: vec![0; MAX_SECRET_SIZE],
        };
        // Simulates data arriving via serde, which bypasses `new`.
        assert!(spec.validate().is_err());
    }

    #[test]
    fn port_protocol_display_matches_serde() {
        for protocol in [PortProtocol::Tcp, PortProtocol::Udp] {
            let json = serde_json::to_string(&protocol).unwrap();
            assert_eq!(json, format!("\"{protocol}\""));
        }
        assert_eq!(format!("8080/{}", PortProtocol::Tcp), "8080/tcp");
    }

    #[test]
    fn endpoint_mode_defaults_to_dnsrr_and_serializes_lowercase() {
        assert_eq!(EndpointMode::default(), EndpointMode::DnsRR);
        assert_eq!(
            serde_json::to_string(&EndpointMode::DnsRR).unwrap(),
            "\"dnsrr\""
        );
    }

    #[test]
    fn cluster_serde_roundtrip() {
        let cluster = Cluster {
            id: Id::generate(),
            meta: Meta::new(),
            spec: ClusterSpec {
                annotations: Annotations {
                    name: "default".to_owned(),
                    labels: BTreeMap::new(),
                },
                raft: RaftConfig::default(),
                dispatcher: DispatcherConfig::default(),
                ca: CaConfig::default(),
                task_defaults: TaskDefaults::default(),
                default_address_pool: vec!["10.100.0.0/14".to_owned()],
                subnet_size: 24,
                autolock: false,
                unlock_key: None,
            },
            join_tokens: JoinTokens::default(),
            blacklisted_certs: BTreeMap::new(),
            root_ca_cert: None,
            encrypted_root_ca_key: None,
            root_rotation: None,
        };
        let json = serde_json::to_string(&cluster).unwrap();
        let back: Cluster = serde_json::from_str(&json).unwrap();
        assert_eq!(cluster, back);
    }

    #[test]
    fn node_serde_roundtrip() {
        let node = Node {
            id: Id::generate(),
            meta: Meta::new(),
            spec: NodeSpec {
                name: None,
                labels: BTreeMap::from([("zone".to_owned(), "a".to_owned())]),
                role: NodeRole::Manager,
                availability: Availability::Active,
            },
            description: Some(NodeDescription {
                hostname: "alpha".to_owned(),
                platform: Platform {
                    os: "freebsd".to_owned(),
                    arch: "amd64".to_owned(),
                },
                resources: Resources {
                    nano_cpus: 4_000_000_000,
                    memory_bytes: 8 * 1024 * 1024 * 1024,
                },
                engine: EngineDescription {
                    version: "0.1.0".to_owned(),
                    labels: BTreeMap::new(),
                },
                linux_emulation: true,
                racct_enabled: false,
                data_addr: Some("10.2.0.11".to_owned()),
            }),
            status: NodeStatus {
                state: NodeState::Ready,
                message: String::new(),
                addr: "10.2.0.11".to_owned(),
            },
            manager_status: Some(ManagerStatus {
                raft_id: 0xdead_beef,
                addr: "10.2.0.11:2377".to_owned(),
                leader: true,
                reachability: Reachability::Reachable,
            }),
            certificate_status: CertificateStatus::default(),
            certificate_issuer: None,
        };
        let json = serde_json::to_string(&node).unwrap();
        let back: Node = serde_json::from_str(&json).unwrap();
        assert_eq!(node, back);
    }

    /// A node description written before [`NodeDescription::data_addr`] existed
    /// must still load: it sits in raft log entries and snapshots that a manager
    /// replays at startup, and a decode failure there is an unstartable cluster,
    /// not a missing address.
    #[test]
    fn a_node_description_without_an_underlay_address_still_loads() {
        let older = r#"{
            "hostname": "alpha",
            "platform": {"os": "freebsd", "arch": "amd64"},
            "resources": {"nano_cpus": 4000000000, "memory_bytes": 8589934592},
            "engine": {"version": "0.1.0", "labels": {}},
            "linux_emulation": true,
            "racct_enabled": true
        }"#;
        let description: NodeDescription = serde_json::from_str(older).expect("older description");
        assert_eq!(description.data_addr, None);
    }

    #[test]
    fn network_serde_roundtrip() {
        let network = Network {
            id: Id::generate(),
            meta: Meta::new(),
            spec: NetworkSpec {
                annotations: Annotations {
                    name: "backend".to_owned(),
                    labels: BTreeMap::new(),
                },
                driver: NetworkDriver::Overlay,
                ipam: Some(IpamConfig {
                    subnet: Some("10.100.4.0/24".to_owned()),
                    gateway: None,
                    ip_range: None,
                }),
                internal: false,
                attachable: false,
                ingress: false,
                encrypted: true,
            },
            vni: Some(4098),
            vxlan_port: Some(4790),
            subnet: Some("10.100.4.0/24".to_owned()),
            node_gateways: BTreeMap::from([
                (Id::generate(), "10.100.4.2".to_owned()),
                (Id::generate(), "10.100.4.3".to_owned()),
            ]),
            keys: vec![NetworkKey {
                tag: 0x5a71_c0de,
                key: [7; 16],
                primary: true,
            }],
            keys_updated_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
        };
        let json = serde_json::to_string(&network).unwrap();
        let back: Network = serde_json::from_str(&json).unwrap();
        assert_eq!(network, back);
    }

    /// A spec written before data-plane encryption existed must still load: it
    /// sits in raft log entries and snapshots that a manager replays at
    /// startup, and a decode failure there is an unstartable cluster.
    #[test]
    fn a_network_spec_without_an_encrypted_flag_still_loads() {
        let older = r#"{
            "annotations": {"name": "blue", "labels": {}},
            "driver": "overlay",
            "ipam": null,
            "internal": false,
            "attachable": false,
            "ingress": false
        }"#;
        let spec: NetworkSpec = serde_json::from_str(older).expect("older spec");
        assert!(!spec.encrypted, "absent means not encrypted");
    }

    /// The dispatcher ships the ingress assignment to **every** node, task or
    /// not (SWK §9.1: every node is a mesh load balancer). That broadcast is
    /// why the default ingress must never be encrypted — a keyring on it
    /// would reach the whole cluster, participant or not. There is no
    /// network-update path that could flip the flag on an existing network,
    /// and the API rejects a second ingress network; this test pins the one
    /// construction site.
    #[test]
    fn the_default_ingress_network_is_never_encrypted() {
        let ingress = Network::default_ingress();
        assert!(ingress.spec.ingress);
        assert!(
            !ingress.spec.encrypted,
            "ingress is broadcast to every node: it must stay unencrypted"
        );
        assert!(ingress.keys.is_empty());
    }

    /// Same compat story one level up: a `Network` without the encryption
    /// fields (keyring, keyring timestamp, VXLAN port) loads with an empty
    /// keyring and no allocator-assigned port.
    #[test]
    fn a_network_without_a_keyring_still_loads() {
        let mut json = serde_json::to_value(Network::default_ingress()).unwrap();
        let object = json.as_object_mut().unwrap();
        // The older shape: none of the encryption fields existed.
        object.remove("keys");
        object.remove("keys_updated_at");
        object.remove("vxlan_port");
        object["spec"].as_object_mut().unwrap().remove("encrypted");
        let network: Network = serde_json::from_value(json).expect("older network");
        assert!(!network.spec.encrypted);
        assert!(network.keys.is_empty());
        assert_eq!(network.keys_updated_at, None);
        assert_eq!(network.vxlan_port, None);
    }
}
