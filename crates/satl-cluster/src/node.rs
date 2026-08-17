// SPDX-License-Identifier: BSD-2-Clause
//! Raft node lifecycle: identity, storage bring-up, openraft configuration,
//! single-node bootstrap and leader seeding (architecture §1.2, §6).

// Triaged pedantic allow: `NodeError` carries `PathBuf`s so operator-facing
// messages can name the file involved; every function returning it runs
// once, at startup — boxing would be noise, not savings.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use openraft::error::{InitializeError, RaftError};
use openraft::{BasicNode, Raft, ServerState, SnapshotPolicy};
use rand::RngExt;

use satl_core::defaults::{MAX_TX_BYTES, RAFT_SLOW_FOLLOWER_ENTRIES, RAFT_SNAPSHOT_INTERVAL};
use satl_core::{
    Annotations, Availability, CaConfig, CertificateStatus, Cluster, ClusterSpec, DispatcherConfig,
    Id, InvalidId, JoinTokens, ManagerStatus, Meta, Node, NodeRole, NodeSpec, NodeState,
    NodeStatus, RaftConfig, Reachability, StoreAction, StoreObject, TaskDefaults,
};

use satl_ca::LiveIdentity;
use satl_proto::MAX_MESSAGE_SIZE;
use satl_proto::v1::control_client::ControlClient;

use crate::crypto::{DEK_FILE, Dek, DekError};
use crate::forward::{LeaderClient, leader_addr_from_status};
use crate::fs_util::atomic_write;
use crate::log_store::{LOG_FILE_NAME, LogStore, LogStoreError};
use crate::server::{
    Authorizer, DEFAULT_PORT, HEALTH_SERVICE_CONTROL, HEALTH_SERVICE_RAFT, HealthRegistry,
    ManagerContext, ManagerSlot, ServerBuilder, ServerError, ServerHandle,
};
use crate::state_machine::{SNAPSHOT_FILE_NAME, StateMachine, StateMachineError};
use crate::store::{ClusterStore, ProposeError};
use crate::transport::{PeerChannels, RaftTransport, TransportError};
use crate::types::TypeConfig;

/// Filename of the persisted SatL node ID inside the raft directory.
const NODE_ID_FILE: &str = "node-id";

/// Filename of the persisted Raft member ID inside the raft directory.
const RAFT_ID_FILE: &str = "raft-id";

/// How long `start` waits for this node to become leader before giving up.
/// Single-node leadership is immediate (election on `initialize`, resumed
/// from the committed vote on restart); this bound only turns a bug into an
/// actionable error instead of a hang.
const LEADERSHIP_TIMEOUT: Duration = Duration::from_mins(1);

/// Default overlay address pool (architecture §15). Local until the
/// allocator lands (M3), at which point it moves to `satl_core::defaults`.
const DEFAULT_ADDRESS_POOL: &str = "10.100.0.0/14";

/// Default overlay subnet prefix length (architecture §15). See
/// [`DEFAULT_ADDRESS_POOL`].
const DEFAULT_SUBNET_SIZE: u8 = 24;

/// Size of one snapshot chunk on the wire.
///
/// openraft splits a snapshot into chunks itself and each chunk travels in
/// one unary `InstallSnapshot` message alongside the vote and the snapshot
/// metadata, so this must stay **comfortably** below
/// [`satl_proto::MAX_MESSAGE_SIZE`] (4 MiB) with room for CBOR framing.
/// A unit test in `transport` pins the relationship.
pub const SNAPSHOT_MAX_CHUNK_SIZE: u64 = 1024 * 1024;

/// How many log entries one `AppendEntries` may carry.
///
/// openraft bounds a replication batch by **count** (its default is 300)
/// while SatL bounds one transaction — one entry — by **bytes**
/// ([`MAX_TX_BYTES`], 1.5 MiB, SWK §10.5). A batch is therefore worth
/// `count x 1.5 MiB` in the worst case, and a message over
/// [`satl_proto::MAX_MESSAGE_SIZE`] (4 MiB) does not fail gracefully: the
/// receiver resets the stream, the sender reports `Internal: h2 protocol
/// error`, and openraft rebuilds the *same* oversized batch on every retry —
/// for ever. Nothing in the protocol shrinks it.
///
/// Who hits it: a manager whose log is behind by more than 4 MiB of entries,
/// which is precisely a manager that just rejoined (it replicates from index
/// 0) or one that was down while large objects were written. Measured on the
/// test cluster with openraft's default of 300: a manager rejoining a cluster
/// whose log held ~1100 entries, several hundred of them 64 KiB configs, never
/// received anything — `h2 protocol error` roughly three times a second on the
/// leader and, two minutes in, `learner never acknowledged replication; it
/// stays a learner and does not count towards quorum`. With the batch bounded
/// it caught up in seconds.
///
/// So the batch is derived from the two limits instead of left at openraft's
/// default, and the worst case is arithmetic rather than luck. Raising
/// `MAX_MESSAGE_SIZE` raises it in step; a unit test pins the relationship.
/// The cost is round-trips on a *catch-up* only: a healthy follower is one or
/// two entries behind, and a rebuilding one pays one LAN round-trip per pair
/// of entries.
const RAFT_MAX_PAYLOAD_ENTRIES: u64 = {
    let entries = (MAX_MESSAGE_SIZE / MAX_TX_BYTES) as u64;
    if entries == 0 { 1 } else { entries }
};

/// How long [`RaftNode::join`] waits for the leader to admit it.
const JOIN_TIMEOUT: Duration = Duration::from_mins(1);

/// Errors starting or stopping the Raft node. Messages name the file or
/// subsystem involved.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// Filesystem error in the raft directory.
    #[error("{path}: {op}: {source}")]
    Io {
        /// The file or directory involved.
        path: PathBuf,
        /// What was being attempted.
        op: &'static str,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The node-id file exists but does not contain a valid ID.
    #[error(
        "node ID file {path} is corrupt: {source}; restore it or remove the raft directory to re-initialize the node"
    )]
    CorruptNodeId {
        /// The node-id file.
        path: PathBuf,
        /// Why the contents were rejected.
        #[source]
        source: InvalidId,
    },
    /// The raft-id file exists but does not contain a valid nonzero u64.
    #[error(
        "raft ID file {path} is corrupt ({message}); restore it or remove the raft directory to re-initialize the node"
    )]
    CorruptRaftId {
        /// The raft-id file.
        path: PathBuf,
        /// Why the contents were rejected.
        message: String,
    },
    /// The DEK could not be loaded or created.
    #[error(transparent)]
    Dek(#[from] DekError),
    /// The log database could not be opened.
    #[error(transparent)]
    LogStore(#[from] LogStoreError),
    /// The persisted snapshot could not be loaded.
    #[error(transparent)]
    StateMachine(#[from] StateMachineError),
    /// The openraft configuration was rejected.
    #[error("invalid raft configuration: {source}")]
    Config {
        /// Underlying openraft config error.
        #[source]
        source: openraft::ConfigError,
    },
    /// Openraft failed to start or initialize.
    #[error("raft {op}: {message}")]
    Raft {
        /// What was being attempted.
        op: &'static str,
        /// Openraft error text.
        message: String,
    },
    /// Seeding the default Cluster/Node objects failed.
    #[error("seeding cluster state: {source}")]
    Seed {
        /// Underlying propose error.
        #[source]
        source: ProposeError,
    },
    /// The node did not gain leadership within [`LEADERSHIP_TIMEOUT`].
    #[error(
        "node did not become raft leader within {timeout:?}; single-node leadership should be immediate. Inspect raft logs"
    )]
    LeadershipTimeout {
        /// How long was waited.
        timeout: Duration,
    },
    /// A blocking startup task panicked or was cancelled.
    #[error("startup task for {op} failed: {message}")]
    Task {
        /// What was being attempted.
        op: &'static str,
        /// Join error text.
        message: String,
    },
    /// The internal gRPC server could not be started.
    #[error(transparent)]
    Server(#[from] ServerError),
    /// The raft transport could not be built.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// [`RaftNode::join`] was called without TLS material.
    #[error(
        "joining an existing cluster needs this node's mTLS identity: set \
         RaftNodeConfig::identity from the certificate the CA issued at join time"
    )]
    MissingIdentity,
    /// [`RaftNode::join`] was called on a node that already belongs to a
    /// cluster (architecture §1.2's dirty-state rule, SWK §12.3).
    #[error(
        "refusing to join {remote}: this node already holds cluster state ({reason}). A node \
         joins once, from a clean raft directory. Restart it with `start` to resume its \
         existing cluster, or wipe {raft_dir} to re-join as a new member"
    )]
    DirtyState {
        /// The address that was to be joined.
        remote: String,
        /// What was found locally.
        reason: String,
        /// The raft directory holding it.
        raft_dir: PathBuf,
    },
    /// The raft directory belongs to a different node than the certificate.
    #[error(
        "node ID file {path} says this node is {stored}, but its certificate was issued to \
         {certificate}: the raft directory and the TLS identity belong to different nodes \
         (architecture section 12.1 pins CN = node ID)"
    )]
    IdentityMismatch {
        /// The node-id file.
        path: PathBuf,
        /// What the file says.
        stored: String,
        /// What the certificate says.
        certificate: String,
    },
    /// This node's own certificate could not be read.
    #[error("reading this node's own certificate: {source}")]
    Identity {
        /// Underlying parse failure.
        #[from]
        source: satl_ca::PeerIdentityError,
    },
    /// The leader refused the join, or could not be reached.
    #[error("joining the cluster through {remote}: {message}")]
    Join {
        /// The address that was dialed.
        remote: String,
        /// What the leader said, or what went wrong reaching it.
        message: String,
    },
    /// Sealed raft state with no key beside it: a restore that left the DEK
    /// behind. Minting a new key here would make the state permanently
    /// unreadable, so it is refused (architecture §12.4).
    #[error(
        "the raft state in {raft_dir} is sealed but its key file is missing: {dek}. {found} \
         cannot be read without it, and satld will not create a new key over sealed data. \
         Restore the key file from the same backup as the rest of {raft_dir} (it is per-node \
         and never shared: another manager's key does not open this one's state). If this \
         node's cluster state is unrecoverable, empty {raft_dir} instead and re-join the node"
    )]
    MissingDek {
        /// The raft state directory.
        raft_dir: PathBuf,
        /// The key file that should be there.
        dek: PathBuf,
        /// The sealed files found beside it.
        found: String,
    },
}

/// Raft tick timings (architecture §15, SWK §11.2).
///
/// The defaults map SwarmKit's tick model — `TickInterval` 1 s,
/// `HeartbeatTick` 1, `ElectionTick` 10 — onto openraft's millisecond
/// configuration, with the election timeout randomized in `[t, 2t)` exactly
/// as SwarmKit randomizes it.
///
/// [`RaftTiming::fast`] exists so in-process tests can watch an election
/// happen in milliseconds instead of tens of seconds. It is **not** a
/// supported production setting: a 200 ms election timeout on a real network
/// turns ordinary jitter into spurious elections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaftTiming {
    /// Heartbeat interval, milliseconds.
    pub heartbeat_interval_ms: u64,
    /// Shortest election timeout, milliseconds.
    pub election_timeout_min_ms: u64,
    /// Longest election timeout, milliseconds.
    pub election_timeout_max_ms: u64,
}

impl RaftTiming {
    /// SwarmKit's timings: heartbeat 1 s, election 10–20 s.
    #[must_use]
    pub const fn swarmkit() -> Self {
        Self {
            heartbeat_interval_ms: 1_000,
            election_timeout_min_ms: 10_000,
            election_timeout_max_ms: 20_000,
        }
    }

    /// Test-scale timings: heartbeat 50 ms, election 300–600 ms.
    #[must_use]
    pub const fn fast() -> Self {
        Self {
            heartbeat_interval_ms: 50,
            election_timeout_min_ms: 300,
            election_timeout_max_ms: 600,
        }
    }

    /// How long a peer counts as reachable for quorum arithmetic after its
    /// last answer (SWK §11.5's `transport.Active`).
    ///
    /// One election timeout: a member that has not answered for that long is
    /// either campaigning or gone, and either way must not be counted on to
    /// keep quorum after someone else is removed.
    #[must_use]
    pub const fn liveness_window(self) -> Duration {
        Duration::from_millis(self.election_timeout_max_ms)
    }
}

impl Default for RaftTiming {
    fn default() -> Self {
        Self::swarmkit()
    }
}

/// Configuration for [`RaftNode::start`] and [`RaftNode::join`].
///
/// [`RaftNodeConfig::default`] is a single-node configuration with no
/// internal listener: that is the M1 shape, and it is what
/// `..Default::default()` in a struct literal gives you.
#[derive(Debug, Clone)]
pub struct RaftNodeConfig {
    /// Directory holding raft state: log database, snapshot, DEK, identity
    /// files. On production nodes this is the dedicated ZFS dataset mounted
    /// at `/var/db/satl/raft` (architecture §6.3).
    pub raft_dir: PathBuf,
    /// This node's name (hostname). Also the `BasicNode` address when no
    /// [`RaftNodeConfig::advertise_addr`] is set (single-node clusters).
    pub node_name: String,
    /// Address the internal gRPC server binds. `None` means **no server**:
    /// the node has no peers, the transport is offline and nothing listens.
    /// Multi-node clusters set `0.0.0.0:2377` (architecture §7, §15).
    pub listen_addr: Option<SocketAddr>,
    /// `host:port` this node tells peers to dial — what lands in
    /// `BasicNode.addr` and in `ManagerStatus.addr`. Empty means "let the
    /// leader substitute the address it sees this node connect from"
    /// (SWK §11.3).
    pub advertise_addr: String,
    /// This node's mTLS identity (architecture §12.1), in its **live**,
    /// renewal-swappable form (§12.3): the server and every peer channel
    /// resolve their certificate through it per handshake, so the renewal
    /// loop swaps it once and this whole node follows. Required whenever
    /// [`RaftNodeConfig::listen_addr`] is set, and by [`RaftNode::join`].
    pub identity: Option<Arc<LiveIdentity>>,
    /// Raft tick timings. Leave at the default outside tests.
    pub timing: RaftTiming,
    /// An already-loaded DEK — a manager that booted through autolock's
    /// `POST /swarm/unlock` hands its unsealed key in here, and no plain
    /// `dek` file is read or created. `None` keeps the default path
    /// ([`Dek::load_or_create`] on `<raft_dir>/dek`).
    pub dek: Option<Dek>,
}

impl Default for RaftNodeConfig {
    fn default() -> Self {
        Self {
            raft_dir: PathBuf::new(),
            node_name: String::new(),
            listen_addr: None,
            advertise_addr: String::new(),
            identity: None,
            timing: RaftTiming::default(),
            dek: None,
        }
    }
}

impl RaftNodeConfig {
    /// The address peers dial: the advertise address if set, the node name
    /// otherwise (the M1 shape, where the "address" is only ever a label).
    fn peer_addr(&self) -> String {
        if self.advertise_addr.is_empty() {
            self.node_name.clone()
        } else {
            self.advertise_addr.clone()
        }
    }
}

/// A running Raft node. Dropping it does not stop Raft — call
/// [`RaftNode::shutdown`].
pub struct RaftNode {
    raft: Raft<TypeConfig>,
    node_id: Id,
    raft_id: u64,
    /// The DEK this node's storage was opened with (see
    /// [`RaftNodeConfig::dek`]).
    dek: Dek,
    role_watcher: tokio::task::JoinHandle<()>,
    manager: ManagerSlot,
    health: HealthRegistry,
    server: Option<ServerHandle>,
}

/// Storage opened and ready to hand to openraft.
struct OpenStorage {
    node_id: Id,
    raft_id: u64,
    /// The key everything below was opened with — kept so the autolock
    /// watcher can seal it (or write it back) without re-reading disk.
    dek: Dek,
    log_store: LogStore,
    state_machine: StateMachine,
}

impl RaftNode {
    /// Starts (or restarts) the node from `cfg.raft_dir`.
    ///
    /// Bring-up: load-or-create identity and DEK → open log store and state
    /// machine (reloading the persisted snapshot) → start openraft → start
    /// the internal gRPC server if this node has one → initialize
    /// single-node membership on first boot → await leadership → seed the
    /// `default` Cluster and this node's Node object if absent (architecture
    /// §1.2). All steps are idempotent across restarts.
    ///
    /// Leadership is awaited and seeding is attempted **only when this node
    /// is the sole voter**. A member of a multi-node cluster comes back as a
    /// follower and must not block startup waiting for an election it may
    /// never win.
    pub async fn start(cfg: RaftNodeConfig) -> Result<(ClusterStore, RaftNode), NodeError> {
        Self::start_with_services(cfg, |builder| builder).await
    }

    /// [`RaftNode::start`], letting the caller register additional gRPC
    /// services on the **same** internal server (architecture §7).
    ///
    /// `register` receives the builder after `Raft`, `Control` and `Health`
    /// have been added and returns it with the caller's services on it:
    ///
    /// ```ignore
    /// RaftNode::start_with_services(cfg, |b| {
    ///     b.add_service(RoleRequirement::WorkerOrManager, dispatcher)
    ///      .add_service(RoleRequirement::Any, node_ca)
    /// }).await
    /// ```
    ///
    /// It is not called at all when the node runs without a listener.
    pub async fn start_with_services<F>(
        cfg: RaftNodeConfig,
        register: F,
    ) -> Result<(ClusterStore, RaftNode), NodeError>
    where
        F: FnOnce(ServerBuilder) -> ServerBuilder + Send,
    {
        let peer_addr = cfg.peer_addr();
        let dek = cfg.dek.clone();
        let storage =
            open_storage(cfg.raft_dir.clone(), None, certificate_node_id(&cfg)?, dek).await?;
        let OpenStorage {
            node_id,
            raft_id,
            dek,
            log_store,
            state_machine,
        } = storage;
        tracing::info!(
            node_id = %node_id,
            raft_id,
            raft_dir = %cfg.raft_dir.display(),
            "raft storage opened"
        );

        let store_handle = state_machine.store_handle();
        let event_sender = state_machine.event_sender();

        let transport = build_transport(raft_id, cfg.identity.as_ref())?;
        let raft = start_raft(
            raft_id,
            cfg.timing,
            transport.clone(),
            log_store,
            state_machine,
        )
        .await?;
        let role_watcher = spawn_role_watcher(&raft);
        let store = ClusterStore::new(store_handle, event_sender, raft.clone());

        let manager = ManagerSlot::new();
        manager.install(ManagerContext {
            raft: raft.clone(),
            store: store.clone(),
            node_id: node_id.clone(),
            raft_id,
            advertise_addr: peer_addr.clone(),
            liveness: transport.liveness(),
            liveness_window: cfg.timing.liveness_window(),
            channels: transport.channels(),
        });

        let ServerParts {
            server,
            health,
            authorizer,
        } = start_server(&cfg, &manager, register).await?;
        // The certificate blacklist lives on the `Cluster` object, so the
        // authorizer can only enforce it once the store exists.
        if let Some(authorizer) = &authorizer {
            authorizer.attach_store(store.clone());
        }
        health.set_serving(HEALTH_SERVICE_RAFT);

        // Single-node bootstrap. Only on a pristine node; restarts carry
        // membership in the log/snapshot and must not re-initialize.
        let initialized = raft.is_initialized().await.map_err(|e| NodeError::Raft {
            op: "query initialization",
            message: e.to_string(),
        })?;
        if initialized {
            tracing::info!(raft_id, "raft state found, resuming existing cluster");
        } else {
            tracing::info!(
                raft_id,
                node_name = cfg.node_name,
                addr = peer_addr,
                "pristine node, initializing single-node cluster"
            );
            let members = BTreeMap::from([(raft_id, BasicNode::new(peer_addr.clone()))]);
            match raft.initialize(members).await {
                // NotAllowed = lost a race with a concurrent initialize; the
                // cluster is formed either way (openraft documents this as
                // safe to ignore).
                Ok(()) | Err(RaftError::APIError(InitializeError::NotAllowed(_))) => {}
                Err(e) => {
                    return Err(NodeError::Raft {
                        op: "initialize",
                        message: e.to_string(),
                    });
                }
            }
        }

        // Leadership + seeding (architecture §1.2). Sole voter only: a
        // follower in a formed cluster neither waits nor seeds.
        if is_sole_voter(&raft, raft_id) {
            wait_for_leadership(&raft).await?;
            seed_cluster_state(&store, &node_id, raft_id, &cfg.node_name, &peer_addr)
                .await
                .map_err(|source| NodeError::Seed { source })?;
        } else {
            tracing::info!(
                raft_id,
                "node is part of a multi-node cluster; leadership and seeding are the cluster's business"
            );
        }
        health.set_serving(HEALTH_SERVICE_CONTROL);

        let node = RaftNode {
            raft,
            node_id,
            raft_id,
            dek,
            role_watcher,
            manager,
            health,
            server,
        };
        Ok((store, node))
    }

    /// Joins an **existing** cluster through `remote_addr` (architecture
    /// §6.6, SWK §11.3).
    ///
    /// Sequence, and the order matters:
    ///
    /// 1. refuse if this node already holds cluster state — architecture
    ///    §1.2's dirty-state rule: a node joins once, from a clean raft
    ///    directory (`SWK §12.3`'s `IsStateDirty`);
    /// 2. start the internal gRPC server **first**, because the leader
    ///    health-checks the joiner back before admitting it and the joiner
    ///    has no raft ID to start openraft with until the leader answers;
    /// 3. call `Control.JoinRaft`, following at most one redirect to the
    ///    leader;
    /// 4. persist the assigned raft ID, then start openraft — **without**
    ///    initializing: membership arrives by replication.
    pub async fn join(
        cfg: RaftNodeConfig,
        remote_addr: &str,
    ) -> Result<(ClusterStore, RaftNode), NodeError> {
        Self::join_with_services(cfg, remote_addr, |builder| builder).await
    }

    /// [`RaftNode::join`] with the same service-registration seam as
    /// [`RaftNode::start_with_services`].
    pub async fn join_with_services<F>(
        cfg: RaftNodeConfig,
        remote_addr: &str,
        register: F,
    ) -> Result<(ClusterStore, RaftNode), NodeError>
    where
        F: FnOnce(ServerBuilder) -> ServerBuilder + Send,
    {
        let identity = cfg.identity.clone().ok_or(NodeError::MissingIdentity)?;
        let mut cfg = cfg;
        if cfg.listen_addr.is_none() {
            cfg.listen_addr = Some(SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)));
        }
        let peer_addr = cfg.peer_addr();

        // Step 1: dirty-state check, before anything is written.
        let storage = open_storage(
            cfg.raft_dir.clone(),
            Some(0),
            certificate_node_id(&cfg)?,
            cfg.dek.clone(),
        )
        .await?;
        let OpenStorage {
            node_id,
            raft_id: existing_raft_id,
            dek,
            log_store,
            state_machine,
        } = storage;
        if let Some(reason) = dirty_state_reason(&state_machine, &node_id, existing_raft_id) {
            return Err(NodeError::DirtyState {
                remote: remote_addr.to_owned(),
                reason,
                raft_dir: cfg.raft_dir.clone(),
            });
        }

        // Step 2: the server, with an empty manager slot. `Raft` and
        // `Control` answer UNAVAILABLE until the raft node exists; `Health`
        // answers, which is exactly what the leader probes.
        let manager = ManagerSlot::new();
        let ServerParts {
            server,
            health,
            authorizer,
        } = start_server(&cfg, &manager, register).await?;
        // The listener is up and the mTLS credentials are loaded, so the
        // leader's `Health.Check("raft")` can succeed. Marking `raft` SERVING
        // here rather than after openraft starts is deliberate: the probe
        // exists to prove the leader can reach this node, and the joiner
        // cannot start openraft before the leader has answered with its raft
        // ID. See `proto/control.proto` step 2.
        health.set_serving(HEALTH_SERVICE_RAFT);

        // Step 3: ask to be admitted.
        let channels = PeerChannels::new(&identity)?;
        let joined = join_cluster(&channels, remote_addr, &node_id, &peer_addr).await?;
        tracing::info!(
            node_id = %node_id,
            raft_id = joined.raft_id,
            remote = remote_addr,
            members = joined.members.len(),
            removed = joined.removed_members.len(),
            "admitted to the raft group"
        );

        // Step 4: persist the assigned ID and start openraft. No
        // initialization: this node is not forming a cluster, it is joining
        // one, and membership arrives with the first replicated entries.
        let raft_id = joined.raft_id;
        {
            let raft_dir = cfg.raft_dir.clone();
            tokio::task::spawn_blocking(move || write_raft_id(&raft_dir, raft_id))
                .await
                .map_err(|e| NodeError::Task {
                    op: "persist the assigned raft ID",
                    message: e.to_string(),
                })??;
        }

        let store_handle = state_machine.store_handle();
        let event_sender = state_machine.event_sender();
        let transport = RaftTransport::with_channels(raft_id, channels.clone());
        let raft = start_raft(
            raft_id,
            cfg.timing,
            transport.clone(),
            log_store,
            state_machine,
        )
        .await?;
        let role_watcher = spawn_role_watcher(&raft);
        let store = ClusterStore::new(store_handle, event_sender, raft.clone());
        if let Some(authorizer) = &authorizer {
            authorizer.attach_store(store.clone());
        }

        manager.install(ManagerContext {
            raft: raft.clone(),
            store: store.clone(),
            node_id: node_id.clone(),
            raft_id,
            advertise_addr: peer_addr,
            liveness: transport.liveness(),
            liveness_window: cfg.timing.liveness_window(),
            channels: Some(channels),
        });
        health.set_serving(HEALTH_SERVICE_CONTROL);

        let node = RaftNode {
            raft,
            node_id,
            raft_id,
            dek,
            role_watcher,
            manager,
            health,
            server,
        };
        Ok((store, node))
    }

    /// This node's SatL node ID (also the certificate CN, §12.1).
    #[must_use]
    pub fn node_id(&self) -> &Id {
        &self.node_id
    }

    /// This node's Raft member ID.
    #[must_use]
    pub fn raft_id(&self) -> u64 {
        self.raft_id
    }

    /// The DEK this node's storage was opened with. The autolock watcher
    /// seals it (or writes it back out) from here; it never touches the key
    /// file directly.
    #[must_use]
    pub fn dek(&self) -> Dek {
        self.dek.clone()
    }

    /// The address the internal gRPC listener actually bound, if this node
    /// serves one (resolves port 0 in tests).
    #[must_use]
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.server.as_ref().map(ServerHandle::local_addr)
    }

    /// The manager context slot, so other subsystems can build gRPC services
    /// against this node's raft and store.
    #[must_use]
    pub fn manager_slot(&self) -> ManagerSlot {
        self.manager.clone()
    }

    /// The health registry this node serves.
    #[must_use]
    pub fn health(&self) -> HealthRegistry {
        self.health.clone()
    }

    /// A client that proposes locally when this node leads and forwards to
    /// the leader otherwise (architecture §6.5).
    #[must_use]
    pub fn leader_client(&self) -> LeaderClient {
        LeaderClient::new(self.manager.clone())
    }

    /// Corrects this node's own address in the Raft membership when it no
    /// longer matches what the node advertises.
    ///
    /// The membership records what *peers dial*, and it is written once, at
    /// `initialize`. Anything that changes the advertise address afterwards —
    /// an operator editing `satld.toml`, or a first boot that self-initialized
    /// (architecture §1.2) before the address was configured — leaves a stale
    /// entry behind, and a stale entry is not merely cosmetic: followers hand
    /// it out when redirecting agents to the leader, so a wrong value there
    /// fails every joiner with "invalid socket address" while the cluster
    /// itself looks healthy.
    ///
    /// Only the leader can rewrite membership, and only its own entry is
    /// touched: a follower's address is that follower's business, and it will
    /// heal on its own next start-up.
    ///
    /// # Errors
    ///
    /// Propagates the membership change failure. A node that is not the
    /// leader, or already correct, is a no-op.
    pub async fn heal_advertise_addr(&self, advertise_addr: &str) -> Result<bool, NodeError> {
        if advertise_addr.is_empty() || !self.is_leader() {
            return Ok(false);
        }
        let recorded = self
            .raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .get_node(&self.raft_id)
            .map(|node| node.addr.clone());
        if recorded.as_deref() == Some(advertise_addr) {
            return Ok(false);
        }
        tracing::warn!(
            raft_id = self.raft_id,
            recorded = recorded.as_deref().unwrap_or("<none>"),
            advertised = advertise_addr,
            "raft membership records a stale address for this node; correcting it"
        );
        let nodes = BTreeMap::from([(self.raft_id, BasicNode::new(advertise_addr.to_owned()))]);
        self.raft
            .change_membership(openraft::ChangeMembers::SetNodes(nodes), false)
            .await
            .map_err(|source| NodeError::Raft {
                op: "correct this node's advertise address in the membership",
                message: source.to_string(),
            })?;
        Ok(true)
    }

    /// Whether this node currently leads the cluster.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        let metrics = self.raft.metrics().borrow().clone();
        metrics.current_leader == Some(self.raft_id)
    }

    /// Stops the internal gRPC server and the Raft core, and releases the
    /// storage handles.
    pub async fn shutdown(self) -> Result<(), NodeError> {
        tracing::info!(raft_id = self.raft_id, "shutting down raft node");
        self.health.set_not_serving(HEALTH_SERVICE_CONTROL);
        self.health.set_not_serving(HEALTH_SERVICE_RAFT);
        if let Some(server) = self.server {
            server.shutdown().await?;
        }
        // Abort the watcher *first*: it reports a closed metrics channel as an
        // engine that died, and a deliberate shutdown closes that channel too.
        self.role_watcher.abort();
        let result = self.raft.shutdown().await;
        result.map_err(|e| NodeError::Raft {
            op: "shutdown",
            message: e.to_string(),
        })
    }
}

/// Opens identity, DEK and storage. All blocking I/O, off the runtime.
///
/// `assigned_raft_id` of `Some(0)` means "do not create a raft ID": the join
/// path gets its ID from the leader and must not mint one first.
///
/// `dek` of `Some` is the autolock path: the caller unsealed the key with
/// the operator's unlock key, so neither the plain-file load nor the
/// sealed-state refusal applies.
async fn open_storage(
    raft_dir: PathBuf,
    assigned_raft_id: Option<u64>,
    certificate_id: Option<Id>,
    dek: Option<Dek>,
) -> Result<OpenStorage, NodeError> {
    tokio::task::spawn_blocking(move || -> Result<OpenStorage, NodeError> {
        std::fs::create_dir_all(&raft_dir).map_err(|source| NodeError::Io {
            path: raft_dir.clone(),
            op: "create raft directory",
            source,
        })?;
        let node_id = load_or_create_node_id(&raft_dir, certificate_id.as_ref())?;
        let raft_id = match assigned_raft_id {
            Some(0) => read_raft_id(&raft_dir)?.unwrap_or(0),
            Some(id) => id,
            None => load_or_create_raft_id(&raft_dir)?,
        };
        let dek = if let Some(dek) = dek {
            dek
        } else {
            refuse_sealed_state_without_a_key(&raft_dir)?;
            Dek::load_or_create(&raft_dir.join(DEK_FILE))?
        };
        let log_store = LogStore::open(&raft_dir, dek.clone())?;
        let state_machine = StateMachine::open(&raft_dir, dek.clone())?;
        Ok(OpenStorage {
            node_id,
            raft_id,
            dek,
            log_store,
            state_machine,
        })
    })
    .await
    .map_err(|e| NodeError::Task {
        op: "storage bring-up",
        message: e.to_string(),
    })?
}

/// Refuses a raft directory that holds sealed state but no key file.
///
/// [`Dek::load_or_create`] cannot tell a first boot from a restore that left
/// the key behind: both look like "no `dek` file". Creating one over sealed
/// data turns a recoverable mistake — the key is still in the backup — into
/// state nothing can ever read, and the failure that follows is an
/// unseal error deep in the raft log store rather than a sentence naming the
/// missing file. So the check happens here, before the key is minted.
///
/// The plaintext identity files (`node-id`, `raft-id`) are deliberately **not**
/// evidence: they are written before the key on a genuine first boot, so a
/// daemon killed between those two writes must still be able to start.
fn refuse_sealed_state_without_a_key(raft_dir: &std::path::Path) -> Result<(), NodeError> {
    let dek = raft_dir.join(DEK_FILE);
    if dek.exists() {
        return Ok(());
    }
    // Only the files whose contents are sealed with the key count.
    let sealed: Vec<&str> = [LOG_FILE_NAME, SNAPSHOT_FILE_NAME]
        .into_iter()
        .filter(|name| raft_dir.join(name).exists())
        .collect();
    if sealed.is_empty() {
        return Ok(());
    }
    Err(NodeError::MissingDek {
        raft_dir: raft_dir.to_path_buf(),
        dek,
        found: sealed.join(" and "),
    })
}

/// The node ID the configured certificate was issued to, if there is one.
/// Architecture §12.1: `CN = node ID`, so this is what the raft directory
/// must agree with.
fn certificate_node_id(cfg: &RaftNodeConfig) -> Result<Option<Id>, NodeError> {
    match cfg.identity.as_ref() {
        None => Ok(None),
        Some(identity) => Ok(Some(
            satl_ca::PeerIdentity::from_pem(identity.identity().cert_pem.as_bytes())?.node_id,
        )),
    }
}

/// The raft transport: gRPC when the node has an identity, offline
/// otherwise.
fn build_transport(
    raft_id: u64,
    identity: Option<&Arc<LiveIdentity>>,
) -> Result<RaftTransport, NodeError> {
    match identity {
        Some(identity) => Ok(RaftTransport::new(raft_id, identity)?),
        None => Ok(RaftTransport::offline(raft_id)),
    }
}

/// Starts openraft with SatL's configuration.
///
/// The tick model mirrors SwarmKit's (SWK §22, architecture §15:
/// heartbeat/election/tick = 1 / 10 / 1 s): tick 1 s × `HeartbeatTick` 1 →
/// `heartbeat_interval` 1000 ms; tick 1 s × `ElectionTick` 10 → election
/// timeout 10 s, randomized in `[t, 2t)`.
async fn start_raft(
    raft_id: u64,
    timing: RaftTiming,
    transport: RaftTransport,
    log_store: LogStore,
    state_machine: StateMachine,
) -> Result<Raft<TypeConfig>, NodeError> {
    let config = openraft::Config {
        cluster_name: "satl".to_owned(),
        heartbeat_interval: timing.heartbeat_interval_ms,
        election_timeout_min: timing.election_timeout_min_ms,
        election_timeout_max: timing.election_timeout_max_ms,
        max_payload_entries: RAFT_MAX_PAYLOAD_ENTRIES,
        snapshot_policy: SnapshotPolicy::LogsSinceLast(RAFT_SNAPSHOT_INTERVAL),
        max_in_snapshot_log_to_keep: RAFT_SLOW_FOLLOWER_ENTRIES,
        snapshot_max_chunk_size: SNAPSHOT_MAX_CHUNK_SIZE,
        ..openraft::Config::default()
    };
    let config = Arc::new(
        config
            .validate()
            .map_err(|source| NodeError::Config { source })?,
    );
    Raft::<TypeConfig>::new(raft_id, config, transport, log_store, state_machine)
        .await
        .map_err(|e| NodeError::Raft {
            op: "start",
            message: e.to_string(),
        })
}

/// What [`start_server`] hands back.
struct ServerParts {
    server: Option<ServerHandle>,
    health: HealthRegistry,
    authorizer: Option<Authorizer>,
}

/// Builds and starts the internal gRPC server, if this node has one.
async fn start_server<F>(
    cfg: &RaftNodeConfig,
    manager: &ManagerSlot,
    register: F,
) -> Result<ServerParts, NodeError>
where
    F: FnOnce(ServerBuilder) -> ServerBuilder + Send,
{
    let (Some(listen_addr), Some(identity)) = (cfg.listen_addr, cfg.identity.as_ref()) else {
        // No listener: a single-node cluster with no peers to talk to. The
        // registry still exists so callers can query it uniformly.
        return Ok(ServerParts {
            server: None,
            health: HealthRegistry::new(),
            authorizer: None,
        });
    };
    let builder = ServerBuilder::new(Arc::clone(identity), listen_addr, manager)?;
    let health = builder.health();
    let authorizer = builder.authorizer();
    let builder = register(builder);
    let server = builder.serve().await?;
    Ok(ServerParts {
        server: Some(server),
        health,
        authorizer: Some(authorizer),
    })
}

/// Whether this node is the only voter in the configuration it starts with.
fn is_sole_voter(raft: &Raft<TypeConfig>, raft_id: u64) -> bool {
    let metrics = raft.metrics().borrow().clone();
    let voters: Vec<u64> = metrics.membership_config.voter_ids().collect();
    voters.is_empty() || voters == vec![raft_id]
}

/// SwarmKit's `IsStateDirty` (SWK §12.3): anything beyond the default
/// cluster object and this node's own node object means the node is already
/// part of a cluster and must not join another.
fn dirty_state_reason(
    state_machine: &StateMachine,
    node_id: &Id,
    existing_raft_id: u64,
) -> Option<String> {
    // The strongest signal, and the one that survives log compaction: a raft
    // member ID on disk means this node has already been admitted somewhere.
    // The store checks below cover the rest, but they only see what a
    // persisted snapshot restored — a node whose log has not been replayed
    // yet would otherwise look pristine.
    if existing_raft_id != 0 {
        return Some(format!("raft member ID {existing_raft_id} on disk"));
    }
    let store = state_machine.store_handle();
    let inner = store.read();
    if !inner.services.is_empty() {
        return Some(format!(
            "{} service(s) in the local store",
            inner.services.len()
        ));
    }
    if !inner.tasks.is_empty() {
        return Some(format!("{} task(s) in the local store", inner.tasks.len()));
    }
    if !inner.networks.is_empty() {
        return Some(format!(
            "{} network(s) in the local store",
            inner.networks.len()
        ));
    }
    if !inner.secrets.is_empty() {
        return Some(format!(
            "{} secret(s) in the local store",
            inner.secrets.len()
        ));
    }
    if !inner.configs.is_empty() {
        return Some(format!(
            "{} config(s) in the local store",
            inner.configs.len()
        ));
    }
    if inner.clusters.len() > 1 {
        return Some(format!(
            "{} cluster objects in the local store",
            inner.clusters.len()
        ));
    }
    if inner.nodes.keys().any(|id| id != node_id) {
        return Some(format!(
            "{} node object(s) belonging to other nodes",
            inner.nodes.keys().filter(|id| *id != node_id).count()
        ));
    }
    if !inner.removed_raft_ids.is_empty() {
        return Some("a raft removal blacklist from a previous cluster".to_owned());
    }
    if inner.last_applied.is_some() {
        return Some("applied raft entries from a previous cluster".to_owned());
    }
    None
}

/// Calls `Control.JoinRaft`, following at most one redirect to the leader
/// (SWK §11.7's one-hop loop protection).
async fn join_cluster(
    channels: &PeerChannels,
    remote_addr: &str,
    node_id: &Id,
    advertise_addr: &str,
) -> Result<satl_proto::v1::JoinRaftResponse, NodeError> {
    let mut addr = remote_addr.to_owned();
    for attempt in 1..=2 {
        let channel = channels.channel(&addr).map_err(|source| NodeError::Join {
            remote: addr.clone(),
            message: source.to_string(),
        })?;
        let mut client = ControlClient::new(channel)
            .max_decoding_message_size(MAX_MESSAGE_SIZE)
            .max_encoding_message_size(MAX_MESSAGE_SIZE);
        let request = satl_proto::v1::JoinRaftRequest {
            node_id: node_id.to_string(),
            addr: advertise_addr.to_owned(),
        };

        let call = client.join_raft(request);
        let outcome = tokio::time::timeout(JOIN_TIMEOUT, call)
            .await
            .map_err(|_| NodeError::Join {
                remote: addr.clone(),
                message: format!("no answer within {JOIN_TIMEOUT:?}"),
            })?;

        match outcome {
            Ok(response) => return Ok(response.into_inner()),
            Err(status) => {
                let redirect = (status.code() == tonic::Code::FailedPrecondition)
                    .then(|| leader_addr_from_status(&status))
                    .flatten();
                match redirect {
                    Some(leader) if attempt == 1 && leader != addr => {
                        tracing::info!(from = %addr, to = %leader, "join redirected to the leader");
                        addr = leader;
                    }
                    _ => {
                        return Err(NodeError::Join {
                            remote: addr,
                            message: format!("{:?}: {}", status.code(), status.message()),
                        });
                    }
                }
            }
        }
    }
    Err(NodeError::Join {
        remote: addr,
        message: "the join was redirected more than once; refusing to chase the leader further"
            .to_owned(),
    })
}

/// Loads or creates `<raft_dir>/node-id` (mode 0644, atomic write).
///
/// When the node has an mTLS identity, the **certificate is authoritative**:
/// architecture §12.1 pins `CN = node ID`, so the file records what the CA
/// issued rather than a locally invented value. A file that disagrees means
/// the raft directory and the certificate belong to different nodes, which is
/// refused rather than silently resolved.
fn load_or_create_node_id(
    raft_dir: &std::path::Path,
    from_certificate: Option<&Id>,
) -> Result<Id, NodeError> {
    let path = raft_dir.join(NODE_ID_FILE);
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let stored =
                contents
                    .trim()
                    .parse::<Id>()
                    .map_err(|source| NodeError::CorruptNodeId {
                        path: path.clone(),
                        source,
                    })?;
            if let Some(expected) = from_certificate
                && *expected != stored
            {
                return Err(NodeError::IdentityMismatch {
                    path,
                    stored: stored.to_string(),
                    certificate: expected.to_string(),
                });
            }
            Ok(stored)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let id = from_certificate.cloned().unwrap_or_else(Id::generate);
            atomic_write(&path, format!("{id}\n").as_bytes(), 0o644).map_err(|source| {
                NodeError::Io {
                    path,
                    op: "write node ID",
                    source,
                }
            })?;
            Ok(id)
        }
        Err(source) => Err(NodeError::Io {
            path,
            op: "read node ID",
            source,
        }),
    }
}

/// Reads `<raft_dir>/raft-id`, or `None` when the node has never been part
/// of a cluster.
fn read_raft_id(raft_dir: &std::path::Path) -> Result<Option<u64>, NodeError> {
    let path = raft_dir.join(RAFT_ID_FILE);
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let id = contents
                .trim()
                .parse::<u64>()
                .map_err(|e| NodeError::CorruptRaftId {
                    path: path.clone(),
                    message: e.to_string(),
                })?;
            if id == 0 {
                return Err(NodeError::CorruptRaftId {
                    path,
                    message: "raft IDs must be nonzero".to_owned(),
                });
            }
            Ok(Some(id))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(NodeError::Io {
            path,
            op: "read raft ID",
            source,
        }),
    }
}

/// Writes `<raft_dir>/raft-id` (mode 0644, atomic write). Used by the join
/// path, where the **leader** assigns the ID and the joiner must persist it
/// before starting its raft node (`proto/control.proto`).
fn write_raft_id(raft_dir: &std::path::Path, raft_id: u64) -> Result<(), NodeError> {
    let path = raft_dir.join(RAFT_ID_FILE);
    if raft_id == 0 {
        return Err(NodeError::CorruptRaftId {
            path,
            message: "the leader assigned raft ID 0, which is not a valid member ID".to_owned(),
        });
    }
    atomic_write(&path, format!("{raft_id}\n").as_bytes(), 0o644).map_err(|source| NodeError::Io {
        path,
        op: "write raft ID",
        source,
    })
}

/// Loads or creates `<raft_dir>/raft-id`: a random nonzero u64, never reused
/// (architecture §6.6); mode 0644, atomic write.
fn load_or_create_raft_id(raft_dir: &std::path::Path) -> Result<u64, NodeError> {
    if let Some(id) = read_raft_id(raft_dir)? {
        return Ok(id);
    }
    let mut rng = rand::rng();
    let mut id: u64 = rng.random();
    while id == 0 {
        id = rng.random();
    }
    write_raft_id(raft_dir, id)?;
    Ok(id)
}

/// Watches the metrics stream and logs Raft role transitions with
/// structured fields (CLAUDE.md observability rule).
fn spawn_role_watcher(raft: &Raft<TypeConfig>) -> tokio::task::JoinHandle<()> {
    let mut rx = raft.metrics();
    tokio::spawn(async move {
        let (mut last_state, mut last_leader) = {
            let m = rx.borrow();
            (m.state, m.current_leader)
        };
        loop {
            if rx.changed().await.is_err() {
                // The metrics channel closes when the raft engine stops. A
                // deliberate shutdown aborts this task before stopping raft
                // (see `RaftNode::shutdown`), so reaching here means the
                // engine quit on its own — openraft treats any storage error
                // as fatal and exits `RaftCore::main`. Nothing restarts it:
                // this manager will not lead, replicate or accept a cluster
                // write again until the daemon is restarted, while its API
                // keeps answering reads from the store it froze with. That is
                // silent by default, so say it once, loudly.
                tracing::error!(
                    "this manager's raft engine has stopped and nothing will restart it: this \
                     node cannot lead, replicate or commit any cluster write until satld is \
                     restarted ('service satld restart'), and reads it still answers are frozen \
                     at the last state it applied. The reason is the raft error logged just \
                     above this line"
                );
                return;
            }
            let (id, state, leader, term) = {
                let m = rx.borrow();
                (m.id, m.state, m.current_leader, m.current_term)
            };
            if state == last_state && leader == last_leader {
                continue;
            }
            match (
                last_state == ServerState::Leader,
                state == ServerState::Leader,
            ) {
                (false, true) => {
                    tracing::info!(raft_id = id, term, "raft leadership gained");
                }
                (true, false) => {
                    tracing::info!(raft_id = id, term, leader = ?leader, "raft leadership lost");
                }
                _ => {
                    tracing::info!(
                        raft_id = id,
                        term,
                        state = ?state,
                        leader = ?leader,
                        "raft role transition"
                    );
                }
            }
            last_state = state;
            last_leader = leader;
        }
    })
}

/// Awaits this node becoming leader, bounded by [`LEADERSHIP_TIMEOUT`].
async fn wait_for_leadership(raft: &Raft<TypeConfig>) -> Result<(), NodeError> {
    let mut rx = raft.metrics();
    let wait = async {
        loop {
            let is_leader = { rx.borrow().state == ServerState::Leader };
            if is_leader {
                return Ok(());
            }
            if rx.changed().await.is_err() {
                return Err(NodeError::Raft {
                    op: "await leadership",
                    message: "raft core stopped while waiting for leadership".to_owned(),
                });
            }
        }
    };
    match tokio::time::timeout(LEADERSHIP_TIMEOUT, wait).await {
        Ok(result) => result,
        Err(_) => Err(NodeError::LeadershipTimeout {
            timeout: LEADERSHIP_TIMEOUT,
        }),
    }
}

/// Seeds the `default` Cluster object and this node's own Node object on
/// first leadership of a fresh cluster (architecture §1.2). Idempotent:
/// checks the store before proposing, so restarts never duplicate.
async fn seed_cluster_state(
    store: &ClusterStore,
    node_id: &Id,
    raft_id: u64,
    node_name: &str,
    advertise_addr: &str,
) -> Result<(), ProposeError> {
    let (need_cluster, need_node) = {
        let view = store.view();
        (view.cluster().is_none(), view.node(node_id).is_none())
    };
    let mut actions = Vec::new();
    if need_cluster {
        actions.push(StoreAction::Create(StoreObject::Cluster(default_cluster())));
    }
    if need_node {
        actions.push(StoreAction::Create(StoreObject::Node(self_node(
            node_id,
            raft_id,
            node_name,
            advertise_addr,
        ))));
    }
    if actions.is_empty() {
        tracing::debug!("cluster state already seeded");
        return Ok(());
    }
    let version = store.propose(actions).await?;
    tracing::info!(
        version = version.0,
        seeded_cluster = need_cluster,
        seeded_node = need_node,
        node_id = %node_id,
        "seeded initial cluster state"
    );
    Ok(())
}

/// The `default` Cluster object (SwarmKit defaults, architecture §15). Join
/// tokens stay empty placeholders until the embedded CA lands (M2).
fn default_cluster() -> Cluster {
    Cluster {
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
            default_address_pool: vec![DEFAULT_ADDRESS_POOL.to_owned()],
            subnet_size: DEFAULT_SUBNET_SIZE,
            autolock: false,
            unlock_key: None,
        },
        join_tokens: JoinTokens::default(),
        blacklisted_certs: BTreeMap::new(),
        root_ca_cert: None,
        encrypted_root_ca_key: None,
        root_rotation: None,
    }
}

/// This node's own Node object as seeded by the first leader.
///
/// **No description is seeded.** The node description is the agent's to
/// report (SWK §15.1 `Executor.Describe`, architecture §8.3): hostname,
/// platform, CPU and memory, whether the linuxulator and racct are available.
/// A leader inventing one has to invent its *contents* too, and the only
/// hostname-shaped string it has is the configured `node_name` — which is a
/// label, not a hostname. That is exactly what happened on the first 3-node
/// cluster: the bootstrap node showed `node1` in the HOSTNAME column while
/// its peers showed real hostnames, because a seeded description that merely
/// *looks* plausible is never corrected by the "update if it differs" path
/// when the seeded and reported values happen to compare equal on the fields
/// the writer looked at.
///
/// So the field stays `None` until the agent's first registration, a second
/// later. Consumers must already tolerate that: a node whose agent has never
/// connected genuinely has no description.
fn self_node(node_id: &Id, raft_id: u64, node_name: &str, advertise_addr: &str) -> Node {
    Node {
        id: node_id.clone(),
        meta: Meta::new(),
        spec: NodeSpec {
            name: Some(node_name.to_owned()),
            labels: BTreeMap::new(),
            role: NodeRole::Manager,
            availability: Availability::Active,
        },
        description: None,
        status: NodeStatus {
            state: NodeState::Ready,
            message: String::new(),
            addr: String::new(),
        },
        manager_status: Some(ManagerStatus {
            raft_id,
            addr: advertise_addr.to_owned(),
            leader: true,
            reachability: Reachability::Reachable,
        }),
        certificate_status: CertificateStatus::default(),
        certificate_issuer: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The replication batch must not be able to exceed the gRPC message
    /// limit, whatever the entries in it are (see
    /// [`RAFT_MAX_PAYLOAD_ENTRIES`]). This is the arithmetic, asserted.
    #[test]
    fn a_worst_case_replication_batch_fits_in_one_message() {
        let limit = MAX_MESSAGE_SIZE as u64;
        let tx = MAX_TX_BYTES as u64;
        let worst_case = RAFT_MAX_PAYLOAD_ENTRIES * tx;
        assert!(
            worst_case < limit,
            "{RAFT_MAX_PAYLOAD_ENTRIES} entries of {tx} B = {worst_case} B, over the {limit} B \
             message limit"
        );
        // A batch of zero entries would replicate nothing at all; the clamp in
        // the constant is what prevents it, whatever the two limits become.
        const { assert!(RAFT_MAX_PAYLOAD_ENTRIES >= 1) };
    }

    #[test]
    fn sealed_state_without_its_key_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        // Nothing at all: a genuine first boot.
        refuse_sealed_state_without_a_key(dir.path()).expect("a pristine directory is fine");

        // The plaintext identity files are written before the key on a first
        // boot, so they must not look like sealed state.
        std::fs::write(dir.path().join(NODE_ID_FILE), "2iup8ysgimfrv5el95efgg5n3").unwrap();
        std::fs::write(dir.path().join(RAFT_ID_FILE), "8454213539863582225").unwrap();
        refuse_sealed_state_without_a_key(dir.path())
            .expect("a node id without a key is a first boot interrupted, not a lost key");

        // A log is sealed with the key, so a log with no key is a restore
        // that left it behind.
        std::fs::write(dir.path().join(LOG_FILE_NAME), b"sealed bytes").unwrap();
        let err = refuse_sealed_state_without_a_key(dir.path()).expect_err("must be refused");
        let msg = err.to_string();
        assert!(matches!(err, NodeError::MissingDek { .. }), "{msg}");
        assert!(msg.contains(DEK_FILE), "{msg}");
        assert!(msg.contains(LOG_FILE_NAME), "{msg}");

        // The same holds for a snapshot alone.
        std::fs::remove_file(dir.path().join(LOG_FILE_NAME)).unwrap();
        std::fs::write(dir.path().join(SNAPSHOT_FILE_NAME), b"sealed bytes").unwrap();
        let err = refuse_sealed_state_without_a_key(dir.path()).expect_err("must be refused");
        assert!(err.to_string().contains(SNAPSHOT_FILE_NAME), "{err}");

        // With the key beside it, the directory opens.
        Dek::load_or_create(&dir.path().join(DEK_FILE)).unwrap();
        refuse_sealed_state_without_a_key(dir.path()).expect("key present");
    }

    #[test]
    fn node_id_persists_and_rejects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let id = load_or_create_node_id(dir.path(), None).unwrap();
        assert_eq!(load_or_create_node_id(dir.path(), None).unwrap(), id);

        std::fs::write(dir.path().join(NODE_ID_FILE), "not an id").unwrap();
        let err = load_or_create_node_id(dir.path(), None).unwrap_err();
        assert!(matches!(err, NodeError::CorruptNodeId { .. }), "{err}");
    }

    /// Architecture §12.1 pins `CN = node ID`: the certificate is what names
    /// the node, and a raft directory that disagrees is refused rather than
    /// quietly adopted.
    #[test]
    fn the_certificate_names_the_node_and_a_mismatch_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let from_cert = Id::generate();
        let id = load_or_create_node_id(dir.path(), Some(&from_cert)).unwrap();
        assert_eq!(id, from_cert, "a fresh directory adopts the certificate CN");
        // Re-reading with the same certificate is fine.
        assert_eq!(
            load_or_create_node_id(dir.path(), Some(&from_cert)).unwrap(),
            from_cert
        );
        // Reading with no certificate returns what was stored.
        assert_eq!(load_or_create_node_id(dir.path(), None).unwrap(), from_cert);

        let other = Id::generate();
        let err = load_or_create_node_id(dir.path(), Some(&other)).unwrap_err();
        match err {
            NodeError::IdentityMismatch {
                stored,
                certificate,
                ..
            } => {
                assert_eq!(stored, from_cert.to_string());
                assert_eq!(certificate, other.to_string());
            }
            other => panic!("expected an identity mismatch, got {other}"),
        }
    }

    #[test]
    fn a_pristine_directory_is_clean_and_a_raft_id_makes_it_dirty() {
        let dir = tempfile::tempdir().unwrap();
        let dek = Dek::load_or_create(&dir.path().join(DEK_FILE)).unwrap();
        let sm = StateMachine::open(dir.path(), dek).unwrap();
        let node_id = Id::generate();

        assert_eq!(dirty_state_reason(&sm, &node_id, 0), None);
        let reason = dirty_state_reason(&sm, &node_id, 42).expect("a raft ID means dirty");
        assert!(reason.contains("42"), "{reason}");
    }

    #[test]
    fn raft_timings_are_ordered_and_the_fast_profile_is_much_shorter() {
        for timing in [RaftTiming::swarmkit(), RaftTiming::fast()] {
            assert!(timing.heartbeat_interval_ms < timing.election_timeout_min_ms);
            assert!(timing.election_timeout_min_ms < timing.election_timeout_max_ms);
            assert_eq!(
                timing.liveness_window(),
                Duration::from_millis(timing.election_timeout_max_ms)
            );
        }
        assert!(
            RaftTiming::fast().election_timeout_max_ms
                < RaftTiming::swarmkit().election_timeout_min_ms
        );
        assert_eq!(RaftTiming::default(), RaftTiming::swarmkit());
    }

    #[test]
    fn the_peer_address_falls_back_to_the_node_name() {
        let mut cfg = RaftNodeConfig {
            node_name: "mgr-1".to_owned(),
            ..Default::default()
        };
        assert_eq!(cfg.peer_addr(), "mgr-1");
        cfg.advertise_addr = "10.0.0.1:2377".to_owned();
        assert_eq!(cfg.peer_addr(), "10.0.0.1:2377");
    }

    #[test]
    fn raft_id_persists_and_rejects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let id = load_or_create_raft_id(dir.path()).unwrap();
        assert_ne!(id, 0);
        assert_eq!(load_or_create_raft_id(dir.path()).unwrap(), id);

        std::fs::write(dir.path().join(RAFT_ID_FILE), "0").unwrap();
        let err = load_or_create_raft_id(dir.path()).unwrap_err();
        assert!(matches!(err, NodeError::CorruptRaftId { .. }), "{err}");

        std::fs::write(dir.path().join(RAFT_ID_FILE), "twelve").unwrap();
        let err = load_or_create_raft_id(dir.path()).unwrap_err();
        assert!(matches!(err, NodeError::CorruptRaftId { .. }), "{err}");
    }
}
