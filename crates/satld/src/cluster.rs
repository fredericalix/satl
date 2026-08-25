// SPDX-License-Identifier: BSD-2-Clause
//! Cluster bring-up: identity, Raft, the internal gRPC surface, the agent
//! session and the leader-only components — started, stopped and *replaced*
//! as one unit.
//!
//! ```text
//!            ┌──────────────── ClusterRuntime ─────────────────┐
//!  identity ─┤ RaftNode (Raft, Control, Health, Dispatcher, CA)│
//!            │ NodeCA bootstrap listener   (2378, no client ct)│
//!            │ dispatcher unix socket      (co-located agent)  │
//!            │ dispatcher background loops (sweep, statuses)   │
//!            │ leadership supervisor       (orchestr., sched.) │
//!            │ agent session               (this node's tasks) │
//!            │ certificate renewal                            │
//!            └────────────────────────┬────────────────────────┘
//!                                     │ published through
//!                              ClusterSlot ──▶ the REST backend
//! ```
//!
//! # Why it is replaceable
//!
//! `satl swarm join` gives this node a *different* identity in a *different*
//! cluster: new certificate, new node id, empty raft state. Everything above
//! is derived from those, so joining means building a second runtime and
//! swapping it in — which is why the REST backend reads the store through
//! [`ClusterSlot`] rather than holding a clone of it. The node-local runtime
//! (executor, worker, images, ZFS, network) is *not* part of this: it belongs
//! to the host, not to the cluster, and survives the swap untouched.
//!
//! # The deferred-store dance
//!
//! `Dispatcher` and `NodeCA` are gRPC services that need the `ClusterStore` —
//! which does not exist until `RaftNode::start` has opened the state machine
//! and started openraft, i.e. *after* the point where services must already
//! be registered on the server. So both are registered as thin proxies over a
//! [`DeferredStore`]/[`DeferredDispatcher`] that is filled in microseconds
//! later, and answer `UNAVAILABLE` in the window before that. The window is
//! not reachable in practice — nothing can dial the listener before
//! `start_with_services` returns — but it is answered rather than panicked
//! on, because "unreachable" and "impossible" are different things.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use satl_ca::{LiveIdentity, NodeIdentity, RoleRequirement};
use satl_cluster::{
    ClusterStore, LeaderClient, ManagerSlot, RaftNode, RaftNodeConfig, ServerBuilder,
};
use satl_core::{Availability, Id, NodeRole};
use satl_dispatcher::agent::SessionReporter;
use satl_dispatcher::{Agent, AgentConfig, Dispatcher, DispatcherConfig};
use satl_proto::v2;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

use crate::channels::{AgentChannels, MtlsChannels};
use crate::config::Config;
use crate::identity::{self, NodeCaService};
use crate::node::NodeRuntime;

/// Health service name published once the agent holds a session.
const HEALTH_SERVICE_DISPATCHER: &str = "dispatcher";

/// Name of the co-located dispatcher socket inside the state directory.
const DISPATCHER_SOCKET: &str = "dispatcher.sock";

// ---------------------------------------------------------------------------
// The slot the REST backend reads through
// ---------------------------------------------------------------------------

/// Everything the REST backend needs from the cluster, as one immutable
/// snapshot.
///
/// Handed out behind an `Arc` so a handler can hold it across an await
/// without keeping a lock — and so a `swarm join` that replaces the runtime
/// under a request in flight lets that request finish against the cluster it
/// started on.
///
/// The manager half is optional because a **worker holds no replicated
/// store** (architecture §1.2): everything cluster-scoped hangs off
/// [`ManagerCore`], and a backend that finds `None` there answers with
/// Docker's "not a swarm manager" refusal instead of half-answering.
pub struct ClusterCore {
    /// The manager-only surfaces: the store, leader forwarding, membership.
    /// `None` on a worker.
    pub manager: Option<ManagerCore>,
    /// This node's id (its certificate CN).
    pub node_id: Id,
    /// This node's role (its certificate OU).
    pub role: NodeRole,
    /// The cluster this node belongs to (its certificate O).
    pub cluster_id: String,
    /// What this node tells peers to dial, empty when undetermined.
    pub advertise_addr: String,
    /// What the agent's session last learned: this node's own object, the
    /// manager list, the root CA bundle. On a worker this is the only view of
    /// the cluster the node has.
    pub agent: tokio::sync::watch::Receiver<satl_dispatcher::AgentState>,
}

/// The parts of a [`ClusterCore`] that exist only on a manager.
#[derive(Clone)]
pub struct ManagerCore {
    /// The replicated object store.
    pub store: ClusterStore,
    /// Proposes locally when this node leads, forwards to the leader
    /// otherwise (architecture §6.5).
    pub leader: LeaderClient,
    /// The manager context, for membership operations.
    pub membership: ManagerSlot,
    /// The manager side of the dispatcher protocol — the metrics collector
    /// reads its open-session count.
    pub dispatcher: satl_dispatcher::Dispatcher,
}

impl ClusterCore {
    /// The store, when this node is a manager holding one.
    #[must_use]
    pub fn store(&self) -> Option<&ClusterStore> {
        self.manager.as_ref().map(|manager| &manager.store)
    }
}

impl std::fmt::Debug for ClusterCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterCore")
            .field("node_id", &self.node_id)
            .field("role", &self.role)
            .field("cluster_id", &self.cluster_id)
            .field("advertise_addr", &self.advertise_addr)
            .field("manager", &self.manager.is_some())
            .finish_non_exhaustive()
    }
}

/// The current [`ClusterCore`], plus the channel `swarm join`/`swarm leave`
/// use to ask the daemon to rebuild it.
#[derive(Debug)]
pub struct ClusterSlot {
    core: RwLock<Option<Arc<ClusterCore>>>,
    control: tokio::sync::mpsc::Sender<ControlRequest>,
}

/// A request from the REST backend to rebuild the cluster runtime.
#[derive(Debug)]
pub enum ControlRequest {
    /// Leave the current cluster and join the one at `remote_addrs`.
    Join {
        /// Manager addresses to try, in order.
        remote_addrs: Vec<String>,
        /// The `SATL-1-…` join token. Never logged.
        token: String,
        /// Advertise address override, if the caller gave one.
        advertise_addr: Option<String>,
        /// Listen address override, if the caller gave one.
        listen_addr: Option<String>,
        /// Availability the node asks to join with.
        availability: Availability,
        /// Where the outcome goes.
        reply: tokio::sync::oneshot::Sender<Result<Id, String>>,
    },
    /// Leave the cluster: wipe identity and raft state, self-initialize a
    /// fresh single-node cluster.
    Leave {
        /// Skip the "you are the last manager" refusal.
        force: bool,
        /// Where the outcome goes.
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    /// Rebuild the runtime for the role this node's certificate now carries —
    /// sent by the role watcher after it renewed the certificate, never by a
    /// REST handler (the role change itself is a store write on a manager;
    /// this is the node *applying* it, architecture §12.3).
    ApplyRole {
        /// The role the fresh certificate carries.
        role: NodeRole,
        /// Managers the rebuilt runtime can dial, in preference order.
        managers: Vec<String>,
    },
}

impl ClusterSlot {
    /// An empty slot and the receiving end of its control channel.
    #[must_use]
    pub fn new() -> (Arc<Self>, tokio::sync::mpsc::Receiver<ControlRequest>) {
        let (control, rx) = tokio::sync::mpsc::channel(1);
        (
            Arc::new(Self {
                core: RwLock::new(None),
                control,
            }),
            rx,
        )
    }

    /// Publishes a new core, replacing whatever was there.
    pub fn publish(&self, core: Arc<ClusterCore>) {
        match self.core.write() {
            Ok(mut slot) => *slot = Some(core),
            Err(poisoned) => {
                // A poisoned lock here means a panic while swapping runtimes.
                // The data is a plain Arc — recovering it is safe and far
                // better than leaving the daemon with no cluster at all.
                *poisoned.into_inner() = Some(core);
            }
        }
    }

    /// The current core, or `None` before the first bring-up.
    #[must_use]
    pub fn get(&self) -> Option<Arc<ClusterCore>> {
        match self.core.read() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Sends a control request to the daemon's cluster supervisor.
    ///
    /// # Errors
    ///
    /// When the supervisor is gone (the daemon is shutting down).
    pub async fn control(&self, request: ControlRequest) -> Result<(), &'static str> {
        self.control
            .send(request)
            .await
            .map_err(|_| "the daemon is shutting down")
    }
}

// ---------------------------------------------------------------------------
// Deferred service wiring
// ---------------------------------------------------------------------------

/// A [`ClusterStore`] handed to a gRPC service before it exists.
#[derive(Clone, Default)]
pub struct DeferredStore(Arc<OnceLock<ClusterStore>>);

impl std::fmt::Debug for DeferredStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeferredStore")
            .field("installed", &self.0.get().is_some())
            .finish()
    }
}

impl DeferredStore {
    /// Installs the store. Later calls are ignored: a runtime gets one store.
    pub fn install(&self, store: ClusterStore) {
        let _ = self.0.set(store);
    }

    /// The store, or `UNAVAILABLE` in the microseconds before it exists.
    pub fn get(&self) -> Result<&ClusterStore, Status> {
        self.0
            .get()
            .ok_or_else(|| Status::unavailable("this manager's cluster store is still starting up"))
    }
}

/// A [`Dispatcher`] registered on the gRPC server before it can be built.
#[derive(Clone, Default)]
pub struct DeferredDispatcher(Arc<OnceLock<Dispatcher>>);

impl std::fmt::Debug for DeferredDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeferredDispatcher")
            .field("installed", &self.0.get().is_some())
            .finish()
    }
}

impl DeferredDispatcher {
    fn install(&self, dispatcher: Dispatcher) {
        let _ = self.0.set(dispatcher);
    }

    fn get(&self) -> Result<&Dispatcher, Status> {
        self.0
            .get()
            .ok_or_else(|| Status::unavailable("this manager's dispatcher is still starting up"))
    }

    /// The tonic service, with SatL's message-size limits applied.
    fn server(&self) -> v2::dispatcher_server::DispatcherServer<Self> {
        v2::dispatcher_server::DispatcherServer::new(self.clone())
            .max_decoding_message_size(satl_proto::MAX_MESSAGE_SIZE)
            .max_encoding_message_size(satl_proto::MAX_MESSAGE_SIZE)
    }
}

#[tonic::async_trait]
impl v2::dispatcher_server::Dispatcher for DeferredDispatcher {
    type SessionStream = <Dispatcher as v2::dispatcher_server::Dispatcher>::SessionStream;
    type AssignmentsStream = <Dispatcher as v2::dispatcher_server::Dispatcher>::AssignmentsStream;

    async fn session(
        &self,
        request: Request<v2::SessionRequest>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        self.get()?.session(request).await
    }

    async fn heartbeat(
        &self,
        request: Request<v2::HeartbeatRequest>,
    ) -> Result<Response<v2::HeartbeatResponse>, Status> {
        self.get()?.heartbeat(request).await
    }

    async fn update_task_status(
        &self,
        request: Request<v2::UpdateTaskStatusRequest>,
    ) -> Result<Response<v2::UpdateTaskStatusResponse>, Status> {
        self.get()?.update_task_status(request).await
    }

    async fn assignments(
        &self,
        request: Request<v2::AssignmentsRequest>,
    ) -> Result<Response<Self::AssignmentsStream>, Status> {
        self.get()?.assignments(request).await
    }
}

// ---------------------------------------------------------------------------
// Bring-up
// ---------------------------------------------------------------------------

/// A running cluster runtime.
///
/// On a manager everything is present; on a worker there is **no raft node,
/// no `NodeCA` listener and no co-located dispatcher socket** — only the agent
/// session, the overlay loops, the role watcher and certificate renewal
/// (architecture §1.2).
pub struct ClusterRuntime {
    raft: Option<RaftNode>,
    core: Arc<ClusterCore>,
    loops: CancellationToken,
    handles: Vec<JoinHandle<()>>,
    ca_server: Option<BootstrapServer>,
    local_server: Option<BootstrapServer>,
}

impl std::fmt::Debug for ClusterRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterRuntime")
            .field("core", &self.core)
            .finish_non_exhaustive()
    }
}

/// One of the two auxiliary tonic servers (`NodeCA` bootstrap, co-located
/// dispatcher socket) and how to stop it.
struct BootstrapServer {
    shutdown: CancellationToken,
    handle: JoinHandle<()>,
}

impl BootstrapServer {
    async fn stop(self) {
        self.shutdown.cancel();
        if let Err(error) = self.handle.await {
            tracing::warn!(%error, "an auxiliary gRPC server did not stop cleanly");
        }
    }
}

impl ClusterRuntime {
    /// The snapshot the REST backend reads.
    #[must_use]
    pub fn core(&self) -> Arc<ClusterCore> {
        Arc::clone(&self.core)
    }

    /// The path of this node's co-located dispatcher socket.
    #[must_use]
    pub fn dispatcher_socket(state_dir: &Path) -> PathBuf {
        state_dir.join(DISPATCHER_SOCKET)
    }

    /// Stops everything this runtime owns, in dependency order: the loops
    /// first (nothing new is proposed or dispatched), then the auxiliary
    /// listeners, then Raft.
    ///
    /// Running jails are deliberately untouched — they outlive the daemon and
    /// are re-attached by the next startup (architecture §7.2).
    pub async fn shutdown(self) {
        self.loops.cancel();
        for handle in self.handles {
            if let Err(error) = handle.await {
                tracing::warn!(%error, "a cluster loop did not stop cleanly");
            }
        }
        if let Some(server) = self.local_server {
            server.stop().await;
        }
        if let Some(server) = self.ca_server {
            server.stop().await;
        }
        if let Some(raft) = self.raft {
            if let Err(error) = raft.shutdown().await {
                tracing::warn!(%error, "raft shutdown reported an error");
            } else {
                tracing::info!("cluster state shut down");
            }
        } else {
            tracing::info!("worker runtime shut down");
        }
    }
}

/// What a bring-up needs from the daemon.
pub struct Bringup<'a> {
    /// Effective daemon configuration.
    pub cfg: &'a Config,
    /// The node-local runtime, whose worker the agent drives.
    pub node: &'a NodeRuntime,
    /// The agent's status sink, shared with the worker.
    pub reporter: Arc<SessionReporter>,
    /// This node's description, refreshed by the agent every 20 s.
    pub describer: Arc<dyn satl_dispatcher::NodeDescriber>,
    /// Resolved advertise address, or `None` to let the leader substitute the
    /// address it sees this node connect from.
    pub advertise_addr: Option<String>,
    /// The slot the runtime publishes through — held here so the role watcher
    /// can ask the supervisor for a rebuild when this node's role changes.
    pub slot: Arc<ClusterSlot>,
    /// The daemon's shutdown token; every loop started here is a child of it.
    pub shutdown: CancellationToken,
    /// The DEK unsealed at the locked boot's `POST /swarm/unlock`; `None`
    /// everywhere else, and the plain key file is used as always.
    pub dek: Option<satl_cluster::Dek>,
}

/// Brings the cluster up on this node (architecture §1.2).
///
/// The identity decides the path:
///
/// - a certificate on disk → restart: start Raft with it;
/// - no certificate → init: bring Raft up **without a listener** to seed (or
///   find) the `Cluster` object, mint the CA and this node's manager
///   certificate against the cluster id it carries, shut that Raft down, and
///   start again for real.
///
/// The init path is also the upgrade path: a daemon that predates the CA has
/// raft state, a node id and no certificate, so it lands here, keeps its node
/// id (the raft directory's is what the certificate is issued for) and
/// updates the `Cluster` object it already has rather than creating one.
pub async fn start(bringup: Bringup<'_>) -> anyhow::Result<ClusterRuntime> {
    let state_dir = &bringup.cfg.state_dir;
    let identity = match identity::load(state_dir)? {
        Some(identity) => {
            let subject = identity::subject(&identity)?;
            tracing::info!(
                node_id = %subject.node_id,
                role = satl_ca::role_ou(subject.role),
                cluster_id = %subject.cluster_id,
                "node identity loaded from disk"
            );
            identity
        }
        None => mint_identity(bringup.cfg, bringup.advertise_addr.as_deref()).await?,
    };
    // The certificate decides the shape (§12.1: the OU is the role). A worker
    // restart rebuilds the worker runtime from the manager list it persisted;
    // a worker whose list was lost cannot rejoin on its own and says so.
    let subject = identity::subject(&identity)?;
    match subject.role {
        NodeRole::Manager => {
            // A manager certificate over an *empty* raft directory is never a
            // node that should form a cluster: with a persisted manager list
            // it is a promotion the daemon did not finish (renewed, then
            // crashed before the raft join landed) and the join is resumed;
            // without one there is nothing to resume and the bring-up is
            // refused. Either way, self-initializing would mint a second,
            // divergent cluster under the same certificate.
            let managers = load_managers(state_dir);
            if raft_state_is_empty(state_dir) {
                if !managers.is_empty() {
                    tracing::warn!(
                        node_id = %subject.node_id,
                        "manager certificate with no raft state: resuming an interrupted promotion"
                    );
                    return apply_role(bringup, NodeRole::Manager, managers).await;
                }
                // A manager certificate is only ever issued to a node that
                // already has raft state: first boot writes the raft
                // directory *first* and mints the certificate against the
                // cluster id it seeds there (`mint_identity`). So a manager
                // certificate over an empty raft directory is never a first
                // boot -- it is state that was lost or a restore that has not
                // been done. Self-initializing would form a second cluster
                // under this certificate, empty, with a new cluster id and no
                // root CA, and would look healthy while every service,
                // secret and network the operator had is gone. Refuse.
                anyhow::bail!(
                    "this node holds a manager certificate for cluster {cluster} but its raft \
                     state directory {raft} is empty, so there is nothing to resume and satld \
                     will not form a new cluster here (that would silently replace the cluster \
                     this certificate belongs to with an empty one). Restore {raft} from a \
                     backup of THIS node, the 'dek' key file included -- see the backup and \
                     restore section of docs/operations.md. If this node's state is \
                     unrecoverable and the cluster has other managers, discard its identity \
                     instead: remove {certs} and empty {raft}, start satld (it forms a fresh \
                     single-node cluster of its own) and re-join it with 'satl swarm join'",
                    cluster = subject.cluster_id,
                    raft = state_dir.join("raft").display(),
                    certs = certs_path_hint(state_dir),
                );
            }
            bring_up(bringup, identity, None).await
        }
        NodeRole::Worker => {
            let managers = load_managers(state_dir);
            anyhow::ensure!(
                !managers.is_empty(),
                "this node holds a worker certificate but no manager list at {}: it cannot \
                 find its cluster. Re-join it (`satl swarm join`) or remove {} to start over \
                 as a fresh single-node cluster.",
                managers_path(state_dir).display(),
                certs_path_hint(state_dir),
            );
            bring_up_worker(bringup, identity, managers).await
        }
    }
}

/// Whether `<state_dir>/raft` holds nothing (or does not exist).
fn raft_state_is_empty(state_dir: &Path) -> bool {
    match std::fs::read_dir(state_dir.join("raft")) {
        Ok(mut entries) => entries.next().is_none(),
        Err(_) => true,
    }
}

/// Bring-up right after a successful join: identical to [`start`] except that
/// Raft asks `remote` to admit it instead of forming its own cluster.
async fn start_joined(
    bringup: Bringup<'_>,
    identity: NodeIdentity,
    remote: &str,
) -> anyhow::Result<ClusterRuntime> {
    bring_up(bringup, identity, Some(remote)).await
}

/// Joins the cluster reachable at `remote_addrs` (architecture §12.2, §6.6).
///
/// The node this runs on has already been torn down by the caller; what is
/// left is a state directory whose raft and certificate material must be
/// **discarded** before anything else happens, because a joiner must arrive
/// clean (`satl_cluster`'s dirty-state rule, SWK §12.3) and because keeping
/// the old identity would let a restart resurrect the abandoned cluster.
///
/// **The token decides the role** (§12.2). A manager token brings the node up
/// with raft asking `remote` to admit it; a worker token brings up the
/// storeless worker runtime, whose only tie to the cluster is the dispatcher
/// session it opens to the managers (invariant #3: managers never dial
/// workers).
pub async fn join(
    bringup: Bringup<'_>,
    remote_addrs: &[String],
    token: &str,
    availability: Availability,
) -> anyhow::Result<ClusterRuntime> {
    anyhow::ensure!(
        !remote_addrs.is_empty(),
        "no manager address to join: pass at least one `host:port`"
    );
    let state_dir = bringup.cfg.state_dir.clone();

    // The CA flow first: it is the step that can legitimately fail (bad
    // token, unreachable manager), and failing it must leave this node's
    // existing state alone.
    let mut last_error = None;
    let mut joined = None;
    for addr in remote_addrs {
        let ca_addr = crate::config::ca_endpoint_of(addr);
        match identity::join_remote(&ca_addr, token, availability).await {
            Ok(outcome) => {
                joined = Some((addr.clone(), outcome));
                break;
            }
            Err(error) => {
                tracing::warn!(manager = %addr, %error, "join attempt failed; trying the next manager");
                last_error = Some(error);
            }
        }
    }
    let Some((remote, joined)) = joined else {
        return Err(last_error.map_or_else(
            || anyhow::anyhow!("no manager address could be reached"),
            anyhow::Error::new,
        ));
    };

    // Point of no return: the old cluster's state goes away.
    wipe_cluster_state(&state_dir)?;
    identity::save(&state_dir, &joined.identity)?;
    tracing::info!(
        node_id = %joined.node_id,
        role = satl_ca::role_ou(joined.role),
        remote = %remote,
        "identity issued by the remote cluster; local cluster state discarded"
    );

    match joined.role {
        NodeRole::Manager => start_joined(bringup, joined.identity, &remote).await,
        NodeRole::Worker => {
            // Every address the operator gave is a manager worth trying; the
            // session's manager list replaces this the moment it arrives.
            let managers: Vec<String> = remote_addrs.to_vec();
            save_managers(&state_dir, &managers);
            bring_up_worker(bringup, joined.identity, managers).await
        }
    }
}

/// Rebuilds the runtime for the role the certificate on disk now carries —
/// the second half of a live promotion or demotion (architecture §12.3). The
/// first half (the renewed certificate) was done by the role watcher before
/// it asked for this; the caller has already shut the previous runtime down.
///
/// A **promotion** joins raft through the existing membership machinery
/// (learner first, §6.6), trying each known manager until one admits it. A
/// **demotion** brings up the storeless worker runtime pointed at the same
/// managers. Both start from a clean raft directory: a promoted worker has
/// no raft state, and an ex-manager's log belongs to a membership it already
/// left — the clean-join rule (SWK §12.3) would refuse it anyway.
pub async fn apply_role(
    bringup: Bringup<'_>,
    role: NodeRole,
    managers: Vec<String>,
) -> anyhow::Result<ClusterRuntime> {
    let Bringup {
        cfg,
        node,
        reporter,
        describer,
        advertise_addr,
        slot,
        shutdown,
        // The raft directory is wiped below, so any sealed key file goes with
        // it: a rebuilt runtime always opens with a fresh plain DEK, and the
        // autolock watcher re-seals it if the cluster says so.
        dek: _,
    } = bringup;
    let state_dir = cfg.state_dir.clone();
    let identity = identity::load(&state_dir)?.ok_or_else(|| {
        anyhow::anyhow!("no certificate on disk while applying a role change; re-join this node")
    })?;
    let subject = identity::subject(&identity)?;
    anyhow::ensure!(
        subject.role == role,
        "the certificate on disk carries the {} role, not the {} this rebuild applies — the \
         renewal that precedes a role rebuild did not land",
        satl_ca::role_ou(subject.role),
        satl_ca::role_ou(role)
    );
    anyhow::ensure!(
        !managers.is_empty(),
        "no manager address to rebuild against; the session's manager list was empty"
    );

    match role {
        NodeRole::Worker => {
            wipe_raft_state(&state_dir)?;
            save_managers(&state_dir, &managers);
            let bringup = Bringup {
                cfg,
                node,
                reporter,
                describer,
                advertise_addr,
                slot,
                shutdown,
                dek: None,
            };
            bring_up_worker(bringup, identity, managers).await
        }
        NodeRole::Manager => {
            for remote in &managers {
                // Clean between attempts too: a join that failed halfway may
                // have written raft state a second attempt must not inherit.
                wipe_raft_state(&state_dir)?;
                let attempt = Bringup {
                    cfg,
                    node,
                    reporter: Arc::clone(&reporter),
                    describer: Arc::clone(&describer),
                    advertise_addr: advertise_addr.clone(),
                    slot: Arc::clone(&slot),
                    shutdown: shutdown.clone(),
                    dek: None,
                };
                match bring_up(attempt, identity.clone(), Some(remote)).await {
                    Ok(runtime) => {
                        save_managers(&state_dir, &managers);
                        return Ok(runtime);
                    }
                    Err(error) => {
                        tracing::warn!(
                            manager = %remote,
                            %error,
                            "raft join for the promotion failed; trying the next manager"
                        );
                    }
                }
            }
            // Every manager refused or was unreachable. The node must keep
            // running its tasks, so fall back to the worker runtime — never
            // to self-initialization, which would mint a second, divergent
            // cluster under this certificate. The role watcher sees the store
            // still asking for a manager and retries the whole change.
            tracing::error!(
                managers = managers.len(),
                "promotion: no manager could admit this node to raft; staying a worker and \
                 retrying from the session"
            );
            wipe_raft_state(&state_dir)?;
            save_managers(&state_dir, &managers);
            let bringup = Bringup {
                cfg,
                node,
                reporter,
                describer,
                advertise_addr,
                slot,
                shutdown,
                dek: None,
            };
            bring_up_worker(bringup, identity, managers).await
        }
    }
}

/// Discards this node's cluster membership entirely: certificates and raft
/// state both.
///
/// This is `swarm leave`. What survives is everything node-local — images,
/// layers, volumes, the network, the local task database — because leaving a
/// cluster is not the same as forgetting the host. The next bring-up
/// self-initializes a fresh single-node cluster around it (architecture
/// §1.2).
pub fn reset(state_dir: &Path) -> anyhow::Result<()> {
    wipe_cluster_state(state_dir)
}

/// Discards this node's raft state, certificates and manager list.
fn wipe_cluster_state(state_dir: &Path) -> anyhow::Result<()> {
    identity::wipe(state_dir)?;
    match std::fs::remove_file(managers_path(state_dir)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(%error, "cannot remove the persisted manager list"),
    }
    wipe_raft_state(state_dir)
}

/// Discards this node's raft state only — a demotion keeps the identity (the
/// node id survives the role change) but must not leave a raft log behind
/// that a later promotion's clean-join would trip over.
///
/// The raft directory's **contents** go, not the directory itself: on a real
/// install `<state_dir>/raft` is a ZFS dataset mountpoint (architecture §10),
/// and `remove_dir_all` on a mountpoint fails with `EBUSY` no matter who owns
/// the files. Emptying it achieves the same thing and keeps the dataset —
/// which is what the operator provisioned — intact.
fn wipe_raft_state(state_dir: &Path) -> anyhow::Result<()> {
    let raft_dir = state_dir.join("raft");
    let entries = match std::fs::read_dir(&raft_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(anyhow::Error::new(source).context(format!(
                "cannot read the raft state at {}",
                raft_dir.display()
            )));
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| {
            anyhow::Error::new(source).context(format!(
                "cannot list the raft state at {}",
                raft_dir.display()
            ))
        })?;
        let path = entry.path();
        let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
        let removed = if is_dir {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        // A racing removal is fine; anything still on disk is not.
        if let Err(source) = removed
            && path.exists()
        {
            return Err(anyhow::Error::new(source).context(format!(
                "cannot discard the raft state file {}",
                path.display()
            )));
        }
    }
    Ok(())
}

/// The init path's first phase: bring raft up with no listener, seed or find
/// the `Cluster` object, mint the CA and this node's certificate, stop.
async fn mint_identity(cfg: &Config, advertise_addr: Option<&str>) -> anyhow::Result<NodeIdentity> {
    tracing::info!(
        state_dir = %cfg.state_dir.display(),
        "no node certificate found; initializing this node's identity"
    );
    // The advertise address matters even though this node serves nothing:
    // `initialize` writes the single-voter membership, and the address it
    // records there is what *peers later dial*. Left empty, the membership
    // would carry the node name — a label, not an endpoint — and the first
    // follower to redirect an agent to this leader would hand out something
    // undialable ("invalid socket address"), which is exactly the failure
    // this argument exists to prevent.
    let (store, raft) = RaftNode::start(RaftNodeConfig {
        raft_dir: cfg.state_dir.join("raft"),
        node_name: cfg.node_name.clone(),
        advertise_addr: advertise_addr.unwrap_or_default().to_owned(),
        ..Default::default()
    })
    .await?;
    let node_id = raft.node_id().clone();
    let outcome = identity::initialize(
        &cfg.state_dir,
        &store,
        &node_id,
        cfg.effective_cert_validity(),
    )
    .await;
    // Stop this bring-up whatever happened: the real one starts next, and
    // two openraft instances must never share a raft directory.
    if let Err(error) = raft.shutdown().await {
        tracing::warn!(%error, "the identity bootstrap raft node did not stop cleanly");
    }
    let outcome = outcome?;
    if outcome.ca_generated {
        tracing::info!(
            node_id = %node_id,
            "this node is now the root of a new cluster: a root CA and both join tokens were \
             generated. `satl swarm join-token manager` prints what another node needs."
        );
    } else {
        tracing::info!(
            node_id = %node_id,
            "re-issued this node's certificate from the cluster CA already in the store"
        );
    }
    Ok(outcome.identity)
}

/// Starts the full runtime for an established identity.
///
/// `join_to` is the manager address this node asks to be admitted by; `None`
/// means "form or resume a cluster of my own", which is every start after the
/// first join.
async fn bring_up(
    bringup: Bringup<'_>,
    identity: NodeIdentity,
    join_to: Option<&str>,
) -> anyhow::Result<ClusterRuntime> {
    let Bringup {
        cfg,
        node,
        reporter,
        describer,
        advertise_addr,
        slot,
        shutdown,
        dek,
    } = bringup;
    let subject = identity::subject(&identity)?;
    let advertise = advertise_addr.unwrap_or_default();

    // The one live identity every TLS surface of this runtime resolves
    // through, and the renewal loop swaps (architecture §12.3): the internal
    // gRPC server, the NodeCA bootstrap listener, the raft/forwarding
    // channels and the agent's dispatcher channels.
    let live = LiveIdentity::new(identity.clone())
        .map_err(|error| anyhow::anyhow!("building this node's TLS identity: {error}"))?;

    let deferred_store = DeferredStore::default();
    let deferred_dispatcher = DeferredDispatcher::default();
    let ca_service = NodeCaService::new(deferred_store.clone(), cfg.cert_validity);
    let (store, raft) = start_raft(
        cfg,
        &live,
        &advertise,
        join_to,
        &deferred_dispatcher,
        &ca_service,
        dek,
    )
    .await?;
    deferred_store.install(store.clone());
    let node_id = raft.node_id().clone();

    let loops = shutdown.child_token();
    let mut handles = Vec::new();
    handles.extend(start_overlay(node, &node_id, &advertise, &loops).await);

    // The manager side of the dispatcher, and its background loops.
    let dispatcher = Dispatcher::new(store.clone(), node_id.clone(), DispatcherConfig::default());
    deferred_dispatcher.install(dispatcher.clone());
    handles.extend(dispatcher.spawn(loops.clone()));

    let (local_server, local_socket) = start_local_dispatcher(cfg, &dispatcher, &identity, &loops);
    let ca_server = start_bootstrap_ca(cfg, &ca_service, &live, &loops).await;

    // Leader-only components.
    handles.push(crate::leadership::spawn(store.clone(), cfg, loops.clone()));

    // The autolock watcher: seals (or reseals, or unseals) this manager's
    // DEK as the Cluster object demands. Managers only — a worker has no
    // raft log to lock.
    handles.push(crate::autolock::spawn(
        store.clone(),
        raft.dek(),
        cfg.state_dir.join("raft"),
        loops.clone(),
    ));

    // The agent: this node's own session, which is where its tasks come from.
    let (agent_handles, agent_state) = start_agent(
        AgentParts {
            identity: &live,
            bootstrap: bootstrap_managers(&store, &node_id),
            node,
            node_id: &node_id,
            local_socket,
            health: raft.health(),
        },
        reporter,
        describer,
        &loops,
    )?;
    handles.extend(agent_handles);

    // The role watcher: a demotion committed by the leader reaches this node
    // through its session (the node object's role flips), and applying it is
    // a certificate renewal plus a runtime rebuild (architecture §12.3).
    handles.push(spawn_role_watch(
        cfg.state_dir.clone(),
        Arc::clone(&live),
        NodeRole::Manager,
        agent_state.clone(),
        Arc::clone(&slot),
        loops.clone(),
    ));

    // Certificate renewal: re-issue in the 50-80 % validity window — or the
    // moment a root rotation marks this node — and swap the live TLS
    // identity, so it takes effect without a restart. The leader client is
    // how a follower manager records its certificate issuer in the store.
    handles.push(identity::spawn_renewal(
        cfg.state_dir.clone(),
        store.clone(),
        raft.leader_client(),
        node_id.clone(),
        live,
        cfg.effective_cert_validity(),
        loops.clone(),
    ));

    let core = Arc::new(ClusterCore {
        manager: Some(ManagerCore {
            store,
            leader: raft.leader_client(),
            membership: raft.manager_slot(),
            dispatcher,
        }),
        node_id,
        role: subject.role,
        cluster_id: subject.cluster_id.clone(),
        advertise_addr: advertise,
        agent: agent_state,
    });

    Ok(ClusterRuntime {
        raft: Some(raft),
        core,
        loops,
        handles,
        ca_server,
        local_server,
    })
}

/// Starts the storeless worker runtime (architecture §1.2): the agent session
/// to the managers, the overlay data plane, the assignment-fed DNS tables,
/// manager-list persistence, the role watcher and remote certificate renewal
/// — and deliberately **no** raft node, no store, no Control/NodeCA service,
/// no dispatcher and no leader-only component.
async fn bring_up_worker(
    bringup: Bringup<'_>,
    identity: NodeIdentity,
    managers: Vec<String>,
) -> anyhow::Result<ClusterRuntime> {
    let Bringup {
        cfg,
        node,
        reporter,
        describer,
        advertise_addr,
        slot,
        shutdown,
        // A worker holds no raft log; nothing on it is ever locked.
        dek: _,
    } = bringup;
    let subject = identity::subject(&identity)?;
    let advertise = advertise_addr.unwrap_or_default();
    let node_id = subject.node_id.clone();

    let live = LiveIdentity::new(identity)
        .map_err(|error| anyhow::anyhow!("building this node's TLS identity: {error}"))?;

    let loops = shutdown.child_token();
    let mut handles = Vec::new();
    handles.extend(start_overlay(node, &node_id, &advertise, &loops).await);

    let (agent_handles, agent_state) = start_agent(
        AgentParts {
            identity: &live,
            bootstrap: bootstrap_peers(&managers),
            node,
            node_id: &node_id,
            // No co-located dispatcher: this node runs none. The agent dials
            // the managers over mTLS, which is the whole of invariant #3's
            // "managers never dial workers" seen from this side.
            local_socket: None,
            health: satl_cluster::HealthRegistry::new(),
        },
        reporter,
        describer,
        &loops,
    )?;
    handles.extend(agent_handles);

    // The session's manager list is the only durable record a worker keeps of
    // where its cluster lives; persist it so a daemon restart can reconnect.
    handles.push(spawn_manager_persist(
        cfg.state_dir.clone(),
        agent_state.clone(),
        loops.clone(),
    ));

    // Promotion arrives here: the node object's role flips to manager on the
    // session, the watcher renews into a manager certificate and asks the
    // supervisor for a manager runtime (learner-first raft join).
    handles.push(spawn_role_watch(
        cfg.state_dir.clone(),
        Arc::clone(&live),
        NodeRole::Worker,
        agent_state.clone(),
        Arc::clone(&slot),
        loops.clone(),
    ));

    // Renewal without a store: the CSR goes to a manager's NodeCA over the
    // existing mTLS channel (the certificate authenticates the renewal).
    handles.push(identity::spawn_remote_renewal(
        cfg.state_dir.clone(),
        Arc::clone(&live),
        agent_state.clone(),
        loops.clone(),
    ));

    tracing::info!(
        node_id = %node_id,
        cluster_id = %subject.cluster_id,
        managers = managers.len(),
        "worker runtime ready: dispatcher session, executor and overlay only - no raft, no store"
    );

    let core = Arc::new(ClusterCore {
        manager: None,
        node_id,
        role: subject.role,
        cluster_id: subject.cluster_id.clone(),
        advertise_addr: advertise,
        agent: agent_state,
    });

    Ok(ClusterRuntime {
        raft: None,
        core,
        loops,
        handles,
        ca_server: None,
        local_server: None,
    })
}

/// Serves the co-located dispatcher socket, best-effort: the agent falls back
/// to the network path when it cannot be bound (architecture §7.2).
fn start_local_dispatcher(
    cfg: &Config,
    dispatcher: &Dispatcher,
    identity: &NodeIdentity,
    loops: &CancellationToken,
) -> (Option<BootstrapServer>, Option<PathBuf>) {
    let socket = ClusterRuntime::dispatcher_socket(&cfg.state_dir);
    match local_dispatcher(&socket, dispatcher, identity, loops.clone()) {
        Ok(server) => {
            let path = socket.clone();
            (Some(server), Some(path))
        }
        Err(error) => {
            tracing::warn!(
                socket = %socket.display(),
                %error,
                "cannot serve the co-located dispatcher socket; this node's agent will use the \
                 network path instead"
            );
            (None, None)
        }
    }
}

/// Serves the unauthenticated `NodeCA` bootstrap listener, best-effort (see
/// `Config::ca_listen_addr`): a manager that cannot bind it still serves its
/// cluster, but no new node can join through it.
async fn start_bootstrap_ca(
    cfg: &Config,
    ca_service: &NodeCaService,
    live: &Arc<LiveIdentity>,
    loops: &CancellationToken,
) -> Option<BootstrapServer> {
    match bootstrap_ca(cfg.ca_listen_addr(), ca_service, live, loops.clone()).await {
        Ok(server) => Some(server),
        Err(error) => {
            tracing::error!(
                addr = %cfg.ca_listen_addr(),
                %error,
                "cannot serve the NodeCA bootstrap endpoint; no node will be able to join this \
                 cluster until satld is restarted"
            );
            None
        }
    }
}

/// Starts openraft and the internal gRPC server, with `Dispatcher` and
/// `NodeCA` registered alongside `Raft`, `Control` and `Health`.
///
/// `join_to` picks which door this node comes in through: `None` forms or
/// resumes its own cluster, `Some(addr)` asks that manager to admit it
/// (architecture §6.6).
async fn start_raft(
    cfg: &Config,
    identity: &Arc<LiveIdentity>,
    advertise: &str,
    join_to: Option<&str>,
    dispatcher: &DeferredDispatcher,
    ca: &NodeCaService,
    dek: Option<satl_cluster::Dek>,
) -> anyhow::Result<(ClusterStore, RaftNode)> {
    let raft_cfg = RaftNodeConfig {
        raft_dir: cfg.state_dir.join("raft"),
        node_name: cfg.node_name.clone(),
        listen_addr: Some(cfg.listen_addr),
        advertise_addr: advertise.to_owned(),
        identity: Some(Arc::clone(identity)),
        dek,
        ..Default::default()
    };
    let register = {
        let dispatcher = dispatcher.clone();
        let ca = ca.clone();
        move |builder: ServerBuilder| {
            builder
                .add_service(RoleRequirement::WorkerOrManager, dispatcher.server())
                // `Any` is the bootstrap surface's requirement on the mTLS
                // server: a *renewal* presents the node's existing
                // certificate, which is what this path authenticates. First
                // joins cannot reach it (they have no certificate at all) and
                // go to the bootstrap listener instead.
                .add_service(RoleRequirement::Any, ca.server())
        }
    };

    let (store, raft) = match join_to {
        None => RaftNode::start_with_services(raft_cfg, register).await?,
        Some(remote) => RaftNode::join_with_services(raft_cfg, remote, register).await?,
    };
    // A node that self-initialized before its advertise address was
    // configured — the common case, since first boot forms a cluster on its
    // own (architecture §1.2) — recorded a stale address in the membership.
    // Peers dial what is recorded there, so heal it now that we know better.
    if let Err(error) = raft.heal_advertise_addr(advertise).await {
        tracing::warn!(%error, "could not correct this node's advertise address in the membership");
    }
    let metrics = store.metrics();
    tracing::info!(
        node_id = %raft.node_id(),
        raft_id = raft.raft_id(),
        listen_addr = ?raft.listen_addr(),
        advertise_addr = advertise,
        joined = join_to.is_some(),
        is_leader = metrics.is_leader,
        term = metrics.term,
        "cluster state ready"
    );
    Ok((store, raft))
}

/// Point this node's overlay programmer at the cluster it now belongs to, and
/// start the two loops that belong to that cluster rather than to the host.
///
/// The programmer itself is node-local and outlives every bring-up — its VTEPs,
/// bridges and epairs belong to the host and survive a `swarm join` — but *what*
/// it programs is per cluster: `Network::node_gateways` is keyed by node id and
/// every VTEP's `vxlanlocal` is this node's advertise address. It is told before
/// the agent can open a session, so the first assignment already has both.
async fn start_overlay(
    node: &NodeRuntime,
    node_id: &Id,
    advertise: &str,
    loops: &CancellationToken,
) -> Vec<JoinHandle<()>> {
    node.overlay
        .adopt_identity(node_id, Some(advertise).filter(|addr| !addr.is_empty()))
        .await;
    vec![
        // The DNS responder answers from the dispatcher's endpoint tables and
        // the node's own task set — the same feed on managers and workers, so
        // a node needs no replicated store to resolve service names
        // (architecture §11.5; the store-fed variant died with the
        // all-managers assumption).
        crate::overlay::spawn_dns_feed(
            Arc::clone(&node.overlay),
            node.task_db.clone(),
            loops.clone(),
        ),
        crate::overlay::spawn_resync(Arc::clone(&node.overlay), loops.clone()),
    ]
}

/// What [`start_agent`] needs from the bring-up it belongs to.
struct AgentParts<'a> {
    identity: &'a Arc<LiveIdentity>,
    /// Managers the agent may dial before its first session message.
    bootstrap: Vec<satl_dispatcher::ManagerPeer>,
    node: &'a NodeRuntime,
    node_id: &'a Id,
    local_socket: Option<PathBuf>,
    health: satl_cluster::HealthRegistry,
}

/// Starts this node's agent session and the task that publishes its state.
/// Returns the join handles and the agent's state receiver — the channel the
/// role watcher, the REST backend and manager-list persistence read.
///
/// A manager runs an agent like every other node (architecture §1.2): it
/// schedules work to itself and receives it through its own dispatcher, over
/// the local socket when there is one.
#[allow(clippy::type_complexity)]
fn start_agent(
    parts: AgentParts<'_>,
    reporter: Arc<SessionReporter>,
    describer: Arc<dyn satl_dispatcher::NodeDescriber>,
    loops: &CancellationToken,
) -> anyhow::Result<(
    Vec<JoinHandle<()>>,
    tokio::sync::watch::Receiver<satl_dispatcher::AgentState>,
)> {
    let channels = MtlsChannels::new(parts.identity)?;
    // (The channels resolve their certificate through the live identity, so
    // the session the agent re-opens after a renewal already presents it.)
    let mut agent_cfg = AgentConfig::new(parts.node_id.clone());
    agent_cfg.local_socket.clone_from(&parts.local_socket);
    agent_cfg.bootstrap_managers = parts.bootstrap;
    // The worker's own sink for tasks, secrets and configs; the overlay wrapper
    // for networks. `satl-dispatcher` may not depend on `satl-overlay`
    // (architecture §2 lists its edges exhaustively), so the crate that owns the
    // protocol cannot own the programming — the daemon composes the two.
    let sink = Arc::new(crate::overlay::OverlaySink::new(
        satl_dispatcher::WorkerSink::new(
            Arc::clone(&parts.node.worker),
            Arc::clone(&parts.node.dependencies),
        ),
        Arc::clone(&parts.node.overlay),
    ));
    let agent = Agent::new(
        agent_cfg,
        sink,
        AgentChannels::new(channels, parts.local_socket.clone()),
        parts.node.task_db.clone(),
        reporter,
        describer,
    );
    let state = agent.state();
    let watcher = watch_session(agent.state(), parts.health.clone());
    Ok((vec![watcher, agent.spawn(loops.clone())], state))
}

/// The managers the agent may dial before its first session message.
///
/// Read from the store rather than from configuration: a restarting node
/// already knows the cluster's managers, and a fresh one is its own.
fn bootstrap_managers(store: &ClusterStore, node_id: &Id) -> Vec<satl_dispatcher::ManagerPeer> {
    let view = store.view();
    view.nodes()
        .into_iter()
        .filter(|node| node.id != *node_id)
        .filter_map(|node| {
            let status = node.manager_status.as_ref()?;
            (!status.addr.is_empty())
                .then(|| satl_dispatcher::ManagerPeer::new(node.id.clone(), status.addr.clone()))
        })
        .collect()
}

/// Bootstrap peers from bare addresses — what a worker has before its first
/// session (the join remotes, or the persisted manager list).
///
/// The node ids are placeholders: the agent uses a peer's id for logging and
/// weighting only, and the session's first message replaces this list with
/// the real one.
fn bootstrap_peers(addrs: &[String]) -> Vec<satl_dispatcher::ManagerPeer> {
    addrs
        .iter()
        .filter(|addr| !addr.is_empty())
        .map(|addr| satl_dispatcher::ManagerPeer::new(Id::generate(), addr.clone()))
        .collect()
}

/// Where a worker persists the manager list its session last reported.
fn managers_path(state_dir: &Path) -> PathBuf {
    state_dir.join("managers.json")
}

/// Spelled out for the operator-facing "no manager list" refusal.
fn certs_path_hint(state_dir: &Path) -> String {
    identity::certs_dir(state_dir).display().to_string()
}

/// The persisted manager addresses, in file order. Missing or unreadable ⇒
/// empty — the caller decides whether that is fatal.
fn load_managers(state_dir: &Path) -> Vec<String> {
    let path = managers_path(state_dir);
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<Vec<String>>(&bytes) {
            Ok(addrs) => addrs,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "unreadable manager list; ignoring it");
                Vec::new()
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "cannot read the manager list");
            Vec::new()
        }
    }
}

/// Persists `addrs` atomically (temp file + rename, like every other state
/// file). Addresses only — no identity material lives here.
fn save_managers(state_dir: &Path, addrs: &[String]) {
    let path = managers_path(state_dir);
    let bytes = match serde_json::to_vec(addrs) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, "cannot encode the manager list");
            return;
        }
    };
    let tmp = path.with_extension("tmp");
    let written = std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, &path));
    if let Err(error) = written {
        tracing::warn!(path = %path.display(), %error, "cannot persist the manager list");
    }
}

/// Keeps `<state_dir>/managers.json` equal to the manager list the session
/// last pushed, so a restarting worker knows whom to dial (SwarmKit persists
/// its remotes the same way, SWK §14.2).
fn spawn_manager_persist(
    state_dir: PathBuf,
    mut state: tokio::sync::watch::Receiver<satl_dispatcher::AgentState>,
    loops: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut last: Vec<String> = load_managers(&state_dir);
        loop {
            let current: Vec<String> = {
                let state = state.borrow_and_update();
                state
                    .managers
                    .iter()
                    .map(|peer| peer.addr.clone())
                    .filter(|addr| !addr.is_empty())
                    .collect()
            };
            if !current.is_empty() && current != last {
                save_managers(&state_dir, &current);
                tracing::info!(managers = current.len(), "manager list persisted");
                last = current;
            }
            tokio::select! {
                () = loops.cancelled() => return,
                changed = state.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    })
}

/// Who an evicted node should ask for re-admission, in order of freshness.
///
/// No certificate renewal is involved anywhere in that path: an eviction does
/// not change this node's role, so the certificate on disk is already the one
/// it needs -- and `renew_remote` would have to reach a CA this node cannot
/// currently reach anyway. All the rebuild needs is somewhere to dial.
///
/// The fallbacks are ordered by how current they are, and the *first* one is
/// the one that is normally empty here: the agent session's manager list is
/// unavailable on precisely the node that needs this, because an evicted
/// manager's session dials its own dispatcher and is refused for not being the
/// leader. The raft membership is the next best thing -- it is local, needs no
/// peer, and lists exactly the nodes that have been refusing this one, which
/// is who has to re-admit it.
fn rejoin_peers(
    session: &[String],
    ctx: Option<&satl_cluster::server::ManagerContext>,
    state_dir: &Path,
) -> Vec<String> {
    if !session.is_empty() {
        return session.to_vec();
    }
    let from_raft = ctx
        .map(satl_cluster::server::ManagerContext::peer_addrs)
        .unwrap_or_default();
    if !from_raft.is_empty() {
        return from_raft;
    }
    load_managers(state_dir)
}

/// What [`rejoin_after_eviction`] managed to do about the eviction.
enum Rejoin {
    /// The supervisor accepted the rebuild; this task is about to be replaced.
    Requested,
    /// The supervisor is gone, so there is nothing left to drive.
    SupervisorGone,
    /// Nobody to dial. Nothing was attempted; the caller retries.
    NoPeers,
}

/// Asks the supervisor to wipe this node's raft directory and re-join.
///
/// `ApplyRole` with the role this node already holds is the whole fix: its
/// manager arm wipes the raft state before every join attempt, which is
/// exactly and only what a blacklisted raft ID needs -- the ID lives in that
/// directory, and no amount of retrying re-admits the old one.
async fn rejoin_after_eviction(
    slot: &Arc<ClusterSlot>,
    eviction: &satl_cluster::transport::Eviction,
    held: NodeRole,
    raft_id: u64,
    peers: Vec<String>,
) -> Rejoin {
    tracing::warn!(
        raft_id,
        role = satl_ca::role_ou(held),
        peers = peers.len(),
        "this node's raft ID was removed from the cluster and can never be re-admitted; \
         wiping the raft directory and re-joining with a fresh ID"
    );
    if peers.is_empty() {
        // Loud, because the node cannot recover on its own from here and
        // will otherwise sit silently outside the cluster.
        tracing::error!(
            raft_id,
            "no peer address to re-join through: the agent session has none, the raft \
             membership has none, and the persisted manager list is empty. Re-join this \
             node manually"
        );
        return Rejoin::NoPeers;
    }
    // Consumed before the request, not after: the rebuild spawns its own
    // role watcher before the supervisor publishes the new core, and that
    // watcher reads this very flag off the stale one.
    eviction.clear();
    if slot
        .control(ControlRequest::ApplyRole {
            role: held,
            managers: peers,
        })
        .await
        .is_err()
    {
        return Rejoin::SupervisorGone;
    }
    Rejoin::Requested
}

/// Applies a role change to this node: when the store's role for this node
/// (pushed on the session) stops matching the certificate's OU, renew the
/// certificate against a manager's `NodeCA` — the store's role is what the CA
/// signs (architecture §12.3) — swap it live, and ask the supervisor for the
/// runtime that role runs.
///
/// This is the whole of live promotion and demotion as seen from the node:
/// the leader already did its half (the role flip for a promotion; raft
/// removal *then* the flip for a demotion, SWK §12.3 two-phase).
fn spawn_role_watch(
    state_dir: PathBuf,
    live: Arc<LiveIdentity>,
    held: NodeRole,
    mut state: tokio::sync::watch::Receiver<satl_dispatcher::AgentState>,
    slot: Arc<ClusterSlot>,
    loops: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        /// A failed renewal retries on the next tick even with no new event.
        const RETRY: std::time::Duration = std::time::Duration::from_secs(5);
        loop {
            let (wanted, managers) = {
                let current = state.borrow_and_update();
                let wanted = current.node.as_ref().map(|node| node.spec.role);
                let managers: Vec<String> = current
                    .managers
                    .iter()
                    .map(|peer| peer.addr.clone())
                    .filter(|addr| !addr.is_empty())
                    .collect();
                (wanted, managers)
            };
            // An eviction is its own trigger, checked before the role change
            // and handled without one.
            //
            // It cannot be folded into `wanted != held`, which is how the
            // first attempt at this got it wrong: `wanted` comes from the
            // agent session, and an evicted manager has no working session --
            // it dials its own dispatcher, which refuses because this node is
            // not the raft leader and never will be. So `wanted` stays `None`
            // on precisely the node that needs the rebuild, and the branch was
            // dead code where it mattered. Measured on fbsd3, where the
            // instrumented daemon logged the refusal every 15s for six minutes
            // and rebuilt nothing (decision log, 2026-08-25).
            let ctx = slot
                .get()
                .and_then(|core| core.manager.as_ref().and_then(|m| m.membership.get()));
            let evicted = ctx.as_ref().and_then(|c| {
                c.eviction
                    .evicted_raft_id()
                    .map(|id| (id, c.eviction.clone()))
            });
            // Only when the role-change path below is not going to run. That
            // path wipes the raft directory too (`apply_role` does, in both
            // arms), so it already resolves the eviction, and letting this one
            // win first would re-join raft in the *old* role just to leave it
            // again a moment later.
            let evicted = evicted.filter(|_| wanted.is_none_or(|w| w == held));
            if let Some((raft_id, eviction)) = evicted {
                let peers = rejoin_peers(&managers, ctx.as_ref(), &state_dir);
                match rejoin_after_eviction(&slot, &eviction, held, raft_id, peers).await {
                    // The rebuild replaces this task; wait to be cancelled
                    // rather than observing our own transition state.
                    Rejoin::Requested => {
                        loops.cancelled().await;
                        return;
                    }
                    Rejoin::SupervisorGone => return,
                    Rejoin::NoPeers => {
                        tokio::select! {
                            () = loops.cancelled() => return,
                            () = tokio::time::sleep(RETRY) => continue,
                        }
                    }
                }
            }
            // `held` is the *runtime's* role, not the certificate's: a
            // renewal that succeeded before a rebuild that failed must fire
            // again on the next event (renewal is idempotent), or the node
            // would sit with a manager certificate and a worker runtime.
            if let Some(wanted) = wanted
                && wanted != held
            {
                tracing::info!(
                    from = satl_ca::role_ou(held),
                    to = satl_ca::role_ou(wanted),
                    "this node's role changed in the store; renewing the certificate to apply it"
                );
                match identity::renew_remote(&state_dir, &live, &managers).await {
                    Ok(subject) if subject.role == wanted => {
                        tracing::info!(
                            node_id = %subject.node_id,
                            role = satl_ca::role_ou(subject.role),
                            "certificate renewed for the new role; rebuilding the cluster runtime"
                        );
                        if slot
                            .control(ControlRequest::ApplyRole {
                                role: subject.role,
                                managers: managers.clone(),
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }
                        // The rebuild replaces this task; wait to be cancelled
                        // rather than observing our own transition state.
                        loops.cancelled().await;
                        return;
                    }
                    Ok(subject) => tracing::warn!(
                        issued = satl_ca::role_ou(subject.role),
                        wanted = satl_ca::role_ou(wanted),
                        "the CA issued a different role than the session reported; retrying"
                    ),
                    Err(error) => tracing::warn!(
                        %error,
                        to = satl_ca::role_ou(wanted),
                        "cannot renew the certificate for the new role; retrying"
                    ),
                }
                tokio::select! {
                    () = loops.cancelled() => return,
                    () = tokio::time::sleep(RETRY) => continue,
                }
            }
            // Waiting on the session watch alone is what left the evicted node
            // parked for ever: its session never changes. The eviction future
            // is registered here, *before* the loop re-checks the flag at the
            // top, so a refusal landing in between wakes this rather than
            // being missed -- `notify_waiters` only reaches waiters already
            // registered.
            let eviction = ctx.map(|c| c.eviction.clone());
            tokio::select! {
                () = loops.cancelled() => return,
                () = async {
                    match eviction {
                        Some(eviction) => eviction.recorded().await,
                        // No manager runtime: nothing can evict this node, so
                        // park and let the other arms decide.
                        None => std::future::pending().await,
                    }
                } => {}
                changed = state.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    })
}

/// Publishes the agent's session state on the gRPC health registry, and logs
/// every transition (CLAUDE.md observability rule).
fn watch_session(
    mut state: tokio::sync::watch::Receiver<satl_dispatcher::AgentState>,
    health: satl_cluster::HealthRegistry,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut connected = false;
        loop {
            {
                let current = state.borrow_and_update();
                if current.connected() != connected {
                    connected = current.connected();
                    if connected {
                        health.set_serving(HEALTH_SERVICE_DISPATCHER);
                        tracing::info!(
                            session_id = current.session_id.as_deref().unwrap_or("?"),
                            managers = current.managers.len(),
                            "agent session established"
                        );
                    } else {
                        health.set_not_serving(HEALTH_SERVICE_DISPATCHER);
                        tracing::warn!("agent session lost; reconnecting");
                    }
                }
            }
            if state.changed().await.is_err() {
                return;
            }
        }
    })
}

/// Serves the dispatcher on a root-owned unix socket for this node's own
/// agent.
///
/// There is no TLS here and none is wanted: the socket lives in the state
/// directory (mode `0700` on a root-owned tree), so reaching it already means
/// being root on this host. The interceptor injects *this node's* identity,
/// which is exactly who the caller is.
fn local_dispatcher(
    socket: &Path,
    dispatcher: &Dispatcher,
    identity: &NodeIdentity,
    shutdown: CancellationToken,
) -> anyhow::Result<BootstrapServer> {
    let peer = satl_ca::PeerIdentity::from_pem(identity.cert_pem.as_bytes())?;
    match std::fs::remove_file(socket) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
            return Err(anyhow::Error::new(err));
        }
        _ => {}
    }
    let listener = std::os::unix::net::UnixListener::bind(socket)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    set_socket_mode(socket)?;

    let service = tonic::service::interceptor::InterceptedService::new(
        v2::dispatcher_server::DispatcherServer::new(dispatcher.clone())
            .max_decoding_message_size(satl_proto::MAX_MESSAGE_SIZE)
            .max_encoding_message_size(satl_proto::MAX_MESSAGE_SIZE),
        move |mut request: Request<()>| {
            request.extensions_mut().insert(peer.clone());
            Ok(request)
        },
    );

    let stop = shutdown.clone();
    let path = socket.to_path_buf();
    let handle = tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
        let result = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(incoming, async move { stop.cancelled().await })
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "the co-located dispatcher socket server stopped with an error");
        }
        if let Err(error) = std::fs::remove_file(&path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(socket = %path.display(), %error, "cannot remove the dispatcher socket");
        }
    });
    tracing::info!(socket = %socket.display(), "co-located dispatcher socket listening");
    Ok(BootstrapServer { shutdown, handle })
}

/// `0600` on the dispatcher socket: root only, like everything else in the
/// state directory.
fn set_socket_mode(socket: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
}

/// Serves `NodeCA` on the bootstrap listener: TLS with this node's
/// certificate, **no client certificate required**.
///
/// `proto/ca.proto` spells out why this exists — a node that has never joined
/// has nothing to present — and what makes it safe: the response of
/// `GetRootCACertificate` is public and is pinned by the caller against its
/// join token digest, and the token in `IssueNodeCertificate` is compared in
/// constant time against the cluster's own.
///
/// It is a second listener rather than a policy on the main one because
/// `satl_cluster::ServerBuilder` builds a mandatory client-certificate
/// verifier for every connection it accepts; making that per-service is a
/// change to that crate, not to this one.
async fn bootstrap_ca(
    addr: std::net::SocketAddr,
    ca: &NodeCaService,
    identity: &Arc<LiveIdentity>,
    shutdown: CancellationToken,
) -> anyhow::Result<BootstrapServer> {
    let tls = satl_ca::live_anonymous_server_config(identity)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let service = ca.server();

    let stop = shutdown.clone();
    let handle = tokio::spawn(async move {
        let incoming = async_stream::accept_tls(listener, acceptor, stop.clone());
        let result = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(incoming, async move { stop.cancelled().await })
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "the NodeCA bootstrap server stopped with an error");
        }
    });
    tracing::info!(addr = %local_addr, "NodeCA bootstrap endpoint listening");
    Ok(BootstrapServer { shutdown, handle })
}

/// The accept loop shared by the auxiliary TLS listener.
mod async_stream {

    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::server::TlsStream;
    use tokio_util::sync::CancellationToken;

    /// How long a peer has to complete its TLS handshake.
    const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// Accepted connections, one handshake per task so a stalled peer cannot
    /// wedge the loop (the same shape `satl_cluster::server` uses).
    pub fn accept_tls(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        shutdown: CancellationToken,
    ) -> tokio_stream::wrappers::ReceiverStream<Result<TlsStream<TcpStream>, std::io::Error>> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    () = shutdown.cancelled() => return,
                    accepted = listener.accept() => accepted,
                };
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(%error, "accepting a NodeCA bootstrap connection failed");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if tx.is_closed() {
                    return;
                }
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let _ = tx.send(Ok(tls)).await;
                        }
                        Ok(Err(error)) => {
                            tracing::debug!(%peer, %error, "NodeCA bootstrap handshake failed");
                        }
                        Err(_) => tracing::debug!(%peer, "NodeCA bootstrap handshake timed out"),
                    }
                });
            }
        });
        tokio_stream::wrappers::ReceiverStream::new(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deferred_store_answers_unavailable_until_it_is_installed() {
        let deferred = DeferredStore::default();
        let Err(status) = deferred.get() else {
            panic!("nothing is installed yet, so the store must be unavailable");
        };
        assert_eq!(status.code(), tonic::Code::Unavailable);
    }

    #[test]
    fn a_deferred_dispatcher_answers_unavailable_until_it_is_installed() {
        let deferred = DeferredDispatcher::default();
        let Err(status) = deferred.get() else {
            panic!("nothing is installed yet, so the store must be unavailable");
        };
        assert_eq!(status.code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn the_slot_starts_empty_and_publishes_what_it_is_given() {
        let (slot, mut rx) = ClusterSlot::new();
        assert!(slot.get().is_none());

        let (reply, _wait) = tokio::sync::oneshot::channel();
        slot.control(ControlRequest::Leave { force: true, reply })
            .await
            .expect("the supervisor is listening");
        let request = rx.recv().await.expect("a request arrived");
        assert!(matches!(request, ControlRequest::Leave { force: true, .. }));
    }

    #[test]
    fn the_dispatcher_socket_lives_in_the_state_directory() {
        assert_eq!(
            ClusterRuntime::dispatcher_socket(Path::new("/var/db/satl")),
            PathBuf::from("/var/db/satl/dispatcher.sock")
        );
    }

    #[test]
    fn an_anonymous_server_config_is_built_from_a_node_identity() {
        let identity = satl_cluster::testing::test_live_identity();
        satl_ca::live_anonymous_server_config(&identity).expect("config");
    }
}
