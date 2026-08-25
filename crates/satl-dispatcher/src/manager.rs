// SPDX-License-Identifier: BSD-2-Clause
//! The manager side: the `Dispatcher` gRPC service and its background loops
//! (architecture §7.1, SWK §13).
//!
//! # Direction rule (CLAUDE.md invariant #3)
//!
//! **Nothing in this module dials anything.** There is no client, no address
//! book of workers, no `connect`. Every code path here starts from a request
//! a worker made and ends on a stream a worker is holding open. The manager's
//! only way to reach a node is to park a message on that node's session or
//! assignment stream — which is precisely why both are server-streaming. A
//! future feature that "just needs to poke a worker" gets a new
//! agent-initiated RPC, not a dial.
//!
//! # Leader-only
//!
//! The service is registered on every manager, but only the leader serves it:
//! a follower answers `FAILED_PRECONDITION` and puts the leader's address in
//! the [`LEADER_ADDR_METADATA`](crate::LEADER_ADDR_METADATA) response
//! metadata so the agent can redial without waiting for a session message.
//! Leadership is read from Raft metrics rather than from a flag someone has
//! to remember to flip.
//!
//! # What runs where
//!
//! | Piece | Where it lives |
//! |---|---|
//! | session registration, heartbeat, status ingest | the RPC handlers, synchronous |
//! | per-node session stream (node object, managers, root CA) | one task per open stream |
//! | per-node assignment stream (snapshot + diffs) | one task per open stream |
//! | TTL sweep, `DOWN`, 24 h orphaning, leadership transitions | one background task |
//! | status batching into the store | one background task |
//!
//! Each stream task owns its own store watch subscription and its own
//! [`AssignmentTracker`]: a lagged subscription then means "re-sync this one
//! node", not "re-sync the cluster".

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use satl_ca::{PeerIdentity, RoleRequirement};
use satl_cluster::{ClusterStore, ProposalRejection, ProposeError};
use satl_core::defaults::MAX_TX_ACTIONS;
use satl_core::{
    Availability, Config, Id, Ipv4Cidr, Network, Node, NodeState, ObjectKind, Secret, StoreAction,
    StoreEvent, StoreObject, Task, TaskState,
};
use satl_proto::v2;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};
use tracing::Instrument as _;

use crate::assignment::{
    AssignmentChange, AssignmentItem, AssignmentTracker, ChangeAction, DependencyLookup,
    GatewayAttachment, NetworkAssignment, NetworkEndpoint, ObjectRef, belongs_to, is_endpoint,
    split_batches,
};
use crate::codec;
use crate::liveness::{HeartbeatConfig, Liveness, SessionRejection};
use crate::peer::ManagerPeer;
use crate::sequence::SequenceGenerator;
use crate::status::{StatusQueue, StatusWriter};
use crate::{
    ASSIGNMENT_BATCH_MAX, ASSIGNMENT_QUIESCENCE, MANAGER_WEIGHT, STATUS_FLUSH_INTERVAL,
    STATUS_FLUSH_MAX,
};

/// Buffered messages per open stream before the sender blocks. Small on
/// purpose: an agent that cannot keep up should slow the manager's stream
/// task down, not grow a queue of stale assignments.
const STREAM_BUFFER: usize = 16;

/// Upper bound on how long the sweep loop sleeps when nothing is due, so a
/// newly registered node is picked up promptly.
const SWEEP_MAX_SLEEP: Duration = Duration::from_secs(1);

/// Dispatcher tuning. The defaults are architecture §15; tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatcherConfig {
    /// Heartbeat period, jitter, TTL factor and the orphaning delay.
    pub heartbeat: HeartbeatConfig,
    /// Maximum changes in one `INCREMENTAL` message.
    pub assignment_batch_max: usize,
    /// Quiescence window assignment changes are batched over.
    pub assignment_quiescence: Duration,
    /// How often queued status updates are flushed into the store.
    pub status_flush_interval: Duration,
    /// Queued status updates that force an immediate flush.
    pub status_flush_max: usize,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            heartbeat: HeartbeatConfig::default(),
            assignment_batch_max: ASSIGNMENT_BATCH_MAX,
            assignment_quiescence: ASSIGNMENT_QUIESCENCE,
            status_flush_interval: STATUS_FLUSH_INTERVAL,
            status_flush_max: STATUS_FLUSH_MAX,
        }
    }
}

/// One open session: the ID the manager issued and the token that tears down
/// its streams when it is superseded or voided.
#[derive(Debug)]
struct SessionEntry {
    session_id: String,
    cancel: CancellationToken,
}

struct Inner {
    store: ClusterStore,
    manager_id: Id,
    config: DispatcherConfig,
    liveness: Mutex<Liveness>,
    sessions: Mutex<BTreeMap<Id, SessionEntry>>,
    statuses: Mutex<StatusQueue>,
    status_ready: tokio::sync::Notify,
    writer: StatusWriter,
}

impl Inner {
    fn liveness(&self) -> MutexGuard<'_, Liveness> {
        self.liveness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn sessions(&self) -> MutexGuard<'_, BTreeMap<Id, SessionEntry>> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn statuses(&self) -> MutexGuard<'_, StatusQueue> {
        self.statuses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The dispatcher: a tonic service plus the loops that keep node liveness and
/// task status moving.
///
/// Cheap to clone (`Arc` inside) — clone it into
/// [`v2::dispatcher_server::DispatcherServer`] and keep one for the
/// leadership supervisor.
#[derive(Clone)]
pub struct Dispatcher {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher")
            .field("manager_id", &self.inner.manager_id)
            .field("sessions", &self.inner.sessions().len())
            .finish_non_exhaustive()
    }
}

impl Dispatcher {
    /// A dispatcher serving `store`, stamping `manager_id` on the statuses it
    /// applies.
    #[must_use]
    pub fn new(store: ClusterStore, manager_id: Id, config: DispatcherConfig) -> Self {
        let writer = StatusWriter::new(store.clone(), manager_id.clone());
        Self {
            inner: Arc::new(Inner {
                store,
                manager_id,
                config,
                liveness: Mutex::new(Liveness::new(config.heartbeat)),
                sessions: Mutex::new(BTreeMap::new()),
                statuses: Mutex::new(StatusQueue::new()),
                status_ready: tokio::sync::Notify::new(),
                writer,
            }),
        }
    }

    /// The tonic service to register on the internal gRPC server.
    ///
    /// Register it on the node's one internal server:
    ///
    /// ```ignore
    /// builder.add_service(RoleRequirement::WorkerOrManager, dispatcher.server())
    /// ```
    ///
    /// `satl_cluster::ServerBuilder::add_service` wraps the service in the
    /// mTLS authorization interceptor, which puts the authenticated
    /// [`PeerIdentity`] in the request extensions — where every handler here
    /// reads it from. On a server assembled by hand, install
    /// [`identity_interceptor`] instead. Without either, every RPC is
    /// `UNAUTHENTICATED`: this service never guesses who is calling.
    #[must_use]
    pub fn server(&self) -> v2::dispatcher_server::DispatcherServer<Self> {
        v2::dispatcher_server::DispatcherServer::new(self.clone())
            .max_decoding_message_size(satl_proto::MAX_MESSAGE_SIZE)
            .max_encoding_message_size(satl_proto::MAX_MESSAGE_SIZE)
    }

    /// Starts the background loops: the TTL sweep (with the `DOWN` and
    /// orphaning transitions) and the status flusher.
    ///
    /// They stop when `shutdown` is cancelled.
    #[must_use]
    pub fn spawn(&self, shutdown: CancellationToken) -> Vec<JoinHandle<()>> {
        vec![
            tokio::spawn(sweep_loop(Arc::clone(&self.inner), shutdown.clone())),
            tokio::spawn(status_loop(Arc::clone(&self.inner), shutdown)),
        ]
    }

    /// The node ID this dispatcher stamps as `applied_by`.
    #[must_use]
    pub fn manager_id(&self) -> &Id {
        &self.inner.manager_id
    }

    /// How many sessions are currently open (tests and metrics).
    #[must_use]
    pub fn open_sessions(&self) -> usize {
        self.inner.sessions().len()
    }

    /// The liveness state this manager holds for a node.
    #[must_use]
    pub fn node_state(&self, node_id: &Id) -> Option<NodeState> {
        self.inner.liveness().state(node_id)
    }

    /// Validates the caller and their session, and refuses if this manager is
    /// not the leader.
    fn authorize<T>(&self, request: &Request<T>, session_id: &str) -> Result<Id, Status> {
        let identity = self.identify(request)?;
        require_leader(&self.inner.store)?;
        self.inner
            .liveness()
            .validate(&identity.node_id, session_id)
            .map_err(|rejection| rejection_status(&rejection))?;
        Ok(identity.node_id)
    }

    /// Authenticates the caller and applies the RPC authorization matrix
    /// (SWK §16.7): a `satl-worker` or `satl-manager` certificate from *this*
    /// cluster, not blacklisted.
    fn identify<T>(&self, request: &Request<T>) -> Result<PeerIdentity, Status> {
        let identity = peer_identity(request)?;
        let (cluster_id, blacklist) = {
            let view = self.inner.store.view();
            match view.cluster() {
                Some(cluster) => (
                    cluster.id.to_string(),
                    cluster.blacklisted_certs.keys().cloned().collect(),
                ),
                None => (String::new(), BTreeSet::new()),
            }
        };
        if cluster_id.is_empty() {
            return Err(Status::failed_precondition(
                "this manager has no cluster object yet; it is still bootstrapping",
            ));
        }
        identity
            .authorize(RoleRequirement::WorkerOrManager, &cluster_id, &blacklist)
            .map_err(|error| Status::permission_denied(error.to_string()))?;
        Ok(identity)
    }
}

/// Reads the authenticated caller out of a request.
///
/// Looks in the extensions first (where [`identity_interceptor`] — or a test
/// harness — puts it), then falls back to the mTLS peer certificate. A
/// request with neither is `UNAUTHENTICATED`: there is no anonymous access to
/// the dispatcher.
pub fn peer_identity<T>(request: &Request<T>) -> Result<PeerIdentity, Status> {
    if let Some(identity) = request.extensions().get::<PeerIdentity>() {
        return Ok(identity.clone());
    }
    let certs = request.peer_certs().ok_or_else(|| {
        Status::unauthenticated(
            "no client certificate on this connection: the dispatcher is mTLS-only",
        )
    })?;
    let leaf = certs.first().ok_or_else(|| {
        Status::unauthenticated("the client presented an empty certificate chain")
    })?;
    PeerIdentity::from_certificate(leaf).map_err(|error| {
        Status::unauthenticated(format!(
            "the client certificate does not carry a usable satl identity: {error}"
        ))
    })
}

/// Interceptor that turns the mTLS peer certificate into a [`PeerIdentity`]
/// in the request extensions.
///
/// Install it on the dispatcher service; the handlers then never touch
/// certificates, and a test harness can inject an identity the same way.
///
/// # Errors
///
/// `UNAUTHENTICATED` when the connection carries no usable client
/// certificate.
pub fn identity_interceptor(mut request: Request<()>) -> Result<Request<()>, Status> {
    let identity = peer_identity(&request)?;
    request.extensions_mut().insert(identity);
    Ok(request)
}

/// Refuses the call unless this node is the Raft leader, redirecting to the
/// leader the same way every other leader-only RPC does
/// ([`satl_cluster::forward::leader_redirect_status`], architecture §6.5).
fn require_leader(store: &ClusterStore) -> Result<(), Status> {
    if store.metrics().is_leader {
        return Ok(());
    }
    Err(satl_cluster::forward::leader_redirect_status(
        store.leader_addr().as_deref(),
        "this manager is not the raft leader; the dispatcher runs on the leader only. \
         Re-register with the manager in the satl-leader-addr metadata",
    ))
}

/// The gRPC status the proto pins for each liveness rejection.
fn rejection_status(rejection: &SessionRejection) -> Status {
    match rejection {
        SessionRejection::NotRegistered { .. } => Status::not_found(rejection.to_string()),
        SessionRejection::SessionInvalid { .. } => {
            Status::failed_precondition(rejection.to_string())
        }
    }
}

/// Secrets, configs and networks read straight from the store.
struct StoreDeps<'a> {
    store: &'a ClusterStore,
}

impl DependencyLookup for StoreDeps<'_> {
    fn secret(&self, id: &Id) -> Option<Secret> {
        let view = self.store.view();
        view.secret(id).map(|secret| (*secret).clone())
    }

    fn config(&self, id: &Id) -> Option<Config> {
        let view = self.store.view();
        view.config(id).map(|config| (*config).clone())
    }

    fn network(&self, id: &Id) -> Option<NetworkAssignment> {
        let view = self.store.view();
        let network = view.network(id)?;
        Some(network_assignment(&view, &network))
    }
}

/// The network plus its endpoint table, as of one store read.
///
/// This is the whole of the FDB distribution channel (architecture §11.2): it
/// walks every task attached to the network cluster-wide, keeps the ones that
/// are live endpoints, and pairs each one's overlay address with the underlay
/// VTEP of the node running it. A task whose address or node cannot be resolved
/// is **skipped with a warning** rather than dropped silently or faked: a
/// missing entry is a peer that cannot be reached, and that has to be visible
/// in the log of the manager that produced the table.
fn network_assignment(view: &satl_cluster::StoreView<'_>, network: &Network) -> NetworkAssignment {
    let mut assignment = NetworkAssignment::new(network.clone());
    // One line per node, not per task: a node running ten tasks on a network
    // would otherwise repeat the same complaint ten times per pass.
    let mut inferred: BTreeSet<Id> = BTreeSet::new();
    for task in view.tasks() {
        if !is_endpoint(&task) {
            continue;
        }
        let Some(attachment) = task
            .networks
            .iter()
            .find(|attachment| attachment.network_id == network.id)
        else {
            continue;
        };
        let Some(node_id) = task.node_id.clone() else {
            continue;
        };
        let Some(addr) = overlay_address(&attachment.addresses) else {
            tracing::warn!(
                task_id = %task.id,
                network_id = %network.id,
                addresses = ?attachment.addresses,
                "task is attached to a network with no usable IPv4 address; peers cannot reach it"
            );
            continue;
        };
        let Some((vtep, source)) = view.node(&node_id).as_deref().and_then(node_vtep) else {
            tracing::warn!(
                task_id = %task.id,
                node_id = %node_id,
                network_id = %network.id,
                "node has reported no underlay address: its VTEP is unknown, so no peer can \
                 program an fdb entry for this task and traffic to it is black-holed. Check \
                 advertise_addr in that node's satld.toml and that its agent holds a session"
            );
            continue;
        };
        if source == VtepSource::Observed && inferred.insert(node_id.clone()) {
            tracing::warn!(
                node_id = %node_id,
                network_id = %network.id,
                %vtep,
                "no underlay address reported by this node; falling back to the address its agent \
                 was seen connecting from. That is the control-plane path, not necessarily the \
                 data-plane one; if overlay traffic to this node goes nowhere, this is why"
            );
        }
        assignment.endpoints.insert(
            task.id.clone(),
            NetworkEndpoint {
                task_id: task.id.clone(),
                node_id,
                addr,
                vtep,
                // The DNS half of the table (§11.5): a node with no store
                // answers service names from these, so the names and the
                // observed state ship with the address. `state` moving also
                // moves the assignment value, which is what pushes "this task
                // left RUNNING" to every node answering for it.
                service_name: task.service_annotations.name.clone(),
                task_name: task.annotations.name.clone(),
                aliases: attachment.aliases.clone(),
                state: task.status.state,
            },
        );
    }
    // The per-node load-balancer attachments (M6d): every gateway the network
    // records, paired with that node's VTEP. A gateway whose node has no
    // usable underlay address is skipped with a warning, like an endpoint's.
    for (node_id, gateway) in &network.node_gateways {
        let Ok(addr) = gateway.parse::<Ipv4Addr>() else {
            tracing::warn!(
                network_id = %network.id,
                node_id = %node_id,
                %gateway,
                "a network records a gateway address that is not an IPv4 address; skipped"
            );
            continue;
        };
        let Some((vtep, _)) = view.node(node_id).as_deref().and_then(node_vtep) else {
            tracing::warn!(
                network_id = %network.id,
                node_id = %node_id,
                %gateway,
                "the gateway's node has reported no underlay address: peers cannot program an \
                 fdb entry for it, and traffic relayed through it is black-holed"
            );
            continue;
        };
        assignment.gateways.insert(
            node_id.clone(),
            GatewayAttachment {
                node_id: node_id.clone(),
                addr,
                vtep,
            },
        );
    }
    assignment
}

/// The first usable IPv4 address of an attachment, host bits included.
///
/// Addresses are stored in CIDR form (`10.100.4.5/24`); the prefix belongs to
/// the network, so only the address travels in the endpoint table.
fn overlay_address(addresses: &[String]) -> Option<Ipv4Addr> {
    addresses
        .iter()
        .filter_map(|text| text.parse::<Ipv4Cidr>().ok())
        .map(Ipv4Cidr::addr)
        .next()
}

/// Where a node's VTEP address came from, in descending order of trust.
///
/// Carried out of [`node_vtep`] rather than kept private because the *source* is
/// the diagnosis: an overlay that carries traffic one way only is almost always a
/// VTEP that was inferred instead of reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VtepSource {
    /// The node's own report ([`satl_core::NodeDescription::data_addr`]).
    Reported,
    /// A manager's raft advertise address.
    ManagerAdvertise,
    /// The address the dispatcher observed the agent connecting from.
    Observed,
}

/// A node's underlay VTEP address (architecture §11.2: the node's own address on
/// the private underlay).
///
/// Three sources, in descending order of trust:
///
/// 1. `description.data_addr` — **the node's own answer**, taken from its
///    `advertise_addr` configuration and shipped in the node description at
///    registration. The only source that is not somebody else's inference, and
///    the only one a worker has.
/// 2. `manager_status.addr` — the raft address a *manager* advertises. Same
///    configured value in practice, so it is a clean fallback for a manager whose
///    agent has not re-registered since [`VtepSource::Reported`] existed; absent
///    on every worker, because managers never dial workers (invariant #3).
/// 3. `status.addr` — the address this node was last seen connecting *from*.
///    Kept only so an overlay does not go dark on a node that has not reported
///    yet, and warned about where it is used: it is the underlay address only for
///    as long as agents happen to reach their managers over the underlay, and it
///    is the source the M3 fix exists to stop trusting.
///
/// Any of them may carry a port (`10.2.0.5:2377`), which is stripped: the VXLAN
/// UDP port is the overlay's, not the control plane's.
fn node_vtep(node: &Node) -> Option<(Ipv4Addr, VtepSource)> {
    let candidates = [
        (
            node.description
                .as_ref()
                .and_then(|description| description.data_addr.as_deref()),
            VtepSource::Reported,
        ),
        (
            node.manager_status
                .as_ref()
                .map(|status| status.addr.as_str()),
            VtepSource::ManagerAdvertise,
        ),
        (Some(node.status.addr.as_str()), VtepSource::Observed),
    ];
    candidates
        .into_iter()
        .find_map(|(value, source)| Some((parse_underlay_addr(value?)?, source)))
}

/// The IPv4 address in a `host` or `host:port` string.
fn parse_underlay_addr(value: &str) -> Option<Ipv4Addr> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(addr) = value.parse::<Ipv4Addr>() {
        return Some(addr);
    }
    match value.parse::<std::net::SocketAddr>() {
        Ok(std::net::SocketAddr::V4(addr)) => Some(*addr.ip()),
        _ => None,
    }
}

/// Everything the session stream pushes, as of one store read.
#[derive(Debug, Clone, PartialEq)]
struct SessionSnapshot {
    node: Node,
    managers: Vec<ManagerPeer>,
    root_ca: Option<Vec<u8>>,
}

/// Reads the session snapshot for `node_id`; `None` when the node object is
/// gone (the stream then ends, per the proto).
fn session_snapshot(store: &ClusterStore, node_id: &Id) -> Option<SessionSnapshot> {
    let view = store.view();
    let node = view.node(node_id)?;
    let mut managers: Vec<ManagerPeer> = view
        .nodes()
        .into_iter()
        .filter_map(|node| {
            let status = node.manager_status.as_ref()?;
            (!status.addr.is_empty()).then(|| ManagerPeer {
                node_id: node.id.clone(),
                addr: status.addr.clone(),
                weight: MANAGER_WEIGHT,
            })
        })
        .collect();
    managers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    let root_ca = view
        .cluster()
        .and_then(|cluster| cluster.root_ca_cert.clone());
    Some(SessionSnapshot {
        node: (*node).clone(),
        managers,
        root_ca,
    })
}

/// Builds a session message, sending only what changed since `previous`.
///
/// `session_id` is on every message; the other fields use protobuf presence,
/// where absent means "unchanged since the last message on this stream"
/// (`proto/dispatcher.proto`).
fn session_message(
    session_id: &str,
    current: &SessionSnapshot,
    previous: Option<&SessionSnapshot>,
) -> Result<v2::SessionMessage, codec::CodecError> {
    let node_changed = previous.is_none_or(|old| old.node != current.node);
    let managers_changed = previous.is_none_or(|old| old.managers != current.managers);
    let ca_changed = previous.is_none_or(|old| old.root_ca != current.root_ca);
    Ok(v2::SessionMessage {
        session_id: session_id.to_owned(),
        node: node_changed
            .then(|| codec::encode_node(&current.node))
            .transpose()?,
        managers: if managers_changed {
            current
                .managers
                .iter()
                .map(|peer| v2::WeightedPeer {
                    node_id: peer.node_id.to_string(),
                    addr: peer.addr.clone(),
                    weight: peer.weight,
                })
                .collect()
        } else {
            Vec::new()
        },
        root_ca_bundle: if ca_changed {
            current.root_ca.clone()
        } else {
            None
        },
    })
}

/// One assignment message on the wire.
fn assignments_message(
    kind: v2::assignments_message::Type,
    applies_to: &str,
    results_in: &str,
    changes: &[AssignmentChange],
) -> Result<v2::AssignmentsMessage, codec::CodecError> {
    let mut wire = Vec::with_capacity(changes.len());
    for change in changes {
        let item = match (&change.item, change.key.kind) {
            (Some(AssignmentItem::Task(task)), _) => {
                v2::assignment::Item::Task(codec::encode_task(task)?)
            }
            (Some(AssignmentItem::Secret(secret)), _) => {
                v2::assignment::Item::Secret(codec::encode_secret(secret)?)
            }
            (Some(AssignmentItem::Config(config)), _) => {
                v2::assignment::Item::Config(codec::encode_config(config)?)
            }
            (Some(AssignmentItem::Network(network)), _) => {
                v2::assignment::Item::Network(codec::encode_network(network)?)
            }
            (None, ObjectRef::Task) => {
                v2::assignment::Item::Task(codec::task_removal(&change.key.id))
            }
            (None, ObjectRef::Secret) => {
                v2::assignment::Item::Secret(codec::secret_removal(&change.key.id))
            }
            (None, ObjectRef::Config) => {
                v2::assignment::Item::Config(codec::config_removal(&change.key.id))
            }
            (None, ObjectRef::Network) => {
                v2::assignment::Item::Network(codec::network_removal(&change.key.id))
            }
        };
        wire.push(v2::AssignmentChange {
            assignment: Some(v2::Assignment { item: Some(item) }),
            action: match change.action {
                ChangeAction::Update => v2::assignment_change::Action::Update as i32,
                ChangeAction::Remove => v2::assignment_change::Action::Remove as i32,
            },
        });
    }
    Ok(v2::AssignmentsMessage {
        r#type: kind as i32,
        applies_to: applies_to.to_owned(),
        results_in: results_in.to_owned(),
        changes: wire,
    })
}

#[tonic::async_trait]
impl v2::dispatcher_server::Dispatcher for Dispatcher {
    type SessionStream = ReceiverStream<Result<v2::SessionMessage, Status>>;
    type AssignmentsStream = ReceiverStream<Result<v2::AssignmentsMessage, Status>>;

    #[tracing::instrument(skip_all, fields(node_id, session_id))]
    async fn session(
        &self,
        request: Request<v2::SessionRequest>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        let identity = self.identify(&request)?;
        require_leader(&self.inner.store)?;
        let node_id = identity.node_id.clone();
        tracing::Span::current().record("node_id", tracing::field::display(&node_id));
        let addr = request
            .remote_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_default();
        let message = request.into_inner();

        // The node object must already exist: it is born at certificate
        // issuance (architecture §12.2) and NEVER by the dispatcher. A
        // session for an unknown node is a bug on the CA side, so it is a
        // hard error rather than a silent create.
        {
            let view = self.inner.store.view();
            if view.node(&node_id).is_none() {
                return Err(Status::not_found(format!(
                    "node {node_id} has no node object: it is created when its certificate is \
                     issued, so this node must re-join with a fresh token"
                )));
            }
        }

        let description = codec::decode_description(&message.description)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;

        // Fresh, random, never persisted, never reused (SWK §13.1).
        let session_id = Id::generate().to_string();
        tracing::Span::current().record("session_id", tracing::field::display(&session_id));
        let period = {
            let mut rng = rand::rng();
            self.inner.config.heartbeat.dictate(&mut rng)
        };

        let superseded =
            self.inner
                .liveness()
                .register(&node_id, session_id.clone(), period, Instant::now());

        // Mark the node READY before answering: the agent is entitled to
        // assume its registration is durable once the first session message
        // arrives (SWK §13.1 blocks on the same write).
        if let Err(error) =
            mark_ready(&self.inner.store, &node_id, &addr, description.as_ref()).await
        {
            tracing::warn!(%error, "could not record the node as ready; the session still opens");
        }

        let cancel = CancellationToken::new();
        self.replace_session(&node_id, &session_id, cancel.clone());
        if let Some(previous) = superseded {
            tracing::info!(
                superseded = %previous,
                "re-registration superseded the previous session; its streams are being torn down"
            );
        }

        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        tokio::spawn(session_loop(
            Arc::clone(&self.inner),
            node_id.clone(),
            session_id.clone(),
            tx,
            cancel,
        ));
        tracing::info!(
            node_id = %node_id,
            session_id = %session_id,
            addr = %addr,
            period_ms = period.as_millis(),
            "agent session registered"
        );
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    #[tracing::instrument(skip_all, fields(node_id))]
    async fn heartbeat(
        &self,
        request: Request<v2::HeartbeatRequest>,
    ) -> Result<Response<v2::HeartbeatResponse>, Status> {
        let session_id = request.get_ref().session_id.clone();
        let node_id = self.authorize(&request, &session_id)?;
        tracing::Span::current().record("node_id", tracing::field::display(&node_id));
        let period = {
            let mut rng = rand::rng();
            self.inner.config.heartbeat.dictate(&mut rng)
        };
        let period = self
            .inner
            .liveness()
            .heartbeat(&node_id, &session_id, period, Instant::now())
            .map_err(|rejection| rejection_status(&rejection))?;
        tracing::trace!(period_ms = period.as_millis(), "heartbeat");
        Ok(Response::new(v2::HeartbeatResponse {
            period: Some(codec::duration_to_proto(period)),
        }))
    }

    #[tracing::instrument(skip_all, fields(node_id, updates = request.get_ref().updates.len()))]
    async fn update_task_status(
        &self,
        request: Request<v2::UpdateTaskStatusRequest>,
    ) -> Result<Response<v2::UpdateTaskStatusResponse>, Status> {
        let session_id = request.get_ref().session_id.clone();
        let node_id = self.authorize(&request, &session_id)?;
        tracing::Span::current().record("node_id", tracing::field::display(&node_id));
        let message = request.into_inner();

        let mut accepted = 0_usize;
        for update in &message.updates {
            let (task_id, status) = codec::decode_status(update)
                .map_err(|error| Status::invalid_argument(error.to_string()))?;

            // Anti-spoofing (SWK §13.3): an unknown task is skipped — the
            // manager may have deleted it — but a task belonging to another
            // node is a permission error, not a skip.
            let owner = {
                let view = self.inner.store.view();
                view.task(&task_id).map(|task| task.node_id.clone())
            };
            match owner {
                None => {
                    tracing::debug!(task_id = %task_id, "status for an unknown task; skipped");
                    continue;
                }
                Some(owner) if owner.as_ref() != Some(&node_id) => {
                    return Err(Status::permission_denied(format!(
                        "node {node_id} reported status for task {task_id}, which is assigned to \
                         {}",
                        owner.map_or_else(|| "no node".to_owned(), |id| id.to_string())
                    )));
                }
                Some(_) => {}
            }

            if self.inner.statuses().push(&task_id, status) {
                accepted += 1;
            }
        }

        let pending = self.inner.statuses().len();
        if accepted > 0 && pending >= self.inner.config.status_flush_max {
            self.inner.status_ready.notify_one();
        }
        tracing::debug!(accepted, pending, "task status batch queued");
        Ok(Response::new(v2::UpdateTaskStatusResponse {}))
    }

    #[tracing::instrument(skip_all, fields(node_id))]
    async fn assignments(
        &self,
        request: Request<v2::AssignmentsRequest>,
    ) -> Result<Response<Self::AssignmentsStream>, Status> {
        let session_id = request.get_ref().session_id.clone();
        let node_id = self.authorize(&request, &session_id)?;
        tracing::Span::current().record("node_id", tracing::field::display(&node_id));

        // The stream dies with the session that owns it.
        let cancel = self
            .inner
            .sessions()
            .get(&node_id)
            .filter(|entry| entry.session_id == session_id)
            .map(|entry| entry.cancel.clone())
            .ok_or_else(|| {
                Status::failed_precondition(
                    "the session backing this assignment stream is gone; re-register",
                )
            })?;

        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        tokio::spawn(assignment_loop(
            Arc::clone(&self.inner),
            node_id,
            session_id,
            tx,
            cancel,
        ));
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

impl Dispatcher {
    /// Installs a session, tearing down the streams of whatever the node had
    /// before (SWK §13.1: re-registration invalidates the previous session).
    fn replace_session(&self, node_id: &Id, session_id: &str, cancel: CancellationToken) {
        let previous = self.inner.sessions().insert(
            node_id.clone(),
            SessionEntry {
                session_id: session_id.to_owned(),
                cancel,
            },
        );
        if let Some(entry) = previous {
            entry.cancel.cancel();
        }
    }
}

// ---------------------------------------------------------------------------
// Store writes
// ---------------------------------------------------------------------------

/// Applies `edit` to a node object and commits it, retrying the
/// optimistic-concurrency race.
async fn update_node(
    store: &ClusterStore,
    node_id: &Id,
    what: &'static str,
    mut edit: impl FnMut(&mut Node) -> bool + Send,
) -> Result<bool, ProposeError> {
    for _ in 0..crate::status::MAX_WRITE_ATTEMPTS {
        let current = {
            let view = store.view();
            view.node(node_id).map(|node| (*node).clone())
        };
        let Some(mut node) = current else {
            return Ok(false);
        };
        if !edit(&mut node) {
            return Ok(false);
        }
        node.meta.updated_at = SystemTime::now();
        match store
            .propose(vec![StoreAction::Update(StoreObject::Node(node))])
            .await
        {
            Ok(_) => return Ok(true),
            Err(ProposeError::Rejected(ProposalRejection::SequenceConflict { .. })) => {
                tracing::debug!(node_id = %node_id, what, "sequence conflict; re-reading");
            }
            Err(ProposeError::Rejected(ProposalRejection::NotFound { .. })) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    tracing::warn!(node_id = %node_id, what, "gave up after repeated sequence conflicts");
    Ok(false)
}

/// The status message that belongs with each liveness state.
///
/// One mapping, used by every writer here *and* by
/// [`heal_node_states`]. If the edge writes and the reconciliation disagreed on
/// the message, each would see the other's node object as wrong and rewrite it:
/// a store write per sweep, forever, on a healthy cluster.
fn state_message(state: NodeState) -> &'static str {
    match state {
        NodeState::Ready => "session registered",
        NodeState::Down => "heartbeat failure",
        NodeState::Unknown => {
            "node moved to unknown state due to a leadership change in the cluster"
        }
        NodeState::Disconnected => "session invalidated",
    }
}

/// Sets a node's liveness state and the message that goes with it, reporting
/// whether anything actually changed.
fn apply_state(node: &mut Node, state: NodeState) -> bool {
    let message = state_message(state);
    let mut changed = false;
    if node.status.state != state {
        node.status.state = state;
        changed = true;
    }
    if node.status.message != message {
        message.clone_into(&mut node.status.message);
        changed = true;
    }
    changed
}

/// Records a registering node as `READY`, with its address and description.
async fn mark_ready(
    store: &ClusterStore,
    node_id: &Id,
    addr: &str,
    description: Option<&satl_core::NodeDescription>,
) -> Result<(), ProposeError> {
    update_node(store, node_id, "registration", |node| {
        let mut changed = apply_state(node, NodeState::Ready);
        if !addr.is_empty() && node.status.addr != addr {
            addr.clone_into(&mut node.status.addr);
            changed = true;
        }
        if let Some(description) = description
            && node.description.as_ref() != Some(description)
        {
            node.description = Some(description.clone());
            changed = true;
        }
        changed
    })
    .await
    .map(|_| ())
}

/// Records a node as `DOWN` after its heartbeat TTL expired.
async fn mark_down(store: &ClusterStore, node_id: &Id) {
    let result = update_node(store, node_id, "heartbeat failure", |node| {
        if node.status.state == NodeState::Down {
            return false;
        }
        apply_state(node, NodeState::Down)
    })
    .await;
    match result {
        Ok(true) => tracing::warn!(node_id = %node_id, "node marked down: heartbeat failure"),
        Ok(false) => {}
        Err(error) => {
            tracing::warn!(node_id = %node_id, %error, "cannot record the node as down");
        }
    }
}

/// Marks every task of a long-down node `ORPHANED` (SWK §13.2).
///
/// Only tasks in `[ASSIGNED, RUNNING]` are touched: terminal tasks are
/// already accounted for, and orphaning is about releasing the resources of
/// tasks nobody can report on any more — it deliberately does not delete
/// them, so the history stays.
async fn orphan_tasks(store: &ClusterStore, node_id: &Id, manager_id: &Id) {
    loop {
        let batch: Vec<Task> = {
            let view = store.view();
            view.tasks()
                .into_iter()
                .filter(|task| {
                    task.node_id.as_ref() == Some(node_id)
                        && task.status.state >= TaskState::Assigned
                        && task.status.state <= TaskState::Running
                })
                .take(MAX_TX_ACTIONS)
                .map(|task| (*task).clone())
                .collect()
        };
        if batch.is_empty() {
            return;
        }
        let count = batch.len();
        let now = SystemTime::now();
        let actions: Vec<StoreAction> = batch
            .into_iter()
            .map(|mut task| {
                task.status.state = TaskState::Orphaned;
                "node is down; task orphaned".clone_into(&mut task.status.message);
                task.status.timestamp = now;
                task.status.applied_by = Some(manager_id.clone());
                task.status.applied_at = Some(now);
                task.meta.updated_at = now;
                StoreAction::Update(StoreObject::Task(task))
            })
            .collect();
        match store.propose(actions).await {
            Ok(_) => tracing::warn!(
                node_id = %node_id,
                tasks = count,
                "node down too long: tasks orphaned"
            ),
            Err(error) => {
                tracing::warn!(node_id = %node_id, %error, "cannot orphan the tasks of a down node");
                return;
            }
        }
        if count < MAX_TX_ACTIONS {
            return;
        }
    }
}

/// Moves every non-down node to `UNKNOWN` after a leadership change.
///
/// "I have heard from nobody yet" is the whole claim this makes, so a node this
/// manager *has* heard from is skipped. That is not hypothetical: this pass
/// commits one Raft entry per node, and the leader's own agent reaches the
/// co-located unix socket in microseconds, so a registration lands in the
/// middle of the walk routinely. The liveness check is therefore re-read per
/// node rather than snapshotted up front, where it would predate every
/// registration this pass can race.
///
/// It still cannot be atomic against a registration — nothing here can be, the
/// write is a Raft round-trip — so it narrows the window and no more.
/// [`heal_node_states`] is what actually closes it.
async fn mark_unknown(inner: &Arc<Inner>) {
    let store = &inner.store;
    let nodes: Vec<Id> = {
        let view = store.view();
        view.nodes()
            .into_iter()
            .filter(|node| node.status.state == NodeState::Ready)
            .map(|node| node.id.clone())
            .collect()
    };
    for node_id in nodes {
        let result = update_node(store, &node_id, "leadership change", |node| {
            if node.status.state != NodeState::Ready {
                return false;
            }
            if inner.liveness().state(&node.id) == Some(NodeState::Ready) {
                return false;
            }
            apply_state(node, NodeState::Unknown)
        })
        .await;
        if let Err(error) = result {
            tracing::warn!(node_id = %node_id, %error, "cannot record the leadership-change state");
        }
    }
}

/// Seeds a registration expectation for every store node this manager does
/// not track, at leadership gain.
///
/// [`Liveness::leadership_gained`] re-times the nodes this manager already
/// holds sessions for — and a manager that just won its first election holds
/// none, so without this pass a node that died *with* the old leader was
/// tracked by nobody: `mark_unknown` wrote `UNKNOWN` once, no TTL ever ticked
/// against it, and its tasks kept their desired state forever while the
/// cluster looked merely degraded. So the new leader walks the store and gives
/// every node it has not heard from the same doubled grace period a tracked
/// node gets (SWK §13.2: the swarmkit dispatcher marks every non-`DOWN` *store*
/// node `UNKNOWN` with the doubled TTL on leadership change — the node set is
/// seeded from the store, not from the sessions held). A live agent
/// re-registers well inside the grace (measured 2.9–7.5 s on the VMs, against
/// 30 s at the defaults) and becomes `READY` through the ordinary path; a dead
/// node's expectation expires through the ordinary sweep into [`mark_down`],
/// which is the level the orchestrator already evicts from. One eviction path,
/// not two.
///
/// Skipped on purpose:
///
/// - a node already `DOWN` in the store — it is exactly where it belongs, and
///   seeding it would resurrect it to `UNKNOWN` and grant its tasks a reprieve
///   every election;
/// - a drained node — the operator has said it hosts no tasks, so there is
///   nothing a `DOWN` transition would evict, and a drained node whose daemon
///   is deliberately stopped for maintenance should not flap to `DOWN` on
///   every leadership change.
///
/// Idempotent by construction: [`Liveness::expect`] refuses any node already
/// tracked, so a racing registration wins and a re-run cannot re-arm a
/// running clock. In the double-failure case — the new leader itself dies
/// mid-grace — the next leader's map starts empty and this pass seeds afresh:
/// the dead node's clock restarts rather than accumulates.
fn seed_expectations(inner: &Arc<Inner>, now: Instant) {
    let candidates: Vec<(Id, NodeState)> = {
        let view = inner.store.view();
        view.nodes()
            .into_iter()
            .filter(|node| {
                node.status.state != NodeState::Down
                    && node.spec.availability != Availability::Drain
            })
            .map(|node| (node.id.clone(), node.status.state))
            .collect()
    };
    let grace = inner.config.heartbeat.unknown_grace();
    for (node_id, stored) in candidates {
        if inner.liveness().expect(&node_id, now) {
            tracing::info!(
                node_id = %node_id,
                stored_state = ?stored,
                deadline_ms = grace.as_millis(),
                "leadership gained with no session for this node: it must re-register within \
                 the grace period or be marked down and have its tasks evicted"
            );
        }
    }
}

/// Re-asserts the sessions this manager holds onto the node objects, on every
/// sweep.
///
/// [`mark_ready`], [`mark_down`] and [`mark_unknown`] are **edge-triggered**:
/// each writes when a transition happens, and a write that is lost — or
/// overwritten by another transition racing it — is never retried, because
/// heartbeats only refresh the in-memory TTL. That left a real hole, not a
/// theoretical one. On the leader, its *own* agent reaches the co-located unix
/// socket (`addr` empty, no TLS handshake, no dial) in microseconds, so it
/// registered before the sweep loop's leadership-gain pass had finished walking
/// the store; that pass then overwrote its fresh `READY` with `UNKNOWN`, and
/// nothing ever wrote it again. `satl node ls` showed the leader `Unknown`
/// while its own agent was streaming assignments, the scheduler skipped it
/// (`satl_sched` filters on `READY`), and only restarting the daemon a second
/// time cleared it.
///
/// So the sweep re-asserts the projection every pass instead. [`Liveness`] is
/// this manager's authority on who is live; the node object is only its
/// published form, and publishing it is **level-triggered**. Nothing in the
/// bring-up order has to hold for it to converge, which is the point: the
/// register-before-the-loop ordering can come back — and will, on a faster or
/// slower host — without the symptom coming back with it.
///
/// Nodes this manager does not track are deliberately left alone: it has no
/// opinion on them beyond the one-shot [`mark_unknown`] on leadership gain, and
/// forcing one here would let a manager overwrite a state it never observed.
/// On a leader that set is small by construction — [`seed_expectations`] makes
/// every non-`DOWN`, non-drained store node tracked *at leadership gain* — but
/// the steady-state rule stands: whatever is untracked here (`DOWN` nodes,
/// drained nodes, a node object born mid-tenure whose agent has not registered
/// yet) is none of this pass's business.
async fn heal_node_states(inner: &Arc<Inner>) {
    let tracked = {
        let liveness = inner.liveness();
        liveness.states()
    };
    for (node_id, state) in tracked {
        let stored = {
            let view = inner.store.view();
            view.node(&node_id).map(|node| node.status.state)
        };
        let Some(stored) = stored else {
            // Gone from the store; `forget_removed_nodes` drops it next pass.
            continue;
        };
        if stored == state {
            continue;
        }
        let result = update_node(&inner.store, &node_id, "session liveness", |node| {
            apply_state(node, state)
        })
        .await;
        match result {
            Ok(true) => tracing::warn!(
                node_id = %node_id,
                from = ?stored,
                to = ?state,
                "node status disagreed with the session this manager holds; corrected"
            ),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                node_id = %node_id,
                from = ?stored,
                to = ?state,
                %error,
                "cannot correct a node status that disagrees with its session"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Background loops
// ---------------------------------------------------------------------------

/// TTL expiry, `DOWN`, orphaning, and leadership transitions.
///
/// The span is attached to the future with [`tracing::Instrument`] rather than
/// entered with a guard: an `Entered` held across an await stays entered on the
/// worker thread while this future is parked, so every unrelated task the
/// runtime later polls on that thread inherits it as a parent. Instrumenting
/// enters and exits the span around each poll, which is the only shape that
/// keeps a log line's parent honest.
async fn sweep_loop(inner: Arc<Inner>, shutdown: CancellationToken) {
    let span = tracing::info_span!("dispatcher.sweep", manager_id = %inner.manager_id);
    sweep_loop_inner(inner, shutdown).instrument(span).await;
}

/// The body of [`sweep_loop`], separated only so the span can wrap the future.
async fn sweep_loop_inner(inner: Arc<Inner>, shutdown: CancellationToken) {
    let mut was_leader = inner.store.metrics().is_leader;
    if was_leader {
        let now = Instant::now();
        inner.liveness().leadership_gained(now);
        seed_expectations(&inner, now);
        mark_unknown(&inner).await;
    }
    tracing::info!(leader = was_leader, "dispatcher sweep loop started");

    loop {
        let until_next = inner
            .liveness()
            .next_deadline(Instant::now())
            .unwrap_or(SWEEP_MAX_SLEEP)
            .min(SWEEP_MAX_SLEEP);
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(until_next) => {}
        }

        let is_leader = inner.store.metrics().is_leader;
        if is_leader != was_leader {
            was_leader = is_leader;
            if is_leader {
                let now = Instant::now();
                inner.liveness().leadership_gained(now);
                seed_expectations(&inner, now);
                mark_unknown(&inner).await;
                tracing::info!("became leader: serving the dispatcher");
            } else {
                let voided = inner.liveness().leadership_lost();
                let sessions = std::mem::take(&mut *inner.sessions());
                for (_, entry) in sessions {
                    entry.cancel.cancel();
                }
                tracing::info!(
                    sessions = voided.len(),
                    "lost leadership: every agent session was voided"
                );
            }
        }
        if !is_leader {
            continue;
        }

        // A node removed from the cluster takes its session, its TTL and its
        // orphaning timer with it — otherwise a demoted or removed node's
        // bookkeeping outlives the object it describes.
        forget_removed_nodes(&inner);

        let sweep = inner.liveness().sweep(Instant::now());
        for node_id in &sweep.went_down {
            if let Some(entry) = inner.sessions().remove(node_id) {
                entry.cancel.cancel();
            }
            mark_down(&inner.store, node_id).await;
        }
        for node_id in &sweep.orphan {
            orphan_tasks(&inner.store, node_id, &inner.manager_id).await;
        }

        // Last, so it sees the transitions this pass just made and does not
        // fight them: whatever the edges above did or failed to do, the node
        // objects now say what this manager's sessions say.
        heal_node_states(&inner).await;
    }
    tracing::info!("dispatcher sweep loop stopped");
}

/// Drops the liveness and session bookkeeping of nodes that no longer have a
/// node object (removed from the cluster, architecture §6.6).
fn forget_removed_nodes(inner: &Arc<Inner>) {
    let known: BTreeSet<Id> = {
        let view = inner.store.view();
        view.nodes()
            .into_iter()
            .map(|node| node.id.clone())
            .collect()
    };
    let gone: Vec<Id> = {
        let liveness = inner.liveness();
        liveness
            .node_ids()
            .into_iter()
            .filter(|id| !known.contains(id))
            .collect()
    };
    for node_id in gone {
        inner.liveness().forget(&node_id);
        if let Some(entry) = inner.sessions().remove(&node_id) {
            entry.cancel.cancel();
        }
        tracing::info!(
            node_id = %node_id,
            "node object is gone; dropping its session and liveness bookkeeping"
        );
    }
}

/// Drains the status queue into the store on the flush interval.
///
/// Instrumented rather than entered, for the reason on [`sweep_loop`].
async fn status_loop(inner: Arc<Inner>, shutdown: CancellationToken) {
    let span = tracing::info_span!("dispatcher.status", manager_id = %inner.manager_id);
    status_loop_inner(inner, shutdown).instrument(span).await;
}

/// The body of [`status_loop`], separated only so the span can wrap the future.
async fn status_loop_inner(inner: Arc<Inner>, shutdown: CancellationToken) {
    let interval = inner.config.status_flush_interval;
    tracing::info!(
        flush_ms = interval.as_millis(),
        force_at = inner.config.status_flush_max,
        "dispatcher status loop started"
    );
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = inner.status_ready.notified() => {}
            () = tokio::time::sleep(interval) => {}
        }
        loop {
            let batch = inner.statuses().take(inner.config.status_flush_max);
            if batch.is_empty() {
                break;
            }
            let size = batch.len();
            let mut failed = Vec::new();
            for (task_id, status) in batch {
                if inner.writer.apply(&task_id, &status).await
                    == crate::status::StatusOutcome::Failed
                {
                    failed.push((task_id, status));
                }
            }
            if !failed.is_empty() {
                tracing::debug!(
                    count = failed.len(),
                    "re-queueing status updates that failed"
                );
                inner.statuses().requeue(failed);
                break;
            }
            if size < inner.config.status_flush_max {
                break;
            }
        }
    }
    // Best effort on the way out: statuses already accepted should reach the
    // store rather than be silently dropped on a clean shutdown. The queue
    // guard is `!Send`, so the batch is taken before the first await.
    let remaining = inner.statuses().drain();
    for (task_id, status) in remaining {
        inner.writer.apply(&task_id, &status).await;
    }
    tracing::info!("dispatcher status loop stopped");
}

/// The per-node session stream: session ID, node object, manager list, root
/// CA bundle — initially and on every change.
#[tracing::instrument(skip_all, fields(node_id = %node_id, session_id = %session_id))]
async fn session_loop(
    inner: Arc<Inner>,
    node_id: Id,
    session_id: String,
    tx: mpsc::Sender<Result<v2::SessionMessage, Status>>,
    cancel: CancellationToken,
) {
    let mut events = inner.store.watch();
    let mut previous: Option<SessionSnapshot> = None;

    loop {
        let current = session_snapshot(&inner.store, &node_id);
        let Some(current) = current else {
            tracing::info!("the node object is gone; ending the session stream");
            let _ = tx
                .send(Err(Status::not_found(
                    "this node was removed from the cluster",
                )))
                .await;
            break;
        };
        if previous.as_ref() != Some(&current) {
            match session_message(&session_id, &current, previous.as_ref()) {
                Ok(message) => {
                    if tx.send(Ok(message)).await.is_err() {
                        tracing::debug!("the agent hung up on the session stream");
                        break;
                    }
                    previous = Some(current);
                }
                Err(error) => {
                    tracing::error!(%error, "cannot encode the session message");
                    let _ = tx.send(Err(Status::internal(error.to_string()))).await;
                    break;
                }
            }
        }

        // Wait for something that could change the message.
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    session_ended(
                        &tx,
                        "the session was superseded or the manager lost leadership",
                    )
                    .await;
                    return;
                }
                event = events.recv() => match event {
                    Ok(event) => {
                        if session_relevant(&event) {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "session watch lagged; re-reading the snapshot");
                        break;
                    }
                    Err(RecvError::Closed) => return,
                },
            }
        }
    }
}

async fn session_ended(tx: &mpsc::Sender<Result<v2::SessionMessage, Status>>, why: &str) {
    tracing::info!(why, "session stream ending");
    let _ = tx
        .send(Err(Status::failed_precondition(why.to_owned())))
        .await;
}

/// Whether a store event can change what the session stream pushes.
///
/// Any node object matters, not just this node's: the manager list is derived
/// from every node's manager status. The cluster object matters because it
/// carries the root CA bundle.
fn session_relevant(event: &StoreEvent) -> bool {
    match event {
        StoreEvent::Created(object) | StoreEvent::Updated { new: object, .. } => {
            matches!(object, StoreObject::Node(_) | StoreObject::Cluster(_))
        }
        StoreEvent::Removed { kind, .. } => *kind == ObjectKind::Node,
        StoreEvent::Commit(_) => false,
    }
}

/// Objects whose store events the assignment stream has to resolve.
#[derive(Debug, Default)]
struct Dirty {
    tasks: BTreeSet<Id>,
    secrets: BTreeSet<Id>,
    configs: BTreeSet<Id>,
    networks: BTreeSet<Id>,
}

impl Dirty {
    fn is_empty(&self) -> bool {
        self.tasks.is_empty()
            && self.secrets.is_empty()
            && self.configs.is_empty()
            && self.networks.is_empty()
    }
}

/// The per-node assignment stream: a `COMPLETE` snapshot, then `INCREMENTAL`
/// diffs batched over the quiescence window.
#[tracing::instrument(skip_all, fields(node_id = %node_id, session_id = %session_id))]
async fn assignment_loop(
    inner: Arc<Inner>,
    node_id: Id,
    session_id: String,
    tx: mpsc::Sender<Result<v2::AssignmentsMessage, Status>>,
    cancel: CancellationToken,
) {
    // Subscribe before the snapshot so that nothing committed between the two
    // is lost: an event for state already in the snapshot is a no-op, a lost
    // event is a stuck node.
    let mut events = inner.store.watch();
    let mut tracker = AssignmentTracker::new(node_id.clone());
    let mut generator = SequenceGenerator::new();
    let mut dirty = Dirty::default();

    if !send_snapshot(&inner, &mut tracker, &mut generator, &tx).await {
        return;
    }

    let quiescence = inner.config.assignment_quiescence;
    let batch_max = inner.config.assignment_batch_max;
    let mut deadline: Option<tokio::time::Instant> = None;

    loop {
        let tick = deadline.map(tokio::time::sleep_until);
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                tracing::debug!("assignment stream cancelled with its session");
                let _ = tx.send(Err(Status::failed_precondition(
                    "the session backing this assignment stream ended",
                ))).await;
                return;
            }
            () = async { match tick { Some(sleep) => sleep.await, None => std::future::pending().await } } => {
                deadline = None;
                let dirty = std::mem::take(&mut dirty);
                resolve(&inner, &mut tracker, dirty);
                let changes = tracker.take_changes();
                if changes.is_empty() {
                    continue;
                }
                for batch in split_batches(&changes, batch_max) {
                    let applies_to = generator.current().to_owned();
                    let results_in = generator.advance();
                    let message = match assignments_message(
                        v2::assignments_message::Type::Incremental,
                        &applies_to,
                        &results_in,
                        &batch,
                    ) {
                        Ok(message) => message,
                        Err(error) => {
                            tracing::error!(%error, "cannot encode an assignment batch");
                            let _ = tx.send(Err(Status::internal(error.to_string()))).await;
                            return;
                        }
                    };
                    tracing::debug!(
                        changes = batch.len(),
                        results_in = %results_in,
                        "shipping an incremental assignment batch"
                    );
                    if tx.send(Ok(message)).await.is_err() {
                        tracing::debug!("the agent hung up on the assignment stream");
                        return;
                    }
                }
            }
            event = events.recv() => match event {
                Ok(event) => {
                    if mark_dirty(&event, &node_id, &tracker, &mut dirty) && deadline.is_none() {
                        deadline = Some(tokio::time::Instant::now() + quiescence);
                    }
                }
                Err(RecvError::Lagged(missed)) => {
                    tracing::warn!(
                        missed,
                        "assignment watch lagged; re-syncing this node from a fresh snapshot"
                    );
                    dirty = Dirty::default();
                    deadline = None;
                    tracker = AssignmentTracker::new(node_id.clone());
                    if !send_snapshot(&inner, &mut tracker, &mut generator, &tx).await {
                        return;
                    }
                }
                Err(RecvError::Closed) => return,
            },
        }
    }
}

/// Builds the assignment set from a fresh store read and ships it as a
/// `COMPLETE` snapshot. Returns whether the stream is still alive.
async fn send_snapshot(
    inner: &Arc<Inner>,
    tracker: &mut AssignmentTracker,
    generator: &mut SequenceGenerator,
    tx: &mpsc::Sender<Result<v2::AssignmentsMessage, Status>>,
) -> bool {
    let node_id = tracker.node_id().clone();
    let tasks: Vec<Task> = {
        let view = inner.store.view();
        view.tasks()
            .into_iter()
            .filter(|task| belongs_to(task, &node_id))
            .map(|task| (*task).clone())
            .collect()
    };
    let deps = StoreDeps {
        store: &inner.store,
    };
    for task in &tasks {
        tracker.observe_task(task, &deps);
    }
    // SWK §9.1 (M6d): the ingress network ships to every node, task or not —
    // every node is a load balancer for the mesh and needs the plumbing.
    {
        let view = inner.store.view();
        if let Some(assignment) = view
            .networks()
            .into_iter()
            .find(|network| network.spec.ingress)
            .map(|network| network_assignment(&view, &network))
        {
            tracker.observe_network(&assignment);
        }
    }
    let changes = tracker.snapshot();
    let results_in = generator.advance();
    let message = match assignments_message(
        v2::assignments_message::Type::Complete,
        "",
        &results_in,
        &changes,
    ) {
        Ok(message) => message,
        Err(error) => {
            tracing::error!(%error, "cannot encode the assignment snapshot");
            let _ = tx.send(Err(Status::internal(error.to_string()))).await;
            return false;
        }
    };
    tracing::info!(
        tasks = tracker.task_ids().len(),
        secrets = tracker.secret_ids().len(),
        configs = tracker.config_ids().len(),
        networks = tracker.network_ids().len(),
        results_in = %results_in,
        "shipping a complete assignment snapshot"
    );
    tx.send(Ok(message)).await.is_ok()
}

/// Records the objects an event touched, if this node cares about them.
///
/// Networks widen the filter, because a node's endpoint table depends on
/// objects that are none of its business otherwise:
///
/// - a task on **another** node, if it is attached to a network this node
///   holds — that is a peer endpoint appearing or moving;
/// - a **node** object, because it carries the underlay address the endpoint
///   table quotes as a VTEP;
/// - a task *deletion*, which arrives as an ID and nothing else. There is no
///   way back from the ID to the networks it was on, so every tracked network
///   is re-read. That is a store read per tracked network per task deletion,
///   which is affordable precisely because the set is "networks with a task on
///   this node", not "networks in the cluster".
fn mark_dirty(
    event: &StoreEvent,
    node_id: &Id,
    tracker: &AssignmentTracker,
    dirty: &mut Dirty,
) -> bool {
    let before = dirty.is_empty();
    match event {
        StoreEvent::Created(object) | StoreEvent::Updated { new: object, .. } => match object {
            StoreObject::Task(task) => {
                if task.node_id.as_ref() == Some(node_id) || tracker.tracks_task(&task.id) {
                    dirty.tasks.insert(task.id.clone());
                }
                for attachment in &task.networks {
                    if tracker.tracks_network(&attachment.network_id) {
                        dirty.networks.insert(attachment.network_id.clone());
                    }
                }
            }
            StoreObject::Secret(secret) if tracker.tracks_secret(&secret.id) => {
                dirty.secrets.insert(secret.id.clone());
            }
            StoreObject::Config(config) if tracker.tracks_config(&config.id) => {
                dirty.configs.insert(config.id.clone());
            }
            StoreObject::Network(network)
                if tracker.tracks_network(&network.id) || network.spec.ingress =>
            {
                dirty.networks.insert(network.id.clone());
            }
            StoreObject::Node(_) => dirty.networks.extend(tracker.referenced_network_ids()),
            _ => {}
        },
        StoreEvent::Removed { kind, id } => match kind {
            ObjectKind::Task => {
                if tracker.tracks_task(id) {
                    dirty.tasks.insert(id.clone());
                }
                dirty.networks.extend(tracker.referenced_network_ids());
            }
            ObjectKind::Secret if tracker.tracks_secret(id) => {
                dirty.secrets.insert(id.clone());
            }
            ObjectKind::Config if tracker.tracks_config(id) => {
                dirty.configs.insert(id.clone());
            }
            ObjectKind::Network if tracker.tracks_network(id) => {
                dirty.networks.insert(id.clone());
            }
            ObjectKind::Node => dirty.networks.extend(tracker.referenced_network_ids()),
            _ => {}
        },
        StoreEvent::Commit(_) => {}
    }
    before && !dirty.is_empty()
}

/// Re-reads every dirty object and feeds it to the tracker.
fn resolve(inner: &Arc<Inner>, tracker: &mut AssignmentTracker, dirty: Dirty) {
    let deps = StoreDeps {
        store: &inner.store,
    };
    for id in dirty.tasks {
        let task = {
            let view = inner.store.view();
            view.task(&id).map(|task| (*task).clone())
        };
        match task {
            Some(task) => {
                tracker.observe_task(&task, &deps);
            }
            None => {
                tracker.forget_task(&id);
            }
        }
    }
    for id in dirty.secrets {
        let secret = {
            let view = inner.store.view();
            view.secret(&id).map(|secret| (*secret).clone())
        };
        match secret {
            Some(secret) => {
                tracker.observe_secret(&secret);
            }
            None => {
                tracker.forget_secret(&id);
            }
        }
    }
    for id in dirty.configs {
        let config = {
            let view = inner.store.view();
            view.config(&id).map(|config| (*config).clone())
        };
        match config {
            Some(config) => {
                tracker.observe_config(&config);
            }
            None => {
                tracker.forget_config(&id);
            }
        }
    }
    // Networks last: a task resolved above may have been the final user of one,
    // in which case it is no longer tracked and re-reading it is a no-op.
    for id in dirty.networks {
        match deps.network(&id) {
            Some(assignment) => {
                tracker.observe_network(&assignment);
            }
            None => {
                tracker.forget_network(&id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;
    use satl_core::{DesiredState, NodeRole};

    fn snapshot(
        node: Node,
        managers: Vec<ManagerPeer>,
        root_ca: Option<Vec<u8>>,
    ) -> SessionSnapshot {
        SessionSnapshot {
            node,
            managers,
            root_ca,
        }
    }

    #[test]
    fn the_first_session_message_carries_everything() {
        let node = testing::node(NodeRole::Worker);
        let peer = ManagerPeer::new(Id::generate(), "10.2.0.1:2377");
        let current = snapshot(node.clone(), vec![peer], Some(b"-----BEGIN".to_vec()));
        let message = session_message("s1", &current, None).expect("encode");
        assert_eq!(message.session_id, "s1");
        assert!(message.node.is_some());
        assert_eq!(message.managers.len(), 1);
        assert!(message.root_ca_bundle.is_some());
    }

    #[test]
    fn an_unchanged_field_is_absent_not_empty() {
        let node = testing::node(NodeRole::Worker);
        let peer = ManagerPeer::new(Id::generate(), "10.2.0.1:2377");
        let previous = snapshot(node.clone(), vec![peer.clone()], Some(b"ca".to_vec()));

        // Only the node object changed.
        let mut changed = previous.clone();
        changed.node.spec.availability = satl_core::Availability::Drain;
        let message = session_message("s1", &changed, Some(&previous)).expect("encode");
        assert_eq!(message.session_id, "s1", "the session id is always present");
        assert!(message.node.is_some());
        assert!(
            message.managers.is_empty(),
            "an unchanged manager list is absent, not an empty list"
        );
        assert!(message.root_ca_bundle.is_none());

        // Only the CA changed.
        let mut rotated = previous.clone();
        rotated.root_ca = Some(b"new ca".to_vec());
        let message = session_message("s1", &rotated, Some(&previous)).expect("encode");
        assert!(message.node.is_none());
        assert_eq!(
            message.root_ca_bundle.as_deref(),
            Some(b"new ca".as_slice())
        );
    }

    #[test]
    fn assignment_messages_carry_the_wire_shape_the_agent_expects() {
        let node_id = Id::generate();
        let secret = testing::secret("s", b"x");
        let task = testing::with_secret(
            testing::task_on(Some(&node_id), TaskState::Assigned, DesiredState::Running),
            &secret,
        );
        let changes = vec![
            AssignmentChange::update(AssignmentItem::Secret(Box::new(secret.clone()))),
            AssignmentChange::update(AssignmentItem::Task(Box::new(task.clone()))),
        ];
        let message =
            assignments_message(v2::assignments_message::Type::Complete, "", "s-1", &changes)
                .expect("encode");
        assert_eq!(message.r#type(), v2::assignments_message::Type::Complete);
        assert!(message.applies_to.is_empty());
        assert_eq!(message.results_in, "s-1");
        assert_eq!(message.changes.len(), 2);
        assert_eq!(
            message.changes[0].action(),
            v2::assignment_change::Action::Update
        );
        match message.changes[0]
            .assignment
            .as_ref()
            .and_then(|a| a.item.as_ref())
        {
            Some(v2::assignment::Item::Secret(wire)) => assert_eq!(wire.id, secret.id.to_string()),
            other => panic!("expected a secret first, got {other:?}"),
        }
    }

    #[test]
    fn a_removal_ships_only_the_id() {
        let id = Id::generate();
        let changes = vec![AssignmentChange::remove(ObjectRef::Task, id.clone())];
        let message = assignments_message(
            v2::assignments_message::Type::Incremental,
            "s-1",
            "s-2",
            &changes,
        )
        .expect("encode");
        assert_eq!(
            message.changes[0].action(),
            v2::assignment_change::Action::Remove
        );
        match message.changes[0]
            .assignment
            .as_ref()
            .and_then(|a| a.item.as_ref())
        {
            Some(v2::assignment::Item::Task(wire)) => {
                assert_eq!(wire.id, id.to_string());
                assert!(wire.payload.is_empty());
            }
            other => panic!("expected a task, got {other:?}"),
        }
    }

    /// The node's own report wins over every inference — the whole point of
    /// [`satl_core::NodeDescription::data_addr`]. A worker is the case that
    /// proves it: it has no `manager_status` at all, so before the field existed
    /// its VTEP was *always* the TCP address the dispatcher happened to see.
    #[test]
    fn a_vtep_is_what_the_node_reported_before_anything_observed() {
        let mut worker = testing::node(NodeRole::Worker);
        worker.status.addr = "127.0.0.1:54321".to_owned();
        let mut description = testing::description("worker-1");
        description.data_addr = Some("10.2.0.5".to_owned());
        worker.description = Some(description);
        assert_eq!(
            node_vtep(&worker),
            Some(("10.2.0.5".parse().expect("addr"), VtepSource::Reported)),
            "the reported underlay address, not the loopback the session came in on"
        );

        // A port on the reported address is stripped: it would be the control
        // plane's, and the VXLAN port is the overlay's.
        let mut with_port = worker.clone();
        if let Some(description) = with_port.description.as_mut() {
            description.data_addr = Some("10.2.0.5:2377".to_owned());
        }
        assert_eq!(
            node_vtep(&with_port).map(|(addr, _)| addr),
            Some("10.2.0.5".parse().expect("addr"))
        );

        // Nothing reported: a manager still has its configured raft address.
        let mut manager = testing::node(NodeRole::Manager);
        manager.status.addr = "127.0.0.1:41234".to_owned();
        manager.manager_status = Some(satl_core::ManagerStatus {
            addr: "10.2.0.1:2377".to_owned(),
            raft_id: 1,
            leader: true,
            reachability: satl_core::Reachability::Reachable,
        });
        assert_eq!(
            node_vtep(&manager),
            Some((
                "10.2.0.1".parse().expect("addr"),
                VtepSource::ManagerAdvertise
            ))
        );

        // A worker that has not reported yet falls back to the observed
        // address, flagged as such so the caller can say so in the log.
        let mut stale = testing::node(NodeRole::Worker);
        stale.status.addr = "10.2.0.5:54321".to_owned();
        assert_eq!(
            node_vtep(&stale),
            Some(("10.2.0.5".parse().expect("addr"), VtepSource::Observed))
        );

        // A node nobody has seen yet has no VTEP: better no FDB entry than a
        // wrong one.
        let fresh = testing::node(NodeRole::Worker);
        assert_eq!(node_vtep(&fresh), None);
    }

    #[test]
    fn an_overlay_address_is_the_host_part_of_the_first_usable_cidr() {
        assert_eq!(
            overlay_address(&["10.100.4.5/24".to_owned()]),
            Some("10.100.4.5".parse().expect("addr"))
        );
        assert_eq!(
            overlay_address(&["fd00::1/64".to_owned(), "10.100.4.6/24".to_owned()]),
            Some("10.100.4.6".parse().expect("addr")),
            "an ipv6 address is skipped, not fatal"
        );
        assert_eq!(overlay_address(&[]), None);
        assert_eq!(overlay_address(&["nonsense".to_owned()]), None);
    }

    #[test]
    fn only_relevant_events_wake_the_assignment_stream() {
        let node_id = Id::generate();
        let tracker = AssignmentTracker::new(node_id.clone());
        let mut dirty = Dirty::default();

        let mine = testing::task_on(Some(&node_id), TaskState::Assigned, DesiredState::Running);
        assert!(mark_dirty(
            &StoreEvent::Created(StoreObject::Task(mine.clone())),
            &node_id,
            &tracker,
            &mut dirty
        ));
        assert_eq!(dirty.tasks.len(), 1);

        let theirs = testing::task_on(
            Some(&Id::generate()),
            TaskState::Assigned,
            DesiredState::Running,
        );
        let mut other_dirty = Dirty::default();
        assert!(!mark_dirty(
            &StoreEvent::Created(StoreObject::Task(theirs)),
            &node_id,
            &tracker,
            &mut other_dirty
        ));
        assert!(other_dirty.is_empty());

        // A secret nobody on this node references is not this stream's
        // business.
        let secret = testing::secret("s", b"x");
        assert!(!mark_dirty(
            &StoreEvent::Created(StoreObject::Secret(secret)),
            &node_id,
            &tracker,
            &mut other_dirty
        ));
        assert!(other_dirty.is_empty());
    }

    /// The endpoint table's inputs are wider than a node's own assignment set:
    /// a task on *another* node, and the node objects that carry VTEP
    /// addresses, both change what this node has to program.
    #[test]
    fn a_tracked_network_widens_the_event_filter_to_peers() {
        let node_id = Id::generate();
        let elsewhere = Id::generate();
        let network = testing::overlay_network("blue");
        let mine = testing::with_network(
            testing::task_on(Some(&node_id), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.5/24",
        );
        let mut tracker = AssignmentTracker::new(node_id.clone());
        // The empty lookup is enough: a reference is counted whether or not the
        // object can be read, and this test is about the event filter.
        tracker.observe_task(&mine, &());
        assert!(tracker.tracks_network(&network.id));

        // A peer's task on that network: not our task, still our business.
        let theirs = testing::with_network(
            testing::task_on(Some(&elsewhere), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.9/24",
        );
        let mut dirty = Dirty::default();
        assert!(mark_dirty(
            &StoreEvent::Created(StoreObject::Task(theirs)),
            &node_id,
            &tracker,
            &mut dirty
        ));
        assert!(
            dirty.tasks.is_empty(),
            "the peer's task is not assigned here"
        );
        assert_eq!(dirty.networks, BTreeSet::from([network.id.clone()]));

        // A node object changed: its underlay address is quoted as a VTEP.
        let mut dirty = Dirty::default();
        assert!(mark_dirty(
            &StoreEvent::Created(StoreObject::Node(testing::node(NodeRole::Worker))),
            &node_id,
            &tracker,
            &mut dirty
        ));
        assert_eq!(dirty.networks, BTreeSet::from([network.id.clone()]));

        // A task deletion arrives as an ID alone, so every tracked network is
        // re-read rather than guessed at.
        let mut dirty = Dirty::default();
        assert!(mark_dirty(
            &StoreEvent::Removed {
                kind: ObjectKind::Task,
                id: Id::generate(),
            },
            &node_id,
            &tracker,
            &mut dirty
        ));
        assert_eq!(dirty.networks, BTreeSet::from([network.id]));
    }
}
