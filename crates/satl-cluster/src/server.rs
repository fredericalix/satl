// SPDX-License-Identifier: BSD-2-Clause
//! The internal gRPC server: **one** tonic server per manager, mTLS
//! everywhere, every internal service multiplexed onto it (architecture §7,
//! §12.5).
//!
//! # The registration seam
//!
//! `satl-cluster` owns the listener, the rustls configuration, the
//! authorization interceptor and the health service. Everything else —
//! `Dispatcher` (satld/satl-agent), `NodeCA` (satl-ca's server side),
//! and any later service — is added by its owner through
//! [`ServerBuilder::add_service`]:
//!
//! ```ignore
//! use satl_ca::RoleRequirement;
//! use satl_cluster::server::ServerBuilder;
//!
//! let builder = ServerBuilder::new(identity, listen_addr, manager_slot)?
//!     // satl-cluster registers Raft, Control and Health itself
//!     .add_service(RoleRequirement::WorkerOrManager, DispatcherServer::new(d))
//!     .add_service(RoleRequirement::Any, NodeCaServer::new(ca));
//! let handle = builder.serve().await?;
//! ```
//!
//! `add_service` takes any generated tonic server (anything implementing
//! [`NamedService`] + `Service<http::Request<Body>, Error = Infallible>`) and
//! the [`RoleRequirement`] from architecture §7's table. It wraps the service
//! in the authorization interceptor before adding it to the router, so a
//! service registered this way **cannot** be served without a role check —
//! that is the point of routing every registration through one function.
//!
//! Both message-size limits are the caller's responsibility on the service it
//! passes in (`.max_decoding_message_size(satl_proto::MAX_MESSAGE_SIZE)` and
//! `.max_encoding_message_size(..)`) — tonic's defaults are not 4 MiB.
//!
//! # Authorization
//!
//! One interceptor per registered service. It pulls the peer's leaf
//! certificate out of the TLS connection info, parses it into a
//! [`PeerIdentity`], and applies [`PeerIdentity::authorize`]: OU against the
//! service's requirement, O against **this node's own** cluster id (read from
//! its certificate, so it is available before the store has anything in it),
//! CN against the blacklist held on the `Cluster` object. The identity is then
//! inserted into the request extensions, where handlers read it with
//! [`peer_identity`].
//!
//! # TLS
//!
//! tonic 0.14's `ServerTlsConfig` builds its own rustls configuration from a
//! PEM identity and cannot be handed one. SatL needs satl-ca's configuration
//! (restricted cipher suites, cluster client verifier, mandatory client
//! certificates), so the listener does its own `tokio-rustls` accept and feeds
//! the resulting `TlsStream`s to `serve_with_incoming`. tonic's
//! `tls-connect-info` feature is what makes `TlsStream<TcpStream>` carry the
//! peer certificates into the request extensions, which is how the
//! interceptor sees them. Each handshake runs in its own task with a
//! deadline, so a stalled peer cannot block the accept loop.
//!
//! The configuration is built **once**, over the node's [`LiveIdentity`]:
//! certificate and trust anchors are resolved through it per handshake, so a
//! renewed certificate (architecture §12.3) is presented by the very next
//! accept with no listener restart. Connections already established keep the
//! identity they were opened with until they reconnect, which is expected —
//! TLS authenticates at handshake time.

use std::convert::Infallible;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tonic::body::Body;
use tonic::server::NamedService;
use tonic::service::Routes;
use tonic::transport::server::TlsConnectInfo;
use tonic::transport::server::{Server, TcpConnectInfo};
use tonic::{Request, Response, Status};

use openraft::async_runtime::watch::WatchReceiver;

use satl_ca::{LiveIdentity, NodeIdentity, PeerIdentity, RoleRequirement};
use satl_core::Id;
use satl_proto::MAX_MESSAGE_SIZE;
use satl_proto::health::health_check_response::ServingStatus;
use satl_proto::health::health_server::{Health, HealthServer};
use satl_proto::health::{HealthCheckRequest, HealthCheckResponse};

use crate::store::ClusterStore;
use crate::transport::{Eviction, PeerChannels, PeerLiveness};
use crate::types::Raft;

/// Default port of the internal gRPC listener (architecture §15).
pub const DEFAULT_PORT: u16 = 2377;

/// Health service name for the raft transport. `Control.JoinRaft` probes this
/// on a joining manager before admitting it (SWK §11.3).
pub const HEALTH_SERVICE_RAFT: &str = "raft";

/// Health service name for the control plane: SERVING once the store has
/// caught up, so forwarded proposals and reads are meaningful.
pub const HEALTH_SERVICE_CONTROL: &str = "control";

/// How long a peer gets to complete the TLS handshake before its connection
/// is dropped. Bounds the work an unauthenticated peer can pin down.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Backlog of accepted-and-handshaken connections waiting to be served.
const ACCEPT_BACKLOG: usize = 64;

/// The server could not be brought up.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The node's TLS material was rejected.
    #[error("building the internal gRPC server TLS configuration: {source}")]
    Tls {
        /// Underlying satl-ca error.
        #[from]
        source: satl_ca::TlsError,
    },
    /// This node's own certificate has no usable identity.
    #[error("reading this node's own certificate: {source}")]
    Identity {
        /// Underlying parse failure.
        #[from]
        source: satl_ca::PeerIdentityError,
    },
    /// The listener could not be bound.
    #[error("binding the internal gRPC listener on {addr}: {source}")]
    Bind {
        /// The address that was attempted.
        addr: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The tonic server stopped with an error.
    #[error("internal gRPC server on {addr} stopped: {message}")]
    Serve {
        /// The address it was serving.
        addr: SocketAddr,
        /// tonic's error text.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Manager context
// ---------------------------------------------------------------------------

/// Everything a manager-side gRPC handler needs about the local node.
///
/// Cheap to clone: `Raft` and [`ClusterStore`] are handles.
#[derive(Clone)]
pub struct ManagerContext {
    /// The local Raft instance.
    pub raft: Raft,
    /// The replicated store façade.
    pub store: ClusterStore,
    /// This node's SatL node ID (the CN of its certificate).
    pub node_id: Id,
    /// This node's Raft member ID.
    pub raft_id: u64,
    /// `host:port` this node tells peers to dial.
    pub advertise_addr: String,
    /// Shared peer-liveness map, for quorum-safety arithmetic.
    pub liveness: PeerLiveness,
    /// Set when peers refuse this node's raft ID as blacklisted -- a state
    /// nothing but a wipe and re-join can leave (see [`Eviction`]).
    pub eviction: Eviction,
    /// How long a peer counts as reachable after its last answer
    /// ([`crate::node::RaftTiming::liveness_window`]).
    pub liveness_window: Duration,
    /// Shared outbound channel pool (health probes, leader forwarding).
    /// `None` on a node with no internal listener — a single-node cluster has
    /// nobody to dial.
    pub channels: Option<PeerChannels>,
}

impl ManagerContext {
    /// The outbound channel pool, or a `FAILED_PRECONDITION` explaining that
    /// this node has no internal transport at all.
    pub fn require_channels(&self, op: &str) -> Result<&PeerChannels, Status> {
        self.channels.as_ref().ok_or_else(|| {
            Status::failed_precondition(format!(
                "{op} needs the internal gRPC transport, but this node runs without one \
                 (no listen address and no mTLS identity): it is a single-node cluster"
            ))
        })
    }

    /// Addresses of the other members this node's raft still believes in.
    ///
    /// Read from the raft membership rather than from the store or the agent
    /// session, because this exists for the one case where neither is
    /// available: an evicted manager's session never establishes (it dials its
    /// own dispatcher, which is not the leader) and its store is whatever it
    /// last replicated. The membership config is local, needs no peer, and is
    /// the very list the node has been failing to talk to -- which is exactly
    /// who to ask for re-admission.
    ///
    /// Excludes this node's own advertise address: re-joining through itself
    /// is not a join.
    #[must_use]
    pub fn peer_addrs(&self) -> Vec<String> {
        let metrics = self.raft.metrics().borrow_watched().clone();
        metrics
            .membership_config
            .nodes()
            .filter(|(id, _)| **id != self.raft_id)
            .map(|(_, node)| node.addr.clone())
            .filter(|addr| !addr.is_empty() && *addr != self.advertise_addr)
            .collect()
    }
}

impl fmt::Debug for ManagerContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagerContext")
            .field("node_id", &self.node_id)
            .field("raft_id", &self.raft_id)
            .field("advertise_addr", &self.advertise_addr)
            .finish_non_exhaustive()
    }
}

/// A late-bound [`ManagerContext`].
///
/// The listener has to be up **before** the raft node exists on the join
/// path: `Control.JoinRaft` health-checks the joiner back over this very
/// server, and the joiner does not know its raft ID until the leader answers
/// (SWK §11.3). Services registered on the server therefore hold a slot and
/// resolve it per request; until [`ManagerSlot::install`] is called they
/// answer `UNAVAILABLE`, which is exactly what a not-yet-started raft node
/// should say.
#[derive(Clone, Default)]
pub struct ManagerSlot {
    inner: Arc<RwLock<Option<ManagerContext>>>,
}

impl fmt::Debug for ManagerSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagerSlot")
            .field("installed", &self.inner.read().is_some())
            .finish()
    }
}

impl ManagerSlot {
    /// An empty slot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes the context to every service holding this slot.
    pub fn install(&self, context: ManagerContext) {
        *self.inner.write() = Some(context);
    }

    /// The context, if the raft node has started.
    #[must_use]
    pub fn get(&self) -> Option<ManagerContext> {
        self.inner.read().clone()
    }

    /// The context, or `UNAVAILABLE` naming the RPC that was attempted.
    pub fn require(&self, op: &str) -> Result<ManagerContext, Status> {
        self.get().ok_or_else(|| {
            Status::unavailable(format!(
                "this manager's raft node is not started yet, so {op} cannot be served: retry \
                 once the node has joined the cluster"
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

/// Applies architecture §12.5's checks to every request on the server.
///
/// The expected cluster id comes from **this node's own certificate**, not
/// from the store: a joining manager has a valid certificate long before its
/// store holds a `Cluster` object, and the O field of its own certificate is
/// the authoritative answer to "which cluster am I in".
#[derive(Clone)]
pub struct Authorizer {
    cluster_id: Arc<str>,
    store: Arc<RwLock<Option<ClusterStore>>>,
}

impl fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authorizer")
            .field("cluster_id", &self.cluster_id)
            .finish_non_exhaustive()
    }
}

impl Authorizer {
    /// Reads the cluster id out of `identity`'s own certificate.
    pub fn from_identity(identity: &NodeIdentity) -> Result<Self, ServerError> {
        let me = PeerIdentity::from_pem(identity.cert_pem.as_bytes())?;
        Ok(Self {
            cluster_id: Arc::from(me.cluster_id.as_str()),
            store: Arc::new(RwLock::new(None)),
        })
    }

    /// Attaches the store the certificate blacklist is read from. Until this
    /// is called nothing is blacklisted — which is correct, because a node
    /// with no replicated state has no blacklist to enforce.
    pub fn attach_store(&self, store: ClusterStore) {
        *self.store.write() = Some(store);
    }

    /// This cluster's id (the O field of every node certificate).
    #[must_use]
    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    /// Authorizes one request against `required`.
    fn authorize(
        &self,
        request: &Request<()>,
        required: RoleRequirement,
    ) -> Result<PeerIdentity, Status> {
        let certs = request.peer_certs().ok_or_else(|| {
            Status::unauthenticated(
                "no client certificate on this connection: the internal gRPC protocol is mTLS \
                 only (architecture section 12.1)",
            )
        })?;
        let leaf = certs.first().ok_or_else(|| {
            Status::unauthenticated("the client presented an empty certificate chain")
        })?;
        let peer = PeerIdentity::from_certificate(leaf)
            .map_err(|err| Status::unauthenticated(err.to_string()))?;

        // `Cluster.blacklisted_certs` is CN -> expiry; pruning expired
        // entries is the manager's job, not this check's.
        let blacklist = self
            .store
            .read()
            .as_ref()
            .and_then(|store| store.view().cluster().map(|c| c.blacklisted_certs.clone()))
            .unwrap_or_default();

        peer.authorize(required, &self.cluster_id, &blacklist)
            .map_err(|err| Status::permission_denied(err.to_string()))?;
        Ok(peer)
    }
}

/// The [`PeerIdentity`] the interceptor established for this request.
///
/// Every handler on this server can rely on it being present: a request that
/// reached a handler passed the interceptor.
pub fn peer_identity<T>(request: &Request<T>) -> Result<&PeerIdentity, Status> {
    request.extensions().get::<PeerIdentity>().ok_or_else(|| {
        Status::internal(
            "no peer identity on this request: the service was registered without the \
             authorization interceptor (see satl_cluster::server::ServerBuilder::add_service)",
        )
    })
}

/// The remote socket address of the request's connection, if the transport
/// has one. `Control.JoinRaft` uses it to resolve an unspecified joiner
/// address (SWK §11.3).
#[must_use]
pub fn peer_addr<T>(request: &Request<T>) -> Option<SocketAddr> {
    request
        .extensions()
        .get::<TlsConnectInfo<TcpConnectInfo>>()
        .and_then(|info| info.get_ref().remote_addr())
        .or_else(|| {
            request
                .extensions()
                .get::<TcpConnectInfo>()
                .and_then(TcpConnectInfo::remote_addr)
        })
}

/// The interceptor `add_service` wraps every service in.
#[derive(Clone, Debug)]
struct AuthInterceptor {
    authorizer: Authorizer,
    required: RoleRequirement,
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let peer = self.authorizer.authorize(&request, self.required)?;
        tracing::trace!(
            peer = %peer.node_id,
            role = peer.ou(),
            "authorized internal gRPC request"
        );
        request.extensions_mut().insert(peer);
        Ok(request)
    }
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

/// The serving statuses this node reports on `grpc.health.v1.Health`.
///
/// Handed out by [`ServerBuilder::health`] so any subsystem — including the
/// ones registered from other crates — can publish its own readiness.
/// Names are the short names `proto/health.proto` documents (`""`, `raft`,
/// `control`), not fully qualified protobuf service names.
#[derive(Clone, Default)]
pub struct HealthRegistry {
    inner: Arc<RwLock<std::collections::BTreeMap<String, ServingStatus>>>,
}

impl fmt::Debug for HealthRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HealthRegistry")
            .field("services", &self.inner.read().len())
            .finish()
    }
}

impl HealthRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes `status` for `service` (`""` means the whole server).
    pub fn set(&self, service: &str, status: ServingStatus) {
        let previous = self.inner.write().insert(service.to_owned(), status);
        if previous != Some(status) {
            tracing::info!(service, ?status, "health status changed");
        }
    }

    /// Shorthand for [`ServingStatus::Serving`].
    pub fn set_serving(&self, service: &str) {
        self.set(service, ServingStatus::Serving);
    }

    /// Shorthand for [`ServingStatus::NotServing`].
    pub fn set_not_serving(&self, service: &str) {
        self.set(service, ServingStatus::NotServing);
    }

    /// The status of `service`, or `None` if it was never registered.
    #[must_use]
    pub fn status(&self, service: &str) -> Option<ServingStatus> {
        self.inner.read().get(service).copied()
    }
}

/// `grpc.health.v1.Health` over a [`HealthRegistry`].
#[derive(Clone, Debug)]
pub struct HealthService {
    registry: HealthRegistry,
}

impl HealthService {
    /// Serves `registry`.
    #[must_use]
    pub fn new(registry: HealthRegistry) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl Health for HealthService {
    async fn check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let service = request.into_inner().service;
        // Upstream contract: an unknown name is NOT_FOUND on `Check` (and
        // SERVICE_UNKNOWN on `Watch`).
        let status = self.registry.status(&service).ok_or_else(|| {
            Status::not_found(format!(
                "no health status is published for {service:?}; this manager reports \"\", \
                 {HEALTH_SERVICE_RAFT:?} and {HEALTH_SERVICE_CONTROL:?}"
            ))
        })?;
        Ok(Response::new(HealthCheckResponse {
            status: status as i32,
        }))
    }

    type WatchStream = ReceiverStream<Result<HealthCheckResponse, Status>>;

    async fn watch(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        // `Check` is the only form SatL's own flows need (`JoinRaft` probes
        // it). `Watch` is part of the upstream shape and is answered
        // explicitly rather than left to a confusing default.
        Err(Status::unimplemented(
            "Health.Watch is not served by this manager; poll Health.Check instead",
        ))
    }
}

// ---------------------------------------------------------------------------
// Server assembly
// ---------------------------------------------------------------------------

/// Assembles the single internal gRPC server.
pub struct ServerBuilder {
    identity: Arc<LiveIdentity>,
    listen_addr: SocketAddr,
    authorizer: Authorizer,
    health: HealthRegistry,
    routes: Routes,
}

impl fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerBuilder")
            .field("listen_addr", &self.listen_addr)
            .field("authorizer", &self.authorizer)
            .finish_non_exhaustive()
    }
}

impl ServerBuilder {
    /// Builds a server that already serves `Raft`, `Control` and `Health` for
    /// `manager`. Add the remaining services with [`Self::add_service`].
    ///
    /// The identity is the node's **live** one (architecture §12.3): the
    /// TLS configuration built in [`Self::serve`] resolves the certificate
    /// and trust anchors through it on every handshake, so a renewal swapped
    /// into it is presented with no listener restart.
    pub fn new(
        identity: Arc<LiveIdentity>,
        listen_addr: SocketAddr,
        manager: &ManagerSlot,
    ) -> Result<Self, ServerError> {
        let authorizer = Authorizer::from_identity(&identity.identity())?;
        let health = HealthRegistry::new();
        let builder = Self {
            identity,
            listen_addr,
            authorizer,
            health: health.clone(),
            routes: Routes::default(),
        };

        let raft = satl_proto::v2::raft_server::RaftServer::new(
            crate::transport::RaftService::new(manager.clone()),
        )
        .max_decoding_message_size(MAX_MESSAGE_SIZE)
        .max_encoding_message_size(MAX_MESSAGE_SIZE);
        let control = satl_proto::v2::control_server::ControlServer::new(
            crate::membership::ControlService::new(manager.clone()),
        )
        .max_decoding_message_size(MAX_MESSAGE_SIZE)
        .max_encoding_message_size(MAX_MESSAGE_SIZE);
        let health_service = HealthServer::new(HealthService::new(health))
            .max_decoding_message_size(MAX_MESSAGE_SIZE)
            .max_encoding_message_size(MAX_MESSAGE_SIZE);

        Ok(builder
            .add_service(crate::transport::RAFT_ROLE, raft)
            .add_service(crate::membership::CONTROL_ROLE, control)
            .add_service(RoleRequirement::Any, health_service))
    }

    /// Registers one more gRPC service on this server, behind the
    /// authorization interceptor for `required`.
    ///
    /// `required` is architecture §7's per-service role: `Manager` for
    /// manager-only services, `WorkerOrManager` for `Dispatcher`, `Any` for
    /// services a node of either role may call. Set both message-size limits
    /// on `service` before passing it in — tonic's defaults are not
    /// [`satl_proto::MAX_MESSAGE_SIZE`].
    #[must_use]
    pub fn add_service<S>(mut self, required: RoleRequirement, service: S) -> Self
    where
        S: tower::Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
            + NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        tracing::debug!(
            service = S::NAME,
            required = ?required,
            "registering internal gRPC service"
        );
        let intercepted = tonic::service::interceptor::InterceptedService::new(
            service,
            AuthInterceptor {
                authorizer: self.authorizer.clone(),
                required,
            },
        );
        self.routes = self.routes.add_service(intercepted);
        self
    }

    /// The health registry this server serves, so other subsystems can
    /// publish their readiness.
    #[must_use]
    pub fn health(&self) -> HealthRegistry {
        self.health.clone()
    }

    /// The authorizer, so the caller can attach the store once it exists.
    #[must_use]
    pub fn authorizer(&self) -> Authorizer {
        self.authorizer.clone()
    }

    /// Binds the listener and starts serving. Returns once the socket is
    /// bound, so a caller can advertise the address it actually got (port 0
    /// in tests).
    pub async fn serve(self) -> Result<ServerHandle, ServerError> {
        let Self {
            identity,
            listen_addr,
            health,
            routes,
            ..
        } = self;

        let tls = Arc::new(satl_ca::live_server_config(&identity)?);
        let listener = tokio::net::TcpListener::bind(listen_addr)
            .await
            .map_err(|source| ServerError::Bind {
                addr: listen_addr,
                source,
            })?;
        let local_addr = listener.local_addr().map_err(|source| ServerError::Bind {
            addr: listen_addr,
            source,
        })?;

        let (conn_tx, conn_rx) = mpsc::channel(ACCEPT_BACKLOG);
        let acceptor = TlsAcceptor::from(tls);
        let accept_loop = tokio::spawn(accept_connections(listener, acceptor, conn_tx));

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let serving = tokio::spawn(async move {
            Server::builder()
                .add_routes(routes)
                .serve_with_incoming_shutdown(ReceiverStream::new(conn_rx), async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        // The listener is up and TLS credentials are loaded: that is exactly
        // what the empty health name means (`proto/health.proto`).
        health.set_serving("");
        tracing::info!(addr = %local_addr, "internal gRPC server listening");

        Ok(ServerHandle {
            local_addr,
            shutdown: Some(shutdown_tx),
            accept_loop,
            serving: Some(serving),
        })
    }
}

/// Accepts TCP connections and hands off completed TLS handshakes.
///
/// Each handshake runs in its own task under [`HANDSHAKE_TIMEOUT`], so one
/// stalled peer cannot wedge the accept loop.
async fn accept_connections(
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
    connections: mpsc::Sender<
        Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::io::Error>,
    >,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                // A per-connection accept error (EMFILE, ECONNABORTED) must
                // not kill the listener.
                tracing::warn!(error = %err, "accepting an internal gRPC connection failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if connections.is_closed() {
            tracing::debug!("internal gRPC server stopped; ending the accept loop");
            return;
        }
        let acceptor = acceptor.clone();
        let connections = connections.clone();
        tokio::spawn(async move {
            let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await;
            match handshake {
                Ok(Ok(tls)) => {
                    let _ = connections.send(Ok(tls)).await;
                }
                Ok(Err(err)) => {
                    if is_certificate_rejection(&err) {
                        // Operator-facing on purpose: this is the one
                        // handshake failure a node cannot heal on its own —
                        // its certificate chains to a root this cluster no
                        // longer trusts, which is what a node that slept
                        // through a root CA rotation presents when it comes
                        // back (architecture 12.3). Debug-level would bury
                        // the only server-side evidence.
                        tracing::warn!(
                            %peer,
                            error = %err,
                            "refused an internal TLS connection: the peer's certificate does \
                             not verify against this cluster's trust anchors. If that node was \
                             offline across a root CA rotation ('satl ca rotate'), its \
                             certificate chains to a dropped root: {}",
                            satl_ca::REJOIN_AFTER_ROTATION_HINT
                        );
                    } else {
                        tracing::debug!(%peer, error = %err, "TLS handshake with a peer failed");
                    }
                }
                Err(_) => {
                    tracing::debug!(%peer, timeout = ?HANDSHAKE_TIMEOUT, "TLS handshake timed out");
                }
            }
        });
    }
}

/// Whether a handshake error is the server rejecting the peer's certificate
/// (as opposed to a timeout, a plain-TCP scanner, a TLS version mismatch...).
///
/// `tokio-rustls` surfaces rustls errors wrapped in `std::io::Error`; the
/// typed downcast is tried first, the message match is the fallback for
/// wrappings that lose the type.
fn is_certificate_rejection(err: &std::io::Error) -> bool {
    if let Some(inner) = err.get_ref()
        && let Some(tls) = inner.downcast_ref::<rustls::Error>()
    {
        return matches!(
            tls,
            rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented
        );
    }
    let text = err.to_string();
    text.contains("InvalidCertificate") || text.contains("NoCertificatesPresented")
}

/// A running internal gRPC server.
pub struct ServerHandle {
    local_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    accept_loop: tokio::task::JoinHandle<()>,
    serving: Option<tokio::task::JoinHandle<Result<(), tonic::transport::Error>>>,
}

impl fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerHandle")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl ServerHandle {
    /// The address the listener actually bound (resolves port 0).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stops accepting, drains in-flight requests and waits for the server
    /// task to finish.
    pub async fn shutdown(mut self) -> Result<(), ServerError> {
        let addr = self.local_addr;
        self.accept_loop.abort();
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let Some(serving) = self.serving.take() else {
            return Ok(());
        };
        match serving.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(ServerError::Serve {
                addr,
                message: err.to_string(),
            }),
            Err(err) if err.is_cancelled() => Ok(()),
            Err(err) => Err(ServerError::Serve {
                addr,
                message: err.to_string(),
            }),
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.accept_loop.abort();
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn the_authorizer_takes_its_cluster_id_from_its_own_certificate() {
        let ca = testing::TestCa::new();
        let identity = ca.identity(satl_core::NodeRole::Manager);
        let authorizer = Authorizer::from_identity(&identity).expect("authorizer");
        assert_eq!(authorizer.cluster_id(), ca.cluster_id());
    }

    #[test]
    fn health_registry_reports_only_registered_names() {
        let registry = HealthRegistry::new();
        assert_eq!(registry.status(HEALTH_SERVICE_RAFT), None);
        registry.set_serving(HEALTH_SERVICE_RAFT);
        assert_eq!(
            registry.status(HEALTH_SERVICE_RAFT),
            Some(ServingStatus::Serving)
        );
        registry.set_not_serving(HEALTH_SERVICE_RAFT);
        assert_eq!(
            registry.status(HEALTH_SERVICE_RAFT),
            Some(ServingStatus::NotServing)
        );
        assert_eq!(registry.status("nonsense"), None);
    }

    #[test]
    fn an_empty_manager_slot_answers_unavailable() {
        let slot = ManagerSlot::new();
        assert!(slot.get().is_none());
        let err = slot.require("append_entries").expect_err("not installed");
        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert!(err.message().contains("append_entries"), "{err}");
    }
}
