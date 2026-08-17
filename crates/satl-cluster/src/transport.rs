// SPDX-License-Identifier: BSD-2-Clause
//! The Raft transport: openraft's [`RaftNetwork`] over tonic + rustls mTLS,
//! and the server side of the `Raft` gRPC service (architecture §6, §7,
//! SWK §11.7).
//!
//! This module replaces the M0 [`crate::network::NoPeersNetwork`] stub.
//!
//! # Wire format
//!
//! openraft's request/response types are **not** re-modelled in protobuf.
//! Every `Raft` RPC carries `bytes payload` holding the CBOR (`ciborium`)
//! encoding of the corresponding openraft type parameterised by
//! [`TypeConfig`]; see `proto/raft.proto` and `proto/README.md` for the
//! rationale.
//!
//! A **response** payload is the CBOR of the whole
//! `Result<Resp, RaftError<..>>` the local `openraft::Raft` handler returned.
//! Raft-level errors are *data*, carried back intact so the caller can hand
//! them to openraft; gRPC status codes are reserved for **transport**
//! failures. Flattening raft errors into gRPC statuses would break openraft's
//! retry and backoff logic, which depends on telling the two apart.
//!
//! # Error mapping (what openraft does with each shape)
//!
//! | Failure | openraft error | openraft's reaction |
//! |---|---|---|
//! | RPC exceeded [`RPCOption::hard_ttl`] | [`RPCError::Timeout`] | retry, no backoff |
//! | connect refused, TLS rejected, peer gone, unknown status | [`RPCError::Unreachable`] | [`RaftNetwork::backoff`] then retry |
//! | payload could not be encoded or decoded | [`RPCError::Network`] | immediate retry |
//! | peer answered with a raft error | [`RPCError::RemoteError`] | raft-level handling |
//!
//! Everything that cannot be fixed by trying again *right now* maps to
//! `Unreachable`, which is the only shape that makes openraft back off — a
//! blacklisted or role-refused sender must not hot-loop against its peer.
//!
//! # Connections
//!
//! One lazily-connected tonic [`Channel`] per peer address, shared by every
//! RPC to that address and cached across
//! [`RaftNetworkFactory::new_client`] calls (openraft builds a fresh client
//! per replication stream and after every address change). Peer addresses
//! come from openraft's [`BasicNode::addr`], which the membership code fills
//! with the peer's advertised `host:port`.
//!
//! A channel reconnects by itself, but the pool would keep handing out a
//! connection that had stopped working for the life of the process, so a
//! transport-level status makes this module *forget* it
//! ([`RaftConnection::discard_broken_connection`]) instead of trusting it to
//! heal.
//!
//! # Liveness
//!
//! Every RPC records its outcome in a shared [`PeerLiveness`] map. That map
//! is SatL's equivalent of SwarmKit's `transport.Active(id)` and is what
//! `Control.LeaveRaft`'s quorum-safety check counts (SWK §11.5) — openraft
//! 0.9 exposes replication progress but not per-peer reachability.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use openraft::error::{
    InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError, Timeout, Unreachable,
};
use openraft::network::{RPCOption, RPCTypes};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{BasicNode, RaftNetwork, RaftNetworkFactory};
use parking_lot::Mutex;
use rustls::ClientConfig;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

use satl_ca::{LiveIdentity, RoleRequirement, SAN_MANAGER};
use satl_proto::MAX_MESSAGE_SIZE;
use satl_proto::v1::raft_client::RaftClient;
use satl_proto::v1::raft_server::Raft as RaftRpc;
use satl_proto::v1::{self as pb};

use crate::server::ManagerSlot;
use crate::types::TypeConfig;

/// The default window a peer stays "active" for quorum arithmetic after its
/// last successful RPC — one election timeout at SwarmKit's timings
/// (architecture §15).
///
/// The value actually applied is
/// [`RaftTiming::liveness_window`](crate::node::RaftTiming::liveness_window),
/// carried on [`crate::server::ManagerContext`], so a cluster running shorter
/// ticks gets a proportionally shorter window.
pub const LIVENESS_WINDOW: Duration = Duration::from_secs(20);

/// Deadline for the whole `Control.JoinRaft` health-check probe (SWK §11.3).
pub const HEALTH_CHECK_BUDGET: Duration = Duration::from_secs(5);

/// TCP connect budget for a peer dial. Kept short: a peer that does not
/// answer the SYN within this is unreachable as far as raft is concerned, and
/// openraft's backoff will pace the retries.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// CBOR codec
// ---------------------------------------------------------------------------

/// A raft payload could not be turned into, or read back from, CBOR.
#[derive(Debug, thiserror::Error)]
#[error("raft {op}: {direction} the CBOR payload of {what}: {message}")]
pub struct CodecError {
    /// The RPC involved (`append_entries`, `vote`, `install_snapshot`).
    pub op: &'static str,
    /// `encoding` or `decoding`.
    pub direction: &'static str,
    /// The Rust type being encoded or decoded.
    pub what: &'static str,
    /// Underlying `ciborium` message.
    pub message: String,
}

/// CBOR-encodes a raft message body.
pub(crate) fn encode<T: Serialize>(
    op: &'static str,
    what: &'static str,
    value: &T,
) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|e| CodecError {
        op,
        direction: "encoding",
        what,
        message: e.to_string(),
    })?;
    Ok(buf)
}

/// CBOR-decodes a raft message body.
pub(crate) fn decode<T: DeserializeOwned>(
    op: &'static str,
    what: &'static str,
    bytes: &[u8],
) -> Result<T, CodecError> {
    ciborium::de::from_reader(bytes).map_err(|e| CodecError {
        op,
        direction: "decoding",
        what,
        message: e.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A peer RPC failed at the transport level. Carries the peer, its address
/// and the operation, so an operator reading the log knows *what* was
/// attempted against *whom* (CLAUDE.md error rule).
#[derive(Debug, thiserror::Error)]
#[error("raft {op} to member {target} at {addr}: {reason}")]
pub struct PeerRpcError {
    /// The RPC that failed.
    pub op: &'static str,
    /// Raft ID of the peer.
    pub target: u64,
    /// Address that was dialed.
    pub addr: String,
    /// What went wrong.
    pub reason: String,
}

/// The transport could not be built (bad TLS material, unusable address).
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The node's own TLS material was rejected.
    #[error("building the raft client TLS configuration: {source}")]
    Tls {
        /// Underlying satl-ca error.
        #[from]
        source: satl_ca::TlsError,
    },
    /// A peer address is not usable as a gRPC endpoint.
    #[error("peer address {addr:?} is not a usable host:port endpoint: {reason}")]
    Address {
        /// The offending address.
        addr: String,
        /// Why it was rejected.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Peer liveness
// ---------------------------------------------------------------------------

/// When each peer last answered. Cloneable handle over shared state; the
/// transport writes it, the membership code reads it.
#[derive(Clone, Default)]
pub struct PeerLiveness {
    inner: Arc<Mutex<HashMap<u64, Instant>>>,
}

impl fmt::Debug for PeerLiveness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerLiveness")
            .field("peers", &self.inner.lock().len())
            .finish()
    }
}

impl PeerLiveness {
    /// An empty liveness map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `target` answered just now.
    pub fn record_success(&self, target: u64) {
        self.inner.lock().insert(target, Instant::now());
    }

    /// Whether `target` answered within `window`.
    ///
    /// There is deliberately no "record a failure" counterpart: a peer ages
    /// out of the window on its own, so a single dropped packet cannot evict
    /// a member that is otherwise healthy — which matters, because this is
    /// what a removal's quorum check counts.
    #[must_use]
    pub fn is_active(&self, target: u64, window: Duration) -> bool {
        self.inner
            .lock()
            .get(&target)
            .is_some_and(|seen| seen.elapsed() <= window)
    }

    /// Forgets a peer (used when a member is removed).
    pub fn forget(&self, target: u64) {
        self.inner.lock().remove(&target);
    }
}

// ---------------------------------------------------------------------------
// Peer channels
// ---------------------------------------------------------------------------

/// Builds and caches one lazily-connected mTLS gRPC channel per peer address.
///
/// Shared by the raft transport, the `JoinRaft` health probe and the
/// follower→leader forwarder, so a manager keeps exactly one connection per
/// peer regardless of which subsystem is talking (SWK §11.7).
#[derive(Clone)]
pub struct PeerChannels {
    tls: Arc<ClientConfig>,
    channels: Arc<Mutex<HashMap<String, Channel>>>,
}

impl fmt::Debug for PeerChannels {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerChannels")
            .field("cached", &self.channels.lock().len())
            .finish_non_exhaustive()
    }
}

impl PeerChannels {
    /// Builds the shared client configuration from this node's **live**
    /// identity. The expected server name is pinned to [`SAN_MANAGER`]: peers
    /// are dialed by address, but the name their certificate must carry is
    /// fixed.
    ///
    /// The configuration resolves the client certificate and the trust
    /// anchors through the live identity on every handshake (architecture
    /// §12.3), so the cached channels — which reconnect by themselves —
    /// present a renewed certificate on their next dial without being
    /// rebuilt or forgotten.
    pub fn new(identity: &Arc<LiveIdentity>) -> Result<Self, TransportError> {
        let tls = satl_ca::live_client_config(identity, SAN_MANAGER)?;
        Ok(Self {
            tls: Arc::new(tls),
            channels: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// A channel to `addr` (`host:port`), building and caching one if needed.
    ///
    /// The returned channel is lazy: it connects on first use and reconnects
    /// by itself afterwards, which is exactly the contract
    /// [`RaftNetworkFactory::new_client`] documents.
    pub fn channel(&self, addr: &str) -> Result<Channel, TransportError> {
        if let Some(channel) = self.channels.lock().get(addr) {
            return Ok(channel.clone());
        }
        let channel = self.build(addr)?;
        let mut cache = self.channels.lock();
        Ok(cache.entry(addr.to_owned()).or_insert(channel).clone())
    }

    /// Drops the cached channel for `addr` (peer removed, address changed).
    pub fn forget(&self, addr: &str) {
        self.channels.lock().remove(addr);
    }

    fn build(&self, addr: &str) -> Result<Channel, TransportError> {
        // The scheme is `http`: tonic must not layer its own TLS on top —
        // the connector below owns the handshake so the rustls configuration
        // is satl-ca's (pinned server name, cluster CA, ECDHE+AEAD suites).
        let endpoint = Endpoint::from_shared(format!("http://{addr}"))
            .map_err(|e| TransportError::Address {
                addr: addr.to_owned(),
                reason: e.to_string(),
            })?
            .connect_timeout(CONNECT_TIMEOUT)
            .tcp_nodelay(true);

        let tls = Arc::clone(&self.tls);
        let target = addr.to_owned();
        let connector = tower::service_fn(move |_: http::Uri| {
            let tls = Arc::clone(&tls);
            let target = target.clone();
            async move {
                let stream = tokio::net::TcpStream::connect(&target).await?;
                stream.set_nodelay(true)?;
                // The verifier pins the expected name itself (satl-ca's
                // `PinnedServerName`), so what is passed here only has to be
                // a syntactically valid DNS name.
                let name = rustls_pki_types::ServerName::try_from(SAN_MANAGER)
                    .map_err(std::io::Error::other)?;
                let stream = TlsConnector::from(tls).connect(name, stream).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        });

        Ok(endpoint.connect_with_connector_lazy(connector))
    }
}

// ---------------------------------------------------------------------------
// RaftNetworkFactory
// ---------------------------------------------------------------------------

/// openraft's network factory over the internal gRPC `Raft` service.
///
/// A node started without TLS material — a single-node cluster with no
/// internal listener — gets an **offline** transport instead of a second
/// implementation: every RPC reports [`Unreachable`], which is the same
/// answer the M0 stub gave and keeps openraft backing off rather than
/// hot-looping if it is ever invoked. A single-node cluster never invokes it.
#[derive(Clone, Debug)]
pub struct RaftTransport {
    local_raft_id: u64,
    channels: Option<PeerChannels>,
    liveness: PeerLiveness,
}

impl RaftTransport {
    /// Builds the transport for a node with `local_raft_id` and its live
    /// identity.
    pub fn new(local_raft_id: u64, identity: &Arc<LiveIdentity>) -> Result<Self, TransportError> {
        Ok(Self::with_channels(
            local_raft_id,
            PeerChannels::new(identity)?,
        ))
    }

    /// Builds a transport over an existing channel pool.
    #[must_use]
    pub fn with_channels(local_raft_id: u64, channels: PeerChannels) -> Self {
        Self {
            local_raft_id,
            channels: Some(channels),
            liveness: PeerLiveness::new(),
        }
    }

    /// A transport with no peers: every RPC is [`Unreachable`].
    #[must_use]
    pub fn offline(local_raft_id: u64) -> Self {
        Self {
            local_raft_id,
            channels: None,
            liveness: PeerLiveness::new(),
        }
    }

    /// The shared peer-liveness map (`LeaveRaft` quorum safety reads it).
    #[must_use]
    pub fn liveness(&self) -> PeerLiveness {
        self.liveness.clone()
    }

    /// The shared channel pool, absent on an offline transport.
    #[must_use]
    pub fn channels(&self) -> Option<PeerChannels> {
        self.channels.clone()
    }
}

impl RaftNetworkFactory<TypeConfig> for RaftTransport {
    type Network = RaftConnection;

    async fn new_client(&mut self, target: u64, node: &BasicNode) -> Self::Network {
        // Per the trait contract this must not connect and must not fail: a
        // bad address is reported later, as `Unreachable`, once openraft
        // actually sends something.
        RaftConnection {
            local_raft_id: self.local_raft_id,
            target,
            addr: node.addr.clone(),
            channels: self.channels.clone(),
            liveness: self.liveness.clone(),
        }
    }
}

/// A client for one peer. Cheap to build; the underlying channel comes from
/// the shared pool on every call, so a connection this node discards as
/// broken is rebuilt on the next one.
pub struct RaftConnection {
    local_raft_id: u64,
    target: u64,
    addr: String,
    channels: Option<PeerChannels>,
    liveness: PeerLiveness,
}

impl fmt::Debug for RaftConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RaftConnection")
            .field("local_raft_id", &self.local_raft_id)
            .field("target", &self.target)
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl RaftConnection {
    /// A client bound to this peer's channel, with both message-size limits
    /// pinned to [`MAX_MESSAGE_SIZE`] (tonic's defaults are not that value).
    fn client(&self, op: &'static str) -> Result<RaftClient<Channel>, PeerRpcError> {
        let err = |reason: String| PeerRpcError {
            op,
            target: self.target,
            addr: self.addr.clone(),
            reason,
        };
        let channel = self
            .channels
            .as_ref()
            .ok_or_else(|| {
                err(
                    "no gRPC endpoint for this peer: this node runs without an internal \
                     listener (single-node cluster)"
                        .to_owned(),
                )
            })?
            .channel(&self.addr)
            .map_err(|source| err(source.to_string()))?;
        Ok(RaftClient::new(channel)
            .max_decoding_message_size(MAX_MESSAGE_SIZE)
            .max_encoding_message_size(MAX_MESSAGE_SIZE))
    }

    /// Drops the pooled connection to this peer when the failure was the
    /// **connection's**, not the peer's answer, so a broken connection cannot
    /// outlive the failure that revealed it.
    ///
    /// Defence in depth rather than a fix for a measured bug: the pool hands
    /// the same [`Channel`] to every RPC and to every later
    /// [`RaftNetworkFactory::new_client`], so anything that leaves one
    /// unusable is unusable for the life of the process. That shape is worth
    /// closing because it is indistinguishable, in the log, from the failure
    /// that `node`'s `RAFT_MAX_PAYLOAD_ENTRIES` documents (`h2 protocol
    /// error`, repeated for ever, on a socket `netstat` calls `ESTABLISHED`),
    /// and an operator who has to tell those apart has already lost an hour.
    /// A transport-level status therefore invalidates the pooled connection
    /// and the next call dials again -- which costs one TCP+TLS handshake, and
    /// only after a failure.
    ///
    /// Application-level statuses -- "not the leader", "blacklisted raft id",
    /// a decode refusal -- leave it alone: they came *from* the peer, over a
    /// connection that works.
    fn discard_broken_connection(&self, op: &'static str, status: &Status) {
        // tonic reports connect failures as `Unavailable` and hyper/h2
        // failures as `Internal`/`Unknown`. Every one of them means "this
        // connection did not carry the request", which is the only case where
        // dropping it can help.
        let transport_level = matches!(
            status.code(),
            tonic::Code::Unavailable | tonic::Code::Internal | tonic::Code::Unknown
        );
        if !transport_level {
            return;
        }
        if let Some(channels) = &self.channels {
            channels.forget(&self.addr);
            tracing::debug!(
                target = self.target,
                addr = %self.addr,
                op,
                code = ?status.code(),
                "discarded the pooled connection to this peer after a transport failure; the \
                 next attempt dials again"
            );
        }
    }

    fn unreachable(&self, err: &PeerRpcError) -> Unreachable {
        tracing::debug!(
            target = self.target,
            addr = %self.addr,
            op = err.op,
            reason = %err.reason,
            "raft peer unreachable"
        );
        Unreachable::new(err)
    }

    fn timeout(&self, action: RPCTypes, timeout: Duration) -> Timeout<u64> {
        Timeout {
            action,
            id: self.local_raft_id,
            target: self.target,
            timeout,
        }
    }

    /// Maps a tonic status onto the openraft error shape it deserves.
    ///
    /// Everything that a retry-right-now cannot fix becomes `Unreachable`, so
    /// openraft backs off instead of hot-looping: a refused role, a
    /// blacklisted sender and a dead peer are all "stop hammering this
    /// address for a while".
    fn status_error(&self, op: &'static str, status: &Status) -> PeerRpcError {
        PeerRpcError {
            op,
            target: self.target,
            addr: self.addr.clone(),
            reason: format!("{:?}: {}", status.code(), status.message()),
        }
    }
}

impl RaftNetwork<TypeConfig> for RaftConnection {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        const OP: &str = "append_entries";

        let payload = encode(OP, "AppendEntriesRequest", &rpc)
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let mut client = self.client(OP).map_err(|e| self.unreachable(&e))?;
        let request = Request::new(pb::AppendEntriesRequest {
            from: self.local_raft_id,
            payload,
        });

        let call = client.append_entries(request);
        let response = match tokio::time::timeout(option.hard_ttl(), call).await {
            Err(_) => {
                return Err(RPCError::Timeout(
                    self.timeout(RPCTypes::AppendEntries, option.hard_ttl()),
                ));
            }
            Ok(Err(status)) => {
                self.discard_broken_connection(OP, &status);
                return Err(RPCError::Unreachable(
                    self.unreachable(&self.status_error(OP, &status)),
                ));
            }
            Ok(Ok(response)) => response.into_inner(),
        };

        self.liveness.record_success(self.target);
        let result: Result<AppendEntriesResponse<u64>, RaftError<u64>> = decode(
            OP,
            "Result<AppendEntriesResponse, RaftError>",
            &response.payload,
        )
        .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        result.map_err(|source| RPCError::RemoteError(RemoteError::new(self.target, source)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        const OP: &str = "vote";

        let payload = encode(OP, "VoteRequest", &rpc)
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let mut client = self.client(OP).map_err(|e| self.unreachable(&e))?;
        let request = Request::new(pb::VoteRequest {
            from: self.local_raft_id,
            payload,
        });

        let call = client.vote(request);
        let response = match tokio::time::timeout(option.hard_ttl(), call).await {
            Err(_) => {
                return Err(RPCError::Timeout(
                    self.timeout(RPCTypes::Vote, option.hard_ttl()),
                ));
            }
            Ok(Err(status)) => {
                self.discard_broken_connection(OP, &status);
                return Err(RPCError::Unreachable(
                    self.unreachable(&self.status_error(OP, &status)),
                ));
            }
            Ok(Ok(response)) => response.into_inner(),
        };

        self.liveness.record_success(self.target);
        let result: Result<VoteResponse<u64>, RaftError<u64>> =
            decode(OP, "Result<VoteResponse, RaftError>", &response.payload)
                .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        result.map_err(|source| RPCError::RemoteError(RemoteError::new(self.target, source)))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>,
    > {
        const OP: &str = "install_snapshot";

        let payload = encode(OP, "InstallSnapshotRequest", &rpc)
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let mut client = self.client(OP).map_err(|e| self.unreachable(&e))?;
        let request = Request::new(pb::InstallSnapshotRequest {
            from: self.local_raft_id,
            payload,
        });

        let call = client.install_snapshot(request);
        let response = match tokio::time::timeout(option.hard_ttl(), call).await {
            Err(_) => {
                return Err(RPCError::Timeout(
                    self.timeout(RPCTypes::InstallSnapshot, option.hard_ttl()),
                ));
            }
            Ok(Err(status)) => {
                self.discard_broken_connection(OP, &status);
                return Err(RPCError::Unreachable(
                    self.unreachable(&self.status_error(OP, &status)),
                ));
            }
            Ok(Ok(response)) => response.into_inner(),
        };

        self.liveness.record_success(self.target);
        let result: Result<InstallSnapshotResponse<u64>, RaftError<u64, InstallSnapshotError>> =
            decode(
                OP,
                "Result<InstallSnapshotResponse, RaftError<InstallSnapshotError>>",
                &response.payload,
            )
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        result.map_err(|source| RPCError::RemoteError(RemoteError::new(self.target, source)))
    }
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// Role every `Raft` RPC requires (architecture §12.5): managers only.
pub const RAFT_ROLE: RoleRequirement = RoleRequirement::Manager;

/// The server side of the `Raft` service.
///
/// **Never leader-proxied**: every manager answers for itself. Forwarding a
/// raft message to the leader would corrupt the protocol (SWK §11.7).
#[derive(Clone, Debug)]
pub struct RaftService {
    manager: ManagerSlot,
}

impl RaftService {
    /// Builds the service around the (possibly not yet installed) manager
    /// context — a joining node serves `Raft` before its raft node exists so
    /// the leader's health probe can reach it.
    #[must_use]
    pub fn new(manager: ManagerSlot) -> Self {
        Self { manager }
    }

    /// Resolves the manager context and refuses senders whose raft ID is on
    /// the removal blacklist (SWK §11.1).
    fn accept(&self, from: u64, op: &'static str) -> Result<crate::server::ManagerContext, Status> {
        let ctx = self.manager.require(op)?;
        if ctx.store.removed_raft_ids().contains(&from) {
            tracing::warn!(
                from,
                op,
                "refused raft message from a removed member; it must wipe its raft state and re-join"
            );
            return Err(Status::permission_denied(format!(
                "raft member {from} was removed from this cluster: its raft ID is blacklisted \
                 and can never be re-admitted. Wipe its raft directory and re-join with a fresh \
                 join token"
            )));
        }
        Ok(ctx)
    }
}

#[tonic::async_trait]
impl RaftRpc for RaftService {
    async fn append_entries(
        &self,
        request: Request<pb::AppendEntriesRequest>,
    ) -> Result<Response<pb::AppendEntriesResponse>, Status> {
        const OP: &str = "append_entries";
        let request = request.into_inner();
        let ctx = self.accept(request.from, OP)?;

        let rpc: AppendEntriesRequest<TypeConfig> =
            decode(OP, "AppendEntriesRequest", &request.payload).map_err(|e| decode_status(&e))?;
        let result = ctx.raft.append_entries(rpc).await;
        let payload = encode(OP, "Result<AppendEntriesResponse, RaftError>", &result)
            .map_err(|e| encode_status(&e))?;
        Ok(Response::new(pb::AppendEntriesResponse { payload }))
    }

    async fn vote(
        &self,
        request: Request<pb::VoteRequest>,
    ) -> Result<Response<pb::VoteResponse>, Status> {
        const OP: &str = "vote";
        let request = request.into_inner();
        let ctx = self.accept(request.from, OP)?;

        // Admission rule from SWK §11.7: a candidate this node has never
        // heard of must not be able to disrupt a stable leader by
        // campaigning. Membership is read from the *effective* configuration,
        // so a member added moments ago is already known.
        let known = ctx
            .store
            .raft_members()
            .iter()
            .any(|m| m.raft_id == request.from);
        if !known {
            tracing::warn!(
                from = request.from,
                "refused a vote request from a member this node does not know"
            );
            return Err(Status::permission_denied(format!(
                "raft member {from} is not part of this cluster's membership as this node sees \
                 it, so its vote request is refused (SWK section 11.7): join through \
                 Control.JoinRaft on the leader",
                from = request.from
            )));
        }

        let rpc: VoteRequest<u64> =
            decode(OP, "VoteRequest", &request.payload).map_err(|e| decode_status(&e))?;
        let result = ctx.raft.vote(rpc).await;
        let payload = encode(OP, "Result<VoteResponse, RaftError>", &result)
            .map_err(|e| encode_status(&e))?;
        Ok(Response::new(pb::VoteResponse { payload }))
    }

    async fn install_snapshot(
        &self,
        request: Request<pb::InstallSnapshotRequest>,
    ) -> Result<Response<pb::InstallSnapshotResponse>, Status> {
        const OP: &str = "install_snapshot";
        let request = request.into_inner();
        let ctx = self.accept(request.from, OP)?;

        let rpc: InstallSnapshotRequest<TypeConfig> =
            decode(OP, "InstallSnapshotRequest", &request.payload)
                .map_err(|e| decode_status(&e))?;
        let result = ctx.raft.install_snapshot(rpc).await;
        let payload = encode(
            OP,
            "Result<InstallSnapshotResponse, RaftError<InstallSnapshotError>>",
            &result,
        )
        .map_err(|e| encode_status(&e))?;
        Ok(Response::new(pb::InstallSnapshotResponse { payload }))
    }

    async fn stream_install_snapshot(
        &self,
        _request: Request<tonic::Streaming<pb::SnapshotChunk>>,
    ) -> Result<Response<pb::InstallSnapshotResponse>, Status> {
        // Defined in the wire contract so adding it later is not a
        // compatibility event; M2 ships the unary form and relies on
        // openraft's own chunking (`proto/raft.proto`). Clients probe with a
        // fallback on UNIMPLEMENTED, exactly as SwarmKit falls back to
        // `ProcessRaftMessage`.
        Err(Status::unimplemented(
            "StreamInstallSnapshot is not served in this version: snapshots are transferred with \
             the unary InstallSnapshot RPC and openraft's own chunking",
        ))
    }
}

/// A payload the peer sent could not be decoded — that is the *sender's*
/// problem, so it is `INVALID_ARGUMENT`, not `INTERNAL`.
fn decode_status(err: &CodecError) -> Status {
    Status::invalid_argument(err.to_string())
}

/// This node could not encode its own answer: a local fault.
fn encode_status(err: &CodecError) -> Status {
    Status::internal(err.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use openraft::error::{ClientWriteError, ForwardToLeader};
    use openraft::raft::{AppendEntriesResponse, VoteResponse};
    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId, Membership, Vote};

    use satl_core::{Id, ObjectKind, StoreAction};

    use crate::types::Proposal;

    use super::*;

    #[test]
    fn append_entries_request_round_trips_through_cbor() {
        let rpc = AppendEntriesRequest::<TypeConfig> {
            vote: Vote::new(3, 7),
            prev_log_id: Some(LogId::new(CommittedLeaderId::new(3, 7), 11)),
            entries: vec![
                Entry {
                    log_id: LogId::new(CommittedLeaderId::new(3, 7), 12),
                    payload: EntryPayload::Blank,
                },
                Entry {
                    log_id: LogId::new(CommittedLeaderId::new(3, 7), 13),
                    payload: EntryPayload::Normal(Proposal {
                        actions: vec![StoreAction::Remove {
                            kind: ObjectKind::Service,
                            id: Id::generate(),
                        }],
                    }),
                },
                Entry {
                    log_id: LogId::new(CommittedLeaderId::new(3, 7), 14),
                    payload: EntryPayload::Membership(Membership::new(
                        vec![BTreeSet::from([7_u64, 9])],
                        None,
                    )),
                },
            ],
            leader_commit: Some(LogId::new(CommittedLeaderId::new(3, 7), 12)),
        };

        let bytes = encode("append_entries", "AppendEntriesRequest", &rpc).expect("encode");
        let back: AppendEntriesRequest<TypeConfig> =
            decode("append_entries", "AppendEntriesRequest", &bytes).expect("decode");
        assert_eq!(format!("{rpc:?}"), format!("{back:?}"));
    }

    #[test]
    fn vote_and_append_responses_round_trip() {
        let vote = VoteResponse::<u64> {
            vote: Vote::new_committed(4, 2),
            vote_granted: true,
            last_log_id: Some(LogId::new(CommittedLeaderId::new(4, 2), 30)),
        };
        let ok: Result<VoteResponse<u64>, RaftError<u64>> = Ok(vote.clone());
        let bytes = encode("vote", "Result", &ok).expect("encode");
        let back: Result<VoteResponse<u64>, RaftError<u64>> =
            decode("vote", "Result", &bytes).expect("decode");
        assert_eq!(back.expect("ok"), vote);

        let success = AppendEntriesResponse::<u64>::Success;
        let ok: Result<AppendEntriesResponse<u64>, RaftError<u64>> = Ok(success);
        let bytes = encode("append_entries", "Result", &ok).expect("encode");
        let back: Result<AppendEntriesResponse<u64>, RaftError<u64>> =
            decode("append_entries", "Result", &bytes).expect("decode");
        assert!(matches!(back.expect("ok"), AppendEntriesResponse::Success));
    }

    /// A raft-level error is DATA on the wire: it must survive the round trip
    /// intact, because openraft's retry logic reads it (`proto/raft.proto`).
    #[test]
    fn a_raft_error_response_round_trips_as_data() {
        let forward = ForwardToLeader::<u64, BasicNode> {
            leader_id: Some(9),
            leader_node: Some(BasicNode::new("10.0.0.9:2377")),
        };
        let err: Result<(), RaftError<u64, ClientWriteError<u64, BasicNode>>> = Err(
            RaftError::APIError(ClientWriteError::ForwardToLeader(forward.clone())),
        );
        let bytes = encode("propose", "Result", &err).expect("encode");
        let back: Result<(), RaftError<u64, ClientWriteError<u64, BasicNode>>> =
            decode("propose", "Result", &bytes).expect("decode");
        match back {
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(got))) => {
                assert_eq!(got.leader_id, forward.leader_id);
                assert_eq!(got.leader_node, forward.leader_node);
            }
            other => panic!("expected a ForwardToLeader error, got {other:?}"),
        }

        // And the shape the Raft service actually returns.
        let err: Result<VoteResponse<u64>, RaftError<u64>> =
            Err(RaftError::Fatal(openraft::error::Fatal::Stopped));
        let bytes = encode("vote", "Result", &err).expect("encode");
        let back: Result<VoteResponse<u64>, RaftError<u64>> =
            decode("vote", "Result", &bytes).expect("decode");
        assert!(matches!(back, Err(RaftError::Fatal(_))), "{back:?}");
    }

    #[test]
    fn decoding_garbage_names_the_operation_and_type() {
        let err = decode::<VoteRequest<u64>>("vote", "VoteRequest", &[0xff, 0xff, 0xff])
            .expect_err("garbage must not decode");
        let msg = err.to_string();
        assert!(msg.contains("vote"), "{msg}");
        assert!(msg.contains("VoteRequest"), "{msg}");
        assert!(msg.contains("decoding"), "{msg}");
    }

    #[test]
    fn peer_rpc_errors_name_peer_address_and_operation() {
        let err = PeerRpcError {
            op: "append_entries",
            target: 42,
            addr: "10.0.0.7:2377".to_owned(),
            reason: "connection refused".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("append_entries"), "{msg}");
        assert!(msg.contains("42"), "{msg}");
        assert!(msg.contains("10.0.0.7:2377"), "{msg}");
        assert!(msg.contains("connection refused"), "{msg}");
    }

    #[test]
    fn liveness_window_expires() {
        let liveness = PeerLiveness::new();
        assert!(!liveness.is_active(1, LIVENESS_WINDOW));
        liveness.record_success(1);
        assert!(liveness.is_active(1, LIVENESS_WINDOW));
        // A zero-length window means "answered in the last instant", which a
        // record from a moment ago has already fallen out of.
        assert!(!liveness.is_active(1, Duration::ZERO));
        liveness.forget(1);
        assert!(!liveness.is_active(1, LIVENESS_WINDOW));
    }

    #[test]
    fn unusable_peer_addresses_are_reported_not_panicked_on() {
        let identity = crate::testing::test_live_identity();
        let channels = PeerChannels::new(&identity).expect("client config");
        let err = channels
            .channel("not a host:port at all")
            .expect_err("a malformed authority must be refused");
        assert!(matches!(err, TransportError::Address { .. }), "{err}");
        assert!(err.to_string().contains("not a host:port at all"));
    }

    #[test]
    fn snapshot_chunks_stay_under_the_message_limit() {
        // openraft chunks snapshots itself; the chunk size must leave room
        // for the vote, the snapshot metadata and CBOR framing.
        let limit = u64::try_from(MAX_MESSAGE_SIZE).expect("4 MiB fits in u64");
        assert!(
            crate::node::SNAPSHOT_MAX_CHUNK_SIZE * 2 < limit,
            "snapshot chunks must stay comfortably below the 4 MiB gRPC limit"
        );
    }
}
