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
use std::future::Future;
use std::io::Cursor;
use std::sync::Arc;
use std::time::{Duration, Instant};

use openraft::error::{
    NetworkError, RPCError, RaftError, ReplicationClosed, StreamingError, Timeout, Unreachable,
};
use openraft::network::{RPCOption, RPCTypes, RaftNetworkFactory, RaftNetworkV2};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, TransferLeaderRequest,
    TransferLeaderResponse, VoteRequest, VoteResponse,
};
use openraft::storage::Snapshot;
use openraft::type_config::alias::{SnapshotMetaOf, SnapshotOf, VoteOf};
use openraft::{BasicNode, OptionalSend};
use parking_lot::Mutex;
use rustls::ClientConfig;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

use satl_ca::{LiveIdentity, RoleRequirement, SAN_MANAGER};
use satl_proto::MAX_MESSAGE_SIZE;
use satl_proto::v2::raft_client::RaftClient;
use satl_proto::v2::raft_server::Raft as RaftRpc;
use satl_proto::v2::{self as pb};

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

/// Set when peers refuse this node's raft messages because its own raft ID is
/// on the removal blacklist.
///
/// A blacklisted ID can never be re-admitted, so a node still carrying one
/// campaigns for ever and no amount of retrying changes anything: it is a
/// manager by role and a non-member in fact, and nothing else notices.
/// Architecture §6.6 already says a node told it was removed wipes its raft
/// state -- this is that signal arriving from a vote refusal instead of from
/// the dispatcher, which is the path that had no handler.
///
/// Measured: a demote followed quickly by a promote leaves exactly this state,
/// because the role watcher rebuilds on a *change* and saw worker -> manager
/// net-zero, so the raft directory was never wiped (decision log, 2026-08-25).
#[derive(Clone, Debug, Default)]
pub struct Eviction {
    /// The raft ID a peer said was blacklisted, once one has.
    evicted: Arc<Mutex<Option<u64>>>,
    /// Wakes whoever is waiting to act on the eviction.
    ///
    /// The signal has to *push*. The role watcher that acts on it is parked on
    /// the agent session's watch channel, and an evicted manager's session is
    /// exactly the thing that does not progress: it dials its own dispatcher,
    /// which refuses because this node is not the raft leader and never will
    /// be, so the watch never changes and a flag nobody reads changes nothing.
    /// Measured on fbsd3 (decision log, 2026-08-25).
    wake: Arc<tokio::sync::Notify>,
}

impl Eviction {
    /// A fresh, unset handle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `raft_id` was refused as blacklisted, and wakes waiters.
    ///
    /// Only the first refusal is kept, but *every* one notifies: a waiter that
    /// woke, failed to re-join and went back to sleep must be woken again by
    /// the next refusal rather than depending on its retry timer alone.
    pub fn record(&self, raft_id: u64) {
        {
            let mut slot = self.evicted.lock();
            if slot.is_none() {
                *slot = Some(raft_id);
            }
        }
        self.wake.notify_waiters();
    }

    /// The raft ID a peer refused, if any.
    #[must_use]
    pub fn evicted_raft_id(&self) -> Option<u64> {
        *self.evicted.lock()
    }

    /// Consumes the signal, so a rebuild is not requested twice for it.
    ///
    /// The rebuild's own role watcher is spawned inside `apply_role`, which
    /// runs *before* the supervisor publishes the new core to the slot, so for
    /// a few hundred microseconds a fresh watcher reads the **old** context --
    /// and would find this flag still set and rebuild all over again. Measured
    /// on fbsd3: two full wipe-and-re-join cycles 180 us apart for one
    /// eviction, bounded only by which read won the race (decision log,
    /// 2026-08-25).
    ///
    /// Losing the signal on a rebuild that then fails costs nothing: the peers
    /// go on refusing, and the next refusal records it again.
    pub fn clear(&self) {
        *self.evicted.lock() = None;
    }

    /// Resolves when a refusal is recorded.
    ///
    /// Check [`Self::evicted_raft_id`] *after* creating this future and before
    /// awaiting it: `notify_waiters` only reaches waiters already registered,
    /// so a refusal that landed first would otherwise be waited on for ever.
    pub async fn recorded(&self) {
        self.wake.notified().await;
    }
}

/// openraft's network factory over the internal gRPC `Raft` service.
///
/// A node started without TLS material -- a single-node cluster with no
/// internal listener -- gets an **offline** transport instead of a second
/// implementation: every RPC reports [`Unreachable`], which is the same
/// answer the M0 stub gave and keeps openraft backing off rather than
/// hot-looping if it is ever invoked. A single-node cluster never invokes it.
#[derive(Clone, Debug)]
pub struct RaftTransport {
    local_raft_id: u64,
    channels: Option<PeerChannels>,
    liveness: PeerLiveness,
    eviction: Eviction,
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
            eviction: Eviction::new(),
        }
    }

    /// A transport with no peers: every RPC is [`Unreachable`].
    #[must_use]
    pub fn offline(local_raft_id: u64) -> Self {
        Self {
            local_raft_id,
            channels: None,
            liveness: PeerLiveness::new(),
            eviction: Eviction::new(),
        }
    }

    /// The shared peer-liveness map (`LeaveRaft` quorum safety reads it).
    #[must_use]
    pub fn liveness(&self) -> PeerLiveness {
        self.liveness.clone()
    }

    /// The shared eviction signal: set when a peer refuses this node's raft
    /// messages because its own raft ID is blacklisted.
    #[must_use]
    pub fn eviction(&self) -> Eviction {
        self.eviction.clone()
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
            eviction: self.eviction.clone(),
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
    eviction: Eviction,
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

    fn unreachable(&self, err: &PeerRpcError) -> Unreachable<TypeConfig> {
        tracing::debug!(
            target = self.target,
            addr = %self.addr,
            op = err.op,
            reason = %err.reason,
            "raft peer unreachable"
        );
        Unreachable::new(err)
    }

    fn timeout(&self, action: RPCTypes, timeout: Duration) -> Timeout<TypeConfig> {
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
    /// One refusal is special and is recorded rather than only reported: a
    /// peer saying **this node's own** raft ID is blacklisted. That is
    /// terminal, not transient -- a blacklisted ID can never be re-admitted --
    /// so backing off and retrying, which is what `Unreachable` buys, buys
    /// nothing at all. `satld` watches the flag and rebuilds the node from a
    /// wiped raft directory, which is architecture §6.6's own rule applied to
    /// a signal that previously had no handler (decision log, 2026-08-25).
    ///
    /// Matched on the message rather than on a code, because
    /// `PERMISSION_DENIED` is also how a peer refuses a wrong role or a
    /// foreign cluster, and those are emphatically not "wipe your state".
    /// `RaftService::accept` is the single producer of this text.
    fn status_error(&self, op: &'static str, status: &Status) -> PeerRpcError {
        if status.code() == tonic::Code::PermissionDenied
            && status.message().contains("its raft ID is blacklisted")
            && status
                .message()
                .contains(&format!("raft member {}", self.local_raft_id))
        {
            if self.eviction.evicted_raft_id().is_none() {
                tracing::error!(
                    raft_id = self.local_raft_id,
                    peer = self.target,
                    addr = %self.addr,
                    op,
                    "this node's raft ID was removed from the cluster and can never be \
                     re-admitted; its raft state will be wiped and the node re-joined"
                );
            }
            self.eviction.record(self.local_raft_id);
        }
        PeerRpcError {
            op,
            target: self.target,
            addr: self.addr.clone(),
            reason: format!("{:?}: {}", status.code(), status.message()),
        }
    }

    /// A raft-level failure reported *by the peer*.
    ///
    /// openraft 0.10 fixes the network RPCs' error parameter to `Infallible`:
    /// a rejection the protocol has an answer for (a higher vote, a log
    /// conflict) now travels as DATA inside the response, so anything still
    /// arriving here as a `RaftError` is the remote's own `Fatal` -- its raft
    /// is shutting down or has panicked. That is not worth retrying
    /// immediately, so it becomes `Unreachable` and openraft backs off,
    /// carrying the peer's own message so an operator sees which node failed
    /// and why.
    fn remote_raft_error(
        &self,
        op: &'static str,
        source: &RaftError<TypeConfig>,
    ) -> Unreachable<TypeConfig> {
        self.unreachable(&PeerRpcError {
            op,
            target: self.target,
            addr: self.addr.clone(),
            reason: source.to_string(),
        })
    }
}

impl RaftNetworkV2<TypeConfig> for RaftConnection {
    /// One sealed CBOR blob, as `state_machine` builds it. openraft 0.10 makes
    /// the snapshot handle a property of the *network* as well as of the state
    /// machine, because the transport now owns the fragmentation.
    type SnapshotData = Cursor<Vec<u8>>;

    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<TypeConfig>, RPCError<TypeConfig>> {
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
        let result: Result<AppendEntriesResponse<TypeConfig>, RaftError<TypeConfig>> = decode(
            OP,
            "Result<AppendEntriesResponse, RaftError>",
            &response.payload,
        )
        .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        result.map_err(|source| RPCError::Unreachable(self.remote_raft_error(OP, &source)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<VoteResponse<TypeConfig>, RPCError<TypeConfig>> {
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
        let result: Result<VoteResponse<TypeConfig>, RaftError<TypeConfig>> =
            decode(OP, "Result<VoteResponse, RaftError>", &response.payload)
                .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        result.map_err(|source| RPCError::Unreachable(self.remote_raft_error(OP, &source)))
    }

    /// Sends one whole snapshot as an ordered `SnapshotChunk` stream.
    ///
    /// openraft 0.9 chunked snapshots itself and this transport carried one
    /// chunk per unary call. 0.10 hands the whole snapshot over once and makes
    /// the fragmentation the transport's business, which is what
    /// `proto/raft.proto`'s streaming `FullSnapshot` was declared for.
    ///
    /// The first frame carries the leader's vote and the snapshot metadata;
    /// the rest carry [`crate::node::SNAPSHOT_MAX_CHUNK_SIZE`] bytes of body
    /// each. The deadline is **the whole transfer's**, scaled by the number of
    /// frames, because tonic gives one future for the whole client-streaming
    /// call and there is no per-frame hook to reset a timer on: a per-frame
    /// deadline would need a hand-rolled sender, and the budget below buys the
    /// same thing (a big snapshot gets proportionally longer) for none of the
    /// complexity. `soft_ttl` is the per-frame allowance.
    ///
    /// `cancel` resolves when the replication task gives up on this transfer;
    /// it is raced against the send so an abandoned snapshot stops occupying
    /// the link rather than running to completion into a closed stream.
    async fn full_snapshot(
        &mut self,
        vote: VoteOf<TypeConfig>,
        snapshot: SnapshotOf<TypeConfig, Self::SnapshotData>,
        cancel: impl Future<Output = ReplicationClosed> + OptionalSend + 'static,
        option: RPCOption,
    ) -> Result<SnapshotResponse<TypeConfig>, StreamingError<TypeConfig>> {
        const OP: &str = "full_snapshot";

        let header = encode(OP, "(Vote, SnapshotMeta)", &(&vote, &snapshot.meta))
            .map_err(|e| StreamingError::Network(NetworkError::new(&e)))?;
        let mut client = self.client(OP).map_err(|e| self.unreachable(&e))?;

        let body = snapshot.snapshot.into_inner();
        let chunk_size = usize::try_from(crate::node::SNAPSHOT_MAX_CHUNK_SIZE)
            .expect("the chunk size is a small constant and fits in usize");
        let from = self.local_raft_id;

        // Built eagerly rather than lazily so the only await inside the stream
        // is tonic's own send: a chunk that cannot be produced must fail here,
        // where the error still has somewhere to go.
        //
        // The cost is one extra copy of the snapshot -- `body` is borrowed by
        // the chunk iterator, so it and the frames are both live at the peak.
        // Accepted because this store holds object metadata and not blobs
        // (layers are ZFS datasets, never raft entries), so a snapshot is
        // megabytes rather than gigabytes. If that ever stops being true, the
        // fix is a lazy sender that pre-validates, not simply dropping the
        // eager build: the reason above still stands.
        let mut frames: Vec<pb::SnapshotChunk> = Vec::new();
        let mut body_chunks = body.chunks(chunk_size).peekable();
        let mut header = Some(header);
        while let Some(data) = body_chunks.next() {
            frames.push(pb::SnapshotChunk {
                from,
                header: header.take().unwrap_or_default(),
                data: data.to_vec(),
                last: body_chunks.peek().is_none(),
            });
        }
        // An empty snapshot is still a snapshot: it must reach the peer as one
        // header-only frame, or the receiver would wait for a stream that
        // never comes.
        if frames.is_empty() {
            frames.push(pb::SnapshotChunk {
                from,
                header: header.take().unwrap_or_default(),
                data: Vec::new(),
                last: true,
            });
        }

        // One frame's allowance times the number of frames, so the budget
        // tracks the snapshot's size instead of capping every transfer at the
        // same wall clock. `hard_ttl` is the floor: a one-frame snapshot still
        // gets the ordinary RPC budget.
        let frame_ttl = option.soft_ttl();
        let frames_len = u32::try_from(frames.len()).unwrap_or(u32::MAX);
        let transfer_ttl = frame_ttl.saturating_mul(frames_len).max(option.hard_ttl());
        let stream = tokio_stream::iter(frames);
        let call = client.full_snapshot(Request::new(stream));

        let response = tokio::select! {
            // Cancellation wins the race deliberately: a transfer the
            // replication task has abandoned should stop using the link now.
            reason = cancel => return Err(StreamingError::Closed(reason)),
            sent = tokio::time::timeout(transfer_ttl, call) => match sent {
                Err(_) => {
                    return Err(StreamingError::Timeout(
                        self.timeout(RPCTypes::InstallSnapshot, transfer_ttl),
                    ));
                }
                Ok(Err(status)) => {
                    self.discard_broken_connection(OP, &status);
                    return Err(StreamingError::Unreachable(
                        self.unreachable(&self.status_error(OP, &status)),
                    ));
                }
                Ok(Ok(response)) => response.into_inner(),
            },
        };

        self.liveness.record_success(self.target);
        let result: Result<SnapshotResponse<TypeConfig>, RaftError<TypeConfig>> =
            decode(OP, "Result<SnapshotResponse, RaftError>", &response.payload)
                .map_err(|e| StreamingError::Network(NetworkError::new(&e)))?;
        // `StreamingError` has no remote-error variant, and a raft-level
        // failure on the peer is not something to retry immediately: it gets
        // the backoff that `Unreachable` carries, with the peer's own message.
        result.map_err(|source| {
            StreamingError::Unreachable(self.unreachable(&PeerRpcError {
                op: OP,
                target: self.target,
                addr: self.addr.clone(),
                reason: source.to_string(),
            }))
        })
    }

    /// The call that makes demoting the current leader terminate.
    ///
    /// Without it openraft's default returns `Unreachable` and every peer
    /// falls back to waiting out the leader lease -- which is exactly the
    /// 30-40 s stall that made `satl node demote <leader>` retry for ever
    /// against openraft 0.9, where no such RPC existed at all.
    async fn transfer_leader(
        &mut self,
        req: TransferLeaderRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<TransferLeaderResponse<TypeConfig>, RPCError<TypeConfig>> {
        const OP: &str = "transfer_leader";

        let payload = encode(OP, "TransferLeaderRequest", &req)
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let mut client = self.client(OP).map_err(|e| self.unreachable(&e))?;
        let request = Request::new(pb::TransferLeaderRequest {
            from: self.local_raft_id,
            payload,
        });

        let call = client.transfer_leader(request);
        let response = match tokio::time::timeout(option.hard_ttl(), call).await {
            Err(_) => {
                return Err(RPCError::Timeout(
                    self.timeout(RPCTypes::TransferLeader, option.hard_ttl()),
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
        let result: Result<TransferLeaderResponse<TypeConfig>, RaftError<TypeConfig>> = decode(
            OP,
            "Result<TransferLeaderResponse, RaftError>",
            &response.payload,
        )
        .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        result.map_err(|source| RPCError::Unreachable(self.remote_raft_error(OP, &source)))
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

        let rpc: VoteRequest<TypeConfig> =
            decode(OP, "VoteRequest", &request.payload).map_err(|e| decode_status(&e))?;
        let result = ctx.raft.vote(rpc).await;
        let payload = encode(OP, "Result<VoteResponse, RaftError>", &result)
            .map_err(|e| encode_status(&e))?;
        Ok(Response::new(pb::VoteResponse { payload }))
    }

    /// Reassembles a streamed snapshot and hands it to openraft whole.
    ///
    /// The first frame carries the leader's vote and the snapshot metadata;
    /// every frame carries body bytes. Nothing is applied until the frame
    /// marked `last` arrives -- an aborted stream is discarded and the leader
    /// retries, which is what keeps a half-received snapshot from replacing a
    /// good store.
    async fn full_snapshot(
        &self,
        request: Request<tonic::Streaming<pb::SnapshotChunk>>,
    ) -> Result<Response<pb::FullSnapshotResponse>, Status> {
        const OP: &str = "full_snapshot";
        let mut stream = request.into_inner();

        let mut ctx = None;
        let mut header: Option<(VoteOf<TypeConfig>, SnapshotMetaOf<TypeConfig>)> = None;
        let mut body: Vec<u8> = Vec::new();
        let mut complete = false;

        while let Some(chunk) = stream.message().await? {
            // The admission check runs on the first frame, before any body
            // byte is buffered: a sender that may not talk to us must not be
            // able to make us allocate.
            if ctx.is_none() {
                ctx = Some(self.accept(chunk.from, OP)?);
            }
            if header.is_none() {
                if chunk.header.is_empty() {
                    return Err(Status::invalid_argument(
                        "the first SnapshotChunk of a FullSnapshot stream must carry a header",
                    ));
                }
                header = Some(
                    decode(OP, "(Vote, SnapshotMeta)", &chunk.header)
                        .map_err(|e| decode_status(&e))?,
                );
            }
            body.extend_from_slice(&chunk.data);
            if chunk.last {
                complete = true;
                break;
            }
        }

        let (Some(ctx), Some((vote, meta))) = (ctx, header) else {
            return Err(Status::invalid_argument(
                "the FullSnapshot stream ended before its first frame",
            ));
        };
        if !complete {
            return Err(Status::aborted(
                "the FullSnapshot stream ended before the frame marked last; nothing was \
                 installed and the leader should retry",
            ));
        }

        let snapshot = Snapshot {
            meta,
            snapshot: Cursor::new(body),
        };
        let result = ctx.raft.install_full_snapshot(vote, snapshot).await;
        let payload = encode(OP, "Result<SnapshotResponse, RaftError>", &result)
            .map_err(|e| encode_status(&e))?;
        Ok(Response::new(pb::FullSnapshotResponse { payload }))
    }

    /// The leader is asking this node to take over now (openraft 0.10).
    ///
    /// Handing the request to openraft is the whole job: it disarms this
    /// node's leader lease for the designated target and campaigns, instead of
    /// waiting the lease out.
    async fn transfer_leader(
        &self,
        request: Request<pb::TransferLeaderRequest>,
    ) -> Result<Response<pb::TransferLeaderResponse>, Status> {
        const OP: &str = "transfer_leader";
        let request = request.into_inner();
        let ctx = self.accept(request.from, OP)?;

        let rpc: TransferLeaderRequest<TypeConfig> =
            decode(OP, "TransferLeaderRequest", &request.payload).map_err(|e| decode_status(&e))?;
        let result = ctx.raft.handle_transfer_leader(rpc).await;
        let payload = encode(OP, "Result<TransferLeaderResponse, RaftError>", &result)
            .map_err(|e| encode_status(&e))?;
        Ok(Response::new(pb::TransferLeaderResponse { payload }))
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

    /// The eviction signal fires on **this node's own** blacklisting, and on
    /// nothing else.
    ///
    /// The discrimination is the whole point. `PERMISSION_DENIED` is also how
    /// a peer refuses a wrong role or a foreign cluster, and treating those as
    /// "wipe your raft state" would destroy a healthy node's identity over a
    /// misconfiguration. A blacklist refusal naming a *different* member is
    /// likewise not this node's business: it is what a leader sees while
    /// relaying for somebody else.
    #[test]
    fn only_this_nodes_own_blacklisting_sets_the_eviction_signal() {
        let conn = |eviction: &Eviction| RaftConnection {
            local_raft_id: 7,
            target: 9,
            addr: "10.0.0.9:2377".to_owned(),
            channels: None,
            liveness: PeerLiveness::new(),
            eviction: eviction.clone(),
        };
        let mine = "raft member 7 was removed from this cluster: its raft ID is blacklisted \
                    and can never be re-admitted. Wipe its raft directory and re-join with a \
                    fresh join token";

        // A refusal that is not about the blacklist at all.
        let e = Eviction::new();
        conn(&e).status_error(
            "vote",
            &Status::permission_denied("certificate OU satl-worker cannot call Raft.Vote"),
        );
        assert_eq!(
            e.evicted_raft_id(),
            None,
            "a role refusal is not an eviction"
        );

        // A blacklist refusal about somebody else.
        let e = Eviction::new();
        conn(&e).status_error(
            "append_entries",
            &Status::permission_denied(mine.replace("raft member 7", "raft member 42")),
        );
        assert_eq!(
            e.evicted_raft_id(),
            None,
            "another member's blacklisting is not this node's eviction"
        );

        // The right code, the right text, this node's own id.
        let e = Eviction::new();
        conn(&e).status_error("vote", &Status::permission_denied(mine));
        assert_eq!(e.evicted_raft_id(), Some(7));

        // The same text under a different code is not a refusal by the
        // authorizer, so it must not act either.
        let e = Eviction::new();
        conn(&e).status_error("vote", &Status::unavailable(mine));
        assert_eq!(e.evicted_raft_id(), None, "only PERMISSION_DENIED counts");
    }

    use openraft::error::{ClientWriteError, ForwardToLeader};
    use openraft::raft::{AppendEntriesResponse, VoteResponse};
    use openraft::{Entry, EntryPayload, Membership, Vote};

    use satl_core::{Id, ObjectKind, StoreAction};

    use crate::types::Proposal;

    use super::*;

    #[test]
    fn append_entries_request_round_trips_through_cbor() {
        let rpc = AppendEntriesRequest::<TypeConfig> {
            vote: Vote::new(3, 7),
            prev_log_id: Some(openraft::testing::log_id::<TypeConfig>(3, 7, 11)),
            entries: vec![
                Entry {
                    log_id: openraft::testing::log_id::<TypeConfig>(3, 7, 12),
                    payload: EntryPayload::Blank,
                },
                Entry {
                    log_id: openraft::testing::log_id::<TypeConfig>(3, 7, 13),
                    payload: EntryPayload::Normal(Proposal {
                        actions: vec![StoreAction::Remove {
                            kind: ObjectKind::Service,
                            id: Id::generate(),
                        }],
                    }),
                },
                Entry {
                    log_id: openraft::testing::log_id::<TypeConfig>(3, 7, 14),
                    payload: EntryPayload::Membership(Membership::new_with_defaults(
                        vec![BTreeSet::from([7_u64, 9])],
                        [],
                    )),
                },
            ],
            leader_commit: Some(openraft::testing::log_id::<TypeConfig>(3, 7, 12)),
        };

        let bytes = encode("append_entries", "AppendEntriesRequest", &rpc).expect("encode");
        let back: AppendEntriesRequest<TypeConfig> =
            decode("append_entries", "AppendEntriesRequest", &bytes).expect("decode");
        assert_eq!(format!("{rpc:?}"), format!("{back:?}"));
    }

    #[test]
    fn vote_and_append_responses_round_trip() {
        let vote = VoteResponse::<TypeConfig> {
            vote: Vote::new_committed(4, 2),
            vote_granted: true,
            last_log_id: Some(openraft::testing::log_id::<TypeConfig>(4, 2, 30)),
        };
        let ok: Result<VoteResponse<TypeConfig>, RaftError<TypeConfig>> = Ok(vote.clone());
        let bytes = encode("vote", "Result", &ok).expect("encode");
        let back: Result<VoteResponse<TypeConfig>, RaftError<TypeConfig>> =
            decode("vote", "Result", &bytes).expect("decode");
        assert_eq!(back.expect("ok"), vote);

        let success = AppendEntriesResponse::<TypeConfig>::Success;
        let ok: Result<AppendEntriesResponse<TypeConfig>, RaftError<TypeConfig>> = Ok(success);
        let bytes = encode("append_entries", "Result", &ok).expect("encode");
        let back: Result<AppendEntriesResponse<TypeConfig>, RaftError<TypeConfig>> =
            decode("append_entries", "Result", &bytes).expect("decode");
        assert!(matches!(back.expect("ok"), AppendEntriesResponse::Success));
    }

    /// A raft-level error is DATA on the wire: it must survive the round trip
    /// intact, because openraft's retry logic reads it (`proto/raft.proto`).
    #[test]
    fn a_raft_error_response_round_trips_as_data() {
        let forward = ForwardToLeader::<TypeConfig> {
            leader_id: Some(9),
            leader_node: Some(BasicNode::new("10.0.0.9:2377")),
        };
        let err: Result<(), RaftError<TypeConfig, ClientWriteError<TypeConfig>>> = Err(
            RaftError::APIError(ClientWriteError::ForwardToLeader(forward.clone())),
        );
        let bytes = encode("propose", "Result", &err).expect("encode");
        let back: Result<(), RaftError<TypeConfig, ClientWriteError<TypeConfig>>> =
            decode("propose", "Result", &bytes).expect("decode");
        match back {
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(got))) => {
                assert_eq!(got.leader_id, forward.leader_id);
                assert_eq!(got.leader_node, forward.leader_node);
            }
            other => panic!("expected a ForwardToLeader error, got {other:?}"),
        }

        // And the shape the Raft service actually returns.
        let err: Result<VoteResponse<TypeConfig>, RaftError<TypeConfig>> =
            Err(RaftError::Fatal(openraft::error::Fatal::Stopped));
        let bytes = encode("vote", "Result", &err).expect("encode");
        let back: Result<VoteResponse<TypeConfig>, RaftError<TypeConfig>> =
            decode("vote", "Result", &bytes).expect("decode");
        assert!(matches!(back, Err(RaftError::Fatal(_))), "{back:?}");
    }

    #[test]
    fn decoding_garbage_names_the_operation_and_type() {
        let err = decode::<VoteRequest<TypeConfig>>("vote", "VoteRequest", &[0xff, 0xff, 0xff])
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

    /// The eviction signal has to wake a waiter that is already parked.
    ///
    /// This is the half that was missing when the self-heal was first written:
    /// the flag was set correctly and nothing ever read it, because its only
    /// reader was blocked on a watch channel that an evicted node never
    /// advances. A `record` that does not wake is a signal that does not exist.
    #[tokio::test]
    async fn recording_an_eviction_wakes_a_waiter_already_parked() {
        let eviction = Eviction::new();
        let waiter = eviction.clone();
        let parked = tokio::spawn(async move { waiter.recorded().await });

        // Give the task time to register before notifying: `notify_waiters`
        // deliberately does not buffer, which is exactly why the caller checks
        // the flag after registering.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        eviction.record(7);

        tokio::time::timeout(std::time::Duration::from_secs(5), parked)
            .await
            .expect("recording an eviction must wake a parked waiter")
            .expect("the waiting task must not panic");
        assert_eq!(eviction.evicted_raft_id(), Some(7));
    }

    /// A second refusal notifies again, so a re-join that failed is retried on
    /// the next refusal rather than only on its timer.
    #[tokio::test]
    async fn a_repeat_refusal_wakes_again_without_changing_the_recorded_id() {
        let eviction = Eviction::new();
        eviction.record(7);

        let waiter = eviction.clone();
        let parked = tokio::spawn(async move { waiter.recorded().await });
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        eviction.record(9);

        tokio::time::timeout(std::time::Duration::from_secs(5), parked)
            .await
            .expect("a repeat refusal must wake a parked waiter")
            .expect("the waiting task must not panic");
        assert_eq!(
            eviction.evicted_raft_id(),
            Some(7),
            "the first refusal is the one that identifies this node's dead ID"
        );
    }

    /// An eviction is acted on once, not once per reader.
    ///
    /// The rebuild's own role watcher starts before the supervisor publishes
    /// the new core, so it reads the *old* context; without a clear it finds
    /// the flag still set and rebuilds again. Measured as two full
    /// wipe-and-re-join cycles for one eviction.
    #[test]
    fn clearing_an_eviction_stops_a_second_reader_acting_on_it() {
        let eviction = Eviction::new();
        eviction.record(7);
        assert_eq!(eviction.evicted_raft_id(), Some(7));

        // The handler consumes it...
        eviction.clear();
        // ...and a stale reader holding the same handle now sees nothing.
        let stale = eviction.clone();
        assert_eq!(
            stale.evicted_raft_id(),
            None,
            "a cleared eviction must not trigger a second rebuild"
        );

        // A refusal that keeps arriving re-arms it, so a failed rebuild is
        // retried rather than lost.
        stale.record(9);
        assert_eq!(eviction.evicted_raft_id(), Some(9));
    }
}
