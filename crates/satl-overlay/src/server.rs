// SPDX-License-Identifier: BSD-2-Clause
//! The UDP responder: answers from the endpoint table, forwards the rest
//! (architecture §11.5).
//!
//! One tokio task per socket. A task's queries arrive on a SatL-owned address
//! and are answered from [`EndpointTable`]; anything the table does not know
//! is forwarded to the host's resolvers and relayed back verbatim.
//!
//! **The bind addresses are a parameter, deliberately.** Whether SatL listens
//! on one address per network (the network's gateway) or on a single per-node
//! address is a data-plane question the VXLAN work decides — `docs/vxlan.md` §8
//! decided it: one socket per network gateway, so that the answer's source
//! address is the one a stub resolver's connected UDP socket asked. Nothing
//! else in this file depends on that choice, because **the socket does not
//! decide the scope** — see below.
//!
//! **Scope is the querying task, not the socket.** Every listener shares one
//! [`ScopeTable`]: the client's source address selects the task, and the task's
//! networks — in attachment order — are what the name is looked up in. A task
//! on two networks is therefore answered for both, whichever of its
//! `nameserver` lines the stub picked, and a source that belongs to no local
//! task is scoped to nothing and forwarded. The reasoning, including why an
//! unknown source must not resolve against everything, is in [`crate::scopes`].
//!
//! **TCP is out of scope** (architecture §11.5 is a DNS-RR responder, not a
//! zone server): a response that would not fit in 512 bytes is truncated with
//! `TC` set, and no listener accepts TCP connections. A client that follows
//! `TC` to TCP finds nothing there and keeps the truncated answer, which is
//! the right outcome for a round-robin set — any subset of the replicas is a
//! usable answer.
//!
//! Hardening, because a container can reach this socket: every packet is
//! parsed by [`crate::dns`], which never panics; malformed packets cost a
//! counter increment and either a `FORMERR` or a drop; forwarding is bounded
//! by a semaphore and a deadline, so no client can make the node open
//! unbounded sockets or hold unbounded memory.
//!
//! **Never bind this on a publicly reachable address.** Because it forwards,
//! it is a resolver for whoever can reach it, and a resolver that answers
//! anyone is a reflection amplifier. The bind list must hold SatL-owned
//! internal addresses only (network gateways, or a per-node overlay address);
//! that is a constraint on whoever chooses the addresses, not something this
//! crate can check.
//!
//! **A name is answered by the first of the task's networks that knows it**,
//! and never merged across them: two services of the same name on two networks
//! are two services, and concatenating their replicas would load-balance
//! traffic across both. `NXDOMAIN` still means what it says — the name exists
//! on none of the querying task's networks.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use satl_core::Id;
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::dns::{self, AnswerReply, Query, Rcode, StatusReply};
use crate::endpoints::{EndpointTable, Family, Lookup};
use crate::resolv::{DNS_PORT, HostResolvConf, ResolvConfError};
use crate::scopes::ScopeTable;

/// Receive buffer for client queries. A query without EDNS0 cannot exceed 512
/// bytes; the extra room means an oversized packet is seen (and rejected) as
/// malformed instead of being silently cut into something parseable.
const QUERY_BUFFER: usize = 2048;

/// Receive buffer for upstream responses.
const RESPONSE_BUFFER: usize = 4096;

/// Consecutive `recv_from` failures after which a listener gives up. A UDP
/// socket can report transient errors (an ICMP port-unreachable from an
/// earlier reply, for one); a permanent one must not spin a core forever.
const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 16;

/// Default TTL on answers, in seconds.
///
/// Short on purpose: the shuffle in [`EndpointTable::lookup`] is the load
/// balancer, and a task that leaves `RUNNING` must stop being used quickly, so
/// a caching resolver in between must not hold an answer long. Not zero, which
/// some stubs treat as "do not cache, do not use".
pub const DEFAULT_ANSWER_TTL: u32 = 30;

/// Default per-upstream timeout for a forwarded query.
pub const DEFAULT_FORWARD_TIMEOUT: Duration = Duration::from_secs(2);

/// Default number of upstreams tried for one query.
///
/// Two attempts at 2 s stay inside the 5 s a FreeBSD stub resolver waits
/// before it retries (`RES_TIMEOUT` in `resolv.h`), so a client sees our
/// `SERVFAIL` rather than its own timeout.
pub const DEFAULT_FORWARD_ATTEMPTS: usize = 2;

/// Default cap on forwards in flight across all listeners.
pub const DEFAULT_INFLIGHT_FORWARDS: usize = 64;

/// Where queries we are not authoritative for go.
#[derive(Debug, Clone, Default)]
pub struct Upstream {
    servers: Vec<SocketAddr>,
}

impl Upstream {
    /// Forward to these servers, in order.
    #[must_use]
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        Self { servers }
    }

    /// Forward nowhere: unknown names get `NXDOMAIN`, since the responder is
    /// then the only resolver the container has and the name genuinely does
    /// not resolve.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Reads the host's resolvers from a `resolv.conf`-shaped file (the path
    /// is a parameter so tests do not depend on the host's).
    pub async fn from_resolv_conf(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, ResolvConfError> {
        let host = HostResolvConf::read(path).await?;
        Ok(Self::new(
            host.nameservers
                .iter()
                .map(|address| SocketAddr::new(*address, DNS_PORT))
                .collect(),
        ))
    }

    /// The configured servers.
    #[must_use]
    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }

    /// Whether forwarding is possible at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

/// Tuning for [`DnsServer`].
#[derive(Debug, Clone)]
pub struct DnsServerConfig {
    /// Addresses to bind, one socket each. Port 0 binds an ephemeral port
    /// (tests). Every socket answers identically; only the source address of
    /// the answer differs, which is the whole reason there is more than one.
    pub binds: Vec<SocketAddr>,
    /// TTL on answers from the table.
    pub answer_ttl: u32,
    /// Timeout for one upstream attempt.
    pub forward_timeout: Duration,
    /// Upstreams tried per query.
    pub max_forward_attempts: usize,
    /// Forwards in flight, across all listeners. When it is reached, further
    /// queries get `SERVFAIL` immediately instead of queueing: honest
    /// backpressure beats unbounded work on behalf of a container.
    pub max_inflight_forwards: usize,
}

impl DnsServerConfig {
    /// Defaults, for these bind addresses.
    #[must_use]
    pub fn new(binds: Vec<SocketAddr>) -> Self {
        Self {
            binds,
            answer_ttl: DEFAULT_ANSWER_TTL,
            forward_timeout: DEFAULT_FORWARD_TIMEOUT,
            max_forward_attempts: DEFAULT_FORWARD_ATTEMPTS,
            max_inflight_forwards: DEFAULT_INFLIGHT_FORWARDS,
        }
    }
}

/// Why the responder could not start.
#[derive(Debug, thiserror::Error)]
pub enum DnsServerError {
    /// No bind addresses were configured.
    #[error("the DNS responder needs at least one listener address")]
    NoListeners,
    /// A socket could not be bound.
    #[error("cannot bind the DNS responder to {addr}: {source}")]
    Bind {
        /// The address we tried to bind.
        addr: SocketAddr,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

/// Counters, for logs, tests and a future metrics surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsStats {
    /// Datagrams received.
    pub received: u64,
    /// Queries answered from the table with at least one record.
    pub answered: u64,
    /// Queries answered `NOERROR` with no records (name known, type absent).
    pub nodata: u64,
    /// Queries answered `NXDOMAIN` (unknown name, no upstream to ask).
    pub nxdomain: u64,
    /// Malformed packets answered with an error rcode.
    pub rejected: u64,
    /// Packets dropped without a response.
    pub dropped: u64,
    /// Queries relayed from an upstream successfully.
    pub forwarded: u64,
    /// Forwards that found no usable upstream answer (`SERVFAIL`).
    pub forward_failed: u64,
    /// Forwards refused because the in-flight cap was reached (`SERVFAIL`).
    pub forward_refused: u64,
}

#[derive(Debug, Default)]
struct Counters {
    received: AtomicU64,
    answered: AtomicU64,
    nodata: AtomicU64,
    nxdomain: AtomicU64,
    rejected: AtomicU64,
    dropped: AtomicU64,
    forwarded: AtomicU64,
    forward_failed: AtomicU64,
    forward_refused: AtomicU64,
}

impl Counters {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> DnsStats {
        DnsStats {
            received: self.received.load(Ordering::Relaxed),
            answered: self.answered.load(Ordering::Relaxed),
            nodata: self.nodata.load(Ordering::Relaxed),
            nxdomain: self.nxdomain.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            forward_failed: self.forward_failed.load(Ordering::Relaxed),
            forward_refused: self.forward_refused.load(Ordering::Relaxed),
        }
    }
}

/// Everything a listener task needs, shared.
struct Shared {
    table: EndpointTable,
    /// Source address → the querying task's networks. Shared by every socket:
    /// the scope is the client, never the socket it reached.
    scopes: ScopeTable,
    upstream: Upstream,
    config: DnsServerConfig,
    forwards: Arc<Semaphore>,
    /// Our own bound addresses: never forward a query to ourselves.
    own_addrs: Vec<SocketAddr>,
    counters: Arc<Counters>,
}

impl Shared {
    /// Whether we can forward — drives the `RA` flag as well.
    fn can_forward(&self) -> bool {
        !self.upstream.is_empty()
    }
}

/// A running responder: one tokio task per bound socket.
///
/// Cancel the [`CancellationToken`] passed to [`DnsServer::bind`], then
/// [`DnsServer::join`], to stop it.
#[derive(Debug)]
pub struct DnsServer {
    local_addrs: Vec<SocketAddr>,
    handles: Vec<JoinHandle<()>>,
    counters: Arc<Counters>,
}

impl DnsServer {
    /// Binds the addresses with default tuning and starts serving.
    pub async fn bind(
        binds: Vec<SocketAddr>,
        table: EndpointTable,
        scopes: ScopeTable,
        upstream: Upstream,
        shutdown: CancellationToken,
    ) -> Result<Self, DnsServerError> {
        Self::bind_with(
            DnsServerConfig::new(binds),
            table,
            scopes,
            upstream,
            shutdown,
        )
        .await
    }

    /// Binds the addresses and starts serving.
    ///
    /// Every socket is bound before any task is spawned, so a bind failure is
    /// reported to the caller instead of appearing later in the logs.
    pub async fn bind_with(
        config: DnsServerConfig,
        table: EndpointTable,
        scopes: ScopeTable,
        upstream: Upstream,
        shutdown: CancellationToken,
    ) -> Result<Self, DnsServerError> {
        if config.binds.is_empty() {
            return Err(DnsServerError::NoListeners);
        }
        let mut bound = Vec::with_capacity(config.binds.len());
        for addr in &config.binds {
            let socket = UdpSocket::bind(addr)
                .await
                .map_err(|source| DnsServerError::Bind {
                    addr: *addr,
                    source,
                })?;
            let local = socket.local_addr().unwrap_or(*addr);
            bound.push((Arc::new(socket), local));
        }

        let local_addrs: Vec<SocketAddr> = bound.iter().map(|(_, local)| *local).collect();
        let counters = Arc::new(Counters::default());
        let forwards = Arc::new(Semaphore::new(config.max_inflight_forwards));
        if upstream.is_empty() {
            tracing::info!("no upstream resolvers configured; unknown names will get NXDOMAIN");
        }
        let shared = Arc::new(Shared {
            table,
            scopes,
            upstream,
            config,
            forwards,
            own_addrs: local_addrs.clone(),
            counters: Arc::clone(&counters),
        });

        let mut handles = Vec::with_capacity(bound.len());
        for (socket, local) in bound {
            tracing::info!(
                addr = %local,
                scoped_sources = shared.scopes.len(),
                "DNS responder listening; queries are scoped to the querying task"
            );
            handles.push(tokio::spawn(serve(
                socket,
                Arc::clone(&shared),
                shutdown.clone(),
            )));
        }
        Ok(Self {
            local_addrs,
            handles,
            counters,
        })
    }

    /// The addresses actually bound (port 0 resolved).
    #[must_use]
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local_addrs
    }

    /// A snapshot of the counters.
    #[must_use]
    pub fn stats(&self) -> DnsStats {
        self.counters.snapshot()
    }

    /// Waits for every listener task to finish (after cancelling the token).
    pub async fn join(self) {
        for handle in self.handles {
            if let Err(error) = handle.await {
                tracing::warn!(%error, "DNS listener task did not exit cleanly");
            }
        }
    }
}

/// One socket's receive loop.
async fn serve(socket: Arc<UdpSocket>, shared: Arc<Shared>, shutdown: CancellationToken) {
    let mut buf = vec![0_u8; QUERY_BUFFER];
    let mut consecutive_errors = 0_u32;
    loop {
        let received = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            result = socket.recv_from(&mut buf) => result,
        };
        let (len, client) = match received {
            Ok(received) => {
                consecutive_errors = 0;
                received
            }
            Err(error) => {
                consecutive_errors += 1;
                tracing::warn!(%error, consecutive_errors, "DNS listener receive failed");
                if consecutive_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                    tracing::error!(
                        "DNS listener giving up after {consecutive_errors} consecutive errors"
                    );
                    break;
                }
                continue;
            }
        };
        Counters::bump(&shared.counters.received);
        handle_packet(&socket, &shared, client, &buf[..len]).await;
    }
    tracing::debug!(addr = ?socket.local_addr().ok(), "DNS listener stopped");
}

/// Parses one datagram and answers, forwards, or drops it.
async fn handle_packet(
    socket: &Arc<UdpSocket>,
    shared: &Arc<Shared>,
    client: SocketAddr,
    packet: &[u8],
) {
    let query = match dns::parse_query(packet) {
        Ok(query) => query,
        Err(error) => {
            match error.reply() {
                None => {
                    Counters::bump(&shared.counters.dropped);
                    tracing::debug!(%client, %error, "dropping DNS packet");
                }
                Some(mut reply) => {
                    reply.recursion_available = shared.can_forward();
                    Counters::bump(&shared.counters.rejected);
                    tracing::debug!(%client, %error, rcode = %reply.rcode, "rejecting DNS query");
                    send_to(socket, &reply.encode(), client).await;
                }
            }
            return;
        }
    };

    let name = query.question.name.to_key();
    // Who is asking decides what may be answered: the source address selects
    // the task, and the task's networks are searched in attachment order. A
    // source that is not a local task's is scoped to nothing, which makes the
    // query an upstream question rather than an authoritative denial.
    let scope = shared.scopes.scope_for(client.ip());
    let task_id = scope.task_id().map(tracing::field::display);
    let outcome = classify(&shared.table, scope.networks(), &name, query.question.qtype);

    match outcome {
        Classified::Answer {
            network,
            addresses,
            searched,
        } => {
            Counters::bump(&shared.counters.answered);
            let bytes = AnswerReply {
                query: &query,
                addresses: &addresses,
                ttl: shared.config.answer_ttl,
                authoritative: true,
                recursion_available: shared.can_forward(),
            }
            .encode();
            tracing::debug!(
                %client,
                task_id,
                network_id = %network,
                searched,
                %name,
                qtype = query.question.qtype,
                answers = addresses.len(),
                "answered from the endpoint table"
            );
            send_to(socket, &bytes, client).await;
        }
        Classified::NoData { network } => {
            Counters::bump(&shared.counters.nodata);
            tracing::debug!(
                %client, task_id, network_id = %network, %name,
                qtype = query.question.qtype,
                "name exists with no record of that type"
            );
            send_to(
                socket,
                &status(&query, Rcode::NoError, true, shared).encode(),
                client,
            )
            .await;
        }
        Classified::NotOurs => {
            tracing::trace!(
                %client, task_id, %name,
                networks = scope.networks().len(),
                "no network in scope knows this name"
            );
            forward(socket, shared, client, &query, packet).await;
        }
    }
}

/// What the table says about a question, over the networks in scope.
enum Classified<'a> {
    /// Answer with these addresses (already shuffled), from this network.
    Answer {
        /// The network that owned the name.
        network: &'a Id,
        /// Addresses to answer with.
        addresses: Vec<IpAddr>,
        /// How many networks were searched before it, plus itself — a small
        /// number an operator can use to see that a collision was resolved.
        searched: usize,
    },
    /// The name exists but has no record of the requested type: `NOERROR`
    /// with no answers, never `NXDOMAIN`.
    NoData {
        /// The network that owned the name.
        network: &'a Id,
    },
    /// Not a name any network in scope knows: forward it.
    NotOurs,
}

/// Resolves `name` over the querying task's networks, **in order**.
///
/// The first network that knows the name answers it, and the search stops
/// there. It is not a merge: the same name on two of a task's networks is two
/// different services, and concatenating their addresses would send half the
/// task's traffic to the wrong one. Attachment order is what makes "first"
/// mean the same thing on every node and for every query
/// ([`crate::scopes`]).
///
/// An empty `networks` — an unknown source — falls out of the loop as
/// [`Classified::NotOurs`], which is the forward path.
fn classify<'a>(
    table: &EndpointTable,
    networks: &'a [Id],
    name: &str,
    qtype: u16,
) -> Classified<'a> {
    let family = match qtype {
        dns::TYPE_A => Some(Family::V4),
        dns::TYPE_AAAA => Some(Family::V6),
        _ => None,
    };
    for (index, network) in networks.iter().enumerate() {
        let searched = index + 1;
        match family {
            Some(family) => match table.lookup(network, name, family) {
                Lookup::Found(addresses) if addresses.is_empty() => {
                    return Classified::NoData { network };
                }
                Lookup::Found(addresses) => {
                    return Classified::Answer {
                        network,
                        addresses,
                        searched,
                    };
                }
                Lookup::Unknown => {}
            },
            // A type we do not serve (`MX`, `SRV`, `TXT`, `ANY`, …). If the
            // name is ours, say so with an empty `NOERROR`: forwarding an
            // internal name upstream would leak it and earn a misleading
            // `NXDOMAIN`.
            None => {
                if table.contains(network, name) {
                    return Classified::NoData { network };
                }
            }
        }
    }
    Classified::NotOurs
}

/// Builds a record-less response for a query.
fn status<'a>(
    query: &'a Query,
    rcode: Rcode,
    authoritative: bool,
    shared: &Shared,
) -> StatusReply<'a> {
    StatusReply {
        id: query.id,
        rcode,
        question: Some(&query.question),
        recursion_desired: query.recursion_desired,
        recursion_available: shared.can_forward(),
        authoritative,
    }
}

/// Sends the query to the host's resolvers and relays the answer.
///
/// The original datagram goes out unchanged, so the upstream sees the same
/// transaction ID and question and its response can be relayed byte for byte.
/// The receive loop is not blocked: one bounded task per forward.
async fn forward(
    socket: &Arc<UdpSocket>,
    shared: &Arc<Shared>,
    client: SocketAddr,
    query: &Query,
    packet: &[u8],
) {
    if !shared.can_forward() {
        Counters::bump(&shared.counters.nxdomain);
        tracing::debug!(
            %client, name = %query.question.name,
            "unknown name and no upstream: answering NXDOMAIN"
        );
        // Not authoritative: we own no zone, we simply have nowhere to ask.
        send_to(
            socket,
            &status(query, Rcode::NxDomain, false, shared).encode(),
            client,
        )
        .await;
        return;
    }

    let Ok(permit) = Arc::clone(&shared.forwards).try_acquire_owned() else {
        Counters::bump(&shared.counters.forward_refused);
        tracing::warn!(
            %client, name = %query.question.name,
            inflight = shared.config.max_inflight_forwards,
            "forward queue full; answering SERVFAIL"
        );
        send_to(
            socket,
            &status(query, Rcode::ServFail, false, shared).encode(),
            client,
        )
        .await;
        return;
    };

    let socket = Arc::clone(socket);
    let shared = Arc::clone(shared);
    let request = packet.to_vec();
    let query = query.clone();
    tokio::spawn(async move {
        // Held for the whole exchange; released when this task ends.
        let _permit: OwnedSemaphorePermit = permit;
        if let Some(response) = exchange_with_upstreams(&shared, &request, query.id).await {
            Counters::bump(&shared.counters.forwarded);
            tracing::debug!(
                %client, name = %query.question.name, bytes = response.len(),
                "relayed an upstream answer"
            );
            send_to(&socket, &response, client).await;
        } else {
            Counters::bump(&shared.counters.forward_failed);
            tracing::warn!(
                %client, name = %query.question.name,
                "no upstream answered; answering SERVFAIL"
            );
            let reply = StatusReply {
                id: query.id,
                rcode: Rcode::ServFail,
                question: Some(&query.question),
                recursion_desired: query.recursion_desired,
                recursion_available: true,
                authoritative: false,
            };
            send_to(&socket, &reply.encode(), client).await;
        }
    });
}

/// Tries the upstreams in order, up to `max_forward_attempts`.
async fn exchange_with_upstreams(shared: &Shared, request: &[u8], id: u16) -> Option<Vec<u8>> {
    let mut attempts = 0;
    for server in shared.upstream.servers() {
        if attempts >= shared.config.max_forward_attempts {
            break;
        }
        // A resolv.conf that points at one of our own sockets would otherwise
        // make us forward to ourselves forever.
        if shared.own_addrs.contains(server) {
            tracing::debug!(%server, "skipping upstream: it is one of our own listeners");
            continue;
        }
        attempts += 1;
        match exchange(*server, request, id, shared.config.forward_timeout).await {
            Ok(response) => return Some(response),
            Err(error) => tracing::debug!(%server, %error, "upstream query failed"),
        }
    }
    None
}

/// One upstream exchange on a fresh ephemeral socket.
///
/// Replies that do not match the transaction ID, or that are not responses,
/// are ignored (off-path spoofing attempts) but do not extend the deadline.
async fn exchange(
    server: SocketAddr,
    request: &[u8],
    id: u16,
    timeout: Duration,
) -> Result<Vec<u8>, io::Error> {
    let bind: SocketAddr = if server.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(server).await?;
    socket.send(request).await?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = vec![0_u8; RESPONSE_BUFFER];
    loop {
        let len = tokio::time::timeout_at(deadline, socket.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream did not answer"))??;
        let response = &buf[..len];
        if dns::peek_id(response) == Some(id) && dns::is_response(response) {
            return Ok(response.to_vec());
        }
        tracing::debug!(%server, "ignoring an upstream packet that does not match the query");
    }
}

async fn send_to(socket: &UdpSocket, bytes: &[u8], client: SocketAddr) {
    if let Err(error) = socket.send_to(bytes, client).await {
        tracing::debug!(%client, %error, "cannot send the DNS response");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(seed: u8) -> Id {
        format!("{}{}", "y".repeat(24), char::from(b'a' + seed % 26))
            .parse()
            .expect("valid id")
    }

    #[test]
    fn upstream_from_servers_and_empty() {
        assert!(Upstream::none().is_empty());
        let upstream = Upstream::new(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 53))]);
        assert_eq!(upstream.servers().len(), 1);
        assert!(!upstream.is_empty());
    }

    #[tokio::test]
    async fn binding_nothing_is_an_error() {
        let error = DnsServer::bind(
            Vec::new(),
            EndpointTable::new(),
            ScopeTable::new(),
            Upstream::none(),
            CancellationToken::new(),
        )
        .await
        .expect_err("no listeners");
        assert!(matches!(error, DnsServerError::NoListeners));
    }

    #[tokio::test]
    async fn an_unbindable_address_names_itself() {
        // Port 1 on a loopback address: unprivileged bind must fail, and the
        // error has to say which address it was.
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        let outcome = DnsServer::bind(
            vec![addr],
            EndpointTable::new(),
            ScopeTable::new(),
            Upstream::none(),
            CancellationToken::new(),
        )
        .await;
        match outcome {
            Err(DnsServerError::Bind { addr: reported, .. }) => assert_eq!(reported, addr),
            Err(other) => panic!("unexpected error: {other}"),
            // Running as root: binding port 1 succeeds, which is not a failure
            // of this code.
            Ok(server) => assert_eq!(server.local_addrs(), [addr]),
        }
    }

    /// Builds a table where every `(network, service, address)` triple is one
    /// running task.
    fn table_of(entries: &[(&Id, &str, IpAddr)]) -> EndpointTable {
        use crate::endpoints::EndpointRecord;
        use satl_core::TaskState;

        let table = EndpointTable::new();
        table.update(
            entries
                .iter()
                .enumerate()
                .map(|(index, (net, name, addr))| {
                    EndpointRecord::new(
                        (*net).clone(),
                        *name,
                        format!("{name}.{index}.task{index}"),
                        vec![*addr],
                        TaskState::Running,
                    )
                }),
        );
        table
    }

    fn v4(third: u8, last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 100, third, last))
    }

    #[test]
    fn classify_distinguishes_nodata_from_unknown() {
        let net = network(9);
        let table = table_of(&[(&net, "web", v4(0, 2))]);
        let scope = [net];

        assert!(matches!(
            classify(&table, &scope, "web", dns::TYPE_A),
            Classified::Answer { searched: 1, .. }
        ));
        assert!(matches!(
            classify(&table, &scope, "web", dns::TYPE_AAAA),
            Classified::NoData { .. }
        ));
        // MX for a name we own: NODATA, not a leak upstream.
        assert!(matches!(
            classify(&table, &scope, "web", 15),
            Classified::NoData { .. }
        ));
        assert!(matches!(
            classify(&table, &scope, "elsewhere.example.com", dns::TYPE_A),
            Classified::NotOurs
        ));
        assert!(matches!(
            classify(&table, &scope, "elsewhere.example.com", 15),
            Classified::NotOurs
        ));
    }

    #[test]
    fn every_network_in_scope_is_searched_and_an_empty_scope_is_not_ours() {
        let (front, back) = (network(10), network(11));
        let table = table_of(&[(&front, "web", v4(0, 2)), (&back, "db", v4(1, 2))]);
        let scope = [front.clone(), back.clone()];

        // A name on the *second* network resolves: this is the whole defect.
        // Scoped to one network, `db` was an NXDOMAIN a stub resolver caches.
        match classify(&table, &scope, "db", dns::TYPE_A) {
            Classified::Answer {
                network,
                addresses,
                searched,
            } => {
                assert_eq!(network, &back);
                assert_eq!(addresses, [v4(1, 2)]);
                assert_eq!(searched, 2, "the first network was searched first");
            }
            _ => panic!("db must resolve on the second network in scope"),
        }
        assert!(matches!(
            classify(&table, &scope, "web", dns::TYPE_A),
            Classified::Answer { searched: 1, .. }
        ));

        // A name on neither is still NotOurs, i.e. forwarded, i.e. NXDOMAIN
        // when there is no upstream. Widening the search does not stop us
        // saying no.
        assert!(matches!(
            classify(&table, &scope, "nowhere", dns::TYPE_A),
            Classified::NotOurs
        ));

        // A source we cannot attribute to a local task is scoped to nothing,
        // and nothing is not everything: `web` exists, and is still not
        // answered.
        assert!(matches!(
            classify(&table, &[], "web", dns::TYPE_A),
            Classified::NotOurs
        ));
        assert!(matches!(
            classify(&table, &[], "web", 15),
            Classified::NotOurs
        ));
    }

    #[test]
    fn a_name_on_two_networks_is_answered_by_the_first_one_attached() {
        let (front, back) = (network(12), network(13));
        let table = table_of(&[(&front, "web", v4(0, 2)), (&back, "web", v4(1, 2))]);

        // The same table, two tasks, two attachment orders: each resolves to
        // its own first network, and neither answer merges the two.
        for (scope, expected) in [
            ([front.clone(), back.clone()], (&front, v4(0, 2))),
            ([back.clone(), front.clone()], (&back, v4(1, 2))),
        ] {
            match classify(&table, &scope, "web", dns::TYPE_A) {
                Classified::Answer {
                    network, addresses, ..
                } => {
                    assert_eq!(network, expected.0);
                    assert_eq!(
                        addresses,
                        [expected.1],
                        "the other network's replica must not be merged in"
                    );
                }
                _ => panic!("web must resolve"),
            }
        }
    }

    #[test]
    fn a_network_that_owns_the_name_answers_nodata_rather_than_deferring() {
        // `web` exists on both, IPv6 only on the second. An `AAAA` query is
        // NODATA from the first: the name lives there, and searching on would
        // mean one name resolving to two different services depending on the
        // record type asked for.
        let (front, back) = (network(14), network(15));
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let table = table_of(&[(&front, "web", v4(0, 2)), (&back, "web", v6)]);
        let scope = [front.clone(), back];
        match classify(&table, &scope, "web", dns::TYPE_AAAA) {
            Classified::NoData { network } => assert_eq!(network, &front),
            _ => panic!("the first network owns the name, records or not"),
        }
    }
}
