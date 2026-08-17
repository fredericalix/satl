// SPDX-License-Identifier: BSD-2-Clause
//! Wire-level tests for the embedded DNS responder: a real UDP socket, real
//! datagrams, and assertions on the bytes that come back.
//!
//! Everything binds on `127.0.0.1:0`, so these tests need no privileges, no
//! network and no jails — they run in `make check` like any unit test.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use satl_core::{Id, TaskState};
use satl_overlay::dns::{self, Question};
use satl_overlay::{
    DnsServer, DnsServerConfig, EndpointRecord, EndpointTable, Name, ScopeTable, TaskScope,
    Upstream,
};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

const REPLY_TIMEOUT: Duration = Duration::from_secs(2);

fn network(seed: u8) -> Id {
    format!("{}{}", "x".repeat(24), char::from(b'a' + seed % 26))
        .parse()
        .expect("valid id")
}

fn task(seed: u8) -> Id {
    format!("{}{}", "t".repeat(24), char::from(b'a' + seed % 26))
        .parse()
        .expect("valid id")
}

/// Every client here sends from the loopback address, because [`ask`] binds
/// `127.0.0.1:0`. Scoping it to `networks` is what makes the responder treat it
/// as one of the node's own tasks; a source that is *not* in the scope table is
/// forwarded, which is what
/// [`a_source_that_belongs_to_no_local_task_is_forwarded`] checks.
fn scoped_loopback(seed: u8, networks: Vec<Id>) -> ScopeTable {
    let scopes = ScopeTable::new();
    scopes.update([TaskScope::new(
        task(seed),
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        networks,
    )]);
    scopes
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn query_bytes(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let question = Question::new(Name::from_ascii(name).expect("valid name"), qtype);
    dns::encode_query(id, &question, true)
}

/// Sends one datagram and waits for the reply.
async fn ask(server: SocketAddr, packet: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("client socket");
    socket.send_to(packet, server).await.expect("send");
    let mut buf = vec![0_u8; 4096];
    let len = tokio::time::timeout(REPLY_TIMEOUT, socket.recv(&mut buf))
        .await
        .ok()?
        .expect("recv");
    buf.truncate(len);
    Some(buf)
}

// -- response inspection ----------------------------------------------------

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

struct Parsed {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    body: Vec<u8>,
}

impl Parsed {
    fn of(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 12, "response shorter than a header");
        Self {
            id: be16(bytes, 0),
            flags: be16(bytes, 2),
            qdcount: be16(bytes, 4),
            ancount: be16(bytes, 6),
            body: bytes[12..].to_vec(),
        }
    }

    fn rcode(&self) -> u8 {
        u8::try_from(self.flags & 0x000F).expect("4 bits")
    }

    fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    fn is_authoritative(&self) -> bool {
        self.flags & 0x0400 != 0
    }

    fn recursion_available(&self) -> bool {
        self.flags & 0x0080 != 0
    }

    /// Walks the answer section, checking every record's shape, and returns the
    /// `A` addresses in the order they appear.
    fn a_records(&self, name: &str) -> Vec<Ipv4Addr> {
        let question_len = Name::from_ascii(name).expect("name").as_wire().len() + 4;
        let mut at = question_len;
        let mut addresses = Vec::new();
        for _ in 0..self.ancount {
            // Owner name: the standard pointer to the question at offset 12.
            assert_eq!(
                &self.body[at..at + 2],
                &[0xC0, 0x0C],
                "answer owner name is not a pointer to the question"
            );
            // owner(2) type(2) class(2) ttl(4) rdlength(2) rdata(rdlength)
            let rtype = be16(&self.body, at + 2);
            let class = be16(&self.body, at + 4);
            let rdlength = usize::from(be16(&self.body, at + 10));
            assert_eq!(class, 1, "class IN");
            assert_eq!(rtype, dns::TYPE_A, "only A records expected");
            assert_eq!(rdlength, 4, "A rdata is 4 bytes");
            let rdata = &self.body[at + 12..at + 12 + rdlength];
            addresses.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
            at += 12 + rdlength;
        }
        assert_eq!(at, self.body.len(), "trailing bytes after the answers");
        addresses
    }
}

// -- a stub upstream resolver ----------------------------------------------

/// What the fake upstream does with what it receives.
#[derive(Clone, Copy)]
enum StubBehavior {
    /// Reply with a recognizable canned answer.
    Answer,
    /// Record the query and never answer.
    Blackhole,
}

struct Stub {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Stub {
    async fn spawn(behavior: StubBehavior) -> Self {
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("stub socket");
        let addr = socket.local_addr().expect("stub addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut buf = vec![0_u8; 4096];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                let request = buf[..len].to_vec();
                recorded
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(request.clone());
                if matches!(behavior, StubBehavior::Answer) {
                    let _ = socket.send_to(&canned_answer(&request), from).await;
                }
            }
        });
        Self { addr, seen }
    }

    fn queries(&self) -> Vec<Vec<u8>> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// A response no SatL code path could have produced: the query with `QR` set,
/// one answer with an implausible TTL, and trailing bytes that only a verbatim
/// relay would preserve.
fn canned_answer(request: &[u8]) -> Vec<u8> {
    let mut response = request.to_vec();
    response[2] |= 0x80; // QR
    response[3] |= 0x80; // RA
    response[6] = 0;
    response[7] = 1; // ANCOUNT = 1
    response.extend_from_slice(&[0xC0, 0x0C]); // owner: the question
    response.extend_from_slice(&dns::TYPE_A.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes()); // IN
    response.extend_from_slice(&0x0001_E240_u32.to_be_bytes()); // TTL 123456
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&[203, 0, 113, 9]);
    response.extend_from_slice(b"upstream-marker");
    response
}

// -- fixtures ---------------------------------------------------------------

struct Fixture {
    server: DnsServer,
    addr: SocketAddr,
    table: EndpointTable,
    shutdown: CancellationToken,
    network: Id,
}

impl Fixture {
    async fn start(upstream: Upstream, tune: impl FnOnce(&mut DnsServerConfig)) -> Self {
        let network = network(0);
        let table = EndpointTable::new();
        let scopes = scoped_loopback(0, vec![network.clone()]);
        let mut config = DnsServerConfig::new(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))]);
        tune(&mut config);
        let shutdown = CancellationToken::new();
        let server =
            DnsServer::bind_with(config, table.clone(), scopes, upstream, shutdown.clone())
                .await
                .expect("bind");
        let addr = server.local_addrs()[0];
        assert_ne!(addr.port(), 0, "port 0 must be resolved to a real port");
        Self {
            server,
            addr,
            table,
            shutdown,
            network,
        }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        self.server.join().await;
    }
}

fn running(net: &Id, slot: u8, address: IpAddr) -> EndpointRecord {
    EndpointRecord::new(
        net.clone(),
        "web",
        format!("web.{slot}.task{slot}"),
        vec![address],
        TaskState::Running,
    )
}

// -- tests ------------------------------------------------------------------

#[tokio::test]
async fn answers_a_service_name_with_every_running_replica() {
    let fixture = Fixture::start(Upstream::none(), |_| {}).await;
    fixture.table.update([
        running(&fixture.network, 1, v4(10, 100, 0, 11)),
        running(&fixture.network, 2, v4(10, 100, 0, 12)),
        running(&fixture.network, 3, v4(10, 100, 0, 13)),
    ]);

    let reply = ask(fixture.addr, &query_bytes(0x1111, "web", dns::TYPE_A))
        .await
        .expect("an answer");
    let parsed = Parsed::of(&reply);
    assert_eq!(parsed.id, 0x1111);
    assert!(parsed.is_response());
    assert!(parsed.is_authoritative(), "AA: the table is the source");
    assert!(
        !parsed.recursion_available(),
        "RA off: this responder has no upstream"
    );
    assert_eq!(parsed.rcode(), 0);
    assert_eq!(parsed.qdcount, 1);
    assert_eq!(parsed.ancount, 3);
    assert_eq!(
        parsed.a_records("web").into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            Ipv4Addr::new(10, 100, 0, 11),
            Ipv4Addr::new(10, 100, 0, 12),
            Ipv4Addr::new(10, 100, 0, 13),
        ])
    );

    // A task name resolves to just that task.
    let reply = ask(fixture.addr, &query_bytes(2, "web.2.task2", dns::TYPE_A))
        .await
        .expect("an answer");
    let parsed = Parsed::of(&reply);
    assert_eq!(parsed.ancount, 1);
    assert_eq!(
        parsed.a_records("web.2.task2"),
        vec![Ipv4Addr::new(10, 100, 0, 12)]
    );

    let stats = fixture.server.stats();
    assert_eq!(stats.answered, 2, "{stats:?}");
    assert_eq!(stats.received, 2, "{stats:?}");
    fixture.stop().await;
}

#[tokio::test]
async fn successive_queries_come_back_in_different_orders() {
    let fixture = Fixture::start(Upstream::none(), |_| {}).await;
    fixture.table.update([
        running(&fixture.network, 1, v4(10, 100, 0, 1)),
        running(&fixture.network, 2, v4(10, 100, 0, 2)),
        running(&fixture.network, 3, v4(10, 100, 0, 3)),
        running(&fixture.network, 4, v4(10, 100, 0, 4)),
    ]);

    let mut orders = BTreeSet::new();
    for id in 0..32 {
        let reply = ask(fixture.addr, &query_bytes(id, "web", dns::TYPE_A))
            .await
            .expect("an answer");
        let parsed = Parsed::of(&reply);
        assert_eq!(parsed.ancount, 4);
        orders.insert(parsed.a_records("web"));
    }
    assert!(
        orders.len() > 1,
        "the responder must shuffle: that is the load balancing"
    );
    fixture.stop().await;
}

#[tokio::test]
async fn a_task_that_leaves_running_stops_being_answered() {
    let fixture = Fixture::start(Upstream::none(), |_| {}).await;
    fixture.table.update([
        running(&fixture.network, 1, v4(10, 100, 0, 1)),
        running(&fixture.network, 2, v4(10, 100, 0, 2)),
    ]);
    let reply = ask(fixture.addr, &query_bytes(1, "web", dns::TYPE_A))
        .await
        .expect("an answer");
    assert_eq!(Parsed::of(&reply).ancount, 2);

    fixture.table.upsert(EndpointRecord::new(
        fixture.network.clone(),
        "web",
        "web.2.task2",
        vec![v4(10, 100, 0, 2)],
        TaskState::Failed,
    ));
    let reply = ask(fixture.addr, &query_bytes(2, "web", dns::TYPE_A))
        .await
        .expect("an answer");
    let parsed = Parsed::of(&reply);
    assert_eq!(parsed.ancount, 1);
    assert_eq!(parsed.a_records("web"), vec![Ipv4Addr::new(10, 100, 0, 1)]);

    // The last one goes away: the name stops existing, and with no upstream
    // that is an NXDOMAIN.
    fixture.table.remove_task(&fixture.network, "web.1.task1");
    let reply = ask(fixture.addr, &query_bytes(3, "web", dns::TYPE_A))
        .await
        .expect("an answer");
    let parsed = Parsed::of(&reply);
    assert_eq!(parsed.rcode(), 3, "NXDOMAIN");
    assert_eq!(parsed.ancount, 0);
    fixture.stop().await;
}

#[tokio::test]
async fn aaaa_for_a_v4_only_service_is_noerror_with_no_records() {
    let fixture = Fixture::start(Upstream::none(), |_| {}).await;
    fixture
        .table
        .update([running(&fixture.network, 1, v4(10, 100, 0, 1))]);

    let reply = ask(fixture.addr, &query_bytes(7, "web", dns::TYPE_AAAA))
        .await
        .expect("an answer");
    let parsed = Parsed::of(&reply);
    assert_eq!(parsed.rcode(), 0, "NOERROR, not NXDOMAIN");
    assert_eq!(parsed.ancount, 0);
    assert!(parsed.is_authoritative());
    assert_eq!(parsed.qdcount, 1, "the question is echoed");

    // An unsupported type on a name we own is also NODATA, not a referral.
    let reply = ask(fixture.addr, &query_bytes(8, "web", 15))
        .await
        .expect("an answer");
    let parsed = Parsed::of(&reply);
    assert_eq!(parsed.rcode(), 0);
    assert_eq!(parsed.ancount, 0);
    fixture.stop().await;
}

#[tokio::test]
async fn unknown_names_are_forwarded_verbatim_and_the_answer_is_relayed() {
    let stub = Stub::spawn(StubBehavior::Answer).await;
    let fixture = Fixture::start(Upstream::new(vec![stub.addr]), |_| {}).await;
    fixture
        .table
        .update([running(&fixture.network, 1, v4(10, 100, 0, 1))]);

    let query = query_bytes(0x2222, "www.example.com", dns::TYPE_A);
    let reply = ask(fixture.addr, &query).await.expect("a relayed answer");

    assert_eq!(stub.queries(), vec![query.clone()], "forwarded verbatim");
    assert_eq!(reply, canned_answer(&query), "relayed byte for byte");
    let parsed = Parsed::of(&reply);
    assert_eq!(parsed.id, 0x2222);
    assert_eq!(parsed.ancount, 1);

    // Names we do own are still answered locally, not forwarded.
    let local = ask(fixture.addr, &query_bytes(0x2223, "web", dns::TYPE_A))
        .await
        .expect("a local answer");
    assert!(Parsed::of(&local).is_authoritative());
    assert_eq!(stub.queries().len(), 1, "no forward for a name we own");

    let stats = fixture.server.stats();
    assert_eq!(stats.forwarded, 1);
    assert_eq!(stats.answered, 1);
    fixture.stop().await;
}

#[tokio::test]
async fn a_silent_upstream_becomes_servfail_within_the_deadline() {
    let stub = Stub::spawn(StubBehavior::Blackhole).await;
    let fixture = Fixture::start(Upstream::new(vec![stub.addr]), |config| {
        config.forward_timeout = Duration::from_millis(120);
    })
    .await;

    let reply = ask(
        fixture.addr,
        &query_bytes(0x3333, "slow.example", dns::TYPE_A),
    )
    .await
    .expect("a SERVFAIL");
    let parsed = Parsed::of(&reply);
    assert_eq!(parsed.rcode(), 2, "SERVFAIL");
    assert_eq!(parsed.ancount, 0);
    assert_eq!(parsed.qdcount, 1);
    assert!(!parsed.is_authoritative());
    assert!(parsed.recursion_available(), "RA on: we do forward");
    // One attempt per configured upstream — retrying the same server is the
    // client stub's job, not ours.
    assert_eq!(stub.queries().len(), 1);
    assert_eq!(fixture.server.stats().forward_failed, 1);
    fixture.stop().await;
}

#[tokio::test]
async fn the_in_flight_forward_cap_answers_servfail_instead_of_queueing() {
    let stub = Stub::spawn(StubBehavior::Blackhole).await;
    let fixture = Fixture::start(Upstream::new(vec![stub.addr]), |config| {
        config.max_inflight_forwards = 1;
        config.forward_timeout = Duration::from_secs(5);
    })
    .await;

    // The first forward takes the only permit and holds it.
    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("client");
    client
        .send_to(&query_bytes(1, "first.example", dns::TYPE_A), fixture.addr)
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let reply = ask(fixture.addr, &query_bytes(2, "second.example", dns::TYPE_A))
        .await
        .expect("an immediate SERVFAIL");
    let parsed = Parsed::of(&reply);
    assert_eq!(parsed.id, 2);
    assert_eq!(parsed.rcode(), 2, "SERVFAIL, not a queued wait");
    assert_eq!(fixture.server.stats().forward_refused, 1);
    fixture.stop().await;
}

#[tokio::test]
async fn malformed_packets_are_answered_or_dropped_but_never_fatal() {
    let fixture = Fixture::start(Upstream::none(), |_| {}).await;
    fixture
        .table
        .update([running(&fixture.network, 1, v4(10, 100, 0, 1))]);

    // FORMERR: one question claimed, none present.
    let reply = ask(fixture.addr, &[0x44, 0x44, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("FORMERR");
    let parsed = Parsed::of(&reply);
    assert_eq!(parsed.id, 0x4444);
    assert_eq!(parsed.rcode(), 1, "FORMERR");
    assert_eq!(parsed.qdcount, 0, "no question to echo");

    // NOTIMP: opcode UPDATE (5).
    let mut update = query_bytes(0x4545, "web", dns::TYPE_A);
    update[2] = 5 << 3;
    let reply = ask(fixture.addr, &update).await.expect("NOTIMP");
    assert_eq!(Parsed::of(&reply).rcode(), 4, "NOTIMP");

    // NOTIMP: class CH, question echoed.
    let mut chaos = query_bytes(0x4646, "web", dns::TYPE_A);
    let last = chaos.len() - 1;
    chaos[last] = 3;
    let reply = ask(fixture.addr, &chaos).await.expect("NOTIMP");
    let parsed = Parsed::of(&reply);
    assert_eq!(parsed.rcode(), 4);
    assert_eq!(parsed.qdcount, 1);

    // Dropped without a reply: a response, and a runt.
    let mut response = query_bytes(0x4747, "web", dns::TYPE_A);
    response[2] |= 0x80;
    assert!(
        ask_briefly(fixture.addr, &response).await.is_none(),
        "a response must never be answered: that is how loops start"
    );
    assert!(ask_briefly(fixture.addr, &[0, 1, 2]).await.is_none());

    // And the responder is still healthy.
    let reply = ask(fixture.addr, &query_bytes(0x4848, "web", dns::TYPE_A))
        .await
        .expect("still answering");
    assert_eq!(Parsed::of(&reply).ancount, 1);
    fixture.stop().await;
}

#[tokio::test]
async fn a_flood_of_junk_does_not_take_the_responder_down() {
    let fixture = Fixture::start(Upstream::none(), |_| {}).await;
    fixture
        .table
        .update([running(&fixture.network, 1, v4(10, 100, 0, 42))]);

    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("client");
    let mut sent = 0_u32;
    for round in 0..250_u32 {
        for junk in junk_packets(round) {
            if client.send_to(&junk, fixture.addr).await.is_ok() {
                sent += 1;
            }
        }
    }
    assert!(sent > 1000, "sent {sent} malformed packets");

    // Drain whatever error responses came back, then ask a real question.
    let mut scratch = vec![0_u8; 4096];
    while tokio::time::timeout(Duration::from_millis(20), client.recv(&mut scratch))
        .await
        .is_ok()
    {}

    let reply = ask(fixture.addr, &query_bytes(0x5050, "web", dns::TYPE_A))
        .await
        .expect("the responder survived the flood");
    let parsed = Parsed::of(&reply);
    assert_eq!(parsed.ancount, 1);
    assert_eq!(parsed.a_records("web"), vec![Ipv4Addr::new(10, 100, 0, 42)]);

    let stats = fixture.server.stats();
    assert!(stats.received > 100, "{stats:?}");
    assert!(stats.rejected + stats.dropped > 100, "{stats:?}");
    assert_eq!(stats.answered, 1, "{stats:?}");
    fixture.stop().await;
}

/// Six shapes of hostile garbage, seeded by `round` so the flood is not one
/// packet repeated.
fn junk_packets(round: u32) -> Vec<Vec<u8>> {
    let seed = round.to_be_bytes();
    let id = [seed[2], seed[3]];
    vec![
        // Runt: no header.
        seed[..3].to_vec(),
        // Header claiming a question, nothing after it.
        vec![id[0], id[1], 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        // A label that runs off the end.
        [
            &[id[0], id[1], 0, 0, 0, 1, 0, 0, 0, 0, 0, 0][..],
            &[63, b'a', b'b'][..],
        ]
        .concat(),
        // Self-pointer: the classic decompression loop.
        [
            &[id[0], id[1], 0, 0, 0, 1, 0, 0, 0, 0, 0, 0][..],
            &[0xC0, 0x0C][..],
        ]
        .concat(),
        // Reserved label type.
        [
            &[id[0], id[1], 0, 0, 0, 1, 0, 0, 0, 0, 0, 0][..],
            &[0x80, b'x', 0, 0, 1, 0, 1][..],
        ]
        .concat(),
        // Random-ish noise of a plausible size.
        (0..64_u8)
            .map(|i| i.wrapping_mul(seed[3]).wrapping_add(seed[2]))
            .collect(),
    ]
}

/// Like [`ask`], with a short timeout: for packets that must go unanswered.
async fn ask_briefly(server: SocketAddr, packet: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("client socket");
    socket.send_to(packet, server).await.expect("send");
    let mut buf = vec![0_u8; 4096];
    let len = tokio::time::timeout(Duration::from_millis(250), socket.recv(&mut buf))
        .await
        .ok()?
        .expect("recv");
    buf.truncate(len);
    Some(buf)
}

#[tokio::test]
async fn a_task_on_two_networks_resolves_on_both_whichever_socket_it_asks() {
    // The defect this scenario exists for: `front` holds `web`, `back` holds
    // `db`, and one task is on both. Scoped to the socket, whichever
    // `nameserver` line the stub picked decided which of the two names existed
    // — and the other one came back NXDOMAIN, which a stub caches and does not
    // retry on the next line. So both names must resolve, on *both* sockets.
    let (front, back) = (network(1), network(2));
    let table = EndpointTable::new();
    table.update([
        EndpointRecord::new(
            front.clone(),
            "web",
            "web.1.aaa",
            vec![v4(10, 100, 1, 1)],
            TaskState::Running,
        ),
        EndpointRecord::new(
            back.clone(),
            "db",
            "db.1.bbb",
            vec![v4(10, 100, 2, 2)],
            TaskState::Running,
        ),
    ]);
    let scopes = scoped_loopback(1, vec![front, back]);
    let shutdown = CancellationToken::new();
    let server = DnsServer::bind(
        vec![
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        ],
        table,
        scopes,
        Upstream::none(),
        shutdown.clone(),
    )
    .await
    .expect("bind");
    let addrs = server.local_addrs().to_vec();
    assert_eq!(addrs.len(), 2);
    assert_ne!(addrs[0], addrs[1]);

    for addr in addrs {
        for (name, expected) in [
            ("web", Ipv4Addr::new(10, 100, 1, 1)),
            ("db", Ipv4Addr::new(10, 100, 2, 2)),
        ] {
            let reply = ask(addr, &query_bytes(1, name, dns::TYPE_A))
                .await
                .expect("an answer");
            let parsed = Parsed::of(&reply);
            assert!(parsed.is_authoritative(), "{name} on {addr}");
            assert_eq!(parsed.ancount, 1, "{name} on {addr}");
            assert_eq!(parsed.a_records(name), vec![expected], "{name} on {addr}");
        }
    }

    // And a name on neither network is still an honest NXDOMAIN: the search
    // widened, the denial did not go away.
    let reply = ask(
        server.local_addrs()[0],
        &query_bytes(2, "nowhere", dns::TYPE_A),
    )
    .await
    .expect("an answer");
    assert_eq!(Parsed::of(&reply).rcode(), 3, "NXDOMAIN");

    shutdown.cancel();
    server.join().await;
}

#[tokio::test]
async fn a_name_on_two_of_the_tasks_networks_answers_from_the_first_attached() {
    // Two services called `web`, one per network, and a task on both. The
    // answer is the first network in the task's attachment order — all of it,
    // and only it: merging the two would round-robin one task's traffic across
    // two different services.
    let (front, back) = (network(4), network(5));
    let table = EndpointTable::new();
    table.update([
        EndpointRecord::new(
            front.clone(),
            "web",
            "web.1.aaa",
            vec![v4(10, 100, 4, 1)],
            TaskState::Running,
        ),
        EndpointRecord::new(
            back.clone(),
            "web",
            "web.1.bbb",
            vec![v4(10, 100, 5, 1)],
            TaskState::Running,
        ),
    ]);

    for (order, expected) in [
        (
            vec![front.clone(), back.clone()],
            Ipv4Addr::new(10, 100, 4, 1),
        ),
        (
            vec![back.clone(), front.clone()],
            Ipv4Addr::new(10, 100, 5, 1),
        ),
    ] {
        let shutdown = CancellationToken::new();
        let server = DnsServer::bind(
            vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
            table.clone(),
            scoped_loopback(2, order.clone()),
            Upstream::none(),
            shutdown.clone(),
        )
        .await
        .expect("bind");
        let reply = ask(server.local_addrs()[0], &query_bytes(1, "web", dns::TYPE_A))
            .await
            .expect("an answer");
        let parsed = Parsed::of(&reply);
        assert_eq!(parsed.ancount, 1, "exactly one service answers, not both");
        assert_eq!(parsed.a_records("web"), vec![expected], "{order:?}");
        shutdown.cancel();
        server.join().await;
    }
}

#[tokio::test]
async fn a_source_that_belongs_to_no_local_task_is_forwarded() {
    // The scope table knows an overlay address, not the loopback one the client
    // sends from. An unrecognised source must resolve *nothing* locally — it is
    // not this node's tenant — so the query goes upstream even though the name
    // is one we hold.
    let net = network(3);
    let table = EndpointTable::new();
    table.update([EndpointRecord::new(
        net.clone(),
        "web",
        "web.1.aaa",
        vec![v4(10, 100, 3, 1)],
        TaskState::Running,
    )]);
    let scopes = ScopeTable::new();
    scopes.update([TaskScope::new(task(3), vec![v4(10, 100, 3, 1)], vec![net])]);

    let stub = Stub::spawn(StubBehavior::Answer).await;
    let shutdown = CancellationToken::new();
    let server = DnsServer::bind(
        vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
        table,
        scopes,
        Upstream::new(vec![stub.addr]),
        shutdown.clone(),
    )
    .await
    .expect("bind");
    let addr = server.local_addrs()[0];

    let query = query_bytes(1, "web", dns::TYPE_A);
    let reply = ask(addr, &query).await.expect("a relayed answer");
    assert_eq!(
        stub.queries(),
        vec![query.clone()],
        "forwarded, not answered"
    );
    assert_eq!(reply, canned_answer(&query), "relayed byte for byte");
    assert!(
        !Parsed::of(&reply).is_authoritative(),
        "the upstream's answer, not ours"
    );
    assert_eq!(server.stats().answered, 0);
    assert_eq!(server.stats().forwarded, 1);

    shutdown.cancel();
    server.join().await;
}

#[tokio::test]
async fn an_oversized_answer_set_comes_back_truncated() {
    let fixture = Fixture::start(Upstream::none(), |_| {}).await;
    let records: Vec<EndpointRecord> = (1..=60_u8)
        .map(|slot| running(&fixture.network, slot, v4(10, 100, 9, slot)))
        .collect();
    fixture.table.update(records);

    let reply = ask(fixture.addr, &query_bytes(0x6060, "web", dns::TYPE_A))
        .await
        .expect("an answer");
    let parsed = Parsed::of(&reply);
    assert!(reply.len() <= 512, "{} bytes on the wire", reply.len());
    assert_ne!(parsed.flags & 0x0200, 0, "TC set");
    // 12 header + 9 question, 16 bytes per record.
    assert_eq!(parsed.ancount, u16::try_from((512 - 21) / 16).unwrap());
    let addresses = parsed.a_records("web");
    assert_eq!(addresses.len(), usize::from(parsed.ancount));
    assert_eq!(
        addresses.iter().collect::<BTreeSet<_>>().len(),
        addresses.len(),
        "no duplicates in a truncated set"
    );
    fixture.stop().await;
}

/// A third-party resolver's opinion of our packets.
///
/// Hand-built queries prove we answer *our* codec; `drill`(1) — ldns, a
/// parser none of this code wrote — proves the bytes are DNS. Unprivileged
/// (ephemeral loopback port), but `#[ignore]`-gated because it needs
/// `dns/ldns` installed, so `make check` never depends on it:
///
/// ```sh
/// cargo test -p satl-overlay --test dns_responder -- --ignored
/// ```
#[tokio::test]
#[ignore = "needs drill(1) from dns/ldns; run via make integration"]
async fn a_real_resolver_client_accepts_our_answers() {
    let fixture = Fixture::start(Upstream::none(), |_| {}).await;
    fixture.table.update([
        running(&fixture.network, 1, v4(10, 100, 0, 11)),
        running(&fixture.network, 2, v4(10, 100, 0, 12)),
    ]);
    let port = fixture.addr.port();

    let service = drill(port, "web", "A").await;
    assert!(service.contains("rcode: NOERROR"), "{service}");
    assert!(service.contains("ANSWER: 2"), "{service}");
    assert!(service.contains("10.100.0.11"), "{service}");
    assert!(service.contains("10.100.0.12"), "{service}");
    assert!(service.contains(" aa "), "AA flag missing: {service}");

    let aaaa = drill(port, "web", "AAAA").await;
    assert!(aaaa.contains("rcode: NOERROR"), "{aaaa}");
    assert!(aaaa.contains("ANSWER: 0"), "{aaaa}");

    let unknown = drill(port, "nothing-here", "A").await;
    assert!(unknown.contains("rcode: NXDOMAIN"), "{unknown}");

    fixture.stop().await;
}

/// Runs `drill -p <port> <name> @127.0.0.1 <type>` and returns its output.
async fn drill(port: u16, name: &str, qtype: &str) -> String {
    let args = vec![
        "-p".to_owned(),
        port.to_string(),
        name.to_owned(),
        "@127.0.0.1".to_owned(),
        qtype.to_owned(),
    ];
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("drill").args(&args).output()
    })
    .await
    .expect("join")
    .expect("drill is installed (pkg install ldns)");
    String::from_utf8_lossy(&output.stdout).into_owned()
}
