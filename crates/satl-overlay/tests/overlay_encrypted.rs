// SPDX-License-Identifier: BSD-2-Clause
//! Root integration tests for the ENCRYPTED overlay data plane
//! (`make integration`, M6 `--opt encrypted`).
//!
//! All `#[ignore]`-gated: they create real vxlan interfaces, bridges, epairs
//! and VNET jails and program the real SAD/SPD through `setkey`, so they need
//! root on FreeBSD. Same discipline as `overlay_dataplane.rs`: everything is
//! prefixed `ovtest-`, the overlay uses `10.79.0.0/24`, and every test ends
//! with a leftovers audit — which here also covers the SAD and SPD.
//!
//! # The single-host nuance (why there is no two-VTEP traffic test)
//!
//! `overlay_dataplane.rs` proves VXLAN traffic only in its two-node tests;
//! this file's ESP proof has the same boundary, and it is structural, not a
//! shortcut. Two VTEPs carrying traffic *between each other on one host* is
//! impossible under the production model SatL programs:
//!
//! - one UDP socket serves one (local address, port) pair, and a VNI exists
//!   once per socket ("network identifier already exists in this socket"), so
//!   the two VTEPs of one network cannot share the host's socket;
//! - SatL sets `vxlanlocalport` == `vxlanremoteport` (the network's
//!   allocator-assigned port), so a VTEP on a scratch port sends to its *own*
//!   socket — there is no second port for a second VTEP to listen on;
//! - and even a hand-built asymmetric pair would hairpin through one socket,
//!   a path no deployment uses.
//!
//! What a single host CAN prove, and this file does:
//!
//! - the VTEP comes up `RUNNING` on a scratch port from the encrypted range
//!   with the measured encrypted MTU (1416 = 1500 - 84), and jails on its
//!   bridge exchange traffic with that MTU exact at the DF boundary;
//! - `plan_security` + `Ipsec::apply` program the real SAD/SPD, walk a whole
//!   key rotation (append -> promote -> prune) with the measured
//!   adds-before-deletes order, reconcile idempotently, and leave the SAD/SPD
//!   empty on teardown;
//! - the outbound SP really encrypts: a UDP datagram matching the SP selector
//!   is ESP-transformed by the kernel, moving the SA's byte counter. The
//!   cross-node wire proof (ESP proto 50 on the underlay, zero cleartext, the
//!   pf guard dropping cleartext) is the cluster scenario's job
//!   (`tests/cluster/run.sh`), exactly as the two-node tests of
//!   `overlay_dataplane.rs` are the only VXLAN-traffic proof there.
//!
//! The fake peer `10.79.99.1` is deliberately inside this file's test
//! namespace and NOT the cluster underlay (10.2.0.0/16): the ESP probe's one
//! datagram leaves towards the default gateway and dies there, rather than
//! being sprayed at a real VM.

use std::net::Ipv4Addr;
use std::process::Command;

use satl_core::NetworkKey;
use satl_overlay::{
    Ipsec, PeerSecurity, PortSelector, PresentSecurity, SecurityAssociation, SecurityOp, VtepSpec,
    Vxlan, desired_sp, inbound_spi, outbound_spi, overlay_mtu_v4_encrypted, plan_security,
};

// ---------------------------------------------------------------------------
// Test namespace
// ---------------------------------------------------------------------------

const PREFIX: &str = "ovtest-";
const VTEP: &str = "ovtest-vx0";
const BRIDGE: &str = "ovtest-br0";
const JAIL_A: &str = "ovtest-j0";
const JAIL_B: &str = "ovtest-j1";
const EPAIR_A: [&str; 2] = ["ovtest-e0a", "ovtest-e0b"];
const EPAIR_B: [&str; 2] = ["ovtest-e1a", "ovtest-e1b"];
/// Deliberately outside every SatL pool, and not one of `overlay_dataplane`'s.
const VNI: u32 = 4_194_301;
/// A scratch port from the encrypted range (4790..=4999): the top of it,
/// which the allocator reaches last.
const PORT: u16 = 4999;
/// This node's VTEP address in these tests (loopback — no real underlay).
const ME: Ipv4Addr = Ipv4Addr::LOCALHOST;
/// The fake remote VTEP: in the test namespace, not the cluster underlay.
const PEER: Ipv4Addr = Ipv4Addr::new(10, 79, 99, 1);
/// The measured encrypted overlay MTU (1500 - 84; experiment Q4).
const ENCRYPTED_MTU: u32 = 1416;

/// Keyring tags, distinct from every fixture's.
const TAG_1: u32 = 0x0e77_0001;
const TAG_2: u32 = 0x0e77_0002;

fn is_root() -> bool {
    let out = Command::new("/usr/bin/id").arg("-u").output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim() == "0"
}

fn run(program: &str, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("could not run {program} {args:?}: {err}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn must(program: &str, args: &[&str]) -> String {
    let (ok, stdout, stderr) = run(program, args);
    assert!(ok, "{program} {args:?} failed: {stdout}{stderr}");
    stdout
}

fn ifconfig(args: &[&str]) -> String {
    must("/sbin/ifconfig", args)
}

/// Destroys every `ovtest-` interface and jail on drop, in the order that
/// works: jails first, so the epair `b` ends they hold return to the host.
/// Also sweeps this test's SAD/SPD entries: they are kernel state, not
/// namespace objects, and a panicking test must not strand them. Identical
/// discipline to `overlay_dataplane.rs`'s guard.
struct Namespace;

impl Namespace {
    fn fresh() -> Self {
        Self::nuke();
        Self
    }

    fn nuke() {
        let (_, jails, _) = run("/usr/sbin/jls", &["name"]);
        for jail in jails.split_whitespace().filter(|j| j.starts_with(PREFIX)) {
            let _ = Command::new("/usr/sbin/jail").args(["-r", jail]).output();
        }
        for _ in 0..2 {
            let (_, list, _) = run("/sbin/ifconfig", &["-l"]);
            for iface in list.split_whitespace().filter(|i| i.starts_with(PREFIX)) {
                let _ = Command::new("/sbin/ifconfig")
                    .args([iface, "destroy"])
                    .output();
            }
        }
        // Best effort: an interrupted run leaves this test's SAs/SPs behind.
        let ipsec = Ipsec::system();
        let plan = plan_security(ME, &[], &present_filtered(&ipsec));
        let _ = tokio_block(ipsec.apply(&plan));
    }

    /// Tear the namespace down and audit it — what every test ends with.
    fn finish(self) {
        drop(self);
        Self::audit();
    }

    fn audit() {
        let (_, list, _) = run("/sbin/ifconfig", &["-l"]);
        let stray: Vec<&str> = list
            .split_whitespace()
            .filter(|i| i.starts_with(PREFIX))
            .collect();
        assert!(stray.is_empty(), "leftover interfaces: {stray:?}");

        let (_, jails, _) = run("/usr/sbin/jls", &["name"]);
        let stray: Vec<&str> = jails
            .split_whitespace()
            .filter(|j| j.starts_with(PREFIX))
            .collect();
        assert!(stray.is_empty(), "leftover jails: {stray:?}");

        // Kernel state is not a namespace object, so the audit covers it too:
        // this test's (peer, port) view of the SAD/SPD must be empty.
        let left = present_filtered(&Ipsec::system());
        assert!(
            left.sas.is_empty() && left.sps.is_empty(),
            "leftover SAD/SPD entries for {PEER}/{PORT}: {left:?}"
        );
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        Self::nuke();
    }
}

/// These tests are synchronous; the wrappers are async. One current-thread
/// runtime per call keeps the test bodies linear.
fn tokio_block<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

// ---------------------------------------------------------------------------
// The IPsec half: filtered views and the SA byte counters
// ---------------------------------------------------------------------------

/// The kernel state **for this test's (peer, port) only**.
///
/// `plan_security` plans to delete anything present that is not desired, so
/// feeding it the whole SAD/SPD on a shared host would tear down entries of a
/// live satld. The tests reconcile against the filtered view — which is also
/// exactly the view the audit needs.
fn present_filtered(ipsec: &Ipsec) -> PresentSecurity {
    let sas = tokio_block(ipsec.sas())
        .expect("setkey -D")
        .into_iter()
        .filter(|sa| sa.src == PEER || sa.dst == PEER)
        .collect();
    let sps = tokio_block(ipsec.sps())
        .expect("setkey -DP")
        .into_iter()
        .filter(|sp| {
            sp.src == PEER
                || sp.dst == PEER
                || sp.src_port == PortSelector::Port(PORT)
                || sp.dst_port == PortSelector::Port(PORT)
        })
        .collect();
    PresentSecurity { sas, sps }
}

/// Remove everything this test could have left behind (a crashed previous
/// run): plan from an empty desire against the filtered present.
fn sweep(ipsec: &Ipsec) {
    let plan = plan_security(ME, &[], &present_filtered(ipsec));
    tokio_block(ipsec.apply(&plan)).expect("the sweep plan applies");
    let left = present_filtered(ipsec);
    assert!(
        left.sas.is_empty() && left.sps.is_empty(),
        "SAD/SPD entries for {PEER}/{PORT} survived the sweep: {left:?}"
    );
}

/// The `current: <n>(bytes)` counters of every SA whose header is
/// `<src> <dst>`, keyed by SPI — raw `setkey -D`, because the typed wrapper
/// deliberately keeps only the SA tuple.
fn sa_byte_counters(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<(u32, u64)> {
    let (_, dump, _) = run("/sbin/setkey", &["-D"]);
    let mut counters = Vec::new();
    let mut in_block = false;
    let mut spi = None;
    for line in dump.lines() {
        if line.starts_with(char::is_whitespace) {
            if in_block {
                let words: Vec<&str> = line.split_whitespace().collect();
                if let Some(field) = words.iter().find_map(|w| w.strip_prefix("spi="))
                    && let Some(open) = field.find("(0x")
                    && let Some(close) = field[open + 3..].find(')')
                {
                    spi = u32::from_str_radix(&field[open + 3..open + 3 + close], 16).ok();
                }
                // `current: 384(bytes)` — the value is the word AFTER the
                // bare `current:` token.
                if let Some(pos) = words.iter().position(|w| *w == "current:")
                    && let Some(bytes) = words
                        .get(pos + 1)
                        .and_then(|w| w.strip_suffix("(bytes)"))
                        .and_then(|n| n.parse::<u64>().ok())
                    && let Some(spi) = spi
                {
                    counters.push((spi, bytes));
                }
            }
            continue;
        }
        in_block = line.trim() == format!("{src} {dst}");
        spi = None;
    }
    counters
}

// ---------------------------------------------------------------------------
// Keys and helpers
// ---------------------------------------------------------------------------

/// A deterministic key for hand-built rings (same shape as the keyring
/// tests').
fn key(tag: u32, primary: bool) -> NetworkKey {
    let mut bytes = [0_u8; 16];
    bytes[..4].copy_from_slice(&tag.to_be_bytes());
    NetworkKey {
        tag,
        key: bytes,
        primary,
    }
}

fn sa(src: Ipv4Addr, dst: Ipv4Addr, spi: u32) -> SecurityAssociation {
    SecurityAssociation { src, dst, spi }
}

/// The SA tuples of one ring towards PEER: inbound for every key, outbound
/// for the primary.
fn inbound(tag: u32) -> SecurityAssociation {
    sa(PEER, ME, inbound_spi(ME, tag, PEER))
}

fn outbound(tag: u32) -> SecurityAssociation {
    sa(ME, PEER, outbound_spi(ME, tag, PEER))
}

/// `jexec <jail> ping -c <count> -D -s <size> -t 10 <target>`.
fn jail_ping(jail: &str, target: Ipv4Addr, size: u32, count: u32) -> (bool, String) {
    let (ok, stdout, stderr) = run(
        "/usr/sbin/jexec",
        &[
            jail,
            "ping",
            "-c",
            &count.to_string(),
            "-D",
            "-s",
            &size.to_string(),
            "-t",
            "10",
            &target.to_string(),
        ],
    );
    (ok, format!("{stdout}{stderr}"))
}

// ---------------------------------------------------------------------------
// 1. The encrypted VTEP: scratch port, measured MTU, jails exchanging traffic
// ---------------------------------------------------------------------------

/// Bring up the VTEP, its bridge, and two `path=/` VNET jails on it. The
/// bridge and epairs belong to `satl-net` in production; they are built here
/// with raw commands, exactly as `overlay_dataplane.rs` does.
fn encrypted_overlay_up(vxlan: &Vxlan) {
    let spec = VtepSpec::new(VNI, ME, Ipv4Addr::new(127, 0, 0, 254))
        .with_mtu(ENCRYPTED_MTU)
        .with_vxlan_port(PORT);
    tokio_block(vxlan.ensure_vtep(&spec, VTEP, "ovtestenc")).expect("VTEP must come up");

    let clone = ifconfig(&["bridge", "create"]);
    ifconfig(&[clone.trim(), "name", BRIDGE]);
    ifconfig(&[BRIDGE, "addm", VTEP]);
    ifconfig(&[BRIDGE, "mtu", &ENCRYPTED_MTU.to_string()]);
    ifconfig(&[BRIDGE, "up"]);

    for (jail, epair, addr) in [
        (JAIL_A, EPAIR_A, Ipv4Addr::new(10, 79, 0, 11)),
        (JAIL_B, EPAIR_B, Ipv4Addr::new(10, 79, 0, 12)),
    ] {
        let clone = ifconfig(&["epair", "create"]);
        let stem = clone.trim().trim_end_matches('a');
        ifconfig(&[clone.trim(), "name", epair[0]]);
        ifconfig(&[&format!("{stem}b"), "name", epair[1]]);
        ifconfig(&[BRIDGE, "addm", epair[0]]);
        ifconfig(&[epair[0], "up"]);
        must(
            "/usr/sbin/jail",
            &[
                "-c",
                &format!("name={jail}"),
                &format!("host.hostname={jail}"),
                "vnet=new",
                "persist",
                "path=/",
                "allow.raw_sockets",
            ],
        );
        ifconfig(&[epair[1], "vnet", jail]);
        must("/usr/sbin/jexec", &[jail, "ifconfig", "lo0", "up"]);
        must(
            "/usr/sbin/jexec",
            &[
                jail,
                "ifconfig",
                epair[1],
                "inet",
                &format!("{addr}/24"),
                "mtu",
                &ENCRYPTED_MTU.to_string(),
                "up",
            ],
        );
    }
}

#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn an_encrypted_vtep_gets_the_measured_mtu_and_port_and_carries_local_traffic() {
    assert!(is_root(), "must run as root");
    let namespace = Namespace::fresh();
    let vxlan = Vxlan::system();
    tokio_block(vxlan.ensure_module()).expect("if_vxlan must be loadable");

    // The constant pins the measured 84-byte overhead (experiment Q4):
    // 50 VXLAN (including the inner Ethernet header) + 34 ESP.
    assert_eq!(overlay_mtu_v4_encrypted(1500), ENCRYPTED_MTU);
    assert_eq!(satl_overlay::DEFAULT_OVERLAY_MTU_ENCRYPTED, ENCRYPTED_MTU);

    encrypted_overlay_up(&vxlan);

    let flags = tokio_block(vxlan.verify_running(VTEP)).expect("must be RUNNING");
    assert!(flags.is_up() && flags.is_running(), "{flags:?}");
    assert_eq!(
        flags.mtu, ENCRYPTED_MTU,
        "the encrypted MTU, set explicitly"
    );

    // The scratch port is on the interface, both ends (read back through the
    // ifconfig parser, not assumed from the spec).
    let config = tokio_block(vxlan.vtep_config(VTEP))
        .expect("show")
        .expect("a vxlan line");
    assert_eq!(config.local.map(|(_, port)| port), Some(PORT));
    assert_eq!(config.remote.map(|(_, port)| port), Some(PORT));

    // Two jails on the bridge exchange traffic: ARP resolves through the
    // bridge alone (the VTEP's blackhole remote is irrelevant to local
    // forwarding), so this is plumbing, not tunnel proof.
    let (ok, output) = jail_ping(JAIL_A, Ipv4Addr::new(10, 79, 0, 12), 56, 3);
    assert!(ok, "jail-to-jail ping on the bridge failed:\n{output}");

    // The MTU is exact at the DF boundary: 1388 + 28 = 1416 crosses, one
    // byte more is refused locally (docs/vxlan.md section 6's check, here
    // against the encrypted 1416 rather than the cleartext 1450).
    let (ok, output) = jail_ping(JAIL_A, Ipv4Addr::new(10, 79, 0, 12), 1388, 2);
    assert!(ok, "1388-byte DF ping must cross at MTU 1416:\n{output}");
    let (ok, output) = jail_ping(JAIL_A, Ipv4Addr::new(10, 79, 0, 12), 1389, 1);
    assert!(
        !ok && output.contains("Message too long"),
        "1389 bytes must be refused locally at MTU 1416:\n{output}"
    );

    namespace.finish();
}

// ---------------------------------------------------------------------------
// 2. plan_security + Ipsec::apply against the real SAD/SPD: a whole rotation
// ---------------------------------------------------------------------------

/// The pass every phase reconciles through: plan from the ring against the
/// filtered kernel view, apply, assert idempotence, and return what was
/// planned.
fn reconcile(ipsec: &Ipsec, keys: Vec<NetworkKey>) -> Vec<SecurityOp> {
    let desired = [PeerSecurity {
        peer: PEER,
        port: PORT,
        keys,
    }];
    let plan = plan_security(ME, &desired, &present_filtered(ipsec));
    tokio_block(ipsec.apply(&plan)).expect("the plan applies");
    // The pass is idempotent by construction: re-planning against the state
    // it just left must find nothing.
    let again = plan_security(ME, &desired, &present_filtered(ipsec));
    assert!(again.is_empty(), "not idempotent: {again:?}");
    plan.ops
}

#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn plan_security_walks_a_full_rotation_against_the_real_kernel() {
    assert!(is_root(), "must run as root");
    let namespace = Namespace::fresh();
    let ipsec = Ipsec::system();
    sweep(&ipsec);

    let sp = desired_sp(ME, PEER, PORT);

    // --- generate: inbound + outbound SA for the first key, one SP.
    let ops = reconcile(&ipsec, vec![key(TAG_1, true)]);
    assert_eq!(
        ops,
        vec![
            SecurityOp::AddSa {
                sa: inbound(TAG_1),
                key: key(TAG_1, true).key,
            },
            SecurityOp::AddSa {
                sa: outbound(TAG_1),
                key: key(TAG_1, true).key,
            },
            SecurityOp::AddSp(sp.clone()),
        ],
        "the first pass installs the whole shape, adds only"
    );
    let present = present_filtered(&ipsec);
    assert_eq!(present.sas.len(), 2, "{:?}", present.sas);
    assert_eq!(present.sps, vec![sp.clone()]);

    // --- the outbound path really encrypts: a UDP datagram matching the SP
    // selector (<me>[any] -> <peer>[<port>] udp) is ESP-transformed by the
    // kernel and the SA's byte counter moves. This is the single-host ESP
    // proof; the wire proof is two-node by nature (module docs).
    let sock = std::net::UdpSocket::bind((ME, 0u16)).expect("bind the probe socket");
    let payload = [0x5a_u8; 64];
    for _ in 0..3 {
        sock.send_to(&payload, (PEER, PORT))
            .expect("send the probe");
    }
    let counters = sa_byte_counters(ME, PEER);
    let outbound_bytes: u64 = counters
        .iter()
        .find(|(spi, _)| *spi == outbound_spi(ME, TAG_1, PEER))
        .map_or_else(
            || panic!("no byte counter for the outbound SA: {counters:?}"),
            |(_, bytes)| *bytes,
        );
    assert!(
        outbound_bytes > 0,
        "the outbound SA's byte counter did not move: the SP did not encrypt \
         our probe datagrams ({counters:?})"
    );

    // --- append: the ring gains a reception-only key; the plan adds its
    // inbound SA and touches nothing else (rotation phase 1, experiment Q6).
    let ops = reconcile(&ipsec, vec![key(TAG_1, true), key(TAG_2, false)]);
    assert_eq!(
        ops,
        vec![SecurityOp::AddSa {
            sa: inbound(TAG_2),
            key: key(TAG_2, false).key,
        }],
        "an append adds the new inbound SA only"
    );
    assert_eq!(present_filtered(&ipsec).sas.len(), 3);

    // --- promote: emission moves to the new key. The plan's order IS the
    // measured protocol (experiment Q6): the new outbound SA is added BEFORE
    // the old one is deleted, and the delete is what switches the SPI.
    let ops = reconcile(&ipsec, vec![key(TAG_1, false), key(TAG_2, true)]);
    assert_eq!(
        ops,
        vec![
            SecurityOp::AddSa {
                sa: outbound(TAG_2),
                key: key(TAG_2, true).key,
            },
            SecurityOp::RemoveSa(outbound(TAG_1)),
        ],
        "adds before deletes — the delete is the promoting step"
    );
    let present = present_filtered(&ipsec);
    assert!(
        present.sas.contains(&outbound(TAG_2)) && !present.sas.contains(&outbound(TAG_1)),
        "{:?}",
        present.sas
    );

    // --- prune: the old key's inbound SA goes; the ring is primary-only and
    // the SAD holds exactly the new key's pair.
    let ops = reconcile(&ipsec, vec![key(TAG_2, true)]);
    assert_eq!(ops, vec![SecurityOp::RemoveSa(inbound(TAG_1))]);
    let present = present_filtered(&ipsec);
    assert_eq!(present.sas.len(), 2, "{:?}", present.sas);
    assert!(present.sas.contains(&inbound(TAG_2)) && present.sas.contains(&outbound(TAG_2)));

    // --- teardown: an empty desire removes the SP before the SAs (no packet
    // outlives the SA it needs, module docs of plan_security) and leaves the
    // kernel empty of this test's entries.
    let plan = plan_security(ME, &[], &present_filtered(&ipsec));
    assert_eq!(
        plan.ops,
        vec![
            SecurityOp::RemoveSp(sp),
            SecurityOp::RemoveSa(inbound(TAG_2)),
            SecurityOp::RemoveSa(outbound(TAG_2)),
        ],
        "policies before associations on the way down"
    );
    tokio_block(ipsec.apply(&plan)).expect("teardown applies");
    let left = present_filtered(&ipsec);
    assert!(
        left.sas.is_empty() && left.sps.is_empty(),
        "teardown left entries behind: {left:?}"
    );

    namespace.finish();
}
