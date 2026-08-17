// SPDX-License-Identifier: BSD-2-Clause
//! Root integration tests for the overlay data plane (`make integration`).
//!
//! All `#[ignore]`-gated: they create real vxlan interfaces, bridges, epairs
//! and VNET jails, and issue the driver ioctl, so they need root on FreeBSD.
//! Everything is prefixed `ovtest-` (never the production `satl-vx*` names),
//! uses `10.79.0.0/24` for the overlay (never the production `10.100.0.0/14`
//! or `satl-net`'s `10.88.0.0/16`), and cleans up through RAII guards; every
//! test ends with a leftovers audit.
//!
//! The single-host tests run anywhere, including the dev host next to a live
//! `satld` — they only ever touch `ovtest-`-prefixed objects, and the VTEPs
//! they create bind `127.0.0.1:4789`, which no real overlay uses.
//!
//! # The multi-node test
//!
//! Two tests, one per role, both skipped unless `SATL_OVERLAY_PEER_*` is set.
//! [`two_node_overlay_holds_a_side_for_a_peer`] brings a side up and keeps it
//! there; [`two_node_overlay_is_carried_by_the_fdb`] does the asserting,
//! including the destructive step. They are separate roles because the active
//! side deletes an FDB entry and demands 100 % loss — if both sides did that at
//! once, each would see the other's outage and prove nothing.
//!
//! Both binaries are the same: build once and copy it to both nodes (the dev
//! host and the VMs are the same FreeBSD 15.1 amd64 ABI).
//!
//! ```sh
//! cargo test -p satl-overlay --test overlay_dataplane --no-run
//! # passive node first, then the active one, each with its own addresses:
//! sudo env SATL_OVERLAY_LOCAL_VTEP=10.2.1.50 SATL_OVERLAY_PEER_VTEP=10.2.2.47 \
//!          SATL_OVERLAY_LOCAL_IP=10.79.0.12 SATL_OVERLAY_PEER_IP=10.79.0.11  \
//!          SATL_OVERLAY_BLACKHOLE=10.2.255.254 SATL_OVERLAY_UNDERLAY_MTU=1500 \
//!          SATL_OVERLAY_HOLD_SECS=180 \
//!      ./overlay_dataplane-<hash> --ignored --exact \
//!      two_node_overlay_holds_a_side_for_a_peer --nocapture
//! ```
//!
//! The blackhole default remote is not optional here: with it pointed at the
//! peer, a *missing* FDB entry would work anyway and the test would prove
//! nothing (`docs/vxlan.md` §2 point 4).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::{Duration, Instant};

use satl_core::MacAddr;
use satl_overlay::{
    Arp, ArpBatch, ArpHelper, DesiredOverlay, FlushScope, Ftable, FtableEntry, FtableOps,
    FtableReader, JailArp, LocalEndpoint, OverlayDelta, Programmer, RemoteEndpoint, SystemRunner,
    VtepSpec, Vxlan, VxlanError, overlay_mtu_v4,
};

// ---------------------------------------------------------------------------
// Test namespace
// ---------------------------------------------------------------------------

const PREFIX: &str = "ovtest-";
const VTEP: &str = "ovtest-vx0";
const VTEP_DUP: &str = "ovtest-vxdup";
const BRIDGE: &str = "ovtest-br0";
const EPAIR_A: &str = "ovtest-ep0a";
const EPAIR_B: &str = "ovtest-ep0b";
const JAIL: &str = "ovtest-j0";
/// Deliberately outside every SatL pool.
const VNI: u32 = 4_194_303;
const VNI_OTHER: u32 = 4_194_302;
const OVERLAY_MTU: u32 = 1450;
/// Full-size frames sent in the bulk fragmentation probe.
const BULK: u32 = 500;

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
/// works: jails first, so the epair `b` ends they hold return to the host and
/// become destroyable, then interfaces twice (destroying a bridge can expose
/// members).
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
    }

    /// Tear the namespace down and audit it — what every test ends with.
    ///
    /// The audit has to run *after* teardown, so it cannot live in `Drop`
    /// (a failed assertion there would panic during unwind and mask the real
    /// failure). `Drop` still cleans up when a test panics early; it just does
    /// not assert.
    fn finish(self) {
        drop(self);
        Self::audit();
    }

    /// Nothing `ovtest-` may survive, and no vxlan interface may be left
    /// without a description (an un-renamed clone from an interrupted create).
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

        let (_, group, _) = run("/sbin/ifconfig", &["-g", "vxlan"]);
        for iface in group.split_whitespace() {
            let (_, show, _) = run("/sbin/ifconfig", &[iface]);
            assert!(
                show.contains("description:"),
                "vxlan interface {iface} has no description: an un-renamed \
                 clone leaked from a create/rename that was interrupted"
            );
        }
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        Self::nuke();
    }
}

fn ip(text: &str) -> Ipv4Addr {
    text.parse().expect("valid address")
}

/// The overlay MAC of an address, which is a pure function of it.
fn mac_of(text: &str) -> MacAddr {
    MacAddr::from_ipv4(ip(text))
}

/// A local-only VTEP spec: `vxlanlocal 127.0.0.1` and a blackhole remote on
/// the loopback net, so a single host can exercise the whole lifecycle without
/// touching any real network.
fn local_spec(vni: u32) -> VtepSpec {
    VtepSpec::new(vni, ip("127.0.0.1"), ip("127.0.0.254")).with_mtu(OVERLAY_MTU)
}

/// The last `count` lines of `/var/log/messages`, which is where `if_vxlan`
/// reports initialisation failures and nowhere else (CLAUDE.md).
fn recent_kernel_log(count: usize) -> String {
    let (_, text, _) = run(
        "/usr/bin/tail",
        &[&format!("-{count}"), "/var/log/messages"],
    );
    text
}

/// Wait for `needle` to appear in `/var/log/messages`.
///
/// Polling rather than a single `tail` because `syslogd` writes the kernel's
/// message a moment after the ioctl returns: a test that reads the log
/// immediately after `ifconfig up` regularly misses it. Any code that surfaces
/// these diagnostics to an operator has the same race.
fn wait_for_kernel_log(needle: &str, deadline: Duration) -> Result<(), String> {
    let start = Instant::now();
    loop {
        let log = recent_kernel_log(60);
        if log.contains(needle) {
            return Ok(());
        }
        if start.elapsed() >= deadline {
            return Err(format!(
                "{needle:?} never appeared in /var/log/messages within \
                 {deadline:?}; last lines:\n{log}"
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn ensure_module(vxlan: &Vxlan) {
    tokio_block(vxlan.ensure_module()).expect("if_vxlan must be loadable");
}

/// A programmer wired to the `jexec arp` mechanism.
///
/// These tests build `path=/` jails, so `jexec arp` works in them and keeps the
/// assertions readable. **A real task cannot use this path** — its rootfs is an
/// OCI image with no usable `arp`(8) — which is what
/// [`the_helper_programs_a_jail_with_no_arp_binary`] and
/// [`a_reconciliation_pass_through_the_helper_needs_nothing_in_the_jail`] cover.
type JexecProgrammer = Programmer<Ftable, Arp, SystemRunner>;

fn jexec_programmer() -> JexecProgrammer {
    Programmer::new(Ftable::new(), Arp::system(), FtableReader::system())
}

/// The child the helper tests spawn: the `satl-jail-arp` binary, which is one
/// call to the real `satl_overlay::child_main`.
///
/// `satld` re-executes *itself* with `satl_overlay::HELPER_SUBCOMMAND`; a test
/// binary cannot, because Cargo's harness parses argv before any test body runs.
/// That the program **and** the argv prefix are [`ArpHelper::new`] parameters
/// rather than a hardcoded `satld` is exactly what makes both possible, and this
/// test is the proof of it.
const HELPER_BIN: &str = env!("CARGO_BIN_EXE_satl-jail-arp");

/// An [`ArpHelper`] driving that binary, with no argv prefix at all.
fn test_helper() -> ArpHelper {
    ArpHelper::new(HELPER_BIN, Vec::<String>::new())
}

/// A programmer wired to the **production** ARP mechanism.
fn helper_programmer() -> Programmer<Ftable, ArpHelper, SystemRunner> {
    Programmer::new(Ftable::new(), test_helper(), FtableReader::system())
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
// 1. The interface lifecycle and the health signal
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn a_vtep_comes_up_running_and_a_duplicate_vni_is_reported_as_unhealthy() {
    assert!(is_root(), "must run as root");
    let namespace = Namespace::fresh();
    let vxlan = Vxlan::system();
    ensure_module(&vxlan);

    // --- the healthy interface.
    let iface = tokio_block(vxlan.ensure_vtep(&local_spec(VNI), VTEP, "ovtestnet"))
        .expect("VTEP must come up")
        .expect("a fresh create reports its clone unit");
    assert_eq!(iface.name, VTEP);

    let flags = tokio_block(vxlan.verify_running(VTEP)).expect("must be RUNNING");
    assert!(flags.is_up() && flags.is_running(), "{flags:?}");
    assert_eq!(flags.mtu, OVERLAY_MTU, "the MTU must be set explicitly");
    // The healthy flag word of docs/vxlan.md §2.
    assert_eq!(flags.raw, 0x0100_8843, "{}", flags.rendered());

    // The description is the ownership marker, and the driver's own group is
    // what enumerates candidates for the sweep.
    let owned = tokio_block(vxlan.list_owned()).expect("sweep");
    let entry = owned
        .iter()
        .find(|entry| entry.name == VTEP)
        .expect("our VTEP must be recognized as ours");
    assert_eq!(entry.network.as_deref(), Some("ovtestnet"));

    // GET_CONFIG agrees with what ifconfig printed, through the ioctl.
    let info = Ftable::new().config(VTEP).expect("GET_CONFIG");
    assert_eq!(info.vni, VNI);
    assert_eq!(info.remote.map(|addr| *addr.ip()), Some(ip("127.0.0.254")));
    assert!(!info.learn, "-vxlanlearn must be in effect");
    assert_eq!(info.ftable_count, 0);

    // --- the deliberately broken one: same VNI, same local address, same port.
    // The create succeeds (the socket does not exist yet) and so does the `up`.
    let broken = local_spec(VNI).with_mtu(OVERLAY_MTU);
    tokio_block(vxlan.create_vtep(&broken, VTEP_DUP)).expect("create must succeed");
    tokio_block(vxlan.set_descr(VTEP_DUP, "satl:vxlan:ovtestdup")).expect("descr");
    tokio_block(vxlan.up(VTEP_DUP)).expect("`ifconfig up` reports success even here");

    let err = tokio_block(vxlan.verify_running(VTEP_DUP))
        .expect_err("a duplicate VNI must be reported as unhealthy, not as success");
    assert!(matches!(err, VxlanError::NotRunning { .. }), "{err:?}");
    let text = err.to_string();
    assert!(text.contains("/var/log/messages"), "{text}");
    assert!(text.contains("1008803"), "{text}");

    // ...and the reason really is in the kernel log, as the error claims.
    wait_for_kernel_log(
        &format!("{VTEP_DUP}: network identifier {VNI} already exists in this socket"),
        Duration::from_secs(10),
    )
    .expect("the duplicate-VNI diagnostic must reach /var/log/messages");

    // A static FDB entry installs fine on the dead interface: programming is
    // not a health check (docs/vxlan.md §2 point 5).
    Ftable::new()
        .add(
            VTEP_DUP,
            FtableEntry::for_endpoint(ip("10.79.0.99"), ip("127.0.0.253")),
        )
        .expect("the FDB only needs the destination address family");

    tokio_block(vxlan.destroy(VTEP_DUP)).expect("destroy");
    tokio_block(vxlan.destroy(VTEP)).expect("destroy");
    assert!(!tokio_block(vxlan.exists(VTEP)).expect("probe"));
    namespace.finish();
}

#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn an_interface_with_no_remote_is_unhealthy_and_reports_1470() {
    assert!(is_root(), "must run as root");
    let namespace = Namespace::fresh();
    let vxlan = Vxlan::system();
    ensure_module(&vxlan);

    // The tidy design — no remote at all, every destination from the FDB — is
    // not available; this is what it looks like when tried.
    let clone = ifconfig(&[
        "vxlan",
        "create",
        "vxlanid",
        &VNI_OTHER.to_string(),
        "vxlanlocal",
        "127.0.0.1",
    ]);
    let clone = clone.trim();
    ifconfig(&[clone, "name", VTEP]);
    ifconfig(&[VTEP, "description", "satl:vxlan:ovtestnoremote"]);
    ifconfig(&[VTEP, "up"]);

    let vxlan = Vxlan::system();
    let flags = tokio_block(vxlan.flags(VTEP)).expect("flags");
    assert!(flags.is_up(), "ifconfig still says UP");
    assert!(!flags.is_running(), "but the driver refused it");
    // 1500 - 30: with no destination the driver cannot know whether to reserve
    // 20 bytes for IPv4 or 40 for IPv6 (docs/vxlan.md §1).
    assert_eq!(flags.mtu, 1470);

    let config = tokio_block(vxlan.vtep_config(VTEP))
        .expect("show")
        .expect("a vxlan line");
    assert_eq!(config.remote, None, "`remote :` must parse as absent");

    // And the FDB ioctl fails with EAFNOSUPPORT, which the error explains.
    let err = Ftable::new()
        .add(
            VTEP,
            FtableEntry::for_endpoint(ip("10.79.0.99"), ip("127.0.0.253")),
        )
        .expect_err("no destination address family to match");
    assert!(err.to_string().contains("vxlanremote"), "{err}");

    wait_for_kernel_log(
        &format!("{VTEP}: cannot initialize interface"),
        Duration::from_secs(10),
    )
    .expect("the missing-remote diagnostic must reach /var/log/messages");

    tokio_block(vxlan.destroy(VTEP)).expect("destroy");
    namespace.finish();
}

#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn adoption_refuses_an_interface_configured_differently() {
    assert!(is_root(), "must run as root");
    let namespace = Namespace::fresh();
    let vxlan = Vxlan::system();
    ensure_module(&vxlan);

    tokio_block(vxlan.ensure_vtep(&local_spec(VNI), VTEP, "ovtestnet")).expect("create");
    // Same name, different VNI: adopting it would blackhole every task on it.
    let err = tokio_block(vxlan.ensure_vtep(&local_spec(VNI_OTHER), VTEP, "ovtestnet"))
        .expect_err("a different VNI must not be silently adopted");
    assert!(err.to_string().contains("configured differently"), "{err}");
    // The matching spec adopts without creating anything.
    let created =
        tokio_block(vxlan.ensure_vtep(&local_spec(VNI), VTEP, "ovtestnet")).expect("adopt");
    assert!(created.is_none(), "adoption cannot know the clone unit");

    tokio_block(vxlan.destroy(VTEP)).expect("destroy");
    namespace.finish();
}

// ---------------------------------------------------------------------------
// 2. The forwarding table: install, read back, survive a flap, die on destroy
// ---------------------------------------------------------------------------

/// The dump sysctl silently stops at about 81 IPv4 entries, and the reconciler
/// has to notice and recover rather than diff against the fragment.
///
/// Measured ceiling (`hack/experiments/jail-arp/captures/40-ftable-dump-ceiling.txt`):
///
/// ```text
///  installed count(ioctl)   dump lines  dump bytes verdict
///         81         81            81        4052 ok
///         82         82            81        4052 TRUNCATED
///       2500       2500            81        4052 TRUNCATED
/// ```
#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn a_forwarding_table_too_big_for_the_dump_sysctl_is_flushed_and_repushed() {
    /// Comfortably past the ceiling, and a plausible size for one network on one
    /// node.
    const ENDPOINTS: u32 = 90;

    assert!(is_root(), "must run as root");
    let namespace = Namespace::fresh();
    let vxlan = Vxlan::system();
    let ftable = Ftable::new();
    let reader = FtableReader::system();
    ensure_module(&vxlan);

    let iface = tokio_block(vxlan.ensure_vtep(&local_spec(VNI), VTEP, "ovtestnet"))
        .expect("VTEP")
        .expect("clone unit");
    let unit = iface.unit;

    let endpoints: Vec<RemoteEndpoint> = (1..=ENDPOINTS)
        .map(|n| {
            RemoteEndpoint::new(
                Ipv4Addr::new(10, 79, 1, u8::try_from(n).expect("under 256")),
                ip("127.0.0.21"),
            )
        })
        .collect();
    for endpoint in &endpoints {
        ftable
            .add(VTEP, FtableEntry::for_endpoint(endpoint.ip, endpoint.vtep))
            .expect("add");
    }

    // --- the raw fact: the ioctl tells the truth, the dump does not, and the
    // dump gives no sign of it.
    let count = ftable.config(VTEP).expect("config").ftable_count;
    assert_eq!(count, ENDPOINTS);
    let rows = tokio_block(reader.dump(unit))
        .expect("dump")
        .expect("the unit exists")
        .len();
    assert!(
        rows < usize::try_from(count).expect("small"),
        "expected the dump to be truncated below {count}, got {rows}: the \
         ceiling moved, so the check in dump_verified needs re-measuring"
    );

    // --- and the checked read-back refuses it, naming both numbers.
    let err = tokio_block(reader.dump_verified(&ftable, VTEP, unit))
        .expect_err("a truncated read-back must not be returned as a table");
    assert!(err.is_dump_truncated(), "{err:?}");
    let text = err.to_string();
    assert!(text.contains(&format!("reports {count}")), "{text}");
    assert!(text.contains("flush it and re-push"), "{text}");

    // --- so the reconciler flushes and re-pushes, and says it did.
    let programmer = jexec_programmer();
    let desired = DesiredOverlay::new(VTEP, ip("127.0.0.1")).with_remote(endpoints.clone());
    let applied = tokio_block(programmer.reconcile(&desired, unit)).expect("reconcile");
    assert!(
        applied.ftable_flushed,
        "the pass must report that it could not read its own state: {applied:?}"
    );
    assert!(applied.is_complete(), "{:?}", applied.failures);
    assert_eq!(applied.ftable_added.len(), endpoints.len());
    assert!(applied.ftable_removed.is_empty(), "{applied:?}");

    // --- the kernel really holds the desired set, whatever the dump shows.
    assert_eq!(
        ftable.config(VTEP).expect("config").ftable_count,
        ENDPOINTS,
        "the flush-and-re-push must be lossless"
    );

    // --- and an unwanted entry is still removed, because the flush took it.
    ftable
        .add(
            VTEP,
            FtableEntry::for_endpoint(ip("10.79.9.99"), ip("127.0.0.99")),
        )
        .expect("add a stray");
    assert_eq!(
        ftable.config(VTEP).expect("config").ftable_count,
        ENDPOINTS + 1
    );
    let applied = tokio_block(programmer.reconcile(&desired, unit)).expect("reconcile");
    assert!(applied.ftable_flushed, "{applied:?}");
    assert_eq!(
        ftable.config(VTEP).expect("config").ftable_count,
        ENDPOINTS,
        "the stray must be gone"
    );

    // --- below the ceiling, nothing is flushed: this is not the normal path.
    let small = DesiredOverlay::new(VTEP, ip("127.0.0.1")).with_remote(endpoints[..3].to_vec());
    let applied = tokio_block(programmer.reconcile(&small, unit)).expect("reconcile");
    assert!(
        applied.ftable_flushed,
        "the pass that shrinks it still starts from a truncated read: {applied:?}"
    );
    let applied = tokio_block(programmer.reconcile(&small, unit)).expect("reconcile");
    assert!(
        !applied.ftable_flushed,
        "with three entries the dump is complete and the diff is used: {applied:?}"
    );
    assert!(
        applied.is_complete() && applied.ftable_added.is_empty(),
        "{applied:?}"
    );

    namespace.finish();
}

#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn ftable_entries_are_read_back_survive_a_flap_and_die_with_the_interface() {
    assert!(is_root(), "must run as root");
    let namespace = Namespace::fresh();
    let vxlan = Vxlan::system();
    let ftable = Ftable::new();
    let reader = FtableReader::system();
    ensure_module(&vxlan);

    let iface = tokio_block(vxlan.ensure_vtep(&local_spec(VNI), VTEP, "ovtestnet"))
        .expect("VTEP")
        .expect("clone unit");
    let unit = iface.unit;

    let entries = [
        FtableEntry::for_endpoint(ip("10.79.0.21"), ip("127.0.0.21")),
        FtableEntry::for_endpoint(ip("10.79.0.22"), ip("127.0.0.22")),
        FtableEntry::for_endpoint(ip("10.79.0.23"), ip("127.0.0.23")),
    ];
    for entry in entries {
        ftable.add(VTEP, entry).expect("add");
    }

    // Read-back one: the ioctl, by name — count only.
    assert_eq!(ftable.config(VTEP).expect("config").ftable_count, 3);
    // Read-back two: the dump sysctl, by clone unit — the entries themselves.
    let dumped = tokio_block(reader.dump(unit))
        .expect("dump")
        .expect("the unit exists");
    assert_eq!(dumped.len(), 3);
    for entry in entries {
        let record = dumped
            .get(&entry.mac)
            .unwrap_or_else(|| panic!("{entry} must be in the dump: {dumped:?}"));
        assert_eq!(record.entry, entry);
        assert!(record.is_static(), "everything we install is static");
    }

    // `add` on an existing MAC is EEXIST — the kernel does NOT overwrite,
    // whether or not the VTEP matches. `docs/vxlan.md` §7 says it replaces;
    // that is wrong, and `replace` (remove-then-add) exists because of it.
    let moved = FtableEntry {
        mac: entries[0].mac,
        vtep: ip("127.0.0.99"),
    };
    for entry in [entries[0], moved] {
        let err = ftable
            .add(VTEP, entry)
            .expect_err("FTABLE_ENTRY_ADD must refuse an existing MAC");
        assert!(err.is_already_exists(), "{err}");
    }
    assert!(
        ftable.replace(VTEP, moved).expect("replace"),
        "the previous entry must have been removed"
    );
    let dumped = tokio_block(reader.dump(unit)).expect("dump").expect("unit");
    assert_eq!(dumped.len(), 3, "a replace must not add a second entry");
    assert_eq!(dumped[&moved.mac].entry.vtep, ip("127.0.0.99"));

    // A flap keeps the table (docs/vxlan.md §3): only destroy loses it.
    tokio_block(vxlan.down(VTEP)).expect("down");
    tokio_block(vxlan.up(VTEP)).expect("up");
    tokio_block(vxlan.verify_running(VTEP)).expect("still RUNNING after a flap");
    assert_eq!(
        tokio_block(reader.dump(unit))
            .expect("dump")
            .expect("unit")
            .len(),
        3,
        "static entries must survive a down/up flap"
    );

    // Removing is idempotent: the second call is ENOENT, mapped to Ok(false).
    assert!(ftable.remove(VTEP, entries[1].mac).expect("remove"));
    assert!(
        !ftable.remove(VTEP, entries[1].mac).expect("remove again"),
        "an absent entry is the idempotent case, not an error"
    );
    assert_eq!(ftable.config(VTEP).expect("config").ftable_count, 2);

    // Plain flush touches dynamic entries only — and we have none.
    ftable.flush(VTEP, FlushScope::Dynamic).expect("flush");
    assert_eq!(
        ftable.config(VTEP).expect("config").ftable_count,
        2,
        "vxlanflush must not remove static entries"
    );
    // FlushScope::All does.
    ftable.flush(VTEP, FlushScope::All).expect("flush all");
    assert_eq!(ftable.config(VTEP).expect("config").ftable_count, 0);
    assert!(
        tokio_block(reader.dump(unit))
            .expect("dump")
            .expect("unit")
            .is_empty()
    );

    // `ifconfig <if> vxlanflushall` is the same operation without the ioctl —
    // the path a reconciler takes when it cannot read the table back and has
    // to start from a known-empty one.
    ftable.add(VTEP, entries[0]).expect("add");
    tokio_block(vxlan.flush_ftable(VTEP)).expect("vxlanflushall");
    assert_eq!(ftable.config(VTEP).expect("config").ftable_count, 0);

    // 2000 is a hard maximum rather than a raisable default (docs/vxlan.md §3
    // says otherwise). The wrapper refuses out-of-range values itself, so an
    // operator gets a reason instead of `Invalid argument`.
    //
    // It is NOT a limit on the static entries this crate installs: nothing on
    // the FTABLE_ENTRY_ADD path consults it with learning off, and
    // `ftable_nospace` never increments. See `satl_overlay::FTABLE_MAX`.
    let info = ftable.config(VTEP).expect("config");
    assert_eq!(info.ftable_max, satl_overlay::FTABLE_MAX);
    let err = tokio_block(vxlan.set_ftable_max(VTEP, satl_overlay::FTABLE_MAX + 1))
        .expect_err("above VXLAN_FTABLE_MAX must be refused");
    assert!(err.to_string().contains("hard ceiling"), "{err}");
    // Zero is refused by the *wrapper*; the kernel accepts it. A ceiling of zero
    // can only be a caller's arithmetic mistake, so it is caught here.
    assert!(
        tokio_block(vxlan.set_ftable_max(VTEP, 0)).is_err(),
        "the wrapper's own lower bound, not the kernel's"
    );
    tokio_block(vxlan.set_ftable_max(VTEP, 1000)).expect("lowering it works");
    assert_eq!(ftable.config(VTEP).expect("config").ftable_max, 1000);
    tokio_block(vxlan.set_ftable_max(VTEP, satl_overlay::FTABLE_MAX)).expect("back to the max");

    // Destroy takes the whole sysctl node with it, so a destroy/create cycle
    // needs a full re-push.
    tokio_block(vxlan.destroy(VTEP)).expect("destroy");
    assert!(
        tokio_block(reader.dump(unit)).expect("dump").is_none(),
        "the unit's sysctl node must be gone with the interface"
    );
    assert!(ftable.config(VTEP).is_err());
    namespace.finish();
}

#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn the_clone_unit_of_a_renamed_interface_can_be_recovered_by_probe() {
    assert!(is_root(), "must run as root");
    let namespace = Namespace::fresh();
    let vxlan = Vxlan::system();
    let ftable = Ftable::new();
    let reader = FtableReader::system();
    ensure_module(&vxlan);

    // Two interfaces, so a probe that matched any unit would be a false pass.
    let first = tokio_block(vxlan.ensure_vtep(&local_spec(VNI), VTEP, "ovtestnet"))
        .expect("VTEP")
        .expect("unit");
    let second = tokio_block(vxlan.ensure_vtep(&local_spec(VNI_OTHER), VTEP_DUP, "ovtestdup"))
        .expect("VTEP")
        .expect("unit");
    assert_ne!(
        first.unit, second.unit,
        "clone units are never recycled, so these must differ"
    );

    // This is the situation after a daemon restart: the name is known, the unit
    // is not, and no sysctl or ioctl maps one to the other.
    assert_eq!(
        tokio_block(reader.resolve_unit(&ftable, VTEP)).expect("probe"),
        first.unit
    );
    assert_eq!(
        tokio_block(reader.resolve_unit(&ftable, VTEP_DUP)).expect("probe"),
        second.unit
    );
    // The probe entry must not survive the probe.
    assert_eq!(ftable.config(VTEP).expect("config").ftable_count, 0);
    assert_eq!(ftable.config(VTEP_DUP).expect("config").ftable_count, 0);

    tokio_block(vxlan.destroy(VTEP)).expect("destroy");
    tokio_block(vxlan.destroy(VTEP_DUP)).expect("destroy");
    namespace.finish();
}

// ---------------------------------------------------------------------------
// 3. A whole node-local overlay, driven by the reconciler
// ---------------------------------------------------------------------------

/// Bring up the node-local half of an overlay: VTEP, bridge, epair, VNET jail.
/// The bridge and epair belong to `satl-net::NetworkManager` in production, so
/// they are built here with raw commands rather than by depending on it.
fn overlay_up(vxlan: &Vxlan, local_ip: Ipv4Addr, spec: &VtepSpec) -> u32 {
    let iface = tokio_block(vxlan.ensure_vtep(spec, VTEP, "ovtestnet"))
        .expect("VTEP must come up RUNNING")
        .expect("clone unit");

    // The bridge takes its MTU from its first member, then propagates it.
    let clone = ifconfig(&["bridge", "create"]);
    ifconfig(&[clone.trim(), "name", BRIDGE]);
    ifconfig(&[BRIDGE, "addm", VTEP]);
    ifconfig(&[BRIDGE, "mtu", &spec.mtu.to_string()]);
    ifconfig(&[BRIDGE, "up"]);

    let clone = ifconfig(&["epair", "create"]);
    let stem = clone.trim().trim_end_matches('a');
    ifconfig(&[clone.trim(), "name", EPAIR_A]);
    ifconfig(&[&format!("{stem}b"), "name", EPAIR_B]);
    // The deterministic MAC survives the vnet move, which is what makes the
    // FDB and ARP programmable with no read-back.
    ifconfig(&[EPAIR_B, "ether", &MacAddr::from_ipv4(local_ip).to_string()]);
    ifconfig(&[BRIDGE, "addm", EPAIR_A]);
    // Each end needs its own `up`: `addm <member> up` brings up the *bridge*.
    ifconfig(&[EPAIR_A, "up"]);

    must(
        "/usr/sbin/jail",
        &[
            "-c",
            &format!("name={JAIL}"),
            &format!("host.hostname={JAIL}"),
            "vnet=new",
            "persist",
            "path=/",
            "allow.raw_sockets",
        ],
    );
    ifconfig(&[EPAIR_B, "vnet", JAIL]);
    must("/usr/sbin/jexec", &[JAIL, "ifconfig", "lo0", "up"]);
    // The `b` end is not a bridge member, so nothing propagates its MTU.
    must(
        "/usr/sbin/jexec",
        &[
            JAIL,
            "ifconfig",
            EPAIR_B,
            "inet",
            &format!("{local_ip}/24"),
            "mtu",
            &spec.mtu.to_string(),
            "up",
        ],
    );
    iface.unit
}

/// Attach a **container-like** jail to the same bridge: `vnet=new`, its own
/// epair, and a rootfs that is an **empty directory**.
///
/// That last part is the whole point. A real task's rootfs is an OCI image, and
/// as far as ARP is concerned an OCI image is one of two things: a rootfs with no
/// `arp`(8) at all, or a Linux rootfs whose `arp` speaks Linux's ARP ABI under
/// the linuxulator. An empty directory reproduces the first exactly, and every
/// in-jail command therefore has to be `ifconfig -j` — `arp`(8) is the one tool
/// with no `-j`.
///
/// Returns the jail name and the name of its in-jail interface.
fn container_jail(local_ip: Ipv4Addr, mtu: u32, rootfs: &std::path::Path) -> (String, String) {
    let jail = format!("{PREFIX}jc");
    let epair_a = format!("{PREFIX}ec0a");
    let epair_b = format!("{PREFIX}ec0b");

    let clone = ifconfig(&["epair", "create"]);
    let stem = clone.trim().trim_end_matches('a');
    ifconfig(&[clone.trim(), "name", &epair_a]);
    ifconfig(&[&format!("{stem}b"), "name", &epair_b]);
    ifconfig(&[&epair_b, "ether", &MacAddr::from_ipv4(local_ip).to_string()]);
    ifconfig(&[BRIDGE, "addm", &epair_a]);
    ifconfig(&[&epair_a, "up"]);

    must(
        "/usr/sbin/jail",
        &[
            "-c",
            &format!("name={jail}"),
            &format!("host.hostname={jail}"),
            "vnet=new",
            "persist",
            &format!("path={}", rootfs.display()),
            "allow.raw_sockets",
        ],
    );
    ifconfig(&[&epair_b, "vnet", &jail]);
    // No binaries in there at all, so this is the only way in.
    ifconfig(&["-j", &jail, "lo0", "up"]);
    ifconfig(&[
        "-j",
        &jail,
        &epair_b,
        "inet",
        &format!("{local_ip}/24"),
        "mtu",
        &mtu.to_string(),
        "up",
    ]);
    (jail, epair_b)
}

/// `jls -j <jail> jid`, as a number.
fn jid_of(jail: &str) -> i32 {
    let out = must("/usr/sbin/jls", &["-j", jail, "jid"]);
    out.trim().parse().expect("jls printed a jid")
}

#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn arp_entries_land_in_the_jails_own_stack() {
    assert!(is_root(), "must run as root");
    let namespace = Namespace::fresh();
    let vxlan = Vxlan::system();
    ensure_module(&vxlan);
    let local_ip = ip("10.79.0.11");
    overlay_up(&vxlan, local_ip, &local_spec(VNI));

    let arp = Arp::system();
    let peer = ip("10.79.0.12");
    let peer_mac = MacAddr::from_ipv4(peer);
    tokio_block(arp.set(JAIL, peer, peer_mac)).expect("set");

    let entries = tokio_block(arp.list(JAIL)).expect("list");
    let entry = entries
        .iter()
        .find(|entry| entry.ip == peer)
        .expect("the entry must be in the jail's table");
    assert_eq!(entry.mac, Some(peer_mac));
    assert_eq!(entry.iface, EPAIR_B);
    assert!(entry.permanent, "static entries are permanent");
    assert!(entry.is_overlay_static());

    // The host's own table is a different stack and knows nothing about it.
    let (_, host_table, _) = run("/usr/sbin/arp", &["-an"]);
    assert!(
        !host_table.contains(&format!("({peer})")),
        "the entry must not be in the host's table: {host_table}"
    );

    // Ownership: the jail's own address looks exactly like one of ours, so
    // list_owned must exclude it by address.
    let owned = tokio_block(arp.list_owned(JAIL, &[local_ip])).expect("list_owned");
    assert_eq!(
        owned.iter().map(|entry| entry.ip).collect::<Vec<_>>(),
        [peer]
    );

    // Replacing works, so a changed MAC is never a delete plus an add.
    let other_mac = MacAddr::from_ipv4(ip("10.79.0.99"));
    tokio_block(arp.set(JAIL, peer, other_mac)).expect("replace");
    assert_eq!(
        tokio_block(arp.list(JAIL))
            .expect("list")
            .into_iter()
            .find(|entry| entry.ip == peer)
            .and_then(|entry| entry.mac),
        Some(other_mac)
    );

    // Deleting is idempotent.
    assert!(tokio_block(arp.delete(JAIL, peer)).expect("delete"));
    assert!(!tokio_block(arp.delete(JAIL, peer)).expect("delete again"));

    // And the exit-0 refusal is caught: 10.80.x is on no interface in there.
    let off_link = ip("10.80.0.5");
    let err = tokio_block(arp.set(JAIL, off_link, MacAddr::from_ipv4(off_link)))
        .expect_err("`arp -s` exits 0 on this and must still be an error");
    assert!(err.to_string().contains("on-link"), "{err}");

    namespace.finish();
}

// ---------------------------------------------------------------------------
// 3b. The mechanism a real task needs: no arp(8) in the jail at all
// ---------------------------------------------------------------------------

/// The child binary answers the protocol, and needs neither root nor a jail to
/// prove it.
///
/// Not `#[ignore]`d: it runs in `cargo test -p satl-overlay` and is the guard
/// against the parent and the child drifting apart, which is the one failure
/// mode a mocked test cannot catch.
#[test]
fn the_helper_child_binary_speaks_the_protocol() {
    // A jail name that resolves to nothing: the child answers, reports
    // `fatal attach` with ENOENT, and the parent turns that into the one error a
    // reconciler is allowed to treat as benign.
    let err = tokio_block(test_helper().run(&satl_overlay::Request::list("ovtest-no-such-jail")))
        .expect_err("attaching to a jail that does not exist cannot succeed");
    assert!(
        err.to_string().contains("ovtest-no-such-jail"),
        "the error must name the jail: {err}"
    );

    // The child's own view of the same thing, so the response shape is pinned
    // and not only the parent's interpretation of it.
    let raw = must_stdin(
        HELPER_BIN,
        &satl_overlay::render_request(&satl_overlay::Request::list("ovtest-no-such-jail")),
    );
    let response = satl_overlay::parse_response(&raw).expect("a well-formed response");
    assert_eq!(
        response.fatal.as_ref().map(|fatal| fatal.stage.clone()),
        Some("attach".to_owned())
    );
    assert!(response.table.is_empty(), "{response:?}");
    assert!(!response.is_complete());

    // A request from a different build is a loud failure on stderr and an empty
    // stdout, never a silent success: `parse_response` has no `end` line to find.
    let (code, stdout, stderr) = run_with_stdin(HELPER_BIN, "satl-arp-request 99\njail 1\n");
    assert_eq!(code, Some(1), "stderr was {stderr:?}");
    assert!(stdout.is_empty(), "{stdout:?}");
    assert!(stderr.contains("different builds of satld"), "{stderr:?}");
    assert!(satl_overlay::parse_response(&stdout).is_err());
}

/// Run `program`, feed it `stdin`, and return `(exit code, stdout, stderr)`.
fn run_with_stdin(program: &str, stdin: &str) -> (Option<i32>, String, String) {
    use std::io::Write as _;
    let mut child = Command::new(program)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("could not run {program}: {err}"));
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(stdin.as_bytes())
        .expect("write the request");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// [`run_with_stdin`], insisting on some output.
fn must_stdin(program: &str, stdin: &str) -> String {
    let (_, stdout, stderr) = run_with_stdin(program, stdin);
    assert!(
        !stdout.is_empty(),
        "{program} said nothing; stderr: {stderr}"
    );
    stdout
}

/// One overlay plus one container-like jail, ready to be programmed.
///
/// Held together so both helper tests build the same world and any difference
/// between them is deliberate. The `TempDir` is returned because dropping it
/// would unlink the jail's rootfs.
struct ContainerWorld {
    namespace: Namespace,
    unit: u32,
    jail: String,
    in_jail_iface: String,
    own: Ipv4Addr,
    _rootfs: tempfile::TempDir,
}

fn container_world(vxlan: &Vxlan) -> ContainerWorld {
    let namespace = Namespace::fresh();
    ensure_module(vxlan);
    let spec = local_spec(VNI);
    let unit = overlay_up(vxlan, ip("10.79.0.11"), &spec);
    let rootfs = tempfile::tempdir().expect("a throwaway rootfs");
    let own = ip("10.79.0.14");
    let (jail, in_jail_iface) = container_jail(own, spec.mtu, rootfs.path());
    ContainerWorld {
        namespace,
        unit,
        jail,
        in_jail_iface,
        own,
        _rootfs: rootfs,
    }
}

#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn the_helper_programs_a_jail_with_no_arp_binary() {
    assert!(is_root(), "must run as root");
    let vxlan = Vxlan::system();
    let world = container_world(&vxlan);
    let (namespace, jail, in_jail_iface, own) = (
        world.namespace,
        world.jail.clone(),
        world.in_jail_iface.clone(),
        world.own,
    );
    let jid = jid_of(&jail);

    // --- the premise of this whole module: jexec cannot work here.
    let (ok, _, stderr) = run("/usr/sbin/jexec", &[&jail, "arp", "-an"]);
    assert!(!ok, "a rootfs with no arp(8) must fail");
    assert!(stderr.contains("execvp"), "{stderr}");
    let err = tokio_block(Arp::system().set(&jail, ip("10.79.0.12"), mac_of("10.79.0.12")))
        .expect_err("the jexec path cannot program a container");
    assert!(
        err.to_string().contains("no usable"),
        "the error must name the cause: {err}"
    );

    // --- and the routing-socket helper can, addressed by name or by jid.
    let helper = test_helper();
    let peer = ip("10.79.0.12");
    let other = ip("10.79.0.13");
    let batch = ArpBatch {
        add: vec![(peer, mac_of("10.79.0.12")), (other, mac_of("10.79.0.13"))],
        remove: vec![],
    };
    let applied = tokio_block(helper.apply(&jail, &batch)).expect("apply by name");
    assert!(applied.failures.is_empty(), "{applied:?}");
    assert_eq!(applied.added.len(), 2, "{applied:?}");

    // --- read it back: in the jail's stack, permanent, and ours.
    let entries = tokio_block(helper.list(&jid.to_string())).expect("list by jid");
    let found = |ip: Ipv4Addr| {
        entries
            .iter()
            .find(|entry| entry.ip == ip)
            .unwrap_or_else(|| panic!("{ip} must be in {entries:?}"))
    };
    for target in [peer, other] {
        let entry = found(target);
        assert_eq!(entry.mac, Some(MacAddr::from_ipv4(target)));
        assert_eq!(entry.iface, in_jail_iface, "{entry:?}");
        assert!(entry.permanent, "static entries never expire: {entry:?}");
        assert!(!entry.pinned, "{entry:?}");
        assert!(entry.is_overlay_static(), "{entry:?}");
    }

    // --- RTF_PINNED is the kernel's own marker for the jail's own address, and
    // it is what keeps the reconciler from ever deleting it.
    let mine = found(own);
    assert!(mine.permanent, "{mine:?}");
    assert!(
        mine.pinned,
        "the jail's own address must be RTF_PINNED (LLE_IFADDR): {mine:?}"
    );
    assert!(
        !mine.is_overlay_static(),
        "and must therefore never look like one of ours: {mine:?}"
    );
    let owned = tokio_block(helper.list_owned(&jail, &[own])).expect("list_owned");
    // Sorted here, not asserted in order: the kernel returns the link-layer
    // table in hash-bucket order, and the reconciler folds it into a BTreeMap
    // for exactly that reason.
    let mut addresses: Vec<Ipv4Addr> = owned.iter().map(|entry| entry.ip).collect();
    addresses.sort_unstable();
    assert_eq!(addresses, [peer, other]);

    // --- a different stack: the host's table has none of it.
    let (_, host_table, _) = run("/usr/sbin/arp", &["-an"]);
    for target in [peer, other] {
        assert!(
            !host_table.contains(&format!("({target})")),
            "{target} leaked into the host's stack: {host_table}"
        );
    }

    namespace.finish();
}

#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn the_helper_is_idempotent_and_reports_every_bad_entry_separately() {
    assert!(is_root(), "must run as root");
    let vxlan = Vxlan::system();
    let world = container_world(&vxlan);
    let (namespace, jail, own) = (world.namespace, world.jail.clone(), world.own);

    let helper = test_helper();
    let peer = ip("10.79.0.12");
    let other = ip("10.79.0.13");
    let batch = ArpBatch {
        add: vec![(peer, mac_of("10.79.0.12")), (other, mac_of("10.79.0.13"))],
        remove: vec![],
    };

    // --- applying the identical batch twice works: RTM_ADD replaces, unlike the
    // FDB's FTABLE_ENTRY_ADD, which is EEXIST.
    for attempt in 0..2 {
        let applied = tokio_block(helper.apply(&jail, &batch)).expect("apply");
        assert!(
            applied.failures.is_empty(),
            "attempt {attempt}: {applied:?}"
        );
        assert_eq!(applied.added.len(), 2, "attempt {attempt}: {applied:?}");
    }

    // --- and so does replacing a MAC, in one operation.
    let moved = MacAddr::from_ipv4(ip("10.79.0.99"));
    let applied = tokio_block(helper.apply(
        &jail,
        &ArpBatch {
            add: vec![(peer, moved)],
            remove: vec![],
        },
    ))
    .expect("replace");
    assert!(applied.failures.is_empty(), "{applied:?}");
    assert_eq!(
        tokio_block(helper.list(&jail))
            .expect("list")
            .into_iter()
            .find(|entry| entry.ip == peer)
            .and_then(|entry| entry.mac),
        Some(moved)
    );

    // --- removal, and its idempotence.
    let withdraw = ArpBatch {
        add: vec![],
        remove: vec![peer],
    };
    let applied = tokio_block(helper.apply(&jail, &withdraw)).expect("remove");
    assert_eq!(applied.removed, [peer], "{applied:?}");
    let applied = tokio_block(helper.apply(&jail, &withdraw)).expect("remove again");
    assert_eq!(applied.absent, [peer], "{applied:?}");
    assert!(applied.removed.is_empty() && applied.failures.is_empty());

    // --- the error paths, all in one batch, and the good entries still land.
    let off_link = ip("10.80.0.5");
    let mixed = ArpBatch {
        add: vec![
            (off_link, MacAddr::from_ipv4(off_link)),
            (peer, mac_of("10.79.0.12")),
        ],
        remove: vec![own],
    };
    let applied = tokio_block(helper.apply(&jail, &mixed)).expect("partial batch");
    assert_eq!(
        applied.added,
        [(peer, mac_of("10.79.0.12"))],
        "one bad entry must not cost the others: {applied:?}"
    );
    assert_eq!(applied.failures.len(), 2, "{applied:?}");
    assert!(
        applied.failures.iter().any(|text| text.contains("on-link")),
        "an off-link address must say so: {applied:?}"
    );
    assert!(
        applied
            .failures
            .iter()
            .any(|text| text.contains("LLE_IFADDR")),
        "deleting the jail's own address is EPERM and must be reported: {applied:?}"
    );
    // ...and the address the kernel refused to delete is still resolvable, which
    // is the outcome that matters: a lost own-address entry is a black hole.
    assert!(
        tokio_block(helper.list(&jail))
            .expect("list")
            .iter()
            .any(|entry| entry.ip == own && entry.mac.is_some()),
        "the jail's own address must still resolve"
    );

    // --- a jail that is not there is the benign race, not a hard failure.
    let err = tokio_block(helper.apply("ovtest-vanished", &batch))
        .expect_err("a missing jail must be typed");
    assert!(
        err.to_string().contains("ovtest-vanished"),
        "the error must name the jail: {err}"
    );

    namespace.finish();
}

#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn a_reconciliation_pass_through_the_helper_needs_nothing_in_the_jail() {
    assert!(is_root(), "must run as root");
    let vxlan = Vxlan::system();
    let world = container_world(&vxlan);
    let (namespace, unit, jail, own) = (world.namespace, world.unit, world.jail.clone(), world.own);

    // The same reconciler as the jexec test, with the production ARP mechanism.
    let programmer = helper_programmer();
    let desired = DesiredOverlay::new(VTEP, ip("127.0.0.1"))
        .with_local([LocalEndpoint::new(&jail, own)])
        .with_remote([
            RemoteEndpoint::new(ip("10.79.0.21"), ip("127.0.0.21")),
            RemoteEndpoint::new(ip("10.79.0.22"), ip("127.0.0.22")),
        ]);

    let state = tokio_block(programmer.read_state(&desired, unit)).expect("read_state");
    assert!(state.ftable.is_empty(), "{state:?}");
    assert!(
        state.arp[&jail].is_empty(),
        "nothing of ours is programmed yet, and the jail's own address is not \
         ours: {state:?}"
    );

    let applied = tokio_block(programmer.reconcile(&desired, unit)).expect("reconcile");
    assert!(applied.is_complete(), "{applied:?}");
    assert_eq!(applied.ftable_added.len(), 2);
    assert_eq!(applied.arp_added.len(), 2);

    let state = tokio_block(programmer.read_state(&desired, unit)).expect("read");
    assert_eq!(
        state.arp[&jail],
        BTreeMap::from([
            (ip("10.79.0.21"), mac_of("10.79.0.21")),
            (ip("10.79.0.22"), mac_of("10.79.0.22")),
        ])
    );

    // Idempotence against the real kernel, through a real child process.
    assert!(OverlayDelta::between(&desired, &state).is_empty());
    let applied = tokio_block(programmer.reconcile(&desired, unit)).expect("reconcile");
    assert!(
        applied.is_complete() && applied.arp_added.is_empty(),
        "{applied:?}"
    );

    // Withdrawing an endpoint clears its ARP entry and nothing else.
    let shrunk = DesiredOverlay::new(VTEP, ip("127.0.0.1"))
        .with_local([LocalEndpoint::new(&jail, own)])
        .with_remote([RemoteEndpoint::new(ip("10.79.0.22"), ip("127.0.0.22"))]);
    let applied = tokio_block(programmer.reconcile(&shrunk, unit)).expect("reconcile");
    assert_eq!(applied.arp_removed.len(), 1, "{applied:?}");
    let state = tokio_block(programmer.read_state(&shrunk, unit)).expect("read");
    assert_eq!(
        state.arp[&jail],
        BTreeMap::from([(ip("10.79.0.22"), mac_of("10.79.0.22"))])
    );
    // ...and the jail's own address survived all of it.
    assert!(
        tokio_block(test_helper().list(&jail))
            .expect("list")
            .iter()
            .any(|entry| entry.ip == own && entry.pinned),
        "the jail's own address must still be there"
    );

    namespace.finish();
}

#[test]
#[ignore = "needs root and FreeBSD; run via make integration"]
fn a_reconciliation_pass_programs_the_kernel_and_is_idempotent() {
    assert!(is_root(), "must run as root");
    let namespace = Namespace::fresh();
    let vxlan = Vxlan::system();
    ensure_module(&vxlan);
    let local_ip = ip("10.79.0.11");
    let unit = overlay_up(&vxlan, local_ip, &local_spec(VNI));

    let programmer = jexec_programmer();
    let desired = DesiredOverlay::new(VTEP, ip("127.0.0.1"))
        .with_local([LocalEndpoint::new(JAIL, local_ip)])
        .with_remote([
            RemoteEndpoint::new(ip("10.79.0.21"), ip("127.0.0.21")),
            RemoteEndpoint::new(ip("10.79.0.22"), ip("127.0.0.22")),
        ]);

    // Nothing programmed yet: an empty FDB and an ARP table with nothing of
    // ours in it (the jail's own permanent entry is excluded by ownership).
    let state = tokio_block(programmer.read_state(&desired, unit)).expect("read");
    assert!(state.ftable.is_empty(), "{state:?}");
    assert!(state.arp[JAIL].is_empty(), "{state:?}");
    assert!(OverlayDelta::between(&DesiredOverlay::new(VTEP, ip("127.0.0.1")), &state).is_empty());

    let applied = tokio_block(programmer.reconcile(&desired, unit)).expect("reconcile");
    assert!(applied.is_complete(), "{applied:?}");
    assert_eq!(applied.ftable_added.len(), 2);
    assert_eq!(applied.arp_added.len(), 2);

    // Read back through both paths and confirm they agree with the desire.
    let state = tokio_block(programmer.read_state(&desired, unit)).expect("read");
    assert_eq!(
        state.ftable,
        BTreeMap::from([
            (MacAddr::from_ipv4(ip("10.79.0.21")), ip("127.0.0.21")),
            (MacAddr::from_ipv4(ip("10.79.0.22")), ip("127.0.0.22")),
        ])
    );
    assert_eq!(
        state.arp[JAIL],
        BTreeMap::from([
            (ip("10.79.0.21"), MacAddr::from_ipv4(ip("10.79.0.21"))),
            (ip("10.79.0.22"), MacAddr::from_ipv4(ip("10.79.0.22"))),
        ])
    );

    // Idempotence against the real kernel: the second pass finds nothing.
    let delta = OverlayDelta::between(&desired, &state);
    assert!(delta.is_empty(), "{delta:?}");
    let applied = tokio_block(programmer.reconcile(&desired, unit)).expect("reconcile");
    assert!(applied.is_complete() && applied.ftable_added.is_empty());

    // A moved endpoint is a replace, and the ARP entry does not move with it.
    let moved = DesiredOverlay::new(VTEP, ip("127.0.0.1"))
        .with_local([LocalEndpoint::new(JAIL, local_ip)])
        .with_remote([
            RemoteEndpoint::new(ip("10.79.0.21"), ip("127.0.0.99")),
            RemoteEndpoint::new(ip("10.79.0.22"), ip("127.0.0.22")),
        ]);
    let applied = tokio_block(programmer.reconcile(&moved, unit)).expect("reconcile");
    assert_eq!(applied.ftable_replaced.len(), 1, "{applied:?}");
    assert!(applied.ftable_added.is_empty() && applied.ftable_removed.is_empty());
    assert!(applied.arp_added.is_empty() && applied.arp_removed.is_empty());
    // The replacement really landed: read it back through the dump.
    let state = tokio_block(programmer.read_state(&moved, unit)).expect("read");
    assert_eq!(
        state.ftable[&MacAddr::from_ipv4(ip("10.79.0.21"))],
        ip("127.0.0.99")
    );

    // Withdrawing an endpoint clears it from both tables...
    let shrunk = DesiredOverlay::new(VTEP, ip("127.0.0.1"))
        .with_local([LocalEndpoint::new(JAIL, local_ip)])
        .with_remote([RemoteEndpoint::new(ip("10.79.0.22"), ip("127.0.0.22"))]);
    let applied = tokio_block(programmer.reconcile(&shrunk, unit)).expect("reconcile");
    assert_eq!(
        applied.ftable_removed,
        [MacAddr::from_ipv4(ip("10.79.0.21"))]
    );
    assert_eq!(applied.arp_removed.len(), 1);

    // ...and the jail's own permanent entry is never touched by any of it.
    let table = tokio_block(Arp::system().list(JAIL)).expect("list");
    assert!(
        table.iter().any(|entry| entry.ip == local_ip),
        "the jail's own address must still be resolvable: {table:?}"
    );
    namespace.finish();
}

// ---------------------------------------------------------------------------
// 4. Two nodes: the FDB is what carries the traffic, and the MTU is exact
// ---------------------------------------------------------------------------

/// Environment for the multi-node test; `None` skips it.
struct TwoNode {
    local_vtep: Ipv4Addr,
    peer_vtep: Ipv4Addr,
    local_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    blackhole: Ipv4Addr,
    underlay_mtu: u32,
}

impl TwoNode {
    fn from_env() -> Option<Self> {
        let addr = |key: &str| -> Option<Ipv4Addr> { std::env::var(key).ok()?.parse().ok() };
        Some(Self {
            local_vtep: addr("SATL_OVERLAY_LOCAL_VTEP")?,
            peer_vtep: addr("SATL_OVERLAY_PEER_VTEP")?,
            local_ip: addr("SATL_OVERLAY_LOCAL_IP")?,
            peer_ip: addr("SATL_OVERLAY_PEER_IP")?,
            blackhole: addr("SATL_OVERLAY_BLACKHOLE")?,
            underlay_mtu: std::env::var("SATL_OVERLAY_UNDERLAY_MTU")
                .ok()
                .and_then(|text| text.parse().ok())
                .unwrap_or(1500),
        })
    }
}

/// Outer-IP fragmentation counters from the **host** stack: encapsulation
/// happens there, while the TCP endpoints live in the jail's stack
/// (`docs/vxlan.md` §6, "Counters live in two different stacks").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FragCounters {
    fragmented: u64,
    created: u64,
    received: u64,
}

impl FragCounters {
    fn read() -> Self {
        let (_, text, _) = run("/usr/bin/netstat", &["-s", "-p", "ip"]);
        let count = |needle: &str| -> u64 {
            text.lines()
                .find(|line| line.contains(needle))
                .and_then(|line| line.split_whitespace().next())
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| panic!("no {needle:?} in netstat output:\n{text}"))
        };
        Self {
            fragmented: count("output datagrams fragmented"),
            created: count("fragments created"),
            received: count("fragments received"),
        }
    }

    fn since(self, before: Self) -> Self {
        Self {
            fragmented: self.fragmented - before.fragmented,
            created: self.created - before.created,
            received: self.received - before.received,
        }
    }

    fn is_zero(self) -> bool {
        self.fragmented == 0 && self.created == 0 && self.received == 0
    }
}

/// `jexec <jail> ping ...`, with an explicit inter-packet interval.
///
/// The interval is not cosmetic: `ping -t <seconds>` caps the **total** run
/// time, so `-c 200` at the default one-second interval sends four packets and
/// exits non-zero. Every bulk probe here therefore sets `-i` (sub-second
/// intervals need root, which these tests have) and a `-t` generous enough for
/// the whole count.
fn jail_ping_at(target: Ipv4Addr, size: Option<u32>, count: u32, interval: &str) -> (bool, String) {
    let timeout = 20 + count / 20;
    let mut args = vec![
        JAIL.to_owned(),
        "ping".to_owned(),
        "-c".to_owned(),
        count.to_string(),
        "-i".to_owned(),
        interval.to_owned(),
        "-t".to_owned(),
        timeout.to_string(),
    ];
    if let Some(bytes) = size {
        args.push("-D".to_owned());
        args.push("-s".to_owned());
        args.push(bytes.to_string());
    }
    args.push(target.to_string());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, stdout, stderr) = run("/usr/sbin/jexec", &refs);
    (ok, format!("{stdout}{stderr}"))
}

fn jail_ping(target: Ipv4Addr, size: Option<u32>, count: u32) -> (bool, String) {
    jail_ping_at(target, size, count, "0.2")
}

/// The last two lines of `ping` output — the statistics summary.
fn ping_stats(output: &str) -> String {
    let lines: Vec<&str> = output.lines().filter(|line| !line.is_empty()).collect();
    lines
        .iter()
        .rev()
        .take(2)
        .rev()
        .copied()
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Poll until the peer answers, so both nodes can be started independently.
fn wait_for_peer(target: Ipv4Addr, deadline: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if jail_ping(target, None, 1).0 {
            return true;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    false
}

/// The overlay MTU this pair must use.
fn mtu_of(peer: &TwoNode) -> u32 {
    overlay_mtu_v4(peer.underlay_mtu)
}

/// Bring this node's half of the two-node overlay up and program the peer.
///
/// Returns the clone unit, the programmer and the desired state, so both roles
/// share one bring-up path and any difference between them is deliberate.
fn two_node_up(vxlan: &Vxlan, peer: &TwoNode) -> (u32, JexecProgrammer, DesiredOverlay) {
    // The default remote is a blackhole. This is what makes the test mean
    // something: with it pointed at the peer, a missing FDB entry would work
    // anyway (docs/vxlan.md §2 point 4).
    let mtu = mtu_of(peer);
    assert_eq!(mtu, 1450, "the measured underlay is 1500 on these nodes");
    let spec = VtepSpec::new(VNI, peer.local_vtep, peer.blackhole).with_mtu(mtu);
    let unit = overlay_up(vxlan, peer.local_ip, &spec);

    let programmer = jexec_programmer();
    let desired = DesiredOverlay::new(VTEP, peer.local_vtep)
        .with_local([LocalEndpoint::new(JAIL, peer.local_ip)])
        .with_remote([RemoteEndpoint::new(peer.peer_ip, peer.peer_vtep)]);

    // The delta drives the whole data plane: one FDB entry, one ARP entry.
    let applied = tokio_block(programmer.reconcile(&desired, unit)).expect("reconcile");
    assert!(applied.is_complete(), "{applied:?}");
    assert_eq!(applied.ftable_added.len(), 1);
    assert_eq!(applied.arp_added.len(), 1);
    (unit, programmer, desired)
}

/// The **passive** half of the two-node test: bring this side up, confirm the
/// peer is reachable at least once, then hold everything in place while the
/// active side runs its assertions — including the destructive one.
///
/// A separate role is not ceremony: the active side deletes an FDB entry and
/// asserts 100 % loss, and if the passive side were doing the same thing at the
/// same time its own probes would fail for the *other* node's reason. The two
/// roles is how the race gets removed.
#[test]
#[ignore = "needs root, FreeBSD and a peer node; see the module docs"]
fn two_node_overlay_holds_a_side_for_a_peer() {
    assert!(is_root(), "must run as root");
    let Some(peer) = TwoNode::from_env() else {
        eprintln!("SATL_OVERLAY_PEER_* not set: skipping the multi-node test");
        return;
    };
    let hold = Duration::from_secs(
        std::env::var("SATL_OVERLAY_HOLD_SECS")
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(180),
    );
    let namespace = Namespace::fresh();
    let vxlan = Vxlan::system();
    ensure_module(&vxlan);
    two_node_up(&vxlan, &peer);

    assert!(
        wait_for_peer(peer.peer_ip, Duration::from_mins(2)),
        "the peer jail never answered; the active side must be running too"
    );
    eprintln!("passive side up and reachable; holding for {hold:?}");
    // Sampled around the hold so the number is a delta over the window the
    // active side runs in — a total since boot would prove nothing.
    let before = FragCounters::read();
    std::thread::sleep(hold);
    let delta = FragCounters::read().since(before);
    let (_, counters, _) = run("/usr/bin/netstat", &["-I", VTEP, "-b"]);
    eprintln!("passive side vxlan counters:\n{counters}");
    eprintln!("passive side outer-IP fragmentation over the hold window: {delta:?}");
    // The receiving end of a correctly sized overlay reassembles nothing. Only
    // asserted when the active side is not deliberately mis-sizing its MTU.
    if std::env::var_os("SATL_OVERLAY_MTU_CONTRAST").is_none() {
        assert!(
            delta.is_zero(),
            "the receiving node must not see a single fragment: {delta:?}"
        );
    }
    namespace.finish();
}

/// The **active** half: everything a single host cannot prove.
#[test]
#[ignore = "needs root, FreeBSD and a peer node; see the module docs"]
fn two_node_overlay_is_carried_by_the_fdb() {
    assert!(is_root(), "must run as root");
    let Some(peer) = TwoNode::from_env() else {
        eprintln!("SATL_OVERLAY_PEER_* not set: skipping the multi-node test");
        return;
    };
    let namespace = Namespace::fresh();
    let vxlan = Vxlan::system();
    ensure_module(&vxlan);
    let (unit, programmer, desired) = two_node_up(&vxlan, &peer);

    assert!(
        wait_for_peer(peer.peer_ip, Duration::from_mins(2)),
        "the peer jail never answered; the passive side must be running too"
    );
    let (ok, output) = jail_ping(peer.peer_ip, None, 3);
    assert!(ok, "jail-to-jail ping across the overlay failed:\n{output}");

    // --- the MTU is exact: 1422 + 28 = 1450 inner, + 50 = 1500 outer.
    let (ok, output) = jail_ping(peer.peer_ip, Some(1422), 2);
    assert!(ok, "1422-byte DF ping must cross:\n{output}");
    let (ok, output) = jail_ping(peer.peer_ip, Some(1423), 1);
    assert!(
        !ok && output.contains("Message too long"),
        "1423 bytes must be refused locally:\n{output}"
    );

    // --- and nothing fragments. The counters are the only reliable signal:
    // throughput on this link varies more between correct runs than between a
    // correct and an over-sized MTU (docs/vxlan.md §6).
    let before = FragCounters::read();
    let (ok, output) = jail_ping_at(peer.peer_ip, Some(1422), BULK, "0.01");
    let delta = FragCounters::read().since(before);
    eprintln!("bulk full-size run: {}", ping_stats(&output));
    eprintln!("outer-IP fragmentation over {BULK} full-size frames: {delta:?}");
    assert!(
        ok,
        "the {BULK}-packet full-size run must succeed:\n{output}"
    );
    assert!(
        delta.is_zero(),
        "a correctly sized overlay must not fragment anything: {delta:?}"
    );

    // For contrast, and only when asked for: the same probe with **this** side's
    // overlay MTU wrongly set to the underlay's — the forgotten −50 of
    // `docs/vxlan.md` §6, applied asymmetrically because the peer is still
    // correct. Two things then show up, and only the second is visible without
    // these counters:
    //
    //   - every full-size datagram leaves as two outer fragments, which the
    //     peer's host stack dutifully reassembles;
    //   - the 1500-byte inner frame that comes out of decapsulation is then too
    //     big for the peer's bridge members, which are still 1450, so it is
    //     dropped after a successful tunnel crossing. Hence 100 % loss with
    //     `fragments received` moving on the far side: the symptom points at the
    //     receiver while the fault is entirely at the sender.
    //
    // Opt-in, so that a plain run leaves the peer's counters clean and its own
    // zero-fragmentation delta means what it says.
    if std::env::var_os("SATL_OVERLAY_MTU_CONTRAST").is_some() {
        tokio_block(vxlan.set_mtu(BRIDGE, peer.underlay_mtu)).expect("raise the bridge MTU");
        must(
            "/usr/sbin/jexec",
            &[
                JAIL,
                "ifconfig",
                EPAIR_B,
                "mtu",
                &peer.underlay_mtu.to_string(),
            ],
        );
        let before = FragCounters::read();
        let (ok, output) = jail_ping_at(peer.peer_ip, Some(1472), BULK, "0.01");
        let oversized = FragCounters::read().since(before);
        eprintln!("oversized-MTU run: ok={ok} {}", ping_stats(&output));
        eprintln!("outer-IP fragmentation with the wrong MTU: {oversized:?}");
        assert!(
            oversized.fragmented > 0 && oversized.created >= 2 * oversized.fragmented,
            "an over-sized overlay MTU must show up as outer-IP fragmentation, \
             two fragments per datagram, which is the only reliable signal: \
             {oversized:?}\n{output}"
        );
        assert!(
            !ok,
            "asymmetric mis-sizing is also visible as loss, because the peer's \
             bridge members are still {} bytes:\n{output}",
            mtu_of(&peer)
        );
        tokio_block(vxlan.set_mtu(BRIDGE, mtu_of(&peer))).expect("restore the bridge MTU");
        must(
            "/usr/sbin/jexec",
            &[JAIL, "ifconfig", EPAIR_B, "mtu", &mtu_of(&peer).to_string()],
        );
    }

    // --- the FDB entry is what carries it. Remove exactly one and the pair
    // breaks: our echo requests now go to the blackhole and nowhere else.
    let ftable = Ftable::new();
    assert!(
        ftable
            .remove(VTEP, MacAddr::from_ipv4(peer.peer_ip))
            .expect("remove"),
        "the entry must have been there"
    );
    let (ok, output) = jail_ping(peer.peer_ip, None, 3);
    assert!(
        !ok,
        "with no FDB entry the peer must be unreachable — if this passes, the \
         default remote is not a blackhole and the test proves nothing:\n{output}"
    );
    // The frames went to the default remote, which is unroutable: that is what
    // Oerrs on a healthy overlay counts.
    let (_, counters, _) = run("/usr/bin/netstat", &["-I", VTEP, "-b"]);
    eprintln!("vxlan counters after the blackholed pings:\n{counters}");

    // --- exactly reversible: re-adding the one entry restores the pair.
    let applied = tokio_block(programmer.reconcile(&desired, unit)).expect("reconcile");
    assert_eq!(applied.ftable_added.len(), 1);
    assert!(
        wait_for_peer(peer.peer_ip, Duration::from_secs(30)),
        "re-adding the single FDB entry must restore the pair"
    );

    namespace.finish();
}
