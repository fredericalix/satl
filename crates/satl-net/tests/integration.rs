// SPDX-License-Identifier: BSD-2-Clause
//! Root integration tests for satl-net (`make integration`).
//!
//! All `#[ignore]`-gated: they create real interfaces and jails and need
//! root. Everything is prefixed `satlnt-` (test namespace, never the
//! production `satl`/`satl0` names), uses the `10.77.0.0/16`–`10.78.0.0/16`
//! pools (never the production `10.88.0.0/16`), and cleans up via RAII
//! guards; each test ends with a leftovers audit.
//!
//! pf: [`NetworkManager`] runs in `PfMode::Disabled` here — on the shared
//! dev host not even `pfctl -nf` works (pf.ko not loaded), and live anchor
//! loads are only allowed on the cluster VMs behind `SATL_PF_LIVE=1`
//! (`pf_live_anchor_roundtrip`).
//!
//! The overlay tests create a **throwaway vxlan interface by hand**: the VTEP
//! belongs to `satl-overlay` in production (`crate::overlay` docs), and this
//! crate must be exercised against a real one without depending on that crate.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use satl_net::{
    ANCHOR_RDR, NetworkManager, NetworkManagerConfig, OverlayAttach, OverlaySegment, OwnedKind,
    PfCtl, PfError, PfMode, PortPublish, SubnetV4,
};

fn is_root() -> bool {
    let out = Command::new("/usr/bin/id").arg("-u").output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim() == "0"
}

fn run(program: &str, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(program).args(args).output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Destroys an interface on drop (best effort; missing is fine).
struct IfaceGuard(&'static str);

impl Drop for IfaceGuard {
    fn drop(&mut self) {
        let _ = Command::new("/sbin/ifconfig")
            .args([self.0, "destroy"])
            .output();
    }
}

/// Removes a jail on drop (best effort; missing is fine).
struct JailGuard(&'static str);

impl Drop for JailGuard {
    fn drop(&mut self) {
        let _ = Command::new("/usr/sbin/jail").args(["-r", self.0]).output();
    }
}

/// Assert no `satlnt`-prefixed interfaces or jails and no group leftovers.
fn audit_leftovers(group: &str) {
    let (_, ifaces, _) = run("/sbin/ifconfig", &["-l"]);
    let stray: Vec<&str> = ifaces
        .split_whitespace()
        .filter(|name| name.starts_with("satlnt"))
        .collect();
    assert!(stray.is_empty(), "leftover satlnt interfaces: {stray:?}");
    let (_, members, _) = run("/sbin/ifconfig", &["-g", group]);
    assert!(
        members.trim().is_empty(),
        "leftover group '{group}' members: {members:?}"
    );
    let (_, jails, _) = run("/usr/sbin/jls", &["name"]);
    let stray_jails: Vec<&str> = jails
        .split_whitespace()
        .filter(|name| name.starts_with("satlnt"))
        .collect();
    assert!(
        stray_jails.is_empty(),
        "leftover satlnt jails: {stray_jails:?}"
    );
}

fn config(
    dir: &std::path::Path,
    network: &str,
    bridge: &str,
    group: &str,
    pool: &str,
) -> NetworkManagerConfig {
    NetworkManagerConfig {
        network: network.to_owned(),
        bridge: bridge.to_owned(),
        group: group.to_owned(),
        state_dir: dir.to_path_buf(),
        pool: pool.parse::<SubnetV4>().unwrap(),
        egress_if: None,
        pf_mode: PfMode::Disabled,
    }
}

/// Bridge lifecycle: create (idempotently), verify group/descr/address
/// markers, then orphan destruction, then teardown.
#[tokio::test]
#[ignore = "requires root and creates real interfaces (make integration)"]
async fn bridge_lifecycle_owned_listing_and_orphan_destroy() {
    assert!(is_root(), "integration tests must run as root");
    let dir = tempfile::tempdir().unwrap();
    let _bridge_guard = IfaceGuard("satlnt-b1");
    let mgr = NetworkManager::open(config(
        dir.path(),
        "satlnta",
        "satlnt-b1",
        "satlnta",
        "10.77.0.0/16",
    ))
    .unwrap();

    let net = mgr.ensure_host_network().await.unwrap();
    assert_eq!(net.bridge, "satlnt-b1");
    assert_eq!(net.subnet.to_string(), "10.77.0.0/24");
    assert_eq!(net.gateway.to_string(), "10.77.0.1");

    // Idempotent: second ensure must not fail or duplicate anything.
    let again = mgr.ensure_host_network().await.unwrap();
    assert_eq!(again, net);

    // The bridge is group-tagged, description-tagged, addressed, up.
    let (ok, show, _) = run("/sbin/ifconfig", &["satlnt-b1"]);
    assert!(ok);
    assert!(
        show.contains("description: satlnta:network:satlnta"),
        "{show}"
    );
    assert!(show.contains("inet 10.77.0.1"), "{show}");
    assert!(show.contains("UP"), "{show}");
    let (_, members, _) = run("/sbin/ifconfig", &["-g", "satlnta"]);
    assert!(members.contains("satlnt-b1"), "{members}");

    // list_owned sees the bridge as a network marker.
    let owned = mgr.list_owned().await.unwrap();
    assert!(
        owned.iter().any(|o| o.name == "satlnt-b1"
            && o.kind
                == OwnedKind::Network {
                    network: "satlnta".to_owned()
                }),
        "{owned:?}"
    );

    // Simulate an interrupted teardown: attach to a throwaway jail, kill
    // the jail without detaching. The b end auto-returns to the host
    // WITHOUT its group — only the description marks it (verified gotcha).
    {
        let _jail_guard = JailGuard("satlnt-orph");
        let (ok, _, err) = run(
            "/usr/sbin/jail",
            &["-c", "name=satlnt-orph", "vnet", "persist"],
        );
        assert!(ok, "jail create failed: {err}");
        let att = mgr
            .attach_task("orphantask00000000000001x", "satlnt-orph")
            .await
            .unwrap();
        let (ok, _, err) = run("/usr/sbin/jail", &["-r", "satlnt-orph"]);
        assert!(ok, "jail remove failed: {err}");
        // Both ends are back on the host now; neither task is known.
        let known = BTreeSet::new();
        let destroyed = mgr.destroy_orphans(&known).await.unwrap();
        assert!(
            destroyed.contains(&att.epair_a),
            "expected {} in {destroyed:?}",
            att.epair_a
        );
        let (_, ifaces, _) = run("/sbin/ifconfig", &["-l"]);
        assert!(!ifaces.contains(&att.epair_a), "{ifaces}");
        assert!(!ifaces.contains(&att.epair_b), "{ifaces}");
        // The bridge survived the orphan sweep.
        let owned = mgr.list_owned().await.unwrap();
        assert!(owned.iter().any(|o| o.name == "satlnt-b1"), "{owned:?}");
    }

    // Teardown and audit.
    let (ok, _, err) = run("/sbin/ifconfig", &["satlnt-b1", "destroy"]);
    assert!(ok, "bridge destroy failed: {err}");
    audit_leftovers("satlnta");
}

/// Full attach/detach against a throwaway VNET jail, asserting in-jail
/// connectivity (default route installed, gateway pingable from inside).
#[tokio::test]
#[ignore = "requires root and creates real interfaces and jails (make integration)"]
async fn attach_detach_roundtrip_with_in_jail_connectivity() {
    assert!(is_root(), "integration tests must run as root");
    let dir = tempfile::tempdir().unwrap();
    let _bridge_guard = IfaceGuard("satlnt-b2");
    let _jail_guard = JailGuard("satlnt-it");
    let mgr = NetworkManager::open(config(
        dir.path(),
        "satlntb",
        "satlnt-b2",
        "satlntb",
        "10.78.0.0/16",
    ))
    .unwrap();

    let net = mgr.ensure_host_network().await.unwrap();
    assert_eq!(net.gateway.to_string(), "10.78.0.1");

    let (ok, _, err) = run(
        "/usr/sbin/jail",
        &["-c", "name=satlnt-it", "vnet", "persist"],
    );
    assert!(ok, "jail create failed: {err}");

    let task_id = "itesttask000000000000001x";
    let att = mgr.attach_task(task_id, "satlnt-it").await.unwrap();
    assert_eq!(att.ip.to_string(), "10.78.0.2");
    assert_eq!(att.gateway.to_string(), "10.78.0.1");

    // The default route is installed inside the jail...
    let (ok, routes, err) = run(
        "/usr/sbin/jexec",
        &["satlnt-it", "netstat", "-rn", "-f", "inet"],
    );
    assert!(ok, "netstat failed: {err}");
    assert!(
        routes
            .lines()
            .any(|l| l.starts_with("default") && l.contains("10.78.0.1")),
        "no default route via gateway in:\n{routes}"
    );
    // ...and the gateway answers from inside the jail.
    let (ok, ping, err) = run(
        "/usr/sbin/jexec",
        &["satlnt-it", "ping", "-c", "1", "-t", "2", "10.78.0.1"],
    );
    assert!(ok, "in-jail ping failed: {ping} {err}");
    assert!(ping.contains("1 packets received"), "{ping}");

    // Stable allocation: attaching the same task again after detach gets
    // the same address.
    mgr.detach_task(task_id, &att).await.unwrap();
    let (_, ifaces, _) = run("/sbin/ifconfig", &["-l"]);
    assert!(!ifaces.contains(&att.epair_a), "epair leaked: {ifaces}");
    // Idempotent detach.
    mgr.detach_task(task_id, &att).await.unwrap();

    // Jail teardown, bridge teardown, audit.
    let (ok, _, err) = run("/usr/sbin/jail", &["-r", "satlnt-it"]);
    assert!(ok, "jail remove failed: {err}");
    let (ok, _, err) = run("/sbin/ifconfig", &["satlnt-b2", "destroy"]);
    assert!(ok, "bridge destroy failed: {err}");
    audit_leftovers("satlntb");
}

// ---------------------------------------------------------------------------
// M3: overlay segments
// ---------------------------------------------------------------------------

/// Create a throwaway unicast VTEP by hand, exactly the way `satl-overlay`
/// does (`docs/vxlan.md` §2), and tag it with the ownership marker this crate's
/// sweep expects. Returns once it is `RUNNING` — the only health signal.
fn create_test_vtep(name: &str, vni: u32, group: &str, network: &str) {
    let _ = run("/sbin/kldload", &["if_vxlan"]);
    let (ok, clone, err) = run(
        "/sbin/ifconfig",
        &[
            "vxlan",
            "create",
            "vxlanid",
            &vni.to_string(),
            "vxlanlocal",
            "127.0.0.1",
            "vxlanremote",
            "127.0.0.254",
            "-vxlanlearn",
        ],
    );
    assert!(ok, "vxlan create failed: {err}");
    let clone = clone.trim();
    let (ok, _, err) = run("/sbin/ifconfig", &[clone, "name", name]);
    assert!(ok, "vxlan rename failed: {err}");
    let descr = format!("{group}:vxlan:{network}");
    let (ok, _, err) = run("/sbin/ifconfig", &[name, "description", &descr]);
    assert!(ok, "vxlan description failed: {err}");
    let (ok, _, err) = run("/sbin/ifconfig", &[name, "up"]);
    assert!(ok, "vxlan up failed: {err}");
    let (_, show, _) = run("/sbin/ifconfig", &[name]);
    assert!(
        show.lines().next().unwrap_or_default().contains("RUNNING"),
        "VTEP came up without RUNNING — read /var/log/messages:\n{show}"
    );
}

/// The MTU on the header line of `ifconfig` output.
fn mtu_of(show: &str) -> u32 {
    let header = show.lines().next().unwrap_or_default();
    let mut words = header.split_whitespace();
    while let Some(word) = words.next() {
        if word == "mtu" {
            return words.next().unwrap_or("0").parse().unwrap_or(0);
        }
    }
    0
}

/// Assert the host side of an ensured overlay segment: marker, gateway
/// address, VTEP membership, `RUNNING`, and the overlay MTU on the bridge *and*
/// on the VTEP (the bridge's MTU is what propagates to its members).
fn assert_overlay_bridge_state(
    bridge: &str,
    vtep: &str,
    gateway: &str,
    group: &str,
    network: &str,
) {
    let (ok, show, _) = run("/sbin/ifconfig", &[bridge]);
    assert!(ok);
    // Printed on purpose: with `--nocapture` this is the evidence the
    // definition of done asks for (the MTU and the membership, read back from
    // the kernel rather than inferred from exit codes).
    eprintln!("--- ifconfig {bridge} ---\n{show}");
    assert_eq!(mtu_of(&show), 1450, "{show}");
    assert!(
        show.contains(&format!("description: {group}:overlay:{network}")),
        "{show}"
    );
    assert!(show.contains(&format!("inet {gateway}")), "{show}");
    assert!(show.contains(&format!("member: {vtep}")), "{show}");
    assert!(show.lines().next().unwrap().contains("RUNNING"), "{show}");
    let (_, vtep_show, _) = run("/sbin/ifconfig", &[vtep]);
    assert_eq!(mtu_of(&vtep_show), 1450, "{vtep_show}");
}

/// Assert the in-jail epair end carries the overlay MTU, the derived MAC and
/// the task's address — the three things nothing propagates for.
fn assert_in_jail_endpoint(jail: &str, iface: &str, mac: &str, ip: &str) {
    let (ok, show, err) = run("/sbin/ifconfig", &["-j", jail, iface]);
    assert!(ok, "in-jail ifconfig failed: {err}");
    eprintln!("--- ifconfig -j {jail} {iface} ---\n{show}");
    assert_eq!(mtu_of(&show), 1450, "{show}");
    assert!(show.contains(&format!("ether {mac}")), "{show}");
    assert!(show.contains(&format!("inet {ip}")), "{show}");
    assert!(show.lines().next().unwrap().contains("RUNNING"), "{show}");
}

/// Prove the MTU accounting from inside the jail: 1422 + 28 = 1450 crosses with
/// DF set, 1423 does not (`docs/vxlan.md` §5).
fn assert_mtu_boundary(jail: &str, peer: &str) {
    let (ok, ping, err) = run(
        "/usr/sbin/jexec",
        &[jail, "ping", "-c", "1", "-t", "2", peer],
    );
    assert!(ok, "in-jail ping failed: {ping} {err}");
    let (ok, out, _) = run(
        "/usr/sbin/jexec",
        &[jail, "ping", "-c", "1", "-t", "2", "-D", "-s", "1422", peer],
    );
    assert!(ok, "1422-byte DF ping should pass at mtu 1450: {out}");
    let (ok, out, err) = run(
        "/usr/sbin/jexec",
        &[jail, "ping", "-c", "1", "-t", "2", "-D", "-s", "1423", peer],
    );
    assert!(!ok, "1423-byte DF ping must not pass at mtu 1450: {out}");
    assert!(
        err.contains("Message too long") || out.contains("Message too long"),
        "unexpected failure mode: {out} {err}"
    );
}

/// Assert the sweep's view of a live overlay segment: the bridge, the task's
/// epair, and the VTEP that carries a SatL marker but is not SatL-net's to
/// destroy.
async fn assert_marker_classification(
    mgr: &NetworkManager,
    network: &str,
    bridge: &str,
    epair_a: &str,
    task_id: &str,
    vtep: &str,
) {
    let owned = mgr.list_owned().await.unwrap();
    let kind_of = |name: &str| {
        owned
            .iter()
            .find(|iface| iface.name == name)
            .map(|iface| iface.kind.clone())
    };
    assert_eq!(
        kind_of(bridge),
        Some(OwnedKind::OverlayNetwork {
            network: network.to_owned()
        }),
        "{owned:?}"
    );
    assert_eq!(
        kind_of(epair_a),
        Some(OwnedKind::OverlayTask {
            network: network.to_owned(),
            task_id: task_id.to_owned()
        }),
        "{owned:?}"
    );
    assert_eq!(
        kind_of(vtep),
        Some(OwnedKind::Vtep {
            network: network.to_owned()
        }),
        "{owned:?}"
    );
}

/// Full overlay segment lifecycle against a real VTEP and a real VNET jail:
/// the bridge carries the per-node gateway and the overlay MTU, the VTEP is a
/// member, both epair ends carry 1450 and the jail end carries the derived MAC,
/// the MTU accounting is proved by a DF ping at the boundary, and teardown
/// leaves the VTEP alone.
#[tokio::test]
#[ignore = "requires root and creates real interfaces and jails (make integration)"]
async fn overlay_segment_lifecycle_with_real_vtep_and_jail() {
    assert!(is_root(), "integration tests must run as root");
    let dir = tempfile::tempdir().unwrap();
    let _vtep_guard = IfaceGuard("satlnt-vx0");
    let _bridge_guard = IfaceGuard("satlnt-bo0");
    let _jail_guard = JailGuard("satlnt-ov1");
    create_test_vtep("satlnt-vx0", 9971, "satlntc", "ovl");

    let mgr = NetworkManager::open(config(
        dir.path(),
        "satlntc",
        "satlnt-bl0",
        "satlntc",
        "10.77.0.0/16",
    ))
    .unwrap();
    let segment = OverlaySegment {
        network: "ovl".to_owned(),
        bridge: "satlnt-bo0".to_owned(),
        vtep: "satlnt-vx0".to_owned(),
        subnet: "10.79.0.0/24".parse().unwrap(),
        // This node's own gateway: never the reserved .1 (docs/vxlan.md §8).
        gateway: "10.79.0.2".parse().unwrap(),
        mtu: 1450,
    };

    let bridge = mgr.ensure_overlay_segment(&segment).await.unwrap();
    assert_eq!(bridge.bridge, "satlnt-bo0");
    assert_eq!(bridge.mtu, 1450);
    // Idempotent, and adoption of its own bridge changes nothing.
    assert_eq!(mgr.ensure_overlay_segment(&segment).await.unwrap(), bridge);

    assert_overlay_bridge_state("satlnt-bo0", "satlnt-vx0", "10.79.0.2", "satlntc", "ovl");

    let (ok, _, err) = run(
        "/usr/sbin/jail",
        &["-c", "name=satlnt-ov1", "vnet", "persist"],
    );
    assert!(ok, "jail create failed: {err}");

    let task_id = "ovltask0000000000000001x";
    let att = mgr
        .attach_task_overlay(
            &segment,
            &OverlayAttach::new(task_id, "satlnt-ov1", "10.79.0.11".parse().unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(att.mac.to_string(), "02:42:0a:4f:00:0b");

    // Host end: the bridge's MTU, and a member of the bridge.
    let (_, show_a, _) = run("/sbin/ifconfig", &[&att.epair_a]);
    assert_eq!(mtu_of(&show_a), 1450, "{show_a}");
    let (_, show_bridge, _) = run("/sbin/ifconfig", &["satlnt-bo0"]);
    assert!(
        show_bridge.contains(&format!("member: {}", att.epair_a)),
        "{show_bridge}"
    );
    // Jail end: the MTU nothing propagates to, and the derived MAC.
    assert_in_jail_endpoint(
        "satlnt-ov1",
        &att.epair_b,
        "02:42:0a:4f:00:0b",
        "10.79.0.11",
    );
    assert_mtu_boundary("satlnt-ov1", "10.79.0.2");

    // Reconciliation runs on a timer, so re-ensuring the segment under a live
    // attachment must be a no-op for the task: the bridge MTU write propagates
    // to every member, and if it flapped the epair or moved the in-jail end's
    // MTU the container would notice.
    mgr.ensure_overlay_segment(&segment).await.unwrap();
    assert_overlay_bridge_state("satlnt-bo0", "satlnt-vx0", "10.79.0.2", "satlntc", "ovl");
    assert_in_jail_endpoint(
        "satlnt-ov1",
        &att.epair_b,
        "02:42:0a:4f:00:0b",
        "10.79.0.11",
    );
    assert_mtu_boundary("satlnt-ov1", "10.79.0.2");

    assert_marker_classification(
        &mgr,
        "ovl",
        "satlnt-bo0",
        &att.epair_a,
        task_id,
        "satlnt-vx0",
    )
    .await;

    // Graceful teardown: detach, then destroy the segment. The VTEP survives.
    mgr.detach_task_overlay(task_id, &att).await.unwrap();
    let (_, ifaces, _) = run("/sbin/ifconfig", &["-l"]);
    assert!(!ifaces.contains(&att.epair_a), "epair leaked: {ifaces}");
    mgr.detach_task_overlay(task_id, &att).await.unwrap(); // idempotent
    assert!(mgr.destroy_overlay_segment(&segment).await.unwrap());
    assert!(!mgr.destroy_overlay_segment(&segment).await.unwrap()); // idempotent
    let (_, ifaces, _) = run("/sbin/ifconfig", &["-l"]);
    assert!(!ifaces.contains("satlnt-bo0"), "bridge leaked: {ifaces}");
    assert!(
        ifaces.contains("satlnt-vx0"),
        "the VTEP belongs to satl-overlay and must survive: {ifaces}"
    );

    // Hand-created VTEP and jail go the same way they came.
    let (ok, _, err) = run("/usr/sbin/jail", &["-r", "satlnt-ov1"]);
    assert!(ok, "jail remove failed: {err}");
    let (ok, _, err) = run("/sbin/ifconfig", &["satlnt-vx0", "destroy"]);
    assert!(ok, "vtep destroy failed: {err}");
    audit_leftovers("satlntc");
}

/// The interrupted-teardown path: a jail dies with its epair still attached
/// (CLAUDE.md's epair leak, which for an overlay also leaves a member on the
/// bridge), and the sweep cleans up without ever touching the VTEP.
#[tokio::test]
#[ignore = "requires root and creates real interfaces and jails (make integration)"]
async fn overlay_sweep_reclaims_orphans_and_preserves_the_vtep() {
    assert!(is_root(), "integration tests must run as root");
    let dir = tempfile::tempdir().unwrap();
    let _vtep_guard = IfaceGuard("satlnt-vx1");
    let _bridge_guard = IfaceGuard("satlnt-bo1");
    let _jail_guard = JailGuard("satlnt-ov2");
    create_test_vtep("satlnt-vx1", 9972, "satlntd", "ovl2");

    let mgr = NetworkManager::open(config(
        dir.path(),
        "satlntd",
        "satlnt-bl1",
        "satlntd",
        "10.77.0.0/16",
    ))
    .unwrap();
    let segment = OverlaySegment::new(
        "ovl2",
        9972,
        "satlnt-vx1",
        "10.79.1.0/24".parse().unwrap(),
        "10.79.1.3".parse().unwrap(),
        1450,
    );
    // The VNI-derived bridge name is the convention; override it into the test
    // namespace so the audit can find leftovers.
    let segment = OverlaySegment {
        bridge: "satlnt-bo1".to_owned(),
        ..segment
    };
    mgr.ensure_overlay_segment(&segment).await.unwrap();

    let (ok, _, err) = run(
        "/usr/sbin/jail",
        &["-c", "name=satlnt-ov2", "vnet", "persist"],
    );
    assert!(ok, "jail create failed: {err}");
    let task_id = "ovltask0000000000000002x";
    let att = mgr
        .attach_task_overlay(
            &segment,
            &OverlayAttach::new(task_id, "satlnt-ov2", "10.79.1.11".parse().unwrap()),
        )
        .await
        .unwrap();

    // A sweep that still wants this task keeps everything.
    let desired: BTreeMap<String, BTreeSet<String>> =
        BTreeMap::from([("ovl2".to_owned(), BTreeSet::from([task_id.to_owned()]))]);
    let sweep = mgr.sweep_overlay(&desired).await.unwrap();
    assert!(sweep.destroyed_epairs.is_empty(), "{sweep:?}");
    assert!(sweep.destroyed_bridges.is_empty(), "{sweep:?}");
    assert!(
        sweep.adopted_bridges.contains(&"satlnt-bo1".to_owned()),
        "{sweep:?}"
    );
    assert!(
        sweep.preserved_vteps.contains(&"satlnt-vx1".to_owned()),
        "{sweep:?}"
    );

    // Now kill the jail without detaching: the b end auto-returns to the host
    // with only its description left, and the a end is still bridged.
    let (ok, _, err) = run("/usr/sbin/jail", &["-r", "satlnt-ov2"]);
    assert!(ok, "jail remove failed: {err}");
    let (_, ifaces, _) = run("/sbin/ifconfig", &["-l"]);
    assert!(
        ifaces.contains(&att.epair_b),
        "b end should be back: {ifaces}"
    );

    // Nothing is desired here any more: the epairs and the bridge go, the VTEP
    // stays.
    let sweep = mgr.sweep_overlay(&BTreeMap::new()).await.unwrap();
    assert!(
        sweep.destroyed_epairs.contains(&att.epair_a)
            || sweep.destroyed_epairs.contains(&att.epair_b),
        "{sweep:?}"
    );
    assert_eq!(sweep.destroyed_bridges, ["satlnt-bo1"], "{sweep:?}");
    assert_eq!(sweep.preserved_vteps, ["satlnt-vx1"], "{sweep:?}");
    let (_, ifaces, _) = run("/sbin/ifconfig", &["-l"]);
    assert!(!ifaces.contains(&att.epair_a), "{ifaces}");
    assert!(!ifaces.contains(&att.epair_b), "{ifaces}");
    assert!(!ifaces.contains("satlnt-bo1"), "{ifaces}");
    assert!(
        ifaces.contains("satlnt-vx1"),
        "the VTEP must survive: {ifaces}"
    );

    let (ok, _, err) = run("/sbin/ifconfig", &["satlnt-vx1", "destroy"]);
    assert!(ok, "vtep destroy failed: {err}");
    audit_leftovers("satlntd");
}

/// The documented silent failure, against the real kernel: a second VTEP with
/// a VNI already in use on the same socket comes up `UP`, `status: active`, and
/// `ifconfig` exits 0 — with no `RUNNING` (`docs/vxlan.md` §2 point 5).
/// `ensure_overlay_segment` must refuse to bridge it and must create nothing,
/// because an overlay built on it looks correct and carries nothing.
#[tokio::test]
#[ignore = "requires root and creates real interfaces (make integration)"]
async fn ensure_refuses_a_vtep_that_is_up_but_not_running() {
    assert!(is_root(), "integration tests must run as root");
    let dir = tempfile::tempdir().unwrap();
    let _healthy_guard = IfaceGuard("satlnt-vx2");
    let _broken_guard = IfaceGuard("satlnt-vx3");
    let _bridge_guard = IfaceGuard("satlnt-bo2");
    // Same VNI, same vxlanlocal, same port: the duplicate-VNI check fires on
    // `up`, not on `create`, so the second interface is created happily.
    create_test_vtep("satlnt-vx2", 9973, "satlnte", "ovl3");
    let (ok, clone, err) = run(
        "/sbin/ifconfig",
        &[
            "vxlan",
            "create",
            "vxlanid",
            "9973",
            "vxlanlocal",
            "127.0.0.1",
            "vxlanremote",
            "127.0.0.254",
            "-vxlanlearn",
        ],
    );
    assert!(ok, "vxlan create failed: {err}");
    let clone = clone.trim();
    let (ok, _, err) = run("/sbin/ifconfig", &[clone, "name", "satlnt-vx3"]);
    assert!(ok, "vxlan rename failed: {err}");
    let (ok, _, err) = run(
        "/sbin/ifconfig",
        &["satlnt-vx3", "description", "satlnte:vxlan:ovl3"],
    );
    assert!(ok, "vxlan description failed: {err}");
    // `ifconfig` reports success here — that is the whole point.
    let (ok, _, _) = run("/sbin/ifconfig", &["satlnt-vx3", "up"]);
    assert!(
        ok,
        "ifconfig lies about success for a refused vxlan interface"
    );
    let (_, show, _) = run("/sbin/ifconfig", &["satlnt-vx3"]);
    eprintln!("--- a VTEP the driver refused ---\n{show}");
    let header = show.lines().next().unwrap_or_default();
    assert!(header.contains("UP"), "{show}");
    assert!(!header.contains("RUNNING"), "{show}");
    assert!(show.contains("status: active"), "{show}");

    let mgr = NetworkManager::open(config(
        dir.path(),
        "satlnte",
        "satlnt-bl2",
        "satlnte",
        "10.77.0.0/16",
    ))
    .unwrap();
    let segment = OverlaySegment {
        network: "ovl3".to_owned(),
        bridge: "satlnt-bo2".to_owned(),
        vtep: "satlnt-vx3".to_owned(),
        subnet: "10.79.2.0/24".parse().unwrap(),
        gateway: "10.79.2.4".parse().unwrap(),
        mtu: 1450,
    };
    let err = mgr.ensure_overlay_segment(&segment).await.unwrap_err();
    let text = err.to_string();
    assert!(text.contains("RUNNING is the only health signal"), "{text}");
    assert!(text.contains("/var/log/messages"), "{text}");
    // Nothing was built on top of it.
    let (_, ifaces, _) = run("/sbin/ifconfig", &["-l"]);
    assert!(!ifaces.contains("satlnt-bo2"), "{ifaces}");

    for iface in ["satlnt-vx2", "satlnt-vx3"] {
        let (ok, _, err) = run("/sbin/ifconfig", &[iface, "destroy"]);
        assert!(ok, "vtep destroy failed: {err}");
    }
    audit_leftovers("satlnte");
}

/// Live pf anchor load/flush roundtrip — cluster VMs only, double-gated:
/// `#[ignore]` *and* `SATL_PF_LIVE=1`. Never enable this on the shared dev
/// host (hard rule: `pfctl -n` dry runs only).
#[tokio::test]
#[ignore = "requires root, pf.ko, and SATL_PF_LIVE=1 (cluster VMs only)"]
async fn pf_live_anchor_roundtrip() {
    if std::env::var("SATL_PF_LIVE").as_deref() != Ok("1") {
        eprintln!("skipping: SATL_PF_LIVE=1 not set (live pf loads are VM-only)");
        return;
    }
    assert!(is_root(), "integration tests must run as root");
    let pf = PfCtl::system();
    let publishes = [PortPublish {
        proto: satl_core::PortProtocol::Tcp,
        host_port: 28080,
        task_ip: "10.88.0.2".parse().unwrap(),
        task_port: 80,
    }];
    let rules = satl_net::rdr_rules(&satl_net::pool_publishes(&publishes));
    pf.check_syntax(&rules).await.unwrap();
    pf.load_anchor(ANCHOR_RDR, &rules).await.unwrap();
    let shown = pf.show_anchor(ANCHOR_RDR).await.unwrap();
    assert!(shown.contains("28080"), "{shown}");

    // The table the rule points at starts empty: push the membership, read
    // it back, push a different one. This is the path every health-driven
    // pool change takes, and it must work without an anchor reload.
    pf.replace_table(
        ANCHOR_RDR,
        "satl_p28080_tcp_80",
        &["10.88.0.2".parse().unwrap()],
    )
    .await
    .unwrap();
    let members = pf
        .show_table(ANCHOR_RDR, "satl_p28080_tcp_80")
        .await
        .unwrap();
    assert!(members.contains("10.88.0.2"), "{members}");
    pf.replace_table(
        ANCHOR_RDR,
        "satl_p28080_tcp_80",
        &["10.88.0.9".parse().unwrap()],
    )
    .await
    .unwrap();
    let members = pf
        .show_table(ANCHOR_RDR, "satl_p28080_tcp_80")
        .await
        .unwrap();
    assert!(members.contains("10.88.0.9"), "{members}");
    assert!(!members.contains("10.88.0.2"), "{members}");
    // The ruleset itself never moved: still one table, one rule.
    let shown = pf.show_anchor(ANCHOR_RDR).await.unwrap();
    assert!(shown.matches("satl_p28080_tcp_80").count() >= 2, "{shown}");

    // `persist` tables survive a flush with their members (measured): a dead
    // pool's table must be killed explicitly.
    pf.flush_anchor(ANCHOR_RDR).await.unwrap();
    let members = pf
        .show_table(ANCHOR_RDR, "satl_p28080_tcp_80")
        .await
        .unwrap();
    assert!(
        members.contains("10.88.0.9"),
        "the persist table kept its members across the flush: {members}"
    );
    pf.kill_table(ANCHOR_RDR, "satl_p28080_tcp_80")
        .await
        .unwrap();
    let tables = {
        let (ok, out) = {
            let output = std::process::Command::new("/sbin/pfctl")
                .args(["-a", ANCHOR_RDR, "-s", "Tables"])
                .output()
                .expect("spawn pfctl");
            (
                output.status.success(),
                String::from_utf8_lossy(&output.stdout).into_owned(),
            )
        };
        assert!(ok);
        out
    };
    assert!(
        !tables.contains("satl_p28080_tcp_80"),
        "the killed table is gone: {tables}"
    );
    let shown = pf.show_anchor(ANCHOR_RDR).await.unwrap();
    assert!(!shown.contains("28080"), "{shown}");
}

/// On any host, the generated rulesets must pass a real `pfctl -nf -` parse
/// wherever pfctl can reach the kernel; hosts without pf.ko skip.
#[tokio::test]
#[ignore = "requires pfctl able to reach the kernel (pf.ko loaded)"]
async fn generated_rulesets_pass_real_pfctl() {
    let pf = PfCtl::system();
    let nat = satl_net::nat_rules("10.88.0.0/24".parse().unwrap(), "vtnet0");
    let rdr = satl_net::rdr_rules(&satl_net::pool_publishes(&[PortPublish {
        proto: satl_core::PortProtocol::Udp,
        host_port: 8053,
        task_ip: "10.88.0.3".parse().unwrap(),
        task_port: 53,
    }]));
    // Two tasks of one service on one node: one table-backed pool. Its own
    // case because `-> <table> port 80 round-robin` is a different production
    // of pf.conf's grammar than a bare redirect host, and the unit test that
    // would catch a wrong ordering skips wherever pfctl cannot reach the
    // kernel — which is every unprivileged run.
    let pool = satl_net::rdr_rules(&satl_net::pool_publishes(&[
        PortPublish {
            proto: satl_core::PortProtocol::Tcp,
            host_port: 18080,
            task_ip: "10.88.0.2".parse().unwrap(),
            task_port: 80,
        },
        PortPublish {
            proto: satl_core::PortProtocol::Tcp,
            host_port: 18080,
            task_ip: "10.88.0.3".parse().unwrap(),
            task_port: 80,
        },
    ]));
    assert!(pool.contains("round-robin"), "{pool}");
    // The mesh half, which nothing checked against a real pfctl until M12.
    // `rdr_rules` and `nat_rules` were covered and `mesh_rules` was not, so an
    // ordering or grammar mistake in the two productions only it emits -- a
    // table-sourced `nat pass` and a `match out ... scrub (max-mss n)` -- could
    // only be found on the cluster, where it looks like a data-plane bug rather
    // than a ruleset that pf refused.
    let mesh_egress = satl_net::MeshEgress {
        gateway: "10.100.0.2".parse().unwrap(),
        bridge: "satl-br4096".to_owned(),
        subnet: "10.100.0.0/24".parse().unwrap(),
        max_mss: 1410,
    };
    let publishes = satl_net::pool_publishes(&[PortPublish {
        proto: satl_core::PortProtocol::Tcp,
        host_port: 18080,
        task_ip: "10.88.0.2".parse().unwrap(),
        task_port: 80,
    }]);
    let mesh = satl_net::mesh_rules(&mesh_egress, &publishes);
    assert!(mesh.contains("nat pass"), "{mesh}");
    assert!(mesh.contains("max-mss 1410"), "{mesh}");

    // The rdr rules and the mesh rules share one anchor and are loaded as one
    // text, so the concatenation is what pf actually parses -- checking the
    // halves separately would miss an ordering rule between them.
    let combined = format!("{}{mesh}", satl_net::rdr_rules(&publishes));

    for rules in [nat, rdr, pool, mesh, combined] {
        match pf.check_syntax(&rules).await {
            Ok(()) => {}
            Err(PfError::Unavailable { .. }) => {
                eprintln!("skipping: pf unavailable on this host (pf.ko not loaded)");
                return;
            }
            Err(other) => panic!("pfctl rejected generated rules {rules:?}: {other}"),
        }
    }
}
