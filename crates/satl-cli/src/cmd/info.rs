// SPDX-License-Identifier: BSD-2-Clause
//! `satl info` -- what this daemon is, in `docker info`'s layout.
//!
//! `GET /info` is already the CLI's most-called endpoint (`node ls` marks the
//! local node with it, `swarm join` learns the role from it, `build` warns
//! about a node-local store with it); this verb is the one that shows an
//! operator what it says.
//!
//! **Sections SatL has no source for are omitted, never zeroed.** `docker
//! info` prints Logging Driver, Cgroup Driver, Runtimes, Registry, Live
//! Restore, Kernel Version, Security Options and the plugin lists; SatL has
//! none of those concepts (there is one runtime, `ocijail`, one storage
//! driver, ZFS, and no plugin system at all). A line reading `Logging Driver:
//! ` or `Kernel Version: 0` would read as a configured value rather than as
//! an absence, so those lines simply are not printed.

use std::fmt::Write as _;

use crate::api::cluster::SystemInfo;
use crate::client::{self, Host};
use crate::format;
use crate::output::Streams;

/// Flags of `satl info` -- none. `docker info`'s `-f/--format` would need a
/// Go template engine, which this CLI does not have.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct InfoArgs {}

/// Run `satl info`: `GET /info`, rendered.
pub async fn execute(host: &Host, _args: &InfoArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let info: SystemInfo = client::get_json(host, "/info").await?;
    streams.out(render(&info).as_bytes()).await;
    Ok(0)
}

/// `docker info`'s server section (pure, for goldens).
#[must_use]
#[allow(clippy::too_many_lines)] // One `writeln!` per line of a flat report.
pub fn render(info: &SystemInfo) -> String {
    let mut out = String::from("Server:\n");
    let _ = writeln!(out, " Containers: {}", info.containers);
    let _ = writeln!(out, "  Running: {}", info.containers_running);
    let _ = writeln!(out, "  Paused: {}", info.containers_paused);
    let _ = writeln!(out, "  Stopped: {}", info.containers_stopped);
    let _ = writeln!(out, " Images: {}", info.images);
    if !info.server_version.is_empty() {
        let _ = writeln!(out, " Server Version: {}", info.server_version);
    }
    if !info.driver.is_empty() {
        let _ = writeln!(out, " Storage Driver: {}", info.driver);
    }
    out.push_str(&swarm_section(info));
    if !info.operating_system.is_empty() {
        let _ = writeln!(out, " Operating System: {}", operating_system(info));
    }
    if !info.os_type.is_empty() {
        let _ = writeln!(out, " OSType: {}", info.os_type);
    }
    if !info.architecture.is_empty() {
        let _ = writeln!(out, " Architecture: {}", info.architecture);
    }
    let _ = writeln!(out, " CPUs: {}", info.ncpu);
    let _ = writeln!(out, " Total Memory: {}", format::human_size(info.mem_total));
    if !info.name.is_empty() {
        let _ = writeln!(out, " Name: {}", info.name);
    }
    if !info.id.is_empty() {
        let _ = writeln!(out, " ID: {}", info.id);
    }
    for warning in &info.warnings {
        let _ = writeln!(out, "WARNING: {warning}");
    }
    out
}

/// `Operating System`, Docker's full description: SatL serves the family and
/// the release separately, and Docker's single line is the two joined.
fn operating_system(info: &SystemInfo) -> String {
    if info.os_version.is_empty() {
        info.operating_system.clone()
    } else {
        format!("{} {}", info.operating_system, info.os_version)
    }
}

/// The `Swarm:` block. A node that is not a member gets the one-line form
/// docker prints (` Swarm: inactive`); the counters are manager-only, so they
/// are omitted when the daemon served zero rather than printed as zero.
fn swarm_section(info: &SystemInfo) -> String {
    let swarm = &info.swarm;
    let state = if swarm.local_node_state.is_empty() {
        "inactive"
    } else {
        swarm.local_node_state.as_str()
    };
    let mut out = format!(" Swarm: {state}\n");
    if swarm.node_id.is_empty() {
        return out;
    }
    let _ = writeln!(out, "  NodeID: {}", swarm.node_id);
    let _ = writeln!(out, "  Is Manager: {}", swarm.control_available);
    if swarm.managers > 0 {
        let _ = writeln!(out, "  Managers: {}", swarm.managers);
    }
    if swarm.nodes > 0 {
        let _ = writeln!(out, "  Nodes: {}", swarm.nodes);
    }
    if !swarm.node_addr.is_empty() {
        let _ = writeln!(out, "  Node Address: {}", swarm.node_addr);
    }
    if !swarm.remote_managers.is_empty() {
        out.push_str("  Manager Addresses:\n");
        for manager in &swarm.remote_managers {
            let _ = writeln!(out, "   {}", manager.addr);
        }
    }
    if !swarm.error.is_empty() {
        let _ = writeln!(out, "  Error: {}", swarm.error);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;
    use crate::stub::{Reply, Stub};

    const NODE: &str = "1hvy0lj3x0b883f8e30fyp217";

    fn manager_json() -> String {
        format!(
            r#"{{"ID":"XPTO:ABCD:1234","Name":"alpha","NCPU":8,"MemTotal":34359738368,
                "OperatingSystem":"FreeBSD","OSVersion":"15.1-RELEASE","OSType":"freebsd",
                "Architecture":"amd64","ServerVersion":"0.1.0","Driver":"zfs",
                "Containers":4,"ContainersRunning":2,"ContainersPaused":0,"ContainersStopped":2,
                "Images":6,
                "Swarm":{{"NodeID":"{NODE}","NodeAddr":"10.2.0.11","LocalNodeState":"active",
                  "ControlAvailable":true,"Error":"","Nodes":3,"Managers":1,
                  "RemoteManagers":[{{"NodeID":"{NODE}","Addr":"10.2.0.11:2377"}}]}},
                "Warnings":[]}}"#
        )
    }

    fn info(raw: &str) -> SystemInfo {
        serde_json::from_str(raw).expect("fixture parses")
    }

    #[test]
    fn manager_golden() {
        let expected = format!(
            "\
Server:
 Containers: 4
  Running: 2
  Paused: 0
  Stopped: 2
 Images: 6
 Server Version: 0.1.0
 Storage Driver: zfs
 Swarm: active
  NodeID: {NODE}
  Is Manager: true
  Managers: 1
  Nodes: 3
  Node Address: 10.2.0.11
  Manager Addresses:
   10.2.0.11:2377
 Operating System: FreeBSD 15.1-RELEASE
 OSType: freebsd
 Architecture: amd64
 CPUs: 8
 Total Memory: 34.36GB
 Name: alpha
 ID: XPTO:ABCD:1234
"
        );
        assert_eq!(render(&info(&manager_json())), expected);
    }

    /// Every omitted `docker info` section is omitted, not zeroed: a
    /// `Logging Driver:` with nothing after it reads as a configured value.
    #[test]
    fn sections_satl_has_no_source_for_are_absent() {
        let rendered = render(&info(&manager_json()));
        for absent in [
            "Logging Driver",
            "Cgroup Driver",
            "Runtimes",
            "Registry",
            "Live Restore",
            "Kernel Version",
            "Security Options",
            "Plugins",
        ] {
            assert!(
                !rendered.contains(absent),
                "{absent} must not be printed:\n{rendered}"
            );
        }
    }

    #[test]
    fn a_worker_omits_the_manager_only_counters() {
        let worker = format!(
            r#"{{"Name":"beta","ServerVersion":"0.1.0","Driver":"zfs",
                "Swarm":{{"NodeID":"{NODE}","NodeAddr":"10.2.0.12","LocalNodeState":"active",
                  "ControlAvailable":false,"Nodes":0,"Managers":0,"RemoteManagers":null}}}}"#
        );
        let rendered = render(&info(&worker));
        assert!(rendered.contains("  Is Manager: false"), "{rendered}");
        assert!(!rendered.contains("Managers:"), "{rendered}");
        assert!(!rendered.contains("Nodes:"), "{rendered}");
        assert!(!rendered.contains("Manager Addresses"), "{rendered}");
        assert!(rendered.contains("  Node Address: 10.2.0.12"), "{rendered}");
    }

    #[test]
    fn a_node_in_no_swarm_gets_dockers_one_line_form() {
        let alone = r#"{"Name":"solo","Swarm":{"LocalNodeState":"inactive"}}"#;
        let rendered = render(&info(alone));
        assert!(rendered.contains(" Swarm: inactive\n"), "{rendered}");
        assert!(!rendered.contains("NodeID"), "{rendered}");
    }

    #[test]
    fn an_empty_document_still_renders_the_counters() {
        let rendered = render(&info("{}"));
        assert!(
            rendered.starts_with("Server:\n Containers: 0\n"),
            "{rendered}"
        );
        assert!(rendered.contains(" Swarm: inactive\n"), "{rendered}");
        assert!(rendered.contains(" CPUs: 0\n"), "{rendered}");
        assert!(rendered.contains(" Total Memory: 0B\n"), "{rendered}");
        // Nothing the daemon did not send is invented.
        assert!(!rendered.contains("Server Version"), "{rendered}");
        assert!(!rendered.contains("Name:"), "{rendered}");
    }

    #[test]
    fn the_operating_system_line_joins_the_family_and_the_release() {
        let rendered = render(&info(
            r#"{"OperatingSystem":"FreeBSD","OSVersion":"15.1-RELEASE"}"#,
        ));
        assert!(
            rendered.contains(" Operating System: FreeBSD 15.1-RELEASE\n"),
            "{rendered}"
        );
        let rendered = render(&info(r#"{"OperatingSystem":"FreeBSD"}"#));
        assert!(
            rendered.contains(" Operating System: FreeBSD\n"),
            "{rendered}"
        );
    }

    #[test]
    fn daemon_warnings_are_printed_last() {
        let rendered = render(&info(r#"{"Warnings":["kern.racct.enable is 0"]}"#));
        assert!(
            rendered.ends_with("WARNING: kern.racct.enable is 0\n"),
            "{rendered}"
        );
    }

    #[test]
    fn a_swarm_error_is_shown() {
        let rendered = render(&info(&format!(
            r#"{{"Swarm":{{"NodeID":"{NODE}","LocalNodeState":"error","Error":"no leader"}}}}"#
        )));
        assert!(rendered.contains("  Error: no leader\n"), "{rendered}");
    }

    #[tokio::test]
    async fn info_reads_the_endpoint_once() {
        let stub = Stub::start().await;
        stub.on("GET", "/info", Reply::json(200, &manager_json()));

        let (mut streams, out, err) = testing::streams();
        let code = execute(&stub.host(), &InfoArgs::default(), &mut streams)
            .await
            .expect("info succeeds");
        assert_eq!(code, 0);
        assert_eq!(stub.routes(), vec!["GET /info"]);
        assert!(out.contents().contains("Name: alpha"), "{}", out.contents());
        assert!(err.contents().is_empty());
    }

    #[tokio::test]
    async fn info_surfaces_a_daemon_error() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/info",
            Reply::json(500, r#"{"message":"the ZFS root dataset is gone"}"#),
        );

        let (mut streams, out, _err) = testing::streams();
        let err = execute(&stub.host(), &InfoArgs::default(), &mut streams)
            .await
            .expect_err("a 500 is an error");
        assert_eq!(
            err.to_string(),
            "Error response from daemon: the ZFS root dataset is gone"
        );
        assert!(out.contents().is_empty());
    }
}
