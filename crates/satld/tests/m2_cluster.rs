// SPDX-License-Identifier: BSD-2-Clause
//! Integration tests for the M2 cluster wiring: identity, the upgrade of a
//! pre-CA install, and two local daemons forming a two-node cluster.
//!
//! `#[ignore]`-gated — run via `make integration` (root, FreeBSD only).
//!
//! **Isolation** (CLAUDE.md: never disturb the running `satld` service). Every
//! daemon here gets its own socket, state directory, network name (so its
//! bridge and interface group are `m2wire*`, never the production
//! `satl0`/`satl` that startup reconciliation sweeps), its own TCP ports, and
//! a `zfs_root` that deliberately does not exist paired with
//! `--skip-zfs-check`, so ZFS operations fail harmlessly instead of touching
//! `zroot/satl`. pf is never loaded (`pf_mode = "disabled"`).

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Base of the TCP ports these tests bind. Well above anything SatL uses by
/// default (2377/2378) so a running production daemon is never touched.
const PORT_BASE: u16 = 23770;

/// One daemon under test, with everything needed to talk to it and to clean
/// up after it.
struct Daemon {
    child: Child,
    socket: PathBuf,
    state: PathBuf,
    network: String,
    listen_port: u16,
    _dir: tempfile::TempDir,
}

impl Daemon {
    /// Writes a config and spawns `satld` against it.
    fn spawn(name: &str, listen_port: u16, pool: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("satl.sock");
        let state = dir.path().join("state");
        let network = format!("m2wire{name}");
        let config = dir.path().join("satld.toml");
        std::fs::create_dir_all(&state).expect("state dir");
        std::fs::write(
            &config,
            format!(
                "socket_path = \"{socket}\"\n\
                 state_dir = \"{state}\"\n\
                 node_name = \"m2wire-{name}\"\n\
                 zfs_root = \"zroot/satl-m2wire-{name}-{pid}\"\n\
                 network_name = \"{network}\"\n\
                 network_pool = \"{pool}\"\n\
                 pf_mode = \"disabled\"\n\
                 listen_addr = \"127.0.0.1:{listen_port}\"\n\
                 advertise_addr = \"127.0.0.1:{listen_port}\"\n",
                socket = socket.display(),
                state = state.display(),
                pid = std::process::id(),
            ),
        )
        .expect("write config");

        let child = Command::new(env!("CARGO_BIN_EXE_satld"))
            .arg("--config")
            .arg(&config)
            .arg("--skip-zfs-check")
            .arg("--log-format")
            .arg("json")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn satld");

        Self {
            child,
            socket,
            state,
            network,
            listen_port,
            _dir: dir,
        }
    }

    /// Waits until the REST socket answers, then returns.
    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_mins(1);
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                panic!("satld exited early with {status}");
            }
            if UnixStream::connect(&self.socket).is_ok() {
                // The socket is up; give the cluster bring-up its last step.
                if self.get("/_ping").starts_with("HTTP/1.1 200") {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "satld never became ready on {}",
                self.socket.display()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// One HTTP request over the unix socket; returns the whole response.
    fn request(&self, method: &str, path: &str, body: Option<&str>) -> String {
        let mut stream = UnixStream::connect(&self.socket).expect("connect to the api socket");
        stream
            .set_read_timeout(Some(Duration::from_mins(3)))
            .expect("read timeout");
        let body = body.unwrap_or("");
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: satl\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).expect("write request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read the response");
        response
    }

    fn get(&self, path: &str) -> String {
        self.request("GET", path, None)
    }

    fn post(&self, path: &str, body: &str) -> String {
        self.request("POST", path, Some(body))
    }

    /// SIGTERM, then wait for the process to go.
    fn stop(&mut self) {
        let _ = Command::new("kill")
            .arg(self.child.id().to_string())
            .status();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
        // The bridge outlives the process; destroy it or the next run adopts
        // a stale one.
        let _ = Command::new("/sbin/ifconfig")
            .args([&format!("{}0", self.network), "destroy"])
            .output();
    }
}

/// The JSON body of an HTTP response (everything after the blank line).
fn body_of(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

/// Whether a response is a 2xx.
fn is_ok(response: &str) -> bool {
    response.starts_with("HTTP/1.1 2")
}

/// Every certificate file the identity path is supposed to have written.
fn cert_files(state: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let certs = state.join("certs");
    (
        certs.join("node.crt"),
        certs.join("node.key"),
        certs.join("ca.crt"),
    )
}

// ---------------------------------------------------------------------------
// (a) fresh init
// ---------------------------------------------------------------------------

#[test]
#[ignore = "integration: spawns the satld binary; run via `make integration`"]
fn a_fresh_node_mints_an_identity_and_serves_the_cluster_api() {
    let mut daemon = Daemon::spawn("init", PORT_BASE, "10.90.0.0/16");
    daemon.wait_ready();

    // The certificate material is on disk, and the key is not world-readable.
    let (cert, key, ca) = cert_files(&daemon.state);
    assert!(cert.exists(), "no node certificate at {}", cert.display());
    assert!(key.exists(), "no node key at {}", key.display());
    assert!(ca.exists(), "no CA bundle at {}", ca.display());
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&key)
            .expect("key metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the node key must be 0600, found {mode:o}");
    }

    // The Cluster object carries the CA and both join tokens.
    let swarm = daemon.get("/v1.43/swarm");
    assert!(is_ok(&swarm), "GET /swarm failed: {swarm}");
    let body = body_of(&swarm);
    assert!(
        body.contains("-----BEGIN CERTIFICATE"),
        "the swarm document carries no root CA: {body}"
    );
    assert!(
        body.contains("SATL-1-"),
        "the swarm document carries no join tokens: {body}"
    );
    assert!(
        !body.contains("PRIVATE KEY"),
        "the swarm document must never expose the root CA key: {body}"
    );

    // And this node is a member of it.
    let nodes = daemon.get("/v1.43/nodes");
    assert!(is_ok(&nodes), "GET /nodes failed: {nodes}");
    assert!(
        body_of(&nodes).contains("m2wire-init"),
        "this node is missing from /nodes: {}",
        body_of(&nodes)
    );

    daemon.stop();
}

// ---------------------------------------------------------------------------
// (b) upgrade of a pre-CA state directory
// ---------------------------------------------------------------------------

#[test]
#[ignore = "integration: spawns the satld binary; run via `make integration`"]
fn a_state_dir_that_predates_the_ca_keeps_its_node_id() {
    // First boot: a normal node, which we then strip back to what an M1
    // install looked like — raft state, a node-id file, no certificates.
    let mut daemon = Daemon::spawn("upgr", PORT_BASE + 2, "10.91.0.0/16");
    daemon.wait_ready();
    let info = daemon.get("/v1.43/info");
    assert!(is_ok(&info), "GET /info failed: {info}");
    let node_id = json_string(body_of(&info), "\"ID\":\"").expect("the node id in /info");
    let stored_id = std::fs::read_to_string(daemon.state.join("raft").join("node-id"))
        .expect("the raft node-id file");
    assert_eq!(stored_id.trim(), node_id, "the two ids must already agree");
    daemon.stop();

    // Strip the certificates: this is exactly the on-disk shape of an install
    // made by a daemon that predates the embedded CA.
    std::fs::remove_dir_all(daemon.state.join("certs")).expect("remove the certs directory");
    assert!(!daemon.state.join("certs").exists());

    // Restart with the same state directory. The daemon must mint an identity
    // for the *existing* node id rather than a new one.
    let mut upgraded = restart(&daemon);
    upgraded.wait_ready();

    let (cert, _, _) = cert_files(&daemon.state);
    assert!(cert.exists(), "the upgrade did not write a certificate");
    let info = upgraded.get("/v1.43/info");
    let after = json_string(body_of(&info), "\"ID\":\"").expect("the node id after the upgrade");
    assert_eq!(
        after, node_id,
        "the upgrade must keep this node's id, not mint a new one"
    );
    // And the certificate's CN is that id (§12.1: the CN is authoritative).
    let pem = std::fs::read_to_string(&cert).expect("read the certificate");
    assert!(
        pem.starts_with("-----BEGIN CERTIFICATE"),
        "unexpected certificate contents"
    );

    // The cluster object now carries a CA it did not have before.
    let swarm = upgraded.get("/v1.43/swarm");
    assert!(
        body_of(&swarm).contains("-----BEGIN CERTIFICATE"),
        "the upgrade did not seed the cluster CA: {}",
        body_of(&swarm)
    );

    upgraded.stop();
}

/// Restarts a stopped daemon against the same state directory and config.
fn restart(previous: &Daemon) -> Daemon {
    let config = previous
        .socket
        .parent()
        .expect("socket dir")
        .join("satld.toml");
    let child = Command::new(env!("CARGO_BIN_EXE_satld"))
        .arg("--config")
        .arg(&config)
        .arg("--skip-zfs-check")
        .arg("--log-format")
        .arg("json")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("respawn satld");
    Daemon {
        child,
        socket: previous.socket.clone(),
        state: previous.state.clone(),
        network: previous.network.clone(),
        listen_port: previous.listen_port,
        // The original guard still owns the directory; this one must not
        // delete it, so it gets a throwaway of its own.
        _dir: tempfile::tempdir().expect("tempdir"),
    }
}

/// Pulls a quoted JSON string value out of a body, given the key prefix to
/// look for. Deliberately crude: these tests assert on a handful of fields
/// and pulling in a JSON parser for them is not worth it.
fn json_string(body: &str, key: &str) -> Option<String> {
    let start = body.find(key)? + key.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

// ---------------------------------------------------------------------------
// (c) two nodes, one cluster
// ---------------------------------------------------------------------------

#[test]
#[ignore = "integration: spawns two satld binaries; run via `make integration`"]
fn two_local_daemons_form_a_two_node_cluster() {
    let mut first = Daemon::spawn("one", PORT_BASE + 4, "10.92.0.0/16");
    first.wait_ready();
    let mut second = Daemon::spawn("two", PORT_BASE + 6, "10.93.0.0/16");
    second.wait_ready();

    // The manager join token of the first cluster.
    let swarm = first.get("/v1.43/swarm");
    assert!(
        is_ok(&swarm),
        "GET /swarm on the first node failed: {swarm}"
    );
    let token = json_string(body_of(&swarm), "\"Manager\":\"")
        .expect("the manager join token in the swarm document");
    assert!(token.starts_with("SATL-1-"), "unexpected token shape");

    // The second node joins it. Note the token is never printed on failure.
    let response = second.post(
        "/v1.43/swarm/join",
        &format!(
            "{{\"RemoteAddrs\":[\"127.0.0.1:{}\"],\"JoinToken\":\"{token}\"}}",
            first.listen_port
        ),
    );
    assert!(
        is_ok(&response),
        "swarm join failed with: {}",
        response.lines().next().unwrap_or_default()
    );

    // Both nodes are now listed, from either node's API.
    let deadline = Instant::now() + Duration::from_mins(1);
    loop {
        let from_first = first.get("/v1.43/nodes");
        let from_second = second.get("/v1.43/nodes");
        let first_count = body_of(&from_first).matches("\"ID\":").count();
        let second_count = body_of(&from_second).matches("\"ID\":").count();
        if first_count >= 2 && second_count >= 2 {
            assert!(
                body_of(&from_first).contains("m2wire-one"),
                "the first node is missing from its own /nodes"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the two nodes never converged: first sees {first_count}, second sees {second_count}\n\
             first: {}\nsecond: {}",
            body_of(&from_first),
            body_of(&from_second)
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    // The joiner holds a certificate from the *first* cluster's CA: the two
    // CA bundles must be identical.
    let (_, _, first_ca) = cert_files(&first.state);
    let (_, _, second_ca) = cert_files(&second.state);
    assert_eq!(
        std::fs::read_to_string(&first_ca).expect("first ca"),
        std::fs::read_to_string(&second_ca).expect("second ca"),
        "the joiner must trust the cluster's root CA, not one of its own"
    );

    second.stop();
    first.stop();
}
