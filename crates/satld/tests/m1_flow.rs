// SPDX-License-Identifier: BSD-2-Clause
//! The M1 definition-of-done flow, end to end, against a real `satld`.
//!
//! One daemon, started as a child process from a temp config, driven **only**
//! over its unix socket with the Docker REST API — no in-process shortcuts,
//! so every layer is exercised the way `satl`/`docker` exercises it:
//!
//! ```text
//! POST /images/create      pull 127.0.0.1:5000/satl-test/freebsd-nginx
//! POST /containers/create  → service written, orchestrator creates the task
//! POST /containers/{id}/start
//!   → scheduler assigns → dispatcher → controller: clone, jail, epair, start
//!   → curl the workload
//! GET  /containers/json    the container is listed as running
//! GET  /containers/{id}/logs
//! POST /containers/{id}/exec + /exec/{id}/start
//! POST /containers/{id}/stop
//! DELETE /containers/{id}
//!   → leftovers audit: no jail, no dataset, no epair, no bundle, no logs
//! SIGTERM                  clean shutdown
//! ```
//!
//! A second test covers the other half of the M1 definition of done: a
//! container survives a daemon restart and is **re-attached** by startup
//! reconciliation rather than restarted.
//!
//! **Isolation** (CLAUDE.md). Everything is `wire-` prefixed and torn down by
//! a drop guard, on success and on panic alike:
//!
//! - sandbox dataset `zroot/satl-wire-<tag>-<pid>` (state dir = its
//!   mountpoint), so `zroot/satl` and the running production daemon are never
//!   touched;
//! - its own socket, its own raft/state directory;
//! - its own network name (`wire`, `rewire`), which decides the bridge name,
//!   the address pool and — most importantly — the ifconfig(8) interface
//!   group, since startup reconciliation destroys orphaned interfaces *in its
//!   own group only*;
//! - `pf_mode = "disabled"`: pf is never loaded on the dev host.
//!
//! The one artifact that cannot carry the prefix is the jail: the pinned M1
//! contract is *jail name = task ID*, so the guard remembers the ID instead.
//!
//! **Published ports vs. task IP.** The container is created with
//! `-p 18080:80`, which SatL turns into a `satl/rdr` pf rule — and pf is not
//! loaded here, so the host port is not reachable. The test therefore asserts
//! reachability on the **task's bridge address**, exactly as
//! `satl-agent/tests/task_lifecycle.rs` does, and additionally asserts that
//! the published port shows up in `docker ps`/`inspect` (which is the part
//! pf-less hosts can still verify).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CURL: &str = "/usr/local/bin/curl";
const ZFS: &str = "/sbin/zfs";
const IFCONFIG: &str = "/sbin/ifconfig";
const JLS: &str = "/usr/sbin/jls";
const JAIL: &str = "/usr/sbin/jail";

/// The milestone-1 definition-of-done image (`docs/image-sources.md`).
const IMAGE: &str = "127.0.0.1:5000/satl-test/freebsd-nginx";

/// Test networks. Each test owns one: the interface group is what startup
/// reconciliation sweeps, so two daemons must never share it. Neither is a
/// prefix of the production `satl`.
///
/// Each also owns a **manager port**. The default is 2377, and a dev host
/// running a real `satld` already holds it — without a port of its own a test
/// daemon dies at startup with `Address already in use`, which reads as a
/// broken test rather than as an occupied host. These are outside the
/// ephemeral range and away from 2377/2378.
const FLOW_NETWORK: Net = Net {
    name: "wire",
    pool: "10.83.0.0/16",
    port: 23_771,
};
const ADOPT_NETWORK: Net = Net {
    name: "rewire",
    pool: "10.86.0.0/16",
    port: 23_773,
};
const RMI_NETWORK: Net = Net {
    name: "unwire",
    pool: "10.89.0.0/16",
    port: 23_775,
};

/// A test network: its bridge is `<name>0` and its interface group `<name>`,
/// and `port` is the manager port its daemon listens on.
#[derive(Debug, Clone, Copy)]
struct Net {
    name: &'static str,
    pool: &'static str,
    port: u16,
}

/// Host port the container publishes (unreachable without pf; see the module
/// docs).
const HOST_PORT: u16 = 18_080;

/// Container (and service) name.
const NAME: &str = "wire_nginx";

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

fn run(program: &str, args: &[&str]) -> (bool, String) {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to spawn `{program} {}`: {err}", args.join(" ")));
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

fn assert_root() {
    let (_, uid) = run("/usr/bin/id", &["-u"]);
    assert_eq!(
        uid.trim(),
        "0",
        "this #[ignore] test must run as root (make integration)"
    );
}

/// One HTTP response from the daemon.
struct Response {
    status: u32,
    body: Vec<u8>,
}

impl Response {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|err| {
            panic!("response is not JSON ({err}): {}", self.text());
        })
    }

    #[track_caller]
    fn expect(self, want: u32, what: &str) -> Self {
        assert_eq!(
            self.status,
            want,
            "{what}: expected HTTP {want}, got {}: {}",
            self.status,
            self.text()
        );
        self
    }
}

/// Talk to the daemon over its unix socket. `curl` writes the body to a file
/// so binary (multiplexed) payloads survive intact and stdout carries only
/// the status code.
fn request(
    socket: &Path,
    scratch: &Path,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout: u64,
) -> Response {
    let out = scratch.join("response.bin");
    let url = format!("http://localhost{path}");
    let timeout = timeout.to_string();
    let mut args = vec![
        "-sS",
        "--unix-socket",
        socket.to_str().expect("utf-8 socket path"),
        "-X",
        method,
        "--max-time",
        &timeout,
        "-o",
        out.to_str().expect("utf-8 scratch path"),
        "-w",
        "%{http_code}",
    ];
    if let Some(body) = body {
        args.extend(["-H", "Content-Type: application/json", "-d", body]);
    }
    args.push(&url);
    let output = Command::new(CURL)
        .args(&args)
        .output()
        .expect("failed to spawn curl");
    assert!(
        output.status.success(),
        "curl {method} {path} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .unwrap_or_else(|err| panic!("curl did not report a status code for {path}: {err}"));
    let body = std::fs::read(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    Response { status, body }
}

// ---------------------------------------------------------------------------
// The sandbox
// ---------------------------------------------------------------------------

/// Tears down everything the test created, on success and on panic alike.
struct Guard {
    daemon: Option<Child>,
    task_id: Option<String>,
    ocijail_root: PathBuf,
    sandbox: String,
    mountpoint: PathBuf,
    network: Net,
}

impl Drop for Guard {
    fn drop(&mut self) {
        // 1. The daemon (SIGKILL: the test already asserted clean shutdown).
        if let Some(mut daemon) = self.daemon.take()
            && daemon.try_wait().ok().flatten().is_none()
        {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }

        // 2. The jail, if the test died mid-flight.
        if let Some(task_id) = &self.task_id {
            let _ = Command::new("/usr/local/bin/ocijail")
                .arg("--root")
                .arg(&self.ocijail_root)
                .args(["delete", "--force", task_id])
                .output();
            let _ = Command::new(JAIL).args(["-r", task_id]).output();
        }

        // 3. Our interfaces (epairs first, then the bridge).
        let (_, members) = run(IFCONFIG, &["-g", self.network.name]);
        for iface in members.split_whitespace() {
            let _ = Command::new(IFCONFIG).args([iface, "destroy"]).output();
        }

        // 4. Anything still mounted under a container rootfs.
        if let Some(task_id) = &self.task_id {
            let rootfs = self.mountpoint.join("containers").join(task_id);
            for sub in ["dev/fd", "dev", "tmp"] {
                let _ = Command::new("/sbin/umount")
                    .arg("-f")
                    .arg(rootfs.join(sub))
                    .output();
            }
        }

        // 5. The sandbox dataset tree (-R also takes dependent clones).
        let destroyed = Command::new(ZFS)
            .args(["destroy", "-r", &self.sandbox])
            .status()
            .is_ok_and(|status| status.success())
            || Command::new(ZFS)
                .args(["destroy", "-R", &self.sandbox])
                .status()
                .is_ok_and(|status| status.success());
        assert!(
            destroyed,
            "clean up manually: zfs destroy -R {}",
            self.sandbox
        );
        let _ = std::fs::remove_dir_all(&self.mountpoint);
    }
}

/// Create the sandbox root dataset; satld's own preflight creates the
/// children, which is part of what this test verifies.
fn create_sandbox(tag: &str) -> (String, PathBuf) {
    let sandbox = format!("zroot/satl-wire-{tag}-{}", std::process::id());
    let mountpoint = PathBuf::from(format!("/tmp/{}", sandbox.replace('/', "-")));
    assert!(
        !Command::new(ZFS)
            .args(["list", "-H", "-o", "name", &sandbox])
            .output()
            .expect("zfs list")
            .status
            .success(),
        "sandbox dataset {sandbox} already exists; clean it up first"
    );
    let created = Command::new(ZFS)
        .args([
            "create",
            "-o",
            &format!("mountpoint={}", mountpoint.display()),
            &sandbox,
        ])
        .status()
        .expect("zfs create");
    assert!(created.success(), "cannot create the sandbox {sandbox}");
    (sandbox, mountpoint)
}

fn write_config(path: &Path, socket: &Path, state_dir: &Path, sandbox: &str, net: Net) {
    std::fs::write(
        path,
        format!(
            "socket_path = \"{socket}\"\n\
             state_dir = \"{state}\"\n\
             zfs_root = \"{sandbox}\"\n\
             node_name = \"wire-node\"\n\
             network_name = \"{network}\"\n\
             network_pool = \"{pool}\"\n\
             listen_addr = \"127.0.0.1:{port}\"\n\
             pf_mode = \"disabled\"\n",
            socket = socket.display(),
            state = state_dir.display(),
            network = net.name,
            pool = net.pool,
            port = net.port,
        ),
    )
    .expect("write config");
}

/// Start the daemon and wait until its socket answers.
fn spawn_daemon(config: &Path, socket: &Path) -> Child {
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_satld"))
        .arg("--config")
        .arg(config)
        .arg("--log-level")
        .arg("info")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn satld");
    wait_for_socket(socket, &mut daemon);
    daemon
}

/// SIGTERM the daemon and assert it exited cleanly.
fn stop_daemon(mut daemon: Child) {
    assert!(
        Command::new("kill")
            .arg(daemon.id().to_string())
            .status()
            .expect("kill")
            .success(),
        "failed to send SIGTERM to satld"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = daemon.try_wait().expect("try_wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "satld did not exit within 30s of SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(status.success(), "satld exited uncleanly: {status}");
}

fn wait_for_socket(socket: &Path, daemon: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = daemon.try_wait().expect("try_wait") {
            panic!("satld exited early with {status}");
        }
        if std::os::unix::net::UnixStream::connect(socket).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "satld never listened on {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Poll `check` until it holds, or fail with `what`.
fn eventually(what: &str, timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    loop {
        if check() {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[test]
#[ignore = "integration: root, ZFS, ocijail and the local test registry (make integration)"]
#[allow(clippy::too_many_lines)]
fn m1_container_lifecycle_over_the_rest_api() {
    assert_root();
    assert!(Path::new(CURL).exists(), "{CURL} is missing");

    let net = FLOW_NETWORK;
    let (sandbox, mountpoint) = create_sandbox("flow");
    let dir = tempfile::Builder::new()
        .prefix("wire-satld-")
        .tempdir()
        .expect("tempdir");
    let socket = dir.path().join("satl.sock");
    let config = dir.path().join("satld.toml");
    // The state dir is the sandbox mountpoint, exactly as production has
    // /var/db/satl be the mountpoint of zroot/satl.
    write_config(&config, &socket, &mountpoint, &sandbox, net);

    let mut guard = Guard {
        daemon: None,
        task_id: None,
        ocijail_root: mountpoint.join("ocijail"),
        sandbox: sandbox.clone(),
        mountpoint: mountpoint.clone(),
        network: net,
    };
    guard.daemon = Some(spawn_daemon(&config, &socket));

    let api = |method: &str, path: &str, body: Option<&str>, timeout: u64| {
        request(&socket, dir.path(), method, path, body, timeout)
    };

    // ---- the daemon is up and knows itself -------------------------------
    let info = api("GET", "/v1.43/info", None, 10)
        .expect(200, "GET /info")
        .json();
    assert_eq!(info["Driver"], "zfs");
    assert_eq!(info["Containers"], 0);

    // ---- pull ------------------------------------------------------------
    let pull = api(
        "POST",
        &format!("/v1.43/images/create?fromImage={IMAGE}&tag=latest"),
        None,
        300,
    )
    .expect(200, "POST /images/create");
    let pull_body = pull.text();
    assert!(
        !pull_body.contains("\"error\""),
        "the pull reported an error: {pull_body}"
    );
    assert!(
        pull_body.contains("Downloaded newer image"),
        "the pull did not complete: {pull_body}"
    );

    let images = api("GET", "/v1.43/images/json", None, 10)
        .expect(200, "GET /images/json")
        .json();
    let images = images.as_array().expect("an array of images");
    assert_eq!(images.len(), 1, "{images:?}");
    assert!(
        images[0]["RepoTags"][0]
            .as_str()
            .is_some_and(|tag| tag.contains("satl-test/freebsd-nginx")),
        "{images:?}"
    );

    // ---- create ----------------------------------------------------------
    let created = api(
        "POST",
        &format!("/v1.43/containers/create?name={NAME}"),
        Some(&format!(
            r#"{{"Image":"{IMAGE}:latest",
                 "HostConfig":{{"PortBindings":{{"80/tcp":[{{"HostPort":"{HOST_PORT}"}}]}}}}}}"#
        )),
        30,
    )
    .expect(201, "POST /containers/create")
    .json();
    let id = created["Id"].as_str().expect("a container id").to_owned();
    assert_eq!(id.len(), 25, "the container id is the task id: {id}");
    guard.task_id = Some(id.clone());

    // A created container is not running yet, and is only listed with ?all=1.
    let inspect = api("GET", &format!("/v1.43/containers/{id}/json"), None, 10)
        .expect(200, "GET /containers/{id}/json")
        .json();
    assert_eq!(inspect["Name"], format!("/{NAME}"));
    assert_eq!(inspect["State"]["Status"], "created");
    let listed = api("GET", "/v1.43/containers/json", None, 10)
        .expect(200, "GET /containers/json")
        .json();
    assert_eq!(listed.as_array().map(Vec::len), Some(0), "{listed:?}");
    let listed = api("GET", "/v1.43/containers/json?all=1", None, 10)
        .expect(200, "GET /containers/json?all=1")
        .json();
    assert_eq!(listed.as_array().map(Vec::len), Some(1), "{listed:?}");

    // ---- start -----------------------------------------------------------
    api("POST", &format!("/v1.43/containers/{id}/start"), None, 120)
        .expect(204, "POST /containers/{id}/start");
    // Starting is asynchronous: the store write is what start returns on.
    eventually(
        "the container to report running",
        Duration::from_mins(2),
        || {
            let state = api("GET", &format!("/v1.43/containers/{id}/json"), None, 10).json();
            state["State"]["Running"] == serde_json::Value::Bool(true)
        },
    );

    let inspect = api("GET", &format!("/v1.43/containers/{id}/json"), None, 10)
        .expect(200, "inspect running")
        .json();
    assert_eq!(inspect["State"]["Status"], "running");
    let ip = inspect["NetworkSettings"]["IPAddress"]
        .as_str()
        .expect("the task address")
        .to_owned();
    assert!(ip.starts_with("10.83."), "unexpected task address {ip}");
    assert_eq!(inspect["NetworkSettings"]["Gateway"], "10.83.0.1");
    assert!(
        inspect["State"]["Pid"].as_i64().unwrap_or(0) > 0,
        "no container pid: {inspect}"
    );
    // A SatL extension: the jail id is in the inspect document.
    assert!(
        inspect["JailID"]
            .as_str()
            .is_some_and(|jid| !jid.is_empty()),
        "no jail id in inspect: {inspect}"
    );
    // The published port is recorded even though pf is not loaded here. It
    // lands with the RUNNING status's harvest, while STARTING already reads
    // as "running" above (api-compat #2) — so this can race the status round
    // trip and must poll, not sample once.
    let mut ports = serde_json::Value::Null;
    eventually(
        "the published port to reach the inspect document",
        Duration::from_secs(30),
        || {
            ports = api("GET", &format!("/v1.43/containers/{id}/json"), None, 10)
                .json()["NetworkSettings"]["Ports"]
                .clone();
            ports["80/tcp"][0]["HostPort"].as_str().is_some()
        },
    );
    assert_eq!(ports["80/tcp"][0]["HostPort"], HOST_PORT.to_string());

    // Jail name = task ID (pinned M1 contract).
    let (found, jail_name) = run(JLS, &["-j", &id, "name"]);
    assert!(found, "jail {id} must exist");
    assert_eq!(jail_name.trim(), id);

    // ---- the workload serves ---------------------------------------------
    // pf is disabled on this host, so the published host port is not
    // reachable; the task's bridge address is (see the module docs).
    let url = format!("http://{ip}/");
    let mut body = String::new();
    eventually(
        "nginx to serve on the task address",
        Duration::from_mins(1),
        || {
            let (ok, out) = run(CURL, &["-sS", "--max-time", "2", &url]);
            body = out;
            ok && body.contains("satl-test-ok")
        },
    );
    assert!(body.contains("satl-test-ok"), "{body}");

    // ---- logs ------------------------------------------------------------
    let logs = api(
        "GET",
        &format!("/v1.43/containers/{id}/logs?stdout=1&stderr=1"),
        None,
        30,
    )
    .expect(200, "GET /containers/{id}/logs");
    let log_text = logs.text();
    assert!(
        log_text.contains("nginx"),
        "the container's logs do not look like nginx output: {log_text:?}"
    );

    // ---- exec ------------------------------------------------------------
    let exec = api(
        "POST",
        &format!("/v1.43/containers/{id}/exec"),
        Some(r#"{"Cmd":["/bin/echo","satl-exec-ok"],"AttachStdout":true,"AttachStderr":true}"#),
        30,
    )
    .expect(201, "POST /containers/{id}/exec")
    .json();
    let exec_id = exec["Id"].as_str().expect("an exec id").to_owned();
    let output = api(
        "POST",
        &format!("/v1.43/exec/{exec_id}/start"),
        Some(r#"{"Detach":false,"Tty":false}"#),
        60,
    )
    .expect(200, "POST /exec/{id}/start");
    assert!(
        output.text().contains("satl-exec-ok"),
        "exec output missing: {:?}",
        output.text()
    );
    let exec_state = api("GET", &format!("/v1.43/exec/{exec_id}/json"), None, 10)
        .expect(200, "GET /exec/{id}/json")
        .json();
    assert_eq!(exec_state["ExitCode"], 0, "{exec_state}");
    assert_eq!(exec_state["Running"], false, "{exec_state}");

    // ---- stop ------------------------------------------------------------
    api("POST", &format!("/v1.43/containers/{id}/stop"), None, 60)
        .expect(204, "POST /containers/{id}/stop");
    eventually(
        "the container to report exited",
        Duration::from_mins(1),
        || {
            let state = api("GET", &format!("/v1.43/containers/{id}/json"), None, 10).json();
            state["State"]["Status"] == "exited"
        },
    );
    // Stopping again changes nothing (Docker's 304).
    api("POST", &format!("/v1.43/containers/{id}/stop"), None, 30)
        .expect(304, "POST /containers/{id}/stop (again)");

    // ---- remove ----------------------------------------------------------
    api("DELETE", &format!("/v1.43/containers/{id}"), None, 60)
        .expect(204, "DELETE /containers/{id}");
    let listed = api("GET", "/v1.43/containers/json?all=1", None, 10)
        .expect(200, "GET /containers/json?all=1")
        .json();
    assert_eq!(listed.as_array().map(Vec::len), Some(0), "{listed:?}");
    api("GET", &format!("/v1.43/containers/{id}/json"), None, 10)
        .expect(404, "the removed container is gone");

    // ---- leftovers audit -------------------------------------------------
    // Resource release is asynchronous (the reaper deletes the object, the
    // dispatcher then tells the worker to let go), so poll.
    eventually("the jail to be gone", Duration::from_mins(1), || {
        !run(JLS, &["-j", &id, "name"]).0
    });
    eventually(
        "the container dataset to be gone",
        Duration::from_mins(1),
        || {
            let (_, datasets) = run(
                ZFS,
                &[
                    "list",
                    "-H",
                    "-o",
                    "name",
                    "-r",
                    &format!("{sandbox}/containers"),
                ],
            );
            datasets.trim() == format!("{sandbox}/containers")
        },
    );
    eventually("the task epairs to be gone", Duration::from_mins(1), || {
        let (_, members) = run(IFCONFIG, &["-g", net.name]);
        members.split_whitespace().collect::<Vec<_>>() == [format!("{}0", net.name)]
    });
    assert!(
        !mountpoint.join("bundles").join(&id).exists(),
        "the OCI bundle directory survived removal"
    );
    assert!(
        !mountpoint.join("logs").join(&id).exists(),
        "the log directory survived removal"
    );
    assert!(
        !mountpoint.join("worker").join("tasks").join(&id).exists(),
        "the local task db record survived removal"
    );
    // The image cache outlives its containers.
    let (_, layers) = run(
        ZFS,
        &[
            "list",
            "-H",
            "-o",
            "name",
            "-r",
            &format!("{sandbox}/layers"),
        ],
    );
    assert!(
        layers.lines().count() > 1,
        "the image's layer datasets should outlive the task: {layers}"
    );

    // ---- clean shutdown --------------------------------------------------
    stop_daemon(guard.daemon.take().expect("the daemon"));
    assert!(
        !socket.exists(),
        "the socket file must be removed on clean shutdown"
    );
}

/// Startup reconciliation, the other half of the M1 definition of done: a
/// container keeps running while `satld` is down and is **re-attached**, not
/// restarted, when it comes back (architecture §7.2).
#[test]
#[ignore = "integration: root, ZFS, ocijail and the local test registry (make integration)"]
fn a_running_container_is_readopted_after_a_daemon_restart() {
    assert_root();
    assert!(Path::new(CURL).exists(), "{CURL} is missing");

    let net = ADOPT_NETWORK;
    let (sandbox, mountpoint) = create_sandbox("adopt");
    let dir = tempfile::Builder::new()
        .prefix("wire-readopt-")
        .tempdir()
        .expect("tempdir");
    let socket = dir.path().join("satl.sock");
    let config = dir.path().join("satld.toml");
    write_config(&config, &socket, &mountpoint, &sandbox, net);

    let mut guard = Guard {
        daemon: None,
        task_id: None,
        ocijail_root: mountpoint.join("ocijail"),
        sandbox: sandbox.clone(),
        mountpoint: mountpoint.clone(),
        network: net,
    };
    guard.daemon = Some(spawn_daemon(&config, &socket));

    let api = |method: &str, path: &str, body: Option<&str>, timeout: u64| {
        request(&socket, dir.path(), method, path, body, timeout)
    };

    api(
        "POST",
        &format!("/v1.43/images/create?fromImage={IMAGE}&tag=latest"),
        None,
        300,
    )
    .expect(200, "POST /images/create");
    let created = api(
        "POST",
        "/v1.43/containers/create?name=rewire_nginx",
        Some(&format!(r#"{{"Image":"{IMAGE}:latest"}}"#)),
        30,
    )
    .expect(201, "POST /containers/create")
    .json();
    let id = created["Id"].as_str().expect("a container id").to_owned();
    guard.task_id = Some(id.clone());
    api("POST", &format!("/v1.43/containers/{id}/start"), None, 120)
        .expect(204, "POST /containers/{id}/start");
    eventually(
        "the container to report running",
        Duration::from_mins(2),
        || {
            let state = api("GET", &format!("/v1.43/containers/{id}/json"), None, 10).json();
            state["State"]["Running"] == serde_json::Value::Bool(true)
        },
    );
    let before = api("GET", &format!("/v1.43/containers/{id}/json"), None, 10)
        .expect(200, "inspect running")
        .json();
    let pid = before["State"]["Pid"].as_i64().unwrap_or(0);
    let ip = before["NetworkSettings"]["IPAddress"]
        .as_str()
        .expect("the task address")
        .to_owned();
    assert!(pid > 0, "no container pid: {before}");

    // ---- the daemon goes away; the container must not -----------------
    stop_daemon(guard.daemon.take().expect("the daemon"));
    assert!(
        run(JLS, &["-j", &id, "name"]).0,
        "the jail must survive the daemon: a running container is re-attached, not restarted"
    );

    // ---- and comes back ----------------------------------------------
    guard.daemon = Some(spawn_daemon(&config, &socket));
    let after = api("GET", &format!("/v1.43/containers/{id}/json"), None, 10)
        .expect(200, "inspect after restart")
        .json();
    assert_eq!(after["State"]["Status"], "running", "{after}");
    assert_eq!(
        after["State"]["Pid"].as_i64().unwrap_or(0),
        pid,
        "the container was restarted instead of re-attached"
    );
    assert_eq!(after["NetworkSettings"]["IPAddress"], ip);
    // Its epair survived the sweep: reconciliation only destroys interfaces
    // no live task claims.
    let (ok, body) = run(CURL, &["-sS", "--max-time", "5", &format!("http://{ip}/")]);
    assert!(
        ok && body.contains("satl-test-ok"),
        "the re-adopted container no longer serves: {body}"
    );

    // ---- and can still be driven -------------------------------------
    api(
        "DELETE",
        &format!("/v1.43/containers/{id}?force=1"),
        None,
        60,
    )
    .expect(204, "DELETE /containers/{id}?force=1");
    eventually("the jail to be gone", Duration::from_mins(1), || {
        !run(JLS, &["-j", &id, "name"]).0
    });
    eventually("the task epairs to be gone", Duration::from_mins(1), || {
        let (_, members) = run(IFCONFIG, &["-g", net.name]);
        members.split_whitespace().collect::<Vec<_>>() == [format!("{}0", net.name)]
    });

    stop_daemon(guard.daemon.take().expect("the daemon"));
}

/// `DELETE /images/{name}` end to end: the conflict arms, then a real removal
/// that takes the layer datasets with it.
///
/// The two things this exists to catch, neither of which a unit test can:
///
/// 1. **the removal really destroys ZFS datasets**, and only the right ones —
///    the whole point of running the two agreeing passes inside the request;
/// 2. **a running container's image cannot be removed even with `--force`**,
///    and a stopped one's can. That distinction is the api-compat 161 rule,
///    and it is decided from the store, so only a live daemon exercises it.
#[test]
#[ignore = "integration: root, ZFS, ocijail and the local test registry (make integration)"]
#[allow(clippy::too_many_lines)]
fn an_image_is_removed_with_its_layers_over_the_rest_api() {
    assert_root();
    assert!(Path::new(CURL).exists(), "{CURL} is missing");

    let net = RMI_NETWORK;
    let (sandbox, mountpoint) = create_sandbox("rmi");
    let dir = tempfile::Builder::new()
        .prefix("rmi-satld-")
        .tempdir()
        .expect("tempdir");
    let socket = dir.path().join("satl.sock");
    let config = dir.path().join("satld.toml");
    write_config(&config, &socket, &mountpoint, &sandbox, net);

    let mut guard = Guard {
        daemon: None,
        task_id: None,
        ocijail_root: mountpoint.join("ocijail"),
        sandbox: sandbox.clone(),
        mountpoint: mountpoint.clone(),
        network: net,
    };
    guard.daemon = Some(spawn_daemon(&config, &socket));

    let api = |method: &str, path: &str, body: Option<&str>, timeout: u64| {
        request(&socket, dir.path(), method, path, body, timeout)
    };

    // ---- pull ------------------------------------------------------------
    api(
        "POST",
        &format!("/v1.43/images/create?fromImage={IMAGE}&tag=latest"),
        None,
        300,
    )
    .expect(200, "POST /images/create");

    let layers_root = format!("{sandbox}/layers");
    // A pull writes blobs and metadata and *no datasets*: `satl-image` owns
    // bytes, `satl-storage` owns datasets, and the unpack happens when a task
    // prepares (architecture §9/§10). So the layer datasets appear below, once
    // a container has been created from this image -- not here.
    assert!(
        zfs_children(&layers_root).is_empty(),
        "a pull alone should not have unpacked anything under {layers_root}"
    );

    // Inspect answers now, and will 404 at the end: that is the observable
    // difference a removal makes to the store.
    let inspected = api(
        "GET",
        &format!("/v1.43/images/{IMAGE}:latest/json"),
        None,
        30,
    )
    .expect(200, "GET /images/{name}/json")
    .json();
    assert_eq!(inspected["RootFS"]["Type"], "layers");
    assert!(
        inspected["RepoTags"]
            .as_array()
            .is_some_and(|tags| tags.iter().any(|tag| tag == &format!("{IMAGE}:latest"))),
        "inspect should list the reference it was asked about: {inspected}"
    );

    // ---- a running container's image cannot be removed, forced or not ----
    let created = api(
        "POST",
        &format!("/v1.43/containers/create?name={NAME}"),
        Some(&format!(r#"{{"Image":"{IMAGE}:latest"}}"#)),
        60,
    )
    .expect(201, "POST /containers/create")
    .json();
    let task_id = created["Id"].as_str().expect("task id").to_owned();
    guard.task_id = Some(task_id.clone());
    api(
        "POST",
        &format!("/v1.43/containers/{task_id}/start"),
        None,
        120,
    )
    .expect(204, "POST /containers/{id}/start");

    // `start` only writes the desired state; the agent prepares and runs the
    // task asynchronously, and it is the *prepare* that unpacks the layers.
    eventually(
        "the container to report running",
        Duration::from_mins(2),
        || {
            let state = api(
                "GET",
                &format!("/v1.43/containers/{task_id}/json"),
                None,
                10,
            )
            .json();
            state["State"]["Running"] == serde_json::Value::Bool(true)
        },
    );

    // Now the image really is on disk as datasets. This is the set the removal
    // has to reclaim.
    let datasets_before = zfs_children(&layers_root);
    assert!(
        !datasets_before.is_empty(),
        "preparing a task from {IMAGE} should have unpacked layers under {layers_root}"
    );

    for query in ["", "?force=1"] {
        let refused = api(
            "DELETE",
            &format!("/v1.43/images/{IMAGE}:latest{query}"),
            None,
            30,
        )
        .expect(409, "DELETE while running");
        let message = refused.json()["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(
            message.contains("cannot be forced"),
            "a live claim is not forceable: {message}"
        );
        assert!(
            message.contains(&task_id) || message.contains("service"),
            "the refusal must name what holds it: {message}"
        );
    }
    // Nothing was destroyed by a refusal.
    assert_eq!(zfs_children(&layers_root), datasets_before);

    // ---- stopped: refused by default, forced through ---------------------
    api(
        "POST",
        &format!("/v1.43/containers/{task_id}/stop"),
        None,
        120,
    )
    .expect(204, "POST /containers/{id}/stop");

    // `stop`, like `start`, only writes the desired state. The claim stays
    // *live* until the task actually reaches a terminal state, which is the
    // distinction api-compat 161 turns on -- so waiting here is not a timing
    // workaround, it is the precondition of the assertion below.
    eventually(
        "the container to report exited",
        Duration::from_mins(1),
        || {
            let state = api(
                "GET",
                &format!("/v1.43/containers/{task_id}/json"),
                None,
                10,
            )
            .json();
            state["State"]["Status"] == "exited"
        },
    );

    let must_force = api("DELETE", &format!("/v1.43/images/{IMAGE}:latest"), None, 30)
        .expect(409, "DELETE while a stopped container references it")
        .json();
    assert!(
        must_force["message"]
            .as_str()
            .unwrap_or_default()
            .contains("must force"),
        "a terminal claim is forceable, and says so: {must_force}"
    );

    // ---- the real removal ------------------------------------------------
    let started = Instant::now();
    let removed = api(
        "DELETE",
        &format!("/v1.43/images/{IMAGE}:latest?force=1"),
        None,
        60,
    )
    .expect(200, "DELETE /images/{name}")
    .json();
    let elapsed = started.elapsed();

    // The two agreeing passes are 1.5 s apart *inside* the request; measuring
    // it here is what makes api-compat 155's "about a second and a half" a
    // fact rather than a claim.
    assert!(
        elapsed >= Duration::from_millis(1500),
        "the removal must run both layer passes, took {elapsed:?}"
    );

    let items = removed.as_array().expect("Docker's rmi array");
    assert!(
        items
            .iter()
            .any(|item| item["Untagged"] == format!("{IMAGE}:latest")),
        "the removal reports the reference it forgot: {removed}"
    );

    // The record is gone from both the listing and inspect.
    let listed = api("GET", "/v1.43/images/json", None, 30)
        .expect(200, "GET /images/json")
        .json();
    assert!(
        !listed.as_array().expect("array").iter().any(|image| {
            image["RepoTags"]
                .as_array()
                .is_some_and(|tags| tags.iter().any(|tag| tag == &format!("{IMAGE}:latest")))
        }),
        "the removed image is still listed: {listed}"
    );
    api(
        "GET",
        &format!("/v1.43/images/{IMAGE}:latest/json"),
        None,
        30,
    )
    .expect(404, "GET /images/{name}/json after removal");

    // ---- the layers survive, and that is the invariant, not a leak --------
    //
    // The stopped container's rootfs is a ZFS *clone* of the image's top
    // layer, so the chain is still claimed even though the image record that
    // named it has gone. `gc.rs`'s `a_layer_held_only_by_a_stopped_container_
    // is_never_collected` is exactly this, and the whole point of exercising
    // it here is that the *new* verb runs the same sweep and therefore obeys
    // the same claim -- a removal that destroyed these datasets would have
    // pulled the ground out from under a container the operator can still
    // start.
    assert_eq!(
        zfs_children(&layers_root),
        datasets_before,
        "the stopped container's clone still claims its chain: removing the \
         image record must not destroy it"
    );

    // ---- once nothing holds them, a prune reclaims them -------------------
    api("DELETE", &format!("/v1.43/containers/{task_id}"), None, 120)
        .expect(204, "DELETE /containers/{id}");
    guard.task_id = None;
    eventually(
        "the container's rootfs clone to go",
        Duration::from_mins(1),
        || zfs_children(&format!("{sandbox}/containers")).is_empty(),
    );

    api("POST", "/v1.43/images/prune", None, 120).expect(200, "POST /images/prune");
    let datasets_after = zfs_children(&layers_root);
    assert!(
        datasets_after.is_empty(),
        "with the record forgotten and the clone gone, nothing claims these \
         chains: before {datasets_before:?}, after {datasets_after:?}"
    );

    stop_daemon(guard.daemon.take().expect("the daemon"));
}

/// The immediate children of a ZFS dataset, sorted. Empty when it does not
/// exist, which is what "everything under it went" looks like.
fn zfs_children(dataset: &str) -> Vec<String> {
    let (ok, out) = run(
        "zfs",
        &["list", "-H", "-r", "-d", "1", "-o", "name", dataset],
    );
    if !ok {
        return Vec::new();
    }
    let mut rows: Vec<String> = out
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && *line != dataset)
        .map(ToOwned::to_owned)
        .collect();
    rows.sort();
    rows
}
