// SPDX-License-Identifier: BSD-2-Clause
//! **Measures** the claim the tighter published-service probe defaults exist to
//! make: how long a container that stops answering keeps its share of the
//! traffic (`docs/api-compat.md` #125-#128, `docs/operations.md` "Published
//! ports and healthchecks").
//!
//! One real `satld`, driven only over its unix socket, publishing a real
//! `pf` `rdr` rule for a real nginx jail:
//!
//! ```text
//! POST /services/create   healthcheck `test -f /tmp/serving`, -p 18081:80
//!   -> the tightened defaults are in the stored spec (5s / 3s / 2)
//!   -> marker created: the probe passes, the task reaches RUNNING
//!   -> the task address appears in the pool's pf table
//! marker removed         <- t0, the probe starts failing
//!   -> 2 failures: unhealthy -> the task is stopped and FAILED (#88)
//!   -> its address leaves the pool's table                      <- t1
//! assert and report t1 - t0
//! ```
//!
//! # Why this needs pf loaded, and what that costs
//!
//! The anchor and its pool tables are the measurement. `pf_mode = "check"`
//! would generate the
//! ruleset and never load it, so there would be nothing to observe: this
//! daemon runs with `pf_mode = "enforce"` and therefore **shares the host's
//! `satl/rdr` and `satl/nat` anchors** with any other `satld` -- there is one
//! anchor name, not one per network (`satl_net::pf::ANCHOR_RDR`). The test
//! refuses to run while another `satld` is alive for that reason, and because
//! both daemons' port sweeps would fight over the anchor every 5 s and each
//! would delete the other's rules -- which would make this measurement look
//! *better* than the truth. Both anchors are level-triggered, so the host's own
//! daemon re-derives them within one sweep of being started again.
//!
//! # Isolation, otherwise as `m1_flow.rs`
//!
//! Own sandbox dataset, own socket, own state dir, own network name (`hpool`,
//! so the bridge is `hpool0` and the interface group `hpool` -- never the
//! production `satl`), own TCP port (23791, so 2377 is left alone). Everything
//! is torn down by a drop guard on success and on panic.
//!
//! The daemon logs to **syslog**, as production does: the test then greps
//! `/var/log/messages` for the two lines an operator would grep for, which is
//! half of what is being verified. On a panic the guard prints the tail of
//! those lines, since there is no stderr to look at.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CURL: &str = "/usr/local/bin/curl";
const ZFS: &str = "/sbin/zfs";
const IFCONFIG: &str = "/sbin/ifconfig";
const JLS: &str = "/usr/sbin/jls";
const PFCTL: &str = "/sbin/pfctl";
const PGREP: &str = "/bin/pgrep";
const LOGGER: &str = "/usr/bin/logger";
const MESSAGES: &str = "/var/log/messages";

/// The definition-of-done image (`docs/image-sources.md`): nginx, which binds
/// its port a few hundred milliseconds after the jail starts.
const IMAGE: &str = "127.0.0.1:5000/satl-test/freebsd-nginx";

/// Network name: bridge `hpool0`, interface group `hpool`. Not a prefix of the
/// production `satl`, and its pool is used by no other test.
const NETWORK: &str = "hpool";
const POOL: &str = "10.87.0.0/16";

/// Internal listener. Not 2377: the host's own daemon may be using it, and
/// nothing here needs the default.
const LISTEN_PORT: u16 = 23_791;

/// The published port of the probed service, and of the unprobed one.
const PUBLISHED: u16 = 18_081;
const UNPROBED_PUBLISHED: u16 = 18_082;

/// The marker file the healthcheck looks for, inside the jail.
const MARKER: &str = "tmp/serving";

/// Node name, and the string to grep `/var/log/messages` by.
const NODE: &str = "hpool-node";

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

/// Put a line in `/var/log/messages` so the operator-facing timeline of this
/// measurement is in the same file as the daemon's own account of it.
fn mark_log(message: &str) {
    let _ = Command::new(LOGGER)
        .args(["-t", "satl-itest", message])
        .status();
}

/// Lines of `/var/log/messages` containing `needle`, as a fixed string.
///
/// `grep -a`, always: one non-ASCII byte anywhere in the file makes grep treat
/// it as binary and print nothing (CLAUDE.md). And `-F`, because every needle
/// here is a literal and one of them is `satld[<pid>]`, where the brackets
/// would otherwise be a character class matching three digits anywhere.
fn log_lines(needle: &str) -> Vec<String> {
    let (_, out) = run("/usr/bin/grep", &["-aF", needle, MESSAGES]);
    out.lines().map(str::to_owned).collect()
}

/// The live `satl/rdr` ruleset, as `pfctl` prints it.
fn rdr_anchor() -> String {
    let (ok, out) = run(PFCTL, &["-a", "satl/rdr", "-s", "nat"]);
    assert!(ok, "pfctl could not read the satl/rdr anchor");
    out
}

/// The live membership of one pool table, as `pfctl -T show` prints it.
///
/// Since M6c the task addresses live in pool **tables** (`satl_p<port>_<proto>_<cport>`),
/// not in the ruleset: "the task address is published" is read here, while the
/// ruleset only proves the `(port, proto, container port)` triple exists. A
/// table that does not exist (yet, or killed with its triple) reads as an
/// empty membership, not an error.
fn pool_members(published: u16) -> String {
    let (_, out) = run(
        PFCTL,
        &[
            "-a",
            "satl/rdr",
            "-t",
            &format!("satl_p{published}_tcp_80"),
            "-T",
            "show",
        ],
    );
    out
}

// ---------------------------------------------------------------------------
// The REST client (as `m1_flow.rs`: curl over the unix socket, nothing else)
// ---------------------------------------------------------------------------

struct Response {
    status: u32,
    body: Vec<u8>,
}

impl Response {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("response is not JSON ({err}): {}", self.text()))
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

/// Poll `check` until it holds, or fail with `what` and a pointer at the log --
/// this daemon's only output is syslog.
#[track_caller]
fn eventually(what: &str, timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    loop {
        if check() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {timeout:?} waiting for {what}; look at `grep -a {NODE} {MESSAGES}`"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// The sandbox
// ---------------------------------------------------------------------------

/// Tears down everything the test created, on success and on panic alike, and
/// on a panic also prints what the daemon said (there is no stderr: it logs to
/// syslog, as production does).
struct Guard {
    daemon: Option<Child>,
    task_id: Option<String>,
    ocijail_root: PathBuf,
    sandbox: String,
    mountpoint: PathBuf,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Grep by the daemon's **pid**, not by the node name: syslog stamps
            // every line `satld[<pid>]:`, while `hpool-node` appears only in
            // the startup banner and the cluster-init line. Measured
            // 2026-08-25: a run that timed out waiting for a task to become
            // healthy dumped exactly those two lines and nothing at all about
            // the task, which is the opposite of what a failure dump is for --
            // the diagnosis had to be redone by hand afterwards, and the
            // failure has not reproduced since, so the dump was the only
            // chance at it.
            let needle = self
                .daemon
                .as_ref()
                .map_or_else(|| NODE.to_owned(), |child| format!("satld[{}]", child.id()));
            eprintln!("--- last daemon lines (grep -aF '{needle}' {MESSAGES}) ---");
            for line in log_lines(&needle).iter().rev().take(80).rev() {
                eprintln!("{line}");
            }
            // And the task's whole life, by identity: the span chain is the
            // parent chain, so this is one task's story start to finish.
            if let Some(task_id) = &self.task_id {
                eprintln!("--- everything logged about task {task_id} ---");
                for line in log_lines(task_id) {
                    eprintln!("{line}");
                }
            }
            eprintln!("--- satl/rdr anchor now ---\n{}", rdr_anchor());
        }
        if let Some(mut daemon) = self.daemon.take()
            && daemon.try_wait().ok().flatten().is_none()
        {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
        if let Some(task_id) = &self.task_id {
            let _ = Command::new("/usr/local/bin/ocijail")
                .arg("--root")
                .arg(&self.ocijail_root)
                .args(["delete", "--force", task_id])
                .output();
            let _ = Command::new("/usr/sbin/jail")
                .args(["-r", task_id])
                .output();
        }
        let (_, members) = run(IFCONFIG, &["-g", NETWORK]);
        for iface in members.split_whitespace() {
            let _ = Command::new(IFCONFIG).args([iface, "destroy"]).output();
        }
        if let Some(task_id) = &self.task_id {
            let rootfs = self.mountpoint.join("containers").join(task_id);
            for sub in ["dev/fd", "dev", "tmp"] {
                let _ = Command::new("/sbin/umount")
                    .arg("-f")
                    .arg(rootfs.join(sub))
                    .output();
            }
        }
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

fn create_sandbox() -> (String, PathBuf) {
    let sandbox = format!("zroot/satl-hpool-{}", std::process::id());
    let mountpoint = PathBuf::from(format!("/tmp/{}", sandbox.replace('/', "-")));
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

/// Start the daemon and wait until its socket answers.
fn spawn_daemon(config: &Path, socket: &Path) -> Child {
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_satld"))
        .arg("--config")
        .arg(config)
        .args(["--log-level", "info", "--log-target", "syslog"])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn satld");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = daemon.try_wait().expect("try_wait") {
            panic!("satld exited early with {status}; see `grep -a {NODE} {MESSAGES}`");
        }
        if std::os::unix::net::UnixStream::connect(socket).is_ok() {
            return daemon;
        }
        assert!(
            Instant::now() < deadline,
            "satld never listened on {}; see `grep -a {NODE} {MESSAGES}`",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

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

// ---------------------------------------------------------------------------
// The bound this test asserts
// ---------------------------------------------------------------------------

/// Worst case, in seconds, from "the workload stops passing its probe" to "its
/// address is out of the anchor", with the tightened defaults (5 s interval,
/// 3 s timeout, 2 retries) and the default 10 s stop grace period:
///
/// - up to one cycle (`interval + timeout` = 8 s) before a probe can even
///   observe the failure -- a probe already in flight at t0 may have read the
///   marker before it went;
/// - `retries` further cycles for the verdict: 2 x 8 s;
/// - the task is then stopped: SIGTERM, and up to `stop_grace_period` (10 s)
///   before SIGKILL, because SatL takes an unhealthy task *out* by killing it
///   (api-compat #88) -- the address leaves the anchor when the container is
///   gone, not when the verdict lands;
/// - plus one port sweep (5 s) if the agent's own edge-triggered `pfctl` load
///   is what failed.
///
/// 3 x 8 + 10 + 5 = 39 s. The same arithmetic with Docker's defaults (30 s
/// interval, 30 s timeout, 3 retries) is 4 x 60 + 10 + 5 = 255 s, which is what
/// this change is worth. What is actually measured is far under the bound --
/// **9.967 s and 9.971 s** on two runs on the dev host, i.e. two 5 s intervals
/// plus about 3 ms of stop and `pfctl`, because nginx answers SIGTERM at once
/// and both failing probes returned immediately. The bound is asserted and the
/// measurement reported, rather than the measurement asserted tightly: a loaded
/// box is allowed to be slow, and a test that fails on a slow box teaches
/// nothing about the pool.
const ANCHOR_DROP_BOUND: Duration = Duration::from_secs(39);

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[test]
#[ignore = "integration: root, ZFS, ocijail, pf and the local test registry (make integration)"]
#[allow(clippy::too_many_lines)]
fn an_unhealthy_published_task_leaves_the_rdr_anchor_within_the_measured_bound() {
    assert_root();
    assert!(Path::new(CURL).exists(), "{CURL} is missing");

    // pf is the instrument here: without it there is no anchor to observe.
    let (pf_ok, _) = run(PFCTL, &["-s", "info"]);
    if !pf_ok {
        eprintln!("skipping: pf is not enabled on this host, so there is no satl/rdr anchor");
        return;
    }
    // One anchor per host, not one per network: two daemons in `enforce` mode
    // would each delete the other's rules every 5 s, and this measurement would
    // come out better than the truth.
    let (_, others) = run(PGREP, &["-x", "satld"]);
    assert!(
        others.trim().is_empty(),
        "another satld is running (pids {}); stop it for this test: `service satld stop`, and \
         start it again afterwards -- it re-derives the satl/rdr and satl/nat anchors on startup",
        others.split_whitespace().collect::<Vec<_>>().join(" ")
    );

    let (sandbox, mountpoint) = create_sandbox();
    let dir = tempfile::Builder::new()
        .prefix("hpool-satld-")
        .tempdir()
        .expect("tempdir");
    let socket = dir.path().join("satl.sock");
    let config = dir.path().join("satld.toml");
    std::fs::write(
        &config,
        format!(
            "socket_path = \"{socket}\"\n\
             state_dir = \"{state}\"\n\
             zfs_root = \"{sandbox}\"\n\
             node_name = \"{NODE}\"\n\
             network_name = \"{NETWORK}\"\n\
             network_pool = \"{POOL}\"\n\
             pf_mode = \"enforce\"\n\
             listen_addr = \"127.0.0.1:{LISTEN_PORT}\"\n\
             advertise_addr = \"127.0.0.1:{LISTEN_PORT}\"\n",
            socket = socket.display(),
            state = mountpoint.display(),
        ),
    )
    .expect("write config");

    let mut guard = Guard {
        daemon: None,
        task_id: None,
        ocijail_root: mountpoint.join("ocijail"),
        sandbox: sandbox.clone(),
        mountpoint: mountpoint.clone(),
    };
    mark_log("health_pool: starting the daemon under test");
    guard.daemon = Some(spawn_daemon(&config, &socket));

    let api = |method: &str, path: &str, body: Option<&str>, timeout: u64| {
        request(&socket, dir.path(), method, path, body, timeout)
    };

    // ---- the image --------------------------------------------------------
    let pull = api(
        "POST",
        &format!("/v1.43/images/create?fromImage={IMAGE}&tag=latest"),
        None,
        300,
    )
    .expect(200, "POST /images/create");
    assert!(
        !pull.text().contains("\"error\""),
        "the pull reported an error: {}",
        pull.text()
    );

    // ---- a published service with a probe ---------------------------------
    // `StartPeriod` is generous on purpose: the marker the probe looks for can
    // only be created once the task's rootfs exists, so early failures must not
    // count. Interval, timeout and retries are left unset -- that is the case
    // under test.
    let created = api(
        "POST",
        "/v1.43/services/create",
        Some(&format!(
            r#"{{"Name":"hpool_web",
                 "TaskTemplate":{{
                   "ContainerSpec":{{"Image":"{IMAGE}:latest",
                     "Healthcheck":{{"Test":["CMD-SHELL","test -f /{MARKER}"],
                                     "StartPeriod":180000000000}}}},
                   "RestartPolicy":{{"Condition":"none"}}}},
                 "Mode":{{"Replicated":{{"Replicas":1}}}},
                 "EndpointSpec":{{"Ports":[{{"Protocol":"tcp","TargetPort":80,
                   "PublishedPort":{PUBLISHED},"PublishMode":"ingress"}}]}}}}"#
        )),
        60,
    )
    .expect(201, "POST /services/create")
    .json();
    let service_id = created["ID"].as_str().expect("a service id").to_owned();
    assert!(
        created["Warnings"].as_array().is_none_or(Vec::is_empty),
        "a service with a healthcheck must not be warned about: {created}"
    );

    // The tightened defaults are in the *stored* spec, so an operator can read
    // them (api-compat #125) instead of guessing.
    let stored = api("GET", &format!("/v1.43/services/{service_id}"), None, 10)
        .expect(200, "GET /services/{id}")
        .json();
    let check = &stored["Spec"]["TaskTemplate"]["ContainerSpec"]["Healthcheck"];
    assert_eq!(check["Interval"], 5_000_000_000_i64, "{check}");
    assert_eq!(check["Timeout"], 3_000_000_000_i64, "{check}");
    assert_eq!(check["Retries"], 2, "{check}");
    assert_eq!(check["StartPeriod"], 180_000_000_000_i64, "{check}");

    // ---- the task, and the marker that makes its probe pass ---------------
    let mut task_id = String::new();
    eventually(
        "the orchestrator to create a task",
        Duration::from_mins(1),
        || {
            let tasks = api("GET", "/v1.43/tasks", None, 10).json();
            let Some(first) = tasks.as_array().and_then(|tasks| tasks.first()) else {
                return false;
            };
            task_id = first["ID"].as_str().unwrap_or_default().to_owned();
            !task_id.is_empty()
        },
    );
    guard.task_id = Some(task_id.clone());
    let marker = mountpoint.join("containers").join(&task_id).join(MARKER);

    // The rootfs is a clone of the image's top snapshot and `/tmp` is mounted
    // over it, so the file can only be created once the jail has been built --
    // which is exactly why the healthcheck gets a long start period.
    eventually(
        "the container rootfs and its /tmp mount",
        Duration::from_mins(3),
        || marker.parent().is_some_and(Path::is_dir),
    );
    std::fs::write(&marker, b"serving\n").expect("create the health marker");
    mark_log(&format!("health_pool: marker created for task {task_id}"));

    // The probe passing is what releases the RUNNING gate (api-compat #87), and
    // RUNNING is what makes the port publishable.
    eventually(
        "the task to be healthy and running",
        Duration::from_mins(3),
        || {
            let state = api(
                "GET",
                &format!("/v1.43/containers/{task_id}/json"),
                None,
                10,
            )
            .json();
            state["State"]["Health"]["Status"] == "healthy" && state["State"]["Running"] == true
        },
    );
    let inspect = api(
        "GET",
        &format!("/v1.43/containers/{task_id}/json"),
        None,
        10,
    )
    .expect(200, "inspect the running task")
    .json();
    let bridge_addr = inspect["NetworkSettings"]["IPAddress"]
        .as_str()
        .expect("the task address")
        .to_owned();
    assert!(
        bridge_addr.starts_with("10.87."),
        "unexpected address {bridge_addr}"
    );
    // M6d: what the pool holds is the task's *ingress* attachment address —
    // the mesh routes to it whether the task is local or remote, and the
    // bridge address is only the pre-attachment fallback. The ingress
    // network exists because the service publishes an ingress port (SWK
    // §9.3, created by the allocator).
    let mut task_addr = String::new();
    eventually(
        "the task's ingress attachment address to be allocated",
        Duration::from_secs(30),
        || {
            let network = api("GET", "/v1.43/networks/ingress", None, 10).json();
            if let Some(cidr) = network["Containers"][task_id.as_str()]["IPv4Address"].as_str() {
                task_addr = cidr.split('/').next().unwrap_or(cidr).to_owned();
            }
            !task_addr.is_empty()
        },
    );

    // ---- the redirect is live ---------------------------------------------
    eventually(
        "the task address to appear in the pool table",
        Duration::from_secs(30),
        || pool_members(PUBLISHED).contains(&task_addr),
    );
    let anchor = rdr_anchor();
    assert!(
        anchor.contains(&PUBLISHED.to_string()) && anchor.contains("satl_p18081_tcp_80"),
        "the static rule for {PUBLISHED} is not in the anchor:\n{anchor}"
    );
    assert!(
        pool_members(PUBLISHED).contains(&task_addr),
        "the task address {task_addr} is not in the pool table"
    );

    // ---- the measurement --------------------------------------------------
    // t0 is the moment the workload stops passing its probe. Nothing else
    // changes: the container keeps running, keeps its address, and keeps its
    // place in the pool until health takes it out.
    mark_log(&format!(
        "health_pool: removing the marker for task {task_id} -- t0"
    ));
    let t0 = Instant::now();
    std::fs::remove_file(&marker).expect("remove the health marker");

    let deadline = t0 + ANCHOR_DROP_BOUND + Duration::from_secs(30);
    let elapsed = loop {
        if !pool_members(PUBLISHED).contains(&task_addr) {
            break t0.elapsed();
        }
        assert!(
            Instant::now() < deadline,
            "the address {task_addr} was still in the pool table {:?} after its probe started \
             failing; see `grep -a {task_id} {MESSAGES}`\n{}",
            t0.elapsed(),
            pool_members(PUBLISHED)
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let measured = format!(
        "health_pool: MEASURED probe-failure-to-anchor-drop {}.{:03}s for task {task_id} \
         (bound {}s)",
        elapsed.as_secs(),
        elapsed.subsec_millis(),
        ANCHOR_DROP_BOUND.as_secs()
    );
    mark_log(&measured);
    println!("{measured}");
    // Also on disk: `cargo test` captures stdout for a passing test, and this
    // number is the point of the whole test.
    let _ = std::fs::write(
        "/tmp/satl-health-pool-measurement.txt",
        format!("{measured}\n"),
    );
    assert!(
        elapsed <= ANCHOR_DROP_BOUND,
        "{measured}: over the bound justified in ANCHOR_DROP_BOUND"
    );

    // ---- what took it out of the pool -------------------------------------
    // Not "pf noticed": SatL's health verdict stopped the container and failed
    // the task (api-compat #88), and the anchor followed. The task carries the
    // streak and the probe's exit code, because "why did this die" must be
    // answerable from the task.
    eventually(
        "the task to be reported failed",
        Duration::from_mins(1),
        || {
            let task = api("GET", &format!("/v1.43/tasks/{task_id}"), None, 10).json();
            task["Status"]["State"] == "failed"
        },
    );
    let task = api("GET", &format!("/v1.43/tasks/{task_id}"), None, 10)
        .expect(200, "GET /tasks/{id}")
        .json();
    let err = task["Status"]["Err"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        err.contains("unhealthy") || err.contains("health"),
        "the failure does not say it was the healthcheck: {err:?}"
    );

    // ---- and the log says both halves, greppable by task id ---------------
    // The two lines an operator would look for, in the file CLAUDE.md points
    // at. Syslog is asynchronous, so poll rather than assume.
    eventually(
        "the health transition to reach /var/log/messages",
        Duration::from_secs(30),
        || {
            log_lines(&task_id)
                .iter()
                .any(|line| line.contains("task health changed") && line.contains("unhealthy"))
        },
    );
    eventually(
        "the anchor rewrite to reach /var/log/messages",
        Duration::from_secs(30),
        || {
            log_lines(&task_id).iter().any(|line| {
                line.contains("published ports removed") || line.contains("published ports")
            })
        },
    );
    let health_lines: Vec<String> = log_lines(&task_id)
        .into_iter()
        .filter(|line| line.contains("task health changed"))
        .collect();
    assert!(
        health_lines.iter().any(|line| line.contains("streak=2")),
        "the unhealthy line should carry the failing streak: {health_lines:?}"
    );

    // ---- the other half of the change: the warning ------------------------
    // Zero replicas: the warning is about the service's shape, not about a
    // running container, so nothing needs to be scheduled to provoke it.
    let bare = api(
        "POST",
        "/v1.43/services/create",
        Some(&format!(
            r#"{{"Name":"hpool_bare",
                 "TaskTemplate":{{"ContainerSpec":{{"Image":"{IMAGE}:latest"}}}},
                 "Mode":{{"Replicated":{{"Replicas":0}}}},
                 "EndpointSpec":{{"Ports":[{{"Protocol":"tcp","TargetPort":80,
                   "PublishedPort":{UNPROBED_PUBLISHED},"PublishMode":"ingress"}}]}}}}"#
        )),
        30,
    )
    .expect(201, "POST /services/create (no healthcheck)")
    .json();
    let warnings = bare["Warnings"]
        .as_array()
        .expect("a published service with no healthcheck is warned about")
        .iter()
        .filter_map(|warning| warning.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        warnings.contains("no healthcheck") && warnings.contains(&UNPROBED_PUBLISHED.to_string()),
        "the warning must name the port and the missing probe: {warnings}"
    );
    let bare_id = bare["ID"].as_str().expect("a service id").to_owned();
    api("DELETE", &format!("/v1.43/services/{bare_id}"), None, 30)
        .expect(200, "DELETE /services/{id}");

    // ---- teardown and the leftovers audit ---------------------------------
    api("DELETE", &format!("/v1.43/services/{service_id}"), None, 30)
        .expect(200, "DELETE /services/{id}");
    // The published services carried the ingress network into existence
    // (M6d, SWK §9.3), and this node's overlay segment for it — bridge, VTEP,
    // gateway — sits in this daemon's interface group. Remove it too, or the
    // epair audit below reads the segment as a leftover.
    api("DELETE", "/v1.43/networks/ingress", None, 30).expect(204, "DELETE /networks/ingress");
    eventually("the jail to be gone", Duration::from_mins(2), || {
        !run(JLS, &["-j", &task_id, "name"]).0
    });
    eventually(
        "the container dataset to be gone",
        Duration::from_mins(2),
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
        let (_, members) = run(IFCONFIG, &["-g", NETWORK]);
        members.split_whitespace().collect::<Vec<_>>() == [format!("{NETWORK}0")]
    });
    // The pf half of the audit: nothing of this test is left redirecting.
    eventually(
        "the satl/rdr anchor to be empty",
        Duration::from_secs(30),
        || {
            let anchor = rdr_anchor();
            !anchor.contains(&PUBLISHED.to_string())
                && !anchor.contains(&UNPROBED_PUBLISHED.to_string())
        },
    );
    assert!(
        !mountpoint.join("bundles").join(&task_id).exists(),
        "the OCI bundle directory survived removal"
    );
    assert!(
        !mountpoint.join("health").join(&task_id).exists(),
        "the probe's scratch directory survived removal"
    );

    mark_log("health_pool: done");
    stop_daemon(guard.daemon.take().expect("the daemon"));
    assert!(
        !socket.exists(),
        "the socket file must be removed on clean shutdown"
    );
}
