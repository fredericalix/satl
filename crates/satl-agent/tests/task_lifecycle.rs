// SPDX-License-Identifier: BSD-2-Clause
//! Root-only end-to-end test of the task executor (`make integration`).
//!
//! One hand-built [`Task`] is driven through the real state machine
//! ([`do_step`]) against real subsystems — image pull from the local test
//! registry, ZFS layer/clone application, ocijail, and satl-net epair
//! plumbing — with **no orchestrator, no dispatcher and no manager**:
//!
//! ```text
//! ASSIGNED → ACCEPTED → PREPARING → READY → STARTING → RUNNING
//!   → curl http://<task ip>/ from the host  (expects "satl-test-ok")
//!   → desired SHUTDOWN → SHUTDOWN
//!   → Controller::remove()
//!   → leftovers audit (jail, mounts, epairs, datasets, dirs)
//! ```
//!
//! Conventions (CLAUDE.md): every artifact this test creates is `agtest-`
//! prefixed (sandbox dataset `zroot/satl-agtest-<pid>`, bridge `agtest0`,
//! interface group `agtest`, IPAM pool `10.79.0.0/16`) and lives in a
//! per-test tempdir, so the running `satld` service, `zroot/satl` and the
//! production `satl`/`satl0` names are never touched. pf is never loaded:
//! the network manager runs in [`PfMode::Disabled`], which is why the test
//! reaches the task on its bridge address rather than through a published
//! host port. A drop guard tears everything down even on panic.
//!
//! The one artifact that cannot carry the prefix is the jail: the pinned M1
//! contract is *jail name = task ID*, so the guard remembers the generated
//! ID instead.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use satl_agent::{
    Controller, Datasets, Executor, ExecutorParts, HostFacts, Rctl, Step, TaskController as _,
    do_step,
};
use satl_core::{
    Annotations, ContainerSpec, DesiredState, Id, Meta, Placement, ResourceRequirements,
    RestartPolicy, Task, TaskSpec, TaskState, TaskStatus,
};
use satl_image::ImageStore;
use satl_net::{NetworkManager, NetworkManagerConfig, PfMode, SubnetV4};
use satl_runtime::{Devfs, Jails, Mounts, OcijailRuntime, Runtime as _};
use satl_storage::{ContainerFsStore, LayerStore, VolumeStore, Zfs};

const ZFS_BIN: &str = "/sbin/zfs";
const IFCONFIG: &str = "/sbin/ifconfig";
const JLS: &str = "/usr/sbin/jls";
const JAIL: &str = "/usr/sbin/jail";
const UMOUNT: &str = "/sbin/umount";
const CURL: &str = "/usr/local/bin/curl";
const OCIJAIL: &str = "/usr/local/bin/ocijail";

/// The milestone-1 definition-of-done image, served by the local test registry (`docs/image-sources.md`).
const IMAGE: &str = "127.0.0.1:5000/satl-test/freebsd-nginx:latest";

/// Test-only network namespace, kept away from the production `satl`/`satl0`
/// names and satl-net's own `10.77`/`10.78` test pools.
const BRIDGE: &str = "agtest0";
const GROUP: &str = "agtest";
const NETWORK: &str = "agtest";
const POOL: &str = "10.79.0.0/16";

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

fn zfs_cmd(args: &[&str]) -> String {
    let output = Command::new(ZFS_BIN).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "`{ZFS_BIN} {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn assert_root() {
    let (_, uid) = run("/usr/bin/id", &["-u"]);
    assert_eq!(
        uid.trim(),
        "0",
        "this #[ignore] test must run as root (make integration)"
    );
}

/// Tears the whole test environment down, on success and on panic alike.
struct Guard {
    task_id: String,
    ocijail_root: PathBuf,
    rootfs: PathBuf,
    sandbox: String,
    sandbox_mountpoint: PathBuf,
}

impl Drop for Guard {
    fn drop(&mut self) {
        // 1. The jail (jail_remove returns in-jail epair ends to the host).
        let _ = Command::new(OCIJAIL)
            .arg("--root")
            .arg(&self.ocijail_root)
            .args(["delete", "--force", &self.task_id])
            .output();
        let _ = Command::new(JAIL).args(["-r", &self.task_id]).output();

        // 2. Every interface we own (epairs first, then the bridge).
        let (_, members) = run(IFCONFIG, &["-g", GROUP]);
        for iface in members.split_whitespace() {
            let _ = Command::new(IFCONFIG).args([iface, "destroy"]).output();
        }

        // 3. Anything still mounted under the container rootfs.
        for sub in ["run/secrets", "etc/agtest.conf", "dev/fd", "dev", "tmp"] {
            let _ = Command::new(UMOUNT)
                .arg("-f")
                .arg(self.rootfs.join(sub))
                .output();
        }

        // 4. The sandbox dataset tree (-R also takes dependent clones, which
        //    only survive when the test failed before `remove`).
        let destroyed = Command::new(ZFS_BIN)
            .args(["destroy", "-r", &self.sandbox])
            .status()
            .is_ok_and(|status| status.success())
            || Command::new(ZFS_BIN)
                .args(["destroy", "-R", &self.sandbox])
                .status()
                .is_ok_and(|status| status.success());
        assert!(
            destroyed,
            "clean up manually: zfs destroy -R {}",
            self.sandbox
        );
        let _ = std::fs::remove_dir_all(&self.sandbox_mountpoint);
    }
}

/// A single-replica task running the definition-of-done nginx image, as
/// `satl run` would build it (architecture §4: a standalone container is a
/// task too).
fn nginx_task(id: &Id) -> Task {
    Task {
        id: id.clone(),
        meta: Meta::new(),
        spec: TaskSpec {
            container: ContainerSpec {
                image: IMAGE.to_owned(),
                labels: std::collections::BTreeMap::new(),
                command: Vec::new(),
                args: Vec::new(),
                hostname: None,
                env: Vec::new(),
                dir: None,
                user: None,
                groups: Vec::new(),
                tty: false,
                open_stdin: false,
                read_only: false,
                stop_signal: None,
                stop_grace_period: Some(std::time::Duration::from_secs(5)),
                healthcheck: None,
                hosts: Vec::new(),
                dns_config: None,
                mounts: Vec::new(),
                secrets: Vec::new(),
                configs: Vec::new(),
                pull_options: None,
                platform: None,
            },
            resources: ResourceRequirements::default(),
            restart: RestartPolicy::default(),
            placement: Placement::default(),
            networks: Vec::new(),
            force_update: 0,
        },
        spec_version: None,
        service_id: None,
        slot: 1,
        node_id: None,
        annotations: Annotations {
            name: format!("agtest-nginx.1.{id}"),
            labels: std::collections::BTreeMap::new(),
        },
        service_annotations: Annotations {
            name: "agtest-nginx".to_owned(),
            labels: std::collections::BTreeMap::new(),
        },
        status: TaskStatus::new(TaskState::Assigned, "assigned"),
        desired_state: DesiredState::Running,
        networks: Vec::new(),
        endpoint: None,
        job_iteration: None,
    }
}

/// The base FreeBSD image, used by the healthcheck tests: they need a shell
/// and a container that stays up, not a server.
const BASE_IMAGE: &str = "127.0.0.1:5000/satl-test/freebsd-runtime:15.1";

/// A task running `sleep`-style forever under the base image, with `health` as
/// its healthcheck. The probe is deliberately file-driven (`test -f <flag>`):
/// the flag lives in the container's own rootfs, which is a ZFS clone the test
/// can touch from the host, so health can be flipped in either direction at an
/// exact moment — which is what an ordering assertion needs.
fn probe_task(id: &Id, health: satl_core::HealthConfig) -> Task {
    let mut task = nginx_task(id);
    BASE_IMAGE.clone_into(&mut task.spec.container.image);
    task.spec.container.command = vec!["/bin/sh".to_owned()];
    task.spec.container.args = vec!["-c".to_owned(), "while :; do /bin/sleep 1; done".to_owned()];
    task.spec.container.healthcheck = Some(health);
    task.annotations.name = format!("agtest-health.1.{id}");
    "agtest-health".clone_into(&mut task.service_annotations.name);
    task
}

/// The healthcheck flag file the probes above look for, inside the rootfs.
const READY_FLAG: &str = "satl-health-ready";

/// `CMD-SHELL test -f /satl-health-ready`, Docker's shell form.
fn ready_flag_healthcheck(
    interval: std::time::Duration,
    retries: u32,
    start_period: std::time::Duration,
) -> satl_core::HealthConfig {
    satl_core::HealthConfig {
        test: vec!["CMD-SHELL".to_owned(), format!("test -f /{READY_FLAG}")],
        interval: Some(interval),
        timeout: Some(std::time::Duration::from_secs(2)),
        retries,
        start_period: Some(start_period),
    }
}

/// One `do_step`, bounded: `None` means the step was still running when the
/// bound expired, which for a health-gated `start` is the expected answer.
async fn step_bounded(
    task: &Task,
    status: &TaskStatus,
    ctlr: &mut Controller,
    bound: std::time::Duration,
) -> Option<Step> {
    tokio::time::timeout(bound, do_step(task, status, ctlr))
        .await
        .ok()
}

/// The state a bounded step advanced to, or a panic naming what it did instead.
fn advanced(step: Option<Step>, what: &str) -> TaskStatus {
    match step {
        Some(Step::Advanced(status)) => status,
        other => panic!("{what}: expected a transition, got {other:?}"),
    }
}

/// Whether a jail of this name exists (live jails only).
fn jail_exists(task_id: &str) -> bool {
    run(JLS, &["-j", task_id, "name"]).0
}

/// The jid of a live jail, if it has one.
fn jail_id(task_id: &str) -> Option<i32> {
    let (ok, out) = run(JLS, &["-j", task_id, "jid"]);
    ok.then(|| out.trim().parse().ok()).flatten()
}

/// pids of processes running in `jid` whose command line contains `needle`.
fn processes_in_jail(jid: i32, needle: &str) -> Vec<i32> {
    let (ok, out) = run("/bin/ps", &["-axo", "jid,pid,command"]);
    if !ok {
        return Vec::new();
    }
    out.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let line_jid: i32 = fields.next()?.parse().ok()?;
            let pid: i32 = fields.next()?.parse().ok()?;
            (line_jid == jid && line.contains(needle)).then_some(pid)
        })
        .collect()
}

/// Wait until no prison of this name is listed, dying ones included — the only
/// reliable observer of a jail's death (`docs/jail-teardown.md`).
async fn wait_for_jail_to_die(task_id: &str) -> bool {
    for _ in 0..80 {
        let (_, out) = run(JLS, &["-d", "-h", "name", "dying"]);
        let still_there = out.lines().any(|line| {
            let mut fields = line.split_whitespace();
            fields.next() == Some(task_id)
        });
        if !still_there && !jail_exists(task_id) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    false
}

/// Run `do_step` until the observed state reaches `target`, with a bound so a
/// stuck controller fails the test instead of hanging the suite.
async fn drive_to(task: &Task, status: &mut TaskStatus, ctlr: &mut Controller, target: TaskState) {
    for _ in 0..12 {
        if status.state == target {
            return;
        }
        match do_step(task, status, ctlr).await {
            Step::Advanced(next) => {
                eprintln!("  {} -> {} ({})", status.state, next.state, next.message);
                *status = next;
            }
            Step::Retry(next) => panic!("unexpected retry at {}: {:?}", next.state, next.err),
            Step::Noop => panic!("unexpected no-op at {} (want {target})", status.state),
        }
    }
    panic!("did not reach {target} (stuck at {})", status.state);
}

/// Create the sandbox dataset tree and return `(dataset, mountpoint)`.
///
/// `tag` keeps two tests in this binary apart: they share a pid, so the pid
/// alone would collide and the "already exists" guard below would fail the
/// second one.
fn create_sandbox(tag: &str) -> (String, PathBuf) {
    let sandbox = format!("zroot/satl-agtest-{}-{tag}", std::process::id());
    let mountpoint = PathBuf::from(format!("/tmp/{}", sandbox.replace('/', "-")));
    assert!(
        !Command::new(ZFS_BIN)
            .args(["list", "-H", "-o", "name", &sandbox])
            .output()
            .unwrap()
            .status
            .success(),
        "sandbox dataset {sandbox} already exists; clean it up first"
    );
    zfs_cmd(&[
        "create",
        "-o",
        &format!("mountpoint={}", mountpoint.display()),
        &sandbox,
    ]);
    for child in ["layers", "containers", "volumes"] {
        zfs_cmd(&["create", &format!("{sandbox}/{child}")]);
    }
    (sandbox, mountpoint)
}

/// Wire the real subsystems into an [`Executor`], and bring up the test
/// bridge network. `deps` plays the dispatcher session's role: the test
/// populates it with the secrets/configs its tasks reference.
async fn build_executor(
    sandbox: &str,
    state_dir: &Path,
    ocijail_root: &Path,
    deps: Arc<satl_agent::DependencyStore>,
) -> (Arc<Executor>, satl_net::HostNetwork) {
    // SatL's devfs ruleset must exist before any jail mounts /dev.
    Devfs::system().ensure_ruleset().await.unwrap();

    let network = NetworkManager::open(NetworkManagerConfig {
        network: NETWORK.to_owned(),
        bridge: BRIDGE.to_owned(),
        group: GROUP.to_owned(),
        state_dir: state_dir.join("net"),
        pool: POOL.parse::<SubnetV4>().unwrap(),
        egress_if: None,
        // Never load pf on the dev host (CLAUDE.md).
        pf_mode: PfMode::Disabled,
    })
    .unwrap();
    let host_network = network.ensure_host_network().await.unwrap();

    let datasets = Datasets {
        root: sandbox.to_owned(),
        layers_root: format!("{sandbox}/layers"),
        containers_root: format!("{sandbox}/containers"),
        volumes_root: format!("{sandbox}/volumes"),
    };
    let executor = Executor::new(ExecutorParts {
        images: ImageStore::open(state_dir.join("images")).unwrap(),
        layers: LayerStore::new(Zfs::system(), datasets.layers_root.clone()),
        container_fs: ContainerFsStore::new(Zfs::system(), datasets.containers_root.clone()),
        volumes: VolumeStore::new(Zfs::system(), format!("{sandbox}/volumes")),
        zfs: Zfs::system(),
        network: Arc::new(network),
        runtime: OcijailRuntime::system(ocijail_root, state_dir.join("scratch")),
        jails: Jails::system(),
        // The dev host runs with kern.racct.enable=0 (architecture §16), so
        // limits degrade rather than fail; enforcement is a cluster-VM test.
        rctl: Rctl::system(false),
        state_dir: state_dir.to_path_buf(),
        datasets,
        host: HostFacts {
            linux_emulation: false,
            racct_enabled: false,
        },
        // No overlay programmer: these tests are the single-node path, where a
        // task attaches only to the node-local bridge. Every overlay step in the
        // controller is skipped when this is `None`, which is also what keeps
        // this test unprivileged of any cluster state.
        overlay: None,
        dependencies: deps,
    });
    (Arc::new(executor), host_network)
}

/// Fetch `url` until it serves the expected body (nginx needs a moment after
/// `ocijail start` releases the container process).
async fn wait_for_body(url: &str, needle: &str) -> String {
    for _ in 0..50 {
        let (ok, out) = run(CURL, &["-sS", "--max-time", "2", url]);
        if ok && out.contains(needle) {
            return out;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    String::new()
}

/// Assert that removing the task left nothing behind anywhere.
async fn audit_leftovers(
    executor: &Executor,
    sandbox: &str,
    task_id: &Id,
    rootfs: &Path,
    ocijail_root: &Path,
) {
    assert!(
        !run(JLS, &["-j", task_id.as_str(), "name"]).0,
        "jail {task_id} survived removal"
    );
    let leftover_mounts = Mounts::system().active_mounts_under(rootfs).await.unwrap();
    assert!(
        leftover_mounts.is_empty(),
        "leftover mounts: {leftover_mounts:?}"
    );
    // And nothing under the *containers root* either, which is the only place a
    // leftover of a task whose rootfs dataset is already gone still exists.
    // ocijail's mounts are MNT_IGNORE, so `mount`, `mount -t tmpfs` and (once
    // the dataset under them is destroyed) `df` show none of them — an audit
    // that looked only under this task's rootfs missed 54 of these per cluster
    // node. `Mounts` reads `mount -p`, which does see them.
    let containers_root = rootfs
        .parent()
        .expect("a container rootfs lives under the containers root");
    let orphans = Mounts::system()
        .orphan_mounts_under(containers_root, &std::collections::BTreeSet::new())
        .await
        .unwrap();
    assert!(
        orphans.is_empty(),
        "leftover mounts under {}: {orphans:?}",
        containers_root.display()
    );
    assert!(
        !ocijail_root.join(task_id.as_str()).exists(),
        "ocijail state entry survived removal"
    );
    assert!(!executor.bundle_dir(task_id.as_str()).exists());
    assert!(!executor.log_dir(task_id.as_str()).exists());

    // No container dataset, while the layer datasets stay (the image cache
    // outlives its containers).
    let containers = zfs_cmd(&[
        "list",
        "-H",
        "-o",
        "name",
        "-r",
        &format!("{sandbox}/containers"),
    ]);
    assert_eq!(
        containers.trim(),
        format!("{sandbox}/containers"),
        "container dataset survived removal"
    );
    let layers = zfs_cmd(&[
        "list",
        "-H",
        "-o",
        "name",
        "-r",
        &format!("{sandbox}/layers"),
    ]);
    assert!(
        layers.lines().count() > 1,
        "the image's layer datasets should outlive the task: {layers}"
    );

    // Only the bridge is left in our interface group: no epair leaked.
    let (_, members) = run(IFCONFIG, &["-g", GROUP]);
    assert_eq!(
        members.split_whitespace().collect::<Vec<_>>(),
        [BRIDGE],
        "leaked interfaces in group {GROUP}"
    );
    assert!(
        !epair_for_task(task_id.as_str()),
        "an epair still carries this task's description"
    );
}

#[tokio::test]
#[ignore = "requires root, ZFS and the local test registry (run via make integration)"]
async fn single_task_end_to_end_without_an_orchestrator() {
    assert_root();

    let (sandbox, sandbox_mountpoint) = create_sandbox("lifecycle");
    let dir = tempfile::Builder::new()
        .prefix("agtest-satl-agent-")
        .tempdir()
        .unwrap();
    let state_dir = dir.path().to_path_buf();
    let ocijail_root = state_dir.join("ocijail");
    let task_id = Id::generate();
    let task = nginx_task(&task_id);

    let _guard = Guard {
        task_id: task_id.as_str().to_owned(),
        ocijail_root: ocijail_root.clone(),
        rootfs: sandbox_mountpoint.join("containers").join(task_id.as_str()),
        sandbox: sandbox.clone(),
        sandbox_mountpoint,
    };

    let (executor, host_network) = build_executor(
        &sandbox,
        &state_dir,
        &ocijail_root,
        Arc::new(satl_agent::DependencyStore::new()),
    )
    .await;

    // ---- ASSIGNED → RUNNING ---------------------------------------------
    let mut ctlr = executor.controller(task.clone());
    let mut status = TaskStatus::new(TaskState::Assigned, "assigned");
    drive_to(&task, &mut status, &mut ctlr, TaskState::Running).await;

    let container = status.container.clone().expect("container status");
    assert_eq!(container.jail_id.as_deref(), Some(task_id.as_str()));
    let pid = container.pid.expect("container pid");
    assert!(pid > 0);
    // Jail name = task ID (pinned M1 contract).
    let (found, jail_name) = run(JLS, &["-j", task_id.as_str(), "name"]);
    assert!(found, "jail {task_id} must exist");
    assert_eq!(jail_name.trim(), task_id.as_str());

    // ---- the workload actually serves on its bridge address --------------
    let attachment = ctlr.attachment().expect("network attachment").clone();
    assert!(
        host_network.subnet.contains(attachment.ip),
        "{attachment:?}"
    );
    let url = format!("http://{}/", attachment.ip);
    let body = wait_for_body(&url, "satl-test-ok").await;
    assert!(
        body.contains("satl-test-ok"),
        "nginx did not serve on {url}; stderr log: {}",
        std::fs::read_to_string(executor.log_dir(task_id.as_str()).join("stderr.log"))
            .unwrap_or_default()
    );

    // ---- logs (pinned M1 contract) ---------------------------------------
    let log_dir = executor.log_dir(task_id.as_str());
    let stdout_log = log_dir.join("stdout.log");
    let stderr_log = log_dir.join("stderr.log");
    assert!(stdout_log.is_file(), "{} missing", stdout_log.display());
    assert!(stderr_log.is_file(), "{} missing", stderr_log.display());
    // The test image's nginx.conf sets `error_log stderr info`, so the
    // inherited fd 2 carries the workload's own output.
    let stderr_text = std::fs::read_to_string(&stderr_log).unwrap();
    assert!(
        !stderr_text.trim().is_empty(),
        "the container's stderr log is empty; stdio inheritance is broken"
    );
    assert!(
        stderr_text.contains("nginx"),
        "stderr log does not look like nginx output: {stderr_text}"
    );

    // ---- RUNNING → SHUTDOWN ---------------------------------------------
    let mut shutting_down = task.clone();
    shutting_down.desired_state = DesiredState::Shutdown;
    drive_to(&shutting_down, &mut status, &mut ctlr, TaskState::Shutdown).await;
    assert_eq!(status.state, TaskState::Shutdown);

    // ---- remove + leftovers audit ---------------------------------------
    let rootfs = ctlr.rootfs().expect("rootfs").to_path_buf();
    ctlr.remove().await.unwrap();
    audit_leftovers(&executor, &sandbox, &task_id, &rootfs, &ocijail_root).await;
}

/// Whether any epair still carries `<group>:<task id>` as its description
/// (the marker that survives the vnet move and the jail's death).
fn epair_for_task(task_id: &str) -> bool {
    let (_, epairs) = run(IFCONFIG, &["-g", "epair"]);
    epairs.split_whitespace().any(|iface| {
        let (_, show) = run(IFCONFIG, &[iface]);
        show.contains(&format!("description: {GROUP}:{task_id}"))
    })
}

/// Sanity: the helpers point at binaries that exist on a FreeBSD host, so a
/// missing dependency fails loudly rather than as a spawn panic mid-test.
#[test]
fn test_dependencies_are_present() {
    for binary in [ZFS_BIN, IFCONFIG, JLS, JAIL, UMOUNT] {
        assert!(Path::new(binary).exists(), "{binary} is missing");
    }
}

// ---------------------------------------------------------------------------
// Healthcheck tests (M4). Docker HEALTHCHECK semantics with the probe running
// through `ocijail exec`, and health gating the RUNNING transition.
// ---------------------------------------------------------------------------

/// Everything one health test needs, built once.
struct HealthFixture {
    _dir: tempfile::TempDir,
    guard: Guard,
    executor: Arc<Executor>,
    sandbox: String,
    ocijail_root: PathBuf,
    task_id: Id,
}

impl HealthFixture {
    async fn new(tag: &str) -> Self {
        assert_root();
        let (sandbox, sandbox_mountpoint) = create_sandbox(tag);
        let dir = tempfile::Builder::new()
            .prefix("agtest-satl-health-")
            .tempdir()
            .unwrap();
        let state_dir = dir.path().to_path_buf();
        let ocijail_root = state_dir.join("ocijail");
        let task_id = Id::generate();
        let guard = Guard {
            task_id: task_id.as_str().to_owned(),
            ocijail_root: ocijail_root.clone(),
            rootfs: sandbox_mountpoint.join("containers").join(task_id.as_str()),
            sandbox: sandbox.clone(),
            sandbox_mountpoint,
        };
        let (executor, _host_network) = build_executor(
            &sandbox,
            &state_dir,
            &ocijail_root,
            Arc::new(satl_agent::DependencyStore::new()),
        )
        .await;
        Self {
            _dir: dir,
            guard,
            executor,
            sandbox,
            ocijail_root,
            task_id,
        }
    }

    fn rootfs(&self) -> &Path {
        &self.guard.rootfs
    }

    fn set_ready(&self, ready: bool) {
        let flag = self.rootfs().join(READY_FLAG);
        if ready {
            std::fs::write(&flag, b"ok").unwrap();
        } else {
            let _ = std::fs::remove_file(&flag);
        }
    }

    fn health(&self) -> Option<satl_agent::TaskHealth> {
        self.executor.health().get(self.task_id.as_str())
    }
}

/// **The feature.** A task with a healthcheck must not be reported `RUNNING`
/// until a probe has passed, and this asserts the *ordering*, not the end state:
/// while the probe fails the state machine cannot leave `STARTING` (measured
/// over several probe intervals, with the container demonstrably up), and the
/// first success is what releases it — the successful probe finishing *before*
/// the RUNNING status was stamped.
#[tokio::test]
#[ignore = "requires root, ZFS and the local test registry (run via make integration)"]
#[allow(clippy::too_many_lines)]
async fn a_healthcheck_gates_running_until_the_first_probe_passes() {
    let fixture = HealthFixture::new("gate").await;
    let task = probe_task(
        &fixture.task_id,
        // A long start period: failures must not count while we hold the task
        // at STARTING on purpose.
        ready_flag_healthcheck(
            std::time::Duration::from_millis(300),
            3,
            std::time::Duration::from_mins(2),
        ),
    );
    let mut ctlr = fixture.executor.controller(task.clone());
    let mut status = TaskStatus::new(TaskState::Assigned, "assigned");

    // ---- up to READY, then STARTING blocks on the probe -------------------
    drive_to(&task, &mut status, &mut ctlr, TaskState::Ready).await;
    let starting = advanced(
        step_bounded(
            &task,
            &status,
            &mut ctlr,
            std::time::Duration::from_secs(30),
        )
        .await,
        "READY -> STARTING",
    );
    assert_eq!(starting.state, TaskState::Starting);
    status = starting;

    // The health-gated start: three seconds of failing probes must not produce
    // a RUNNING task.
    let blocked = step_bounded(&task, &status, &mut ctlr, std::time::Duration::from_secs(3)).await;
    assert!(
        blocked.is_none(),
        "start returned {blocked:?} while the healthcheck was failing: RUNNING is not gated"
    );
    assert_eq!(
        status.state,
        TaskState::Starting,
        "the task must sit in STARTING while it is not healthy"
    );
    // ...and that is not because nothing happened: the container is up and the
    // probe has run several times, unsuccessfully.
    assert!(
        jail_exists(fixture.task_id.as_str()),
        "the container should be running while the task is still STARTING"
    );
    let health = fixture
        .health()
        .expect("health is published while starting");
    assert_eq!(health.status, satl_agent::HealthStatus::Starting);
    assert!(
        health.log.len() >= 2,
        "the probe should have run repeatedly: {health:?}"
    );
    assert!(
        health.log.iter().all(|result| result.exit_code != 0),
        "no probe should have passed yet: {health:?}"
    );
    assert_eq!(
        health.failing_streak, 0,
        "failures inside the start period must not count: {health:?}"
    );

    // ---- the first passing probe releases the gate ------------------------
    let flipped = std::time::SystemTime::now();
    fixture.set_ready(true);
    let running = advanced(
        step_bounded(
            &task,
            &status,
            &mut ctlr,
            std::time::Duration::from_secs(30),
        )
        .await,
        "STARTING -> RUNNING",
    );
    let running_observed = std::time::SystemTime::now();
    assert_eq!(running.state, TaskState::Running);
    status = running;

    let health = fixture.health().expect("health after the gate opened");
    assert_eq!(health.status, satl_agent::HealthStatus::Healthy);
    let first_success = health
        .log
        .iter()
        .find(|result| result.exit_code == 0)
        .expect("a successful probe in the log");
    // The ordering, as two assertions on real clock readings. The witness is
    // *not* `status.timestamp`: `do_step` stamps that when the step begins, so
    // for a gated start it predates the probe that released it.
    assert!(
        first_success.start >= flipped,
        "the passing probe started at {:?}, before the flag was planted at {flipped:?}: it \
         cannot be the probe that released the gate",
        first_success.start
    );
    assert!(
        first_success.end <= running_observed,
        "RUNNING was observed at {running_observed:?}, before the first successful probe \
         ended at {:?}",
        first_success.end
    );

    // ---- teardown + audit -------------------------------------------------
    let mut shutting_down = task.clone();
    shutting_down.desired_state = DesiredState::Shutdown;
    drive_to(&shutting_down, &mut status, &mut ctlr, TaskState::Shutdown).await;
    let rootfs = ctlr.rootfs().expect("rootfs").to_path_buf();
    ctlr.remove().await.unwrap();
    assert!(
        fixture.health().is_none(),
        "the health entry must be dropped with the task"
    );
    assert!(
        !fixture
            .executor
            .health_dir(fixture.task_id.as_str())
            .exists()
    );
    audit_leftovers(
        &fixture.executor,
        &fixture.sandbox,
        &fixture.task_id,
        &rootfs,
        &fixture.ocijail_root,
    )
    .await;
}

/// A healthcheck that never passes fails the task instead of parking it in
/// `STARTING` forever: `retries` consecutive failures past the start period are
/// a verdict, the container is stopped, and the task is `FAILED` so the
/// orchestrator's restart supervisor replaces it. SwarmKit's
/// `ErrContainerUnhealthy` at start time.
#[tokio::test]
#[ignore = "requires root, ZFS and the local test registry (run via make integration)"]
async fn a_task_whose_healthcheck_never_passes_fails_instead_of_running() {
    let fixture = HealthFixture::new("never").await;
    let task = probe_task(
        &fixture.task_id,
        // No start period, two retries: a verdict within a second.
        ready_flag_healthcheck(
            std::time::Duration::from_millis(300),
            2,
            std::time::Duration::ZERO,
        ),
    );
    let mut ctlr = fixture.executor.controller(task.clone());
    let mut status = TaskStatus::new(TaskState::Assigned, "assigned");
    drive_to(&task, &mut status, &mut ctlr, TaskState::Starting).await;

    let failed = advanced(
        step_bounded(&task, &status, &mut ctlr, std::time::Duration::from_mins(1)).await,
        "STARTING -> FAILED",
    );
    assert_eq!(
        failed.state,
        TaskState::Failed,
        "an unhealthy container must fail the task, not reach RUNNING"
    );
    let err = failed.err.clone().expect("a failure reason");
    assert!(
        err.contains("unhealthy") && err.contains("healthcheck"),
        "the failure should name the healthcheck: {err}"
    );
    let health = fixture.health().expect("health after the verdict");
    assert_eq!(health.status, satl_agent::HealthStatus::Unhealthy);
    assert!(health.failing_streak >= 2, "{health:?}");
    // The container was stopped rather than left running unhealthy.
    let container = failed.container.clone().expect("container status");
    assert!(
        container.exit_code.is_some(),
        "the unhealthy container should have been stopped: {container:?}"
    );
    let rootfs = ctlr.rootfs().expect("rootfs").to_path_buf();
    ctlr.remove().await.unwrap();
    audit_leftovers(
        &fixture.executor,
        &fixture.sandbox,
        &fixture.task_id,
        &rootfs,
        &fixture.ocijail_root,
    )
    .await;
}

/// A task that was healthy and then goes unhealthy is stopped and reported
/// `FAILED` through the ordinary status path — the restart supervisor replaces
/// it, and nothing here creates a replacement.
#[tokio::test]
#[ignore = "requires root, ZFS and the local test registry (run via make integration)"]
async fn a_healthy_task_that_becomes_unhealthy_is_stopped_and_failed() {
    let fixture = HealthFixture::new("degrade").await;
    let task = probe_task(
        &fixture.task_id,
        ready_flag_healthcheck(
            std::time::Duration::from_millis(300),
            2,
            std::time::Duration::ZERO,
        ),
    );
    let mut ctlr = fixture.executor.controller(task.clone());
    let mut status = TaskStatus::new(TaskState::Assigned, "assigned");

    // Prepare first, so the rootfs exists and the flag can be planted before
    // the container starts: this task is healthy from its first probe.
    drive_to(&task, &mut status, &mut ctlr, TaskState::Ready).await;
    fixture.set_ready(true);
    drive_to(&task, &mut status, &mut ctlr, TaskState::Running).await;
    assert_eq!(
        fixture.health().map(|health| health.status),
        Some(satl_agent::HealthStatus::Healthy)
    );

    // Now break it: the flag goes away and the probe starts failing.
    fixture.set_ready(false);
    let failed = advanced(
        step_bounded(&task, &status, &mut ctlr, std::time::Duration::from_mins(1)).await,
        "RUNNING -> FAILED",
    );
    assert_eq!(failed.state, TaskState::Failed);
    let err = failed.err.clone().expect("a failure reason");
    assert!(err.contains("unhealthy"), "{err}");
    assert_eq!(
        fixture.health().map(|health| health.status),
        Some(satl_agent::HealthStatus::Unhealthy)
    );
    let container = failed.container.clone().expect("container status");
    assert!(
        container.exit_code.is_some(),
        "the unhealthy container should have been stopped: {container:?}"
    );

    let rootfs = ctlr.rootfs().expect("rootfs").to_path_buf();
    ctlr.remove().await.unwrap();
    audit_leftovers(
        &fixture.executor,
        &fixture.sandbox,
        &fixture.task_id,
        &rootfs,
        &fixture.ocijail_root,
    )
    .await;
}

/// A probe that outlives its timeout is **killed**, not abandoned: probes do
/// not pile up inside the jail while the task runs, no probe process survives
/// the task's removal, and the prison dies at once (a leaked process holding
/// something open is exactly what keeps a rootfs busy — `docs/jail-teardown.md`).
#[tokio::test]
#[ignore = "requires root, ZFS and the local test registry (run via make integration)"]
async fn a_probe_that_outlives_its_timeout_is_killed_and_leaks_nothing() {
    let fixture = HealthFixture::new("slowprobe").await;
    let mut health = ready_flag_healthcheck(
        std::time::Duration::from_millis(300),
        99,
        // Long enough that the timeouts never fail the task: this test is about
        // the probe processes, not the verdict.
        std::time::Duration::from_mins(10),
    );
    // A probe that always outlives its 1 s timeout.
    health.test = vec!["CMD-SHELL".to_owned(), "/bin/sleep 30".to_owned()];
    health.timeout = Some(std::time::Duration::from_secs(1));
    let task = probe_task(&fixture.task_id, health);

    let mut ctlr = fixture.executor.controller(task.clone());
    let mut status = TaskStatus::new(TaskState::Assigned, "assigned");
    drive_to(&task, &mut status, &mut ctlr, TaskState::Starting).await;
    // The start blocks (no probe ever passes), which is the window this test
    // needs: five seconds is at least three probe attempts.
    let blocked = step_bounded(&task, &status, &mut ctlr, std::time::Duration::from_secs(5)).await;
    assert!(blocked.is_none(), "the task should still be starting");

    let jid = jail_id(fixture.task_id.as_str()).expect("a live jail");
    let probes = processes_in_jail(jid, "sleep 30");
    assert!(
        probes.len() <= 1,
        "timed-out probes are piling up in the jail ({} of them): they are not being killed",
        probes.len()
    );
    let health_state = fixture.health().expect("health while starting");
    assert!(
        health_state.log.len() >= 2,
        "several probes should have been attempted: {health_state:?}"
    );
    assert!(
        health_state
            .log
            .iter()
            .all(|result| result.output.contains("exceeded timeout")),
        "every probe should have timed out: {health_state:?}"
    );

    // ---- removal: nothing left, and the prison dies ----------------------
    let rootfs = ctlr.rootfs().expect("rootfs").to_path_buf();
    ctlr.remove().await.unwrap();
    for pid in probes {
        assert!(
            !satl_runtime::signal_process(pid, 0).unwrap_or(false),
            "probe process {pid} survived the task's removal"
        );
    }
    assert!(
        wait_for_jail_to_die(fixture.task_id.as_str()).await,
        "the jail never finished dying (jls -d -h name dying still lists it)"
    );
    assert!(fixture.health().is_none());
    audit_leftovers(
        &fixture.executor,
        &fixture.sandbox,
        &fixture.task_id,
        &rootfs,
        &fixture.ocijail_root,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Secrets and configs (M5) — tmpfs delivery, never-touches-disk, sweep.
// ---------------------------------------------------------------------------

const JEXEC: &str = "/usr/sbin/jexec";

/// A store-shaped secret around `data`.
fn make_secret(name: &str, data: &[u8]) -> satl_core::Secret {
    satl_core::Secret {
        id: Id::generate(),
        meta: Meta::new(),
        spec: satl_core::SecretSpec::new(
            Annotations {
                name: name.to_owned(),
                labels: std::collections::BTreeMap::new(),
            },
            data.to_vec(),
        )
        .expect("valid secret payload"),
    }
}

/// A store-shaped config around `data`.
fn make_config(name: &str, data: &[u8]) -> satl_core::Config {
    satl_core::Config {
        id: Id::generate(),
        meta: Meta::new(),
        spec: satl_core::ConfigSpec::new(
            Annotations {
                name: name.to_owned(),
                labels: std::collections::BTreeMap::new(),
            },
            data.to_vec(),
        )
        .expect("valid config payload"),
    }
}

/// A long-running task of the base image referencing `secret` and `config`.
fn dependent_task(id: &Id, secret: &satl_core::Secret, config: &satl_core::Config) -> Task {
    let mut task = nginx_task(id);
    BASE_IMAGE.clone_into(&mut task.spec.container.image);
    task.spec.container.command = vec!["/bin/sh".to_owned()];
    task.spec.container.args = vec!["-c".to_owned(), "while :; do /bin/sleep 1; done".to_owned()];
    task.annotations.name = format!("agtest-secrets.1.{id}");
    "agtest-secrets".clone_into(&mut task.service_annotations.name);
    task.spec.container.secrets = vec![satl_core::SecretReference {
        secret_id: secret.id.clone(),
        secret_name: secret.spec.annotations.name.clone(),
        file: satl_core::FileTarget {
            name: "db_password".to_owned(),
            uid: "65534".to_owned(),
            gid: "65534".to_owned(),
            mode: 0o440,
        },
    }];
    task.spec.container.configs = vec![satl_core::ConfigReference {
        config_id: config.id.clone(),
        config_name: config.spec.annotations.name.clone(),
        file: satl_core::FileTarget {
            name: "/etc/agtest.conf".to_owned(),
            uid: "0".to_owned(),
            gid: "0".to_owned(),
            mode: 0o444,
        },
    }];
    task
}

/// Every mountpoint of the sandbox dataset tree (each is its own filesystem,
/// so a per-mountpoint `find -x` walks ZFS only and never enters a tmpfs).
fn sandbox_mountpoints(sandbox: &str) -> Vec<PathBuf> {
    zfs_cmd(&["list", "-H", "-o", "mountpoint", "-r", sandbox])
        .lines()
        .filter(|line| line.starts_with('/'))
        .map(PathBuf::from)
        .collect()
}

/// Regular files under `dir` on `dir`'s own filesystem (never crossing a
/// mount boundary) whose bytes contain `marker`.
fn files_containing(dir: &Path, marker: &[u8]) -> Vec<String> {
    if !dir.exists() {
        return Vec::new();
    }
    let (ok, listing) = run(
        "/usr/bin/find",
        &["-x", dir.to_str().unwrap(), "-type", "f"],
    );
    assert!(ok, "find -x {} failed", dir.display());
    listing
        .lines()
        .filter(|path| {
            std::fs::read(path).is_ok_and(|bytes| {
                marker
                    .first()
                    .is_some_and(|_| bytes.windows(marker.len()).any(|window| window == marker))
            })
        })
        .map(str::to_owned)
        .collect()
}

/// Assert `marker` exists on no ZFS dataset of the sandbox and nowhere under
/// `state_dir` except the allowed paths.
fn assert_payload_only_in(sandbox: &str, state_dir: &Path, marker: &[u8], allowed: &[PathBuf]) {
    let mut hits: Vec<String> = Vec::new();
    for mountpoint in sandbox_mountpoints(sandbox) {
        hits.extend(files_containing(&mountpoint, marker));
    }
    hits.extend(files_containing(state_dir, marker));
    let stray: Vec<&String> = hits
        .iter()
        .filter(|hit| !allowed.iter().any(|ok| Path::new(hit) == ok))
        .collect();
    assert!(
        stray.is_empty(),
        "payload bytes found outside the allowed locations: {stray:?}"
    );
}

/// The payload must appear neither in the task's log sinks nor in syslog
/// (`/var/log/messages` is where satld's own tracing lands; this test's
/// tracing goes to stderr, so any hit would be a real leak).
fn assert_not_in_logs(executor: &Executor, task_id: &Id, marker: &str) {
    let log_dir = executor.log_dir(task_id.as_str());
    for log in ["stdout.log", "stderr.log"] {
        let bytes = std::fs::read(log_dir.join(log)).unwrap_or_default();
        assert!(
            !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "secret payload leaked into {log}"
        );
    }
    let (_, syslog_hits) = run("/usr/bin/grep", &["-a", "-c", marker, "/var/log/messages"]);
    assert_eq!(
        syslog_hits.trim(),
        "0",
        "secret payload appeared in /var/log/messages"
    );
}

/// End-to-end secret + config delivery (invariant #7):
///
/// - the secret is a file on a tmpfs at `/run/secrets` inside the jail, with
///   the requested uid/gid/mode, and the config a read-only file at its
///   absolute target;
/// - while the task runs, the payload bytes exist **nowhere on ZFS or in the
///   node state dir** (the config's bundle source file is the one allowed
///   exception — configs may touch disk, secrets may not);
/// - teardown unmounts the tmpfs and the leftover audit stays clean.
#[tokio::test]
#[ignore = "requires root, ZFS and the local test registry (run via make integration)"]
async fn a_secret_is_delivered_via_tmpfs_only_and_never_touches_disk() {
    assert_root();

    let secret_marker = format!("agtest-secret-{}", Id::generate());
    let config_marker = format!("agtest-config-{}", Id::generate());
    let secret = make_secret("agtest-db-password", secret_marker.as_bytes());
    let config = make_config("agtest-app-conf", config_marker.as_bytes());

    let (sandbox, sandbox_mountpoint) = create_sandbox("secrets");
    let dir = tempfile::Builder::new()
        .prefix("agtest-satl-secrets-")
        .tempdir()
        .unwrap();
    let state_dir = dir.path().to_path_buf();
    let ocijail_root = state_dir.join("ocijail");
    let task_id = Id::generate();
    let task = dependent_task(&task_id, &secret, &config);

    let _guard = Guard {
        task_id: task_id.as_str().to_owned(),
        ocijail_root: ocijail_root.clone(),
        rootfs: sandbox_mountpoint.join("containers").join(task_id.as_str()),
        sandbox: sandbox.clone(),
        sandbox_mountpoint,
    };

    let deps = Arc::new(satl_agent::DependencyStore::new());
    deps.put_secret(secret.clone());
    deps.put_config(config.clone());
    let (executor, _host_network) = build_executor(&sandbox, &state_dir, &ocijail_root, deps).await;

    let mut ctlr = executor.controller(task.clone());
    let mut status = TaskStatus::new(TaskState::Assigned, "assigned");
    drive_to(&task, &mut status, &mut ctlr, TaskState::Running).await;
    let rootfs = ctlr.rootfs().expect("rootfs").to_path_buf();

    // ---- the mount: a tmpfs at <rootfs>/run/secrets ----------------------
    let mounts = Mounts::system().active_mounts_under(&rootfs).await.unwrap();
    let secrets_dir = rootfs.join("run/secrets");
    let tmpfs = mounts
        .iter()
        .find(|entry| entry.node == secrets_dir)
        .unwrap_or_else(|| panic!("no mount at {}: {mounts:?}", secrets_dir.display()));
    assert_eq!(tmpfs.fstype, "tmpfs", "{tmpfs:?}");

    // ---- the file: content, mode, owner ----------------------------------
    let secret_path = secrets_dir.join("db_password");
    assert_eq!(
        std::fs::read(&secret_path).unwrap(),
        secret_marker.as_bytes()
    );
    let meta = std::fs::metadata(&secret_path).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o440);
    assert_eq!((meta.uid(), meta.gid()), (65534, 65534));

    // ---- visible from inside the jail at Docker's path -------------------
    let (ok, in_jail) = run(
        JEXEC,
        &[task_id.as_str(), "/bin/cat", "/run/secrets/db_password"],
    );
    assert!(ok, "jexec cat /run/secrets/db_password failed");
    assert_eq!(in_jail, secret_marker);
    let (ok, in_jail) = run(JEXEC, &[task_id.as_str(), "/bin/cat", "/etc/agtest.conf"]);
    assert!(ok, "jexec cat /etc/agtest.conf failed");
    assert_eq!(in_jail, config_marker);
    // The config mount is read-only inside the jail.
    let (writable, _) = run(
        JEXEC,
        &[
            task_id.as_str(),
            "/bin/sh",
            "-c",
            "echo tamper >> /etc/agtest.conf",
        ],
    );
    assert!(!writable, "the config file must be mounted read-only");

    // ---- the proof: payload bytes on no ZFS dataset, not in the state dir
    // (find -x never descends across a mount boundary, so the tmpfs is
    // excluded and its presence is asserted separately above).
    assert_payload_only_in(&sandbox, &state_dir, secret_marker.as_bytes(), &[]);
    // The config is allowed on disk in exactly one place — its bundle source
    // file. Its in-jail target also shows the bytes to a host-side read:
    // find -x cannot prune a *file* mountpoint (only directory descent), and
    // reading that path reads the nullfs-mounted view, not ZFS. The bytes
    // under it on ZFS are the empty file ocijail created to hang the mount on.
    let config_source = executor.bundle_dir(task_id.as_str()).join("configs/0");
    let config_target_view = rootfs.join("etc/agtest.conf");
    assert_payload_only_in(
        &sandbox,
        &state_dir,
        config_marker.as_bytes(),
        &[config_source, config_target_view],
    );
    assert_not_in_logs(&executor, &task_id, &secret_marker);

    // ---- teardown unmounts the tmpfs --------------------------------------
    let mut shutting_down = task.clone();
    shutting_down.desired_state = DesiredState::Shutdown;
    drive_to(&shutting_down, &mut status, &mut ctlr, TaskState::Shutdown).await;
    ctlr.remove().await.unwrap();
    let leftover = Mounts::system().active_mounts_under(&rootfs).await.unwrap();
    assert!(
        leftover.is_empty(),
        "teardown left mounts behind: {leftover:?}"
    );
    audit_leftovers(&executor, &sandbox, &task_id, &rootfs, &ocijail_root).await;
}

/// The two interruption cases around the secret tmpfs:
///
/// 1. **Killed between `create` (tmpfs mounted) and the payload write**: on
///    restart, an adopted created-but-not-started container gets its payloads
///    rewritten from the re-fetched dependency set.
/// 2. **Killed between mount and start, task gone on restart**: the
///    reconcile path (`ocijail delete --force` + mount sweep, what
///    `satld`'s startup pass runs) unmounts the tmpfs and leaves nothing.
#[tokio::test]
#[ignore = "requires root, ZFS and the local test registry (run via make integration)"]
async fn an_interrupted_teardown_leaks_no_secret_tmpfs() {
    assert_root();

    let secret_marker = format!("agtest-secret-{}", Id::generate());
    let config_marker = format!("agtest-config-{}", Id::generate());
    let secret = make_secret("agtest-db-password", secret_marker.as_bytes());
    let config = make_config("agtest-app-conf", config_marker.as_bytes());

    let (sandbox, sandbox_mountpoint) = create_sandbox("sweep");
    let dir = tempfile::Builder::new()
        .prefix("agtest-satl-sweep-")
        .tempdir()
        .unwrap();
    let state_dir = dir.path().to_path_buf();
    let ocijail_root = state_dir.join("ocijail");
    let task_id = Id::generate();
    let mut task = dependent_task(&task_id, &secret, &config);
    // Prepare but do not start: the interruption window under test is
    // between the tmpfs mount (create) and jail start.
    task.desired_state = DesiredState::Ready;

    let _guard = Guard {
        task_id: task_id.as_str().to_owned(),
        ocijail_root: ocijail_root.clone(),
        rootfs: sandbox_mountpoint.join("containers").join(task_id.as_str()),
        sandbox: sandbox.clone(),
        sandbox_mountpoint,
    };

    let deps = Arc::new(satl_agent::DependencyStore::new());
    deps.put_secret(secret.clone());
    deps.put_config(config.clone());
    let (executor, _host_network) =
        build_executor(&sandbox, &state_dir, &ocijail_root, Arc::clone(&deps)).await;

    let mut ctlr = executor.controller(task.clone());
    let mut status = TaskStatus::new(TaskState::Assigned, "assigned");
    drive_to(&task, &mut status, &mut ctlr, TaskState::Ready).await;
    let rootfs = ctlr.rootfs().expect("rootfs").to_path_buf();
    let secret_path = rootfs.join("run/secrets/db_password");
    assert!(secret_path.is_file(), "prepare must write the payload");

    // ---- case 1: crash after mount, before the write ----------------------
    // Simulate it by deleting the written file, dropping the controller (the
    // dead daemon), and re-driving prepare with a fresh one: the adoption
    // path must rewrite the payload into the still-mounted tmpfs.
    std::fs::remove_file(&secret_path).unwrap();
    drop(ctlr);
    let mut adopted = executor.controller(task.clone());
    let mut replay = TaskStatus::new(TaskState::Preparing, "preparing");
    let next = advanced(
        step_bounded(
            &task,
            &replay,
            &mut adopted,
            std::time::Duration::from_secs(30),
        )
        .await,
        "adopting prepare",
    );
    assert_eq!(next.state, TaskState::Ready);
    replay = next;
    let _ = replay;
    assert_eq!(
        std::fs::read(&secret_path).unwrap(),
        secret_marker.as_bytes(),
        "the adopted prepare must rewrite the payload"
    );
    let meta = std::fs::metadata(&secret_path).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o440);
    assert_eq!((meta.uid(), meta.gid()), (65534, 65534));

    // ---- case 2: the daemon dies for good; the task is gone on restart ----
    // What satld's startup reconciliation runs for a container no live task
    // claims is `runtime().delete(id, rootfs, force)` — ocijail's delete plus
    // the mount-leak sweep. Precondition: the tmpfs is really mounted now.
    let before = Mounts::system().active_mounts_under(&rootfs).await.unwrap();
    assert!(
        before
            .iter()
            .any(|entry| entry.node == rootfs.join("run/secrets") && entry.fstype == "tmpfs"),
        "precondition: the secrets tmpfs must be mounted: {before:?}"
    );
    drop(adopted);
    let report = executor
        .runtime()
        .delete(task_id.as_str(), &rootfs, true)
        .await
        .unwrap();
    // A created-but-never-started jail's mounts are unwound by ocijail's own
    // delete (they are recorded in its state entry); the runtime's sweep is
    // the backstop for the documented leak cases (docs/linuxulator.md — a
    // deleted *exited* jail, a missing state entry). Either way the invariant
    // is the same and is what the rest of this test asserts: nothing remains.
    eprintln!("  delete report: {report:?}");
    let leftover = Mounts::system().active_mounts_under(&rootfs).await.unwrap();
    assert!(leftover.is_empty(), "leftover mounts: {leftover:?}");
    assert!(
        !secret_path.exists(),
        "the payload file must be gone with its tmpfs"
    );
    // No payload bytes anywhere on disk once the tmpfs is gone.
    assert_payload_only_in(&sandbox, &state_dir, secret_marker.as_bytes(), &[]);

    // Finish the cleanup so the audit and the sandbox guard stay green.
    let mut cleaner = executor.controller(task.clone());
    cleaner.remove().await.unwrap();
    audit_leftovers(&executor, &sandbox, &task_id, &rootfs, &ocijail_root).await;
}
