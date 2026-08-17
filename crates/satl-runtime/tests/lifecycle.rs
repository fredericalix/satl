// SPDX-License-Identifier: BSD-2-Clause
//! Root-only integration tests for the ocijail runtime (`make integration`).
//!
//! Conventions (CLAUDE.md / hack/experiments/ocijail):
//! - every artifact (container id = jail name, state db, rootfs, bundle) is
//!   prefixed `rtest-` and lives in a per-test tempdir;
//! - a private ocijail `--root` is used so the default `/var/run/ocijail`
//!   and any running satld are never touched;
//! - every test installs a drop guard that force-deletes the container,
//!   removes a stray jail and unmounts anything left under the rootfs, even
//!   on panic.
//!
//! The rootfs is built from the host's statically linked `/rescue` crunched
//! binary (one copy + hardlinks inside the rootfs), the same technique as
//! `hack/experiments/ocijail/mkrootfs.sh`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use satl_runtime::{
    BundleSpec, CreateStdio, Devfs, ImagePlatform, Mounts, OcijailRuntime, Runtime, RuntimeStatus,
    StdioSink, SystemRunner, wait_for_exit,
};

const RESCUE_TOOLS: [&str; 8] = [
    "sleep", "echo", "cat", "ls", "ps", "ifconfig", "kill", "test",
];

fn assert_root() {
    assert!(
        nix::unistd::geteuid().is_root(),
        "these #[ignore] tests must run as root (make integration)"
    );
}

/// Build a minimal FreeBSD rootfs from /rescue (no shared libraries needed).
fn build_rescue_rootfs(rootfs: &Path) {
    for dir in ["bin", "dev", "tmp", "etc", "root"] {
        fs::create_dir_all(rootfs.join(dir)).unwrap();
    }
    fs::copy("/rescue/sh", rootfs.join("bin/sh")).unwrap();
    for tool in RESCUE_TOOLS {
        // Hardlink inside the rootfs: /rescue may be on another dataset.
        fs::hard_link(rootfs.join("bin/sh"), rootfs.join("bin").join(tool)).unwrap();
    }
    fs::write(
        rootfs.join("etc/passwd"),
        "root:*:0:0:Charlie &:/root:/bin/sh\n",
    )
    .unwrap();
    fs::write(rootfs.join("etc/group"), "wheel:*:0:root\n").unwrap();
}

/// Per-test environment: tempdir layout + runtime with a private state db.
struct TestEnv {
    id: String,
    // Held for its Drop (removes the tempdir tree).
    dir: tempfile::TempDir,
    rootfs: PathBuf,
    bundle_dir: PathBuf,
    state_root: PathBuf,
    runtime: OcijailRuntime<SystemRunner>,
    guard: Option<JailGuard>,
}

impl TestEnv {
    fn new(tag: &str) -> Self {
        assert_root();
        let id = format!("rtest-{}-{tag}", std::process::id());
        let dir = tempfile::Builder::new()
            .prefix("rtest-satl-runtime-")
            .tempdir()
            .unwrap();
        let rootfs = dir.path().join("rootfs");
        let bundle_dir = dir.path().join("bundle");
        let state_root = dir.path().join("state");
        let scratch = dir.path().join("scratch");
        build_rescue_rootfs(&rootfs);
        fs::create_dir_all(&bundle_dir).unwrap();
        let runtime = OcijailRuntime::system(&state_root, scratch);
        let guard = Some(JailGuard {
            id: id.clone(),
            state_root: state_root.clone(),
            rootfs: rootfs.clone(),
        });
        Self {
            id,
            dir,

            rootfs,
            bundle_dir,
            state_root,
            runtime,
            guard,
        }
    }

    fn spec(&self, script: &str) -> BundleSpec {
        BundleSpec {
            rootfs: self.rootfs.clone(),
            readonly_rootfs: false,
            args: vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()],
            env: vec!["PATH=/bin".to_owned()],
            cwd: "/".to_owned(),
            user: None,
            hostname: Some(format!("{}-host", self.id)),
            terminal: false,
            platform: ImagePlatform::Freebsd,
            mounts: Vec::new(),
            vnet: false,
            extra_jail_annotations: BTreeMap::new(),
        }
    }

    /// Read+write log sinks (read-back of create errors needs read).
    fn stdio(&self, dir_name: &str) -> (CreateStdio, PathBuf, PathBuf) {
        let dir = self.dir.path().join(dir_name);
        fs::create_dir_all(&dir).unwrap();
        let stdout_path = dir.join("stdout.log");
        let stderr_path = dir.join("stderr.log");
        let open = |path: &Path| {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .unwrap()
        };
        (
            CreateStdio {
                stdin: StdioSink::Null,
                stdout: StdioSink::File(open(&stdout_path)),
                stderr: StdioSink::File(open(&stderr_path)),
            },
            stdout_path,
            stderr_path,
        )
    }

    /// Everything went through cleanly; disarm the panic guard.
    fn disarm(&mut self) {
        self.guard.take();
    }
}

/// Best-effort cleanup on panic: force-delete the container, remove a stray
/// jail, unmount the known platform mounts under the rootfs (deepest first).
struct JailGuard {
    id: String,
    state_root: PathBuf,
    rootfs: PathBuf,
}

impl Drop for JailGuard {
    fn drop(&mut self) {
        let _ = Command::new("/usr/local/bin/ocijail")
            .args(["--root"])
            .arg(&self.state_root)
            .args(["delete", "--force", &self.id])
            .output();
        let _ = Command::new("/usr/sbin/jail")
            .args(["-r", &self.id])
            .output();
        for sub in ["dev/fd", "dev", "tmp"] {
            let _ = Command::new("/sbin/umount")
                .arg("-f")
                .arg(self.rootfs.join(sub))
                .output();
        }
    }
}

fn jls_field(id: &str, field: &str) -> Option<String> {
    let output = Command::new("/usr/sbin/jls")
        .args(["-j", id, field])
        .output()
        .unwrap();
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Full happy path: create (stdio to files) → state created → start → state
/// running → kqueue harvests the real exit code → delete → no mounts left →
/// state `NotFound`.
#[tokio::test]
#[ignore = "requires root and FreeBSD (run via make integration)"]
async fn full_lifecycle_with_exit_code_harvest() {
    let mut env = TestEnv::new("life");
    Devfs::system().ensure_ruleset().await.unwrap();
    let (stdio, stdout_path, stderr_path) = env.stdio("logs");
    let spec = env.spec("echo hello-stdout; echo hello-stderr 1>&2; sleep 2; exit 42");

    let created = env
        .runtime
        .create(&env.id, &env.bundle_dir, &spec, None, stdio)
        .await
        .unwrap();
    assert!(created.pid > 0);

    let state = env.runtime.state(&env.id).await.unwrap();
    assert_eq!(state.status, RuntimeStatus::Created);
    assert_eq!(state.pid, Some(created.pid));
    assert!(state.jid().is_some(), "state: {state:?}");

    // Arm the exit watch BEFORE start (docs/ocijail.md §1.4 gotcha).
    let watch = tokio::spawn(wait_for_exit(created.pid));

    env.runtime.start(&env.id).await.unwrap();
    assert_eq!(
        env.runtime.state(&env.id).await.unwrap().status,
        RuntimeStatus::Running
    );

    // The real exit code, which ocijail itself never reports.
    let exit = watch.await.unwrap().unwrap();
    assert_eq!(exit.code, Some(42), "exit: {exit:?}");
    assert_eq!(exit.signal, None);

    // stdio inheritance: the container wrote into our sinks.
    assert!(
        fs::read_to_string(&stdout_path)
            .unwrap()
            .contains("hello-stdout")
    );
    assert!(
        fs::read_to_string(&stderr_path)
            .unwrap()
            .contains("hello-stderr")
    );

    // state now observes the death.
    assert_eq!(
        env.runtime.state(&env.id).await.unwrap().status,
        RuntimeStatus::Stopped
    );

    // delete + leak sweep: nothing may stay mounted below the rootfs.
    env.runtime
        .delete(&env.id, &env.rootfs, false)
        .await
        .unwrap();
    let leftover = Mounts::system()
        .active_mounts_under(&env.rootfs)
        .await
        .unwrap();
    assert!(leftover.is_empty(), "leftover mounts: {leftover:?}");

    let err = env.runtime.state(&env.id).await.unwrap_err();
    assert!(err.is_not_found(), "{err}");
    assert_eq!(jls_field(&env.id, "name"), None, "jail must be gone");
    env.disarm();
}

/// The leak rule: mounts exist from create time; when the state db entry is
/// lost (crash window, docs/ocijail.md §4.4) a bare `ocijail delete` exits 0
/// and cleans nothing — the mounts leak until `unmount_all_under` sweeps.
#[tokio::test]
#[ignore = "requires root and FreeBSD (run via make integration)"]
async fn leaked_mounts_after_bare_delete_are_swept() {
    let mut env = TestEnv::new("leak");
    Devfs::system().ensure_ruleset().await.unwrap();
    let spec = env.spec("sleep 60");

    env.runtime
        .create(&env.id, &env.bundle_dir, &spec, None, CreateStdio::null())
        .await
        .unwrap();

    // devfs /dev, fdescfs /dev/fd, tmpfs /tmp are mounted already (created,
    // never started).
    let mounts = Mounts::system()
        .active_mounts_under(&env.rootfs)
        .await
        .unwrap();
    let fstypes: Vec<&str> = mounts.iter().map(|m| m.fstype.as_str()).collect();
    assert_eq!(mounts.len(), 3, "platform mounts expected: {mounts:?}");
    assert!(
        fstypes.contains(&"devfs") && fstypes.contains(&"fdescfs") && fstypes.contains(&"tmpfs")
    );

    // Crash window: the state db entry vanishes, the jail+mounts stay.
    fs::remove_dir_all(env.state_root.join(&env.id)).unwrap();

    // Bare delete "succeeds" (exit 0) and cleans nothing.
    env.runtime.ocijail().delete(&env.id, true).await.unwrap();
    assert_eq!(jls_field(&env.id, "name").as_deref(), Some(env.id.as_str()));
    let leaked = Mounts::system()
        .active_mounts_under(&env.rootfs)
        .await
        .unwrap();
    assert_eq!(leaked.len(), 3, "mounts must have leaked: {leaked:?}");

    // Reconciliation recipe: remove the stray jail, then sweep the mounts.
    let removed = Command::new("/usr/sbin/jail")
        .args(["-r", &env.id])
        .output()
        .unwrap();
    assert!(removed.status.success());
    let swept = Mounts::system()
        .unmount_all_under(&env.rootfs)
        .await
        .unwrap();
    assert_eq!(swept.len(), 3, "swept: {swept:?}");
    assert!(
        Mounts::system()
            .active_mounts_under(&env.rootfs)
            .await
            .unwrap()
            .is_empty()
    );
    env.disarm();
}

/// vnet: the `org.freebsd.jail.vnet=new` annotation must yield a jail with
/// its own network stack — `jls vnet` says `new` and the jail sees only lo0.
#[tokio::test]
#[ignore = "requires root and FreeBSD (run via make integration)"]
async fn vnet_annotation_creates_isolated_network_stack() {
    let mut env = TestEnv::new("vnet");
    Devfs::system().ensure_ruleset().await.unwrap();
    let mut spec = env.spec("sleep 30");
    spec.vnet = true;

    let created = env
        .runtime
        .create(&env.id, &env.bundle_dir, &spec, None, CreateStdio::null())
        .await
        .unwrap();
    let watch = tokio::spawn(wait_for_exit(created.pid));
    env.runtime.start(&env.id).await.unwrap();
    assert_eq!(
        env.runtime.state(&env.id).await.unwrap().status,
        RuntimeStatus::Running
    );

    // Isolated stack, created by ocijail alone (epairs are satl-net's job).
    assert_eq!(jls_field(&env.id, "vnet").as_deref(), Some("new"));
    let ifconfig = Command::new("/sbin/ifconfig")
        .args(["-j", &env.id, "-l"])
        .output()
        .unwrap();
    assert!(ifconfig.status.success());
    let interfaces = String::from_utf8_lossy(&ifconfig.stdout).trim().to_owned();
    assert_eq!(interfaces, "lo0", "jail must only see lo0");

    // Shutdown recipe: SIGKILL, harvest, delete, verify gone.
    env.runtime.kill(&env.id, 9).await.unwrap();
    let exit = watch.await.unwrap().unwrap();
    assert_eq!(exit.signal, Some(9), "exit: {exit:?}");
    env.runtime
        .delete(&env.id, &env.rootfs, false)
        .await
        .unwrap();
    let err = env.runtime.state(&env.id).await.unwrap_err();
    assert!(err.is_not_found(), "{err}");
    assert_eq!(jls_field(&env.id, "name"), None);
    assert!(
        Mounts::system()
            .active_mounts_under(&env.rootfs)
            .await
            .unwrap()
            .is_empty()
    );
    env.disarm();
}
