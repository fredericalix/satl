// SPDX-License-Identifier: BSD-2-Clause
//! Integration test: boots the real `satld` binary with a temp config,
//! pings it over its unix socket, and verifies clean SIGTERM shutdown.
//!
//! `#[ignore]`-gated — runs via `make integration` (root, FreeBSD only).
//!
//! **Isolation** (CLAUDE.md: never disturb the running `satld` service). This
//! daemon gets its own socket, its own state dir, its own network name — so
//! its bridge is `wireping0` and its interface group is `wireping`, never the
//! production `satl0`/`satl` that startup reconciliation sweeps — and a
//! `zfs_root` that deliberately does not exist, paired with
//! `--skip-zfs-check`: every ZFS operation then fails harmlessly instead of
//! touching `zroot/satl`. pf is never loaded (`pf_mode = "disabled"`).

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Network name for this test: its bridge is `wireping0`, its interface group
/// `wireping`. Must not be a prefix of, or equal to, the production `satl`.
const NETWORK: &str = "wireping";

fn connect_with_retry(socket_path: &Path, child: &mut Child) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("satld exited early with {status}");
        }
        match UnixStream::connect(socket_path) {
            Ok(stream) => return stream,
            Err(err) => {
                assert!(
                    Instant::now() < deadline,
                    "satld never listened on {}: {err}",
                    socket_path.display()
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "satld did not exit within 10s of SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Destroys the bridge this test's daemon created, on success and on panic.
struct BridgeGuard;

impl Drop for BridgeGuard {
    fn drop(&mut self) {
        let _ = Command::new("/sbin/ifconfig")
            .args([&format!("{NETWORK}0"), "destroy"])
            .output();
    }
}

#[test]
#[ignore = "integration: spawns the satld binary; run via `make integration`"]
fn daemon_answers_ping_and_shuts_down_cleanly_on_sigterm() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("satl.sock");
    let config_path = dir.path().join("satld.toml");
    std::fs::write(
        &config_path,
        format!(
            "socket_path = \"{socket}\"\n\
             state_dir = \"{state}\"\n\
             node_name = \"itest\"\n\
             zfs_root = \"zroot/satl-wire-ping-{pid}\"\n\
             network_name = \"{NETWORK}\"\n\
             network_pool = \"10.84.0.0/16\"\n\
             pf_mode = \"disabled\"\n",
            socket = socket_path.display(),
            state = dir.path().join("state").display(),
            pid = std::process::id(),
        ),
    )
    .unwrap();
    let _bridge = BridgeGuard;

    let mut child = Command::new(env!("CARGO_BIN_EXE_satld"))
        .arg("--config")
        .arg(&config_path)
        .arg("--skip-zfs-check")
        .arg("--log-format")
        .arg("json")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    let mut stream = connect_with_retry(&socket_path, &mut child);
    stream
        .write_all(b"GET /_ping HTTP/1.1\r\nHost: satl\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200 OK from /_ping, got: {response}"
    );
    assert!(
        response.ends_with("OK"),
        "expected OK body, got: {response}"
    );

    // Graceful shutdown on SIGTERM: exit 0 and no socket file left behind.
    let killed = Command::new("kill")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(killed.success(), "failed to send SIGTERM to satld");

    let status = wait_for_exit(&mut child);
    assert!(status.success(), "satld exited uncleanly: {status}");
    assert!(
        !socket_path.exists(),
        "socket file must be removed on clean shutdown"
    );
}
