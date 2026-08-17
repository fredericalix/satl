// SPDX-License-Identifier: BSD-2-Clause
//! Measures the empirical fact M6c's split writer is built on: **`pfctl -T
//! replace` on a pool table leaves established states alone** — and only new
//! connections are balanced over the new membership.
//!
//! If this ever stopped holding, `NetworkManager::write_rdr`'s split (static
//! ruleset, dynamic membership) would kill in-flight connections on every
//! health-driven pool change, and the whole table-backed design would have to
//! be rethought. Measured shape (FreeBSD 15.1, this test on a cluster VM):
//!
//! ```text
//! table <satl_p29080_tcp_29101> persist
//! rdr pass inet proto tcp from any to any port 29080 -> <satl_p29080_tcp_29101> port 29101 round-robin
//!
//! table = { 127.0.0.1 }  -> conn1 is answered by A, echoes as A
//! -T replace 127.0.0.2   -> conn1 KEEPS answering as A (state pinned)
//!                        -> conn2 is answered by B
//! ```
//!
//! # Isolation
//!
//! The measurement loads the real `satl/rdr` anchor — the one a running
//! `satld` owns and rewrites every 5 s — so the test **refuses to run while a
//! `satld` is alive** (same discipline as `health_pool.rs`), and flushes the
//! anchor when done: a daemon's next port sweep re-derives it. Echo servers A
//! and B are in-process; B needs `127.0.0.2`, which FreeBSD's `lo0` does not
//! carry by default, so the test adds the alias and removes it afterwards
//! (only if it added it).

use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const PFCTL: &str = "/sbin/pfctl";
const IFCONFIG: &str = "/sbin/ifconfig";
const PGREP: &str = "/bin/pgrep";
const ANCHOR: &str = "satl/rdr";
const TABLE: &str = "satl_p29080_tcp_29101";
const PUBLISHED_PORT: u16 = 29080;
const ECHO_PORT: u16 = 29101;
const ADDR_A: &str = "127.0.0.1";
const ADDR_B: &str = "127.0.0.2";

const RULES: &str = "table <satl_p29080_tcp_29101> persist\nrdr pass inet proto tcp from any to any port 29080 -> <satl_p29080_tcp_29101> port 29101 round-robin\n";

fn run(binary: &str, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(binary)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to spawn {binary}: {err}"));
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn pfctl(args: &[&str], stdin: Option<&str>) {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut child = Command::new(PFCTL)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pfctl");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin piped")
            .write_all(text.as_bytes())
            .expect("feed pfctl");
    }
    let output = child.wait_with_output().expect("wait pfctl");
    assert!(
        output.status.success(),
        "pfctl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Everything the test loaded into the host, undone on drop — success or
/// panic alike.
struct Cleanup {
    alias_added: bool,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new(PFCTL)
            .args(["-a", ANCHOR, "-F", "nat"])
            .status();
        let _ = Command::new(PFCTL)
            .args(["-a", ANCHOR, "-F", "rules"])
            .status();
        if self.alias_added {
            let _ = Command::new(IFCONFIG)
                .args(["lo0", ADDR_B, "-alias"])
                .status();
        }
    }
}

/// One echo server: greets with its identity, then answers every line with
/// `<ident>:<line>`.
async fn echo_server(ident: &'static str, addr: &str) {
    let listener = TcpListener::bind((addr, ECHO_PORT))
        .await
        .unwrap_or_else(|err| panic!("echo server {ident} cannot bind {addr}:{ECHO_PORT}: {err}"));
    loop {
        let (mut conn, _) = listener.accept().await.expect("accept");
        tokio::spawn(async move {
            conn.write_all(ident.as_bytes()).await.unwrap();
            conn.write_all(b"\n").await.unwrap();
            let mut buf = [0_u8; 256];
            loop {
                let read = conn.read(&mut buf).await.unwrap_or(0);
                if read == 0 {
                    break;
                }
                let mut reply = ident.as_bytes().to_vec();
                reply.extend_from_slice(b":");
                reply.extend_from_slice(&buf[..read]);
                if conn.write_all(&reply).await.is_err() {
                    break;
                }
            }
        });
    }
}

/// Read one `\n`-terminated line.
async fn recv_line(conn: &mut TcpStream) -> String {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = conn
            .read(&mut byte)
            .await
            .expect("connection closed mid-line");
        assert!(read > 0, "connection closed mid-line");
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return String::from_utf8_lossy(&line).trim_end().to_owned();
        }
    }
}

/// A connection through the published port, greeted by whoever answered.
async fn probe(tag: &str) -> (TcpStream, String) {
    let mut conn = TcpStream::connect((ADDR_A, PUBLISHED_PORT))
        .await
        .unwrap_or_else(|err| {
            panic!(
                "{tag}: cannot connect to {ADDR_A}:{PUBLISHED_PORT}: {err} -- the rdr did not \
                 fire; is pf enabled with an `rdr-anchor \"satl/*\"` hookup on this host?"
            )
        });
    let who = recv_line(&mut conn).await;
    (conn, who)
}

#[tokio::test]
#[ignore = "requires root, pf loaded with the satl/* hookup, and no live satld"]
async fn established_states_survive_a_table_replace() {
    assert!(
        nix_is_root(),
        "integration tests must run as root (sudo make integration)"
    );
    let (satld_alive, out, _) = run(PGREP, &["-x", "satld"]);
    assert!(
        !satld_alive,
        "refusing to fight a live satld over the satl/rdr anchor (stop it first): {out}"
    );
    // pf must be usable at all (pf.ko + permission).
    let (pf_ok, _, pf_err) = run(PFCTL, &["-s", "info"]);
    assert!(pf_ok, "pf is not usable on this host: {pf_err}");

    // B's address: lo0 carries only 127.0.0.1 on FreeBSD; add the alias and
    // remember whether we did.
    let (_, aliases, _) = run(IFCONFIG, &["lo0"]);
    let alias_added = !aliases.contains(ADDR_B);
    if alias_added {
        let (ok, _, err) = run(IFCONFIG, &["lo0", ADDR_B, "alias"]);
        assert!(ok, "ifconfig lo0 {ADDR_B} alias failed: {err}");
    }
    let _cleanup = Cleanup { alias_added };

    tokio::spawn(echo_server("A", ADDR_A));
    tokio::spawn(echo_server("B", ADDR_B));
    tokio::time::sleep(Duration::from_millis(300)).await;

    pfctl(&["-a", ANCHOR, "-f", "-"], Some(RULES));
    pfctl(&["-a", ANCHOR, "-t", TABLE, "-T", "replace", ADDR_A], None);

    let (mut conn1, who) = probe("conn1").await;
    assert_eq!(who, "A", "conn1 must be answered by A");
    conn1.write_all(b"ping1\n").await.unwrap();
    assert_eq!(recv_line(&mut conn1).await, "A:ping1");

    // The measurement: swap the whole membership under the live connection.
    pfctl(&["-a", ANCHOR, "-t", TABLE, "-T", "replace", ADDR_B], None);

    conn1.write_all(b"ping2\n").await.unwrap();
    let echo = recv_line(&mut conn1).await;
    assert_eq!(
        echo, "A:ping2",
        "the established connection did NOT survive the table replace -- \
         the M6c split writer would kill in-flight connections on every pool change"
    );

    let (conn2, who) = probe("conn2").await;
    assert_eq!(who, "B", "a new connection must land on the new member");
    drop(conn2);
    drop(conn1);

    println!(
        "measured: established state survived -T replace (A kept answering); \
         new connections went to the new member (B)"
    );
}

/// getuid()==0 without a libc dependency in the test harness.
fn nix_is_root() -> bool {
    let (ok, out, _) = run("/usr/bin/id", &["-u"]);
    ok && out.trim() == "0"
}
