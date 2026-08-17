// SPDX-License-Identifier: BSD-2-Clause
//! The L4 proxy publish mode (M6e): an opt-in userspace path that preserves
//! the client address, for services labeled `satl.publish.proxy_protocol=v2`.
//!
//! Why this exists: the pf mesh (M6d) SNATs relayed connections, so the task
//! sees the relaying node's gateway, not the client. For workloads that need
//! the real address (logs, rate limiting, fail2ban, geo), `satld` itself
//! listens on the published port, picks a healthy task from the same set that
//! feeds the pf pool, dials it over the overlay, writes a PROXY protocol v2
//! header, and splices. The TCP connection is re-originated, so there is no
//! MTU concern and no SNAT — the trade is a userspace copy and `satld` in the
//! data path, documented in `docs/operations.md`.
//!
//! A port in proxy mode never gets a pf `rdr` rule (the kernel would win the
//! race for the packet): the port sweep splits the two sets
//! (`crates/satld/src/reconcile.rs`) and feeds this manager the proxy one.
//! TCP only; a UDP port of a labeled service stays on the pf path.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use satl_core::PortProtocol;
use tokio_util::sync::CancellationToken;

/// What one published port proxies to: the live members (task overlay or
/// bridge address + container port), shared with the accept loop.
struct ProxyPort {
    /// Members as `addr:task_port`, refreshed by the port sweep.
    members: Arc<RwLock<Arc<Vec<SocketAddr>>>>,
    /// Round-robin cursor.
    next: Arc<std::sync::atomic::AtomicUsize>,
    /// Stops the accept loop when the port leaves the proxy set.
    cancel: CancellationToken,
}

/// The proxy-mode view of the published ports, fed by the port sweep.
pub struct ProxyManager {
    /// Live listeners, keyed by (published port, protocol).
    ports: tokio::sync::Mutex<BTreeMap<(u16, PortProtocol), ProxyPort>>,
    /// The daemon's shutdown token: listener loops end with it.
    shutdown: CancellationToken,
}

impl ProxyPort {
    /// The next member, round-robin. `None` when the pool is empty — the
    /// caller closes the connection, which is what a drained pool must look
    /// like to a client.
    fn pick(&self) -> Option<SocketAddr> {
        let members = self.members.read().expect("members lock poisoned").clone();
        if members.is_empty() {
            return None;
        }
        let at = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(members[at % members.len()])
    }
}

impl ProxyManager {
    /// An idle manager; `update` drives everything.
    #[must_use]
    pub fn new(shutdown: CancellationToken) -> Self {
        Self {
            ports: tokio::sync::Mutex::new(BTreeMap::new()),
            shutdown,
        }
    }

    /// Converge the listeners on `desired`: published port (+ protocol) to the
    /// current healthy members. Level-triggered like the pf writer it shares
    /// the sweep with: new ports get a listener, gone ports lose theirs, and
    /// membership changes land in the shared cell without touching the
    /// listener.
    pub async fn update(&self, desired: BTreeMap<(u16, PortProtocol), Vec<(Ipv4Addr, u16)>>) {
        let shutdown = &self.shutdown;
        let mut ports = self.ports.lock().await;
        let stale: Vec<(u16, PortProtocol)> = ports
            .keys()
            .filter(|key| !desired.contains_key(*key))
            .copied()
            .collect();
        for key in stale {
            if let Some(port) = ports.remove(&key) {
                tracing::info!(port = key.0, "proxy listener removed");
                port.cancel.cancel();
            }
        }
        for ((port, proto), members) in desired {
            let members: Vec<SocketAddr> = members
                .into_iter()
                .map(|(addr, task_port)| SocketAddr::from((addr, task_port)))
                .collect();
            if let Some(existing) = ports.get_mut(&(port, proto)) {
                *existing.members.write().expect("members lock poisoned") = Arc::new(members);
                continue;
            }
            if proto != PortProtocol::Tcp {
                // PROXY v2 over UDP is out of scope (M6e); the port
                // stays on the pf path (the sweep never split it out).
                continue;
            }
            match self.listen(port, shutdown).await {
                Ok(proxy) => {
                    *proxy.members.write().expect("members lock poisoned") = Arc::new(members);
                    ports.insert((port, proto), proxy);
                }
                Err(error) => {
                    // Typically EADDRINUSE. Not fatal: the next pass
                    // retries, and the error names the port.
                    tracing::error!(%port, %error, "proxy listener failed to bind");
                }
            }
        }
    }

    /// Bind one published port and spawn its accept loop.
    async fn listen(
        &self,
        port: u16,
        shutdown: &CancellationToken,
    ) -> Result<ProxyPort, std::io::Error> {
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))).await?;
        tracing::info!(%port, "proxy listener bound (PROXY protocol v2)");
        let proxy = ProxyPort {
            members: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            next: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            cancel: CancellationToken::new(),
        };
        let loop_members = Arc::clone(&proxy.members);
        let loop_next = Arc::clone(&proxy.next);
        let loop_cancel = proxy.cancel.clone();
        let loop_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let port_view = ProxyPort {
                members: loop_members,
                next: loop_next,
                cancel: loop_cancel.clone(),
            };
            loop {
                tokio::select! {
                    biased;
                    () = loop_cancel.cancelled() => break,
                    () = loop_shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((client, peer)) => {
                                tokio::spawn(relay(client, peer, ProxyPort {
                                    members: Arc::clone(&port_view.members),
                                    next: Arc::clone(&port_view.next),
                                    cancel: loop_cancel.clone(),
                                }));
                            }
                            Err(error) => {
                                tracing::warn!(%error, "proxy accept failed");
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }
        });
        Ok(proxy)
    }
}

/// One client connection: pick a member, connect, write the PROXY v2 header,
/// splice. A member that refuses is skipped for the next one (a member that
/// refuses connections is about to leave the pool — the health loop drives
/// that).
async fn relay(client: tokio::net::TcpStream, peer: SocketAddr, port: ProxyPort) {
    let mut tried = Vec::new();
    for _ in 0..2 {
        let Some(member) = port.pick() else {
            tracing::debug!(%peer, "proxy pool is empty; connection closed");
            return;
        };
        if tried.contains(&member) {
            return;
        }
        tried.push(member);
        match tokio::net::TcpStream::connect(member).await {
            Ok(upstream) => {
                if let Err(error) = splice(client, peer, member, upstream).await {
                    tracing::debug!(%peer, %member, %error, "proxy relay failed");
                }
                return;
            }
            Err(error) => {
                tracing::debug!(%peer, %member, %error, "proxy member refused; trying the next");
            }
        }
    }
}

/// Write the PROXY v2 header, then splice both directions to completion.
async fn splice(
    mut client: tokio::net::TcpStream,
    peer: SocketAddr,
    member: SocketAddr,
    mut upstream: tokio::net::TcpStream,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;
    upstream.write_all(&proxy_v2_header(peer, member)).await?;
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
    let to_client = tokio::io::copy(&mut upstream_read, &mut client_write);
    let _ = tokio::join!(to_upstream, to_client);
    Ok(())
}

/// A PROXY protocol v2 header (TCP over IPv4): the client's real address and
/// port, so the task behind the proxy sees the caller, not the relay.
fn proxy_v2_header(client: SocketAddr, server: SocketAddr) -> Vec<u8> {
    let mut header = Vec::with_capacity(28);
    header.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n"); // signature
    header.push(0x21); // version 2, PROXY command
    if let (SocketAddr::V4(client), SocketAddr::V4(server)) = (client, server) {
        header.push(0x11); // AF_INET, STREAM
        header.extend_from_slice(&12_u16.to_be_bytes()); // addr len
        header.extend_from_slice(&client.ip().octets());
        header.extend_from_slice(&server.ip().octets());
        header.extend_from_slice(&client.port().to_be_bytes());
        header.extend_from_slice(&server.port().to_be_bytes());
    } else {
        // No IPv6 on SatL's data plane today: LOCAL command, zero-length
        // addresses — the receiver must ignore the addresses but accept
        // the connection (HAProxy's PROXY v2 spec).
        header[12] = 0x20; // version 2, LOCAL command
        header.push(0x00); // UNSPEC
        header.extend_from_slice(&0_u16.to_be_bytes());
    }
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_v2_header_is_the_spec_shape() {
        let client: SocketAddr = "203.0.113.7:49152".parse().unwrap();
        let server: SocketAddr = "10.100.0.5:80".parse().unwrap();
        let header = proxy_v2_header(client, server);
        assert_eq!(header.len(), 28);
        assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(header[12], 0x21); // v2, PROXY
        assert_eq!(header[13], 0x11); // inet, stream
        assert_eq!(&header[14..16], &12_u16.to_be_bytes());
        assert_eq!(&header[16..20], &[203, 0, 113, 7]);
        assert_eq!(&header[20..24], &[10, 100, 0, 5]);
        assert_eq!(&header[24..26], &49152_u16.to_be_bytes());
        assert_eq!(&header[26..28], &80_u16.to_be_bytes());
    }

    #[test]
    fn round_robin_cycles_and_an_empty_pool_picks_nothing() {
        let port = ProxyPort {
            members: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            next: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            cancel: CancellationToken::new(),
        };
        assert_eq!(port.pick(), None);
        let a = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 80));
        let b = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 80));
        *port.members.write().unwrap() = Arc::new(vec![a, b]);
        assert_eq!(port.pick(), Some(a));
        assert_eq!(port.pick(), Some(b));
        assert_eq!(port.pick(), Some(a));
    }

    /// A live relay: the listener answers, the member receives the PROXY
    /// header with the client's real address before the payload.
    #[tokio::test]
    async fn a_connection_is_relayed_with_the_client_address() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        // The member: a listener that reports what it received. The header
        // and the payload arrive as separate segments — read them as such.
        let member_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let member_addr = member_listener.local_addr().unwrap();
        let member_task = tokio::spawn(async move {
            let (mut conn, _) = member_listener.accept().await.unwrap();
            let mut header = [0_u8; 28];
            conn.read_exact(&mut header).await.unwrap();
            let mut payload = Vec::new();
            let mut buf = [0_u8; 16];
            let n = conn.read(&mut buf).await.unwrap();
            payload.extend_from_slice(&buf[..n]);
            conn.write_all(b"answer").await.unwrap();
            (header.to_vec(), payload)
        });

        let manager = ProxyManager::new(CancellationToken::new());
        let probe_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe_listener.local_addr().unwrap().port();
        drop(probe_listener);
        let mut desired = BTreeMap::new();
        desired.insert(
            (port, PortProtocol::Tcp),
            vec![(Ipv4Addr::LOCALHOST, member_addr.port())],
        );
        manager.update(desired).await;

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut answer = [0_u8; 6];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"answer");

        let (received, payload) = member_task.await.unwrap();
        assert_eq!(&received[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(received[12], 0x21);
        // The client address in the header is the loopback peer, not the proxy.
        assert_eq!(&received[16..20], &[127, 0, 0, 1]);
        assert_eq!(payload, b"hello");
    }
}
