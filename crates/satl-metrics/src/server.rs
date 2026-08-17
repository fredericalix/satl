// SPDX-License-Identifier: BSD-2-Clause
//! The standalone `/metrics` HTTP listener.
//!
//! A **separate** axum listener serving only `GET /metrics` — deliberately not
//! a route on the Docker API router: that router is mounted as a
//! `fallback_service` under the version-prefix rewriter
//! (`satl_api::routes`), which would rewrite `/metrics` into
//! `/v1.43/metrics`, and it is bound to a unix socket a Prometheus server
//! cannot scrape. Mirroring dockerd's `--metrics-addr`.
//!
//! **Unauthenticated**, exactly like dockerd's. Bind it to a private address
//! (`docs/operations.md`); the scrape reveals cluster shape, task ids and
//! per-task resource usage.

use std::future::Future;
use std::net::SocketAddr;

use axum::Router;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;

use crate::Metrics;

/// The Prometheus text exposition content type.
const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Serve `GET /metrics` on `addr` until `shutdown` resolves.
///
/// The bind happens up front so a bad address fails the daemon's startup
/// loudly instead of surfacing as a silent task that died.
pub async fn serve(
    addr: SocketAddr,
    metrics: Metrics,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "metrics endpoint listening (unauthenticated)");
    let router = Router::new()
        .route("/metrics", axum::routing::get(metrics_handler))
        .with_state(metrics);
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}

async fn metrics_handler(State(metrics): State<Metrics>) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, CONTENT_TYPE)], metrics.encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scrape over a real socket answers 200, the exposition content type,
    /// and the registered series; any other path is a 404.
    #[tokio::test]
    async fn the_listener_serves_metrics_and_only_metrics() {
        let metrics = Metrics::new();
        metrics.set_services(2);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(addr, metrics, async move {
            let _ = stop_rx.await;
        }));
        // The bind is inside `serve`; retry until it is up.
        let mut body = String::new();
        for _ in 0..50 {
            match scrape(addr, "/metrics").await {
                Ok(got) => {
                    body = got;
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        }
        assert!(body.starts_with("HTTP/1.1 200"), "{body}");
        assert!(body.contains("text/plain; version=0.0.4"), "{body}");
        assert!(body.contains("satl_services 2"), "{body}");
        assert!(body.contains("satl_raft_role"), "{body}");

        let not_found = scrape(addr, "/containers/json").await.unwrap();
        assert!(not_found.starts_with("HTTP/1.1 404"), "{not_found}");

        let _ = stop_tx.send(());
        server.await.unwrap().unwrap();
    }

    /// Minimal HTTP/1.1 GET with `Connection: close` — enough for axum, no
    /// client dependency needed.
    async fn scrape(addr: SocketAddr, path: &str) -> std::io::Result<String> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}
