// SPDX-License-Identifier: BSD-2-Clause
//! A scripted Docker-API daemon on a temporary unix socket.
//!
//! Real axum server, real hyper client, real unix socket in a tempdir — the
//! only thing faked is the daemon's behavior. Replies are queued per
//! `METHOD /path`; the last queued reply for a route keeps answering, so a
//! script like "404 then 201" pins the pull-on-missing-image retry exactly.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use hyper::StatusCode;
use hyper::header::{CONNECTION, CONTENT_TYPE, UPGRADE};
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt as _;

use crate::client::Host;

/// What the stub answers for one call.
#[derive(Debug, Clone)]
pub enum Reply {
    /// Status, extra response headers, and a body (JSON unless the body is
    /// not JSON-shaped).
    Body(StatusCode, Vec<(String, String)>, Vec<u8>),
    /// `101 Switching Protocols`, then these bytes on the hijacked socket.
    Hijack(Vec<u8>),
}

impl Reply {
    /// A JSON reply.
    pub fn json(status: u16, body: &str) -> Self {
        Self::Body(
            StatusCode::from_u16(status).expect("valid status"),
            Vec::new(),
            body.as_bytes().to_vec(),
        )
    }

    /// An empty reply (`204`, or an error status with no body).
    pub fn empty(status: u16) -> Self {
        Self::Body(
            StatusCode::from_u16(status).expect("valid status"),
            Vec::new(),
            Vec::new(),
        )
    }

    /// A raw byte body — multiplexed log frames, progress lines, …
    pub fn raw(status: u16, body: Vec<u8>) -> Self {
        Self::Body(
            StatusCode::from_u16(status).expect("valid status"),
            Vec::new(),
            body,
        )
    }

    /// Add a response header. The daemon puts what does not fit Docker's
    /// response shapes here — `X-Satl-Deferred-Layers` on an image removal.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        if let Self::Body(_, headers, _) = &mut self {
            headers.push((name.to_owned(), value.to_owned()));
        }
        self
    }
}

/// One call the CLI made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    /// HTTP method.
    pub method: String,
    /// Path, without the query string.
    pub path: String,
    /// Raw query string.
    pub query: String,
    /// Request body, as text.
    pub body: String,
}

impl Recorded {
    /// `"METHOD /path"`, for asserting on call sequences.
    pub fn route(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

#[derive(Debug, Default)]
struct Shared {
    replies: Mutex<HashMap<String, Vec<Reply>>>,
    recorded: Mutex<Vec<Recorded>>,
}

impl Shared {
    fn take(&self, route: &str) -> Option<Reply> {
        let mut replies = self.replies.lock().unwrap_or_else(PoisonError::into_inner);
        let queue = replies.get_mut(route)?;
        if queue.len() > 1 {
            Some(queue.remove(0))
        } else {
            queue.first().cloned()
        }
    }
}

/// A running stub daemon; the socket and its directory are removed on drop.
#[derive(Debug)]
pub struct Stub {
    shared: Arc<Shared>,
    socket: PathBuf,
    _dir: tempfile::TempDir,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Stub {
    /// Bind a socket in a fresh tempdir and start serving.
    // Async without an await: it must run inside a tokio runtime anyway (it
    // binds the socket and spawns the server task).
    #[allow(clippy::unused_async)]
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("satl.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind stub socket");
        let shared = Arc::new(Shared::default());
        let app = axum::Router::new()
            .fallback(handle)
            .with_state(Arc::clone(&shared));
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            shared,
            socket,
            _dir: dir,
            server,
        }
    }

    /// The `--host` value pointing at this stub.
    pub fn host(&self) -> Host {
        Host::Unix(self.socket.clone())
    }

    /// Queue a reply for `METHOD path`.
    pub fn on(&self, method: &str, path: &str, reply: Reply) -> &Self {
        self.shared
            .replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(format!("{method} {path}"))
            .or_default()
            .push(reply);
        self
    }

    /// Every call the CLI made, in order.
    pub fn calls(&self) -> Vec<Recorded> {
        self.shared
            .recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The `METHOD /path` sequence, for sequence assertions.
    pub fn routes(&self) -> Vec<String> {
        self.calls().iter().map(Recorded::route).collect()
    }

    /// The first recorded call to a route, if any.
    pub fn first_call(&self, route: &str) -> Option<Recorded> {
        self.calls().into_iter().find(|call| call.route() == route)
    }
}

async fn handle(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    let (mut parts, body) = request.into_parts();
    let upgrade = parts.extensions.remove::<hyper::upgrade::OnUpgrade>();
    let bytes = axum::body::to_bytes(body, 4 * 1024 * 1024)
        .await
        .unwrap_or_default();
    let recorded = Recorded {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().unwrap_or_default().to_owned(),
        body: String::from_utf8_lossy(&bytes).into_owned(),
    };
    let route = recorded.route();
    shared
        .recorded
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(recorded);

    match shared.take(&route) {
        Some(Reply::Body(status, headers, body)) => {
            let mut builder = Response::builder()
                .status(status)
                .header(CONTENT_TYPE, "application/json");
            for (name, value) in headers {
                builder = builder.header(name, value);
            }
            builder.body(Body::from(body)).expect("valid response")
        }
        Some(Reply::Hijack(payload)) => {
            if let Some(upgrade) = upgrade {
                tokio::spawn(async move {
                    if let Ok(upgraded) = upgrade.await {
                        let mut io = TokioIo::new(upgraded);
                        let _ = io.write_all(&payload).await;
                        let _ = io.shutdown().await;
                    }
                });
            }
            Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(UPGRADE, "tcp")
                .header(CONNECTION, "Upgrade")
                .body(Body::empty())
                .expect("valid response")
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"message":"stub daemon has no scripted reply for {route}"}}"#
            )))
            .expect("valid response"),
    }
}

/// Build a multiplexed frame the way the daemon does.
pub fn frame(stream: u8, payload: &str) -> Vec<u8> {
    let mut out = vec![stream, 0, 0, 0];
    let len = u32::try_from(payload.len()).expect("payload fits u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload.as_bytes());
    out
}

/// Concatenate frames into one response body.
pub fn frames(parts: &[(u8, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (stream, payload) in parts {
        out.extend_from_slice(&frame(*stream, payload));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client;

    #[tokio::test]
    async fn serves_scripted_replies_and_records_calls() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/version",
            Reply::json(200, r#"{"Version":"0.1.0"}"#),
        );

        let value: serde_json::Value = client::get_json(&stub.host(), "/version").await.unwrap();
        assert_eq!(value["Version"], "0.1.0");
        assert_eq!(stub.routes(), vec!["GET /version"]);
    }

    #[tokio::test]
    async fn queued_replies_are_consumed_in_order_then_repeat() {
        let stub = Stub::start().await;
        stub.on("GET", "/x", Reply::json(500, r#"{"message":"boom"}"#))
            .on("GET", "/x", Reply::json(200, r#"{"ok":true}"#));

        let err = client::get_json::<serde_json::Value>(&stub.host(), "/x")
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "Error response from daemon: boom");
        for _ in 0..2 {
            let value: serde_json::Value = client::get_json(&stub.host(), "/x").await.unwrap();
            assert_eq!(value["ok"], true);
        }
    }

    #[tokio::test]
    async fn unscripted_routes_produce_a_daemon_error() {
        let stub = Stub::start().await;
        let err = client::get_json::<serde_json::Value>(&stub.host(), "/nope")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no scripted reply"), "{err}");
    }

    #[tokio::test]
    async fn connection_refused_keeps_the_operator_message() {
        let host = Host::parse("unix:///nonexistent/satl.sock").unwrap();
        let err = client::get_json::<serde_json::Value>(&host, "/version")
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Cannot connect to the SatL daemon at unix:///nonexistent/satl.sock. Is satld running?"
        );
    }
}
