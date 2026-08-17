// SPDX-License-Identifier: BSD-2-Clause
//! The locked-manager API surface (Docker's autolock, SWK §12.4).
//!
//! A manager whose DEK is sealed boots into **this router alone**: the store
//! cannot be opened, so nothing the full API serves can be answered. What
//! remains is exactly two routes — `GET /_ping`, so a client can see the
//! daemon is alive, and `POST /swarm/unlock`, the one way forward — and a
//! `503` naming the state for everything else.
//!
//! The daemon injects the key check as an [`UnlockGate`], so this crate
//! never names the DEK machinery: the gate is where "the key opens
//! `dek.sealed`" is decided (satld, via `satl_cluster::Dek::open_sealed`).

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;

use crate::types::{UnlockKeyBody, error_response};

/// The daemon's key check: `true` accepts the presented unlock key. What a
/// accepted key sets in motion (unsealing the DEK, continuing the boot) is
/// the daemon's side of the gate.
pub type UnlockGate = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// What every other route answers while the manager is locked.
const LOCKED_MESSAGE: &str =
    "this swarm manager is locked and needs to be unlocked with its unlock key";

/// Builds the locked-mode router. Version-prefixed paths are deliberately
/// not special-cased: a locked daemon answers the bare paths, and anything
/// else — prefixed or not — gets the 503.
pub fn locked_router(gate: UnlockGate) -> Router {
    Router::new()
        .route("/_ping", get(ping))
        .route("/swarm/unlock", post(unlock))
        .fallback(locked)
        .with_state(gate)
}

/// `GET /_ping`: the daemon is alive, and that is all it says.
// Handlers must be `async` for axum even when they never await.
#[allow(clippy::unused_async)]
async fn ping() -> &'static str {
    "OK"
}

/// `POST /swarm/unlock`: the operator's key, tried once against the sealed
/// DEK. Docker's error shape throughout; a wrong key is a 401.
#[allow(clippy::needless_pass_by_value)]
async fn unlock(State(gate): State<UnlockGate>, body: Bytes) -> Response {
    let body: UnlockKeyBody = match crate::routes::json_body(&body) {
        Ok(body) => body,
        Err(error) => return error.into_response(),
    };
    if body.unlock_key.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid parameter: UnlockKey is required",
        );
    }
    if gate(&body.unlock_key) {
        tracing::info!("unlock key accepted; the manager is unsealing its store");
        // Docker answers 200 with an empty body.
        return StatusCode::OK.into_response();
    }
    error_response(
        StatusCode::UNAUTHORIZED,
        "invalid unlock key: it does not open this manager's sealed store",
    )
}

/// Everything else: the store is sealed, so the only honest answer is the
/// 503 that names it (Docker's `errLocked` maps to 503 the same way).
#[allow(clippy::unused_async)]
async fn locked() -> Response {
    error_response(StatusCode::SERVICE_UNAVAILABLE, LOCKED_MESSAGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises the router in-process, over axum's own test call.
    async fn call(
        router: &Router,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;

        let request = http::Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.map_or_else(Vec::new, |body| {
                serde_json::to_vec(&body).expect("json")
            })))
            .expect("request");
        let response = router.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            // Ping answers plain "OK"; everything else is Docker's JSON.
            serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
            })
        };
        (status, json)
    }

    #[tokio::test]
    async fn a_locked_manager_answers_ping_and_nothing_else() {
        let router = locked_router(Arc::new(|_| false));
        let (status, _) = call(&router, "GET", "/_ping", None).await;
        assert_eq!(status, StatusCode::OK);

        for (method, path) in [
            ("GET", "/swarm"),
            ("GET", "/info"),
            ("POST", "/swarm/init"),
            ("GET", "/v1.43/info"),
        ] {
            let (status, body) = call(&router, method, path, None).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{method} {path}");
            assert_eq!(body["message"], LOCKED_MESSAGE, "{method} {path}");
        }
    }

    #[tokio::test]
    async fn unlock_accepts_the_right_key_and_rejects_the_wrong_one() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let gate = {
            let seen = Arc::clone(&seen);
            move |key: &str| {
                seen.lock().expect("lock").push(key.to_owned());
                key == "open-sesame"
            }
        };
        let router = locked_router(Arc::new(gate));

        let (status, body) = call(
            &router,
            "POST",
            "/swarm/unlock",
            Some(serde_json::json!({"UnlockKey": "wrong"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            body["message"]
                .as_str()
                .expect("message")
                .contains("invalid unlock key")
        );

        let (status, _) = call(
            &router,
            "POST",
            "/swarm/unlock",
            Some(serde_json::json!({"UnlockKey": "open-sesame"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            seen.lock().expect("lock").as_slice(),
            ["wrong", "open-sesame"]
        );

        // An empty key is a 400, and never reaches the gate.
        let (status, _) = call(&router, "POST", "/swarm/unlock", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
