// SPDX-License-Identifier: BSD-2-Clause
//! Route table, the M0 system endpoints (`/_ping`, `/version`, `/info`) and
//! the shared request-parsing helpers used by the M1 handlers.
//!
//! Handlers stay deliberately thin: extract, validate/convert
//! (`crate::convert`), call the [`Backend`](crate::backend::Backend), render
//! (`crate::render`). Everything else belongs behind the trait.

mod configs;
mod containers;
mod events;
mod exec;
mod images;
mod networks;
mod nodes;
mod prune;
mod secrets;
mod services;
mod swarm;
mod tasks;
mod volumes;

use std::collections::HashMap;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post};
use axum::{Json, Router, middleware as axum_middleware};
use bytes::Bytes;
use serde::de::DeserializeOwned;

use crate::API_VERSION;
use crate::backend::model::{BackendError, Counts, RegistryAuth};
use crate::middleware;
use crate::render;
use crate::state::ApiState;
use crate::types::{
    ComponentVersion, EngineDetails, InfoResponse, PlatformInfo, VersionResponse, error_response,
};

/// Headers Docker clients read off `/_ping` for version negotiation, sent on
/// both `GET` and `HEAD`.
const PING_HEADERS: [(&str, &str); 5] = [
    ("Api-Version", API_VERSION),
    ("Ostype", "freebsd"),
    ("Docker-Experimental", "false"),
    ("Cache-Control", "no-cache, no-store, must-revalidate"),
    ("Pragma", "no-cache"),
];

/// Largest request body accepted on the JSON endpoints (Docker create bodies
/// are a few kilobytes; this is a sanity bound, not a Docker limit).
const MAX_JSON_BODY: usize = 1024 * 1024;

/// Cap for the two endpoints whose body *is* a payload: `POST /secrets/create`
/// and `POST /configs/create`.
///
/// The largest config `satl-core` accepts is just under 1000 KiB
/// (`MAX_CONFIG_SIZE`), and base64 costs 4 bytes per 3 — 1333 KiB — plus the
/// JSON envelope. [`MAX_JSON_BODY`] would therefore reject a config the store
/// would have accepted, with a message about body size rather than about the
/// config limit. 2 MiB clears the encoded maximum with room for the envelope
/// while still bounding what one request can allocate; the real limit stays
/// `satl-core`'s, which is where the operator-facing message comes from.
const PAYLOAD_JSON_BODY: usize = 2 * 1024 * 1024;

/// Builds the Docker Engine REST API router.
///
/// Every route is served both on its bare path and under any supported
/// `/vX.Y/` version prefix (Docker version negotiation, handled by
/// middleware). All responses carry a `Server: SatL/<version>` header, and
/// unmatched paths return Docker's `{"message": "page not found"}` shape.
pub fn router(state: ApiState) -> Router {
    let api = Router::new()
        .route("/_ping", get(ping).head(ping_head))
        .route("/version", get(version))
        .route("/info", get(info))
        .route("/events", get(events::stream))
        // Containers.
        .route("/containers/create", post(containers::create))
        .route("/containers/json", get(containers::list))
        // Before `/containers/{id}`: axum matches literals first, but keeping
        // the prune routes adjacent to their siblings is what stops a future
        // `/containers/{id}` verb from shadowing one.
        .route("/containers/prune", post(prune::containers))
        .route("/containers/{id}", delete(containers::remove))
        .route("/containers/{id}/json", get(containers::inspect))
        .route("/containers/{id}/start", post(containers::start))
        .route("/containers/{id}/stop", post(containers::stop))
        .route("/containers/{id}/kill", post(containers::kill))
        .route("/containers/{id}/wait", post(containers::wait))
        .route("/containers/{id}/logs", get(containers::logs))
        .route("/containers/{id}/exec", post(exec::create))
        // Exec.
        .route("/exec/{id}/start", post(exec::start))
        .route("/exec/{id}/json", get(exec::inspect))
        // Images.
        .route("/images/create", post(images::create))
        .route("/images/json", get(images::list))
        .route("/images/prune", post(prune::images))
        // `/images/{name}/tag` — a tail wildcard because an image name may
        // carry slashes; the handler serves only the tag verb and answers
        // the fallback's 404 to everything else. Literals above win over
        // the wildcard, so `/images/create` & co. are untouched.
        .route("/images/{*rest}", any(images::by_name))
        // Volumes.
        .route("/volumes", get(volumes::list))
        .route("/volumes/create", post(volumes::create))
        .route("/volumes/prune", post(prune::volumes))
        .route(
            "/volumes/{name}",
            get(volumes::inspect).delete(volumes::remove),
        )
        // Networks.
        .route("/networks", get(networks::list))
        .route("/networks/create", post(networks::create))
        .route("/networks/prune", post(prune::networks))
        .route(
            "/networks/{id}",
            get(networks::inspect).delete(networks::remove),
        )
        .route("/networks/{id}/connect", post(networks::connect))
        .route("/networks/{id}/disconnect", post(networks::disconnect))
        // Swarm.
        .route("/swarm", get(swarm::inspect))
        .route("/swarm/init", post(swarm::init))
        .route("/swarm/join", post(swarm::join))
        .route("/swarm/leave", post(swarm::leave))
        .route("/swarm/update", post(swarm::update))
        .route("/swarm/unlock", post(swarm::unlock))
        .route("/swarm/unlockkey", get(swarm::unlock_key))
        // Nodes.
        .route("/nodes", get(nodes::list))
        .route("/nodes/{id}", get(nodes::inspect).delete(nodes::remove))
        .route("/nodes/{id}/update", post(nodes::update))
        // Services.
        .route("/services", get(services::list))
        .route("/services/create", post(services::create))
        .route(
            "/services/{id}",
            get(services::inspect).delete(services::remove),
        )
        .route("/services/{id}/update", post(services::update))
        // Tasks.
        .route("/tasks", get(tasks::list))
        .route("/tasks/{id}", get(tasks::inspect))
        // Secrets.
        .route("/secrets", get(secrets::list))
        .route("/secrets/create", post(secrets::create))
        .route(
            "/secrets/{id}",
            get(secrets::inspect).delete(secrets::remove),
        )
        .route("/secrets/{id}/update", post(secrets::update))
        // Configs.
        .route("/configs", get(configs::list))
        .route("/configs/create", post(configs::create))
        .route(
            "/configs/{id}",
            get(configs::inspect).delete(configs::remove),
        )
        .route("/configs/{id}/update", post(configs::update))
        .fallback(not_found)
        .with_state(state.clone());

    // Middleware added with `Router::layer` runs *after* routing, so the
    // URI-rewriting `version_prefix` middleware cannot be layered onto `api`
    // directly. Instead every request enters an outer router whose fallback
    // is the whole API router: the layers below wrap that fallback and
    // therefore run *before* the API router routes. Outermost first:
    // trace -> server header -> version prefix -> API routing, so the 400
    // responses minted by `version_prefix` are still stamped and logged.
    Router::new()
        .fallback_service(api)
        .layer(axum_middleware::from_fn(middleware::version_prefix))
        .layer(axum_middleware::from_fn_with_state(
            state,
            middleware::server_header,
        ))
        .layer(axum_middleware::from_fn(middleware::trace_http))
}

/// `GET /_ping`: liveness probe plus version-negotiation headers.
// Handlers must be `async` for axum even when they never await.
#[allow(clippy::unused_async)]
async fn ping() -> impl IntoResponse {
    (PING_HEADERS, "OK")
}

/// `HEAD /_ping`: same headers as `GET`, empty body.
#[allow(clippy::unused_async)]
async fn ping_head() -> impl IntoResponse {
    (PING_HEADERS, "")
}

/// `GET /version`: Docker `SystemVersion` document built from [`ApiState`].
// Extractors are taken by value; `ApiState` is an Arc handle, cloning is the point.
#[allow(clippy::unused_async, clippy::needless_pass_by_value)]
async fn version(State(state): State<ApiState>) -> Json<VersionResponse> {
    let v = state.version();
    Json(VersionResponse {
        platform: PlatformInfo {
            name: "SatL".to_owned(),
        },
        components: vec![ComponentVersion {
            name: "Engine".to_owned(),
            version: v.version.clone(),
            details: EngineDetails {
                api_version: v.api_version.clone(),
                arch: v.arch.clone(),
                build_time: v.build_time.clone(),
                git_commit: v.git_commit.clone(),
                kernel_version: v.kernel_version.clone(),
                min_api_version: v.min_api_version.clone(),
                os: v.os.clone(),
            },
        }],
        version: v.version.clone(),
        api_version: v.api_version.clone(),
        min_api_version: v.min_api_version.clone(),
        git_commit: v.git_commit.clone(),
        os: v.os.clone(),
        arch: v.arch.clone(),
        kernel_version: v.kernel_version.clone(),
        build_time: v.build_time.clone(),
    })
}

/// `GET /info`: minimal coherent Docker `SystemInfo` document.
///
/// Counts and the `Swarm` section both come from the backend. A backend that
/// answers `NotImplemented` to
/// [`swarm_status`](crate::Backend::swarm_status) — the state `satld` is in
/// before it wires its own implementation — falls back to the static identity
/// injected into [`ApiState`], so `/info` never fails for want of cluster
/// state.
#[allow(clippy::needless_pass_by_value)]
async fn info(State(state): State<ApiState>) -> Result<Json<InfoResponse>, BackendError> {
    let sys = state.system();
    let counts: Counts = state.backend().system_counts().await?;
    let swarm = match state.backend().swarm_status().await {
        Ok(status) => render::cluster::swarm_info(&status),
        Err(BackendError::NotImplemented(_)) => render::cluster::swarm_info_static(state.swarm()),
        Err(err) => return Err(err),
    };
    Ok(Json(InfoResponse {
        id: sys.id.clone(),
        name: sys.name.clone(),
        ncpu: sys.ncpu,
        mem_total: sys.mem_total,
        operating_system: sys.operating_system.clone(),
        os_version: sys.os_version.clone(),
        os_type: "freebsd".to_owned(),
        architecture: state.version().arch.clone(),
        server_version: sys.server_version.clone(),
        driver: "zfs".to_owned(),
        containers: counts.containers,
        containers_running: counts.containers_running,
        containers_paused: counts.containers_paused,
        containers_stopped: counts.containers_stopped,
        images: counts.images,
        swarm,
        warnings: Vec::new(),
    }))
}

/// Fallback for unmatched paths: Docker's 404 error shape.
#[allow(clippy::unused_async)]
async fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "page not found")
}

/// Query parameters of a request, as Docker sends them (flat, string-valued).
pub(crate) type Params = HashMap<String, String>;

/// Docker's boolean query semantics (`api/server/httputils.BoolValue`): any
/// value that is not empty, `0`, `no`, `false` or `none` means true.
pub(crate) fn flag(params: &Params, key: &str) -> bool {
    params.get(key).is_some_and(|value| {
        let value = value.trim().to_ascii_lowercase();
        !matches!(value.as_str(), "" | "0" | "no" | "false" | "none")
    })
}

/// A non-empty query parameter, trimmed.
pub(crate) fn param<'a>(params: &'a Params, key: &str) -> Option<&'a str> {
    params
        .get(key)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
}

/// Header carrying the base64url-encoded `AuthConfig` document.
const REGISTRY_AUTH_HEADER: &str = "X-Registry-Auth";

/// Decodes `X-Registry-Auth`, if the client sent one.
pub(crate) fn registry_auth(headers: &HeaderMap) -> Result<Option<RegistryAuth>, BackendError> {
    let Some(value) = headers.get(REGISTRY_AUTH_HEADER) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| BackendError::invalid("invalid X-Registry-Auth header: not valid ASCII"))?;
    if value.trim().is_empty() {
        return Ok(None);
    }
    crate::convert::decode_registry_auth(value).map(Some)
}

/// Rejects a non-empty `?filters=` on the listing endpoints that do not
/// implement filtering yet, rather than silently listing everything.
pub(crate) fn reject_filters(params: &Params, kind: &str) -> Result<(), BackendError> {
    match param(params, "filters") {
        None | Some("{}") => Ok(()),
        Some(filters) => Err(BackendError::not_implemented(format!(
            "filtering {kind} is not supported yet (got {filters:?})"
        ))),
    }
}

/// Deserializes a JSON request body, treating an empty body as "all
/// defaults" (Docker clients omit the body on `POST /exec/{id}/start`-style
/// calls) and reporting parse failures in Docker's error shape.
pub(crate) fn json_body<T: DeserializeOwned + Default>(body: &Bytes) -> Result<T, BackendError> {
    json_body_sized(body, MAX_JSON_BODY)
}

/// [`json_body`] with an explicit cap, for the endpoints whose body carries a
/// base64 payload ([`PAYLOAD_JSON_BODY`]).
pub(crate) fn json_body_sized<T: DeserializeOwned + Default>(
    body: &Bytes,
    max: usize,
) -> Result<T, BackendError> {
    if body.len() > max {
        return Err(BackendError::invalid(format!(
            "request body is too large ({} bytes, maximum {max})",
            body.len()
        )));
    }
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    serde_json::from_slice(body)
        .map_err(|err| BackendError::invalid(format!("invalid JSON in request body: {err}")))
}

/// Serializes one streamed JSON line, falling back to a Docker-shaped error
/// line rather than panicking (no `unwrap` on the streaming paths).
pub(crate) fn json_line(value: &impl serde::Serialize, terminator: &[u8]) -> Bytes {
    let mut buffer = serde_json::to_vec(value).unwrap_or_else(|err| {
        tracing::error!(error = %err, "failed to encode a streamed JSON line");
        br#"{"error":"satld failed to encode this message"}"#.to_vec()
    });
    buffer.extend_from_slice(terminator);
    Bytes::from(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> Params {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn flag_follows_docker_bool_value() {
        let truthy = params(&[
            ("a", "1"),
            ("b", "true"),
            ("c", "True"),
            ("d", "yes"),
            ("e", "anything"),
        ]);
        for key in ["a", "b", "c", "d", "e"] {
            assert!(flag(&truthy, key), "{key} must be true");
        }
        let falsey = params(&[
            ("a", ""),
            ("b", "0"),
            ("c", "no"),
            ("d", "false"),
            ("e", "None"),
        ]);
        for key in ["a", "b", "c", "d", "e"] {
            assert!(!flag(&falsey, key), "{key} must be false");
        }
        assert!(!flag(&falsey, "missing"));
    }

    #[test]
    fn param_trims_and_drops_empties() {
        let values = params(&[("name", " web "), ("tag", "")]);
        assert_eq!(param(&values, "name"), Some("web"));
        assert_eq!(param(&values, "tag"), None);
        assert_eq!(param(&values, "missing"), None);
    }

    #[test]
    fn json_body_accepts_empty_and_rejects_garbage() {
        #[derive(Debug, Default, PartialEq, Eq, serde::Deserialize)]
        struct Body {
            #[serde(default)]
            name: String,
        }
        assert_eq!(
            json_body::<Body>(&Bytes::from_static(b"")).expect("empty body is defaults"),
            Body::default()
        );
        assert_eq!(
            json_body::<Body>(&Bytes::from_static(b" \n")).expect("blank body is defaults"),
            Body::default()
        );
        assert_eq!(
            json_body::<Body>(&Bytes::from_static(br#"{"name":"web"}"#)).expect("valid body"),
            Body {
                name: "web".to_owned()
            }
        );
        let err = json_body::<Body>(&Bytes::from_static(b"{oops")).expect_err("invalid JSON");
        assert!(
            err.to_string().contains("invalid JSON in request body"),
            "{err}"
        );
    }

    #[test]
    fn json_line_appends_its_terminator() {
        let line = json_line(&serde_json::json!({"status": "Pulling"}), b"\r\n");
        assert_eq!(&line[..], b"{\"status\":\"Pulling\"}\r\n");
    }
}
