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
// `pub(crate)` for this module alone: the three operations behind the
// `/images/{name}/*` tail wildcard cannot be registered through `routes!`
// (OpenAPI has no tail wildcard), so they are declared on `ApiDoc` in
// `crate::openapi` instead, and that sibling module has to be able to name
// them.
pub(crate) mod images;
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
use axum::routing::any;
use axum::{Json, Router, middleware as axum_middleware};
use bytes::Bytes;
use serde::de::DeserializeOwned;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

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
    let api = api_router()
        .split_for_parts()
        .0
        // The ONE route in this file not registered through `routes!`, and
        // the only `.route(` call a reviewer should find here: OpenAPI cannot
        // express a tail wildcard. The `/images/{name}/*` family needs one
        // because an image name may carry slashes; the handler dispatches on
        // the method and serves tag, inspect and remove, answering the
        // fallback's 404 to everything else. Its three operations are
        // documented on `ApiDoc` (`crate::openapi`) instead. Literals
        // registered above win over the wildcard, so `/images/create` & co.
        // are untouched.
        .route("/images/{*rest}", any(images::by_name))
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

/// The route set, declared once for both the axum router and the `OpenAPI`
/// document.
///
/// Every operation is registered through [`routes!`], which reads its method
/// and path off the handler's own `#[utoipa::path]` attribute — so a route
/// and its documentation cannot drift apart. All handlers in one `routes!`
/// invocation must declare the *same* path: that is the direct translation of
/// `.route(p, get(x).delete(y))`.
fn api_router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(ping, ping_head))
        .routes(routes!(version))
        .routes(routes!(info))
        .routes(routes!(events::stream))
        // Containers.
        .routes(routes!(containers::create))
        .routes(routes!(containers::list))
        // Before `/containers/{id}`: axum matches literals first, but keeping
        // the prune routes adjacent to their siblings is what stops a future
        // `/containers/{id}` verb from shadowing one.
        .routes(routes!(prune::containers))
        .routes(routes!(containers::remove))
        .routes(routes!(containers::inspect))
        .routes(routes!(containers::start))
        .routes(routes!(containers::stop))
        .routes(routes!(containers::kill))
        .routes(routes!(containers::wait))
        .routes(routes!(containers::logs))
        .routes(routes!(exec::create))
        // Exec.
        .routes(routes!(exec::start))
        .routes(routes!(exec::inspect))
        // Images.
        .routes(routes!(images::create))
        .routes(routes!(images::list))
        .routes(routes!(prune::images))
        // The `/images/{name}/*` family is the tail wildcard added in
        // `router`; its three operations live on `ApiDoc` instead.
        // Volumes.
        .routes(routes!(volumes::list))
        .routes(routes!(volumes::create))
        .routes(routes!(prune::volumes))
        .routes(routes!(volumes::inspect, volumes::remove))
        // Networks.
        .routes(routes!(networks::list))
        .routes(routes!(networks::create))
        .routes(routes!(prune::networks))
        .routes(routes!(networks::inspect, networks::remove))
        .routes(routes!(networks::connect))
        .routes(routes!(networks::disconnect))
        // Swarm.
        .routes(routes!(swarm::inspect))
        .routes(routes!(swarm::init))
        .routes(routes!(swarm::join))
        .routes(routes!(swarm::leave))
        .routes(routes!(swarm::update))
        .routes(routes!(swarm::unlock))
        .routes(routes!(swarm::unlock_key))
        // Nodes.
        .routes(routes!(nodes::list))
        .routes(routes!(nodes::inspect, nodes::remove))
        .routes(routes!(nodes::update))
        // Services.
        .routes(routes!(services::list))
        .routes(routes!(services::create))
        .routes(routes!(services::inspect, services::remove))
        .routes(routes!(services::update))
        // Tasks.
        .routes(routes!(tasks::list))
        .routes(routes!(tasks::inspect))
        // Secrets.
        .routes(routes!(secrets::list))
        .routes(routes!(secrets::create))
        .routes(routes!(secrets::inspect, secrets::remove))
        .routes(routes!(secrets::update))
        // Configs.
        .routes(routes!(configs::list))
        .routes(routes!(configs::create))
        .routes(routes!(configs::inspect, configs::remove))
        .routes(routes!(configs::update))
}

/// The paths and schemas collected off the route set, for
/// [`crate::openapi::spec`] to dress with info, tags and servers.
// Only the document generator (a test) calls this; see the note at the top of
// `crate::openapi`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    api_router().split_for_parts().1
}

/// `GET /_ping`: liveness probe plus version-negotiation headers.
// Handlers must be `async` for axum even when they never await.
#[allow(clippy::unused_async)]
#[utoipa::path(
    get,
    path = "/_ping",
    operation_id = "SystemPing",
    tag = "System",
    description = "Liveness probe. The body is the literal string `OK`; the \
        version-negotiation headers are what clients read: `Api-Version`, \
        `Ostype`, `Docker-Experimental` (always `false`) and no \
        `Builder-Version` -- SatL has no BuildKit (api-compat, daemon-wide). \
        One of the two routes a locked manager still serves.",
    responses((status = 200, description = "The daemon is alive.", body = String, content_type = "text/plain"))
)]
async fn ping() -> impl IntoResponse {
    (PING_HEADERS, "OK")
}

/// `HEAD /_ping`: same headers as `GET`, empty body.
#[allow(clippy::unused_async)]
#[utoipa::path(
    head,
    path = "/_ping",
    operation_id = "SystemPingHead",
    tag = "System",
    description = "The same headers as `GET /_ping`, with an empty body.",
    responses((status = 200, description = "The daemon is alive."))
)]
async fn ping_head() -> impl IntoResponse {
    (PING_HEADERS, "")
}

/// `GET /version`: Docker `SystemVersion` document built from [`ApiState`].
// Extractors are taken by value; `ApiState` is an Arc handle, cloning is the point.
#[allow(clippy::unused_async, clippy::needless_pass_by_value)]
#[utoipa::path(
    get,
    path = "/version",
    operation_id = "SystemVersion",
    tag = "System",
    description = "Build and version identity of this daemon. No `GoVersion` \
        and no `Experimental` field: SatL is not Go (api-compat, daemon-wide).",
    responses((status = 200, description = "Daemon version document.", body = crate::types::VersionResponse))
)]
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
#[utoipa::path(
    get,
    path = "/info",
    operation_id = "SystemInfo",
    tag = "System",
    description = "A minimal coherent Docker `SystemInfo`: `Driver` is always \
        `zfs` (invariant #5), and `LoggingDriver`, `RegistryConfig`, \
        `Plugins`, cgroup and runtime fields are absent. `Swarm` omits \
        Docker's `Cluster` sub-document (api-compat #46), and \
        `LocalNodeState` is `active` from first boot because a SatL node \
        bootstraps a single-node cluster (api-compat, daemon-wide).",
    responses(
        (status = 200, description = "Daemon and node information.", body = crate::types::InfoResponse),
        (status = 500, description = "The daemon failed to gather its counts.", body = crate::types::ErrorBody),
        (status = 503, description = "This node cannot answer for the cluster right now.", body = crate::types::ErrorBody)
    )
)]
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
