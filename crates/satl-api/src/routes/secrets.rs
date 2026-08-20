// SPDX-License-Identifier: BSD-2-Clause
//! Secret endpoints: create, list, inspect, remove — and the deliberate 501 on
//! update (`docs/api-compat.md`).
//!
//! Two things are different here from every other endpoint family, and both
//! come from invariant #7:
//!
//! - **a response never carries a payload.** `crate::render::cluster::secret`
//!   has no way to emit one, so no handler here can leak one by forgetting a
//!   flag.
//! - **the create body is bigger than the shared cap.** A 500 KiB secret is
//!   ~667 KiB of base64, and the rest of the API is capped at 1 MiB; the
//!   payload endpoints use [`json_body_sized`] instead.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;

use super::{PAYLOAD_JSON_BODY, Params, json_body_sized, reject_filters};
use crate::backend::model::BackendError;
use crate::convert::cluster as convert;
use crate::render::cluster as render;
use crate::state::ApiState;
use crate::types::{IdResponse, SecretSpecWire};

/// `POST /secrets/create`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/secrets/create",
    operation_id = "SecretCreate",
    tag = "Secret",
    description = "The payload arrives base64-encoded and is never written to \
        a worker's disk: it is delivered over mTLS and materialized on a \
        per-task tmpfs that dies with the jail (invariant #7). This is one of \
        the two endpoints whose body *is* a payload, so it accepts a larger \
        request body than the rest of the API.",
    request_body = crate::types::SecretSpecWire,
    responses(
        (status = 201, description = "Created.", body = crate::types::IdResponse),
        (status = 400, description = "Invalid name, payload or body size.", body = crate::types::ErrorBody),
        (status = 409, description = "A secret of that name already exists.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn create(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, BackendError> {
    let body: SecretSpecWire = json_body_sized(&body, PAYLOAD_JSON_BODY)?;
    let spec = convert::secret_spec(body)?;
    let name = spec.annotations.name.clone();
    let created = state.backend().create_secret(spec).await?;
    // Size, never content: the byte count is operational information, the
    // bytes are not.
    tracing::info!(secret = %created.id, name = %name, "secret created");
    Ok((StatusCode::CREATED, Json(IdResponse { id: created.id })).into_response())
}

/// `GET /secrets`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    get,
    path = "/secrets",
    operation_id = "SecretList",
    tag = "Secret",
    description = "A secret document never carries its payload: the renderer \
        has no way to emit one, so no handler here can leak one by forgetting \
        a flag (invariant #7).",
    params(("filters" = Option<String>, Query, description = "A non-empty value is rejected with 501 rather than silently listing everything (api-compat #47).")),
    responses(
        (status = 200, description = "One row per secret, payloads excluded.", body = Vec<crate::types::SecretResponse>),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "`?filters=` was non-empty, or the daemon has no store wired.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn list(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    reject_filters(&params, "secrets")?;
    let secrets = state.backend().list_secrets().await?;
    let body: Vec<_> = secrets.iter().map(render::secret).collect();
    Ok(Json(body).into_response())
}

/// `GET /secrets/{id}`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    get,
    path = "/secrets/{id}",
    operation_id = "SecretInspect",
    tag = "Secret",
    description = "One secret, payload excluded (invariant #7).",
    params(("id" = String, Path, description = "Secret ID or name.")),
    responses(
        (status = 200, description = "The secret document, payload excluded.", body = crate::types::SecretResponse),
        (status = 404, description = "No such secret.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let secret = state.backend().inspect_secret(&id).await?;
    Ok(Json(render::secret(&secret)).into_response())
}

/// `DELETE /secrets/{id}`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    delete,
    path = "/secrets/{id}",
    operation_id = "SecretDelete",
    tag = "Secret",
    description = "Removes a secret. A secret still referenced by a service \
        is refused.",
    params(("id" = String, Path, description = "Secret ID or name.")),
    responses(
        (status = 204, description = "Removed."),
        (status = 404, description = "No such secret.", body = crate::types::ErrorBody),
        (status = 409, description = "The secret is still referenced by a service.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn remove(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<StatusCode, BackendError> {
    state.backend().remove_secret(&id).await?;
    tracing::info!(secret = %id, "secret removed");
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /secrets/{id}/update`: refused.
///
/// Docker's endpoint can only change labels — the payload is immutable there
/// too — and answering "updated" to a request that changed nothing an operator
/// cares about is worse than refusing it. Rotation is the documented path.
// Handlers must be `async` for axum even when they never await.
#[allow(clippy::unused_async)]
#[utoipa::path(
    post,
    path = "/secrets/{id}/update",
    operation_id = "SecretUpdate",
    tag = "Secret",
    description = "**Always 501.** Docker's endpoint can only change labels \
        -- the payload is immutable there too -- and answering \"updated\" to \
        a request that changed nothing an operator cares about is worse than \
        refusing it. Rotation is the documented path: create a new secret, \
        update the services that use it, remove the old one.",
    params(("id" = String, Path, description = "Secret ID or name.")),
    responses((status = 501, description = "Secrets are immutable; rotate instead.", body = crate::types::ErrorBody))
)]
pub(super) async fn update() -> Result<Response, BackendError> {
    Err(BackendError::not_implemented(
        "secrets are immutable; rotate by creating a new secret, updating the services that use \
         it, and removing the old one",
    ))
}
