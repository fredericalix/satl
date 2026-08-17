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
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let secret = state.backend().inspect_secret(&id).await?;
    Ok(Json(render::secret(&secret)).into_response())
}

/// `DELETE /secrets/{id}`.
#[allow(clippy::needless_pass_by_value)]
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
pub(super) async fn update() -> Result<Response, BackendError> {
    Err(BackendError::not_implemented(
        "secrets are immutable; rotate by creating a new secret, updating the services that use \
         it, and removing the old one",
    ))
}
