// SPDX-License-Identifier: BSD-2-Clause
//! Config endpoints: create, list, inspect, remove — and the same deliberate
//! 501 on update as `/secrets` (`docs/api-compat.md`).
//!
//! A config is a secret without the secrecy: the payload *is* returned on list
//! and inspect (Docker does the same), and the only reason these handlers are
//! not the secret ones is the size cap — a config is twice as large.

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
use crate::types::{ConfigSpecWire, IdResponse};

/// `POST /configs/create`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/configs/create",
    operation_id = "ConfigCreate",
    tag = "Config",
    description = "A config is a secret without the secrecy: the payload *is* \
        returned on list and inspect, as Docker does. One of the two \
        endpoints whose body *is* a payload, so it accepts a larger request \
        body than the rest of the API.",
    request_body = crate::types::ConfigSpecWire,
    responses(
        (status = 201, description = "Created.", body = crate::types::IdResponse),
        (status = 400, description = "Invalid name, payload or body size.", body = crate::types::ErrorBody),
        (status = 409, description = "A config of that name already exists.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn create(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, BackendError> {
    let body: ConfigSpecWire = json_body_sized(&body, PAYLOAD_JSON_BODY)?;
    let spec = convert::config_spec(body)?;
    let name = spec.annotations.name.clone();
    let created = state.backend().create_config(spec).await?;
    tracing::info!(config = %created.id, name = %name, "config created");
    Ok((StatusCode::CREATED, Json(IdResponse { id: created.id })).into_response())
}

/// `GET /configs`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    get,
    path = "/configs",
    operation_id = "ConfigList",
    tag = "Config",
    description = "Config rows carry their payload, as Docker's do.",
    params(("filters" = Option<String>, Query, description = "A non-empty value is rejected with 501 rather than silently listing everything (api-compat #47).")),
    responses(
        (status = 200, description = "One row per config.", body = Vec<crate::types::ConfigResponse>),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "`?filters=` was non-empty, or the daemon has no store wired.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn list(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    reject_filters(&params, "configs")?;
    let configs = state.backend().list_configs().await?;
    let body: Vec<_> = configs.iter().map(render::config).collect();
    Ok(Json(body).into_response())
}

/// `GET /configs/{id}`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    get,
    path = "/configs/{id}",
    operation_id = "ConfigInspect",
    tag = "Config",
    description = "One config, payload included.",
    params(("id" = String, Path, description = "Config ID or name.")),
    responses(
        (status = 200, description = "The config document.", body = crate::types::ConfigResponse),
        (status = 404, description = "No such config.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let config = state.backend().inspect_config(&id).await?;
    Ok(Json(render::config(&config)).into_response())
}

/// `DELETE /configs/{id}`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    delete,
    path = "/configs/{id}",
    operation_id = "ConfigDelete",
    tag = "Config",
    description = "Removes a config. A config still referenced by a service \
        is refused.",
    params(("id" = String, Path, description = "Config ID or name.")),
    responses(
        (status = 204, description = "Removed."),
        (status = 404, description = "No such config.", body = crate::types::ErrorBody),
        (status = 409, description = "The config is still referenced by a service.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn remove(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<StatusCode, BackendError> {
    state.backend().remove_config(&id).await?;
    tracing::info!(config = %id, "config removed");
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /configs/{id}/update`: refused, exactly as `/secrets/{id}/update` is.
// Handlers must be `async` for axum even when they never await.
#[allow(clippy::unused_async)]
#[utoipa::path(
    post,
    path = "/configs/{id}/update",
    operation_id = "ConfigUpdate",
    tag = "Config",
    description = "**Always 501**, exactly as `POST /secrets/{id}/update` is: \
        a config is immutable, and rotation -- create, update the services \
        that use it, remove the old one -- is the documented path.",
    params(("id" = String, Path, description = "Config ID or name.")),
    responses((status = 501, description = "Configs are immutable; rotate instead.", body = crate::types::ErrorBody))
)]
pub(super) async fn update() -> Result<Response, BackendError> {
    Err(BackendError::not_implemented(
        "configs are immutable; rotate by creating a new config, updating the services that use \
         it, and removing the old one",
    ))
}
