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
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let config = state.backend().inspect_config(&id).await?;
    Ok(Json(render::config(&config)).into_response())
}

/// `DELETE /configs/{id}`.
#[allow(clippy::needless_pass_by_value)]
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
pub(super) async fn update() -> Result<Response, BackendError> {
    Err(BackendError::not_implemented(
        "configs are immutable; rotate by creating a new config, updating the services that use \
         it, and removing the old one",
    ))
}
