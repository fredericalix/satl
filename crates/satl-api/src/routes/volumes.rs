// SPDX-License-Identifier: BSD-2-Clause
//! Volume endpoints: list, create, inspect and remove.
//!
//! SatL volumes are node-local ZFS datasets (architecture §10), so `Scope` is
//! always `local` and the only driver is `local`.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;

use super::{Params, flag, json_body};
use crate::backend::model::BackendError;
use crate::state::ApiState;
use crate::types::{VolumeCreateBody, VolumeListResponse};
use crate::{convert, render};

/// `GET /volumes`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn list(State(state): State<ApiState>) -> Result<Response, BackendError> {
    let volumes = state.backend().list_volumes().await?;
    Ok(Json(VolumeListResponse {
        volumes: volumes.iter().map(render::volume).collect(),
        warnings: Vec::new(),
    })
    .into_response())
}

/// `POST /volumes/create`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn create(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, BackendError> {
    let body: VolumeCreateBody = json_body(&body)?;
    let options = convert::volume_options(body)?;
    let volume = state.backend().create_volume(options).await?;
    tracing::info!(volume = %volume.name, "volume created");
    Ok((StatusCode::CREATED, Json(render::volume(&volume))).into_response())
}

/// `GET /volumes/{name}`.
///
/// Served from [`list_volumes`](crate::backend::Backend::list_volumes): the
/// backend has no separate inspect call, and volume lists are node-local and
/// short.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Response, BackendError> {
    let volumes = state.backend().list_volumes().await?;
    let volume = volumes
        .iter()
        .find(|volume| volume.name == name)
        .ok_or_else(|| BackendError::not_found(format!("get {name}: no such volume")))?;
    Ok(Json(render::volume(volume)).into_response())
}

/// `DELETE /volumes/{name}?force=`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn remove(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Query(params): Query<Params>,
) -> Result<StatusCode, BackendError> {
    state
        .backend()
        .remove_volume(&name, flag(&params, "force"))
        .await?;
    tracing::info!(volume = %name, "volume removed");
    Ok(StatusCode::NO_CONTENT)
}
