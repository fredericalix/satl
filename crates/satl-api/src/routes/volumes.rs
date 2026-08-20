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
#[utoipa::path(
    get,
    path = "/volumes",
    operation_id = "VolumeList",
    tag = "Volume",
    description = "Volumes on *this* node: a SatL volume is a node-local ZFS \
        dataset (architecture section 10, api-compat #130). `Scope` is always \
        `local`, `Status` always `{}`, there is no `UsageData`, filters are \
        not read and `Warnings` is always empty (api-compat #20).",
    responses(
        (status = 200, description = "The node's volumes.", body = crate::types::VolumeListResponse),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    post,
    path = "/volumes/create",
    operation_id = "VolumeCreate",
    tag = "Volume",
    description = "The `local` driver only -- any other driver is a 400 \
        (api-compat #20). Labels and driver options are accepted but not \
        persisted (api-compat #39).",
    request_body = crate::types::VolumeCreateBody,
    responses(
        (status = 201, description = "Created.", body = crate::types::VolumeResponse),
        (status = 400, description = "Invalid name, or a driver other than `local`.", body = crate::types::ErrorBody),
        (status = 409, description = "A volume of that name already exists.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    get,
    path = "/volumes/{name}",
    operation_id = "VolumeInspect",
    tag = "Volume",
    description = "Served from the node's volume list: there is no separate \
        inspect call behind it, and volume lists are node-local and short.",
    params(("name" = String, Path, description = "Volume name.")),
    responses(
        (status = 200, description = "The volume document.", body = crate::types::VolumeResponse),
        (status = 404, description = "No such volume on this node.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    delete,
    path = "/volumes/{name}",
    operation_id = "VolumeDelete",
    tag = "Volume",
    description = "Destroys the node-local ZFS dataset behind the volume.",
    params(
        ("name" = String, Path, description = "Volume name."),
        ("force" = Option<String>, Query, description = "Remove even when in use. Docker `BoolValue` semantics.")
    ),
    responses(
        (status = 204, description = "Removed."),
        (status = 404, description = "No such volume on this node.", body = crate::types::ErrorBody),
        (status = 409, description = "The volume is in use.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
