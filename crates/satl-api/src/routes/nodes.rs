// SPDX-License-Identifier: BSD-2-Clause
//! Node endpoints: list, inspect, update and remove cluster members.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;

use super::{Params, flag, json_body, param, reject_filters};
use crate::backend::model::BackendError;
use crate::convert::cluster as convert;
use crate::render::cluster as render;
use crate::state::ApiState;
use crate::types::NodeSpecWire;

/// `GET /nodes`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn list(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    reject_filters(&params, "nodes")?;
    let nodes = state.backend().list_nodes().await?;
    let body: Vec<_> = nodes
        .iter()
        .map(|summary| render::node(&summary.node))
        .collect();
    Ok(Json(body).into_response())
}

/// `GET /nodes/{id}`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let node = state.backend().inspect_node(&id).await?;
    Ok(Json(render::node(&node.node)).into_response())
}

/// `POST /nodes/{id}/update?version=`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn update(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<Params>,
    body: Bytes,
) -> Result<StatusCode, BackendError> {
    let version = convert::object_version(param(&params, "version"))?;
    let body: NodeSpecWire = json_body(&body)?;
    let spec = convert::node_spec_update(body)?;
    tracing::info!(
        node = %id,
        role = render::node_role_name(spec.role),
        availability = render::availability_name(spec.availability),
        "node spec updated"
    );
    state.backend().update_node(&id, version, spec).await?;
    Ok(StatusCode::OK)
}

/// `DELETE /nodes/{id}?force=`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn remove(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<Params>,
) -> Result<StatusCode, BackendError> {
    let force = flag(&params, "force");
    state.backend().remove_node(&id, force).await?;
    tracing::info!(node = %id, force, "node removed from the cluster");
    Ok(StatusCode::OK)
}
