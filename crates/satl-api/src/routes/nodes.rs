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
#[utoipa::path(
    get,
    path = "/nodes",
    operation_id = "NodeList",
    tag = "Node",
    description = "`Description.Engine.Plugins` is always empty and \
        `Description.TLSInfo` is omitted (api-compat #53).",
    params(("filters" = Option<String>, Query, description = "A non-empty value is rejected with 501 rather than silently listing everything (api-compat #47).")),
    responses(
        (status = 200, description = "One row per cluster member.", body = Vec<crate::types::NodeResponse>),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "`?filters=` was non-empty, or the daemon has no store wired.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    get,
    path = "/nodes/{id}",
    operation_id = "NodeInspect",
    tag = "Node",
    description = "One cluster member.",
    params(("id" = String, Path, description = "Node ID or hostname.")),
    responses(
        (status = 200, description = "The node document.", body = crate::types::NodeResponse),
        (status = 404, description = "No such node.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let node = state.backend().inspect_node(&id).await?;
    Ok(Json(render::node(&node.node)).into_response())
}

/// `POST /nodes/{id}/update?version=`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/nodes/{id}/update",
    operation_id = "NodeUpdate",
    tag = "Node",
    description = "Promotion and demotion apply live: the role change reaches \
        the node on its session, it renews its certificate to the new role \
        and rebuilds its cluster runtime in place. Running containers are not \
        disturbed and the daemon does not restart (api-compat #48). A missing \
        or unparsable `?version=` is a 400 before the backend is called \
        (api-compat #54).",
    params(
        ("id" = String, Path, description = "Node ID or hostname."),
        ("version" = Option<String>, Query, description = "The object version being updated. Required: a missing or unparsable value is a 400 (api-compat #54).")
    ),
    request_body = crate::types::NodeSpecWire,
    responses(
        (status = 200, description = "Updated."),
        (status = 400, description = "Missing or unparsable `?version=`, or an invalid spec.", body = crate::types::ErrorBody),
        (status = 404, description = "No such node.", body = crate::types::ErrorBody),
        (status = 409, description = "The stored object version has moved on.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    delete,
    path = "/nodes/{id}",
    operation_id = "NodeDelete",
    tag = "Node",
    description = "Removes a member from the cluster.",
    params(
        ("id" = String, Path, description = "Node ID or hostname."),
        ("force" = Option<String>, Query, description = "Remove a node that is still reachable or still a manager. Docker `BoolValue` semantics.")
    ),
    responses(
        (status = 200, description = "Removed."),
        (status = 404, description = "No such node.", body = crate::types::ErrorBody),
        (status = 409, description = "The node is still active and `?force=` was not set.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
