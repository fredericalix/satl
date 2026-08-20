// SPDX-License-Identifier: BSD-2-Clause
//! Task endpoints: list (with Docker's filter set) and inspect.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};

use super::{Params, param};
use crate::backend::model::BackendError;
use crate::convert::cluster as convert;
use crate::render::cluster as render;
use crate::state::ApiState;

/// `GET /tasks?filters=`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    get,
    path = "/tasks",
    operation_id = "TaskList",
    tag = "Task",
    description = "The only listing endpoint with real filtering: `id`, \
        `name`, `service`, `node`, `desired-state` and `label` are \
        understood, and any other key is a 400 (api-compat #47). Task \
        documents omit `AssignedGenericResources`, `GenericResources` and \
        `JobIteration` (api-compat #53), and \
        `Status.ContainerStatus.ContainerID` carries the jail name, which is \
        the bare task ID (api-compat #52).",
    params(("filters" = Option<String>, Query, description = "JSON filter map; `id`, `name`, `service`, `node`, `desired-state` and `label` only (api-compat #47).")),
    responses(
        (status = 200, description = "One row per task.", body = Vec<crate::types::TaskResponse>),
        (status = 400, description = "An unsupported filter key.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn list(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    let filters = convert::task_filters(param(&params, "filters"))?;
    let tasks = state.backend().list_tasks(filters).await?;
    let body: Vec<_> = tasks.iter().map(|task| render::task(&task.task)).collect();
    Ok(Json(body).into_response())
}

/// `GET /tasks/{id}`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    get,
    path = "/tasks/{id}",
    operation_id = "TaskInspect",
    tag = "Task",
    description = "One task. Tasks are immutable and one-shot (invariant #2): \
        a restart is a replacement task in the same slot, not this one \
        running again.",
    params(("id" = String, Path, description = "Task ID.")),
    responses(
        (status = 200, description = "The task document.", body = crate::types::TaskResponse),
        (status = 404, description = "No such task.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let task = state.backend().inspect_task(&id).await?;
    Ok(Json(render::task(&task.task)).into_response())
}
