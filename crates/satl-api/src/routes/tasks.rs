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
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let task = state.backend().inspect_task(&id).await?;
    Ok(Json(render::task(&task.task)).into_response())
}
