// SPDX-License-Identifier: BSD-2-Clause
//! Container endpoints: create, start, stop, kill, wait, remove, list,
//! inspect and logs.

use std::time::{Duration, SystemTime};

use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, body::Body};
use bytes::Bytes;
use futures_util::StreamExt as _;

use super::{Params, flag, json_body, param};
use crate::backend::model::{BackendError, ChangeOutcome};
use crate::state::ApiState;
use crate::types::{ContainerCreateBody, ContainerCreateResponse, WaitError, WaitResponse};
use crate::{convert, framing, render};

/// `POST /containers/create?name=&platform=`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn create(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
    body: Bytes,
) -> Result<Response, BackendError> {
    let body: ContainerCreateBody = json_body(&body)?;
    let options = convert::create_container_options(
        body,
        param(&params, "name"),
        param(&params, "platform"),
    )?;
    let created = state.backend().create_container(options).await?;
    tracing::info!(container = %created.id, "container created");
    Ok((
        StatusCode::CREATED,
        Json(ContainerCreateResponse {
            id: created.id,
            warnings: created.warnings,
        }),
    )
        .into_response())
}

/// `POST /containers/{id}/start`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn start(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<StatusCode, BackendError> {
    Ok(no_content_or_not_modified(
        state.backend().start_container(&id).await?,
    ))
}

/// `POST /containers/{id}/stop?t=`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn stop(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<Params>,
) -> Result<StatusCode, BackendError> {
    let timeout = match param(&params, "t") {
        None => None,
        Some(value) => {
            let seconds: i64 = value.parse().map_err(|_| {
                BackendError::invalid(format!(
                    "invalid stop timeout {value:?}: expected a number of seconds"
                ))
            })?;
            // Docker's negative `t` means "wait forever"; SatL has no
            // unbounded stop, so it falls back to the daemon default
            // (deviation recorded in docs/api-compat.md).
            u64::try_from(seconds).ok().map(Duration::from_secs)
        }
    };
    Ok(no_content_or_not_modified(
        state.backend().stop_container(&id, timeout).await?,
    ))
}

/// Docker answers `304 Not Modified` when the container was already in the
/// requested state.
fn no_content_or_not_modified(outcome: ChangeOutcome) -> StatusCode {
    match outcome {
        ChangeOutcome::Changed => StatusCode::NO_CONTENT,
        ChangeOutcome::Unchanged => StatusCode::NOT_MODIFIED,
    }
}

/// `POST /containers/{id}/kill?signal=`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn kill(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<Params>,
) -> Result<StatusCode, BackendError> {
    let signal = param(&params, "signal").unwrap_or("SIGKILL");
    state.backend().kill_container(&id, signal).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /containers/{id}/wait?condition=`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn wait(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<Params>,
) -> Result<Json<WaitResponse>, BackendError> {
    let condition = convert::wait_condition(param(&params, "condition"))?;
    let result = state.backend().wait_container(&id, condition).await?;
    Ok(Json(WaitResponse {
        status_code: result.status_code,
        error: result.error.map(|message| WaitError { message }),
    }))
}

/// `DELETE /containers/{id}?force=&v=&link=`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn remove(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<Params>,
) -> Result<StatusCode, BackendError> {
    if flag(&params, "link") {
        return Err(BackendError::invalid(
            "container links are not supported by SatL",
        ));
    }
    state
        .backend()
        .remove_container(&id, flag(&params, "force"), flag(&params, "v"))
        .await?;
    tracing::info!(container = %id, "container removed");
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /containers/json?all=`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn list(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    let summaries = state
        .backend()
        .list_containers(flag(&params, "all"))
        .await?;
    let now = SystemTime::now();
    let body: Vec<_> = summaries
        .iter()
        .map(|summary| render::container_summary(summary, now))
        .collect();
    Ok(Json(body).into_response())
}

/// `GET /containers/{id}/json`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let inspect = state.backend().inspect_container(&id).await?;
    Ok(Json(render::container_inspect(&inspect)).into_response())
}

/// `GET /containers/{id}/logs?follow=&stdout=&stderr=&tail=&timestamps=&since=`.
///
/// The response is a chunked stream of Docker multiplexed frames
/// (`crate::framing`); SatL never emits the raw (TTY) variant.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn logs(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    let options = convert::log_options(
        flag(&params, "follow"),
        flag(&params, "stdout"),
        flag(&params, "stderr"),
        param(&params, "tail"),
        flag(&params, "timestamps"),
        param(&params, "since"),
    )?;
    let timestamps = options.timestamps;
    let frames = state.backend().container_logs(&id, options).await?;
    let body = Body::from_stream(frames.map(move |frame| {
        Ok::<Bytes, std::convert::Infallible>(framing::encode_log_frame(&frame, timestamps))
    }));
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, framing::MULTIPLEXED_CONTENT_TYPE)
        .body(body)
        // The builder only fails on invalid header values, and both are
        // compile-time constants here.
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}
