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
#[utoipa::path(
    post,
    path = "/containers/create",
    operation_id = "ContainerCreate",
    tag = "Container",
    description = "Creates a container. In SatL a container *is* a Task of an \
        anonymous Service (invariant #2), so `Id` is the 25-character base36 \
        task ID rather than 64 hex characters (api-compat #1). Host options \
        SatL cannot honour are rejected with 400 rather than silently \
        ignored (api-compat #4-#8): half-honoured isolation is a security \
        trap. `Config.Healthcheck` is accepted and dropped (api-compat #127).",
    params(
        ("name" = Option<String>, Query,
            description = "Container name. Must satisfy SatL's *service* naming rule -- dots are rejected, unlike Docker's (api-compat #3). Omitted, the daemon generates one."),
        ("platform" = Option<String>, Query,
            description = "`os/arch[/variant]`. The variant is ignored, and a single component such as `freebsd` is a 400 where Docker would infer the rest (api-compat #9).")
    ),
    request_body = crate::types::ContainerCreateBody,
    responses(
        (status = 201, description = "Created.", body = crate::types::ContainerCreateResponse),
        (status = 400, description = "Invalid body, name, platform, or an unsupported host option.", body = crate::types::ErrorBody),
        (status = 404, description = "The image is not present on this node.", body = crate::types::ErrorBody),
        (status = 409, description = "The name is already taken.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    post,
    path = "/containers/{id}/start",
    operation_id = "ContainerStart",
    tag = "Container",
    description = "Starts a *created* container. A task is one-shot and \
        immutable, so starting a container that has already run is a 409: \
        re-running it would mean a new task, i.e. a new container ID, which \
        Docker's API cannot express (api-compat #30).",
    params(("id" = String, Path, description = "Container (task) ID or name.")),
    responses(
        (status = 204, description = "Started."),
        (status = 304, description = "Already running; nothing changed."),
        (status = 404, description = "No such container.", body = crate::types::ErrorBody),
        (status = 409, description = "The container has already run once and cannot be restarted (api-compat #30).", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    post,
    path = "/containers/{id}/stop",
    operation_id = "ContainerStop",
    tag = "Container",
    description = "Stops a running container: the task's stop signal, then \
        its grace period, then SIGKILL. `?t=` is parsed and validated but the \
        grace period lives in the immutable task spec (api-compat #32); a \
        negative `t` (Docker's \"wait forever\") degrades to the daemon \
        default (api-compat #10).",
    params(
        ("id" = String, Path, description = "Container (task) ID or name."),
        ("t" = Option<String>, Query, description = "Seconds to wait before killing. See api-compat #10 and #32.")
    ),
    responses(
        (status = 204, description = "Stopped."),
        (status = 304, description = "Already stopped; nothing changed."),
        (status = 400, description = "`?t=` is not a number of seconds.", body = crate::types::ErrorBody),
        (status = 404, description = "No such container.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    post,
    path = "/containers/{id}/kill",
    operation_id = "ContainerKill",
    tag = "Container",
    description = "Maps onto a graceful shutdown honouring the task's stop \
        signal, grace period and then SIGKILL: `?signal=` is accepted but not \
        forwarded (api-compat #31). On a service task this retires the slot \
        -- the service is *not* brought back to N/N (api-compat #146).",
    params(
        ("id" = String, Path, description = "Container (task) ID or name."),
        ("signal" = Option<String>, Query, description = "Accepted and not forwarded; defaults to `SIGKILL` (api-compat #31).")
    ),
    responses(
        (status = 204, description = "Signalled."),
        (status = 404, description = "No such container.", body = crate::types::ErrorBody),
        (status = 409, description = "The container is not running.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    post,
    path = "/containers/{id}/wait",
    operation_id = "ContainerWait",
    tag = "Container",
    description = "Blocks until the container reaches the requested \
        condition, then reports its exit code.",
    params(
        ("id" = String, Path, description = "Container (task) ID or name."),
        ("condition" = Option<String>, Query, description = "`not-running` (the default), `next-exit` or `removed`.")
    ),
    responses(
        (status = 200, description = "The container reached the condition.", body = crate::types::WaitResponse),
        (status = 400, description = "Unknown `?condition=`.", body = crate::types::ErrorBody),
        (status = 404, description = "No such container.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    delete,
    path = "/containers/{id}",
    operation_id = "ContainerDelete",
    tag = "Container",
    description = "Removes a container. This deletes the backing Service as \
        well -- otherwise the orchestrator would refill the slot with a new \
        task the moment the reaper freed it (api-compat #33). `?v=` is a \
        no-op and `?link=` is a 400 (api-compat #11).",
    params(
        ("id" = String, Path, description = "Container (task) ID or name."),
        ("force" = Option<String>, Query, description = "Remove a running container. Docker `BoolValue` semantics: any value other than an empty string, `0`, `no`, `false` or `none` is true."),
        ("v" = Option<String>, Query, description = "Accepted and a no-op: there are no anonymous volumes (api-compat #33)."),
        ("link" = Option<String>, Query, description = "Rejected with 400: there are no container links (api-compat #11).")
    ),
    responses(
        (status = 204, description = "Removed."),
        (status = 400, description = "`?link=` was set.", body = crate::types::ErrorBody),
        (status = 404, description = "No such container.", body = crate::types::ErrorBody),
        (status = 409, description = "The container is running and `?force=` was not set.", body = crate::types::ErrorBody),
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
#[utoipa::path(
    get,
    path = "/containers/json",
    operation_id = "ContainerList",
    tag = "Container",
    description = "Lists the newest task per slot (api-compat #34): retained \
        restart attempts are not listed as extra containers. `limit`, `size` \
        and `filters` are ignored, there are no size fields, and each row \
        carries an extra `Platform` (api-compat #12).",
    params(
        ("all" = Option<String>, Query, description = "Include non-running containers. Docker `BoolValue` semantics: `?all=maybe` is true."),
        ("limit" = Option<String>, Query, description = "Accepted and ignored (api-compat #12)."),
        ("size" = Option<String>, Query, description = "Accepted and ignored; no `SizeRw`/`SizeRootFs` is reported (api-compat #12)."),
        ("filters" = Option<String>, Query, description = "Accepted and ignored (api-compat #12).")
    ),
    responses(
        (status = 200, description = "One row per container.", body = Vec<crate::types::ContainerSummaryResponse>),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    get,
    path = "/containers/{id}/json",
    operation_id = "ContainerInspect",
    tag = "Container",
    description = "`Platform` is `os/arch` where Docker sends a bare OS \
        string, and there is a SatL-only `JailID`; `Driver` is always `zfs`, \
        and `GraphDriver`, `HostnamePath`, `LogPath`, `ResolvConfPath`, \
        `AppArmorProfile` and the size fields are absent (api-compat #13).",
    params(("id" = String, Path, description = "Container (task) ID or name.")),
    responses(
        (status = 200, description = "The container document.", body = crate::types::ContainerInspectResponse),
        (status = 404, description = "No such container.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    get,
    path = "/containers/{id}/logs",
    operation_id = "ContainerLogs",
    tag = "Container",
    description = "**Not JSON.** The 200 body is a chunked stream of Docker \
        multiplexed frames (8-byte header: stream byte, three zero bytes, \
        big-endian payload length), always -- SatL never allocates a TTY, so \
        the raw variant is never emitted even for `Tty:true` containers \
        (api-compat #14). `?since=` is ignored and `timestamps=1` stamps read \
        time, because the raw log files carry no per-line timestamps \
        (api-compat #36).",
    params(
        ("id" = String, Path, description = "Container (task) ID or name."),
        ("follow" = Option<String>, Query, description = "Keep the stream open. Docker `BoolValue` semantics."),
        ("stdout" = Option<String>, Query, description = "Include stdout. Docker `BoolValue` semantics."),
        ("stderr" = Option<String>, Query, description = "Include stderr. Docker `BoolValue` semantics."),
        ("tail" = Option<String>, Query, description = "`all` or a line count."),
        ("timestamps" = Option<String>, Query, description = "Prefix each line with the *read* time (api-compat #36)."),
        ("since" = Option<String>, Query, description = "Accepted and ignored (api-compat #36).")
    ),
    responses(
        (status = 200, description = "A stream of Docker multiplexed frames.", body = String, content_type = "application/vnd.docker.multiplexed-stream"),
        (status = 400, description = "Neither stdout nor stderr was requested, or `?tail=` is unparsable.", body = crate::types::ErrorBody),
        (status = 404, description = "No such container.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
