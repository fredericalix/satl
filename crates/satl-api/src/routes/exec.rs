// SPDX-License-Identifier: BSD-2-Clause
//! Exec endpoints: `POST /containers/{id}/exec`, the hijacked `POST
//! /exec/{id}/start`, and `GET /exec/{id}/json`.
//!
//! `start` implements Docker's connection hijack: the client sends
//! `Connection: Upgrade` / `Upgrade: tcp`, the daemon answers `101 Switching
//! Protocols` with `Content-Type: application/vnd.docker.raw-stream` and then
//! owns the raw socket, over which it writes multiplexed frames until the
//! process exits. Client → daemon bytes (stdin) are read and discarded: M1
//! exec is non-interactive.
//!
//! A client that does *not* ask for an upgrade still gets its output, as a
//! normal chunked `200` response with the same framing (deviation recorded in
//! `docs/api-compat.md`).

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_util::StreamExt as _;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt as _;

use super::{MAX_JSON_BODY, json_body};
use crate::backend::model::{BackendError, ExecStream};
use crate::state::ApiState;
use crate::types::{ExecCreateBody, ExecCreateResponse, ExecStartBody};
use crate::{convert, framing, render};

/// `POST /containers/{id}/exec`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/containers/{id}/exec",
    operation_id = "ContainerExec",
    tag = "Exec",
    description = "Creates an exec instance. Exec is non-interactive: \
        `Tty:true` is a 400 on create *and* on start, `Privileged:true` is a \
        400, `DetachKeys` is ignored, and stdin on the hijacked socket is \
        read and discarded (api-compat #17, #38).",
    params(("id" = String, Path, description = "Container (task) ID or name.")),
    request_body = crate::types::ExecCreateBody,
    responses(
        (status = 201, description = "The exec instance was created.", body = crate::types::ExecCreateResponse),
        (status = 400, description = "`Tty` or `Privileged` was set, or the body is invalid.", body = crate::types::ErrorBody),
        (status = 404, description = "No such container.", body = crate::types::ErrorBody),
        (status = 409, description = "The container is not running.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn create(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, BackendError> {
    let body: ExecCreateBody = json_body(&body)?;
    let config = convert::exec_config(body)?;
    let exec_id = state.backend().create_exec(&id, config).await?;
    tracing::info!(container = %id, exec = %exec_id, "exec instance created");
    Ok((
        StatusCode::CREATED,
        Json(ExecCreateResponse {
            id: exec_id.to_string(),
        }),
    )
        .into_response())
}

/// `POST /exec/{id}/start`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/exec/{id}/start",
    operation_id = "ExecStart",
    tag = "Exec",
    description = "**Not JSON, and two shapes.** With `Connection: Upgrade` \
        and `Upgrade: tcp` the daemon answers `101 Switching Protocols` with \
        an empty body and then owns the raw socket, writing Docker \
        multiplexed frames over it until the process exits. **Without** the \
        upgrade headers it answers `200` with the same frames as an ordinary \
        chunked body, where Docker would hijack in both cases (api-compat \
        #18). Output is delivered when the process exits rather than streamed \
        live (api-compat #38).",
    params(("id" = String, Path, description = "Exec instance ID.")),
    request_body = crate::types::ExecStartBody,
    responses(
        (status = 101, description = "Connection hijacked: the raw socket now carries Docker multiplexed frames."),
        (status = 200, description = "No upgrade was requested: the same frames as a chunked body (api-compat #18).", body = String, content_type = "application/vnd.docker.raw-stream"),
        (status = 400, description = "`Tty` was set, or the body is invalid.", body = crate::types::ErrorBody),
        (status = 404, description = "No such exec instance.", body = crate::types::ErrorBody),
        (status = 409, description = "The exec instance has already run.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "`Detach` was set (api-compat #17), or the daemon has no executor wired.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn start(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    mut request: Request,
) -> Result<Response, BackendError> {
    let upgrade_requested = wants_upgrade(request.headers());
    let on_upgrade = request.extensions_mut().remove::<OnUpgrade>();

    let body = axum::body::to_bytes(request.into_body(), MAX_JSON_BODY)
        .await
        .map_err(|err| BackendError::invalid(format!("could not read the request body: {err}")))?;
    let body: ExecStartBody = json_body(&body)?;
    if body.tty {
        return Err(BackendError::invalid("tty not supported yet"));
    }
    if body.detach {
        return Err(BackendError::not_implemented(
            "detached exec (Detach=true) is not supported yet",
        ));
    }

    let stream = state.backend().start_exec(&id).await?;
    tracing::info!(exec = %id, hijacked = upgrade_requested, "exec instance started");

    if let Some(on_upgrade) = on_upgrade.filter(|_| upgrade_requested) {
        tokio::spawn(async move {
            match on_upgrade.await {
                Ok(upgraded) => pump(TokioIo::new(upgraded), stream).await,
                Err(err) => tracing::warn!(error = %err, "exec connection upgrade failed"),
            }
        });
        return Ok(Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::CONTENT_TYPE, framing::RAW_STREAM_CONTENT_TYPE)
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "tcp")
            .body(Body::empty())
            // Only invalid header values fail the builder; all constants.
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()));
    }

    // No upgrade available (or requested): stream the same frames as a
    // chunked response body.
    let ExecStream { frames, exit } = stream;
    let body = Body::from_stream(frames.map(move |frame| {
        // Hold the exit receiver open for as long as the body streams, so the
        // backend's send of the exit code does not fail on a dropped receiver.
        let _exit = &exit;
        Ok::<Bytes, std::convert::Infallible>(framing::encode_log_frame(&frame, false))
    }));
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, framing::RAW_STREAM_CONTENT_TYPE)
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}

/// Whether the client asked for Docker's raw-stream upgrade.
fn wants_upgrade(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
    connection_upgrade && headers.contains_key(header::UPGRADE)
}

/// Writes multiplexed frames onto the hijacked connection until the process
/// exits, discarding whatever the client sends (stdin).
async fn pump<S>(io: S, stream: ExecStream)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(io);
    let drain = tokio::spawn(async move {
        // M1 exec is non-interactive: stdin is accepted, then dropped.
        let mut sink = tokio::io::sink();
        let _ = tokio::io::copy(&mut reader, &mut sink).await;
    });

    let ExecStream { mut frames, exit } = stream;
    while let Some(frame) = frames.next().await {
        let bytes = framing::encode_log_frame(&frame, false);
        if let Err(err) = writer.write_all(&bytes).await {
            tracing::debug!(error = %err, "exec client went away mid-stream");
            break;
        }
    }
    let _ = writer.flush().await;
    if let Ok(code) = exit.await {
        tracing::info!(exit_code = code, "exec instance finished");
    } else {
        tracing::debug!("exec exit code was never reported");
    }
    let _ = writer.shutdown().await;
    drain.abort();
}

/// `GET /exec/{id}/json`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    get,
    path = "/exec/{id}/json",
    operation_id = "ExecInspect",
    tag = "Exec",
    description = "`ProcessConfig.privileged` is always false, `DetachKeys` \
        always empty and `CanRemove` always true (api-compat #19).",
    params(("id" = String, Path, description = "Exec instance ID.")),
    responses(
        (status = 200, description = "The exec instance document.", body = crate::types::ExecInspectResponse),
        (status = 404, description = "No such exec instance.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let exec = state.backend().inspect_exec(&id).await?;
    Ok(Json(render::exec_inspect(&exec)).into_response())
}
