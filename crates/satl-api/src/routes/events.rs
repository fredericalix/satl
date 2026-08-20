// SPDX-License-Identifier: BSD-2-Clause
//! `GET /events`: the daemon event stream.
//!
//! Each message is one JSON object terminated by `\n`, streamed as it
//! happens. Docker's `filters` parameter is accepted and ignored in M1
//! (deviation recorded in `docs/api-compat.md`).

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt as _;

use super::{Params, param};
use crate::backend::model::BackendError;
use crate::state::ApiState;
use crate::{render, timefmt};

/// `GET /events?since=&until=&filters=`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    get,
    path = "/events",
    operation_id = "SystemEvents",
    tag = "System",
    description = "**Newline-delimited JSON, not a JSON array.** The 200 body \
        is a chunked stream carrying one JSON object per line, terminated by \
        `\\n`, written as each event happens; a client must read it line by \
        line and never buffer it as a single document. The schema below \
        describes one such line. `filters` is not read at all -- no key is \
        validated either, so a nonsense filter passes as silently as a real \
        one (api-compat #21); `?since=` is accepted but there is no \
        replayable history (api-compat #37), and `?until=` is a 501. The \
        legacy top-level `status`/`id`/`from` fields are omitted.",
    params(
        ("since" = Option<String>, Query, description = "Accepted and parsed for validity; there is no replayable history (api-compat #37)."),
        ("until" = Option<String>, Query, description = "Rejected with 501 (api-compat #21)."),
        ("filters" = Option<String>, Query, description = "Not read at all (api-compat #21).")
    ),
    responses(
        (status = 200, description = "One JSON object per line, not a JSON array.", body = crate::types::EventResponse, content_type = "application/json"),
        (status = 400, description = "`?since=` is not a timestamp.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "`?until=` was set, or the daemon has no event source wired.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn stream(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    let since = match param(&params, "since") {
        None => None,
        Some(value) => timefmt::parse_timestamp(value).map_err(BackendError::invalid)?,
    };
    if param(&params, "until").is_some() {
        return Err(BackendError::not_implemented(
            "the until parameter of /events is not supported yet",
        ));
    }

    let events = state.backend().events(since).await?;
    let body = Body::from_stream(events.map(|event| {
        Ok::<_, std::convert::Infallible>(super::json_line(&render::event(&event), b"\n"))
    }));
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        // Only invalid header values fail the builder; both are constants.
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}
