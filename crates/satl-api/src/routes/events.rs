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
