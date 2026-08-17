// SPDX-License-Identifier: BSD-2-Clause
//! Image endpoints: pull (`POST /images/create`) and list.

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt as _;

use super::{Params, param, registry_auth};
use crate::backend::model::BackendError;
use crate::state::ApiState;
use crate::types::error_response;
use crate::{convert, render};

/// `POST /images/create?fromImage=&tag=&platform=`.
///
/// Answers `200` immediately and streams Docker `JSONMessage` progress lines
/// (each terminated by `\r\n`) as the pull proceeds — including the failure,
/// which is reported as an `error` line on an already-successful response,
/// exactly like Docker.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn create(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
    headers: HeaderMap,
) -> Result<Response, BackendError> {
    if param(&params, "fromSrc").is_some() {
        return Err(BackendError::not_implemented(
            "importing images from a source (fromSrc) is not supported yet",
        ));
    }
    let reference = convert::image_reference(
        param(&params, "fromImage").unwrap_or_default(),
        param(&params, "tag"),
    )?;
    let platform = param(&params, "platform")
        .map(convert::parse_platform)
        .transpose()?;
    let auth = registry_auth(&headers)?;

    let lines = state
        .backend()
        .pull_image(&reference, auth, platform)
        .await?;
    tracing::info!(image = %reference, "image pull started");
    let body = Body::from_stream(lines.map(|line| {
        Ok::<_, std::convert::Infallible>(super::json_line(&render::pull_progress(&line), b"\r\n"))
    }));
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        // Only invalid header values can fail the builder; both are constants.
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}

/// `GET /images/json`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn list(State(state): State<ApiState>) -> Result<Response, BackendError> {
    let images = state.backend().list_images().await?;
    let body: Vec<_> = images.iter().map(render::image_summary).collect();
    Ok(Json(body).into_response())
}

/// `POST /images/{name}/tag?repo=&tag=` — Docker's exact route, the one
/// member of the `/images/{name}/*` family SatL serves.
///
/// An image name may carry slashes (`ghcr.io/x/y:v1`), which a `{name}` path
/// parameter cannot capture, so the route is registered as a tail wildcard
/// for every method: the one POST whose path ends in `/tag` is served here
/// and everything else gets the fallback's 404 `page not found`, keeping the
/// unimplemented rest of the family at its documented shape
/// (`docs/api-compat.md` #22).
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn by_name(
    State(state): State<ApiState>,
    method: Method,
    Path(rest): Path<String>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    let name = if method == Method::POST {
        rest.strip_suffix("/tag")
    } else {
        None
    };
    let Some(name) = name else {
        return Ok(error_response(StatusCode::NOT_FOUND, "page not found"));
    };
    let target = convert::tag_target(
        param(&params, "repo").unwrap_or_default(),
        param(&params, "tag"),
    )?;
    state.backend().tag_image(name, &target).await?;
    tracing::info!(image = %name, target = %target, "image tagged");
    Ok(StatusCode::CREATED.into_response())
}
