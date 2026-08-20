// SPDX-License-Identifier: BSD-2-Clause
//! Image endpoints: pull (`POST /images/create`), list, and the
//! `/images/{name}/*` family (tag, inspect, remove).

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
#[utoipa::path(
    post,
    path = "/images/create",
    operation_id = "ImageCreate",
    tag = "Image",
    description = "**Newline-delimited JSON, not a JSON array.** The response \
        is `200` immediately, then one Docker `JSONMessage` per line (each \
        terminated by `\\r\\n`) as the pull proceeds -- including the \
        failure, which is reported as an `error` line on an \
        already-successful response, exactly like Docker. The schema below \
        describes one such line. `fromSrc` (import) is a 501, and \
        `X-Registry-Auth` is accepted in base64url *or* standard base64 \
        (api-compat #16).",
    params(
        ("fromImage" = Option<String>, Query, description = "Image reference to pull."),
        ("tag" = Option<String>, Query, description = "Tag or digest, when `fromImage` carries none."),
        ("platform" = Option<String>, Query, description = "`os/arch[/variant]` (api-compat #9)."),
        ("fromSrc" = Option<String>, Query, description = "Rejected with 501: importing from a source is not supported (api-compat #16)."),
        ("X-Registry-Auth" = Option<String>, Header, description = "base64url or standard-base64 `AuthConfig` document (api-compat #16).")
    ),
    responses(
        (status = 200, description = "One JSON progress object per line, not a JSON array.", body = crate::types::JsonMessage, content_type = "application/json"),
        (status = 400, description = "Unparsable reference, platform or `X-Registry-Auth`.", body = crate::types::ErrorBody),
        (status = 404, description = "No such image in the registry.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "`?fromSrc=` was set, or the daemon has no image store wired.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    get,
    path = "/images/json",
    operation_id = "ImageList",
    tag = "Image",
    description = "Images this node holds. `all`, `filters`, `digests` and \
        `shared-size` are not read; each row carries an extra `Platform`, \
        `SharedSize` is always 0, `Labels` always null and `ParentId` always \
        empty (api-compat #15). Image content is node-local (api-compat \
        #130).",
    responses(
        (status = 200, description = "One row per image.", body = Vec<crate::types::ImageSummaryResponse>),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn list(State(state): State<ApiState>) -> Result<Response, BackendError> {
    let images = state.backend().list_images().await?;
    let body: Vec<_> = images.iter().map(render::image_summary).collect();
    Ok(Json(body).into_response())
}

/// Last path segments that name a *verb* of Docker's `/images/{name}/*`
/// family rather than part of an image name.
///
/// A `DELETE` whose tail ends in one of these keeps the fallback's 404 instead
/// of being read as an image called that. The cost is stated rather than
/// hidden (api-compat 157): a repository whose last component is literally one
/// of these words has to be spelled with its tag — `DELETE
/// /images/team/get:latest` — because `team/get` alone is ambiguous with the
/// unimplemented `GET` verb.
const SUB_VERBS: [&str; 6] = ["tag", "json", "push", "history", "get", "load"];

/// Whether `rest` ends in a sub-verb segment, with something before it.
///
/// The "something before it" is what keeps `DELETE /images/get` — an image
/// genuinely named `get` — working: a bare tail is always a name.
fn names_sub_verb(rest: &str) -> bool {
    matches!(
        rest.rsplit_once('/'),
        Some((head, last)) if !head.is_empty() && SUB_VERBS.contains(&last)
    )
}

/// The `/images/{name}/…` family, dispatched on the method first.
///
/// An image name may carry slashes (`ghcr.io/x/y:v1`), which a `{name}` path
/// parameter cannot capture, so the whole family is one tail wildcard
/// registered for every method. Three verbs are served — `POST …/tag`,
/// `GET …/json` and a bare `DELETE` — and everything else gets the fallback's
/// 404 `page not found`, keeping the unimplemented rest of the family at its
/// documented shape (`docs/api-compat.md` #22, 158).
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn by_name(
    State(state): State<ApiState>,
    method: Method,
    Path(rest): Path<String>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    match method {
        Method::POST => match rest.strip_suffix("/tag") {
            Some(name) => tag(&state, name, &params).await,
            None => Ok(not_found()),
        },
        Method::GET => match rest.strip_suffix("/json") {
            Some(name) => inspect(&state, name).await,
            None => Ok(not_found()),
        },
        // On a DELETE the tail *is* the reference, verbatim: there is no
        // trailing verb to strip, which is why this arm reads `rest` whole.
        Method::DELETE if !names_sub_verb(&rest) => remove(&state, &rest, &params).await,
        _ => Ok(not_found()),
    }
}

/// The fallback's shape, hand-rolled: the wildcard swallowed the request
/// before axum's own fallback could answer it.
fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "page not found")
}

/// `POST /images/{name}/tag?repo=&tag=` — Docker's exact route.
#[utoipa::path(
    post,
    path = "/images/{name}/tag",
    operation_id = "ImageTag",
    tag = "Image",
    description = "Adds one more reference to the same store entry: no blob \
        is copied, both names keep resolving, and tagging an image with the \
        name it already has is a no-op success (api-compat #22). Served \
        through the `/images/{name}/*` tail wildcard, because an image name \
        may carry slashes.",
    params(
        ("name" = String, Path, description = "Source image reference; may carry slashes (`ghcr.io/team/app:v1`)."),
        ("repo" = Option<String>, Query, description = "Target repository."),
        ("tag" = Option<String>, Query, description = "Target tag; `latest` when omitted.")
    ),
    responses(
        (status = 201, description = "Tagged."),
        (status = 400, description = "The target reference is unparsable.", body = crate::types::ErrorBody),
        (status = 404, description = "No such source image.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(crate) async fn tag(
    state: &ApiState,
    name: &str,
    params: &Params,
) -> Result<Response, BackendError> {
    let target = convert::tag_target(
        param(params, "repo").unwrap_or_default(),
        param(params, "tag"),
    )?;
    state.backend().tag_image(name, &target).await?;
    tracing::info!(image = %name, target = %target, "image tagged");
    Ok(StatusCode::CREATED.into_response())
}

/// `GET /images/{name}/json` — Docker's `ImageInspect`.
#[utoipa::path(
    get,
    path = "/images/{name}/json",
    operation_id = "ImageInspect",
    tag = "Image",
    description = "Served through the `/images/{name}/*` tail wildcard, \
        because an image name may carry slashes. The rest of that family -- \
        `history`, `get`, `load` and `push` -- stays 404 `page not found` \
        (api-compat #22, #152).",
    params(("name" = String, Path, description = "Image reference; may carry slashes.")),
    responses(
        (status = 200, description = "The image document.", body = crate::types::ImageInspectResponse),
        (status = 404, description = "No such image.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(crate) async fn inspect(state: &ApiState, name: &str) -> Result<Response, BackendError> {
    let image = state.backend().inspect_image(name).await?;
    Ok(Json(render::image_inspect(&image)).into_response())
}

/// `DELETE /images/{name}?force=&noprune=`.
///
/// Docker's response is a bare array of `{"Untagged"}`/`{"Deleted"}` items,
/// which leaves nowhere for what the layer sweep deferred (api-compat #131), so
/// the count travels in a header instead (api-compat 156).
/// That count travels as `X-Satl-Deferred-Layers`: invisible to a Docker
/// client, and what `satl images rm` reads to print the "run again" hint.
#[utoipa::path(
    delete,
    path = "/images/{name}",
    operation_id = "ImageDelete",
    tag = "Image",
    description = "Removes one reference, and the content it was the last \
        reference to. The response is Docker's bare array, which leaves \
        nowhere for what the layer sweep deferred, so that count travels in \
        the SatL-only `X-Satl-Deferred-Layers` response header (api-compat \
        156). Served through the `/images/{name}/*` tail wildcard: a tail \
        whose last segment is `tag`, `json`, `push`, `history`, `get` or \
        `load` is read as a verb, so a repository whose last component is \
        literally one of those words has to be spelled with its tag.",
    params(
        ("name" = String, Path, description = "Image reference; may carry slashes."),
        ("force" = Option<String>, Query, description = "Override a refusal that says `must force`: a reference held only by terminal tasks, or an image reachable from several references. It never overrides a live claim (api-compat 161). Docker `BoolValue` semantics."),
        ("noprune" = Option<String>, Query, description = "Skip the layer and content sweep, and with it the two agreeing passes it takes. Docker's meaning -- keep untagged *parent* images -- has no analogue here, because SatL images have no parents (api-compat 155, 157). Docker `BoolValue` semantics.")
    ),
    responses(
        (status = 200, description = "What was untagged and what was deleted.", body = Vec<crate::types::ImageDeleteResponseItem>),
        (status = 404, description = "No such image.", body = crate::types::ErrorBody),
        (status = 409, description = "Something still claims the image. Two arms: \
            `(cannot be forced)` when a non-terminal task or a service that still wants \
            tasks names it -- `force` does not override that -- and `(must force)` when \
            only terminal tasks do, or when several references resolve to the same image \
            (api-compat 159, 161).", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody)
        // Deliberately no 503: an image is node-local, so the claim set falls
        // back to this node's task DB when there is no manager to ask, and the
        // removal answers everywhere (api-compat 161). `satl node ps` is the
        // contrast -- it reads cluster state and does 503.
    )
)]
pub(crate) async fn remove(
    state: &ApiState,
    name: &str,
    params: &Params,
) -> Result<Response, BackendError> {
    let force = super::flag(params, "force");
    let noprune = super::flag(params, "noprune");
    let report = state.backend().remove_image(name, force, noprune).await?;
    tracing::info!(
        image = %name,
        force,
        noprune,
        items = report.deleted.len(),
        deferred = report.deferred.len(),
        space_reclaimed = report.space_reclaimed,
        "image removed"
    );
    let body: Vec<_> = report.deleted.iter().map(render::image_deleted).collect();
    if report.deferred.is_empty() {
        return Ok(Json(body).into_response());
    }
    Ok((
        [(DEFERRED_LAYERS_HEADER, report.deferred.len().to_string())],
        Json(body),
    )
        .into_response())
}

/// Header carrying what the layer sweep deferred, because Docker's rmi
/// response body is an array with no field for it.
const DEFERRED_LAYERS_HEADER: &str = "X-Satl-Deferred-Layers";

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard fires on a verb word in the *last* segment with something
    /// before it, and never on a bare tail — which is what keeps an image
    /// genuinely called `get` addressable.
    #[test]
    fn only_a_trailing_sub_verb_with_a_prefix_is_a_verb() {
        assert!(names_sub_verb("nginx/push"));
        assert!(names_sub_verb("ghcr.io/team/app/json"));
        assert!(names_sub_verb("team/get"));

        // A bare tail is always a name.
        assert!(!names_sub_verb("push"));
        assert!(!names_sub_verb("get"));
        // Ordinary references, however many slashes.
        assert!(!names_sub_verb("nginx:1.25"));
        assert!(!names_sub_verb("ghcr.io/team/app:v1"));
        // The documented escape: spell the tag.
        assert!(!names_sub_verb("team/get:latest"));
        // A verb word that is not the last segment is just a path component.
        assert!(!names_sub_verb("tag/app"));
    }
}
