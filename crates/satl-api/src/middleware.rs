// SPDX-License-Identifier: BSD-2-Clause
//! Router middleware: API version prefix negotiation, `Server` header,
//! request tracing.

use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::uri::{PathAndQuery, Uri};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::ApiState;
use crate::types::error_response;
use crate::{API_VERSION, MIN_API_VERSION};

/// Maximum accepted `/vX.Y/` prefix, as (major, minor). Kept in sync with
/// [`API_VERSION`] (asserted by a unit test below).
pub(crate) const MAX_VERSION: (u64, u64) = (1, 43);

/// Minimum accepted `/vX.Y/` prefix, as (major, minor). Kept in sync with
/// [`MIN_API_VERSION`].
pub(crate) const MIN_VERSION: (u64, u64) = (1, 24);

/// Outcome of inspecting a request path for a Docker API version prefix.
enum VersionPrefix {
    /// `/vX.Y/...` with a supported version: route the rewritten URI.
    Supported(Uri),
    /// `/vX.Y/...` below [`MIN_VERSION`].
    TooOld(String),
    /// `/vX.Y/...` above [`MAX_VERSION`].
    TooNew(String),
}

/// Docker-style API version negotiation on the request path.
///
/// Paths starting with a `/vX.Y/` segment are checked against the supported
/// range: in-range prefixes are stripped so `/v1.43/version` routes exactly
/// like `/version`; out-of-range prefixes get Docker's 400 error shape. A
/// leading segment that merely starts with `v` but is not `v<major>.<minor>`
/// is not version negotiation — the request routes (and 404s) as-is.
pub(crate) async fn version_prefix(mut req: Request, next: Next) -> Response {
    match inspect_version_prefix(req.uri()) {
        None => next.run(req).await,
        Some(VersionPrefix::Supported(uri)) => {
            *req.uri_mut() = uri;
            next.run(req).await
        }
        Some(VersionPrefix::TooOld(version)) => error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "client version {version} is too old. \
                 Minimum supported API version is {MIN_API_VERSION}"
            ),
        ),
        Some(VersionPrefix::TooNew(version)) => error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "client version {version} is too new. \
                 Maximum supported API version is {API_VERSION}"
            ),
        ),
    }
}

/// Classifies the leading path segment; `None` means "no version prefix".
fn inspect_version_prefix(uri: &Uri) -> Option<VersionPrefix> {
    let path = uri.path();
    let rest = path.strip_prefix("/v")?;
    let segment_len = rest.find('/').unwrap_or(rest.len());
    let candidate = &rest[..segment_len];
    let version = parse_api_version(candidate)?;
    if version < MIN_VERSION {
        return Some(VersionPrefix::TooOld(candidate.to_owned()));
    }
    if version > MAX_VERSION {
        return Some(VersionPrefix::TooNew(candidate.to_owned()));
    }
    let stripped = &rest[segment_len..];
    let new_path = if stripped.is_empty() { "/" } else { stripped };
    let path_and_query = match uri.query() {
        Some(query) => PathAndQuery::try_from(format!("{new_path}?{query}")),
        None => PathAndQuery::try_from(new_path),
    }
    // The rewritten path is a suffix of an already-valid URI, so this cannot
    // fail in practice; if it somehow does, skip negotiation and route as-is.
    .ok()?;
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query);
    let uri = Uri::from_parts(parts).ok()?;
    Some(VersionPrefix::Supported(uri))
}

/// Parses `major.minor` (both components required, digits only).
fn parse_api_version(segment: &str) -> Option<(u64, u64)> {
    let (major, minor) = segment.split_once('.')?;
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|b| b.is_ascii_digit())
        || !minor.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Stamps `Server: SatL/<version>` on every response.
// Extractors are taken by value; `ApiState` is an Arc handle, cloning is the point.
#[allow(clippy::needless_pass_by_value)]
pub(crate) async fn server_header(
    State(state): State<ApiState>,
    req: Request,
    next: Next,
) -> Response {
    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert(header::SERVER, state.server_header());
    response
}

/// Logs method, path, status and latency for every request at `debug` level,
/// and observes the same triple into `http_requests_total` — Docker's own
/// API histogram, under its exact name (`docs/api-compat.md`).
pub(crate) async fn trace_http(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let start = Instant::now();
    let response = next.run(req).await;
    let elapsed = start.elapsed();
    let latency_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    tracing::debug!(
        %method,
        path,
        status = response.status().as_u16(),
        latency_us,
        "http request"
    );
    satl_metrics::observe_http_request(
        method.as_str(),
        response.status().as_u16(),
        elapsed.as_secs_f64(),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_constants_match_public_strings() {
        assert_eq!(parse_api_version(API_VERSION), Some(MAX_VERSION));
        assert_eq!(parse_api_version(MIN_API_VERSION), Some(MIN_VERSION));
    }

    #[test]
    fn parses_well_formed_versions() {
        assert_eq!(parse_api_version("1.43"), Some((1, 43)));
        assert_eq!(parse_api_version("1.24"), Some((1, 24)));
        assert_eq!(parse_api_version("2.0"), Some((2, 0)));
    }

    #[test]
    fn rejects_malformed_versions() {
        assert_eq!(parse_api_version(""), None);
        assert_eq!(parse_api_version("1"), None);
        assert_eq!(parse_api_version("1."), None);
        assert_eq!(parse_api_version(".43"), None);
        assert_eq!(parse_api_version("1.4.3"), None);
        assert_eq!(parse_api_version("1.+3"), None);
        assert_eq!(parse_api_version("abc"), None);
        assert_eq!(parse_api_version("1.4x"), None);
    }
}
