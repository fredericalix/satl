// SPDX-License-Identifier: BSD-2-Clause
//! Operator-facing errors for the API server.

use std::path::PathBuf;

/// Errors from binding and serving the Docker REST API.
///
/// Per the project error rules, every variant states *what* was attempted and
/// on *which* path, so an operator can act on the message without reading
/// code.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Removing a stale socket file left over from a previous run failed.
    #[error("failed to remove stale unix socket {}: {source}", path.display())]
    RemoveStaleSocket {
        /// Socket path that could not be removed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The configured socket path exists but is not a unix socket; refusing
    /// to delete arbitrary files.
    #[error("refusing to replace {}: path exists and is not a unix socket", path.display())]
    NotASocket {
        /// Offending path.
        path: PathBuf,
    },

    /// Inspecting the existing socket path failed.
    #[error("failed to inspect socket path {}: {source}", path.display())]
    InspectSocketPath {
        /// Path that could not be inspected.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Binding the unix listener failed.
    #[error("failed to bind unix socket {}: {source}", path.display())]
    Bind {
        /// Socket path that could not be bound.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Setting `0660` permissions on the bound socket failed.
    #[error("failed to set permissions 0660 on unix socket {}: {source}", path.display())]
    SetPermissions {
        /// Socket path that could not be chmod-ed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The HTTP server failed while accepting or serving connections.
    #[error("error serving Docker API on unix socket {}: {source}", path.display())]
    Serve {
        /// Socket path being served.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Docker's HTTP mapping for backend failures.
///
/// Kept here, next to the other operator-facing error handling, so that
/// `backend::model` stays free of HTTP types: `NotFound` → 404, `Conflict` →
/// 409, `InvalidParameter` → 400, `NotImplemented` → 501, `Unavailable` →
/// 503, `Internal` → 500, each with Docker's `{"message": "..."}` body.
///
/// `Unavailable` is a 5xx that is logged at debug, not error: its main use is
/// the "not a swarm manager" refusal every cluster-scoped call gets on a
/// worker, which is the daemon answering exactly as designed — an ERROR line
/// per `satl service ls` on a worker would teach operators to ignore the
/// errors that matter.
impl axum::response::IntoResponse for crate::backend::model::BackendError {
    fn into_response(self) -> axum::response::Response {
        use crate::backend::model::BackendError;
        use axum::http::StatusCode;

        let status = match self {
            BackendError::NotFound(_) => StatusCode::NOT_FOUND,
            BackendError::Conflict(_) => StatusCode::CONFLICT,
            BackendError::InvalidParameter(_) => StatusCode::BAD_REQUEST,
            BackendError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            BackendError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            BackendError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status.is_server_error() && status != StatusCode::SERVICE_UNAVAILABLE {
            tracing::error!(status = status.as_u16(), error = %self, "docker api request failed");
        } else {
            tracing::debug!(status = status.as_u16(), error = %self, "docker api request rejected");
        }
        crate::types::error_response(status, self.to_string())
    }
}
