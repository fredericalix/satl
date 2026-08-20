// SPDX-License-Identifier: BSD-2-Clause
//! Docker Engine REST API server (axum) and API types.
//!
//! This crate implements the external HTTP surface of `satld`: a Docker Engine
//! API v1.43-compatible server (see `docs/architecture.md` §13). The daemon
//! constructs an [`ApiState`] from facts it gathers at startup (this crate does
//! no system introspection), builds the [`router`], and serves it on the SatL
//! unix socket via [`serve_unix`].
//!
//! Version negotiation follows Docker: every endpoint is reachable both on its
//! bare path (`/_ping`) and on a version-prefixed path (`/v1.43/_ping`), with
//! prefixes outside the supported range rejected using Docker's error shape.
//! Intentional deviations from Docker semantics are recorded in
//! `docs/api-compat.md`.

//! The daemon-facing seam is [`backend::Backend`]: `satld` implements it and
//! injects it with [`ApiState::with_backend`]; everything Docker-specific
//! (status codes, JSON shapes, stream framing, timestamps) lives here.

pub mod backend;
mod convert;
mod error;
mod framing;
mod locked;
mod middleware;
mod openapi;
mod render;
mod routes;
mod server;
mod state;
mod timefmt;
mod types;

pub use backend::model;
pub use backend::{Backend, UnwiredBackend};
pub use error::ApiError;
pub use framing::{MULTIPLEXED_CONTENT_TYPE, RAW_STREAM_CONTENT_TYPE};
pub use locked::{UnlockGate, locked_router};
pub use routes::router;
pub use server::serve_unix;
pub use state::{ApiState, SystemInfo, VersionInfo};
pub use types::{
    ComponentVersion, EngineDetails, ErrorBody, InfoResponse, PlatformInfo, RemoteManagerWire,
    SwarmInfo, SwarmInfoResponse, VersionResponse,
};

/// Docker Engine API version implemented by this server (`Api-Version` ping
/// header, maximum accepted `/vX.Y/` path prefix).
pub const API_VERSION: &str = "1.43";

/// Oldest client API version accepted on `/vX.Y/`-prefixed paths.
pub const MIN_API_VERSION: &str = "1.24";
