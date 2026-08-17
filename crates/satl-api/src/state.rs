// SPDX-License-Identifier: BSD-2-Clause
//! Shared state injected into the API router by the daemon.

use std::fmt;
use std::sync::Arc;

use axum::http::HeaderValue;

use crate::backend::{Backend, UnwiredBackend};
use crate::types::SwarmInfo;

/// Build/version identity of the daemon, reported by `GET /version`.
///
/// Filled in by `satld` at startup — this crate performs no system
/// introspection of its own.
#[derive(Debug, Clone)]
pub struct VersionInfo {
    /// SatL release version, e.g. `0.1.0`.
    pub version: String,
    /// Docker Engine API version implemented, e.g. `1.43`.
    pub api_version: String,
    /// Minimum negotiable Docker Engine API version, e.g. `1.24`.
    pub min_api_version: String,
    /// Git commit the daemon was built from.
    pub git_commit: String,
    /// Operating system the daemon runs on (`freebsd`).
    pub os: String,
    /// CPU architecture, Docker-style (`amd64`, `arm64`).
    pub arch: String,
    /// Kernel version string (FreeBSD `uname -r` equivalent).
    pub kernel_version: String,
    /// Build timestamp, RFC 3339.
    pub build_time: String,
}

/// Node-level facts reported by `GET /info`.
///
/// Filled in by `satld` at startup — this crate performs no system
/// introspection of its own.
#[derive(Debug, Clone)]
pub struct SystemInfo {
    /// Unique daemon/node identifier.
    pub id: String,
    /// Node hostname.
    pub name: String,
    /// Number of logical CPUs.
    pub ncpu: i64,
    /// Total physical memory in bytes.
    pub mem_total: i64,
    /// Operating system name, e.g. `FreeBSD`.
    pub operating_system: String,
    /// Operating system release, e.g. `15.1-RELEASE`.
    pub os_version: String,
    /// SatL daemon version (mirrors [`VersionInfo::version`]).
    pub server_version: String,
}

struct StateInner {
    version: VersionInfo,
    system: SystemInfo,
    swarm: SwarmInfo,
    server_header: HeaderValue,
    backend: Arc<dyn Backend>,
}

impl fmt::Debug for StateInner {
    /// The backend is a trait object with no `Debug` bound — name it by shape.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateInner")
            .field("version", &self.version)
            .field("system", &self.system)
            .field("swarm", &self.swarm)
            .field("server_header", &self.server_header)
            .field("backend", &"Arc<dyn Backend>")
            .finish()
    }
}

/// Cheap-to-clone handle (an [`Arc`] inside) carrying everything the API
/// handlers need. One instance is built by `satld` at startup and shared by
/// the whole router.
#[derive(Debug, Clone)]
pub struct ApiState {
    inner: Arc<StateInner>,
}

impl ApiState {
    /// Builds the shared state from daemon-provided facts.
    ///
    /// `swarm` is the cluster identity served in `/info`'s `Swarm` section;
    /// `satld` fills it from the bootstrapped Raft node (architecture §1.2).
    ///
    /// The container/image/volume endpoints start out backed by
    /// [`UnwiredBackend`] (every call answers `501 Not Implemented`); the
    /// daemon replaces it with [`ApiState::with_backend`] once its own
    /// implementation is constructed.
    #[must_use]
    pub fn new(version: VersionInfo, system: SystemInfo, swarm: SwarmInfo) -> Self {
        // Fall back to a bare product token if the version string contains
        // bytes that are invalid in an HTTP header (provably won't panic).
        let server_header = HeaderValue::from_str(&format!("SatL/{}", version.version))
            .unwrap_or_else(|_| HeaderValue::from_static("SatL"));
        Self {
            inner: Arc::new(StateInner {
                version,
                system,
                swarm,
                server_header,
                backend: Arc::new(UnwiredBackend),
            }),
        }
    }

    /// Attaches the daemon's [`Backend`] implementation, replacing the
    /// `501`-everything default.
    #[must_use]
    pub fn with_backend(self, backend: Arc<dyn Backend>) -> Self {
        // Called once at startup: unwrapping the Arc when possible, cloning
        // the (small) facts otherwise, is cheaper than reference-counting a
        // second indirection on every request.
        let inner = match Arc::try_unwrap(self.inner) {
            Ok(inner) => StateInner { backend, ..inner },
            Err(shared) => StateInner {
                version: shared.version.clone(),
                system: shared.system.clone(),
                swarm: shared.swarm.clone(),
                server_header: shared.server_header.clone(),
                backend,
            },
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// The daemon operations behind the container/image/volume endpoints.
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn Backend> {
        &self.inner.backend
    }

    /// Version/build identity served by `GET /version`.
    #[must_use]
    pub fn version(&self) -> &VersionInfo {
        &self.inner.version
    }

    /// Node facts served by `GET /info`.
    #[must_use]
    pub fn system(&self) -> &SystemInfo {
        &self.inner.system
    }

    /// Cluster identity served in `GET /info`'s `Swarm` section.
    #[must_use]
    pub fn swarm(&self) -> &SwarmInfo {
        &self.inner.swarm
    }

    /// Pre-computed `Server: SatL/<version>` header value.
    pub(crate) fn server_header(&self) -> HeaderValue {
        self.inner.server_header.clone()
    }
}
