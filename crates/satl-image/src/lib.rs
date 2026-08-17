// SPDX-License-Identifier: BSD-2-Clause
//! OCI distribution client (pull only), manifest/platform resolution and
//! node-local content store. Lands in M1. See `docs/architecture.md` §9.
//!
//! # Overview
//!
//! - [`reference`]: image reference parsing with Docker CLI normalization
//!   (`nginx` → `docker.io/library/nginx:latest`).
//! - [`auth`]: registry token auth (`WWW-Authenticate: Bearer` challenges,
//!   Basic credentials); nothing is ever persisted.
//! - [`client`]: HTTPS (rustls) pull client — manifests and blobs with
//!   digest verification and transient-failure retries; plain HTTP allowed
//!   for loopback registries only.
//! - [`platform`]: platform selection — explicit `--platform`, else
//!   `freebsd/<host arch>`, else `linux/amd64` under the linuxulator, else
//!   a typed error listing what the index offers.
//! - [`manifest`]: OCI *and* Docker media types normalized into one set of
//!   types; layer blobs stay compressed (gzip/zstd/plain recorded, never
//!   decompressed here — unpack is `satl-storage`'s job).
//! - [`store`]: content-addressed blob + metadata store under
//!   `/var/db/satl/images` with atomic metadata writes and per-reference
//!   pull serialization; entry point [`ImageStore::pull`].
//!
//! Decoding Docker's `X-Registry-Auth` header and streaming pull progress
//! over the REST API belong to `satl-api`, not this crate.

pub mod auth;
pub mod client;
pub mod error;
pub mod manifest;
pub mod platform;
pub mod reference;
pub mod store;

pub use auth::RegistryAuth;
pub use client::{FetchedManifest, RegistryClient};
pub use error::ImageError;
pub use manifest::{ImageConfig, LayerCompression};
pub use platform::{Platform, PlatformPolicy};
pub use reference::{Digest, ImageReference};
pub use store::{
    ContentAudit, ContentFile, ContentKind, ImageStore, LayerDescriptor, LocalImage,
    ProgressSender, PullProgress, PulledImage,
};
