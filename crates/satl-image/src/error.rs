// SPDX-License-Identifier: BSD-2-Clause
//! Error types for the image pipeline.
//!
//! Operator-facing rule (CLAUDE.md): every network-facing error names the
//! registry, repository and/or digest involved, so a failed pull can be
//! diagnosed from the message alone.

use std::path::PathBuf;

/// Errors produced by the `satl-image` crate.
#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    /// An image reference string failed to parse.
    #[error("invalid image reference {input:?}: {reason}")]
    InvalidReference {
        /// The offending input string.
        input: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A digest string failed validation (`sha256:<64 lowercase hex>`).
    #[error("invalid digest {input:?}: {reason}")]
    InvalidDigest {
        /// The offending input string.
        input: String,
        /// Why it was rejected.
        reason: String,
    },

    /// Plain-HTTP registries are only allowed on the loopback host.
    #[error(
        "refusing plain-HTTP registry {registry:?}: only localhost/127.0.0.1 may be \
         contacted without TLS"
    )]
    PlainHttpRefused {
        /// The non-loopback registry that would have been contacted over HTTP.
        registry: String,
    },

    /// Transport-level HTTP failure (connect, TLS, body read, ...).
    #[error("registry {registry}: {context} for {repository}: {source}")]
    Http {
        /// Registry host the request was sent to.
        registry: String,
        /// Repository the request concerned.
        repository: String,
        /// What was being attempted (e.g. "GET manifest sha256:...").
        context: String,
        /// Underlying transport error.
        #[source]
        source: reqwest::Error,
    },

    /// The registry answered with an unexpected HTTP status.
    #[error("registry {registry}: {context} for {repository}: HTTP {status}: {body}")]
    RegistryStatus {
        /// Registry host that answered.
        registry: String,
        /// Repository the request concerned.
        repository: String,
        /// What was being attempted.
        context: String,
        /// The HTTP status code received.
        status: u16,
        /// Response body excerpt (registry error payloads are informative).
        body: String,
    },

    /// The registry opened a blob upload but sent no `Location` to continue
    /// it (a spec violation: there is nothing to PUT to).
    #[error("registry {registry}: blob upload for {repository} opened with no Location header")]
    MissingUploadLocation {
        /// Registry host that answered.
        registry: String,
        /// Repository the upload concerned.
        repository: String,
    },

    /// The registry returned 401 and we could not satisfy its challenge.
    #[error(
        "registry {registry}: authentication failed for {repository}: {reason} \
         (WWW-Authenticate: {challenge:?})"
    )]
    Unauthorized {
        /// Registry host that rejected us.
        registry: String,
        /// Repository access was denied to.
        repository: String,
        /// Why the challenge could not be satisfied.
        reason: String,
        /// The raw `WWW-Authenticate` header, if any.
        challenge: Option<String>,
    },

    /// Fetching a bearer token from the auth service failed.
    #[error("registry {registry}: token fetch from {realm} for scope {scope:?} failed: {reason}")]
    TokenFetch {
        /// Registry the token was for.
        registry: String,
        /// The `realm` URL from the challenge.
        realm: String,
        /// The scope requested.
        scope: String,
        /// Why it failed.
        reason: String,
    },

    /// Downloaded content did not hash to the expected digest.
    #[error(
        "registry {registry}: digest mismatch for {repository} {context}: \
         expected {expected}, got {actual}"
    )]
    DigestMismatch {
        /// Registry the content came from.
        registry: String,
        /// Repository the content belongs to.
        repository: String,
        /// What was being verified (e.g. "manifest", "blob").
        context: String,
        /// The digest we expected.
        expected: String,
        /// The digest the bytes actually hash to.
        actual: String,
    },

    /// A manifest, index or config document failed to parse.
    #[error("failed to parse {what} {reference}: {source}")]
    Parse {
        /// Document kind ("manifest", "image index", "image config", ...).
        what: &'static str,
        /// Which document (digest or reference) failed.
        reference: String,
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },

    /// A media type we do not understand appeared where a layer/manifest was
    /// expected.
    #[error("unsupported media type {media_type:?} for {context}")]
    UnsupportedMediaType {
        /// The media type string.
        media_type: String,
        /// Where it appeared.
        context: String,
    },

    /// The requested (or host-derived) platform is not in the image index.
    #[error(
        "no matching platform for {requested} in {reference}; available: [{}]",
        available.join(", ")
    )]
    PlatformNotFound {
        /// What we were looking for ("freebsd/amd64, linux/amd64 (emulation)"
        /// or the explicit `--platform` value).
        requested: String,
        /// The image reference being resolved.
        reference: String,
        /// Platforms actually present in the index.
        available: Vec<String>,
    },

    /// Manifest layer list and config `rootfs.diff_ids` disagree in length.
    #[error(
        "image {reference}: manifest has {manifest_layers} layers but config lists \
         {diff_ids} diff_ids"
    )]
    LayerCountMismatch {
        /// The image reference being pulled.
        reference: String,
        /// Number of layers in the manifest.
        manifest_layers: usize,
        /// Number of `diff_ids` in the config.
        diff_ids: usize,
    },

    /// Local content/metadata store I/O failure.
    #[error("image store I/O at {path}: {source}")]
    Io {
        /// Path involved.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The store metadata is internally inconsistent (e.g. repositories.json
    /// points at a manifest file that is missing).
    #[error("image store corrupt: {reason}")]
    StoreCorrupt {
        /// What is inconsistent.
        reason: String,
    },

    /// A reference the local store does not hold (Docker's "An image does not
    /// exist locally").
    #[error("no such image in the local store: {reference}")]
    NotFound {
        /// The canonical reference that was looked up.
        reference: String,
    },
}

impl ImageError {
    /// Helper for store I/O errors.
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
