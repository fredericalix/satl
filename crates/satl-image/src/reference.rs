// SPDX-License-Identifier: BSD-2-Clause
//! Image reference parsing with Docker CLI normalization semantics.
//!
//! `[registry/]repository[:tag][@digest]` where:
//!
//! - a first path component counts as a registry only if it contains a `.` or
//!   a `:` or equals `localhost` (Docker's heuristic);
//! - bare names on Docker Hub gain the `library/` namespace
//!   (`nginx` → `docker.io/library/nginx`);
//! - `index.docker.io` and `registry-1.docker.io` normalize to `docker.io`,
//!   whose actual API endpoint is [`ImageReference::api_host`];
//! - the default tag is `latest`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::ImageError;

/// The normalized name of Docker Hub.
pub const DOCKER_IO: &str = "docker.io";

/// The API host actually serving `docker.io` pulls.
const DOCKER_IO_API_HOST: &str = "registry-1.docker.io";

/// A validated content digest: `sha256:<64 lowercase hex>`.
///
/// Only sha256 is accepted; that is the only algorithm the store lays out on
/// disk (`blobs/sha256/...`) and the only one Docker Hub and ghcr.io emit.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(String);

impl Digest {
    /// Computes the sha256 digest of `bytes`.
    #[must_use]
    pub fn sha256_of(bytes: &[u8]) -> Self {
        Self::from_sha256_hash(&Sha256::digest(bytes))
    }

    /// Wraps a raw 32-byte sha256 hash.
    #[must_use]
    pub fn from_sha256_hash(hash: &[u8]) -> Self {
        Self(format!("sha256:{}", hex::encode(hash)))
    }

    /// The full textual form, `sha256:<hex>`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The 64-character hex part (used for on-disk file names).
    #[must_use]
    pub fn hex(&self) -> &str {
        // Constructor validates the "sha256:" prefix, so this cannot slice
        // out of bounds.
        &self.0["sha256:".len()..]
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Digest {
    type Err = ImageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = |reason: &str| ImageError::InvalidDigest {
            input: s.to_owned(),
            reason: reason.to_owned(),
        };
        let Some(hex_part) = s.strip_prefix("sha256:") else {
            return Err(invalid("expected \"sha256:\" prefix"));
        };
        if hex_part.len() != 64 {
            return Err(invalid("expected 64 hex characters after \"sha256:\""));
        }
        if !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("digest hex must be lowercase [0-9a-f]"));
        }
        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<String> for Digest {
    type Error = ImageError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Digest> for String {
    fn from(digest: Digest) -> Self {
        digest.0
    }
}

/// A parsed, normalized image reference.
///
/// `Display` renders the *familiar* form Docker users expect (`nginx:latest`,
/// `ghcr.io/x/y:v1`); [`ImageReference::canonical`] renders the fully
/// qualified form used as the store key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageReference {
    /// Registry host, e.g. `docker.io`, `ghcr.io`, `localhost:5000`.
    pub registry: String,
    /// Repository path, e.g. `library/nginx`, `x/y`.
    pub repository: String,
    /// Tag; defaults to `latest` when absent (ignored for resolution when a
    /// digest is pinned).
    pub tag: String,
    /// Optional digest pin (`name@sha256:...`).
    pub digest: Option<Digest>,
}

impl ImageReference {
    /// Parses and normalizes a reference with Docker CLI semantics.
    pub fn parse(input: &str) -> Result<Self, ImageError> {
        let invalid = |reason: &str| ImageError::InvalidReference {
            input: input.to_owned(),
            reason: reason.to_owned(),
        };
        if input.is_empty() {
            return Err(invalid("empty reference"));
        }

        // 1. Split off a digest pin.
        let (name_and_tag, digest) = match input.split_once('@') {
            Some((rest, digest_str)) => (rest, Some(digest_str.parse::<Digest>()?)),
            None => (input, None),
        };

        // 2. Split off the registry: the first path component is a registry
        //    only if it looks like a host (contains '.' or ':', or equals
        //    "localhost"). Otherwise the whole name lives on Docker Hub.
        let (registry, remainder) = match name_and_tag.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (normalize_registry(first), rest)
            }
            _ => (DOCKER_IO.to_owned(), name_and_tag),
        };

        // 3. Split off the tag: a ':' after the last '/' of the remainder.
        let last_slash = remainder.rfind('/');
        let (repository, tag) = match remainder.rfind(':') {
            Some(colon) if last_slash.is_none_or(|slash| colon > slash) => {
                let (repo, tag_with_colon) = remainder.split_at(colon);
                (repo, &tag_with_colon[1..])
            }
            _ => (remainder, "latest"),
        };

        // 4. Docker Hub `library/` namespace for bare names.
        let repository = if registry == DOCKER_IO && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository.to_owned()
        };

        validate_repository(&repository).map_err(|reason| invalid(&reason))?;
        validate_tag(tag).map_err(|reason| invalid(&reason))?;

        Ok(Self {
            registry,
            repository,
            tag: tag.to_owned(),
            digest,
        })
    }

    /// Fully qualified form used as the metadata-store key.
    ///
    /// A digest pin wins over the tag: `ubuntu:24.04@sha256:x` canonicalizes
    /// to `docker.io/library/ubuntu@sha256:x`, so re-pulls by digest are
    /// idempotent regardless of the tag they were spelled with.
    #[must_use]
    pub fn canonical(&self) -> String {
        match &self.digest {
            Some(digest) => format!("{}/{}@{digest}", self.registry, self.repository),
            None => format!("{}/{}:{}", self.registry, self.repository, self.tag),
        }
    }

    /// The host actually contacted for API requests: `registry-1.docker.io`
    /// for Docker Hub, the registry itself otherwise.
    #[must_use]
    pub fn api_host(&self) -> &str {
        if self.registry == DOCKER_IO {
            DOCKER_IO_API_HOST
        } else {
            &self.registry
        }
    }

    /// The tag or digest to request the manifest by (digest pin wins).
    #[must_use]
    pub fn manifest_reference(&self) -> &str {
        match &self.digest {
            Some(digest) => digest.as_str(),
            None => &self.tag,
        }
    }

    /// The OCI distribution token scope granting pull access.
    #[must_use]
    pub fn pull_scope(&self) -> String {
        format!("repository:{}:pull", self.repository)
    }

    /// The scope granting push access (pull included: a push re-reads blobs
    /// and manifests to skip what the registry already has).
    #[must_use]
    pub fn push_scope(&self) -> String {
        format!("repository:{}:pull,push", self.repository)
    }
}

impl fmt::Display for ImageReference {
    /// The familiar form: Docker Hub's registry and `library/` namespace are
    /// omitted; the `:latest` tag is omitted when a digest is pinned.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let repo = if self.registry == DOCKER_IO {
            self.repository
                .strip_prefix("library/")
                .unwrap_or(&self.repository)
        } else {
            write!(f, "{}/", self.registry)?;
            &self.repository
        };
        f.write_str(repo)?;
        match &self.digest {
            Some(digest) => {
                if self.tag != "latest" {
                    write!(f, ":{}", self.tag)?;
                }
                write!(f, "@{digest}")
            }
            None => write!(f, ":{}", self.tag),
        }
    }
}

impl FromStr for ImageReference {
    type Err = ImageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// The canonical store key for a user-written reference; an input that
/// will not parse keys as itself (the store can hold no such record, so
/// the lookup misses honestly rather than lying).
///
/// This is the one canonical-key rule for every map keyed by an image
/// reference. Two callers spelling it differently is a recurring bug family:
/// `list_images`' Containers count read 0 for informally spelled images
/// (2026-08-19), and the PLATFORM column was empty for the same inputs
/// (2026-08-23), both because one side keyed on the canonical reference and
/// the other looked up the raw user string.
#[must_use]
pub fn canonical_key(reference: &str) -> String {
    ImageReference::parse(reference)
        .map_or_else(|_| reference.to_owned(), |parsed| parsed.canonical())
}

/// Collapses Docker Hub aliases and lowercases the host.
fn normalize_registry(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    match host.as_str() {
        "index.docker.io" | "registry-1.docker.io" | "docker.io" => DOCKER_IO.to_owned(),
        _ => host,
    }
}

/// Validates a repository path: lowercase alphanumeric components separated
/// by `/`, with `.`, `_`, `__` or `-` separators inside a component.
fn validate_repository(repository: &str) -> Result<(), String> {
    if repository.is_empty() {
        return Err("empty repository name".to_owned());
    }
    if repository.len() > 255 {
        return Err("repository name longer than 255 characters".to_owned());
    }
    for component in repository.split('/') {
        if component.is_empty() {
            return Err("empty repository path component".to_owned());
        }
        let bytes = component.as_bytes();
        let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if !alnum(bytes[0]) || !alnum(bytes[bytes.len() - 1]) {
            return Err(format!(
                "repository component {component:?} must start and end with lowercase \
                 alphanumeric (repository names must be lowercase)"
            ));
        }
        if !bytes
            .iter()
            .all(|&b| alnum(b) || b == b'.' || b == b'_' || b == b'-')
        {
            return Err(format!(
                "repository component {component:?} contains invalid characters \
                 (allowed: lowercase alphanumeric, '.', '_', '-')"
            ));
        }
    }
    Ok(())
}

/// Validates a tag: `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`.
fn validate_tag(tag: &str) -> Result<(), String> {
    let bytes = tag.as_bytes();
    if bytes.is_empty() {
        return Err("empty tag".to_owned());
    }
    if bytes.len() > 128 {
        return Err("tag longer than 128 characters".to_owned());
    }
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    if !word(bytes[0]) {
        return Err(format!("tag {tag:?} must start with [A-Za-z0-9_]"));
    }
    if !bytes.iter().all(|&b| word(b) || b == b'.' || b == b'-') {
        return Err(format!("tag {tag:?} contains invalid characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

    /// `(input, registry, repository, tag, has_digest, familiar, canonical)`
    // Triaged: this is a flat data table, not logic — line count and tuple
    // width are the point.
    #[allow(clippy::type_complexity, clippy::too_many_lines)]
    fn table() -> Vec<(
        String,
        &'static str,
        &'static str,
        &'static str,
        bool,
        String,
        String,
    )> {
        vec![
            (
                "nginx".into(),
                "docker.io",
                "library/nginx",
                "latest",
                false,
                "nginx:latest".into(),
                "docker.io/library/nginx:latest".into(),
            ),
            (
                "library/nginx".into(),
                "docker.io",
                "library/nginx",
                "latest",
                false,
                "nginx:latest".into(),
                "docker.io/library/nginx:latest".into(),
            ),
            (
                "docker.io/nginx".into(),
                "docker.io",
                "library/nginx",
                "latest",
                false,
                "nginx:latest".into(),
                "docker.io/library/nginx:latest".into(),
            ),
            (
                "index.docker.io/library/nginx:1.25".into(),
                "docker.io",
                "library/nginx",
                "1.25",
                false,
                "nginx:1.25".into(),
                "docker.io/library/nginx:1.25".into(),
            ),
            (
                "registry-1.docker.io/library/nginx".into(),
                "docker.io",
                "library/nginx",
                "latest",
                false,
                "nginx:latest".into(),
                "docker.io/library/nginx:latest".into(),
            ),
            (
                "ghcr.io/x/y:v1".into(),
                "ghcr.io",
                "x/y",
                "v1",
                false,
                "ghcr.io/x/y:v1".into(),
                "ghcr.io/x/y:v1".into(),
            ),
            // Non-Hub registries never gain the library/ namespace.
            (
                "quay.io/prometheus".into(),
                "quay.io",
                "prometheus",
                "latest",
                false,
                "quay.io/prometheus:latest".into(),
                "quay.io/prometheus:latest".into(),
            ),
            // localhost keeps its port and gets no library/ insertion.
            (
                "localhost:5000/x".into(),
                "localhost:5000",
                "x",
                "latest",
                false,
                "localhost:5000/x:latest".into(),
                "localhost:5000/x:latest".into(),
            ),
            (
                "localhost/x".into(),
                "localhost",
                "x",
                "latest",
                false,
                "localhost/x:latest".into(),
                "localhost/x:latest".into(),
            ),
            (
                "127.0.0.1:5000/foo/bar:dev".into(),
                "127.0.0.1:5000",
                "foo/bar",
                "dev",
                false,
                "127.0.0.1:5000/foo/bar:dev".into(),
                "127.0.0.1:5000/foo/bar:dev".into(),
            ),
            // A digest pin.
            (
                format!("alpine@{SHA}"),
                "docker.io",
                "library/alpine",
                "latest",
                true,
                format!("alpine@{SHA}"),
                format!("docker.io/library/alpine@{SHA}"),
            ),
            // Tag + digest: digest wins for canonical, tag kept in familiar.
            (
                format!("alpine:3.20@{SHA}"),
                "docker.io",
                "library/alpine",
                "3.20",
                true,
                format!("alpine:3.20@{SHA}"),
                format!("docker.io/library/alpine@{SHA}"),
            ),
            // A first component with a dot is a registry.
            (
                "example.com/app".into(),
                "example.com",
                "app",
                "latest",
                false,
                "example.com/app:latest".into(),
                "example.com/app:latest".into(),
            ),
            // A first component with a colon (port) is a registry.
            (
                "myhost:5000/app:2".into(),
                "myhost:5000",
                "app",
                "2",
                false,
                "myhost:5000/app:2".into(),
                "myhost:5000/app:2".into(),
            ),
            // Nested repositories stay on Docker Hub without library/.
            (
                "someuser/someimage:tag".into(),
                "docker.io",
                "someuser/someimage",
                "tag",
                false,
                "someuser/someimage:tag".into(),
                "docker.io/someuser/someimage:tag".into(),
            ),
        ]
    }

    #[test]
    fn parse_table() {
        for (input, registry, repository, tag, has_digest, familiar, canonical) in table() {
            let parsed = ImageReference::parse(&input)
                .unwrap_or_else(|e| panic!("{input:?} should parse: {e}"));
            assert_eq!(parsed.registry, registry, "registry of {input:?}");
            assert_eq!(parsed.repository, repository, "repository of {input:?}");
            assert_eq!(parsed.tag, tag, "tag of {input:?}");
            assert_eq!(parsed.digest.is_some(), has_digest, "digest of {input:?}");
            assert_eq!(parsed.to_string(), familiar, "familiar of {input:?}");
            assert_eq!(parsed.canonical(), canonical, "canonical of {input:?}");
        }
    }

    #[test]
    fn parse_roundtrips_through_display() {
        for (input, ..) in table() {
            let parsed = ImageReference::parse(&input).unwrap();
            let reparsed = ImageReference::parse(&parsed.to_string()).unwrap();
            assert_eq!(
                parsed.canonical(),
                reparsed.canonical(),
                "roundtrip of {input:?}"
            );
        }
    }

    #[test]
    fn api_host_maps_docker_io() {
        let hub = ImageReference::parse("nginx").unwrap();
        assert_eq!(hub.api_host(), "registry-1.docker.io");
        let ghcr = ImageReference::parse("ghcr.io/x/y").unwrap();
        assert_eq!(ghcr.api_host(), "ghcr.io");
        let local = ImageReference::parse("localhost:5000/x").unwrap();
        assert_eq!(local.api_host(), "localhost:5000");
    }

    #[test]
    fn pull_scope_uses_full_repository() {
        let r = ImageReference::parse("nginx").unwrap();
        assert_eq!(r.pull_scope(), "repository:library/nginx:pull");
    }

    #[test]
    fn manifest_reference_prefers_digest() {
        let by_tag = ImageReference::parse("alpine:3.20").unwrap();
        assert_eq!(by_tag.manifest_reference(), "3.20");
        let pinned = ImageReference::parse(&format!("alpine:3.20@{SHA}")).unwrap();
        assert_eq!(pinned.manifest_reference(), SHA);
    }

    #[test]
    fn rejects_invalid_references() {
        for bad in [
            "",
            "UPPER/case",
            "nginx:",
            "nginx:.badtag",
            "nginx:-bad",
            "a//b",
            "registry.example.com/",
            "alpine@sha256:short",
            "alpine@md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "alpine@sha256:ZZe853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
        ] {
            assert!(
                ImageReference::parse(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn digest_validation() {
        let ok: Digest = SHA.parse().unwrap();
        assert_eq!(ok.as_str(), SHA);
        assert_eq!(ok.hex().len(), 64);
        assert!(Digest::from_str("sha256:abc").is_err());
        assert!(
            Digest::from_str(&format!("sha512:{}", "a".repeat(64))).is_err(),
            "only sha256 accepted"
        );
        assert!(
            Digest::from_str(&format!("sha256:{}", "A".repeat(64))).is_err(),
            "uppercase hex rejected"
        );
    }

    #[test]
    fn canonical_key_normalizes_a_bare_name() {
        assert_eq!(canonical_key("alpine"), "docker.io/library/alpine:latest");
    }

    #[test]
    fn canonical_key_roundtrips_a_qualified_reference() {
        assert_eq!(canonical_key("ghcr.io/x/y:v1"), "ghcr.io/x/y:v1");
    }

    #[test]
    fn canonical_key_pins_on_the_digest() {
        assert_eq!(
            canonical_key(&format!("alpine:3.20@{SHA}")),
            format!("docker.io/library/alpine@{SHA}"),
            "the digest wins over the tag"
        );
    }

    #[test]
    fn canonical_key_of_unparsable_input_is_itself() {
        assert_eq!(canonical_key("UPPER case image"), "UPPER case image");
        assert_eq!(canonical_key(""), "");
    }

    #[test]
    fn digest_of_bytes() {
        // sha256("") is a well-known constant.
        assert_eq!(
            Digest::sha256_of(b"").as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
