// SPDX-License-Identifier: BSD-2-Clause
//! Manifest, index and config document parsing.
//!
//! Both OCI (`application/vnd.oci.image.*`) and Docker
//! (`application/vnd.docker.distribution.manifest.*`) media types are
//! accepted and normalized into the same types. Layer blobs stay compressed
//! exactly as downloaded — decompression is `satl-storage`'s job during
//! layer unpack — so the compression is *recorded* here, never applied.

use serde::Deserialize;

use crate::error::ImageError;
use crate::platform::Platform;
use crate::reference::Digest;

/// OCI image index media type.
pub const MEDIA_TYPE_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// OCI image manifest media type.
pub const MEDIA_TYPE_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// Docker schema2 manifest list media type.
pub const MEDIA_TYPE_DOCKER_MANIFEST_LIST: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";
/// Docker schema2 manifest media type.
pub const MEDIA_TYPE_DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// The `Accept` header value sent on manifest requests: OCI index/manifest
/// plus Docker manifest list/v2 (architecture §9).
pub const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v2+json";

/// Compression applied to a layer blob (recorded from the media type; the
/// blob itself is stored verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerCompression {
    /// Plain tar.
    None,
    /// tar+gzip (OCI `+gzip`, Docker `.tar.gzip`).
    Gzip,
    /// tar+zstd (OCI `+zstd`).
    Zstd,
}

/// Classifies a layer media type into its compression.
///
/// Accepts OCI (`application/vnd.oci.image.layer.v1.tar[+gzip|+zstd]`,
/// including the deprecated `nondistributable` variants) and Docker
/// (`application/vnd.docker.image.rootfs.diff.tar.gzip`, incl. `foreign`)
/// spellings.
// Triaged: these are media-type constants from the OCI/Docker specs (always
// emitted lowercase), not file paths — case-insensitive comparison would be
// wrong here.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
pub fn layer_compression(media_type: &str) -> Result<LayerCompression, ImageError> {
    let unsupported = || ImageError::UnsupportedMediaType {
        media_type: media_type.to_owned(),
        context: "image layer".to_owned(),
    };
    let is_oci = media_type.starts_with("application/vnd.oci.image.layer.");
    let is_docker = media_type.starts_with("application/vnd.docker.image.rootfs.");
    if !is_oci && !is_docker {
        return Err(unsupported());
    }
    if media_type.ends_with(".tar+gzip") || media_type.ends_with(".tar.gzip") {
        Ok(LayerCompression::Gzip)
    } else if media_type.ends_with(".tar+zstd") || media_type.ends_with(".tar.zstd") {
        Ok(LayerCompression::Zstd)
    } else if media_type.ends_with(".tar") {
        Ok(LayerCompression::None)
    } else {
        Err(unsupported())
    }
}

/// A content descriptor (manifest `config`/`layers` entries).
#[derive(Debug, Clone, Deserialize)]
pub struct Descriptor {
    /// Media type of the referenced content.
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    /// Digest of the referenced content.
    pub digest: Digest,
    /// Size in bytes.
    pub size: u64,
}

/// One entry of an image index / manifest list.
#[derive(Debug, Clone, Deserialize)]
pub struct IndexEntry {
    /// Media type of the referenced manifest.
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    /// Digest of the referenced manifest.
    pub digest: Digest,
    /// Size of the referenced manifest in bytes.
    #[serde(default)]
    pub size: u64,
    /// Platform of the referenced manifest. Buildx attestation entries carry
    /// `unknown/unknown` here and are skipped during selection.
    pub platform: Option<Platform>,
}

/// A parsed image index (OCI) / manifest list (Docker) — same shape.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageIndex {
    /// The per-platform manifest entries.
    pub manifests: Vec<IndexEntry>,
}

impl ImageIndex {
    /// The platforms of runnable entries (attestations excluded), for
    /// selection and for error listings.
    #[must_use]
    pub fn platforms(&self) -> Vec<Platform> {
        self.manifests
            .iter()
            .filter_map(|entry| entry.platform.clone())
            .filter(|platform| !platform.is_unknown())
            .collect()
    }

    /// Finds the entry whose platform matches `platform` exactly (as chosen
    /// by [`crate::platform::PlatformPolicy::select`] from
    /// [`Self::platforms`]).
    #[must_use]
    pub fn entry_for(&self, platform: &Platform) -> Option<&IndexEntry> {
        self.manifests
            .iter()
            .find(|entry| entry.platform.as_ref() == Some(platform))
    }
}

/// A parsed image manifest (single platform), OCI or Docker schema2.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageManifest {
    /// The document's own media type, echoed back on a push (empty when the
    /// manifest omits it, which Docker schema2 documents may).
    #[serde(default, rename = "mediaType")]
    pub media_type: String,
    /// Descriptor of the image config blob.
    pub config: Descriptor,
    /// Layer descriptors, base first.
    pub layers: Vec<Descriptor>,
}

/// Either kind of manifest document a registry can answer with.
#[derive(Debug, Clone)]
pub enum ManifestKind {
    /// A multi-platform index / manifest list.
    Index(ImageIndex),
    /// A single-platform image manifest.
    Manifest(ImageManifest),
}

impl ManifestKind {
    /// Parses manifest bytes, dispatching on the `Content-Type` the registry
    /// sent. Falls back to sniffing the document shape (`manifests` key ⇒
    /// index) when the content type is missing or generic — some registries
    /// answer `application/json`.
    pub fn parse(bytes: &[u8], content_type: &str, reference: &str) -> Result<Self, ImageError> {
        let content_type = content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim();
        let parse_index = || -> Result<Self, ImageError> {
            serde_json::from_slice(bytes)
                .map(Self::Index)
                .map_err(|source| ImageError::Parse {
                    what: "image index",
                    reference: reference.to_owned(),
                    source,
                })
        };
        let parse_manifest = || -> Result<Self, ImageError> {
            serde_json::from_slice(bytes)
                .map(Self::Manifest)
                .map_err(|source| ImageError::Parse {
                    what: "image manifest",
                    reference: reference.to_owned(),
                    source,
                })
        };
        match content_type {
            MEDIA_TYPE_OCI_INDEX | MEDIA_TYPE_DOCKER_MANIFEST_LIST => parse_index(),
            MEDIA_TYPE_OCI_MANIFEST | MEDIA_TYPE_DOCKER_MANIFEST => parse_manifest(),
            other => {
                // Sniff: an index has "manifests", a manifest has "config".
                let value: serde_json::Value =
                    serde_json::from_slice(bytes).map_err(|source| ImageError::Parse {
                        what: "manifest document",
                        reference: reference.to_owned(),
                        source,
                    })?;
                if value.get("manifests").is_some() {
                    parse_index()
                } else if value.get("config").is_some() {
                    parse_manifest()
                } else {
                    Err(ImageError::UnsupportedMediaType {
                        media_type: other.to_owned(),
                        context: format!("manifest response for {reference}"),
                    })
                }
            }
        }
    }
}

/// The runnable subset of an OCI image config, flattened for consumers
/// (`satl-runtime` OCI spec generation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageConfig {
    /// Environment (`KEY=value` entries).
    pub env: Vec<String>,
    /// Entrypoint, empty if unset.
    pub entrypoint: Vec<String>,
    /// Default command, empty if unset.
    pub cmd: Vec<String>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// User (name or uid[:gid]).
    pub user: Option<String>,
    /// Exposed ports as `port/proto` strings (e.g. `80/tcp`).
    pub exposed_ports: Vec<String>,
    /// OS the image was built for.
    pub os: String,
    /// Architecture the image was built for (GOARCH spelling).
    pub architecture: String,
}

/// Raw OCI image config document (only the fields we consume).
#[derive(Debug, Deserialize)]
struct RawImageConfig {
    architecture: String,
    os: String,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    config: Option<RawConfigBlock>,
    rootfs: RawRootFs,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default, rename = "os.version")]
    os_version: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawConfigBlock {
    #[serde(rename = "Env", default)]
    env: Vec<String>,
    #[serde(rename = "Entrypoint", default)]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd", default)]
    cmd: Option<Vec<String>>,
    #[serde(rename = "WorkingDir", default)]
    working_dir: Option<String>,
    #[serde(rename = "User", default)]
    user: Option<String>,
    #[serde(rename = "ExposedPorts", default)]
    exposed_ports: Option<std::collections::BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct RawRootFs {
    #[serde(rename = "type")]
    fs_type: String,
    diff_ids: Vec<Digest>,
}

/// Parsed image config: the flattened runnable config plus the rootfs
/// diff IDs (uncompressed-layer digests, zipped against manifest layers).
#[derive(Debug, Clone)]
pub struct ParsedConfig {
    /// Flattened runnable configuration.
    pub config: ImageConfig,
    /// The platform recorded in the config document.
    pub platform: Platform,
    /// `rootfs.diff_ids`, base layer first.
    pub diff_ids: Vec<Digest>,
    /// The config's `created` timestamp, when the builder set one. Rendered
    /// by `/images/json`; an image whose builder left it out (or set an
    /// unparseable one) simply lists no creation time.
    pub created: Option<std::time::SystemTime>,
}

/// Parses an image config blob.
pub fn parse_config(bytes: &[u8], reference: &str) -> Result<ParsedConfig, ImageError> {
    let raw: RawImageConfig =
        serde_json::from_slice(bytes).map_err(|source| ImageError::Parse {
            what: "image config",
            reference: reference.to_owned(),
            source,
        })?;
    if raw.rootfs.fs_type != "layers" {
        return Err(ImageError::UnsupportedMediaType {
            media_type: raw.rootfs.fs_type,
            context: format!("rootfs.type of image config {reference} (expected \"layers\")"),
        });
    }
    let block = raw.config.unwrap_or_default();
    // A builder that writes a broken `created` must not fail the pull: the
    // field is informational, and Docker renders its absence as the epoch.
    let created = raw
        .created
        .and_then(|stamp| chrono::DateTime::parse_from_rfc3339(&stamp).ok())
        .map(|parsed| parsed.with_timezone(&chrono::Utc).into());
    Ok(ParsedConfig {
        config: ImageConfig {
            env: block.env,
            entrypoint: block.entrypoint.unwrap_or_default(),
            cmd: block.cmd.unwrap_or_default(),
            working_dir: block.working_dir.filter(|dir| !dir.is_empty()),
            user: block.user.filter(|user| !user.is_empty()),
            exposed_ports: block
                .exposed_ports
                .map(|ports| ports.into_keys().collect())
                .unwrap_or_default(),
            os: raw.os.clone(),
            architecture: raw.architecture.clone(),
        },
        platform: Platform {
            os: raw.os,
            architecture: raw.architecture,
            variant: raw.variant,
            os_version: raw.os_version,
        },
        diff_ids: raw.rootfs.diff_ids,
        created,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real registry responses; provenance in tests/fixtures/README.md.
    const ALPINE_INDEX: &[u8] = include_bytes!("../tests/fixtures/alpine-index.json");
    const ALPINE_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/alpine-manifest.json");
    const ALPINE_CONFIG: &[u8] = include_bytes!("../tests/fixtures/alpine-config.json");
    const BUSYBOX_LIST: &[u8] = include_bytes!("../tests/fixtures/busybox-list.json");
    const BUSYBOX_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/busybox-manifest.json");

    #[test]
    fn fixture_digests_match_capture_notes() {
        // The fixtures are byte-for-byte as served; their digests are part
        // of the provenance note and other tests rely on them.
        assert_eq!(
            Digest::sha256_of(ALPINE_INDEX).as_str(),
            "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
        );
        assert_eq!(
            Digest::sha256_of(ALPINE_MANIFEST).as_str(),
            "sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e"
        );
        assert_eq!(
            Digest::sha256_of(ALPINE_CONFIG).as_str(),
            "sha256:bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731"
        );
    }

    #[test]
    fn parses_oci_index_and_skips_attestations() {
        let parsed =
            ManifestKind::parse(ALPINE_INDEX, MEDIA_TYPE_OCI_INDEX, "alpine:3.20").unwrap();
        let ManifestKind::Index(index) = parsed else {
            panic!("expected an index");
        };
        // 8 runnable platforms + 8 unknown/unknown attestation entries.
        assert_eq!(index.manifests.len(), 16);
        let platforms = index.platforms();
        assert_eq!(platforms.len(), 8);
        assert!(platforms.iter().any(|p| p.to_string() == "linux/amd64"));
        assert!(platforms.iter().all(|p| !p.is_unknown()));

        let amd64 = platforms
            .iter()
            .find(|p| p.to_string() == "linux/amd64")
            .unwrap();
        let entry = index.entry_for(amd64).unwrap();
        assert_eq!(
            entry.digest.as_str(),
            "sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e"
        );
        assert_eq!(entry.media_type, MEDIA_TYPE_OCI_MANIFEST);
    }

    #[test]
    fn parses_docker_manifest_list() {
        let parsed = ManifestKind::parse(
            BUSYBOX_LIST,
            MEDIA_TYPE_DOCKER_MANIFEST_LIST,
            "busybox:1.31",
        )
        .unwrap();
        let ManifestKind::Index(index) = parsed else {
            panic!("expected an index");
        };
        let platforms = index.platforms();
        assert!(platforms.iter().any(|p| p.to_string() == "linux/amd64"));
        assert!(platforms.iter().any(|p| p.to_string() == "linux/arm/v7"));
        let amd64 = platforms
            .iter()
            .find(|p| p.to_string() == "linux/amd64")
            .unwrap();
        assert_eq!(
            index.entry_for(amd64).unwrap().digest.as_str(),
            "sha256:fd4a8673d0344c3a7f427fe4440d4b8dfd4fa59cfabbd9098f9eb0cb4ba905d0"
        );
    }

    #[test]
    fn parses_oci_manifest() {
        let parsed =
            ManifestKind::parse(ALPINE_MANIFEST, MEDIA_TYPE_OCI_MANIFEST, "alpine").unwrap();
        let ManifestKind::Manifest(manifest) = parsed else {
            panic!("expected a manifest");
        };
        assert_eq!(manifest.layers.len(), 1);
        assert_eq!(
            manifest.config.digest.as_str(),
            "sha256:bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731"
        );
        assert_eq!(
            layer_compression(&manifest.layers[0].media_type).unwrap(),
            LayerCompression::Gzip
        );
    }

    #[test]
    fn parses_docker_manifest() {
        let parsed =
            ManifestKind::parse(BUSYBOX_MANIFEST, MEDIA_TYPE_DOCKER_MANIFEST, "busybox").unwrap();
        let ManifestKind::Manifest(manifest) = parsed else {
            panic!("expected a manifest");
        };
        assert_eq!(manifest.layers.len(), 1);
        assert_eq!(
            manifest.layers[0].media_type,
            "application/vnd.docker.image.rootfs.diff.tar.gzip"
        );
        assert_eq!(
            layer_compression(&manifest.layers[0].media_type).unwrap(),
            LayerCompression::Gzip
        );
    }

    #[test]
    fn sniffs_document_shape_for_generic_content_type() {
        let index = ManifestKind::parse(ALPINE_INDEX, "application/json", "alpine").unwrap();
        assert!(matches!(index, ManifestKind::Index(_)));
        let manifest = ManifestKind::parse(ALPINE_MANIFEST, "application/json", "alpine").unwrap();
        assert!(matches!(manifest, ManifestKind::Manifest(_)));
        assert!(ManifestKind::parse(b"{}", "application/json", "alpine").is_err());
        assert!(ManifestKind::parse(b"not json", "application/json", "alpine").is_err());
    }

    #[test]
    fn parses_alpine_config() {
        let parsed = parse_config(ALPINE_CONFIG, "alpine").unwrap();
        assert_eq!(parsed.config.os, "linux");
        assert_eq!(parsed.config.architecture, "amd64");
        assert_eq!(parsed.config.cmd, ["/bin/sh"]);
        assert!(parsed.config.entrypoint.is_empty());
        assert_eq!(parsed.config.env.len(), 1);
        assert!(parsed.config.env[0].starts_with("PATH="));
        assert_eq!(parsed.config.working_dir.as_deref(), Some("/"));
        assert_eq!(parsed.diff_ids.len(), 1);
        assert_eq!(parsed.platform.to_string(), "linux/amd64");
    }

    #[test]
    fn parses_exposed_ports_and_user() {
        let doc = br#"{
            "architecture": "amd64",
            "os": "freebsd",
            "config": {
                "User": "nginx",
                "ExposedPorts": {"80/tcp": {}, "443/tcp": {}},
                "Entrypoint": ["/entry.sh"],
                "Cmd": ["serve"]
            },
            "rootfs": {"type": "layers", "diff_ids": [
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ]}
        }"#;
        let parsed = parse_config(doc, "test").unwrap();
        assert_eq!(parsed.config.user.as_deref(), Some("nginx"));
        assert_eq!(parsed.config.exposed_ports, ["443/tcp", "80/tcp"]);
        assert_eq!(parsed.config.entrypoint, ["/entry.sh"]);
        assert_eq!(parsed.config.cmd, ["serve"]);
    }

    #[test]
    fn rejects_non_layer_rootfs() {
        let doc = br#"{
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "weird", "diff_ids": []}
        }"#;
        assert!(parse_config(doc, "test").is_err());
    }

    #[test]
    fn created_is_read_when_present_and_tolerated_when_broken() {
        let doc = br#"{
            "architecture": "amd64",
            "os": "freebsd",
            "created": "2026-08-14T18:00:00Z",
            "rootfs": {"type": "layers", "diff_ids": [
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ]}
        }"#;
        let parsed = parse_config(doc, "test").unwrap();
        let expected: std::time::SystemTime =
            chrono::DateTime::parse_from_rfc3339("2026-08-14T18:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
                .into();
        assert_eq!(parsed.created, Some(expected));

        // An unparseable stamp is dropped, not fatal (the field is
        // informational; Docker renders its absence as the epoch).
        let broken = br#"{
            "architecture": "amd64",
            "os": "freebsd",
            "created": "last tuesday",
            "rootfs": {"type": "layers", "diff_ids": [
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ]}
        }"#;
        assert_eq!(parse_config(broken, "test").unwrap().created, None);
    }

    #[test]
    fn layer_compression_matrix() {
        for (media_type, expected) in [
            (
                "application/vnd.oci.image.layer.v1.tar",
                LayerCompression::None,
            ),
            (
                "application/vnd.oci.image.layer.v1.tar+gzip",
                LayerCompression::Gzip,
            ),
            (
                "application/vnd.oci.image.layer.v1.tar+zstd",
                LayerCompression::Zstd,
            ),
            (
                "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
                LayerCompression::Gzip,
            ),
            (
                "application/vnd.docker.image.rootfs.diff.tar.gzip",
                LayerCompression::Gzip,
            ),
            (
                "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
                LayerCompression::Gzip,
            ),
        ] {
            assert_eq!(
                layer_compression(media_type).unwrap(),
                expected,
                "{media_type}"
            );
        }
        assert!(layer_compression("application/vnd.oci.image.config.v1+json").is_err());
        assert!(layer_compression("text/plain").is_err());
    }
}
