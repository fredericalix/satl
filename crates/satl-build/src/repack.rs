// SPDX-License-Identifier: BSD-2-Clause
//! Assembling the OCI image of a build: the base image's layers plus one
//! layer per mutating step (M8b; single-layer squashing was M6f's shape and
//! is gone — the layer-per-step shape is what makes the build cache's
//! `diff_ids` mean something to every other consumer of the store).
//!
//! `package_image` is pure assembly: the step layers arrive already packed
//! and staged (see `crate::layer` and the build driver), the base layers are
//! already in the store, and what this module adds is the manifest and the
//! config — `diff_ids` chained after the base's, history aligned one entry per
//! layer, `created` stamped (M7a).

use std::path::PathBuf;

use satl_image::{LayerDescriptor, LocalImage, Platform};

use crate::satlfile::Stage;

/// Packaging failed. Carries the step and the underlying error text — for
/// external commands, the full argv and stderr (see `crate::run`).
#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    /// The OCI documents failed to serialize (should not happen).
    #[error("oci documents: {0}")]
    Serialize(#[from] serde_json::Error),
    /// An I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// The media types, pinned so a consumer never has to guess.
const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// One step's layer, packed and staged, ready for the manifest.
#[derive(Debug)]
pub struct StepRecord {
    /// The instruction text (`RUN npm install`), for the config's history.
    pub instruction: String,
    /// sha256 of the uncompressed tar.
    pub diff_id: String,
    /// sha256 of the gzip blob.
    pub blob_digest: String,
    /// The blob's byte length.
    pub size: u64,
    /// The blob, staged under the store's `tmp/` (registration renames it).
    pub staged: PathBuf,
}

/// Assemble the OCI image of a build: `base_layers` first (already in the
/// store), then one descriptor per `steps` record. The config's
/// `rootfs.diff_ids` chains the same way, and `history` carries one entry
/// per layer so the two stay aligned. `stage` is the build's last stage —
/// the only one whose rootfs and metadata become the image (M8c).
pub fn package_image(
    stage: &Stage,
    base_layers: &[LayerDescriptor],
    steps: &[StepRecord],
) -> Result<LocalImage, PackageError> {
    // 1. The config: runtime fields from the stage, platform pinned to
    //    the host's — a SatL build host is a FreeBSD one.
    let created = created_now();
    let config_block = runtime_config(stage);
    let diff_ids: Vec<String> = base_layers
        .iter()
        .map(|layer| layer.diff_id.to_string())
        .chain(steps.iter().map(|step| step.diff_id.clone()))
        .collect();
    // One history entry per layer, so entries without `empty_layer` align
    // with `diff_ids` one-to-one (the OCI config spec's only hard rule about
    // history). The base's own history is not readable from a pulled image,
    // and inventing it would be worse.
    let history: Vec<serde_json::Value> = base_layers
        .iter()
        .map(|_| {
            serde_json::json!({
                "created": created,
                "created_by": "base image layer",
            })
        })
        .chain(steps.iter().map(|step| {
            serde_json::json!({
                "created": created,
                "created_by": format!("satl build: {}", step.instruction),
            })
        }))
        .collect();
    let config = serde_json::json!({
        "created": created,
        "architecture": "amd64",
        "os": "freebsd",
        "config": serde_json::Value::Object(config_block),
        "rootfs": { "type": "layers", "diff_ids": diff_ids },
        "history": history,
    });
    let config_bytes = serde_json::to_vec_pretty(&config)?;
    let config_digest = format!("sha256:{}", sha256_hex(&config_bytes));

    // 2. The manifest: base descriptors as pulled, step descriptors as
    //    packed.
    let layers: Vec<serde_json::Value> = base_layers
        .iter()
        .map(|layer| {
            serde_json::json!({
                "mediaType": layer.media_type,
                "digest": layer.blob_digest.to_string(),
                "size": layer.size,
            })
        })
        .chain(steps.iter().map(|step| {
            serde_json::json!({
                "mediaType": LAYER_MEDIA_TYPE,
                "digest": step.blob_digest,
                "size": step.size,
            })
        }))
        .collect();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": config_bytes.len(),
        },
        "layers": layers,
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;

    Ok(LocalImage {
        manifest: manifest_bytes,
        config: config_bytes,
        layers: steps
            .iter()
            .map(|step| {
                (
                    step.blob_digest.parse().expect("a sha256 digest"),
                    step.staged.clone(),
                )
            })
            .collect(),
        platform: Platform {
            os: "freebsd".to_owned(),
            architecture: "amd64".to_owned(),
            variant: None,
            os_version: None,
        },
    })
}

/// The image config's runtime block (`config`): the stage's ENTRYPOINT,
/// CMD, ENV, WORKDIR, LABEL and EXPOSE fields.
fn runtime_config(stage: &Stage) -> serde_json::Map<String, serde_json::Value> {
    let mut config_block = serde_json::Map::new();
    if let Some(entrypoint) = &stage.entrypoint {
        config_block.insert("Entrypoint".into(), serde_json::json!(entrypoint));
    }
    if let Some(cmd) = &stage.cmd {
        config_block.insert("Cmd".into(), serde_json::json!(cmd));
    }
    if !stage.env.is_empty() {
        let env: Vec<String> = stage
            .env
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        config_block.insert("Env".into(), serde_json::json!(env));
    }
    if let Some(workdir) = &stage.workdir {
        config_block.insert("WorkingDir".into(), serde_json::json!(workdir));
    }
    if !stage.labels.is_empty() {
        config_block.insert("Labels".into(), serde_json::json!(stage.labels));
    }
    if !stage.expose.is_empty() {
        let ports: serde_json::Map<String, serde_json::Value> = stage
            .expose
            .iter()
            .map(|port| (port.clone(), serde_json::json!({})))
            .collect();
        config_block.insert("ExposedPorts".into(), serde_json::Value::Object(ports));
    }
    config_block
}

/// sha256 of `bytes`, lowercase hex.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// gzip with no name and no timestamp, so two builds of the same bytes
/// produce the same blob.
pub(crate) fn gzip(bytes: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).expect("gzip to memory");
    encoder.finish().expect("gzip to memory")
}

/// RFC 3339 UTC, the OCI `created` shape.
fn created_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    // Compose YYYY-MM-DDTHH:MM:SSZ from the epoch without a chrono dep.
    let days = secs / 86_400;
    let secs_of_day = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Days since the epoch to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_are_right() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_449), (2023, 4, 2));
        assert_eq!(civil_from_days(20_382), (2025, 10, 21));
    }

    #[test]
    fn created_is_rfc3339_utc() {
        let created = created_now();
        assert!(created.ends_with('Z') && created.len() == 20, "{created}");
    }

    #[test]
    fn sha256_hex_is_64_lower_hex() {
        let hex = sha256_hex(b"satl");
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    /// sha256-prefixed hex of a byte, for fake layer digests.
    fn digest(byte: &str) -> String {
        format!("sha256:{}", byte.repeat(32))
    }

    #[test]
    fn the_manifest_chains_base_then_steps() {
        let base = vec![
            LayerDescriptor {
                blob_digest: digest("aa").parse().unwrap(),
                diff_id: digest("bb").parse().unwrap(),
                media_type: LAYER_MEDIA_TYPE.to_owned(),
                size: 100,
            },
            LayerDescriptor {
                blob_digest: digest("cc").parse().unwrap(),
                diff_id: digest("dd").parse().unwrap(),
                media_type: LAYER_MEDIA_TYPE.to_owned(),
                size: 200,
            },
        ];
        let steps = vec![StepRecord {
            instruction: "RUN npm install".to_owned(),
            diff_id: digest("11"),
            blob_digest: digest("22"),
            size: 300,
            staged: PathBuf::from("/tmp/staged"),
        }];
        let spec = crate::Satlfile::parse("FROM base\nRUN npm install\n").unwrap();
        let image = package_image(spec.last_stage(), &base, &steps).unwrap();

        let manifest: serde_json::Value = serde_json::from_slice(&image.manifest).unwrap();
        let layers = manifest["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 3, "two base layers plus the step layer");
        assert_eq!(layers[0]["digest"], digest("aa"));
        assert_eq!(layers[2]["digest"], digest("22"));
        assert_eq!(layers[2]["size"], 300);

        let config: serde_json::Value = serde_json::from_slice(&image.config).unwrap();
        assert_eq!(
            config["rootfs"]["diff_ids"],
            serde_json::json!([digest("bb"), digest("dd"), digest("11")])
        );
        assert_eq!(
            config["history"].as_array().unwrap().len(),
            3,
            "one history entry per layer, so the two stay aligned"
        );
        assert!(config["created"].as_str().unwrap().ends_with('Z'));
        // Only the step blob is handed to registration; the base is already
        // in the store.
        assert_eq!(image.layers.len(), 1);
    }
}
