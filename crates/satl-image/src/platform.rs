// SPDX-License-Identifier: BSD-2-Clause
//! Platform selection policy (architecture §9, brief §1.6).
//!
//! From a manifest list / OCI index SatL picks, in order:
//!
//! 1. the explicitly requested platform (`--platform`), which must exist —
//!    otherwise a typed error lists what is available;
//! 2. `freebsd/<host arch>` (native jails);
//! 3. `linux/amd64` when the node runs the linuxulator;
//! 4. otherwise a typed error listing the available platforms.
//!
//! `variant` is matched loosely: it only participates when needed to
//! disambiguate several entries of the same os/arch. `os.version` is
//! recorded but never used for matching. Buildx attestation entries
//! (`unknown/unknown`) are ignored.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ImageError;

/// An OCI platform (`os`, `architecture`, optional `variant`/`os.version`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Platform {
    /// Operating system, e.g. `freebsd`, `linux`.
    pub os: String,
    /// CPU architecture in GOARCH spelling, e.g. `amd64`, `arm64`.
    pub architecture: String,
    /// Optional architecture variant, e.g. `v8` for `arm64`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// Optional OS version; recorded, never matched on.
    #[serde(
        default,
        rename = "os.version",
        skip_serializing_if = "Option::is_none"
    )]
    pub os_version: Option<String>,
}

impl Platform {
    /// Convenience constructor without variant/os.version.
    #[must_use]
    pub fn new(os: &str, architecture: &str) -> Self {
        Self {
            os: os.to_owned(),
            architecture: architecture.to_owned(),
            variant: None,
            os_version: None,
        }
    }

    /// Whether this is a buildx attestation placeholder (`unknown/unknown`),
    /// which is never a runnable platform.
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        self.os == "unknown" || self.architecture == "unknown"
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.architecture)?;
        if let Some(variant) = &self.variant {
            write!(f, "/{variant}")?;
        }
        Ok(())
    }
}

impl FromStr for Platform {
    type Err = ImageError;

    /// Parses `os/arch[/variant]` (the `--platform` syntax).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || ImageError::InvalidReference {
            input: s.to_owned(),
            reason: "platform must be os/arch[/variant], e.g. freebsd/amd64".to_owned(),
        };
        let mut parts = s.split('/');
        let os = parts.next().filter(|p| !p.is_empty()).ok_or_else(invalid)?;
        let arch = parts.next().filter(|p| !p.is_empty()).ok_or_else(invalid)?;
        let variant = parts.next().filter(|p| !p.is_empty());
        if parts.next().is_some() {
            return Err(invalid());
        }
        Ok(Self {
            os: os.to_owned(),
            architecture: arch.to_owned(),
            variant: variant.map(str::to_owned),
            os_version: None,
        })
    }
}

/// How to choose a platform from an image index for this node.
#[derive(Debug, Clone)]
pub struct PlatformPolicy {
    /// Host operating system (`freebsd` on a SatL node).
    pub host_os: String,
    /// Host architecture in GOARCH spelling (`amd64`, `arm64`).
    pub host_arch: String,
    /// Whether the node can run Linux binaries via the linuxulator,
    /// enabling the `linux/amd64` fallback.
    pub linux_emulation: bool,
    /// Explicit `--platform` request; must exist in the index if set.
    pub explicit: Option<Platform>,
}

impl PlatformPolicy {
    /// Policy for the current compilation target.
    ///
    /// `host_arch` uses GOARCH spelling as found in image indexes.
    #[must_use]
    pub fn for_host(linux_emulation: bool) -> Self {
        let host_arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        Self {
            host_os: std::env::consts::OS.to_owned(),
            host_arch: host_arch.to_owned(),
            linux_emulation,
            explicit: None,
        }
    }

    /// Selects a platform from `available` (the runnable entries of an image
    /// index; attestation placeholders are skipped).
    ///
    /// `reference` only labels the error message.
    pub fn select<'a>(
        &self,
        available: &'a [Platform],
        reference: &str,
    ) -> Result<&'a Platform, ImageError> {
        let runnable: Vec<&Platform> = available.iter().filter(|p| !p.is_unknown()).collect();

        if let Some(explicit) = &self.explicit {
            return pick(&runnable, explicit)
                .ok_or_else(|| not_found(explicit.to_string(), &runnable, reference));
        }

        let native = Platform::new(&self.host_os, &self.host_arch);
        if let Some(found) = pick(&runnable, &native) {
            return Ok(found);
        }

        if self.linux_emulation {
            let emulated = Platform::new("linux", "amd64");
            if let Some(found) = pick(&runnable, &emulated) {
                return Ok(found);
            }
        }

        let mut requested = native.to_string();
        if self.linux_emulation {
            requested.push_str(" or linux/amd64 (emulation)");
        }
        Err(not_found(requested, &runnable, reference))
    }

    /// Validates the platform of a single-manifest image (no index to choose
    /// from): it must be the one [`select`](Self::select) would have chosen.
    pub fn validate(&self, actual: &Platform, reference: &str) -> Result<(), ImageError> {
        self.select(std::slice::from_ref(actual), reference)
            .map(|_| ())
    }
}

/// Builds the typed "no matching platform" error, listing what was there.
fn not_found(requested: String, runnable: &[&Platform], reference: &str) -> ImageError {
    ImageError::PlatformNotFound {
        requested,
        reference: reference.to_owned(),
        available: runnable.iter().map(ToString::to_string).collect(),
    }
}

/// Finds the entry matching `wanted` os/arch.
///
/// Variant is used only to disambiguate: if `wanted` names one, an exact
/// variant match is required among multiple candidates (a lone candidate of
/// the right os/arch is accepted regardless — registries are sloppy about
/// variants). If `wanted` has no variant and several candidates differ only
/// by variant, the entry without a variant wins, else the first listed.
fn pick<'a>(available: &[&'a Platform], wanted: &Platform) -> Option<&'a Platform> {
    let candidates: Vec<&Platform> = available
        .iter()
        .filter(|p| p.os == wanted.os && p.architecture == wanted.architecture)
        .copied()
        .collect();
    match (candidates.as_slice(), &wanted.variant) {
        ([], _) => None,
        ([only], _) => Some(only),
        (many, Some(variant)) => many
            .iter()
            .find(|p| p.variant.as_deref() == Some(variant))
            .copied(),
        (many, None) => Some(
            many.iter()
                .find(|p| p.variant.is_none())
                .copied()
                .unwrap_or(many[0]),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn freebsd_policy(linux_emulation: bool) -> PlatformPolicy {
        PlatformPolicy {
            host_os: "freebsd".to_owned(),
            host_arch: "amd64".to_owned(),
            linux_emulation,
            explicit: None,
        }
    }

    fn platforms(specs: &[&str]) -> Vec<Platform> {
        specs.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn prefers_native_freebsd() {
        let available = platforms(&["linux/amd64", "freebsd/amd64", "freebsd/arm64"]);
        let chosen = freebsd_policy(true).select(&available, "img").unwrap();
        assert_eq!(chosen.to_string(), "freebsd/amd64");
    }

    #[test]
    fn falls_back_to_linux_amd64_with_emulation() {
        let available = platforms(&["linux/amd64", "linux/arm64/v8"]);
        let chosen = freebsd_policy(true).select(&available, "img").unwrap();
        assert_eq!(chosen.to_string(), "linux/amd64");
    }

    #[test]
    fn no_emulation_means_typed_error_listing_platforms() {
        let available = platforms(&["linux/amd64", "linux/arm64/v8"]);
        let err = freebsd_policy(false).select(&available, "img").unwrap_err();
        let ImageError::PlatformNotFound {
            requested,
            available,
            ..
        } = err
        else {
            panic!("expected PlatformNotFound, got {err}");
        };
        assert_eq!(requested, "freebsd/amd64");
        assert_eq!(available, ["linux/amd64", "linux/arm64/v8"]);
    }

    #[test]
    fn emulation_without_linux_amd64_still_errors() {
        let available = platforms(&["linux/arm64/v8", "linux/s390x"]);
        let err = freebsd_policy(true).select(&available, "img").unwrap_err();
        let ImageError::PlatformNotFound { requested, .. } = err else {
            panic!("expected PlatformNotFound, got {err}");
        };
        assert!(requested.contains("freebsd/amd64"), "{requested}");
        assert!(requested.contains("linux/amd64"), "{requested}");
    }

    #[test]
    fn explicit_platform_wins_over_native() {
        let available = platforms(&["freebsd/amd64", "linux/amd64"]);
        let mut policy = freebsd_policy(true);
        policy.explicit = Some("linux/amd64".parse().unwrap());
        let chosen = policy.select(&available, "img").unwrap();
        assert_eq!(chosen.to_string(), "linux/amd64");
    }

    #[test]
    fn explicit_platform_missing_lists_available() {
        let available = platforms(&["linux/amd64"]);
        let mut policy = freebsd_policy(true);
        policy.explicit = Some("freebsd/arm64".parse().unwrap());
        let err = policy.select(&available, "img").unwrap_err();
        let ImageError::PlatformNotFound {
            requested,
            available,
            ..
        } = err
        else {
            panic!("expected PlatformNotFound, got {err}");
        };
        assert_eq!(requested, "freebsd/arm64");
        assert_eq!(available, ["linux/amd64"]);
    }

    #[test]
    fn explicit_variant_disambiguates() {
        let available = platforms(&["linux/arm/v6", "linux/arm/v7"]);
        let mut policy = freebsd_policy(true);
        policy.explicit = Some("linux/arm/v7".parse().unwrap());
        let chosen = policy.select(&available, "img").unwrap();
        assert_eq!(chosen.variant.as_deref(), Some("v7"));
    }

    #[test]
    fn missing_variant_among_many_prefers_unversioned_then_first() {
        let available = platforms(&["linux/arm/v6", "linux/arm/v7"]);
        let mut policy = freebsd_policy(true);
        policy.explicit = Some("linux/arm".parse().unwrap());
        let chosen = policy.select(&available, "img").unwrap();
        assert_eq!(chosen.to_string(), "linux/arm/v6", "first listed wins");
    }

    #[test]
    fn variant_ignored_when_single_candidate() {
        // arm64/v8 is the only arm64 entry; asking for bare linux/arm64
        // (or arm64/v8 when the index says bare arm64) must both work.
        let available = platforms(&["linux/arm64/v8"]);
        let mut policy = freebsd_policy(true);
        policy.explicit = Some("linux/arm64".parse().unwrap());
        assert!(policy.select(&available, "img").is_ok());

        let available = platforms(&["linux/arm64"]);
        policy.explicit = Some("linux/arm64/v8".parse().unwrap());
        assert!(policy.select(&available, "img").is_ok());
    }

    #[test]
    fn attestation_entries_are_ignored() {
        let mut available = platforms(&["linux/amd64"]);
        available.push(Platform::new("unknown", "unknown"));
        let chosen = freebsd_policy(true).select(&available, "img").unwrap();
        assert_eq!(chosen.to_string(), "linux/amd64");

        // And they never appear in the "available" error listing.
        let err = freebsd_policy(false).select(&available, "img").unwrap_err();
        let ImageError::PlatformNotFound { available, .. } = err else {
            panic!("expected PlatformNotFound");
        };
        assert_eq!(available, ["linux/amd64"]);
    }

    #[test]
    fn validate_single_manifest_platform() {
        let policy = freebsd_policy(true);
        assert!(
            policy
                .validate(&Platform::new("freebsd", "amd64"), "img")
                .is_ok()
        );
        assert!(
            policy
                .validate(&Platform::new("linux", "amd64"), "img")
                .is_ok()
        );
        assert!(
            policy
                .validate(&Platform::new("linux", "arm64"), "img")
                .is_err()
        );
        let strict = freebsd_policy(false);
        assert!(
            strict
                .validate(&Platform::new("linux", "amd64"), "img")
                .is_err()
        );
    }

    #[test]
    fn os_version_is_recorded_not_matched() {
        let with_version: Platform =
            serde_json::from_str(r#"{"os":"freebsd","architecture":"amd64","os.version":"15.1"}"#)
                .unwrap();
        assert_eq!(with_version.os_version.as_deref(), Some("15.1"));
        let available = vec![with_version];
        assert!(freebsd_policy(false).select(&available, "img").is_ok());
    }

    #[test]
    fn platform_parse_and_display() {
        let p: Platform = "linux/arm/v7".parse().unwrap();
        assert_eq!(p.to_string(), "linux/arm/v7");
        assert!("".parse::<Platform>().is_err());
        assert!("linux".parse::<Platform>().is_err());
        assert!("a/b/c/d".parse::<Platform>().is_err());
    }
}
