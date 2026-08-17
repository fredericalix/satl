// SPDX-License-Identifier: BSD-2-Clause
//! Pure OCI `config.json` generation for the ocijail runtime.
//!
//! The emitted document contains **exactly** the fields ocijail 0.6.0
//! consumes (docs/ocijail.md §2.1) and nothing else: `ociVersion`, `process`
//! (terminal/user/args/env/cwd), `root.path|readonly`, `mounts`, `hostname`,
//! `annotations`. There is no `linux` section, no `os`/`platform` field and
//! no `freebsd` section — all FreeBSD knobs are annotations (§2.2), and the
//! only one SatL sets from the bundle spec is `org.freebsd.jail.vnet=new`.
//!
//! Platform handling (docs/linuxulator.md): for `linux/*` images the
//! emulation mount set is added automatically (linprocfs `/proc`, linsysfs
//! `/sys`, devfs `/dev` with SatL's ruleset, fdescfs `linrdlnk` `/dev/fd`,
//! tmpfs `/dev/shm` + `/tmp`); for FreeBSD images: devfs `/dev` (SatL
//! ruleset), fdescfs `/dev/fd`, tmpfs `/tmp`. Platform mounts come first —
//! `/dev` must be mounted before `/dev/fd` and `/dev/shm` — then the caller's
//! mounts (binds, volumes, secret tmpfs) in the given order.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::devfs::SATL_DEVFS_RULESET;

/// `ociVersion` SatL emits. ocijail accepts 1.0.x–1.3.x (docs/ocijail.md
/// §2.1); the runtime itself reports 1.0.2 in `state`, so we claim the same.
pub const OCI_VERSION: &str = "1.0.2";

/// Annotation requesting an isolated network stack (docs/ocijail.md §2.2).
pub const ANNOTATION_VNET: &str = "org.freebsd.jail.vnet";

/// Annotation carrying the jail's jid in `ocijail state` output.
pub const ANNOTATION_JID: &str = "org.freebsd.jail.jid";

/// Resolved image platform, reduced to what the executor branches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImagePlatform {
    /// Native FreeBSD image.
    Freebsd,
    /// Linux image, run under the linuxulator (docs/linuxulator.md).
    Linux,
}

impl ImagePlatform {
    /// Map a resolved [`satl_core::Platform`] to the runtime branch;
    /// `None` for OSes SatL cannot run.
    #[must_use]
    pub fn from_core(platform: &satl_core::Platform) -> Option<Self> {
        match platform.os.as_str() {
            "freebsd" => Some(Self::Freebsd),
            "linux" => Some(Self::Linux),
            _ => None,
        }
    }
}

/// `process.user` — uid/gid are required numbers when the object is present
/// (docs/ocijail.md §2.1). `umask` is deliberately absent: ocijail parses but
/// never applies it (dead code, always 077).
///
/// Deserializable because a healthcheck probe is an `ocijail exec` that must
/// run as the container's own user, and the truth about that is the
/// `config.json` the bundle was created with (`satl_agent::health`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailUser {
    /// Numeric uid inside the jail.
    pub uid: u32,
    /// Numeric gid inside the jail.
    pub gid: u32,
    /// Supplementary groups.
    #[serde(rename = "additionalGids", skip_serializing_if = "Vec::is_empty")]
    pub additional_gids: Vec<u32>,
}

/// Filesystem types SatL mounts into jails. Everything goes through
/// nmount(2) from the host at `create` time (docs/ocijail.md §2.3), so
/// in-jail `allow.mount.*` being off is irrelevant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountFstype {
    /// Bind mount (`"bind"` is an ocijail alias for nullfs).
    Nullfs,
    /// In-memory filesystem (secrets tmpfs, `/tmp`, `/dev/shm`).
    Tmpfs,
    /// Device filesystem; visibility controlled by the `ruleset=N` mount
    /// option, not the `devfs_ruleset` jail parameter (docs/ocijail.md §7.11).
    Devfs,
    /// Linux `/proc` emulation.
    Linprocfs,
    /// Linux `/sys` emulation.
    Linsysfs,
    /// `/dev/fd`; mounted with `linrdlnk` for Linux jails.
    Fdescfs,
}

impl MountFstype {
    /// The `type` string in `config.json`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nullfs => "nullfs",
            Self::Tmpfs => "tmpfs",
            Self::Devfs => "devfs",
            Self::Linprocfs => "linprocfs",
            Self::Linsysfs => "linsysfs",
            Self::Fdescfs => "fdescfs",
        }
    }
}

/// One mount in the bundle spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleMount {
    /// Filesystem type.
    pub fstype: MountFstype,
    /// nullfs: host source path; pseudo filesystems: conventional token
    /// (`"devfs"`, `"tmpfs"`, ...).
    pub source: String,
    /// Absolute path inside the container.
    pub target: String,
    /// Mount options, passed through to nmount(2) (e.g. `ro`, `size=1m`,
    /// `mode=1777`, `ruleset=N`, `linrdlnk`).
    pub options: Vec<String>,
}

/// Everything needed to render a container's `config.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSpec {
    /// Absolute path of the container rootfs (the ZFS clone mountpoint).
    pub rootfs: PathBuf,
    /// Remount the rootfs read-only (`root.readonly`).
    pub readonly_rootfs: bool,
    /// Entrypoint argv; must be non-empty (ocijail rejects empty args).
    pub args: Vec<String>,
    /// Environment as `K=V` strings.
    pub env: Vec<String>,
    /// Working directory inside the jail (`process.cwd` is required).
    pub cwd: String,
    /// Run as this user; `None` means uid 0 / gid 0.
    pub user: Option<JailUser>,
    /// Jail hostname; `None` inherits the host's (`host=inherit`).
    pub hostname: Option<String>,
    /// Allocate a pty (`process.terminal`); requires a console socket at
    /// create time.
    pub terminal: bool,
    /// Resolved image platform; drives the automatic mount set.
    pub platform: ImagePlatform,
    /// Caller mounts (binds, volumes, secrets tmpfs), appended after the
    /// platform mount set in the given order.
    pub mounts: Vec<BundleMount>,
    /// Isolated network stack (`org.freebsd.jail.vnet=new`); `false` shares
    /// the host stack (`inherit`, the kernel default).
    pub vnet: bool,
    /// Additional `org.freebsd.jail.*` annotations (allow-params, sysvipc,
    /// parentJail — docs/ocijail.md §2.2). Values must be strings; a vnet
    /// key here is overridden by [`BundleSpec::vnet`].
    pub extra_jail_annotations: BTreeMap<String, String>,
}

/// `process` object — shared verbatim between `config.json` and the
/// `--process` file of `ocijail exec` (docs/ocijail.md §4.1).
///
/// Deserializable for the healthcheck prober, which reads the container's own
/// `config.json` back to inherit its env, cwd and user (see [`JailUser`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSpec {
    /// Allocate a pty.
    #[serde(default)]
    pub terminal: bool,
    /// Run as this user; `None` means uid 0 / gid 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<JailUser>,
    /// argv; non-empty.
    pub args: Vec<String>,
    /// Environment as `K=V` strings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Working directory (required by ocijail).
    pub cwd: String,
}

/// `root` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OciRoot {
    /// Absolute rootfs path.
    pub path: PathBuf,
    /// Read-only remount; omitted when false (the ocijail default).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub readonly: bool,
}

/// One `mounts[]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OciMount {
    /// Absolute path inside the container.
    pub destination: String,
    /// Filesystem type.
    #[serde(rename = "type")]
    pub fstype: &'static str,
    /// Source path or pseudo-fs token.
    pub source: String,
    /// nmount(2) options; omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

/// The rendered `config.json` document. Contains only fields ocijail
/// consumes — serializing this type is the whole generation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OciConfig {
    /// Always [`OCI_VERSION`].
    #[serde(rename = "ociVersion")]
    pub oci_version: &'static str,
    /// The container process.
    pub process: ProcessSpec,
    /// Rootfs.
    pub root: OciRoot,
    /// Jail hostname (`host=new`); omitted ⇒ `host=inherit`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Mounts, performed host-side at create time, in order.
    pub mounts: Vec<OciMount>,
    /// FreeBSD extension annotations; omitted when empty.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// The automatic platform mount set (see module docs). Ordering matters:
/// `/dev` before `/dev/fd` and `/dev/shm`.
#[must_use]
pub fn platform_mounts(platform: ImagePlatform) -> Vec<BundleMount> {
    let ruleset_opt = format!("ruleset={SATL_DEVFS_RULESET}");
    let mode1777 = "mode=1777".to_owned();
    match platform {
        ImagePlatform::Freebsd => vec![
            BundleMount {
                fstype: MountFstype::Devfs,
                source: "devfs".to_owned(),
                target: "/dev".to_owned(),
                options: vec![ruleset_opt],
            },
            BundleMount {
                fstype: MountFstype::Fdescfs,
                source: "fdescfs".to_owned(),
                target: "/dev/fd".to_owned(),
                options: Vec::new(),
            },
            BundleMount {
                fstype: MountFstype::Tmpfs,
                source: "tmpfs".to_owned(),
                target: "/tmp".to_owned(),
                options: vec![mode1777],
            },
        ],
        ImagePlatform::Linux => vec![
            BundleMount {
                fstype: MountFstype::Linprocfs,
                source: "linprocfs".to_owned(),
                target: "/proc".to_owned(),
                options: Vec::new(),
            },
            BundleMount {
                fstype: MountFstype::Linsysfs,
                source: "linsysfs".to_owned(),
                target: "/sys".to_owned(),
                options: Vec::new(),
            },
            BundleMount {
                fstype: MountFstype::Devfs,
                source: "devfs".to_owned(),
                target: "/dev".to_owned(),
                options: vec![ruleset_opt],
            },
            BundleMount {
                fstype: MountFstype::Fdescfs,
                source: "fdescfs".to_owned(),
                target: "/dev/fd".to_owned(),
                options: vec!["linrdlnk".to_owned()],
            },
            BundleMount {
                fstype: MountFstype::Tmpfs,
                source: "tmpfs".to_owned(),
                target: "/dev/shm".to_owned(),
                options: vec![mode1777.clone()],
            },
            BundleMount {
                fstype: MountFstype::Tmpfs,
                source: "tmpfs".to_owned(),
                target: "/tmp".to_owned(),
                options: vec![mode1777],
            },
        ],
    }
}

/// Render the `config.json` document for `spec`. Pure; no I/O.
#[must_use]
pub fn build_config(spec: &BundleSpec) -> OciConfig {
    let mounts = platform_mounts(spec.platform)
        .into_iter()
        .chain(spec.mounts.iter().cloned())
        .map(|mount| OciMount {
            destination: mount.target,
            fstype: mount.fstype.as_str(),
            source: mount.source,
            options: mount.options,
        })
        .collect();

    let mut annotations = spec.extra_jail_annotations.clone();
    if spec.vnet {
        annotations.insert(ANNOTATION_VNET.to_owned(), "new".to_owned());
    }

    OciConfig {
        oci_version: OCI_VERSION,
        process: ProcessSpec {
            terminal: spec.terminal,
            user: spec.user.clone(),
            args: spec.args.clone(),
            env: spec.env.clone(),
            cwd: spec.cwd.clone(),
        },
        root: OciRoot {
            path: spec.rootfs.clone(),
            readonly: spec.readonly_rootfs,
        },
        hostname: spec.hostname.clone(),
        mounts,
        annotations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn base_spec() -> BundleSpec {
        BundleSpec {
            rootfs: PathBuf::from("/var/db/satl/containers/task1"),
            readonly_rootfs: false,
            args: vec!["/bin/sh".to_owned(), "-c".to_owned(), "sleep 1".to_owned()],
            env: vec!["PATH=/bin".to_owned()],
            cwd: "/".to_owned(),
            user: None,
            hostname: None,
            terminal: false,
            platform: ImagePlatform::Freebsd,
            mounts: Vec::new(),
            vnet: false,
            extra_jail_annotations: BTreeMap::new(),
        }
    }

    fn render(spec: &BundleSpec) -> Value {
        serde_json::to_value(build_config(spec)).unwrap()
    }

    /// Fields ocijail 0.6.0 consumes (docs/ocijail.md §2.1). Nothing outside
    /// this set may ever be emitted.
    const CONSUMED_TOP_LEVEL: &[&str] = &[
        "ociVersion",
        "process",
        "root",
        "hostname",
        "mounts",
        "annotations",
        "hooks",
    ];

    fn assert_only_consumed_fields(value: &Value) {
        let object = value.as_object().unwrap();
        for key in object.keys() {
            assert!(
                CONSUMED_TOP_LEVEL.contains(&key.as_str()),
                "config.json emitted a field ocijail ignores: {key}"
            );
        }
        // The big ones by name, so a regression is unmistakable.
        assert!(object.get("linux").is_none());
        assert!(object.get("os").is_none());
        assert!(object.get("platform").is_none());
        assert!(object.get("freebsd").is_none());
        let process = object.get("process").unwrap().as_object().unwrap();
        for key in ["capabilities", "rlimits", "noNewPrivileges", "oomScoreAdj"] {
            assert!(process.get(key).is_none(), "ignored process field: {key}");
        }
    }

    #[test]
    fn golden_freebsd_minimal() {
        let value = render(&base_spec());
        assert_eq!(
            value,
            json!({
                "ociVersion": "1.0.2",
                "process": {
                    "terminal": false,
                    "args": ["/bin/sh", "-c", "sleep 1"],
                    "env": ["PATH=/bin"],
                    "cwd": "/"
                },
                "root": {"path": "/var/db/satl/containers/task1"},
                "mounts": [
                    {"destination": "/dev", "type": "devfs", "source": "devfs",
                     "options": ["ruleset=5000"]},
                    {"destination": "/dev/fd", "type": "fdescfs", "source": "fdescfs"},
                    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
                     "options": ["mode=1777"]}
                ]
            })
        );
        assert_only_consumed_fields(&value);
    }

    #[test]
    fn golden_linux_full_emulation_mounts() {
        let mut spec = base_spec();
        spec.platform = ImagePlatform::Linux;
        spec.hostname = Some("web-1".to_owned());
        spec.user = Some(JailUser {
            uid: 1000,
            gid: 1000,
            additional_gids: vec![10, 20],
        });
        let value = render(&spec);
        assert_eq!(
            value,
            json!({
                "ociVersion": "1.0.2",
                "process": {
                    "terminal": false,
                    "user": {"uid": 1000, "gid": 1000, "additionalGids": [10, 20]},
                    "args": ["/bin/sh", "-c", "sleep 1"],
                    "env": ["PATH=/bin"],
                    "cwd": "/"
                },
                "root": {"path": "/var/db/satl/containers/task1"},
                "hostname": "web-1",
                "mounts": [
                    {"destination": "/proc", "type": "linprocfs", "source": "linprocfs"},
                    {"destination": "/sys", "type": "linsysfs", "source": "linsysfs"},
                    {"destination": "/dev", "type": "devfs", "source": "devfs",
                     "options": ["ruleset=5000"]},
                    {"destination": "/dev/fd", "type": "fdescfs", "source": "fdescfs",
                     "options": ["linrdlnk"]},
                    {"destination": "/dev/shm", "type": "tmpfs", "source": "tmpfs",
                     "options": ["mode=1777"]},
                    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
                     "options": ["mode=1777"]}
                ]
            })
        );
        assert_only_consumed_fields(&value);
    }

    #[test]
    fn golden_vnet_annotation() {
        let mut spec = base_spec();
        spec.vnet = true;
        spec.extra_jail_annotations.insert(
            "org.freebsd.jail.allow.raw_sockets".to_owned(),
            "true".to_owned(),
        );
        // A conflicting vnet value in the extras is overridden by the flag.
        spec.extra_jail_annotations
            .insert(ANNOTATION_VNET.to_owned(), "inherit".to_owned());
        let value = render(&spec);
        assert_eq!(
            value.get("annotations").unwrap(),
            &json!({
                "org.freebsd.jail.allow.raw_sockets": "true",
                "org.freebsd.jail.vnet": "new"
            })
        );
        assert_only_consumed_fields(&value);
    }

    #[test]
    fn golden_bind_mounts_and_readonly_root() {
        let mut spec = base_spec();
        spec.readonly_rootfs = true;
        spec.mounts.push(BundleMount {
            fstype: MountFstype::Nullfs,
            source: "/var/db/satl/volumes/data".to_owned(),
            target: "/data".to_owned(),
            options: vec!["ro".to_owned()],
        });
        let value = render(&spec);
        assert_eq!(
            value.get("root").unwrap(),
            &json!({"path": "/var/db/satl/containers/task1", "readonly": true})
        );
        // Caller mounts come after the platform set, in order.
        let mounts = value.get("mounts").unwrap().as_array().unwrap();
        assert_eq!(
            mounts.last().unwrap(),
            &json!({"destination": "/data", "type": "nullfs",
                    "source": "/var/db/satl/volumes/data", "options": ["ro"]})
        );
        assert_only_consumed_fields(&value);
    }

    #[test]
    fn golden_tmpfs_secret_mount() {
        let mut spec = base_spec();
        // Invariant #7: secrets are delivered via tmpfs only.
        spec.mounts.push(BundleMount {
            fstype: MountFstype::Tmpfs,
            source: "tmpfs".to_owned(),
            target: "/run/secrets".to_owned(),
            options: vec!["size=1m".to_owned(), "mode=0700".to_owned()],
        });
        let value = render(&spec);
        let mounts = value.get("mounts").unwrap().as_array().unwrap();
        assert_eq!(
            mounts.last().unwrap(),
            &json!({"destination": "/run/secrets", "type": "tmpfs",
                    "source": "tmpfs", "options": ["size=1m", "mode=0700"]})
        );
        assert_only_consumed_fields(&value);
    }

    #[test]
    fn platform_from_core() {
        let fbsd = satl_core::Platform {
            os: "freebsd".to_owned(),
            arch: "amd64".to_owned(),
        };
        let linux = satl_core::Platform {
            os: "linux".to_owned(),
            arch: "amd64".to_owned(),
        };
        let windows = satl_core::Platform {
            os: "windows".to_owned(),
            arch: "amd64".to_owned(),
        };
        assert_eq!(
            ImagePlatform::from_core(&fbsd),
            Some(ImagePlatform::Freebsd)
        );
        assert_eq!(ImagePlatform::from_core(&linux), Some(ImagePlatform::Linux));
        assert_eq!(ImagePlatform::from_core(&windows), None);
    }
}
