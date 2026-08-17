// SPDX-License-Identifier: BSD-2-Clause
//! Pure bundle planning: turn a [`Task`]'s [`ContainerSpec`] plus the pulled
//! image's config into the [`BundleSpec`] `satl-runtime` renders as
//! `config.json`. No I/O — every rule here is a decision table, unit-tested
//! against Docker's documented semantics.
//!
//! # Entrypoint / command merge (Docker semantics)
//!
//! `ContainerSpec.command` is the **entrypoint** override and
//! `ContainerSpec.args` the **cmd** override (SWK §3.6: swarmkit maps
//! `Command → Entrypoint`, `Args → Cmd`). Docker's daemon-side merge
//! (`daemon.merge(userConf, imageConf)`) is:
//!
//! ```text
//! if user entrypoint is empty:
//!     if user cmd is empty: cmd = image cmd
//!     entrypoint = image entrypoint
//! argv = entrypoint ++ cmd
//! ```
//!
//! The load-bearing consequence: **overriding the entrypoint drops the
//! image's CMD** (`docker run --entrypoint /bin/ls ubuntu` runs `ls` with no
//! arguments, not `ls bash`). SatL reproduces that exactly.
//!
//! # Environment
//!
//! Image env first, spec env second, spec wins per `KEY` (the image's
//! position is kept so the rendered env is stable). Docker injects a default
//! `PATH` when neither side sets one; so do we — without it ocijail's
//! `args[0]` lookup cannot resolve a bare command name.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use satl_core::{ContainerSpec, FileTarget, Id, Mount, MountType, Task};
use satl_image::ImageConfig;
use satl_runtime::{BundleMount, BundleSpec, ImagePlatform, JailUser, MountFstype};

/// Where a task's secrets are materialized inside the jail — Docker's path
/// (`/run/secrets/<target>`), used for FreeBSD and Linux images alike:
/// ocijail creates missing mountpoint directories (docs/ocijail.md §2.3), and
/// Linux images usually symlink `/var/run` to `/run` anyway.
pub const SECRETS_TARGET_DIR: &str = "/run/secrets";

/// Subdirectory of the task's bundle directory holding config payload files
/// (the nullfs file-mount sources). Configs are not sensitive; writing them
/// under the bundle dir is allowed where a secret payload never may be
/// (invariant #7).
pub const CONFIGS_BUNDLE_SUBDIR: &str = "configs";

/// Slack added to the secrets tmpfs beyond the payload bytes: directory
/// entries, per-file rounding to page size, and room for the jail to replace
/// nothing (the tmpfs is sized to hold exactly what SatL wrote).
const SECRETS_TMPFS_SLACK: u64 = 64 * 1024;

/// Floor for the secrets tmpfs size.
const SECRETS_TMPFS_MIN: u64 = 128 * 1024;

/// Fallback `PATH` when neither the image config nor the spec sets one —
/// FreeBSD's default root path (Docker injects the Linux equivalent).
pub const DEFAULT_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// How many leading characters of the task ID become the default hostname
/// (Docker uses the container ID's first 12 hex digits).
pub const HOSTNAME_PREFIX_LEN: usize = 12;

/// A bundle could not be planned. Every variant is terminal: the task is
/// `REJECTED` with this text (architecture §8.2).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    /// Neither the spec nor the image config names anything to run.
    #[error(
        "task {task_id}: image {image} defines no entrypoint or command and the service spec \
         overrides neither: nothing to run"
    )]
    EmptyEntrypoint {
        /// The task being planned.
        task_id: String,
        /// The image reference.
        image: String,
    },

    /// `user`/`group` is a name, not a number. Resolving names means reading
    /// the image's `/etc/passwd`; deferred (see the crate docs).
    #[error(
        "task {task_id}: user {user:?} must be numeric (`uid` or `uid:gid`); resolving user \
         names from the image's /etc/passwd is not implemented yet"
    )]
    NonNumericUser {
        /// The task being planned.
        task_id: String,
        /// The offending user string.
        user: String,
    },

    /// The resolved image platform is not one SatL can run.
    #[error("task {task_id}: image platform {platform} is not runnable on FreeBSD")]
    UnsupportedPlatform {
        /// The task being planned.
        task_id: String,
        /// The platform from the image manifest/config.
        platform: String,
    },

    /// A mount target is not an absolute in-jail path.
    #[error("task {task_id}: mount target {target:?} must be an absolute path")]
    RelativeMountTarget {
        /// The task being planned.
        task_id: String,
        /// The offending target.
        target: String,
    },

    /// Two mounts claim the same target.
    #[error("task {task_id}: duplicate mount target {target:?}")]
    DuplicateMountTarget {
        /// The task being planned.
        task_id: String,
        /// The duplicated target.
        target: String,
    },

    /// A `bind`/`volume` mount has no source.
    #[error("task {task_id}: {kind} mount at {target:?} has no source")]
    MissingMountSource {
        /// The task being planned.
        task_id: String,
        /// Mount flavor (`bind` / `volume`).
        kind: &'static str,
        /// The mount target.
        target: String,
    },

    /// A named volume was not resolved to a host path before planning.
    #[error("task {task_id}: volume {name:?} was not created before bundle planning")]
    UnresolvedVolume {
        /// The task being planned.
        task_id: String,
        /// The volume name.
        name: String,
    },

    /// `tty: true` needs the console-socket handshake (docs/ocijail.md §3),
    /// which lands with interactive `satl run -t`.
    #[error(
        "task {task_id}: TTY allocation is not supported: the executor has no console socket handshake"
    )]
    TtyUnsupported {
        /// The task being planned.
        task_id: String,
    },

    /// A secret/config reference's file target is not materializable. The
    /// message names the object, never its payload (invariant #7).
    #[error("task {task_id}: {kind} {name}: target {target:?} {reason}")]
    BadFileTarget {
        /// The task being planned.
        task_id: String,
        /// `"secret"` or `"config"`.
        kind: &'static str,
        /// Name of the referenced secret/config.
        name: String,
        /// The offending target path.
        target: String,
        /// Why it was rejected (plain ASCII, payload-free).
        reason: &'static str,
    },

    /// A secret/config file target's uid/gid is not numeric. Resolving names
    /// would need the image's `/etc/passwd` (same wall as
    /// [`PlanError::NonNumericUser`]).
    #[error(
        "task {task_id}: {kind} {name}: owner {owner:?} must be numeric \
         (uid/gid names are not resolved from the image)"
    )]
    NonNumericFileOwner {
        /// The task being planned.
        task_id: String,
        /// `"secret"` or `"config"`.
        kind: &'static str,
        /// Name of the referenced secret/config.
        name: String,
        /// The offending uid/gid string.
        owner: String,
    },

    /// Two secrets (or two configs, or a config and a mount) resolve to the
    /// same in-jail path.
    #[error("task {task_id}: duplicate {kind} target {target:?}")]
    DuplicateDependencyTarget {
        /// The task being planned.
        task_id: String,
        /// `"secret"` or `"config"`.
        kind: &'static str,
        /// The duplicated in-jail path.
        target: String,
    },
}

/// The process half of a bundle: what `config.json`'s `process` object gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessPlan {
    /// Full argv (entrypoint ++ cmd).
    pub args: Vec<String>,
    /// Environment as `KEY=VALUE`, image first then spec overrides.
    pub env: Vec<String>,
    /// Working directory.
    pub cwd: String,
    /// Numeric user, when the spec or image asks for one.
    pub user: Option<JailUser>,
    /// Jail hostname.
    pub hostname: String,
}

/// Map an image-pipeline platform onto the runtime's branch.
///
/// # Errors
///
/// [`PlanError::UnsupportedPlatform`] for OSes SatL cannot run.
pub fn image_platform(
    task_id: &str,
    platform: &satl_image::Platform,
) -> Result<ImagePlatform, PlanError> {
    let core = satl_core::Platform {
        os: platform.os.clone(),
        arch: platform.architecture.clone(),
    };
    ImagePlatform::from_core(&core).ok_or_else(|| PlanError::UnsupportedPlatform {
        task_id: task_id.to_owned(),
        platform: platform.to_string(),
    })
}

/// Merge entrypoint/cmd per Docker semantics (see the module docs).
fn merge_argv(spec: &ContainerSpec, image: &ImageConfig) -> Vec<String> {
    if spec.command.is_empty() {
        let cmd = if spec.args.is_empty() {
            image.cmd.clone()
        } else {
            spec.args.clone()
        };
        let mut argv = image.entrypoint.clone();
        argv.extend(cmd);
        argv
    } else {
        // Overriding the entrypoint discards the image's CMD (Docker).
        let mut argv = spec.command.clone();
        argv.extend(spec.args.iter().cloned());
        argv
    }
}

/// The `KEY` part of a `KEY=VALUE` entry (the whole string when there is no
/// `=`, which is how Docker treats a bare name too).
fn env_key(entry: &str) -> &str {
    entry.split_once('=').map_or(entry, |(key, _)| key)
}

/// Image env first, spec env overriding per key in place (stable order).
fn merge_env(spec: &ContainerSpec, image: &ImageConfig) -> Vec<String> {
    let mut merged: Vec<String> = image.env.clone();
    for entry in &spec.env {
        let key = env_key(entry);
        if let Some(slot) = merged.iter_mut().find(|existing| env_key(existing) == key) {
            slot.clone_from(entry);
        } else {
            merged.push(entry.clone());
        }
    }
    if !merged.iter().any(|entry| env_key(entry) == "PATH") {
        merged.push(DEFAULT_PATH.to_owned());
    }
    merged
}

/// Parse `uid`, `uid:gid` (numeric only — see [`PlanError::NonNumericUser`]).
fn parse_user(task_id: &str, user: &str) -> Result<JailUser, PlanError> {
    let invalid = || PlanError::NonNumericUser {
        task_id: task_id.to_owned(),
        user: user.to_owned(),
    };
    let (uid, gid) = match user.split_once(':') {
        Some((uid, gid)) => (uid, Some(gid)),
        None => (user, None),
    };
    let uid: u32 = uid.parse().map_err(|_| invalid())?;
    let gid: u32 = match gid {
        Some(gid) => gid.parse().map_err(|_| invalid())?,
        None => uid,
    };
    Ok(JailUser {
        uid,
        gid,
        additional_gids: Vec::new(),
    })
}

/// Plan the process half of the bundle.
///
/// # Errors
///
/// See [`PlanError`].
pub fn plan_process(
    task_id: &str,
    spec: &ContainerSpec,
    image: &ImageConfig,
) -> Result<ProcessPlan, PlanError> {
    if spec.tty {
        return Err(PlanError::TtyUnsupported {
            task_id: task_id.to_owned(),
        });
    }
    let args = merge_argv(spec, image);
    if args.is_empty() {
        return Err(PlanError::EmptyEntrypoint {
            task_id: task_id.to_owned(),
            image: spec.image.clone(),
        });
    }
    let cwd = spec
        .dir
        .clone()
        .or_else(|| image.working_dir.clone())
        .filter(|dir| !dir.is_empty())
        .unwrap_or_else(|| "/".to_owned());
    let user = spec
        .user
        .clone()
        .or_else(|| image.user.clone())
        .filter(|user| !user.is_empty())
        .map(|user| parse_user(task_id, &user))
        .transpose()?;
    let hostname = spec.hostname.clone().unwrap_or_else(|| {
        task_id
            .chars()
            .take(HOSTNAME_PREFIX_LEN)
            .collect::<String>()
    });
    Ok(ProcessPlan {
        args,
        env: merge_env(spec, image),
        cwd,
        user,
        hostname,
    })
}

/// Plan the caller-supplied mounts (the platform mount set is added by
/// `satl-runtime`'s spec generator, which puts it first).
///
/// `volumes` maps each named volume to the host mountpoint the volume store
/// created for it.
///
/// # Errors
///
/// See [`PlanError`].
pub fn plan_mounts(
    task_id: &str,
    mounts: &[Mount],
    volumes: &BTreeMap<String, PathBuf>,
) -> Result<Vec<BundleMount>, PlanError> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut planned = Vec::with_capacity(mounts.len());
    for mount in mounts {
        if !Path::new(&mount.target).is_absolute() {
            return Err(PlanError::RelativeMountTarget {
                task_id: task_id.to_owned(),
                target: mount.target.clone(),
            });
        }
        if !seen.insert(mount.target.as_str()) {
            return Err(PlanError::DuplicateMountTarget {
                task_id: task_id.to_owned(),
                target: mount.target.clone(),
            });
        }
        let missing_source = |kind: &'static str| PlanError::MissingMountSource {
            task_id: task_id.to_owned(),
            kind,
            target: mount.target.clone(),
        };
        let (fstype, source, mut options) = match mount.kind {
            MountType::Bind => {
                let source = mount.source.clone().ok_or_else(|| missing_source("bind"))?;
                (MountFstype::Nullfs, source, Vec::new())
            }
            MountType::Volume => {
                let name = mount
                    .source
                    .clone()
                    .ok_or_else(|| missing_source("volume"))?;
                let host = volumes
                    .get(&name)
                    .ok_or_else(|| PlanError::UnresolvedVolume {
                        task_id: task_id.to_owned(),
                        name: name.clone(),
                    })?;
                (MountFstype::Nullfs, host.display().to_string(), Vec::new())
            }
            MountType::Tmpfs => (
                MountFstype::Tmpfs,
                "tmpfs".to_owned(),
                vec!["mode=1777".to_owned()],
            ),
        };
        if mount.read_only {
            options.push("ro".to_owned());
        }
        planned.push(BundleMount {
            fstype,
            source,
            target: mount.target.clone(),
            options,
        });
    }
    Ok(planned)
}

/// One secret/config payload file to write, with ownership and mode.
///
/// Deliberately carries **no payload bytes**: the controller zips these
/// (spec order is preserved) with the payloads it resolved from the
/// dependency store, so a `Debug`-formatted plan can never leak a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadFile {
    /// ID of the referenced secret/config.
    pub id: Id,
    /// Name of the referenced secret/config (for errors and logs).
    pub name: String,
    /// Absolute **host** path to write the payload to.
    pub path: PathBuf,
    /// Owning uid.
    pub uid: u32,
    /// Owning gid.
    pub gid: u32,
    /// Permission bits.
    pub mode: u32,
}

/// The materialization half of a bundle: which files to write where, and the
/// mounts that carry them into the jail (architecture §12.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyPlan {
    /// Secret payload files, under `<rootfs>/run/secrets`. Written **after**
    /// `ocijail create` (the tmpfs must be mounted first) and before start.
    /// Same order as `ContainerSpec::secrets`.
    pub secret_files: Vec<PayloadFile>,
    /// Config payload files, under the bundle dir. Written **before**
    /// `ocijail create` (they are the nullfs mount sources). Same order as
    /// `ContainerSpec::configs`.
    pub config_files: Vec<PayloadFile>,
    /// The secrets tmpfs (at most one) followed by one read-only nullfs
    /// file-mount per config, appended after the caller mounts.
    pub mounts: Vec<BundleMount>,
}

/// Size of the secrets tmpfs for `payload_total` bytes of secrets: the
/// payloads plus fixed slack, floored (invariant #7 wants the mount tight —
/// it is not a scratch filesystem).
#[must_use]
pub fn secrets_tmpfs_size(payload_total: u64) -> u64 {
    (payload_total + SECRETS_TMPFS_SLACK).max(SECRETS_TMPFS_MIN)
}

/// Parse a [`FileTarget`]'s uid/gid (numeric only; empty means 0, which is
/// what Docker sends as the default).
fn parse_file_owner(
    task_id: &str,
    kind: &'static str,
    name: &str,
    owner: &str,
) -> Result<u32, PlanError> {
    if owner.is_empty() {
        return Ok(0);
    }
    owner.parse().map_err(|_| PlanError::NonNumericFileOwner {
        task_id: task_id.to_owned(),
        kind,
        name: name.to_owned(),
        owner: owner.to_owned(),
    })
}

/// Validate a secret target: relative, non-empty, no `..`/`.`; returns the
/// path under [`SECRETS_TARGET_DIR`]. Relative-only is a documented deviation
/// (`docs/api-compat.md`): Docker allows absolute secret targets, SatL mounts
/// one tmpfs and keeps every secret on it.
fn secret_relative_target(
    task_id: &str,
    name: &str,
    file: &FileTarget,
) -> Result<PathBuf, PlanError> {
    let reject = |reason: &'static str| PlanError::BadFileTarget {
        task_id: task_id.to_owned(),
        kind: "secret",
        name: name.to_owned(),
        target: file.name.clone(),
        reason,
    };
    if file.name.is_empty() {
        return Err(reject("must not be empty"));
    }
    let path = Path::new(&file.name);
    if path.is_absolute() {
        return Err(reject(
            "must be a relative path; secrets are materialized under /run/secrets",
        ));
    }
    if !path.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(reject("must not contain . or .. components"));
    }
    Ok(path.to_path_buf())
}

/// Validate a config target and return the absolute in-jail path. A relative
/// target is rooted at `/`, as Docker does for configs.
fn config_absolute_target(
    task_id: &str,
    name: &str,
    file: &FileTarget,
) -> Result<String, PlanError> {
    let reject = |reason: &'static str| PlanError::BadFileTarget {
        task_id: task_id.to_owned(),
        kind: "config",
        name: name.to_owned(),
        target: file.name.clone(),
        reason,
    };
    if file.name.is_empty() {
        return Err(reject("must not be empty"));
    }
    let path = Path::new(&file.name);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new("/").join(path)
    };
    if !absolute
        .components()
        .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(reject("must not contain . or .. components"));
    }
    Ok(absolute.display().to_string())
}

/// Plan the materialization of a task's secrets and configs.
///
/// `rootfs` is the container's ZFS clone mountpoint, `bundle_dir` the task's
/// OCI bundle directory, `secrets_payload_total` the summed byte length of
/// the referenced secrets' payloads (resolved by the controller from the
/// dependency store — this function never sees payload bytes).
///
/// # Errors
///
/// See [`PlanError`].
pub fn plan_dependencies(
    task_id: &str,
    spec: &ContainerSpec,
    rootfs: &Path,
    bundle_dir: &Path,
    secrets_payload_total: u64,
) -> Result<DependencyPlan, PlanError> {
    let mut plan = DependencyPlan::default();
    let mut secret_targets: BTreeSet<PathBuf> = BTreeSet::new();
    // The tmpfs mountpoint inside the rootfs, as a host path.
    let secrets_host_dir = rootfs.join(&SECRETS_TARGET_DIR[1..]);
    for reference in &spec.secrets {
        let name = &reference.secret_name;
        let relative = secret_relative_target(task_id, name, &reference.file)?;
        if !secret_targets.insert(relative.clone()) {
            return Err(PlanError::DuplicateDependencyTarget {
                task_id: task_id.to_owned(),
                kind: "secret",
                target: reference.file.name.clone(),
            });
        }
        plan.secret_files.push(PayloadFile {
            id: reference.secret_id.clone(),
            name: name.clone(),
            path: secrets_host_dir.join(relative),
            uid: parse_file_owner(task_id, "secret", name, &reference.file.uid)?,
            gid: parse_file_owner(task_id, "secret", name, &reference.file.gid)?,
            mode: reference.file.mode,
        });
    }
    if !spec.secrets.is_empty() {
        plan.mounts.push(BundleMount {
            fstype: MountFstype::Tmpfs,
            source: "tmpfs".to_owned(),
            target: SECRETS_TARGET_DIR.to_owned(),
            options: vec![
                format!("size={}", secrets_tmpfs_size(secrets_payload_total)),
                "mode=0755".to_owned(),
            ],
        });
    }

    let mut config_targets: BTreeSet<String> = BTreeSet::new();
    for (index, reference) in spec.configs.iter().enumerate() {
        let name = &reference.config_name;
        let target = config_absolute_target(task_id, name, &reference.file)?;
        if !config_targets.insert(target.clone()) {
            return Err(PlanError::DuplicateDependencyTarget {
                task_id: task_id.to_owned(),
                kind: "config",
                target,
            });
        }
        let source = bundle_dir
            .join(CONFIGS_BUNDLE_SUBDIR)
            .join(index.to_string());
        plan.config_files.push(PayloadFile {
            id: reference.config_id.clone(),
            name: name.clone(),
            path: source.clone(),
            uid: parse_file_owner(task_id, "config", name, &reference.file.uid)?,
            gid: parse_file_owner(task_id, "config", name, &reference.file.gid)?,
            mode: reference.file.mode,
        });
        // A read-only nullfs file-mount: ocijail supports regular-file
        // sources with a copy fallback (docs/ocijail.md §2.3), and nullfs
        // preserves the source's uid/gid/mode.
        plan.mounts.push(BundleMount {
            fstype: MountFstype::Nullfs,
            source: source.display().to_string(),
            target,
            options: vec!["ro".to_owned()],
        });
    }
    Ok(plan)
}

/// Plan the whole bundle for `task`.
///
/// `rootfs` is the container's ZFS clone mountpoint; `volumes` maps named
/// volumes to their host paths (created by the controller before planning).
///
/// # Errors
///
/// See [`PlanError`].
pub fn plan_bundle(
    task: &Task,
    image: &satl_image::PulledImage,
    rootfs: PathBuf,
    volumes: &BTreeMap<String, PathBuf>,
    dependencies: &DependencyPlan,
) -> Result<BundleSpec, PlanError> {
    let task_id = task.id.as_str();
    let spec = &task.spec.container;
    let platform = image_platform(task_id, &image.platform)?;
    let process = plan_process(task_id, spec, &image.config)?;
    let mut mounts = plan_mounts(task_id, &spec.mounts, volumes)?;
    // Dependency mounts come after the caller's, and may not collide with
    // them (a user tmpfs at /run/secrets would shadow or be shadowed).
    for mount in &dependencies.mounts {
        if mounts
            .iter()
            .any(|existing| existing.target == mount.target)
        {
            return Err(PlanError::DuplicateMountTarget {
                task_id: task_id.to_owned(),
                target: mount.target.clone(),
            });
        }
        mounts.push(mount.clone());
    }
    Ok(BundleSpec {
        rootfs,
        readonly_rootfs: spec.read_only,
        args: process.args,
        env: process.env,
        cwd: process.cwd,
        user: process.user,
        hostname: Some(process.hostname),
        terminal: false,
        platform,
        mounts,
        // Architecture §11.1: one VNET jail per task, epair plumbed by
        // satl-net after create.
        vnet: true,
        extra_jail_annotations: satl_core::defaults::jail_annotations(&spec.labels),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{container_spec, image_config};

    const TASK: &str = "1hvy0lj3x0b883f8e30fyp217";

    fn plan(spec: &ContainerSpec, image: &ImageConfig) -> ProcessPlan {
        plan_process(TASK, spec, image).unwrap()
    }

    // ---- entrypoint / cmd matrix (Docker semantics) ------------------------

    #[test]
    fn image_entrypoint_and_cmd_when_the_spec_overrides_nothing() {
        let image = image_config(&["/docker-entrypoint.sh"], &["nginx", "-g", "daemon off;"]);
        assert_eq!(
            plan(&container_spec(), &image).args,
            ["/docker-entrypoint.sh", "nginx", "-g", "daemon off;"]
        );
    }

    #[test]
    fn spec_args_replace_the_image_cmd_keeping_the_entrypoint() {
        let image = image_config(&["/docker-entrypoint.sh"], &["nginx"]);
        let mut spec = container_spec();
        spec.args = vec!["httpd".to_owned(), "-f".to_owned()];
        assert_eq!(
            plan(&spec, &image).args,
            ["/docker-entrypoint.sh", "httpd", "-f"]
        );
    }

    /// The load-bearing Docker rule: `--entrypoint` clears the image CMD.
    #[test]
    fn spec_command_replaces_the_entrypoint_and_drops_the_image_cmd() {
        let image = image_config(&["/docker-entrypoint.sh"], &["nginx", "-g", "daemon off;"]);
        let mut spec = container_spec();
        spec.command = vec!["/bin/ls".to_owned()];
        assert_eq!(plan(&spec, &image).args, ["/bin/ls"]);
    }

    #[test]
    fn spec_command_and_args_compose_without_the_image() {
        let image = image_config(&["/docker-entrypoint.sh"], &["nginx"]);
        let mut spec = container_spec();
        spec.command = vec!["/bin/sh".to_owned()];
        spec.args = vec!["-c".to_owned(), "sleep 1".to_owned()];
        assert_eq!(plan(&spec, &image).args, ["/bin/sh", "-c", "sleep 1"]);
    }

    #[test]
    fn image_cmd_alone_is_the_argv_when_there_is_no_entrypoint() {
        let image = image_config(&[], &["/bin/sh"]);
        assert_eq!(plan(&container_spec(), &image).args, ["/bin/sh"]);
    }

    #[test]
    fn nothing_to_run_is_a_typed_rejection() {
        let image = image_config(&[], &[]);
        let err = plan_process(TASK, &container_spec(), &image).unwrap_err();
        assert!(matches!(err, PlanError::EmptyEntrypoint { .. }), "{err}");
        assert!(err.to_string().contains("nothing to run"), "{err}");
    }

    // ---- env ---------------------------------------------------------------

    #[test]
    fn spec_env_overrides_image_env_in_place_and_appends_new_keys() {
        let mut image = image_config(&["/bin/sh"], &[]);
        image.env = vec![
            "PATH=/usr/bin".to_owned(),
            "TIER=base".to_owned(),
            "KEEP=1".to_owned(),
        ];
        let mut spec = container_spec();
        spec.env = vec!["TIER=web".to_owned(), "EXTRA=yes".to_owned()];
        assert_eq!(
            plan(&spec, &image).env,
            ["PATH=/usr/bin", "TIER=web", "KEEP=1", "EXTRA=yes"]
        );
    }

    #[test]
    fn a_default_path_is_injected_only_when_nobody_sets_one() {
        let image = image_config(&["/bin/sh"], &[]);
        assert_eq!(plan(&container_spec(), &image).env, [DEFAULT_PATH]);

        let mut spec = container_spec();
        spec.env = vec!["PATH=/opt/bin".to_owned()];
        assert_eq!(plan(&spec, &image).env, ["PATH=/opt/bin"]);

        let mut image_with_path = image_config(&["/bin/sh"], &[]);
        image_with_path.env = vec!["PATH=/image/bin".to_owned()];
        assert_eq!(
            plan(&container_spec(), &image_with_path).env,
            ["PATH=/image/bin"]
        );
    }

    #[test]
    fn env_entries_without_a_value_are_keyed_by_the_whole_string() {
        let mut image = image_config(&["/bin/sh"], &[]);
        image.env = vec!["PATH=/bin".to_owned(), "FLAG".to_owned()];
        let mut spec = container_spec();
        spec.env = vec!["FLAG=on".to_owned()];
        assert_eq!(plan(&spec, &image).env, ["PATH=/bin", "FLAG=on"]);
    }

    // ---- cwd / user / hostname --------------------------------------------

    #[test]
    fn cwd_prefers_the_spec_then_the_image_then_root() {
        let mut image = image_config(&["/bin/sh"], &[]);
        assert_eq!(plan(&container_spec(), &image).cwd, "/");
        image.working_dir = Some("/srv".to_owned());
        assert_eq!(plan(&container_spec(), &image).cwd, "/srv");
        let mut spec = container_spec();
        spec.dir = Some("/app".to_owned());
        assert_eq!(plan(&spec, &image).cwd, "/app");
    }

    #[test]
    fn numeric_users_are_parsed_and_named_users_rejected() {
        let mut image = image_config(&["/bin/sh"], &[]);
        assert_eq!(plan(&container_spec(), &image).user, None);

        let mut spec = container_spec();
        spec.user = Some("1000".to_owned());
        assert_eq!(
            plan(&spec, &image).user,
            Some(JailUser {
                uid: 1000,
                gid: 1000,
                additional_gids: Vec::new()
            })
        );
        spec.user = Some("1000:2000".to_owned());
        assert_eq!(
            plan(&spec, &image).user,
            Some(JailUser {
                uid: 1000,
                gid: 2000,
                additional_gids: Vec::new()
            })
        );

        spec.user = Some("www:www".to_owned());
        let err = plan_process(TASK, &spec, &image).unwrap_err();
        assert!(matches!(err, PlanError::NonNumericUser { .. }), "{err}");

        // The image's USER is used when the spec does not override it.
        image.user = Some("65534".to_owned());
        assert_eq!(plan(&container_spec(), &image).user.unwrap().uid, 65534);
    }

    #[test]
    fn hostname_defaults_to_the_task_id_prefix() {
        let image = image_config(&["/bin/sh"], &[]);
        assert_eq!(plan(&container_spec(), &image).hostname, "1hvy0lj3x0b8");
        let mut spec = container_spec();
        spec.hostname = Some("web-1".to_owned());
        assert_eq!(plan(&spec, &image).hostname, "web-1");
    }

    #[test]
    fn tty_is_rejected_until_the_console_socket_lands() {
        let image = image_config(&["/bin/sh"], &[]);
        let mut spec = container_spec();
        spec.tty = true;
        let err = plan_process(TASK, &spec, &image).unwrap_err();
        assert!(matches!(err, PlanError::TtyUnsupported { .. }), "{err}");
    }

    // ---- mounts ------------------------------------------------------------

    fn mount(kind: MountType, source: Option<&str>, target: &str, read_only: bool) -> Mount {
        Mount {
            kind,
            source: source.map(str::to_owned),
            target: target.to_owned(),
            read_only,
        }
    }

    #[test]
    fn volumes_binds_and_tmpfs_become_the_right_bundle_mounts() {
        let volumes: BTreeMap<String, PathBuf> = [(
            "data".to_owned(),
            PathBuf::from("/var/db/satl/volumes/data"),
        )]
        .into();
        let mounts = [
            mount(MountType::Volume, Some("data"), "/data", false),
            mount(MountType::Bind, Some("/host/etc"), "/etc/app", true),
            mount(MountType::Tmpfs, None, "/run", false),
        ];
        let planned = plan_mounts(TASK, &mounts, &volumes).unwrap();
        assert_eq!(
            planned,
            [
                BundleMount {
                    fstype: MountFstype::Nullfs,
                    source: "/var/db/satl/volumes/data".to_owned(),
                    target: "/data".to_owned(),
                    options: Vec::new(),
                },
                BundleMount {
                    fstype: MountFstype::Nullfs,
                    source: "/host/etc".to_owned(),
                    target: "/etc/app".to_owned(),
                    options: vec!["ro".to_owned()],
                },
                BundleMount {
                    fstype: MountFstype::Tmpfs,
                    source: "tmpfs".to_owned(),
                    target: "/run".to_owned(),
                    options: vec!["mode=1777".to_owned()],
                },
            ]
        );
    }

    #[test]
    fn mount_planning_rejects_bad_shapes() {
        let empty = BTreeMap::new();
        let cases: [(Mount, &str); 4] = [
            (
                mount(MountType::Bind, Some("/src"), "relative", false),
                "absolute",
            ),
            (mount(MountType::Bind, None, "/target", false), "no source"),
            (
                mount(MountType::Volume, Some("ghost"), "/target", false),
                "was not created",
            ),
            (
                mount(MountType::Volume, None, "/target", false),
                "no source",
            ),
        ];
        for (mount, needle) in cases {
            let err = plan_mounts(TASK, std::slice::from_ref(&mount), &empty).unwrap_err();
            assert!(err.to_string().contains(needle), "{mount:?}: {err}");
        }

        let duplicate = [
            mount(MountType::Tmpfs, None, "/run", false),
            mount(MountType::Tmpfs, None, "/run", false),
        ];
        let err = plan_mounts(TASK, &duplicate, &empty).unwrap_err();
        assert!(
            matches!(err, PlanError::DuplicateMountTarget { .. }),
            "{err}"
        );
    }

    #[test]
    fn platform_mapping_covers_the_runnable_set() {
        assert_eq!(
            image_platform(TASK, &satl_image::Platform::new("freebsd", "amd64")).unwrap(),
            ImagePlatform::Freebsd
        );
        assert_eq!(
            image_platform(TASK, &satl_image::Platform::new("linux", "amd64")).unwrap(),
            ImagePlatform::Linux
        );
        let err = image_platform(TASK, &satl_image::Platform::new("windows", "amd64")).unwrap_err();
        assert!(
            matches!(err, PlanError::UnsupportedPlatform { .. }),
            "{err}"
        );
    }

    #[test]
    fn plan_bundle_always_requests_a_vnet_jail_and_carries_the_rootfs() {
        let task = crate::testing::task_with(|spec| {
            spec.container.read_only = true;
        });
        let image = crate::testing::pulled_image(
            image_config(&["/bin/sh"], &["-c", "true"]),
            satl_image::Platform::new("freebsd", "amd64"),
        );
        let bundle = plan_bundle(
            &task,
            &image,
            PathBuf::from("/var/db/satl/containers/t1"),
            &BTreeMap::new(),
            &DependencyPlan::default(),
        )
        .unwrap();
        assert!(bundle.vnet);
        assert!(bundle.readonly_rootfs);
        assert!(!bundle.terminal);
        assert_eq!(bundle.rootfs, PathBuf::from("/var/db/satl/containers/t1"));
        assert_eq!(bundle.platform, ImagePlatform::Freebsd);
        assert_eq!(bundle.args, ["/bin/sh", "-c", "true"]);
        assert_eq!(bundle.hostname.as_deref(), Some(&task.id.as_str()[..12]));
    }

    #[test]
    fn plan_bundle_maps_satl_jail_labels_to_ocijail_annotations() {
        let task = crate::testing::task_with(|spec| {
            spec.container
                .labels
                .insert("satl.jail.sysvshm".to_owned(), "new".to_owned());
            spec.container
                .labels
                .insert("unrelated".to_owned(), "ignored".to_owned());
            spec.container
                .labels
                .insert("satl.jail.".to_owned(), "ignored".to_owned());
        });
        let image = crate::testing::pulled_image(
            image_config(&["/bin/sh"], &["-c", "true"]),
            satl_image::Platform::new("freebsd", "amd64"),
        );
        let bundle = plan_bundle(
            &task,
            &image,
            PathBuf::from("/var/db/satl/containers/t1"),
            &BTreeMap::new(),
            &DependencyPlan::default(),
        )
        .unwrap();
        assert_eq!(
            bundle.extra_jail_annotations,
            BTreeMap::from([("org.freebsd.jail.sysvshm".to_owned(), "new".to_owned())])
        );
    }

    // ---- secrets / configs (M5) ---------------------------------------------

    fn secret_ref(name: &str, target: &str, uid: &str, gid: &str, mode: u32) -> SecretReference {
        SecretReference {
            secret_id: Id::generate(),
            secret_name: name.to_owned(),
            file: satl_core::FileTarget {
                name: target.to_owned(),
                uid: uid.to_owned(),
                gid: gid.to_owned(),
                mode,
            },
        }
    }

    fn config_ref(name: &str, target: &str, mode: u32) -> ConfigReference {
        ConfigReference {
            config_id: Id::generate(),
            config_name: name.to_owned(),
            file: satl_core::FileTarget {
                name: target.to_owned(),
                uid: "0".to_owned(),
                gid: "0".to_owned(),
                mode,
            },
        }
    }

    use satl_core::{ConfigReference, SecretReference};

    const ROOTFS: &str = "/var/db/satl/containers/t1";
    const BUNDLE: &str = "/var/db/satl/state/bundles/t1";

    fn plan_deps(spec: &ContainerSpec, total: u64) -> Result<DependencyPlan, PlanError> {
        plan_dependencies(TASK, spec, Path::new(ROOTFS), Path::new(BUNDLE), total)
    }

    #[test]
    fn a_task_without_references_plans_nothing() {
        let plan = plan_deps(&container_spec(), 0).unwrap();
        assert_eq!(plan, DependencyPlan::default());
    }

    #[test]
    fn secrets_get_one_sized_tmpfs_and_files_under_run_secrets() {
        let mut spec = container_spec();
        spec.secrets = vec![
            secret_ref("db.password", "db.password", "0", "0", 0o444),
            secret_ref("api.key", "nested/api.key", "1000", "1000", 0o400),
        ];
        let plan = plan_deps(&spec, 1000).unwrap();
        assert_eq!(plan.mounts.len(), 1, "{plan:?}");
        let tmpfs = &plan.mounts[0];
        assert_eq!(tmpfs.fstype, MountFstype::Tmpfs);
        assert_eq!(tmpfs.target, SECRETS_TARGET_DIR);
        // 1000 bytes + slack is under the floor, so the floor wins.
        assert_eq!(tmpfs.options, ["size=131072", "mode=0755"]);
        assert_eq!(plan.secret_files.len(), 2);
        assert_eq!(
            plan.secret_files[0].path,
            Path::new(ROOTFS).join("run/secrets/db.password")
        );
        assert_eq!(plan.secret_files[0].mode, 0o444);
        assert_eq!(
            plan.secret_files[1].path,
            Path::new(ROOTFS).join("run/secrets/nested/api.key")
        );
        assert_eq!(plan.secret_files[1].uid, 1000);
        assert_eq!(plan.secret_files[1].gid, 1000);
        assert!(plan.config_files.is_empty());
    }

    #[test]
    fn the_tmpfs_size_has_slack_and_a_floor() {
        assert_eq!(secrets_tmpfs_size(0), 128 * 1024);
        assert_eq!(secrets_tmpfs_size(63 * 1024), 128 * 1024);
        assert_eq!(secrets_tmpfs_size(500 * 1024), 564 * 1024);
    }

    #[test]
    fn configs_become_readonly_nullfs_file_mounts_from_the_bundle_dir() {
        let mut spec = container_spec();
        spec.configs = vec![
            config_ref("nginx.conf", "/etc/nginx/nginx.conf", 0o444),
            // A relative config target is rooted at /, as Docker does.
            config_ref("motd", "motd", 0o644),
        ];
        let plan = plan_deps(&spec, 0).unwrap();
        assert_eq!(plan.mounts.len(), 2);
        assert_eq!(plan.mounts[0].fstype, MountFstype::Nullfs);
        assert_eq!(plan.mounts[0].source, format!("{BUNDLE}/configs/0"));
        assert_eq!(plan.mounts[0].target, "/etc/nginx/nginx.conf");
        assert_eq!(plan.mounts[0].options, ["ro"]);
        assert_eq!(plan.mounts[1].target, "/motd");
        assert_eq!(
            plan.config_files[1].path,
            Path::new(BUNDLE).join("configs/1")
        );
        assert!(plan.secret_files.is_empty());
    }

    #[test]
    fn bad_file_targets_are_rejected_by_name_not_payload() {
        let cases: [(ContainerSpec, &str); 5] = [
            (
                {
                    let mut spec = container_spec();
                    spec.secrets = vec![secret_ref("s", "/absolute", "0", "0", 0o444)];
                    spec
                },
                "relative",
            ),
            (
                {
                    let mut spec = container_spec();
                    spec.secrets = vec![secret_ref("s", "../escape", "0", "0", 0o444)];
                    spec
                },
                ".. components",
            ),
            (
                {
                    let mut spec = container_spec();
                    spec.secrets = vec![secret_ref("s", "", "0", "0", 0o444)];
                    spec
                },
                "empty",
            ),
            (
                {
                    let mut spec = container_spec();
                    spec.configs = vec![config_ref("c", "/etc/../escape", 0o444)];
                    spec
                },
                ".. components",
            ),
            (
                {
                    let mut spec = container_spec();
                    spec.secrets = vec![secret_ref("s", "ok", "www", "0", 0o444)];
                    spec
                },
                "numeric",
            ),
        ];
        for (spec, needle) in cases {
            let err = plan_deps(&spec, 0).unwrap_err();
            let message = err.to_string();
            assert!(message.contains(needle), "{message}");
            assert!(message.contains(TASK), "{message}");
        }
    }

    #[test]
    fn duplicate_dependency_targets_are_rejected() {
        let mut spec = container_spec();
        spec.secrets = vec![
            secret_ref("a", "token", "0", "0", 0o444),
            secret_ref("b", "token", "0", "0", 0o444),
        ];
        let err = plan_deps(&spec, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PlanError::DuplicateDependencyTarget { kind: "secret", .. }
            ),
            "{err}"
        );

        let mut spec = container_spec();
        spec.configs = vec![
            config_ref("a", "/etc/app.conf", 0o444),
            config_ref("b", "etc/app.conf", 0o444),
        ];
        let err = plan_deps(&spec, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PlanError::DuplicateDependencyTarget { kind: "config", .. }
            ),
            "{err}"
        );
    }

    #[test]
    fn empty_owner_strings_mean_root() {
        let mut spec = container_spec();
        spec.secrets = vec![secret_ref("s", "token", "", "", 0o444)];
        let plan = plan_deps(&spec, 0).unwrap();
        assert_eq!(plan.secret_files[0].uid, 0);
        assert_eq!(plan.secret_files[0].gid, 0);
    }

    #[test]
    fn a_user_mount_colliding_with_the_secrets_tmpfs_is_rejected() {
        let mut task = crate::testing::task_with(|spec| {
            spec.container.secrets = vec![secret_ref("s", "token", "0", "0", 0o444)];
            spec.container.mounts = vec![Mount {
                kind: MountType::Tmpfs,
                source: None,
                target: SECRETS_TARGET_DIR.to_owned(),
                read_only: false,
            }];
        });
        task.spec.container.image = "example/app:1".to_owned();
        let image = crate::testing::pulled_image(
            image_config(&["/bin/sh"], &[]),
            satl_image::Platform::new("freebsd", "amd64"),
        );
        let deps = plan_dependencies(
            task.id.as_str(),
            &task.spec.container,
            Path::new(ROOTFS),
            Path::new(BUNDLE),
            5,
        )
        .unwrap();
        let err = plan_bundle(
            &task,
            &image,
            PathBuf::from(ROOTFS),
            &BTreeMap::new(),
            &deps,
        )
        .unwrap_err();
        assert!(
            matches!(err, PlanError::DuplicateMountTarget { .. }),
            "{err}"
        );
    }

    #[test]
    fn dependency_mounts_ride_the_bundle_after_user_mounts() {
        let task = crate::testing::task_with(|spec| {
            spec.container.secrets = vec![secret_ref("s", "token", "0", "0", 0o400)];
            spec.container.configs = vec![config_ref("c", "/etc/app.conf", 0o444)];
        });
        let image = crate::testing::pulled_image(
            image_config(&["/bin/sh"], &[]),
            satl_image::Platform::new("freebsd", "amd64"),
        );
        let deps = plan_dependencies(
            task.id.as_str(),
            &task.spec.container,
            Path::new(ROOTFS),
            Path::new(BUNDLE),
            5,
        )
        .unwrap();
        let bundle = plan_bundle(
            &task,
            &image,
            PathBuf::from(ROOTFS),
            &BTreeMap::new(),
            &deps,
        )
        .unwrap();
        let targets: Vec<&str> = bundle
            .mounts
            .iter()
            .map(|mount| mount.target.as_str())
            .collect();
        assert_eq!(targets, [SECRETS_TARGET_DIR, "/etc/app.conf"]);
    }
}
