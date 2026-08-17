// SPDX-License-Identifier: BSD-2-Clause
//! Named local volumes (`docs/architecture.md` §10): one dataset per volume
//! under `<root>/volumes/<name>`, mounted into jails via nullfs.
//!
//! Volumes are node-local in v1 (not cluster objects) and deliberately
//! survive task removal — Docker semantics: `satl volume rm` is the only
//! thing that destroys one. Removal policy (force, prune) is the caller's
//! job; this store only reports the typed [`VolumeStoreError::InUse`]
//! outcome when ZFS refuses to destroy a busy dataset.

use std::path::PathBuf;

use tracing::Instrument as _;

use crate::zfs::{CommandRunner, SystemRunner, Zfs, ZfsError};

/// One named volume and where it lives on the host filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// Volume name (also the dataset's last path component).
    pub name: String,
    /// Host mountpoint (the nullfs source when mounted into a jail).
    pub mountpoint: PathBuf,
}

/// Error from the volume store.
#[derive(Debug, thiserror::Error)]
pub enum VolumeStoreError {
    /// A `zfs` invocation failed (full argv/status/stderr inside).
    #[error(transparent)]
    Zfs(#[from] ZfsError),

    /// The volume name cannot be used as a ZFS dataset name component.
    #[error("invalid volume name {name:?}: {reason}")]
    InvalidName {
        /// The offending name.
        name: String,
        /// Why it was rejected.
        reason: String,
    },

    /// The dataset is busy (still nullfs-mounted into a jail). Whether to
    /// retry, force, or surface this is the caller's policy.
    #[error(
        "volume '{name}' is in use (zfs reported dataset '{dataset}' busy); \
         remove the tasks mounting it first"
    )]
    InUse {
        /// The volume name.
        name: String,
        /// The busy dataset.
        dataset: String,
    },

    /// [`VolumeStore::remove`] was asked to remove a volume that does not
    /// exist.
    #[error("volume '{name}' does not exist")]
    NotFound {
        /// The requested name.
        name: String,
    },
}

/// Validate a volume name: `[a-zA-Z0-9][a-zA-Z0-9_.-]*` (Docker's local
/// volume name shape, safe as a ZFS dataset component).
fn validate_name(name: &str) -> Result<(), VolumeStoreError> {
    let invalid = |reason: &str| VolumeStoreError::InvalidName {
        name: name.to_owned(),
        reason: reason.to_owned(),
    };
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(invalid("volume name is empty"));
    };
    if !first.is_ascii_alphanumeric() {
        return Err(invalid("must start with an ASCII letter or digit"));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')) {
        return Err(invalid(
            "may only contain ASCII letters, digits, '_', '.', and '-'",
        ));
    }
    Ok(())
}

/// Manages named volume datasets under a volumes root dataset
/// (e.g. `zroot/satl/volumes`).
#[derive(Debug, Clone)]
pub struct VolumeStore<R = SystemRunner> {
    zfs: Zfs<R>,
    root: String,
}

impl<R: CommandRunner> VolumeStore<R> {
    /// Store over `zfs`, holding volume datasets under
    /// `volumes_root_dataset`.
    pub fn new(zfs: Zfs<R>, volumes_root_dataset: impl Into<String>) -> Self {
        Self {
            zfs,
            root: volumes_root_dataset.into(),
        }
    }

    fn dataset_for(&self, name: &str) -> String {
        format!("{}/{name}", self.root)
    }

    /// Ensure the volume `name` exists (creating its dataset if missing) and
    /// return its host mountpoint. Idempotent.
    ///
    /// # Errors
    ///
    /// [`VolumeStoreError::InvalidName`] for unusable names;
    /// [`VolumeStoreError::Zfs`] when creation or mountpoint resolution
    /// fails.
    pub async fn ensure(&self, name: &str) -> Result<PathBuf, VolumeStoreError> {
        validate_name(name)?;
        let dataset = self.dataset_for(name);
        let span = tracing::info_span!("volume_ensure", volume = %name, dataset = %dataset);
        async {
            if !self.zfs.dataset_exists(&dataset).await? {
                self.zfs.create(&dataset, &[]).await?;
                tracing::info!("volume created");
            }
            Ok(self.zfs.mountpoint_of(&dataset).await?)
        }
        .instrument(span)
        .await
    }

    /// Destroy the volume `name` (recursively, so stray snapshots do not
    /// block removal).
    ///
    /// # Errors
    ///
    /// [`VolumeStoreError::NotFound`] when the volume does not exist;
    /// [`VolumeStoreError::InUse`] when the dataset is busy (mounted into a
    /// jail) — the caller decides the policy; [`VolumeStoreError::Zfs`]
    /// otherwise.
    pub async fn remove(&self, name: &str) -> Result<(), VolumeStoreError> {
        validate_name(name)?;
        let dataset = self.dataset_for(name);
        let span = tracing::info_span!("volume_remove", volume = %name, dataset = %dataset);
        async {
            if !self.zfs.dataset_exists(&dataset).await? {
                return Err(VolumeStoreError::NotFound {
                    name: name.to_owned(),
                });
            }
            match self.zfs.destroy(&dataset, true).await {
                Ok(()) => {
                    tracing::info!("volume destroyed");
                    Ok(())
                }
                Err(ZfsError::CommandFailed { stderr, .. })
                    if stderr.contains("dataset is busy") =>
                {
                    Err(VolumeStoreError::InUse {
                        name: name.to_owned(),
                        dataset,
                    })
                }
                Err(err) => Err(err.into()),
            }
        }
        .instrument(span)
        .await
    }

    /// List all volumes (direct children of the volumes root). Datasets
    /// without a filesystem mountpoint are skipped with a warning — they are
    /// not usable as volumes.
    ///
    /// # Errors
    ///
    /// [`VolumeStoreError::Zfs`] when listing fails.
    pub async fn list(&self) -> Result<Vec<VolumeInfo>, VolumeStoreError> {
        let prefix = format!("{}/", self.root);
        let children = self.zfs.list_children(&self.root).await?;
        Ok(children
            .into_iter()
            .filter_map(|child| {
                let name = child.name.strip_prefix(&prefix)?.to_owned();
                let Some(mountpoint) = child.mountpoint else {
                    tracing::warn!(
                        volume = %name,
                        dataset = %child.name,
                        "volume dataset has no mountpoint; skipping"
                    );
                    return None;
                };
                Some(VolumeInfo { name, mountpoint })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zfs::MockRunner;

    const ROOT: &str = "zroot/satl/volumes";

    fn missing_stderr(name: &str) -> String {
        format!("cannot open '{name}': dataset does not exist\n")
    }

    #[tokio::test]
    async fn ensure_creates_missing_volume_and_returns_mountpoint() {
        let mock = MockRunner::new();
        mock.push_output(1, "", &missing_stderr(&format!("{ROOT}/data"))); // exists? no
        mock.push_output(0, "", ""); // create
        mock.push_output(0, "/var/db/satl/volumes/data\n", ""); // mountpoint
        let store = VolumeStore::new(Zfs::with_runner(&mock), ROOT);
        let mountpoint = store.ensure("data").await.unwrap();
        assert_eq!(mountpoint, PathBuf::from("/var/db/satl/volumes/data"));
        assert_eq!(
            mock.calls(),
            [
                format!("/sbin/zfs list -H -o name {ROOT}/data"),
                format!("/sbin/zfs create {ROOT}/data"),
                format!("/sbin/zfs get -H -p -o value mountpoint {ROOT}/data"),
            ]
        );
    }

    #[tokio::test]
    async fn ensure_adopts_existing_volume_without_creating() {
        let mock = MockRunner::new();
        mock.push_output(0, &format!("{ROOT}/data\n"), ""); // exists? yes
        mock.push_output(0, "/var/db/satl/volumes/data\n", ""); // mountpoint
        let store = VolumeStore::new(Zfs::with_runner(&mock), ROOT);
        let mountpoint = store.ensure("data").await.unwrap();
        assert_eq!(mountpoint, PathBuf::from("/var/db/satl/volumes/data"));
        assert_eq!(
            mock.calls(),
            [
                format!("/sbin/zfs list -H -o name {ROOT}/data"),
                format!("/sbin/zfs get -H -p -o value mountpoint {ROOT}/data"),
            ]
        );
    }

    #[tokio::test]
    async fn remove_destroys_recursively() {
        let mock = MockRunner::new();
        mock.push_output(0, &format!("{ROOT}/data\n"), ""); // exists? yes
        mock.push_output(0, "", ""); // destroy -r
        let store = VolumeStore::new(Zfs::with_runner(&mock), ROOT);
        store.remove("data").await.unwrap();
        assert_eq!(
            mock.calls(),
            [
                format!("/sbin/zfs list -H -o name {ROOT}/data"),
                format!("/sbin/zfs destroy -r {ROOT}/data"),
            ]
        );
    }

    #[tokio::test]
    async fn remove_missing_volume_is_a_typed_not_found() {
        let mock = MockRunner::new();
        mock.push_output(1, "", &missing_stderr(&format!("{ROOT}/ghost")));
        let store = VolumeStore::new(Zfs::with_runner(&mock), ROOT);
        let err = store.remove("ghost").await.unwrap_err();
        assert!(
            matches!(&err, VolumeStoreError::NotFound { name } if name == "ghost"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn remove_busy_dataset_is_a_typed_in_use() {
        let mock = MockRunner::new();
        mock.push_output(0, &format!("{ROOT}/data\n"), ""); // exists? yes
        mock.push_output(
            1,
            "",
            &format!("cannot destroy '{ROOT}/data': dataset is busy\n"),
        );
        let store = VolumeStore::new(Zfs::with_runner(&mock), ROOT);
        let err = store.remove("data").await.unwrap_err();
        match &err {
            VolumeStoreError::InUse { name, dataset } => {
                assert_eq!(name, "data");
                assert_eq!(dataset, &format!("{ROOT}/data"));
            }
            other => panic!("expected InUse, got {other}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("in use"), "{msg}");
    }

    #[tokio::test]
    async fn remove_other_zfs_failures_pass_through_with_context() {
        let mock = MockRunner::new();
        mock.push_output(0, &format!("{ROOT}/data\n"), "");
        mock.push_output(
            1,
            "",
            &format!("cannot destroy '{ROOT}/data': permission denied\n"),
        );
        let store = VolumeStore::new(Zfs::with_runner(&mock), ROOT);
        let err = store.remove("data").await.unwrap_err();
        assert!(matches!(err, VolumeStoreError::Zfs(_)), "{err}");
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("/sbin/zfs destroy -r {ROOT}/data")),
            "{msg}"
        );
        assert!(msg.contains("permission denied"), "{msg}");
    }

    #[tokio::test]
    async fn list_returns_named_volumes_and_skips_unmounted() {
        let mock = MockRunner::new();
        mock.push_output(
            0,
            &format!(
                "{ROOT}\t/var/db/satl/volumes\n\
                 {ROOT}/data\t/var/db/satl/volumes/data\n\
                 {ROOT}/broken\tnone\n\
                 {ROOT}/web.assets\t/var/db/satl/volumes/web.assets\n"
            ),
            "",
        );
        let store = VolumeStore::new(Zfs::with_runner(&mock), ROOT);
        let volumes = store.list().await.unwrap();
        assert_eq!(
            volumes,
            [
                VolumeInfo {
                    name: "data".to_owned(),
                    mountpoint: PathBuf::from("/var/db/satl/volumes/data"),
                },
                VolumeInfo {
                    name: "web.assets".to_owned(),
                    mountpoint: PathBuf::from("/var/db/satl/volumes/web.assets"),
                },
            ]
        );
        assert_eq!(
            mock.calls(),
            [format!(
                "/sbin/zfs list -H -p -r -d 1 -o name,mountpoint {ROOT}"
            )]
        );
    }

    #[tokio::test]
    async fn invalid_names_are_rejected_before_any_zfs_call() {
        let mock = MockRunner::new();
        let store = VolumeStore::new(Zfs::with_runner(&mock), ROOT);
        for bad in ["", "-lead", ".hidden", "_x", "a/b", "a b", "a@snap", "é"] {
            let err = store.ensure(bad).await.unwrap_err();
            assert!(
                matches!(err, VolumeStoreError::InvalidName { .. }),
                "{bad:?}: {err}"
            );
            let err = store.remove(bad).await.unwrap_err();
            assert!(
                matches!(err, VolumeStoreError::InvalidName { .. }),
                "{bad:?}: {err}"
            );
        }
        assert!(mock.calls().is_empty(), "no zfs command may have run");
    }

    #[test]
    fn valid_names_pass() {
        for good in ["data", "web.assets", "a", "0store", "x_y-z.9"] {
            validate_name(good).unwrap();
        }
    }
}
