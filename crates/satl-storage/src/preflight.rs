// SPDX-License-Identifier: BSD-2-Clause
//! Startup storage preflight: verify the SatL ZFS root dataset and ensure
//! the child dataset layout from `docs/architecture.md` §10 exists.
//!
//! ```text
//! <root>                       e.g. zroot/satl, mountpoint=/var/db/satl
//! ├── raft                     raft log + snapshots (managers)
//! ├── images                   blob + metadata files
//! ├── layers                   one dataset per applied layer chain
//! ├── containers               writable layers (clones)
//! └── volumes                  named local volumes
//! ```
//!
//! ZFS is mandatory (architecture invariant #5): a missing root dataset is a
//! fatal, operator-actionable error — the daemon must not limp along on
//! non-ZFS storage.

use std::path::PathBuf;

use crate::zfs::{CommandRunner, Zfs, ZfsError};

/// Child datasets created under the SatL root dataset
/// (`docs/architecture.md` §10).
pub const CHILD_DATASETS: [&str; 5] = ["raft", "images", "layers", "containers", "volumes"];

/// Successful preflight result.
#[derive(Debug, Clone)]
pub struct StoragePreflight {
    /// Filesystem mountpoint of the root dataset (normally `/var/db/satl`).
    pub root_mountpoint: PathBuf,
}

/// Preflight failure. Every variant renders an operator-actionable message.
#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    /// The configured root dataset does not exist at all.
    #[error(
        "ZFS root dataset '{dataset}' does not exist; create it with: \
         zfs create -o mountpoint={suggested_mountpoint} {dataset}"
    )]
    RootDatasetMissing {
        /// The configured root dataset name.
        dataset: String,
        /// Mountpoint to suggest in the hint (the configured state dir).
        suggested_mountpoint: String,
    },

    /// A `zfs` invocation failed (full argv/status/stderr inside).
    #[error(transparent)]
    Zfs(#[from] ZfsError),
}

/// Verify the root dataset exists and ensure the M0 child dataset layout,
/// creating missing children (`zfs create`, requires root).
///
/// `suggested_mountpoint` is only used in the error hint when the root
/// dataset is missing (pass the configured state dir).
///
/// # Errors
///
/// [`PreflightError::RootDatasetMissing`] when the root dataset is absent;
/// [`PreflightError::Zfs`] when any `zfs` command fails (the error carries
/// the full command line, exit status, and stderr).
pub async fn preflight<R: CommandRunner>(
    zfs: &Zfs<R>,
    root_dataset: &str,
    suggested_mountpoint: &str,
) -> Result<StoragePreflight, PreflightError> {
    tracing::info!(root_dataset, "running storage preflight");

    if !zfs.dataset_exists(root_dataset).await? {
        return Err(PreflightError::RootDatasetMissing {
            dataset: root_dataset.to_owned(),
            suggested_mountpoint: suggested_mountpoint.to_owned(),
        });
    }

    let root_mountpoint = zfs.mountpoint_of(root_dataset).await?;

    for child in CHILD_DATASETS {
        let name = format!("{root_dataset}/{child}");
        if zfs.dataset_exists(&name).await? {
            tracing::debug!(dataset = %name, "dataset present");
        } else {
            tracing::info!(dataset = %name, "dataset missing, creating");
            zfs.create(&name, &[]).await?;
        }
    }

    tracing::info!(
        root_dataset,
        root_mountpoint = %root_mountpoint.display(),
        "storage preflight complete"
    );
    Ok(StoragePreflight { root_mountpoint })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zfs::MockRunner;

    const MISSING: &str = "cannot open '%s': dataset does not exist\n";

    fn missing_stderr(name: &str) -> String {
        MISSING.replace("%s", name)
    }

    #[tokio::test]
    async fn preflight_creates_all_missing_children() {
        let mock = MockRunner::new();
        // root exists
        mock.push_output(0, "zroot/satl\n", "");
        // mountpoint query
        mock.push_output(0, "/var/db/satl\n", "");
        // each child: exists? -> no; create -> ok
        for child in CHILD_DATASETS {
            mock.push_output(1, "", &missing_stderr(&format!("zroot/satl/{child}")));
            mock.push_output(0, "", "");
        }

        let zfs = Zfs::with_runner(&mock);
        let result = preflight(&zfs, "zroot/satl", "/var/db/satl").await.unwrap();
        assert_eq!(result.root_mountpoint, PathBuf::from("/var/db/satl"));

        let calls = mock.calls();
        assert_eq!(
            calls,
            [
                "/sbin/zfs list -H -o name zroot/satl",
                "/sbin/zfs get -H -p -o value mountpoint zroot/satl",
                "/sbin/zfs list -H -o name zroot/satl/raft",
                "/sbin/zfs create zroot/satl/raft",
                "/sbin/zfs list -H -o name zroot/satl/images",
                "/sbin/zfs create zroot/satl/images",
                "/sbin/zfs list -H -o name zroot/satl/layers",
                "/sbin/zfs create zroot/satl/layers",
                "/sbin/zfs list -H -o name zroot/satl/containers",
                "/sbin/zfs create zroot/satl/containers",
                "/sbin/zfs list -H -o name zroot/satl/volumes",
                "/sbin/zfs create zroot/satl/volumes",
            ]
        );
    }

    #[tokio::test]
    async fn preflight_skips_existing_children() {
        let mock = MockRunner::new();
        mock.push_output(0, "zroot/satl\n", "");
        mock.push_output(0, "/var/db/satl\n", "");
        for child in CHILD_DATASETS {
            mock.push_output(0, &format!("zroot/satl/{child}\n"), "");
        }

        let zfs = Zfs::with_runner(&mock);
        preflight(&zfs, "zroot/satl", "/var/db/satl").await.unwrap();

        let calls = mock.calls();
        assert_eq!(calls.len(), 2 + CHILD_DATASETS.len());
        assert!(!calls.iter().any(|c| c.contains("zfs create")));
    }

    #[tokio::test]
    async fn preflight_missing_root_tells_operator_what_to_run() {
        let mock = MockRunner::new();
        mock.push_output(1, "", &missing_stderr("zroot/satl"));

        let zfs = Zfs::with_runner(&mock);
        let err = preflight(&zfs, "zroot/satl", "/var/db/satl")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("zfs create -o mountpoint=/var/db/satl zroot/satl"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn preflight_propagates_create_failure_with_context() {
        let mock = MockRunner::new();
        mock.push_output(0, "zroot/satl\n", "");
        mock.push_output(0, "/var/db/satl\n", "");
        mock.push_output(1, "", &missing_stderr("zroot/satl/raft"));
        mock.push_output(
            1,
            "",
            "cannot create 'zroot/satl/raft': permission denied\n",
        );

        let zfs = Zfs::with_runner(&mock);
        let err = preflight(&zfs, "zroot/satl", "/var/db/satl")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/sbin/zfs create zroot/satl/raft"), "{msg}");
        assert!(msg.contains("permission denied"), "{msg}");
    }

    #[tokio::test]
    async fn preflight_rejects_unmounted_root() {
        let mock = MockRunner::new();
        mock.push_output(0, "zroot/satl\n", "");
        mock.push_output(0, "none\n", "");

        let zfs = Zfs::with_runner(&mock);
        let err = preflight(&zfs, "zroot/satl", "/var/db/satl")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("zfs set mountpoint=<path> zroot/satl"),
            "{msg}"
        );
    }
}
