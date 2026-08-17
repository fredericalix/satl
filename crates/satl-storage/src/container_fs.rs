// SPDX-License-Identifier: BSD-2-Clause
//! Container writable layers (`docs/architecture.md` §10): one dataset per
//! task under `<root>/containers/<task-id>`, cloned from the image's top
//! layer `@final` snapshot, destroyed on task removal.

use std::path::PathBuf;

use tracing::Instrument as _;

use crate::chain::ChainId;
use crate::layers::FINAL_SNAPSHOT;
use crate::zfs::{CommandRunner, SystemRunner, Zfs, ZfsError};

/// Error managing container writable layers.
#[derive(Debug, thiserror::Error)]
pub enum ContainerFsError {
    /// A `zfs` invocation failed (full argv/status/stderr inside).
    #[error(transparent)]
    Zfs(#[from] ZfsError),

    /// The task ID cannot be used as a ZFS dataset name component.
    #[error("invalid task id {task_id:?}: {reason}")]
    InvalidTaskId {
        /// The offending task ID.
        task_id: String,
        /// Why it was rejected.
        reason: String,
    },
}

/// Validate that a task ID is safe to embed as a ZFS dataset name component
/// (no separators, no shell/zfs metacharacters, no empty/hidden names).
fn validate_task_id(task_id: &str) -> Result<(), ContainerFsError> {
    let invalid = |reason: &str| ContainerFsError::InvalidTaskId {
        task_id: task_id.to_owned(),
        reason: reason.to_owned(),
    };
    let mut chars = task_id.chars();
    let Some(first) = chars.next() else {
        return Err(invalid("task id is empty"));
    };
    if !first.is_ascii_alphanumeric() {
        return Err(invalid("must start with an ASCII letter or digit"));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Err(invalid(
            "may only contain ASCII letters, digits, '-', '_', and '.'",
        ));
    }
    Ok(())
}

/// Manages container rootfs datasets under a containers root dataset
/// (e.g. `zroot/satl/containers`).
#[derive(Debug, Clone)]
pub struct ContainerFsStore<R = SystemRunner> {
    zfs: Zfs<R>,
    containers_root: String,
}

impl<R: CommandRunner> ContainerFsStore<R> {
    /// Store over `zfs`, holding container datasets under `containers_root`.
    pub fn new(zfs: Zfs<R>, containers_root: impl Into<String>) -> Self {
        Self {
            zfs,
            containers_root: containers_root.into(),
        }
    }

    fn dataset_for(&self, task_id: &str) -> String {
        format!("{}/{task_id}", self.containers_root)
    }

    /// Create the writable rootfs for `task_id` by cloning the image's top
    /// layer snapshot (`<layers_root>/<image_top>@final`); returns the
    /// mountpoint the OCI spec will use as the jail root.
    ///
    /// # Errors
    ///
    /// [`ContainerFsError::InvalidTaskId`] for unusable task IDs;
    /// [`ContainerFsError::Zfs`] when cloning or resolving the mountpoint
    /// fails (full command context inside).
    pub async fn create(
        &self,
        task_id: &str,
        image_top: &ChainId,
        layers_root: &str,
    ) -> Result<PathBuf, ContainerFsError> {
        validate_task_id(task_id)?;
        let dataset = self.dataset_for(task_id);
        let snapshot = format!("{layers_root}/{}@{FINAL_SNAPSHOT}", image_top.hex());
        let span = tracing::info_span!(
            "container_fs_create",
            task_id = %task_id,
            dataset = %dataset,
            image_top = %image_top,
        );
        async {
            self.zfs.clone_snapshot(&snapshot, &dataset, &[]).await?;
            let mountpoint = self.zfs.mountpoint_of(&dataset).await?;
            tracing::info!(mountpoint = %mountpoint.display(), "container rootfs created");
            Ok(mountpoint)
        }
        .instrument(span)
        .await
    }

    /// Destroy the writable rootfs of `task_id` (recursively, so stray
    /// snapshots do not block removal).
    ///
    /// # Errors
    ///
    /// [`ContainerFsError::InvalidTaskId`] for unusable task IDs;
    /// [`ContainerFsError::Zfs`] when `zfs destroy` fails.
    pub async fn destroy(&self, task_id: &str) -> Result<(), ContainerFsError> {
        validate_task_id(task_id)?;
        let dataset = self.dataset_for(task_id);
        let span = tracing::info_span!(
            "container_fs_destroy",
            task_id = %task_id,
            dataset = %dataset,
        );
        async {
            self.zfs.destroy(&dataset, true).await?;
            tracing::info!("container rootfs destroyed");
            Ok(())
        }
        .instrument(span)
        .await
    }

    /// List the task IDs that currently have a container dataset — used by
    /// the M1 startup reconciliation to adopt or destroy leftovers.
    ///
    /// # Errors
    ///
    /// [`ContainerFsError::Zfs`] when listing fails.
    pub async fn list(&self) -> Result<Vec<String>, ContainerFsError> {
        let prefix = format!("{}/", self.containers_root);
        let children = self.zfs.list_children(&self.containers_root).await?;
        Ok(children
            .into_iter()
            .filter_map(|child| child.name.strip_prefix(&prefix).map(str::to_owned))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::chain_id;
    use crate::zfs::MockRunner;

    const LAYERS_ROOT: &str = "zroot/satl/layers";
    const CONTAINERS_ROOT: &str = "zroot/satl/containers";

    fn some_chain_id() -> ChainId {
        chain_id(
            None,
            "sha256:0139c1c77468f75e6763a4612262743bd47a36b26cb2863d662756b3377bb029",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn create_clones_the_image_top_and_returns_the_mountpoint() {
        let top = some_chain_id();
        let dataset = format!("{CONTAINERS_ROOT}/task-1");

        let mock = MockRunner::new();
        mock.push_output(0, "", ""); // clone
        mock.push_output(0, "/var/db/satl/containers/task-1\n", ""); // mountpoint

        let store = ContainerFsStore::new(Zfs::with_runner(&mock), CONTAINERS_ROOT);
        let mountpoint = store.create("task-1", &top, LAYERS_ROOT).await.unwrap();
        assert_eq!(mountpoint, PathBuf::from("/var/db/satl/containers/task-1"));
        assert_eq!(
            mock.calls(),
            [
                format!(
                    "/sbin/zfs clone {LAYERS_ROOT}/{}@final {dataset}",
                    top.hex()
                ),
                format!("/sbin/zfs get -H -p -o value mountpoint {dataset}"),
            ]
        );
    }

    #[tokio::test]
    async fn destroy_removes_the_dataset_recursively() {
        let mock = MockRunner::new();
        mock.push_output(0, "", "");
        let store = ContainerFsStore::new(Zfs::with_runner(&mock), CONTAINERS_ROOT);
        store.destroy("task-1").await.unwrap();
        assert_eq!(
            mock.calls(),
            [format!("/sbin/zfs destroy -r {CONTAINERS_ROOT}/task-1")]
        );
    }

    #[tokio::test]
    async fn list_returns_task_ids_from_child_datasets() {
        let mock = MockRunner::new();
        mock.push_output(
            0,
            &format!(
                "{CONTAINERS_ROOT}\tnone\n\
                 {CONTAINERS_ROOT}/task-1\t/var/db/satl/containers/task-1\n\
                 {CONTAINERS_ROOT}/task-2\t/var/db/satl/containers/task-2\n"
            ),
            "",
        );
        let store = ContainerFsStore::new(Zfs::with_runner(&mock), CONTAINERS_ROOT);
        let ids = store.list().await.unwrap();
        assert_eq!(ids, ["task-1", "task-2"]);
        assert_eq!(
            mock.calls(),
            [format!(
                "/sbin/zfs list -H -p -r -d 1 -o name,mountpoint {CONTAINERS_ROOT}"
            )]
        );
    }

    #[tokio::test]
    async fn invalid_task_ids_are_rejected_before_any_zfs_call() {
        let mock = MockRunner::new();
        let store = ContainerFsStore::new(Zfs::with_runner(&mock), CONTAINERS_ROOT);
        let top = some_chain_id();
        for bad in ["", "a/b", "../evil", ".hidden", "task id", "task@snap"] {
            let err = store.create(bad, &top, LAYERS_ROOT).await.unwrap_err();
            assert!(
                matches!(err, ContainerFsError::InvalidTaskId { .. }),
                "{bad:?}: {err}"
            );
            let err = store.destroy(bad).await.unwrap_err();
            assert!(
                matches!(err, ContainerFsError::InvalidTaskId { .. }),
                "{bad:?}: {err}"
            );
        }
        assert!(mock.calls().is_empty(), "no zfs command may have run");
    }

    #[test]
    fn task_id_validation_accepts_docker_style_ids() {
        validate_task_id("3fa85f64d5717").unwrap();
        validate_task_id("web.1.abc123").unwrap();
        validate_task_id("task_1-x").unwrap();
    }
}
