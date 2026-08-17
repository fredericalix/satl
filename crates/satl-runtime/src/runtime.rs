// SPDX-License-Identifier: BSD-2-Clause
//! The [`Runtime`] trait (architecture §8.1) and its only implementation,
//! [`OcijailRuntime`] — SatL never implements a container runtime
//! (invariant #6): it generates the OCI bundle and drives `ocijail`.
//!
//! Composition rules this layer owns:
//!
//! - `create` = platform precheck → write `config.json` into the
//!   caller-provided bundle directory → `ocijail create` (mounts happen
//!   here, and the returned pid is what [`crate::exit::wait_for_exit`] must
//!   watch *before* `start` is called);
//! - `delete` = `ocijail delete` **plus** the leak sweep
//!   ([`Mounts::unmount_all_under`] on the rootfs) — ocijail's delete does
//!   not reliably unmount (docs/ocijail.md §4.3/§4.4);
//! - every lifecycle transition runs inside a `tracing` span carrying the
//!   jail id (CLAUDE.md observability).
//!
//! Policy (restart, grace periods, reconciliation decisions) lives in
//! `satl-agent`/`satld`; this crate only exposes mechanism and data —
//! [`Runtime::reconcile_list`] reports what exists, it decides nothing.

use std::future::Future;
use std::path::{Path, PathBuf};

use tracing::Instrument as _;

use crate::error::RuntimeError;
use crate::mounts::Mounts;
use crate::ocijail::{ExecOutcome, ExecSpec, Features, Ocijail, OcijailError, RuntimeState};
use crate::runner::{CommandRunner, CreateStdio, SystemRunner};
use crate::spec::BundleSpec;
use crate::{precheck, spec};

/// Result of a successful [`Runtime::create`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedContainer {
    /// The container process pid (from ocijail's `--pid-file`). Arm
    /// [`crate::exit::wait_for_exit`] on it before calling `start`.
    pub pid: i32,
    /// Where the pid file lives (inside the bundle directory).
    pub pid_file: PathBuf,
}

/// Result of a successful [`Runtime::delete`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteReport {
    /// Mountpoints that were still mounted under the rootfs after
    /// `ocijail delete` and had to be swept (docs/ocijail.md §4.4).
    pub leaked_mounts_cleaned: Vec<PathBuf>,
}

/// Thin, typed driver for the OCI runtime binary (architecture §8.1).
///
/// Not dyn-compatible (async methods); consumers stay generic over
/// `T: Runtime`, which also keeps them testable with a fake.
pub trait Runtime: Send + Sync {
    /// Precheck the platform, write `config.json` into `bundle_dir` (the
    /// caller creates and owns that directory) and run `ocijail create`.
    /// `stdio` handles become the container's stdio for its whole life;
    /// `console_socket` is required iff `spec.terminal`.
    fn create(
        &self,
        id: &str,
        bundle_dir: &Path,
        spec: &BundleSpec,
        console_socket: Option<&Path>,
        stdio: CreateStdio,
    ) -> impl Future<Output = Result<CreatedContainer, RuntimeError>> + Send;

    /// `ocijail start`: let the created container process exec the workload.
    fn start(&self, id: &str) -> impl Future<Output = Result<(), RuntimeError>> + Send;

    /// Send a numeric signal to the container init process (only — see
    /// [`Ocijail::kill`] for the `--all` caveat).
    fn kill(&self, id: &str, signal: i32) -> impl Future<Output = Result<(), RuntimeError>> + Send;

    /// `ocijail delete` followed by the mount-leak sweep under `rootfs`.
    /// Safe to call for ids ocijail no longer knows (the sweep still runs).
    fn delete(
        &self,
        id: &str,
        rootfs: &Path,
        force: bool,
    ) -> impl Future<Output = Result<DeleteReport, RuntimeError>> + Send;

    /// `ocijail state` (also flips a dead container to `stopped`).
    fn state(&self, id: &str) -> impl Future<Output = Result<RuntimeState, RuntimeError>> + Send;

    /// Non-detached `ocijail exec`; returns the process's exit code
    /// (healthcheck probes).
    fn exec(
        &self,
        id: &str,
        process: &ExecSpec,
        stdio: CreateStdio,
    ) -> impl Future<Output = Result<ExecOutcome, RuntimeError>> + Send;

    /// `ocijail features` (informational).
    fn features(&self) -> impl Future<Output = Result<Features, RuntimeError>> + Send;

    /// Everything ocijail's state db knows, with full state (annotations,
    /// jid) per container — the data source for satld's startup adoption
    /// pass. Note this cannot see jails whose state entry was lost
    /// (docs/ocijail.md §4.4); reconciliation must additionally consult
    /// `jls` and the mount table.
    fn reconcile_list(
        &self,
    ) -> impl Future<Output = Result<Vec<RuntimeState>, RuntimeError>> + Send;
}

/// The ocijail-backed [`Runtime`].
#[derive(Debug, Clone)]
pub struct OcijailRuntime<R: CommandRunner = SystemRunner> {
    ocijail: Ocijail<R>,
    mounts: Mounts<R>,
    runner: R,
}

impl OcijailRuntime<SystemRunner> {
    /// Production runtime: real binaries, satld-owned `--root` state db and
    /// exec scratch directory.
    pub fn system(state_root: impl Into<PathBuf>, scratch_dir: impl Into<PathBuf>) -> Self {
        Self::with_runner(SystemRunner, state_root, scratch_dir)
    }
}

impl<R: CommandRunner + Clone> OcijailRuntime<R> {
    /// Runtime with an injected [`CommandRunner`] (tests).
    pub fn with_runner(
        runner: R,
        state_root: impl Into<PathBuf>,
        scratch_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            ocijail: Ocijail::with_runner(runner.clone(), state_root, scratch_dir),
            mounts: Mounts::with_runner(runner.clone()),
            runner,
        }
    }

    /// Access the underlying ocijail wrapper (integration tests, detached
    /// exec).
    #[must_use]
    pub fn ocijail(&self) -> &Ocijail<R> {
        &self.ocijail
    }

    /// Access the mount wrapper (startup reconciliation sweeps).
    #[must_use]
    pub fn mounts(&self) -> &Mounts<R> {
        &self.mounts
    }

    async fn write_bundle_config(
        &self,
        id: &str,
        bundle_dir: &Path,
        bundle: &BundleSpec,
    ) -> Result<(), RuntimeError> {
        let path = bundle_dir.join("config.json");
        let write_err = |source: std::io::Error| RuntimeError::WriteBundle {
            jail_id: id.to_owned(),
            path: path.clone(),
            source,
        };
        let config = spec::build_config(bundle);
        let mut json = serde_json::to_vec_pretty(&config).map_err(|e| write_err(e.into()))?;
        json.push(b'\n');
        tokio::fs::write(&path, json).await.map_err(write_err)?;
        Ok(())
    }
}

impl<R: CommandRunner + Clone> Runtime for OcijailRuntime<R> {
    async fn create(
        &self,
        id: &str,
        bundle_dir: &Path,
        bundle: &BundleSpec,
        console_socket: Option<&Path>,
        stdio: CreateStdio,
    ) -> Result<CreatedContainer, RuntimeError> {
        let span = tracing::info_span!("jail_create", jail_id = %id, platform = ?bundle.platform);
        async {
            if !bundle.rootfs.is_absolute() {
                return Err(RuntimeError::RootfsNotAbsolute {
                    jail_id: id.to_owned(),
                    path: bundle.rootfs.clone(),
                });
            }
            precheck::check_platform(&self.runner, id, bundle.platform, &bundle.args).await?;
            self.write_bundle_config(id, bundle_dir, bundle).await?;
            let pid_file = bundle_dir.join("pid");
            let pid = self
                .ocijail
                .create(id, bundle_dir, &pid_file, console_socket, stdio)
                .await?;
            tracing::info!(pid, rootfs = %bundle.rootfs.display(), "jail created");
            Ok(CreatedContainer { pid, pid_file })
        }
        .instrument(span)
        .await
    }

    async fn start(&self, id: &str) -> Result<(), RuntimeError> {
        let span = tracing::info_span!("jail_start", jail_id = %id);
        async {
            self.ocijail.start(id).await?;
            tracing::info!("jail started");
            Ok(())
        }
        .instrument(span)
        .await
    }

    async fn kill(&self, id: &str, signal: i32) -> Result<(), RuntimeError> {
        let span = tracing::info_span!("jail_kill", jail_id = %id, signal);
        async {
            self.ocijail.kill(id, signal).await?;
            tracing::info!("signal sent to jail init process");
            Ok(())
        }
        .instrument(span)
        .await
    }

    async fn delete(
        &self,
        id: &str,
        rootfs: &Path,
        force: bool,
    ) -> Result<DeleteReport, RuntimeError> {
        let span = tracing::info_span!("jail_delete", jail_id = %id, force);
        async {
            self.ocijail.delete(id, force).await?;
            // The leak rule (docs/ocijail.md §4.4): delete does not reliably
            // unmount; sweep everything still mounted below the rootfs.
            let leaked_mounts_cleaned = self.mounts.unmount_all_under(rootfs).await?;
            if leaked_mounts_cleaned.is_empty() {
                tracing::info!("jail deleted; no leaked mounts");
            } else {
                tracing::warn!(
                    leaked = leaked_mounts_cleaned.len(),
                    mounts = ?leaked_mounts_cleaned,
                    "jail deleted; swept mounts ocijail delete leaked"
                );
            }
            Ok(DeleteReport {
                leaked_mounts_cleaned,
            })
        }
        .instrument(span)
        .await
    }

    async fn state(&self, id: &str) -> Result<RuntimeState, RuntimeError> {
        Ok(self.ocijail.state(id).await?)
    }

    async fn exec(
        &self,
        id: &str,
        process: &ExecSpec,
        stdio: CreateStdio,
    ) -> Result<ExecOutcome, RuntimeError> {
        let span = tracing::info_span!("jail_exec", jail_id = %id);
        async {
            let outcome = self.ocijail.exec(id, process, stdio).await?;
            tracing::debug!(exit_code = ?outcome.exit_code, "exec finished");
            Ok(outcome)
        }
        .instrument(span)
        .await
    }

    async fn features(&self) -> Result<Features, RuntimeError> {
        Ok(self.ocijail.features().await?)
    }

    async fn reconcile_list(&self) -> Result<Vec<RuntimeState>, RuntimeError> {
        let entries = self.ocijail.list().await?;
        let mut states = Vec::with_capacity(entries.len());
        for entry in entries {
            match self.ocijail.state(&entry.id).await {
                Ok(state) => states.push(state),
                // Deleted between list and state: fine, it is gone.
                Err(error @ OcijailError::NotFound { .. }) => {
                    tracing::debug!(jail_id = %entry.id, %error, "container vanished during reconcile listing");
                }
                // Foreign junk in the state db (not a SatL id): report, skip.
                Err(error @ OcijailError::InvalidId { .. }) => {
                    tracing::warn!(jail_id = %entry.id, %error, "skipping non-SatL entry in ocijail state db");
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(states)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;
    use crate::spec::{BundleSpec, ImagePlatform};
    use std::collections::BTreeMap;

    fn bundle_spec(rootfs: &Path) -> BundleSpec {
        BundleSpec {
            rootfs: rootfs.to_owned(),
            readonly_rootfs: false,
            args: vec!["/bin/sh".to_owned(), "-c".to_owned(), "true".to_owned()],
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

    fn runtime<'m>(mock: &'m MockRunner, scratch: &Path) -> OcijailRuntime<&'m MockRunner> {
        OcijailRuntime::with_runner(mock, "/var/run/satld/ocijail", scratch)
    }

    #[tokio::test]
    async fn create_writes_config_then_creates() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_dir = dir.path().join("bundle");
        std::fs::create_dir(&bundle_dir).unwrap();
        std::fs::write(bundle_dir.join("pid"), "4242\n").unwrap();
        let mock = MockRunner::new();
        mock.push_output(0, "", ""); // ocijail create
        let rt = runtime(&mock, dir.path());
        let created = rt
            .create(
                "t1",
                &bundle_dir,
                &bundle_spec(Path::new("/var/db/satl/containers/t1")),
                None,
                CreateStdio::null(),
            )
            .await
            .unwrap();
        assert_eq!(created.pid, 4242);
        assert_eq!(created.pid_file, bundle_dir.join("pid"));
        // FreeBSD platform: no sysctl probe; exactly one external command.
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].starts_with("/usr/local/bin/ocijail --root /var/run/satld/ocijail create -b"),
            "{calls:?}"
        );
        // The bundle got a config.json containing only consumed fields.
        let config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(bundle_dir.join("config.json")).unwrap())
                .unwrap();
        assert_eq!(config["ociVersion"], "1.0.2");
        assert_eq!(config["root"]["path"], "/var/db/satl/containers/t1");
        assert!(config.get("linux").is_none());
    }

    #[tokio::test]
    async fn create_rejects_relative_rootfs_before_any_command() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        let rt = runtime(&mock, dir.path());
        let err = rt
            .create(
                "t1",
                dir.path(),
                &bundle_spec(Path::new("containers/t1")),
                None,
                CreateStdio::null(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, RuntimeError::RootfsNotAbsolute { .. }),
            "{err}"
        );
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn create_linux_rejects_systemd_without_running_anything() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        let rt = runtime(&mock, dir.path());
        let mut spec = bundle_spec(Path::new("/var/db/satl/containers/t1"));
        spec.platform = ImagePlatform::Linux;
        spec.args = vec!["/usr/lib/systemd/systemd".to_owned()];
        let err = rt
            .create("t1", dir.path(), &spec, None, CreateStdio::null())
            .await
            .unwrap_err();
        assert!(
            matches!(err, RuntimeError::EntrypointNeedsInit { .. }),
            "{err}"
        );
        assert!(mock.calls().is_empty());
        assert!(!dir.path().join("config.json").exists());
    }

    #[tokio::test]
    async fn delete_sweeps_leaked_mounts_deepest_first() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_output(0, "", ""); // ocijail delete
        let listing = "devfs\t\t\t/r/t1/dev devfs\trw\t\t0 0\n\
                       fdescfs\t\t\t/r/t1/dev/fd fdescfs\trw\t\t0 0\n";
        mock.push_output(0, listing, ""); // mount -p
        mock.push_output(0, "", ""); // umount /r/t1/dev/fd
        mock.push_output(0, "", ""); // umount /r/t1/dev
        let rt = runtime(&mock, dir.path());
        let report = rt.delete("t1", Path::new("/r/t1"), true).await.unwrap();
        assert_eq!(
            report.leaked_mounts_cleaned,
            [PathBuf::from("/r/t1/dev/fd"), PathBuf::from("/r/t1/dev")]
        );
        assert_eq!(
            mock.calls(),
            [
                "/usr/local/bin/ocijail --root /var/run/satld/ocijail delete --force t1",
                "/sbin/mount -p",
                "/sbin/umount /r/t1/dev/fd",
                "/sbin/umount /r/t1/dev",
            ]
        );
    }

    #[tokio::test]
    async fn reconcile_list_states_every_container_and_skips_vanished() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_output(
            0,
            r#"[{"bundle":"/b/a","id":"a1","pid":10,"status":"running"},
                {"bundle":"/b/b","id":"b2","pid":0,"status":"stopped"}]"#,
            "",
        );
        mock.push_output(
            0,
            r#"{"annotations":{"org.freebsd.jail.jid":"7"},"bundle":"/b/a","id":"a1","ociVersion":"1.0.2","pid":10,"status":"running"}"#,
            "",
        );
        // b2 was deleted between list and state.
        mock.push_output(
            1,
            "",
            "2026-08-09T00:00:00000000000Z: opening state lock: No such file or directory\n",
        );
        let rt = runtime(&mock, dir.path());
        let states = rt.reconcile_list().await.unwrap();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].id, "a1");
        assert_eq!(states[0].jid(), Some(7));
    }
}
