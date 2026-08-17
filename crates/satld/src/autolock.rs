// SPDX-License-Identifier: BSD-2-Clause
//! The per-manager autolock watcher (Docker's `--autolock`, SWK §12.4).
//!
//! Autolock is a *cluster* setting with a *per-manager* consequence: when
//! the store's Cluster object says `autolock` (or the unlock key rotates),
//! every manager must seal its own DEK under the key from the store and drop
//! the plain key file; when the flag clears, each writes its plain DEK back.
//! A central component cannot do this — the DEK never leaves its manager —
//! so each manager runs this watcher, reconciling its two key files against
//! the store on every Cluster change:
//!
//! ```text
//!   store says locked     plain dek present      ──▶ seal under the store's key, remove dek
//!   store says locked     dek.sealed under old   ──▶ reseal (rotation)
//!   store says unlocked   dek.sealed present     ──▶ write plain dek back, remove dek.sealed
//! ```
//!
//! The in-memory DEK comes from the running [`RaftNode`], never re-read from
//! disk; the key never leaves the store's own encryption. A worker has no
//! raft log and no watcher — nothing on a worker is locked, ever.
//!
//! The reconcile is level-triggered and failure-honest: a failed seal leaves
//! the plain file in place and is logged loudly, because that is the state
//! "this manager boots unlocked" — degraded, not corrupt.

use std::path::{Path, PathBuf};

use satl_cluster::{ClusterStore, Dek};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// What one reconcile did to the key files (the log line's payload, and the
/// unit tests' assertion point).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockAction {
    /// `dek` sealed into `dek.sealed`, plain file removed.
    Sealed,
    /// `dek.sealed` rewritten under a new key (rotation).
    Resealed,
    /// Plain `dek` written back, `dek.sealed` removed (autolock disabled).
    Unsealed,
    /// Already in the desired state.
    Nothing,
}

/// Runs the watcher until `shutdown` is cancelled: reconcile once at
/// startup, then on every Cluster object change (an autolock toggle or a key
/// rotation is one), with a lagged feed falling back to a reconcile —
/// level-triggered like every other loop in this daemon.
pub fn spawn(
    store: ClusterStore,
    dek: Dek,
    raft_dir: PathBuf,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut events = store.watch();
        reconcile(&store, &dek, &raft_dir).await;
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                event = events.recv() => match event {
                    Ok(event) if is_cluster_change(&event) => {
                        reconcile(&store, &dek, &raft_dir).await;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "watch feed lagged; reconciling the autolock state");
                        reconcile(&store, &dek, &raft_dir).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
            }
        }
        tracing::debug!("autolock watcher stopped");
    })
}

/// Whether the event is a Cluster object write — the only thing that can
/// change what this manager's key files should look like.
fn is_cluster_change(event: &satl_core::StoreEvent) -> bool {
    match event {
        satl_core::StoreEvent::Created(object) => {
            matches!(object, satl_core::StoreObject::Cluster(_))
        }
        satl_core::StoreEvent::Updated { new, .. } => {
            matches!(new, satl_core::StoreObject::Cluster(_))
        }
        satl_core::StoreEvent::Removed { .. } | satl_core::StoreEvent::Commit(_) => false,
    }
}

/// Reads the cluster spec and applies it to this manager's key files, off
/// the async runtime (small file I/O, but the DEK file rules say blocking).
async fn reconcile(store: &ClusterStore, dek: &Dek, raft_dir: &Path) {
    let (autolock, key) = {
        let view = store.view();
        view.cluster().map_or((false, None), |cluster| {
            (cluster.spec.autolock, cluster.spec.unlock_key.clone())
        })
    };
    let dek = dek.clone();
    let raft_dir = raft_dir.to_path_buf();
    let result =
        tokio::task::spawn_blocking(move || reconcile_files(&raft_dir, &dek, autolock, key)).await;
    match result {
        Ok(Ok(LockAction::Nothing)) => {}
        Ok(Ok(action)) => tracing::info!(
            action = match action {
                LockAction::Sealed => "sealed",
                LockAction::Resealed => "resealed",
                LockAction::Unsealed => "unsealed",
                LockAction::Nothing => unreachable!(),
            },
            "autolock: this manager's DEK now matches the cluster"
        ),
        Ok(Err(error)) => {
            tracing::warn!(error = %format!("{error:#}"), "autolock reconcile failed");
        }
        Err(error) => tracing::warn!(%error, "autolock reconcile task failed"),
    }
}

/// The whole decision, synchronous and total: bring the two key files in
/// line with (`autolock`, `key`). `dek` is the running manager's own key,
/// held in memory by its raft node.
///
/// The ordering is the safety rule: the replacement file is written (temp +
/// rename + fsync, mode `0600`) **before** the file it replaces is removed,
/// so a crash anywhere in the middle leaves a bootable manager — worst case
/// both files exist, which [`satl_cluster::is_locked`] reads as *unlocked*
/// and the next reconcile cleans up.
fn reconcile_files(
    raft_dir: &Path,
    dek: &Dek,
    autolock: bool,
    key: Option<String>,
) -> anyhow::Result<LockAction> {
    let plain = raft_dir.join(satl_cluster::DEK_FILE);
    let sealed = raft_dir.join(satl_cluster::SEALED_DEK_FILE);
    if !autolock {
        if sealed.exists() {
            dek.store_to(&plain)?;
            std::fs::remove_file(&sealed)?;
            return Ok(LockAction::Unsealed);
        }
        return Ok(LockAction::Nothing);
    }
    let Some(key) = key else {
        // The API never produces this state; a hand-edited store could.
        tracing::warn!("autolock is on but the store holds no unlock key; not sealing");
        return Ok(LockAction::Nothing);
    };
    let kek = satl_cluster::kek_from_unlock_key(&key)
        .map_err(|error| anyhow::anyhow!("the stored unlock key is unusable: {error}"))?;
    if plain.exists() {
        dek.seal_to(&kek, &sealed)?;
        std::fs::remove_file(&plain)?;
        return Ok(LockAction::Sealed);
    }
    // Already sealed: under *this* key? A rotation is the one case where the
    // answer is no, and resealing from memory is always safe.
    if sealed.exists() && Dek::open_sealed(&kek, &sealed).is_ok() {
        return Ok(LockAction::Nothing);
    }
    dek.seal_to(&kek, &sealed)?;
    Ok(LockAction::Resealed)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn key_pair() -> (String, Dek) {
        let key = satl_cluster::generate_unlock_key();
        let kek = satl_cluster::kek_from_unlock_key(&key).expect("generated key parses");
        (key, kek)
    }

    fn dek() -> Dek {
        Dek::from_bytes(&[7_u8; satl_cluster::DEK_LEN])
    }

    #[test]
    fn enabling_seals_the_dek_and_drops_the_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join(satl_cluster::DEK_FILE);
        dek().store_to(&plain).unwrap();
        let (key, kek) = key_pair();

        let action = reconcile_files(dir.path(), &dek(), true, Some(key)).expect("seal");
        assert_eq!(action, LockAction::Sealed);
        assert!(!plain.exists());
        assert!(satl_cluster::is_locked(dir.path()));
        // The sealed file opens with the store's key, to the same DEK.
        let sealed =
            Dek::open_sealed(&kek, &dir.path().join(satl_cluster::SEALED_DEK_FILE)).expect("opens");
        let record = dek().seal(b"log entry");
        assert_eq!(sealed.open(&record).unwrap(), b"log entry");
        let mode = std::fs::metadata(dir.path().join(satl_cluster::SEALED_DEK_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o600, "mode was {mode:04o}");
    }

    #[test]
    fn a_second_reconcile_is_a_no_op_and_a_rotation_reseals() {
        let dir = tempfile::tempdir().unwrap();
        dek()
            .store_to(&dir.path().join(satl_cluster::DEK_FILE))
            .unwrap();
        let (key, _kek) = key_pair();
        reconcile_files(dir.path(), &dek(), true, Some(key)).expect("seal");

        let (rotated, rotated_kek) = key_pair();
        let action =
            reconcile_files(dir.path(), &dek(), true, Some(rotated.clone())).expect("reseal");
        assert_eq!(action, LockAction::Resealed, "a new key reseals");
        let sealed = Dek::open_sealed(
            &rotated_kek,
            &dir.path().join(satl_cluster::SEALED_DEK_FILE),
        )
        .expect("opens under the new key");
        assert_eq!(sealed.open(&dek().seal(b"x")).unwrap(), b"x");

        let action = reconcile_files(dir.path(), &dek(), true, Some(rotated)).expect("steady");
        assert_eq!(action, LockAction::Nothing, "sealed under the current key");
    }

    #[test]
    fn disabling_writes_the_plain_dek_back() {
        let dir = tempfile::tempdir().unwrap();
        let (key, _kek) = key_pair();
        dek()
            .store_to(&dir.path().join(satl_cluster::DEK_FILE))
            .unwrap();
        reconcile_files(dir.path(), &dek(), true, Some(key)).expect("seal");

        let action = reconcile_files(dir.path(), &dek(), false, None).expect("unseal");
        assert_eq!(action, LockAction::Unsealed);
        assert!(!satl_cluster::is_locked(dir.path()));
        let reloaded = Dek::load_or_create(&dir.path().join(satl_cluster::DEK_FILE)).unwrap();
        assert_eq!(reloaded.open(&dek().seal(b"back")).unwrap(), b"back");

        let action = reconcile_files(dir.path(), &dek(), false, None).expect("steady");
        assert_eq!(action, LockAction::Nothing);
    }
}
