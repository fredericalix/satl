// SPDX-License-Identifier: BSD-2-Clause
//! The worker's local task database (architecture §7.2, SWK §14.3).
//!
//! One CBOR file per task at `<state_dir>/worker/tasks/<task_id>` holding the
//! task snapshot **and** the last status the agent reported. Every write is
//! write-to-temp + atomic rename, so a crash mid-write can never leave a
//! half-written record: the reader either sees the previous version or the
//! new one.
//!
//! Why it exists (SWK §14.3): after a restart the agent resumes each task at
//! the right lifecycle point instead of re-running work, and re-reports every
//! persisted status to whichever manager it registers with next. **The local
//! status is canonical** when the manager's copy lags (architecture §7.2), so
//! [`TaskDb::put_task`] never lets an incoming task snapshot overwrite it.
//!
//! Like SwarmKit's `PutTaskStatus`, [`TaskDb::put_status`] deliberately does
//! not create a missing entry: a status arriving after the task was removed
//! must not resurrect it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use satl_core::{Id, Task, TaskStatus};
use serde::{Deserialize, Serialize};

/// Counter making temp-file names unique within the process.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One task's persisted record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskRecord {
    /// The task as last assigned by a manager.
    pub task: Task,
    /// The last status the agent produced — canonical over `task.status`.
    pub status: TaskStatus,
}

/// Failure reading or writing the local task DB.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// Filesystem failure.
    #[error("task db: {what} failed at {path}: {source}")]
    Io {
        /// What was being attempted.
        what: &'static str,
        /// The path involved.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A record could not be encoded.
    #[error("task db: encoding the record for task {task_id} failed: {reason}")]
    Encode {
        /// The task whose record failed.
        task_id: String,
        /// The CBOR error text.
        reason: String,
    },

    /// A record on disk is not decodable (truncated by something other than
    /// our own writes, or written by an incompatible build).
    #[error("task db: record {path} is corrupt and was ignored: {reason}")]
    Decode {
        /// The record path.
        path: PathBuf,
        /// The CBOR error text.
        reason: String,
    },
}

/// The per-node task database. Cheap to clone-by-`Arc`; `satld` keeps one.
#[derive(Debug, Clone)]
pub struct TaskDb {
    dir: PathBuf,
}

impl TaskDb {
    /// Open (creating) the database under `state_dir`.
    ///
    /// # Errors
    ///
    /// [`DbError::Io`] when the directory cannot be created.
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self, DbError> {
        let dir = state_dir.as_ref().join("worker").join("tasks");
        std::fs::create_dir_all(&dir).map_err(|source| DbError::Io {
            what: "creating the task db directory",
            path: dir.clone(),
            source,
        })?;
        Ok(Self { dir })
    }

    /// The directory holding the records.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_for(&self, task_id: &Id) -> PathBuf {
        self.dir.join(task_id.as_str())
    }

    /// Write `record` atomically (temp file in the same directory, then
    /// rename).
    ///
    /// # Errors
    ///
    /// [`DbError::Encode`] or [`DbError::Io`].
    pub async fn put(&self, record: &TaskRecord) -> Result<(), DbError> {
        let task_id = record.task.id.clone();
        let mut bytes = Vec::new();
        ciborium::into_writer(record, &mut bytes).map_err(|error| DbError::Encode {
            task_id: task_id.as_str().to_owned(),
            reason: error.to_string(),
        })?;
        let final_path = self.path_for(&task_id);
        let unique = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self.dir.join(format!(
            ".tmp-{}-{}-{unique}",
            task_id.as_str(),
            std::process::id()
        ));
        tokio::fs::write(&tmp_path, &bytes)
            .await
            .map_err(|source| DbError::Io {
                what: "writing the staging record",
                path: tmp_path.clone(),
                source,
            })?;
        tokio::fs::rename(&tmp_path, &final_path)
            .await
            .map_err(|source| DbError::Io {
                what: "renaming the staging record into place",
                path: final_path,
                source,
            })?;
        Ok(())
    }

    /// Persist a newly assigned (or updated) task, **keeping** any status
    /// already on disk: the local status is canonical (architecture §7.2).
    ///
    /// # Errors
    ///
    /// See [`TaskDb::put`].
    pub async fn put_task(&self, task: &Task) -> Result<TaskStatus, DbError> {
        let status = match self.get(&task.id).await? {
            Some(record) => record.status,
            None => task.status.clone(),
        };
        self.put(&TaskRecord {
            task: task.clone(),
            status: status.clone(),
        })
        .await?;
        Ok(status)
    }

    /// Update the status of an existing record. A missing record is a no-op
    /// (SWK §14.3: never resurrect a removed task); returns whether anything
    /// was written.
    ///
    /// # Errors
    ///
    /// See [`TaskDb::put`].
    pub async fn put_status(&self, task_id: &Id, status: &TaskStatus) -> Result<bool, DbError> {
        let Some(mut record) = self.get(task_id).await? else {
            return Ok(false);
        };
        record.status = status.clone();
        self.put(&record).await?;
        Ok(true)
    }

    /// Read one record; `None` when the task is not in the db.
    ///
    /// # Errors
    ///
    /// [`DbError::Io`] on read failure, [`DbError::Decode`] on a corrupt
    /// record.
    pub async fn get(&self, task_id: &Id) -> Result<Option<TaskRecord>, DbError> {
        let path = self.path_for(task_id);
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(DbError::Io {
                    what: "reading a task record",
                    path,
                    source,
                });
            }
        };
        decode(&path, &bytes).map(Some)
    }

    /// [`Self::get`] with blocking I/O, for callers that need a synchronous
    /// answer — the log follower's "has this task finished?" probe, which is
    /// a plain `Fn` closure polled once per follow round. The records are a
    /// few kilobytes, so the read is bounded and rare; anything hotter must
    /// use the async accessors.
    #[must_use]
    pub fn get_blocking(&self, task_id: &Id) -> Option<TaskRecord> {
        let path = self.path_for(task_id);
        let bytes = std::fs::read(&path).ok()?;
        decode(&path, &bytes).ok()
    }

    /// Every record in the db. Corrupt records are logged and skipped so one
    /// bad file cannot stop the agent from starting.
    ///
    /// # Errors
    ///
    /// [`DbError::Io`] when the directory cannot be enumerated.
    pub async fn list(&self) -> Result<Vec<TaskRecord>, DbError> {
        let mut entries = tokio::fs::read_dir(&self.dir)
            .await
            .map_err(|source| DbError::Io {
                what: "listing the task db",
                path: self.dir.clone(),
                source,
            })?;
        let mut records = Vec::new();
        loop {
            let entry = entries.next_entry().await.map_err(|source| DbError::Io {
                what: "listing the task db",
                path: self.dir.clone(),
                source,
            })?;
            let Some(entry) = entry else { break };
            let path = entry.path();
            // Staging files from an interrupted write.
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".tmp-"))
            {
                if let Err(error) = tokio::fs::remove_file(&path).await {
                    tracing::warn!(path = %path.display(), %error, "cannot remove a stale task db staging file");
                }
                continue;
            }
            let bytes = tokio::fs::read(&path).await.map_err(|source| DbError::Io {
                what: "reading a task record",
                path: path.clone(),
                source,
            })?;
            match decode(&path, &bytes) {
                Ok(record) => records.push(record),
                Err(error) => tracing::error!(%error, "skipping a corrupt task record"),
            }
        }
        records.sort_by(|a, b| a.task.id.as_str().cmp(b.task.id.as_str()));
        Ok(records)
    }

    /// Delete a record. Missing is fine.
    ///
    /// # Errors
    ///
    /// [`DbError::Io`] on any failure other than "not found".
    pub async fn remove(&self, task_id: &Id) -> Result<(), DbError> {
        let path = self.path_for(task_id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(DbError::Io {
                what: "removing a task record",
                path,
                source,
            }),
        }
    }
}

fn decode(path: &Path, bytes: &[u8]) -> Result<TaskRecord, DbError> {
    ciborium::from_reader(bytes).map_err(|error: ciborium::de::Error<std::io::Error>| {
        DbError::Decode {
            path: path.to_owned(),
            reason: error.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;
    use satl_core::{TaskState, TaskStatus};

    fn db() -> (tempfile::TempDir, TaskDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = TaskDb::open(dir.path()).unwrap();
        (dir, db)
    }

    #[tokio::test]
    async fn open_creates_the_pinned_layout() {
        let (dir, db) = db();
        assert_eq!(db.dir(), dir.path().join("worker").join("tasks"));
        assert!(db.dir().is_dir());
    }

    #[tokio::test]
    async fn roundtrip_preserves_the_task_and_the_status() {
        let (_dir, db) = db();
        let task = testing::task();
        let status = TaskStatus::new(TaskState::Running, "started");
        db.put(&TaskRecord {
            task: task.clone(),
            status: status.clone(),
        })
        .await
        .unwrap();

        let back = db.get(&task.id).await.unwrap().unwrap();
        assert_eq!(back.task, task);
        assert_eq!(back.status.state, status.state);
        assert_eq!(back.status.message, status.message);
        // The record file is named exactly by the task id (pinned contract).
        assert!(db.dir().join(task.id.as_str()).is_file());
    }

    #[tokio::test]
    async fn missing_records_read_as_none_and_remove_is_idempotent() {
        let (_dir, db) = db();
        let task = testing::task();
        assert!(db.get(&task.id).await.unwrap().is_none());
        db.remove(&task.id).await.unwrap();
        db.remove(&task.id).await.unwrap();
    }

    /// The local status is canonical: a re-assigned task must not drag the
    /// manager's stale status back over ours (architecture §7.2).
    #[tokio::test]
    async fn put_task_keeps_the_persisted_status() {
        let (_dir, db) = db();
        let mut task = testing::task();
        let local = TaskStatus::new(TaskState::Running, "started");
        db.put(&TaskRecord {
            task: task.clone(),
            status: local.clone(),
        })
        .await
        .unwrap();

        // The manager re-sends the task carrying its own (older) status.
        task.status = TaskStatus::new(TaskState::Assigned, "assigned");
        task.desired_state = satl_core::DesiredState::Shutdown;
        let kept = db.put_task(&task).await.unwrap();
        assert_eq!(kept.state, TaskState::Running);

        let back = db.get(&task.id).await.unwrap().unwrap();
        assert_eq!(back.status.state, TaskState::Running);
        // ...while the new task definition *is* stored.
        assert_eq!(back.task.desired_state, satl_core::DesiredState::Shutdown);
    }

    #[tokio::test]
    async fn put_task_seeds_the_status_for_a_brand_new_task() {
        let (_dir, db) = db();
        let task = testing::task();
        let seeded = db.put_task(&task).await.unwrap();
        assert_eq!(seeded.state, TaskState::Assigned);
    }

    /// SWK §14.3: a status for a task that is gone must not resurrect it.
    #[tokio::test]
    async fn put_status_never_creates_a_missing_record() {
        let (_dir, db) = db();
        let task = testing::task();
        let status = TaskStatus::new(TaskState::Running, "started");
        assert!(!db.put_status(&task.id, &status).await.unwrap());
        assert!(db.get(&task.id).await.unwrap().is_none());

        db.put_task(&task).await.unwrap();
        assert!(db.put_status(&task.id, &status).await.unwrap());
        assert_eq!(
            db.get(&task.id).await.unwrap().unwrap().status.state,
            TaskState::Running
        );
    }

    /// Atomic rename semantics: overwriting with a *shorter* payload must not
    /// leave a tail of the previous record behind, and no staging file may
    /// survive a successful write.
    #[tokio::test]
    async fn writes_are_atomic_and_leave_no_staging_files() {
        let (_dir, db) = db();
        let mut task = testing::task();
        task.spec.container.env = (0..500).map(|n| format!("VAR{n}=value{n}")).collect();
        db.put_task(&task).await.unwrap();
        let big = tokio::fs::metadata(db.dir().join(task.id.as_str()))
            .await
            .unwrap()
            .len();

        task.spec.container.env.clear();
        db.put(&TaskRecord {
            task: task.clone(),
            status: TaskStatus::new(TaskState::Ready, "prepared"),
        })
        .await
        .unwrap();
        let small = tokio::fs::metadata(db.dir().join(task.id.as_str()))
            .await
            .unwrap()
            .len();
        assert!(small < big, "record did not shrink: {small} vs {big}");
        // Decodes cleanly, i.e. no trailing garbage from the bigger record.
        let back = db.get(&task.id).await.unwrap().unwrap();
        assert!(back.task.spec.container.env.is_empty());

        let mut names = Vec::new();
        let mut entries = tokio::fs::read_dir(db.dir()).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        assert_eq!(names, [task.id.as_str()]);
    }

    #[tokio::test]
    async fn list_is_sorted_skips_corrupt_records_and_sweeps_staging_files() {
        let (_dir, db) = db();
        let mut first = testing::task();
        first.id = "0aaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap();
        let mut second = testing::task();
        second.id = "1bbbbbbbbbbbbbbbbbbbbbbbb".parse().unwrap();
        db.put_task(&first).await.unwrap();
        db.put_task(&second).await.unwrap();
        tokio::fs::write(db.dir().join("2ccccccccccccccccccccccccc"), b"not cbor")
            .await
            .unwrap();
        tokio::fs::write(db.dir().join(".tmp-interrupted"), b"partial")
            .await
            .unwrap();

        let records = db.list().await.unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| record.task.id.as_str())
                .collect::<Vec<_>>(),
            [first.id.as_str(), second.id.as_str()]
        );
        assert!(
            !db.dir().join(".tmp-interrupted").exists(),
            "stale staging files must be swept"
        );
    }

    #[tokio::test]
    async fn a_corrupt_record_is_a_typed_error_not_a_panic() {
        let (_dir, db) = db();
        let task = testing::task();
        tokio::fs::write(db.dir().join(task.id.as_str()), b"\xff\xff\xff")
            .await
            .unwrap();
        let err = db.get(&task.id).await.unwrap_err();
        assert!(matches!(err, DbError::Decode { .. }), "{err}");
        assert!(err.to_string().contains("corrupt"), "{err}");
    }
}
