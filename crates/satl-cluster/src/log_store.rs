// SPDX-License-Identifier: BSD-2-Clause
//! Raft log persistence over redb (architecture §6.3).
//!
//! **Backend decision (architecture §17 open question 1): redb.** A
//! purpose-built append-only segment log was the alternative; redb wins on
//! being boring: pure Rust (no C toolchain quirks on FreeBSD), ACID with
//! synchronous durable commits (commit returns after fsync), single-file,
//! MVCC readers that never block the writer, and crash recovery we do not
//! have to write ourselves. The Raft log write pattern (append, truncate-from,
//! purge-to, point/range reads) maps directly onto one ordered `u64 → bytes`
//! table. Throughput is bounded by one fsync per append batch — the same
//! bound a hand-rolled WAL would have.
//!
//! Layout:
//!
//! - table `logs`: `u64` log index → sealed entry bytes. The value is the
//!   whole CBOR-serialized [`openraft::Entry`] sealed with the node DEK
//!   (architecture §12.4) — index/term stay queryable via the entry itself
//!   after unsealing, and nothing about an entry (including membership and
//!   secret payloads inside proposals) touches disk in the clear. SwarmKit
//!   encrypts whole WAL records the same way.
//! - table `meta`: `str` key → sealed CBOR value; keys [`META_VOTE`],
//!   [`META_LAST_PURGED`], [`META_COMMITTED`].
//!
//! Durability rules from the [`RaftLogStorage`] contract: `save_vote` returns
//! only after the vote is on disk; `append` invokes the flush callback only
//! after a durable commit. redb commits are synchronous, so every redb
//! transaction runs inside [`tokio::task::spawn_blocking`] (CLAUDE.md
//! invariant #4: no blocking I/O on the async runtime).

// Triaged pedantic allow: `StorageError<u64>` (~200 bytes) is the error type
// imposed by openraft's storage trait signatures — it cannot be boxed here,
// and these are cold error paths.
#![allow(clippy::result_large_err)]

use std::ops::{Bound, RangeBounds};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openraft::storage::{LogFlushed, LogState, RaftLogStorage};
use openraft::{
    AnyError, ErrorSubject, ErrorVerb, LogId, OptionalSend, RaftLogReader, StorageError,
    StorageIOError, Vote,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::crypto::Dek;
use crate::types::TypeConfig;

/// Raft log entries: log index → sealed CBOR entry.
const LOGS_TABLE: TableDefinition<'_, u64, &[u8]> = TableDefinition::new("logs");

/// Log metadata: key → sealed CBOR value.
const META_TABLE: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("meta");

/// Meta key: the last saved [`Vote`].
const META_VOTE: &str = "vote";

/// Meta key: the last purged [`LogId`] (compaction watermark).
const META_LAST_PURGED: &str = "last_purged";

/// Meta key: the last committed [`LogId`] saved by openraft.
const META_COMMITTED: &str = "committed";

/// Filename of the redb database inside the raft directory.
pub const LOG_FILE_NAME: &str = "log.redb";

type Entry = openraft::Entry<TypeConfig>;

/// Error opening the log store database.
#[derive(Debug, thiserror::Error)]
pub enum LogStoreError {
    /// redb could not open/create the database file.
    #[error("open raft log database {path}: {source}")]
    Open {
        /// The database file.
        path: PathBuf,
        /// Underlying redb error.
        #[source]
        source: Box<redb::Error>,
    },
    /// The initial transaction creating the tables failed.
    #[error("initialize raft log tables in {path}: {source}")]
    Init {
        /// The database file.
        path: PathBuf,
        /// Underlying redb error.
        #[source]
        source: Box<redb::Error>,
    },
}

/// Raft log storage over redb. Cheap to clone: clones share the database
/// handle and DEK, which is how the log reader hands copies to replication
/// tasks.
#[derive(Debug, Clone)]
pub struct LogStore {
    db: Arc<Database>,
    dek: Dek,
    /// Database file path, carried for error messages (SRE rule: say what
    /// file the failed operation touched).
    path: Arc<PathBuf>,
}

impl LogStore {
    /// Opens (or creates) the log database at `<dir>/log.redb`.
    ///
    /// Synchronous (redb recovery may replay the file): callers on the async
    /// runtime wrap this in `spawn_blocking`.
    pub fn open(dir: &Path, dek: Dek) -> Result<Self, LogStoreError> {
        let path = dir.join(LOG_FILE_NAME);
        let db = Database::create(&path).map_err(|e| LogStoreError::Open {
            path: path.clone(),
            source: Box::new(e.into()),
        })?;
        // Create both tables up front so read transactions never race a
        // missing table.
        let init = || -> Result<(), redb::Error> {
            let txn = db.begin_write()?;
            txn.open_table(LOGS_TABLE)?;
            txn.open_table(META_TABLE)?;
            txn.commit()?;
            Ok(())
        };
        init().map_err(|e| LogStoreError::Init {
            path: path.clone(),
            source: Box::new(e),
        })?;
        Ok(Self {
            db: Arc::new(db),
            dek,
            path: Arc::new(path),
        })
    }

    /// Serializes and seals one log entry for storage.
    fn encode_entry(&self, entry: &Entry) -> Result<Vec<u8>, StorageError<u64>> {
        let mut plain = Vec::new();
        ciborium::ser::into_writer(entry, &mut plain).map_err(|e| {
            StorageError::from(StorageIOError::write_log_entry(
                entry.log_id,
                AnyError::new(&e),
            ))
        })?;
        Ok(self.dek.seal(&plain))
    }

    /// Unseals and deserializes one log entry read from storage.
    fn decode_entry(&self, index: u64, sealed: &[u8]) -> Result<Entry, StorageError<u64>> {
        let plain = self.dek.open(sealed).map_err(|e| {
            StorageIOError::new(
                ErrorSubject::LogIndex(index),
                ErrorVerb::Read,
                AnyError::error(format!(
                    "unseal log entry {index} in {}: {e}",
                    self.path.display()
                )),
            )
        })?;
        ciborium::de::from_reader(plain.as_slice()).map_err(|e| {
            StorageIOError::new(
                ErrorSubject::LogIndex(index),
                ErrorVerb::Read,
                AnyError::error(format!(
                    "decode log entry {index} in {}: {e}",
                    self.path.display()
                )),
            )
            .into()
        })
    }

    /// Seals a serde value for the meta table.
    fn encode_meta<T: serde::Serialize>(
        &self,
        key: &'static str,
        value: &T,
    ) -> Result<Vec<u8>, StorageError<u64>> {
        let mut plain = Vec::new();
        ciborium::ser::into_writer(value, &mut plain).map_err(|e| {
            self.meta_err(key, ErrorVerb::Write, &format!("encode meta {key}: {e}"))
        })?;
        Ok(self.dek.seal(&plain))
    }

    /// Unseals and decodes a meta table value.
    fn decode_meta<T: serde::de::DeserializeOwned>(
        &self,
        key: &'static str,
        sealed: &[u8],
    ) -> Result<T, StorageError<u64>> {
        let plain = self
            .dek
            .open(sealed)
            .map_err(|e| self.meta_err(key, ErrorVerb::Read, &format!("unseal meta {key}: {e}")))?;
        ciborium::de::from_reader(plain.as_slice())
            .map_err(|e| self.meta_err(key, ErrorVerb::Read, &format!("decode meta {key}: {e}")))
    }

    /// Builds a storage error for a meta-table operation, naming the file.
    fn meta_err(&self, key: &'static str, verb: ErrorVerb, msg: &str) -> StorageError<u64> {
        let subject = if key == META_VOTE {
            ErrorSubject::Vote
        } else {
            ErrorSubject::Store
        };
        StorageIOError::new(
            subject,
            verb,
            AnyError::error(format!("{msg} (database {})", self.path.display())),
        )
        .into()
    }

    /// Builds a storage error from a redb error, naming the operation and
    /// file.
    fn db_err(
        &self,
        subject: ErrorSubject<u64>,
        verb: ErrorVerb,
        op: &str,
        err: &redb::Error,
    ) -> StorageError<u64> {
        StorageIOError::new(
            subject,
            verb,
            AnyError::error(format!("{op} (database {}): {err}", self.path.display())),
        )
        .into()
    }

    /// Runs a blocking redb operation on the blocking pool.
    async fn blocking<T, F>(&self, op: &'static str, f: F) -> Result<T, StorageError<u64>>
    where
        T: Send + 'static,
        F: FnOnce(LogStore) -> Result<T, StorageError<u64>> + Send + 'static,
    {
        let this = self.clone();
        tokio::task::spawn_blocking(move || f(this))
            .await
            .map_err(|e| {
                StorageIOError::new(
                    ErrorSubject::Store,
                    ErrorVerb::Write,
                    AnyError::error(format!(
                        "blocking task for {op} on {} panicked or was cancelled: {e}",
                        self.path.display()
                    )),
                )
            })?
    }

    /// Reads and decodes one meta value inside a blocking context.
    fn read_meta_blocking<T: serde::de::DeserializeOwned>(
        &self,
        key: &'static str,
    ) -> Result<Option<T>, StorageError<u64>> {
        let txn = self.db.begin_read().map_err(|e| {
            self.db_err(
                ErrorSubject::Store,
                ErrorVerb::Read,
                "begin read transaction",
                &e.into(),
            )
        })?;
        let table = txn.open_table(META_TABLE).map_err(|e| {
            self.db_err(
                ErrorSubject::Store,
                ErrorVerb::Read,
                "open meta table",
                &e.into(),
            )
        })?;
        let value = table.get(key).map_err(|e| {
            self.db_err(ErrorSubject::Store, ErrorVerb::Read, "read meta", &e.into())
        })?;
        match value {
            Some(guard) => Ok(Some(self.decode_meta(key, guard.value())?)),
            None => Ok(None),
        }
    }

    /// Writes one pre-sealed meta value in its own durable transaction,
    /// inside a blocking context.
    fn write_meta_blocking(
        &self,
        key: &'static str,
        sealed: &[u8],
    ) -> Result<(), StorageError<u64>> {
        let subject = if key == META_VOTE {
            ErrorSubject::Vote
        } else {
            ErrorSubject::Store
        };
        let txn = self.db.begin_write().map_err(|e| {
            self.db_err(
                subject.clone(),
                ErrorVerb::Write,
                "begin write transaction",
                &e.into(),
            )
        })?;
        {
            let mut table = txn.open_table(META_TABLE).map_err(|e| {
                self.db_err(
                    subject.clone(),
                    ErrorVerb::Write,
                    "open meta table",
                    &e.into(),
                )
            })?;
            table.insert(key, sealed).map_err(|e| {
                self.db_err(subject.clone(), ErrorVerb::Write, "write meta", &e.into())
            })?;
        }
        // redb commit is durable (fsync) before returning — this is what
        // satisfies "vote must be persisted before returning".
        txn.commit()
            .map_err(|e| self.db_err(subject, ErrorVerb::Write, "commit meta write", &e.into()))
    }
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry>, StorageError<u64>> {
        // Owned bounds so the range can cross into the blocking closure.
        let bounds: (Bound<u64>, Bound<u64>) =
            (range.start_bound().cloned(), range.end_bound().cloned());
        self.blocking("read log entries", move |store| {
            let txn = store.db.begin_read().map_err(|e| {
                store.db_err(
                    ErrorSubject::Logs,
                    ErrorVerb::Read,
                    "begin read transaction",
                    &e.into(),
                )
            })?;
            let table = txn.open_table(LOGS_TABLE).map_err(|e| {
                store.db_err(
                    ErrorSubject::Logs,
                    ErrorVerb::Read,
                    "open logs table",
                    &e.into(),
                )
            })?;
            let mut entries = Vec::new();
            let iter = table.range(bounds).map_err(|e| {
                store.db_err(ErrorSubject::Logs, ErrorVerb::Read, "range logs", &e.into())
            })?;
            for item in iter {
                let (key, value) = item.map_err(|e| {
                    store.db_err(
                        ErrorSubject::Logs,
                        ErrorVerb::Read,
                        "iterate logs",
                        &e.into(),
                    )
                })?;
                entries.push(store.decode_entry(key.value(), value.value())?);
            }
            Ok(entries)
        })
        .await
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<u64>> {
        self.blocking("read log state", move |store| {
            let last_purged: Option<LogId<u64>> = store.read_meta_blocking(META_LAST_PURGED)?;
            let txn = store.db.begin_read().map_err(|e| {
                store.db_err(
                    ErrorSubject::Logs,
                    ErrorVerb::Read,
                    "begin read transaction",
                    &e.into(),
                )
            })?;
            let table = txn.open_table(LOGS_TABLE).map_err(|e| {
                store.db_err(
                    ErrorSubject::Logs,
                    ErrorVerb::Read,
                    "open logs table",
                    &e.into(),
                )
            })?;
            let last = table.last().map_err(|e| {
                store.db_err(
                    ErrorSubject::Logs,
                    ErrorVerb::Read,
                    "read last log",
                    &e.into(),
                )
            })?;
            let last_log_id = match last {
                Some((key, value)) => Some(store.decode_entry(key.value(), value.value())?.log_id),
                None => last_purged,
            };
            Ok(LogState {
                last_purged_log_id: last_purged,
                last_log_id,
            })
        })
        .await
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        let sealed = self.encode_meta(META_VOTE, vote)?;
        self.blocking("save vote", move |store| {
            store.write_meta_blocking(META_VOTE, &sealed)
        })
        .await
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        self.blocking("read vote", move |store| {
            store.read_meta_blocking(META_VOTE)
        })
        .await
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<u64>>,
    ) -> Result<(), StorageError<u64>> {
        let sealed = self.encode_meta(META_COMMITTED, &committed)?;
        self.blocking("save committed", move |store| {
            store.write_meta_blocking(META_COMMITTED, &sealed)
        })
        .await
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        self.blocking("read committed", move |store| {
            Ok(store
                .read_meta_blocking::<Option<LogId<u64>>>(META_COMMITTED)?
                .flatten())
        })
        .await
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        // Serialize + seal on this task (CPU work), write + fsync on the
        // blocking pool. The callback fires only after the durable commit.
        let mut encoded = Vec::new();
        for entry in entries {
            encoded.push((entry.log_id.index, self.encode_entry(&entry)?));
        }
        self.blocking("append log entries", move |store| {
            let txn = store.db.begin_write().map_err(|e| {
                store.db_err(
                    ErrorSubject::Logs,
                    ErrorVerb::Write,
                    "begin write transaction",
                    &e.into(),
                )
            })?;
            {
                let mut table = txn.open_table(LOGS_TABLE).map_err(|e| {
                    store.db_err(
                        ErrorSubject::Logs,
                        ErrorVerb::Write,
                        "open logs table",
                        &e.into(),
                    )
                })?;
                for (index, sealed) in &encoded {
                    table.insert(index, sealed.as_slice()).map_err(|e| {
                        store.db_err(
                            ErrorSubject::LogIndex(*index),
                            ErrorVerb::Write,
                            "append log entry",
                            &e.into(),
                        )
                    })?;
                }
            }
            txn.commit().map_err(|e| {
                store.db_err(
                    ErrorSubject::Logs,
                    ErrorVerb::Write,
                    "commit append",
                    &e.into(),
                )
            })?;
            // Durably committed: report IO completion. (On error we return
            // the StorageError instead — openraft treats it as fatal.)
            callback.log_io_completed(Ok(()));
            Ok(())
        })
        .await
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        tracing::debug!(
            index = log_id.index,
            "truncating raft log from index (inclusive)"
        );
        self.blocking("truncate log", move |store| {
            let txn = store.db.begin_write().map_err(|e| {
                store.db_err(
                    ErrorSubject::Logs,
                    ErrorVerb::Delete,
                    "begin write transaction",
                    &e.into(),
                )
            })?;
            {
                let mut table = txn.open_table(LOGS_TABLE).map_err(|e| {
                    store.db_err(
                        ErrorSubject::Logs,
                        ErrorVerb::Delete,
                        "open logs table",
                        &e.into(),
                    )
                })?;
                table.retain_in(log_id.index.., |_, _| false).map_err(|e| {
                    store.db_err(
                        ErrorSubject::Logs,
                        ErrorVerb::Delete,
                        "delete truncated entries",
                        &e.into(),
                    )
                })?;
            }
            txn.commit().map_err(|e| {
                store.db_err(
                    ErrorSubject::Logs,
                    ErrorVerb::Delete,
                    "commit truncate",
                    &e.into(),
                )
            })
        })
        .await
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        tracing::debug!(
            index = log_id.index,
            "purging raft log up to index (inclusive)"
        );
        let sealed_purged = self.encode_meta(META_LAST_PURGED, &log_id)?;
        self.blocking("purge log", move |store| {
            // One transaction: the purge watermark and the deletion land
            // together or not at all.
            let txn = store.db.begin_write().map_err(|e| {
                store.db_err(
                    ErrorSubject::Logs,
                    ErrorVerb::Delete,
                    "begin write transaction",
                    &e.into(),
                )
            })?;
            {
                let mut meta = txn.open_table(META_TABLE).map_err(|e| {
                    store.db_err(
                        ErrorSubject::Logs,
                        ErrorVerb::Write,
                        "open meta table",
                        &e.into(),
                    )
                })?;
                meta.insert(META_LAST_PURGED, sealed_purged.as_slice())
                    .map_err(|e| {
                        store.db_err(
                            ErrorSubject::Logs,
                            ErrorVerb::Write,
                            "write purge watermark",
                            &e.into(),
                        )
                    })?;
                let mut logs = txn.open_table(LOGS_TABLE).map_err(|e| {
                    store.db_err(
                        ErrorSubject::Logs,
                        ErrorVerb::Delete,
                        "open logs table",
                        &e.into(),
                    )
                })?;
                logs.retain_in(..=log_id.index, |_, _| false).map_err(|e| {
                    store.db_err(
                        ErrorSubject::Logs,
                        ErrorVerb::Delete,
                        "delete purged entries",
                        &e.into(),
                    )
                })?;
            }
            txn.commit().map_err(|e| {
                store.db_err(
                    ErrorSubject::Logs,
                    ErrorVerb::Delete,
                    "commit purge",
                    &e.into(),
                )
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use openraft::testing::log_id;
    use openraft::{CommittedLeaderId, EntryPayload};

    use crate::crypto::DEK_LEN;
    use crate::types::Proposal;

    use super::*;

    fn test_dek() -> Dek {
        Dek::from_bytes(&[3_u8; DEK_LEN])
    }

    fn entry(term: u64, index: u64) -> Entry {
        Entry {
            log_id: LogId::new(CommittedLeaderId::new(term, 1), index),
            payload: EntryPayload::Normal(Proposal { actions: vec![] }),
        }
    }

    async fn append_entries(store: &mut LogStore, entries: Vec<Entry>) {
        use openraft::storage::RaftLogStorageExt;
        store.blocking_append(entries).await.unwrap();
    }

    #[tokio::test]
    async fn append_and_read_ranges() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = LogStore::open(dir.path(), test_dek()).unwrap();

        append_entries(&mut store, (1..=10).map(|i| entry(1, i)).collect()).await;

        let all = store.try_get_log_entries(..).await.unwrap();
        assert_eq!(all.len(), 10);
        assert_eq!(all[0].log_id.index, 1);
        assert_eq!(all[9].log_id.index, 10);

        let mid = store.try_get_log_entries(3..7).await.unwrap();
        assert_eq!(
            mid.iter().map(|e| e.log_id.index).collect::<Vec<_>>(),
            vec![3, 4, 5, 6]
        );

        let none = store.try_get_log_entries(11..20).await.unwrap();
        assert!(none.is_empty());

        let state = store.get_log_state().await.unwrap();
        assert_eq!(state.last_purged_log_id, None);
        assert_eq!(state.last_log_id, Some(log_id(1, 1, 10)));
    }

    #[tokio::test]
    async fn vote_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let vote = Vote::new(7, 42);
        {
            let mut store = LogStore::open(dir.path(), test_dek()).unwrap();
            assert_eq!(store.read_vote().await.unwrap(), None);
            store.save_vote(&vote).await.unwrap();
            assert_eq!(store.read_vote().await.unwrap(), Some(vote));
        }
        let mut reopened = LogStore::open(dir.path(), test_dek()).unwrap();
        assert_eq!(reopened.read_vote().await.unwrap(), Some(vote));
    }

    #[tokio::test]
    async fn committed_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = LogStore::open(dir.path(), test_dek()).unwrap();
            assert_eq!(store.read_committed().await.unwrap(), None);
            store.save_committed(Some(log_id(2, 1, 5))).await.unwrap();
        }
        let mut reopened = LogStore::open(dir.path(), test_dek()).unwrap();
        assert_eq!(
            reopened.read_committed().await.unwrap(),
            Some(log_id(2, 1, 5))
        );
    }

    #[tokio::test]
    async fn truncate_deletes_from_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = LogStore::open(dir.path(), test_dek()).unwrap();
        append_entries(&mut store, (1..=10).map(|i| entry(1, i)).collect()).await;

        store.truncate(log_id(1, 1, 6)).await.unwrap();

        let remaining = store.try_get_log_entries(..).await.unwrap();
        assert_eq!(
            remaining.iter().map(|e| e.log_id.index).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        let state = store.get_log_state().await.unwrap();
        assert_eq!(state.last_log_id, Some(log_id(1, 1, 5)));
    }

    #[tokio::test]
    async fn purge_deletes_up_to_index_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = LogStore::open(dir.path(), test_dek()).unwrap();
            append_entries(&mut store, (1..=10).map(|i| entry(1, i)).collect()).await;

            store.purge(log_id(1, 1, 4)).await.unwrap();

            let remaining = store.try_get_log_entries(..).await.unwrap();
            assert_eq!(
                remaining.iter().map(|e| e.log_id.index).collect::<Vec<_>>(),
                vec![5, 6, 7, 8, 9, 10]
            );
            let state = store.get_log_state().await.unwrap();
            assert_eq!(state.last_purged_log_id, Some(log_id(1, 1, 4)));
            assert_eq!(state.last_log_id, Some(log_id(1, 1, 10)));
        }
        // Purge everything: last_log_id falls back to the purge watermark,
        // including after reopen.
        let mut store = LogStore::open(dir.path(), test_dek()).unwrap();
        store.purge(log_id(1, 1, 10)).await.unwrap();
        let state = store.get_log_state().await.unwrap();
        assert_eq!(state.last_purged_log_id, Some(log_id(1, 1, 10)));
        assert_eq!(state.last_log_id, Some(log_id(1, 1, 10)));
        drop(store);

        let mut reopened = LogStore::open(dir.path(), test_dek()).unwrap();
        let state = reopened.get_log_state().await.unwrap();
        assert_eq!(state.last_purged_log_id, Some(log_id(1, 1, 10)));
        assert_eq!(state.last_log_id, Some(log_id(1, 1, 10)));
    }

    #[tokio::test]
    async fn entries_unreadable_without_the_right_dek() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = LogStore::open(dir.path(), test_dek()).unwrap();
            append_entries(&mut store, vec![entry(1, 1)]).await;
            store.save_vote(&Vote::new(1, 1)).await.unwrap();
        }
        let wrong = Dek::from_bytes(&[9_u8; DEK_LEN]);
        let mut store = LogStore::open(dir.path(), wrong).unwrap();
        let err = store.try_get_log_entries(..).await.unwrap_err();
        assert!(err.to_string().contains("unseal"), "{err}");
        let err = store.read_vote().await.unwrap_err();
        assert!(err.to_string().contains("unseal"), "{err}");
    }
}
