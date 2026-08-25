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

// Triaged pedantic allow: `StorageError<TypeConfig>` (~200 bytes) is the error type
// imposed by openraft's storage trait signatures — it cannot be boxed here,
// and these are cold error paths.
#![allow(clippy::result_large_err)]

use std::io;
use std::ops::{Bound, RangeBounds};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use openraft::storage::{IOFlushed, LogState, RaftLogStorage};
use openraft::type_config::alias::{LogIdOf, VoteOf};
use openraft::{AnyError, ErrorSubject, ErrorVerb, OptionalSend, RaftLogReader, StorageError};
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

type Entry = openraft::type_config::alias::EntryOf<TypeConfig>;

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
    db: Arc<DbHandle>,
    dek: Dek,
    /// Database file path, carried for error messages (SRE rule: say what
    /// file the failed operation touched).
    path: Arc<PathBuf>,
}

/// Owns the redb [`Database`] and announces, **after** it has been dropped,
/// that the file lock is gone.
///
/// The flag cannot be replaced by an `Arc` strong count. `Arc`'s drop
/// decrements the counter *before* running the inner value's `Drop`, so a
/// `Weak::strong_count() == 0` can be observed while `Database::drop` -- which
/// is what releases redb's lock -- is still executing on another thread. That
/// window is small and entirely real: it is what made
/// `tests/autolock.rs` fail with `DatabaseAlreadyOpen` against a
/// count-based check that reported "released" a moment too early.
#[derive(Debug)]
struct DbHandle {
    /// `Option` only so [`Drop`] can drop the database before the flag is set.
    db: Option<Database>,
    released: Arc<AtomicBool>,
}

impl Drop for DbHandle {
    fn drop(&mut self) {
        // Order matters: the lock must be gone before anyone is told so.
        drop(self.db.take());
        self.released.store(true, Ordering::Release);
    }
}

impl std::ops::Deref for DbHandle {
    type Target = Database;

    fn deref(&self) -> &Database {
        self.db
            .as_ref()
            .expect("the database is taken only by Drop, which ends this value's life")
    }
}

/// Observes whether the redb log database file has been released.
///
/// openraft 0.10 hands `LogStore` clones to its core task, its state-machine
/// worker and every replication task, and `Raft::shutdown()` joins only the
/// core task -- so it can return while a clone is still alive. redb refuses a
/// second open on a file it already holds (`DatabaseAlreadyOpen`), so
/// re-opening the raft directory right after a shutdown is a race. SatL
/// re-opens on exactly that boundary: `satld` shuts the manager runtime down
/// and rebuilds it on every role change, so a demote that raced this would
/// leave the node unable to open its own raft state.
#[derive(Clone, Debug)]
pub struct LogStoreRelease {
    released: Arc<AtomicBool>,
    path: Arc<PathBuf>,
}

impl LogStoreRelease {
    /// True once the database has been dropped and the file can be opened
    /// again.
    #[must_use]
    pub fn released(&self) -> bool {
        self.released.load(Ordering::Acquire)
    }

    /// The database file this watches, for error messages.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl LogStore {
    /// A handle that reports when every clone of this store is gone.
    ///
    /// See [`LogStoreRelease`] for why shutdown has to wait on this.
    #[must_use]
    pub fn release_watch(&self) -> LogStoreRelease {
        LogStoreRelease {
            released: Arc::clone(&self.db.released),
            path: Arc::clone(&self.path),
        }
    }
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
            db: Arc::new(DbHandle {
                db: Some(db),
                released: Arc::new(AtomicBool::new(false)),
            }),
            dek,
            path: Arc::new(path),
        })
    }

    /// Serializes and seals one log entry for storage.
    fn encode_entry(&self, entry: &Entry) -> Result<Vec<u8>, StorageError<TypeConfig>> {
        let mut plain = Vec::new();
        ciborium::ser::into_writer(entry, &mut plain)
            .map_err(|e| StorageError::write_log_entry(entry.log_id, AnyError::new(&e)))?;
        Ok(self.dek.seal(&plain))
    }

    /// Unseals and deserializes one log entry read from storage.
    fn decode_entry(&self, index: u64, sealed: &[u8]) -> Result<Entry, StorageError<TypeConfig>> {
        let plain = self.dek.open(sealed).map_err(|e| {
            StorageError::new(
                ErrorSubject::LogIndex(index),
                ErrorVerb::Read,
                AnyError::error(format!(
                    "unseal log entry {index} in {}: {e}",
                    self.path.display()
                )),
            )
        })?;
        ciborium::de::from_reader(plain.as_slice()).map_err(|e| {
            StorageError::new(
                ErrorSubject::LogIndex(index),
                ErrorVerb::Read,
                AnyError::error(format!(
                    "decode log entry {index} in {}: {e}",
                    self.path.display()
                )),
            )
        })
    }

    /// Seals a serde value for the meta table.
    fn encode_meta<T: serde::Serialize>(
        &self,
        key: &'static str,
        value: &T,
    ) -> Result<Vec<u8>, StorageError<TypeConfig>> {
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
    ) -> Result<T, StorageError<TypeConfig>> {
        let plain = self
            .dek
            .open(sealed)
            .map_err(|e| self.meta_err(key, ErrorVerb::Read, &format!("unseal meta {key}: {e}")))?;
        ciborium::de::from_reader(plain.as_slice())
            .map_err(|e| self.meta_err(key, ErrorVerb::Read, &format!("decode meta {key}: {e}")))
    }

    /// Builds a storage error for a meta-table operation, naming the file.
    fn meta_err(&self, key: &'static str, verb: ErrorVerb, msg: &str) -> StorageError<TypeConfig> {
        let subject = if key == META_VOTE {
            ErrorSubject::Vote
        } else {
            ErrorSubject::Store
        };
        StorageError::new(
            subject,
            verb,
            AnyError::error(format!("{msg} (database {})", self.path.display())),
        )
    }

    /// Builds a storage error from a redb error, naming the operation and
    /// file.
    fn db_err(
        &self,
        subject: ErrorSubject<TypeConfig>,
        verb: ErrorVerb,
        op: &str,
        err: &redb::Error,
    ) -> StorageError<TypeConfig> {
        StorageError::new(
            subject,
            verb,
            AnyError::error(format!("{op} (database {}): {err}", self.path.display())),
        )
    }

    /// Runs a blocking redb operation on the blocking pool.
    async fn blocking<T, F>(&self, op: &'static str, f: F) -> Result<T, StorageError<TypeConfig>>
    where
        T: Send + 'static,
        F: FnOnce(LogStore) -> Result<T, StorageError<TypeConfig>> + Send + 'static,
    {
        let this = self.clone();
        tokio::task::spawn_blocking(move || f(this))
            .await
            .map_err(|e| {
                StorageError::new(
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
    ) -> Result<Option<T>, StorageError<TypeConfig>> {
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
    ) -> Result<(), StorageError<TypeConfig>> {
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
    ) -> Result<Vec<Entry>, io::Error> {
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
        .map_err(io::Error::from)
    }

    /// The vote lives in the meta table next to the log, not in the state
    /// machine: openraft 0.10 reads it through the *reader* half of the
    /// storage pair (it moved off `RaftLogStorage` in that release) so a
    /// replication task can check the leader without touching the writer.
    async fn read_vote(&mut self) -> Result<Option<VoteOf<TypeConfig>>, io::Error> {
        self.blocking("read vote", move |store| {
            store.read_meta_blocking(META_VOTE)
        })
        .await
        .map_err(io::Error::from)
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, io::Error> {
        self.blocking("read log state", move |store| {
            let last_purged: Option<LogIdOf<TypeConfig>> =
                store.read_meta_blocking(META_LAST_PURGED)?;
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
        .map_err(io::Error::from)
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &VoteOf<TypeConfig>) -> Result<(), io::Error> {
        let sealed = self.encode_meta(META_VOTE, vote)?;
        self.blocking("save vote", move |store| {
            store.write_meta_blocking(META_VOTE, &sealed)
        })
        .await
        .map_err(io::Error::from)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogIdOf<TypeConfig>>,
    ) -> Result<(), io::Error> {
        let sealed = self.encode_meta(META_COMMITTED, &committed)?;
        self.blocking("save committed", move |store| {
            store.write_meta_blocking(META_COMMITTED, &sealed)
        })
        .await
        .map_err(io::Error::from)
    }

    async fn read_committed(&mut self) -> Result<Option<LogIdOf<TypeConfig>>, io::Error> {
        self.blocking("read committed", move |store| {
            Ok(store
                .read_meta_blocking::<Option<LogIdOf<TypeConfig>>>(META_COMMITTED)?
                .flatten())
        })
        .await
        .map_err(io::Error::from)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: IOFlushed<TypeConfig>,
    ) -> Result<(), io::Error>
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
            callback.io_completed(Ok(()));
            Ok(())
        })
        .await
        .map_err(io::Error::from)
    }

    /// openraft 0.10 renamed `truncate(log_id)` — "delete from this index,
    /// inclusive" — to `truncate_after(last_log_id)`, which keeps
    /// `last_log_id` and deletes everything *after* it. The two differ by one
    /// index, and `None` means "keep nothing". The `from` computed here is
    /// the first index to delete, so the redb range stays half-open exactly
    /// as before.
    async fn truncate_after(
        &mut self,
        last_log_id: Option<LogIdOf<TypeConfig>>,
    ) -> Result<(), io::Error> {
        let from = last_log_id.as_ref().map_or(0, |id| id.index + 1);
        tracing::debug!(from, "truncating raft log from index (inclusive)");
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
                table.retain_in(from.., |_, _| false).map_err(|e| {
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
        .map_err(io::Error::from)
    }

    async fn purge(&mut self, log_id: LogIdOf<TypeConfig>) -> Result<(), io::Error> {
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
        .map_err(io::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use openraft::testing::log_id;
    use openraft::{EntryPayload, Vote};

    use crate::crypto::DEK_LEN;
    use crate::types::Proposal;

    use super::*;

    fn test_dek() -> Dek {
        Dek::from_bytes(&[3_u8; DEK_LEN])
    }

    fn entry(term: u64, index: u64) -> Entry {
        Entry {
            log_id: log_id::<TypeConfig>(term, 1, index),
            payload: EntryPayload::Normal(Proposal { actions: vec![] }),
        }
    }

    /// The release flag means "redb has let the file go", not "the last
    /// reference count went away".
    ///
    /// `Arc` decrements its counter *before* running the inner `Drop`, so a
    /// count-based check can report the store released while
    /// `Database::drop` -- which holds the lock -- is still running. That
    /// window only opens when the last clone dies on another thread, which is
    /// what openraft's tasks do; `tests/autolock.rs` is where it was actually
    /// caught. This test pins the cheap half of the invariant: the flag never
    /// leads the drop, and a clone still holding the store never reads as
    /// released.
    #[test]
    fn the_file_is_reopenable_as_soon_as_the_watch_says_released() {
        let dir = tempfile::tempdir().unwrap();
        let store = LogStore::open(dir.path(), test_dek()).unwrap();
        let release = store.release_watch();
        assert!(!release.released(), "a live store is not released");

        // A clone is what openraft's tasks hold; one of them going away must
        // not be mistaken for the file being free.
        let clone = store.clone();
        drop(store);
        assert!(
            !release.released(),
            "a surviving clone still holds the file"
        );

        drop(clone);
        assert!(release.released());
        LogStore::open(dir.path(), test_dek())
            .expect("the file is openable the moment the watch says it is released");
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
        assert_eq!(state.last_log_id, Some(log_id::<TypeConfig>(1, 1, 10)));
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
            store
                .save_committed(Some(log_id::<TypeConfig>(2, 1, 5)))
                .await
                .unwrap();
        }
        let mut reopened = LogStore::open(dir.path(), test_dek()).unwrap();
        assert_eq!(
            reopened.read_committed().await.unwrap(),
            Some(log_id::<TypeConfig>(2, 1, 5))
        );
    }

    #[tokio::test]
    async fn truncate_after_deletes_beyond_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = LogStore::open(dir.path(), test_dek()).unwrap();
        append_entries(&mut store, (1..=10).map(|i| entry(1, i)).collect()).await;

        // openraft 0.10's `truncate_after` KEEPS the log id it is given and
        // deletes what follows, where 0.9's `truncate` deleted from that id
        // inclusive. Keeping index 5 is therefore the same outcome the old
        // `truncate(6)` produced.
        store
            .truncate_after(Some(log_id::<TypeConfig>(1, 1, 5)))
            .await
            .unwrap();

        let remaining = store.try_get_log_entries(..).await.unwrap();
        assert_eq!(
            remaining.iter().map(|e| e.log_id.index).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        let state = store.get_log_state().await.unwrap();
        assert_eq!(state.last_log_id, Some(log_id::<TypeConfig>(1, 1, 5)));
    }

    /// `None` means "keep nothing", which has no 0.9 equivalent and is the
    /// easiest half of the rename to get wrong.
    #[tokio::test]
    async fn truncate_after_none_empties_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = LogStore::open(dir.path(), test_dek()).unwrap();
        append_entries(&mut store, (1..=4).map(|i| entry(1, i)).collect()).await;

        store.truncate_after(None).await.unwrap();

        assert!(store.try_get_log_entries(..).await.unwrap().is_empty());
        assert_eq!(store.get_log_state().await.unwrap().last_log_id, None);
    }

    #[tokio::test]
    async fn purge_deletes_up_to_index_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = LogStore::open(dir.path(), test_dek()).unwrap();
            append_entries(&mut store, (1..=10).map(|i| entry(1, i)).collect()).await;

            store.purge(log_id::<TypeConfig>(1, 1, 4)).await.unwrap();

            let remaining = store.try_get_log_entries(..).await.unwrap();
            assert_eq!(
                remaining.iter().map(|e| e.log_id.index).collect::<Vec<_>>(),
                vec![5, 6, 7, 8, 9, 10]
            );
            let state = store.get_log_state().await.unwrap();
            assert_eq!(
                state.last_purged_log_id,
                Some(log_id::<TypeConfig>(1, 1, 4))
            );
            assert_eq!(state.last_log_id, Some(log_id::<TypeConfig>(1, 1, 10)));
        }
        // Purge everything: last_log_id falls back to the purge watermark,
        // including after reopen.
        let mut store = LogStore::open(dir.path(), test_dek()).unwrap();
        store.purge(log_id::<TypeConfig>(1, 1, 10)).await.unwrap();
        let state = store.get_log_state().await.unwrap();
        assert_eq!(
            state.last_purged_log_id,
            Some(log_id::<TypeConfig>(1, 1, 10))
        );
        assert_eq!(state.last_log_id, Some(log_id::<TypeConfig>(1, 1, 10)));
        drop(store);

        let mut reopened = LogStore::open(dir.path(), test_dek()).unwrap();
        let state = reopened.get_log_state().await.unwrap();
        assert_eq!(
            state.last_purged_log_id,
            Some(log_id::<TypeConfig>(1, 1, 10))
        );
        assert_eq!(state.last_log_id, Some(log_id::<TypeConfig>(1, 1, 10)));
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
