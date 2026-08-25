// SPDX-License-Identifier: BSD-2-Clause
//! Runs openraft's official storage compliance suite against the SatL
//! `RaftLogStorage` + `RaftStateMachine` implementations (redb log store +
//! in-memory FSM with sealed snapshots).
//!
//! The suite exercises the full storage contract: log state, vote
//! persistence, range reads, truncate/purge semantics, membership recovery
//! from log and state machine, apply, and snapshot metadata/transfer.
//!
//! openraft 0.10 moved the suite from `openraft::testing` to
//! `openraft::testing::log` and made `test_all` async; the storage traits it
//! checks are now parameterized by the type config rather than by the node id.

use openraft::testing::log::{StoreBuilder, Suite};
use openraft::{AnyError, ErrorSubject, ErrorVerb, StorageError};
use tempfile::TempDir;

use satl_cluster::crypto::Dek;
use satl_cluster::{LogStore, StateMachine, TypeConfig};

struct SatlStoreBuilder;

/// Wraps a bring-up failure into the suite's error type.
fn build_err(msg: String) -> StorageError<TypeConfig> {
    StorageError::new(ErrorSubject::Store, ErrorVerb::Write, AnyError::error(msg))
}

impl StoreBuilder<TypeConfig, LogStore, StateMachine, TempDir> for SatlStoreBuilder {
    async fn build(&self) -> Result<(TempDir, LogStore, StateMachine), StorageError<TypeConfig>> {
        let dir = TempDir::new().map_err(|e| build_err(format!("create tempdir: {e}")))?;
        let dek =
            Dek::load_or_create(&dir.path().join("dek")).map_err(|e| build_err(e.to_string()))?;
        let log_store =
            LogStore::open(dir.path(), dek.clone()).map_err(|e| build_err(e.to_string()))?;
        let state_machine =
            StateMachine::open(dir.path(), dek).map_err(|e| build_err(e.to_string()))?;
        Ok((dir, log_store, state_machine))
    }
}

#[tokio::test]
async fn openraft_storage_compliance_suite() {
    Suite::test_all(SatlStoreBuilder)
        .await
        .expect("openraft storage suite failed");
}
