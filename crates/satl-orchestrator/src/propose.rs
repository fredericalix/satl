// SPDX-License-Identifier: BSD-2-Clause
//! Store writes for the orchestration loops: propose with bounded
//! sequence-conflict retry (architecture §6.4, CLAUDE.md invariant #1).
//!
//! Every loop reads a fresh view, decides, and proposes. Between the read
//! and the commit another leader-side loop may have written the same object,
//! in which case the state machine deterministically rejects the whole
//! transaction with
//! [`SequenceConflict`](satl_cluster::ProposalRejection::SequenceConflict)
//! and nothing is applied. The fix is always the same: re-read, re-decide,
//! re-propose — *bounded*, so a loop that keeps losing the race gives up and
//! lets its periodic reconciliation pass (or the next watch event) try again
//! instead of spinning on the Raft log.
//!
//! A failed proposal must never kill a loop: callers log the error and carry
//! on. That is why this module returns a typed error instead of panicking,
//! and why every caller is expected to be idempotent — re-running a decision
//! that already applied produces an empty action list.

use satl_cluster::{ClusterStore, ProposalRejection, ProposeError, StoreView};
use satl_core::{StoreAction, Version};

/// How many times a decision is re-read and re-proposed before the loop
/// gives up and waits for its next pass.
pub(crate) const MAX_CONFLICT_RETRIES: u32 = 5;

/// Why an orchestration loop could not commit a decision.
///
/// None of these are fatal: the caller logs and continues, and the periodic
/// reconciliation pass re-derives the same decision from store state.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProposeRetryError {
    /// The transaction lost the optimistic-concurrency race
    /// [`MAX_CONFLICT_RETRIES`] times in a row.
    #[error(
        "{what}: gave up after {attempts} rejected proposals (last: {last}); the periodic reconciliation pass will retry"
    )]
    RetriesExhausted {
        /// What the loop was trying to do.
        what: &'static str,
        /// Number of attempts made.
        attempts: u32,
        /// The rejection seen on the final attempt.
        last: ProposalRejection,
    },
    /// The transaction was malformed (too many actions, too large). Retrying
    /// cannot help — this is a bug in the calling loop's batching.
    #[error("{what}: transaction rejected as malformed: {source}")]
    Malformed {
        /// What the loop was trying to do.
        what: &'static str,
        /// The deterministic rejection.
        #[source]
        source: ProposalRejection,
    },
    /// Raft refused the proposal (not leader, shutting down). Leader-only
    /// components are stopped on leadership loss; until they are, this is
    /// the expected error.
    #[error("{what}: {source}")]
    Propose {
        /// What the loop was trying to do.
        what: &'static str,
        /// The underlying store error.
        #[source]
        source: ProposeError,
    },
}

/// Runs `decide` against a fresh store view and proposes its actions,
/// re-deciding on deterministic rejections up to [`MAX_CONFLICT_RETRIES`]
/// times.
///
/// `decide` must be **idempotent and pure**: it is called once per attempt
/// and must derive the whole transaction from the view it is handed (never
/// from state captured before the previous attempt). Returning an empty
/// action list means "nothing left to do" and is reported as `Ok(None)`.
///
/// The view guard is `!Send` and is scoped to a sync block, so it is never
/// held across the `await` on the proposal (architecture §6.2).
///
/// The action list must respect [`satl_core::defaults::MAX_TX_ACTIONS`];
/// callers cap their own batches and let the next pass handle the rest.
pub(crate) async fn propose_with_retry<F>(
    store: &ClusterStore,
    what: &'static str,
    mut decide: F,
) -> Result<Option<Version>, ProposeRetryError>
where
    F: FnMut(&StoreView<'_>) -> Vec<StoreAction> + Send,
{
    let mut attempt = 0;
    loop {
        attempt += 1;
        let actions = {
            // Scoped so the !Send read guard is dropped before the await.
            let view = store.view();
            decide(&view)
        };
        if actions.is_empty() {
            return Ok(None);
        }
        let count = actions.len();
        match store.propose(actions).await {
            Ok(version) => {
                tracing::debug!(
                    what,
                    actions = count,
                    attempt,
                    version = version.0,
                    "committed store transaction"
                );
                return Ok(Some(version));
            }
            Err(ProposeError::Rejected(rejection)) => {
                if matches!(
                    rejection,
                    ProposalRejection::TooManyActions { .. } | ProposalRejection::TooLarge { .. }
                ) {
                    return Err(ProposeRetryError::Malformed {
                        what,
                        source: rejection,
                    });
                }
                if attempt >= MAX_CONFLICT_RETRIES {
                    return Err(ProposeRetryError::RetriesExhausted {
                        what,
                        attempts: attempt,
                        last: rejection,
                    });
                }
                tracing::debug!(
                    what,
                    attempt,
                    rejection = %rejection,
                    "store rejected the transaction; re-reading and re-deciding"
                );
            }
            Err(source) => return Err(ProposeRetryError::Propose { what, source }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use satl_core::{ObjectKind, StoreObject};

    use crate::testing::{TestCluster, sample_service};

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_decision_commits_nothing() {
        let cluster = TestCluster::start().await;
        let calls = AtomicU32::new(0);
        let result = propose_with_retry(cluster.store(), "noop", |_view| {
            calls.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        })
        .await;
        assert!(matches!(result, Ok(None)), "{result:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        cluster.shutdown().await;
    }

    /// The retry path, deterministically: the first decision is built from a
    /// deliberately stale version (as if another loop had written the object
    /// between read and propose), the second re-reads and wins.
    #[tokio::test(flavor = "multi_thread")]
    async fn sequence_conflict_is_retried_after_a_fresh_read() {
        let cluster = TestCluster::start().await;
        let store = cluster.store();
        let service = sample_service("web", 1);
        let service_id = service.id.clone();
        store
            .propose(vec![StoreAction::Create(StoreObject::Service(service))])
            .await
            .expect("service create");

        let attempts = AtomicU32::new(0);
        let version = propose_with_retry(store, "stale update", |view| {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            let mut service = (*view.service(&service_id).expect("service")).clone();
            if attempt == 0 {
                // Simulate having read the object before someone else wrote it.
                service.meta.version = satl_core::Version(1);
            }
            service
                .spec
                .annotations
                .labels
                .insert("attempt".to_owned(), attempt.to_string());
            vec![StoreAction::Update(StoreObject::Service(service))]
        })
        .await
        .expect("retried proposal commits");

        assert!(version.is_some());
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "one conflict, one win");
        let view = store.view();
        let stored = view.service(&service_id).expect("service");
        assert_eq!(
            stored
                .spec
                .annotations
                .labels
                .get("attempt")
                .map(String::as_str),
            Some("1")
        );
        drop(view);
        cluster.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn persistent_conflicts_give_up_without_panicking() {
        let cluster = TestCluster::start().await;
        let store = cluster.store();
        let service = sample_service("web", 1);
        let service_id = service.id.clone();
        store
            .propose(vec![StoreAction::Create(StoreObject::Service(service))])
            .await
            .expect("service create");

        let attempts = AtomicU32::new(0);
        let err = propose_with_retry(store, "always stale", |view| {
            attempts.fetch_add(1, Ordering::SeqCst);
            let mut service = (*view.service(&service_id).expect("service")).clone();
            service.meta.version = satl_core::Version(1);
            vec![StoreAction::Update(StoreObject::Service(service))]
        })
        .await
        .expect_err("never converges");

        assert!(
            matches!(err, ProposeRetryError::RetriesExhausted { attempts: n, .. } if n == MAX_CONFLICT_RETRIES),
            "{err:?}"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), MAX_CONFLICT_RETRIES);
        cluster.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversized_transactions_are_not_retried() {
        let cluster = TestCluster::start().await;
        let store = cluster.store();
        let attempts = AtomicU32::new(0);
        let err = propose_with_retry(store, "oversized", |_view| {
            attempts.fetch_add(1, Ordering::SeqCst);
            (0..=satl_core::defaults::MAX_TX_ACTIONS)
                .map(|_| StoreAction::Remove {
                    kind: ObjectKind::Task,
                    id: satl_core::Id::generate(),
                })
                .collect()
        })
        .await
        .expect_err("malformed");
        assert!(
            matches!(err, ProposeRetryError::Malformed { .. }),
            "{err:?}"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "no retry on a bug");
        cluster.shutdown().await;
    }
}
