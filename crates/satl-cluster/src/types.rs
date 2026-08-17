// SPDX-License-Identifier: BSD-2-Clause
//! Raft type configuration and the proposal protocol (architecture §6.1).
//!
//! A [`Proposal`] is one atomic store transaction: a list of
//! [`StoreAction`]s that either all apply or all fail. The state machine
//! answers every proposal with a [`ProposalResponse`]; rejections are **data**
//! returned to the proposer, not errors — every replica decodes the same
//! entry, runs the same deterministic validation, and computes the same
//! outcome, so the replicated state never diverges.

use std::io::Cursor;

use serde::{Deserialize, Serialize};

use satl_core::{Id, ObjectKind, StoreAction, Version};

openraft::declare_raft_types!(
    /// Openraft type configuration for the SatL cluster store.
    ///
    /// - `NodeId` is a random, never-reused `u64` (architecture §6.6).
    /// - `Node` is [`openraft::BasicNode`]: the addr carries the node name at
    ///   M0 and the Raft transport address from M2 on.
    /// - `SnapshotData` is the default `Cursor<Vec<u8>>`: snapshots are one
    ///   sealed CBOR blob (see `state_machine`).
    pub TypeConfig:
        D = Proposal,
        R = ProposalResponse,
        NodeId = u64,
        Node = openraft::BasicNode,
);

/// One store transaction submitted through Raft (architecture §6.1).
///
/// Bounded by [`satl_core::defaults::MAX_TX_ACTIONS`] and
/// [`satl_core::defaults::MAX_TX_BYTES`]; the bounds are enforced by the
/// state machine so that every replica agrees on the verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    /// The actions of this transaction, applied in order, all-or-nothing.
    pub actions: Vec<StoreAction>,
}

/// Deterministic outcome of applying a [`Proposal`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalResponse {
    /// The whole transaction applied; every written object now carries this
    /// version (the Raft log index of the entry).
    Applied {
        /// Version stamped on every object the transaction wrote.
        version: Version,
    },
    /// The whole transaction was rejected; nothing was applied.
    Rejected(ProposalRejection),
}

/// Why a proposal was rejected (first failing action wins; nothing applies).
///
/// These are business outcomes, not faults: optimistic concurrency
/// (architecture §3) turns stale writes into [`Self::SequenceConflict`] and
/// the caller retries from a fresh read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum ProposalRejection {
    /// An update carried a stale `meta.version`.
    #[error(
        "sequence conflict on {kind} {id}: store has version {expected}, caller wrote from version {found}"
    )]
    SequenceConflict {
        /// Kind of the conflicting object.
        kind: ObjectKind,
        /// ID of the conflicting object.
        id: Id,
        /// Version currently in the store.
        expected: u64,
        /// Stale version the caller supplied.
        found: u64,
    },
    /// Update/Remove targeted an object that does not exist.
    #[error("{kind} {id} not found")]
    NotFound {
        /// Kind of the missing object.
        kind: ObjectKind,
        /// ID of the missing object.
        id: Id,
    },
    /// Create targeted an ID that already exists.
    #[error("{kind} {id} already exists")]
    AlreadyExists {
        /// Kind of the duplicate object.
        kind: ObjectKind,
        /// ID of the duplicate object.
        id: Id,
    },
    /// The transaction exceeded [`satl_core::defaults::MAX_TX_ACTIONS`].
    #[error(
        "transaction has {count} actions, more than the maximum of {max}",
        max = satl_core::defaults::MAX_TX_ACTIONS
    )]
    TooManyActions {
        /// Number of actions in the oversized transaction.
        count: usize,
    },
    /// The serialized transaction exceeded
    /// [`satl_core::defaults::MAX_TX_BYTES`].
    #[error(
        "transaction is {bytes} bytes serialized, more than the maximum of {max}",
        max = satl_core::defaults::MAX_TX_BYTES
    )]
    TooLarge {
        /// Serialized size of the oversized transaction.
        bytes: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_response_serde_roundtrip() {
        let responses = vec![
            ProposalResponse::Applied {
                version: Version(7),
            },
            ProposalResponse::Rejected(ProposalRejection::SequenceConflict {
                kind: ObjectKind::Service,
                id: Id::generate(),
                expected: 9,
                found: 4,
            }),
            ProposalResponse::Rejected(ProposalRejection::TooManyActions { count: 300 }),
        ];
        let json = serde_json::to_string(&responses).unwrap();
        let back: Vec<ProposalResponse> = serde_json::from_str(&json).unwrap();
        assert_eq!(responses, back);
    }

    #[test]
    fn rejection_messages_name_the_object() {
        let id = Id::generate();
        let msg = ProposalRejection::NotFound {
            kind: ObjectKind::Network,
            id: id.clone(),
        }
        .to_string();
        assert!(msg.contains("network"), "{msg}");
        assert!(msg.contains(id.as_str()), "{msg}");
    }

    #[test]
    fn rejection_limits_name_the_limits() {
        let msg = ProposalRejection::TooManyActions { count: 500 }.to_string();
        assert!(msg.contains("500"), "{msg}");
        assert!(msg.contains("200"), "{msg}");
        let msg = ProposalRejection::TooLarge { bytes: 2_000_000 }.to_string();
        assert!(msg.contains("2000000"), "{msg}");
        assert!(msg.contains("1572864"), "{msg}");
    }
}
