// SPDX-License-Identifier: BSD-2-Clause
//! Error types shared by the two sides of the protocol.
//!
//! Manager-side failures become `tonic::Status` at the service boundary
//! ([`crate::manager`]); the mapping is deliberately explicit rather than a
//! blanket `internal`, because the proto pins which code an agent must see
//! for each condition — an agent's recovery path is chosen by the code.

use crate::codec::CodecError;
use crate::sequence::SequenceGap;

/// Why an agent session ended.
///
/// Every variant is recoverable: the session loop logs, backs off, and
/// re-registers (SWK §14.1 — any error tears down the whole session).
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// No manager could be dialed.
    #[error(
        "no manager to connect to: the manager list is empty and this node has no local manager socket"
    )]
    NoManager,

    /// The transport failed to connect.
    #[error("connecting to {endpoint}: {source}")]
    Connect {
        /// The endpoint that was dialed.
        endpoint: String,
        /// Underlying connector error.
        #[source]
        source: crate::agent::ConnectError,
    },

    /// An RPC failed. The status code is what decides the recovery path:
    /// `FAILED_PRECONDITION` means "wrong manager or stale session, go
    /// re-register", `NOT_FOUND` means this node is not registered.
    #[error("dispatcher rpc {rpc} failed: {status}")]
    Rpc {
        /// Which RPC.
        rpc: &'static str,
        /// The gRPC status.
        #[source]
        status: Box<tonic::Status>,
    },

    /// A stream ended without an error. The manager lost leadership, the
    /// session was superseded, or the node was removed.
    #[error("the {stream} stream ended; re-registering")]
    StreamEnded {
        /// Which stream.
        stream: &'static str,
    },

    /// The manager re-registered this agent under a new session ID, so every
    /// other stream is stale (SWK §13.1).
    #[error("session superseded: the manager issued session {new} while this agent held {held}")]
    SessionSuperseded {
        /// The session the agent was holding.
        held: String,
        /// The session the manager just pushed.
        new: String,
    },

    /// The assignment stream lost its place in the sequence chain. The only
    /// correct reaction is to re-open the stream for a fresh COMPLETE
    /// snapshot — never to patch the gap.
    #[error(transparent)]
    Sequence(#[from] SequenceGap),

    /// A message could not be decoded.
    #[error(transparent)]
    Codec(#[from] CodecError),

    /// Applying an assignment failed.
    #[error(transparent)]
    Apply(#[from] ApplyError),

    /// The node description changed, so the session must be re-opened to
    /// carry it (SWK §14.1, architecture §8.3).
    #[error("the node description changed; re-registering so the manager sees it")]
    DescriptionChanged,
}

impl SessionError {
    /// An RPC failure, boxing the status (a `tonic::Status` is large enough
    /// to make every `Result` in the session loop fat).
    #[must_use]
    pub fn rpc(rpc: &'static str, status: tonic::Status) -> Self {
        Self::Rpc {
            rpc,
            status: Box::new(status),
        }
    }

    /// Whether the manager told us our session is invalid, meaning the agent
    /// should register from scratch rather than retry the same stream.
    #[must_use]
    pub fn needs_registration(&self) -> bool {
        match self {
            Self::Rpc { status, .. } => matches!(
                status.code(),
                tonic::Code::FailedPrecondition | tonic::Code::NotFound
            ),
            Self::SessionSuperseded { .. } | Self::StreamEnded { .. } => true,
            _ => false,
        }
    }
}

/// Applying an assignment to the local worker failed.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The worker refused the task (it could not persist it, so it must not
    /// start it — SWK §14.2).
    #[error("applying task {task_id}: {source}")]
    Task {
        /// The task involved.
        task_id: String,
        /// Underlying worker error.
        #[source]
        source: crate::sink::SinkError,
    },

    /// The worker failed to release a task.
    #[error("removing task {task_id}: {source}")]
    Remove {
        /// The task involved.
        task_id: String,
        /// Underlying worker error.
        #[source]
        source: crate::sink::SinkError,
    },

    /// The worker could not program a network. Fatal to the session for the
    /// same reason a task failure is: a task attached to a network the node
    /// never programmed has no connectivity, and starting it anyway would look
    /// healthy to the cluster and be unreachable in practice.
    #[error("programming network {network_id}: {source}")]
    Network {
        /// The network involved.
        network_id: String,
        /// Underlying worker error.
        #[source]
        source: crate::sink::SinkError,
    },

    /// The worker failed to tear a network down.
    #[error("removing network {network_id}: {source}")]
    NetworkRemove {
        /// The network involved.
        network_id: String,
        /// Underlying worker error.
        #[source]
        source: crate::sink::SinkError,
    },

    /// The startup pass over the local task DB failed.
    #[error("rebuilding the task set from the local db: {source}")]
    Init {
        /// Underlying worker error.
        #[source]
        source: crate::sink::SinkError,
    },
}
