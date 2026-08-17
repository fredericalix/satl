// SPDX-License-Identifier: BSD-2-Clause
//! The dispatcher protocol: the manager ↔ worker control channel
//! (`proto/dispatcher.proto`, architecture §7.1–§7.2, SWK §13–§14).
//!
//! **Both ends of the protocol live in this crate on purpose.** The wire
//! contract is one document (`proto/dispatcher.proto`) and its rules —
//! sequence markers, dependency reference counting, application order, the
//! heartbeat TTL machine — are obligations shared between the two sides. A
//! manager-side change that silently violates an agent-side assumption is the
//! failure mode this layout exists to prevent: the pure pieces the two sides
//! agree on ([`assignment`], [`sequence`], [`liveness`], [`codec`]) are
//! written once and used by both.
//!
//! ```text
//!   worker                                         leader manager
//!   ------                                         --------------
//!   agent::Agent ──── Session ───────────────────▶ manager::Dispatcher
//!        │       ◀─── session id, node, managers, root CA ───┤
//!        ├─────── Heartbeat ─────────────────────▶ liveness::Liveness
//!        │       ◀─── next period ───────────────┤   (TTL → DOWN → ORPHANED)
//!        ├─────── Assignments ───────────────────▶ assignment::AssignmentTracker
//!        │       ◀─── COMPLETE, then INCREMENTAL ┤   (diff + ref counting)
//!        └─────── UpdateTaskStatus ──────────────▶ status::StatusQueue → store
//! ```
//!
//! # Direction rule (CLAUDE.md invariant #3): managers never dial workers
//!
//! Every connection in this crate is opened **by the worker**. The manager
//! side owns no client, no address book of workers and no code path that
//! constructs an outbound channel — the only thing it can do with a worker is
//! answer on a stream the worker is holding open. That is why `Session` and
//! `Assignments` are server-streaming: a manager with something to say parks
//! it on the stream the agent already opened. If a future change needs the
//! manager to reach a worker, the answer is a new agent-initiated RPC, never
//! a dial.
//!
//! # Testability
//!
//! The protocol logic is pure and lives outside the tonic service and the
//! session loop:
//!
//! - [`assignment`] — the assignment set, its diff, the secret/config/network
//!   reference counting and the overlay endpoint table;
//! - [`sequence`] — `applies_to`/`results_in` chaining and gap detection;
//! - [`liveness`] — the heartbeat TTL / `DOWN` / `ORPHANED` state machine,
//!   driven by an injected `Instant`;
//! - [`backoff`] — the agent's reconnect backoff;
//! - [`peer`] — manager selection (local socket first);
//! - [`status`] — status coalescing and the monotonicity guard;
//! - [`codec`] — CBOR payload + mirrored-scalar encoding of the envelopes.
//!
//! The I/O shells are [`manager`] (the gRPC service) and [`agent`] (the
//! session client); both are generic over seams ([`sink::AssignmentSink`],
//! [`agent::ChannelFactory`]) so tests drive them without a network, and the
//! crate's integration tests drive them *over* a real loopback tonic server.

extern crate self as satl_dispatcher;

pub mod agent;
pub mod assignment;
pub mod backoff;
pub mod codec;
pub mod error;
pub mod liveness;
pub mod manager;
pub mod peer;
pub mod sequence;
pub mod sink;
pub mod status;

#[cfg(test)]
pub(crate) mod testing;

use std::time::Duration;

pub use agent::{Agent, AgentConfig, AgentState, ChannelFactory, ConnectError, NodeDescriber};
pub use assignment::{
    AssignmentChange, AssignmentItem, AssignmentTracker, ChangeAction, ChangeKey, DependencyLookup,
    EndpointChanges, GatewayAttachment, NetworkAssignment, NetworkEndpoint, ObjectRef,
};
pub use backoff::Backoff;
pub use codec::CodecError;
pub use error::{ApplyError, SessionError};
pub use liveness::{HeartbeatConfig, Liveness, SessionRejection, Sweep};
pub use manager::{Dispatcher, DispatcherConfig};
pub use peer::{Endpoint, ManagerPeer};
pub use sequence::{SequenceGap, SequenceGenerator, SequenceTracker};
pub use sink::{AssignmentSink, SinkError, WorkerSink};
pub use status::{StatusQueue, StatusWriter};

/// Maximum assignment changes in one `INCREMENTAL` message (architecture
/// §15). A `COMPLETE` snapshot is **not** split: applying it resets the
/// agent's state, so it has to arrive as one message (its bound is the 4 MiB
/// gRPC limit, [`satl_proto::MAX_MESSAGE_SIZE`]).
pub const ASSIGNMENT_BATCH_MAX: usize = 100;

/// Quiescence window assignment changes are batched over (architecture §15).
pub const ASSIGNMENT_QUIESCENCE: Duration = Duration::from_millis(100);

/// Status-report flush interval, on both sides (architecture §15).
pub const STATUS_FLUSH_INTERVAL: Duration = Duration::from_millis(100);

/// Queued status updates that force an immediate flush (architecture §15).
pub const STATUS_FLUSH_MAX: usize = 10_000;

/// Extra TTL granted to nodes moved to `UNKNOWN` by a leadership change: the
/// grace period is doubled so agents have time to find the new leader
/// (architecture §7.1, SWK §13.2).
pub const UNKNOWN_GRACE_FACTOR: u32 = 2;

/// Selection weight every manager is offered with (SWK §13.1 weights them
/// all equally; SatL does the same until there is a reason not to).
pub const MANAGER_WEIGHT: i64 = 10;

/// Response metadata key carrying the leader's address when a follower
/// refuses a dispatcher RPC (`proto/dispatcher.proto`).
///
/// Aliased to `satl-cluster`'s constant rather than re-spelled: the
/// dispatcher redirect and the store-mutation redirect are the same contract,
/// and two string literals is one too many.
pub const LEADER_ADDR_METADATA: &str = satl_cluster::LEADER_ADDR_METADATA;

/// Timeout on session initiation and on every unary dispatcher RPC
/// (SWK §14.1).
pub const RPC_TIMEOUT: Duration = Duration::from_secs(5);
