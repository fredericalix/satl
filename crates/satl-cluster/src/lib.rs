// SPDX-License-Identifier: BSD-2-Clause
//! Raft-replicated cluster state: openraft FSM, object store, watch feed,
//! log/snapshot persistence with at-rest encryption, and the manager-to-manager
//! transport. See `docs/architecture.md` §6 and §7.
//!
//! Module map:
//!
//! - [`types`] — openraft type config, [`Proposal`]/[`ProposalResponse`]
//! - [`crypto`] — the per-node DEK and the sealed record format (§12.4)
//! - [`log_store`] — [`openraft::storage::RaftLogStorage`] over redb (§6.3)
//! - [`state_machine`] — the in-memory object store FSM + snapshots (§6.1)
//! - [`store`] — [`ClusterStore`]: reads, proposals, watch feed, metrics
//! - [`transport`] — openraft's `RaftNetwork` over tonic + rustls, and the
//!   server side of the `Raft` service (§7, SWK §11.7)
//! - [`server`] — the single internal gRPC server, its mTLS authorization
//!   interceptor, the health registry and the **service-registration seam**
//!   other crates add `Dispatcher`/`NodeCA` through
//! - [`membership`] — `Control.JoinRaft`/`LeaveRaft`, quorum safety, the raft
//!   ID removal blacklist, two-phase demotion (§6.6, SWK §11.3/§11.5/§12.3)
//! - [`forward`] — follower→leader forwarding of store mutations (§6.5)
//! - [`node`] — [`RaftNode`] lifecycle: identity, bootstrap, join, seeding
//! - [`testing`] — a throwaway cluster CA for tests

pub mod crypto;
pub mod forward;
mod fs_util;
pub mod log_store;
pub mod membership;
pub mod node;
pub mod server;
pub mod state_machine;
pub mod store;
pub mod testing;
pub mod transport;
pub mod types;

pub use crypto::{
    DEK_FILE, DEK_LEN, Dek, DekError, OpenSealedError, SEALED_DEK_FILE, UnlockKeyError,
    UnsealError, generate_unlock_key, is_locked, kek_from_unlock_key,
};
pub use forward::{ForwardError, LEADER_ADDR_METADATA, LeaderClient};
pub use log_store::{LogStore, LogStoreError};
pub use membership::{
    CONTROL_ROLE, ControlService, MemberHealth, MembershipError, can_remove_member,
    demote_to_worker, pick_raft_id, resolve_join_addr,
};
pub use node::{NodeError, RaftNode, RaftNodeConfig};
pub use server::{
    Authorizer, DEFAULT_PORT, HealthRegistry, ManagerContext, ManagerSlot, ServerBuilder,
    ServerError, ServerHandle,
};
pub use state_machine::{EVENT_CHANNEL_CAPACITY, StateMachine, StateMachineError};
pub use store::{ClusterMetrics, ClusterStore, ProposeError, RaftMember, StoreView};
pub use transport::{PeerLiveness, RaftTransport, TransportError};
pub use types::{Proposal, ProposalRejection, ProposalResponse, TypeConfig};
