// SPDX-License-Identifier: BSD-2-Clause
//! Raft membership: `Control.JoinRaft` / `Control.LeaveRaft`, quorum safety,
//! the raft-ID removal blacklist and two-phase demotion (architecture §6.6,
//! SWK §11.3, §11.5, §12.3).
//!
//! # Join (SWK §11.3, in order)
//!
//! 1. Resolve the joiner's address — its own `addr`, or the gRPC peer address
//!    when it sent an unspecified IP or nothing at all.
//! 2. **Health-check the joiner back** (`grpc.health.v1.Health/Check` with
//!    service name `raft`, 5 s, over mTLS). This is the step most
//!    reimplementations skip: a joiner the leader cannot reach would count
//!    towards quorum without being able to vote.
//! 3. Dedupe by node ID — a re-join only updates the address.
//! 4. Pick an unused, non-blacklisted random `u64` raft ID.
//! 5. Admit it as a **learner** and answer; a background task promotes it to
//!    voter as soon as it starts replicating. The split is forced by
//!    openraft's joint consensus — see [`admit_member`] for why it cannot be
//!    one step, and why SwarmKit's etcd/raft can do it in one.
//!
//! # Quorum safety (SWK §11.5)
//!
//! [`can_remove_member`] counts the members that would remain **reachable**
//! after a removal and refuses if that count drops below `(n−1)/2 + 1`.
//! Reachability is the transport's own liveness map
//! ([`crate::transport::PeerLiveness`]), the equivalent of SwarmKit's
//! `transport.Active(id)`.
//!
//! # Never reusing a raft ID
//!
//! Removed raft IDs go on a blacklist that lives in the state machine and
//! travels in snapshots (SWK §11.1). It is derived from the applied
//! membership entries rather than proposed separately, so it cannot disagree
//! with the membership it describes. [`crate::transport::RaftService`] refuses
//! messages from blacklisted IDs and [`pick_raft_id`] never hands one out.
//!
//! # Demotion is raft-first (SWK §12.3)
//!
//! [`demote_to_worker`] removes the node from consensus and only then flips
//! `Node.spec.role`, so certificate renewal cannot hand a worker certificate
//! to a live raft member.
//!
//! # Leadership transfer
//!
//! openraft 0.9 has no `TransferLeadership`. [`yield_leadership`] stands in
//! for it: the leader stops its ticker, its followers' leases expire, one of
//! them campaigns, and the old leader learns the new term from the first
//! `AppendEntries` it receives. The removal is then finished by the new
//! leader, which is exactly SwarmKit's sequencing — a departing leader cannot
//! reliably observe its own removal commit.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use openraft::error::{ChangeMembershipError, ClientWriteError, RaftError};
use openraft::{BasicNode, ChangeMembers};
use rand::RngExt;
use tonic::{Request, Response, Status};

use satl_ca::RoleRequirement;
use satl_core::{
    Availability, CertificateStatus, Id, ManagerStatus, Meta, Node, NodeDescription, NodeRole,
    NodeSpec, NodeState, NodeStatus, Platform, Reachability, Resources, StoreAction, StoreObject,
};
use satl_proto::MAX_MESSAGE_SIZE;
use satl_proto::health::HealthCheckRequest;
use satl_proto::health::health_check_response::ServingStatus;
use satl_proto::health::health_client::HealthClient;
use satl_proto::v2::control_server::Control;
use satl_proto::v2::{self as pb};

use crate::forward;
use crate::server::{
    DEFAULT_PORT, HEALTH_SERVICE_RAFT, ManagerContext, ManagerSlot, peer_addr, peer_identity,
};
use crate::store::{ClusterStore, RaftMember};
use crate::transport::{HEALTH_CHECK_BUDGET, PeerLiveness};
use openraft::async_runtime::watch::WatchReceiver;

use crate::store::ProposeError;
use crate::types::{ProposalRejection, Raft};

/// The role the `Control` service's interceptor enforces.
///
/// **`WorkerOrManager`, not `Manager`** — and that is deliberate. `JoinRaft`
/// is a documented authorization exception (`proto/control.proto`): a promoted
/// node calls it *before* its manager certificate has been renewed, so its OU
/// may still be `satl-worker`. The interceptor therefore admits either role
/// and every other RPC on the service re-checks `Manager` itself
/// ([`require_manager`]); `JoinRaft` checks the role recorded on the node
/// **object** instead, which the role manager has already flipped.
pub const CONTROL_ROLE: RoleRequirement = RoleRequirement::WorkerOrManager;

/// Budget for the whole membership change once the joiner has been
/// health-checked. Bounds the RPC — openraft's own waits are unbounded.
const MEMBERSHIP_CHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long [`yield_leadership`] waits for the target to take over.
///
/// openraft 0.10's `transfer_leader` broadcasts a request that **disarms the
/// leader lease** for the designated node, so the handover costs one broadcast
/// plus one election round -- not the `leader_lease + election_timeout`
/// (30-40 s at architecture §15's timings) that a node waiting for a
/// spontaneous election has to pay. The budget is generous against that, so a
/// single lost round still fits, and small enough that an operator waiting on
/// `satl node demote` is not left guessing.
const LEADERSHIP_TRANSFER_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the leader keeps re-reading and retrying a departing node's
/// object ([`finish_departure`]).
///
/// The object is contended right after a leadership handover (the new leader
/// writes its own manager status, description refreshes land), so a sequence
/// conflict is the expected first outcome, not an error. Long enough to
/// outlast that burst, short enough that a genuinely stuck write still
/// answers the operator.
const DEPARTURE_WRITE_BUDGET: Duration = Duration::from_secs(10);

/// How long the leader keeps trying to promote a freshly admitted learner
/// before giving up and logging loudly.
const PROMOTION_TIMEOUT: Duration = Duration::from_mins(2);

/// How often the promotion task re-checks whether the learner is replicating.
const PROMOTION_POLL: Duration = Duration::from_millis(50);

/// How long to wait before retrying a configuration change that openraft
/// refused because another one was still committing.
const MEMBERSHIP_RETRY_DELAY: Duration = Duration::from_millis(50);

/// Attempts at drawing an unused raft ID before giving up. With a 64-bit
/// space and a handful of members, one attempt always suffices; the bound
/// only turns a broken RNG into an error instead of a hang.
const RAFT_ID_ATTEMPTS: usize = 32;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A membership operation could not be carried out.
#[derive(Debug, thiserror::Error)]
pub enum MembershipError {
    /// This node is not the leader; only the leader changes membership.
    #[error("not the raft leader{}", match leader_addr {
        Some(addr) => format!("; the current leader is at {addr}"),
        None => String::from("; no leader is currently known"),
    })]
    NotLeader {
        /// Where to retry, if known.
        leader_addr: Option<String>,
    },
    /// Removing this member would cost the cluster its quorum.
    ///
    /// "Reachable" here means **answered an outgoing raft RPC inside the
    /// liveness window** (`RaftTiming::liveness_window`, one election
    /// timeout), which is not the same as "up". A manager that has just won an
    /// election, or whose connection was re-established a moment ago, has not
    /// answered *this* node yet and counts as unreachable until it does. The
    /// message says so, because the alternative -- "only 1 of 2 members are
    /// reachable" on a cluster every `satl node ls` shows healthy -- sends an
    /// operator hunting a network fault that is not there. Measured: a demote
    /// refused this way succeeded a minute later, unchanged, on the same idle
    /// cluster.
    #[error(
        "refusing to remove raft member {raft_id}: only {reachable} of the remaining {remaining} \
         members have answered this node within the liveness window, and {needed} are needed \
         for quorum. If the other managers are up and `satl node ls` shows them Reachable, this \
         is transient -- they have not answered a raft RPC here *yet* -- and the same command \
         succeeds shortly after. If they are genuinely down, bring them back or force-remove \
         them one at a time"
    )]
    QuorumWouldBreak {
        /// The member that was to be removed.
        raft_id: u64,
        /// Members left after the removal.
        remaining: usize,
        /// How many of them answered recently.
        reachable: usize,
        /// How many are needed.
        needed: usize,
    },
    /// The joiner could not be reached back.
    #[error(
        "refusing to admit node {node_id} at {addr}: its {service} health check did not \
         succeed within {budget:?} ({reason}). A member the leader cannot reach would count \
         towards quorum without being able to vote"
    )]
    JoinerUnreachable {
        /// The joining node.
        node_id: String,
        /// The address that was probed.
        addr: String,
        /// The health service name probed.
        service: &'static str,
        /// The probe budget.
        budget: Duration,
        /// What went wrong.
        reason: String,
    },
    /// A removal forwarded to the leader failed there, or in transit.
    #[error("the raft leader at {addr} could not remove member {raft_id}: {message}")]
    ForwardedRemove {
        /// The leader address that was asked.
        addr: String,
        /// The member that was to be removed.
        raft_id: u64,
        /// The leader's (or the transport's) explanation.
        message: String,
    },

    /// No raft ID could be drawn.
    #[error("could not draw an unused raft ID in {attempts} attempts")]
    NoRaftId {
        /// How many draws were tried.
        attempts: usize,
    },
    /// The member named does not exist, or does not match the node named.
    #[error("{message}")]
    UnknownMember {
        /// Operator-facing explanation.
        message: String,
    },
    /// Raft refused or failed the configuration change.
    #[error("raft {op} for member {raft_id}: {message}")]
    Raft {
        /// What was attempted.
        op: &'static str,
        /// The member involved.
        raft_id: u64,
        /// openraft's error text.
        message: String,
    },
    /// The membership change did not commit within the budget.
    #[error(
        "raft {op} for member {raft_id} did not commit within {budget:?}; the outcome is \
         unknown. Re-read the membership before retrying"
    )]
    Timeout {
        /// What was attempted.
        op: &'static str,
        /// The member involved.
        raft_id: u64,
        /// The budget that expired.
        budget: Duration,
    },
    /// The store transaction that follows a membership change failed.
    #[error("recording the membership change in the store: {source}")]
    Store {
        /// Underlying propose error.
        #[source]
        source: crate::store::ProposeError,
    },
    /// The store transaction that follows a membership change failed on (or
    /// on the way to) the leader.
    #[error("recording the membership change through the leader: {source}")]
    ForwardedStore {
        /// Underlying forwarding error.
        #[source]
        source: crate::forward::ForwardError,
    },
    /// Leadership could not be handed to another manager.
    #[error(
        "this manager is the leader and could not hand leadership over within {budget:?}; retry \
         the removal once another manager has been elected"
    )]
    LeadershipTransfer {
        /// The budget that expired.
        budget: Duration,
    },
}

impl From<MembershipError> for Status {
    fn from(err: MembershipError) -> Self {
        let message = err.to_string();
        match err {
            MembershipError::NotLeader { leader_addr } => {
                forward::leader_redirect_status(leader_addr.as_deref(), &message)
            }
            MembershipError::QuorumWouldBreak { .. }
            | MembershipError::JoinerUnreachable { .. }
            | MembershipError::ForwardedRemove { .. }
            | MembershipError::LeadershipTransfer { .. } => Status::failed_precondition(message),
            MembershipError::UnknownMember { .. } => Status::not_found(message),
            MembershipError::Timeout { .. } => Status::deadline_exceeded(message),
            MembershipError::NoRaftId { .. }
            | MembershipError::Raft { .. }
            | MembershipError::Store { .. }
            | MembershipError::ForwardedStore { .. } => Status::internal(message),
        }
    }
}

/// A join address could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JoinAddrError {
    /// The joiner sent nothing and the transport has no peer address either.
    #[error(
        "the joiner sent no address and the connection has no peer address to substitute; set \
         the advertise address explicitly on the joining node"
    )]
    Unresolvable,
    /// The address has no port and no default could be applied.
    #[error("join address {addr:?} has no port: expected host:port")]
    MissingPort {
        /// The offending address.
        addr: String,
    },
    /// The address is syntactically unusable.
    #[error("join address {addr:?} is not a usable host:port: {reason}")]
    Malformed {
        /// The offending address.
        addr: String,
        /// Why it was rejected.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Resolves the address peers should dial for a joining manager (SWK §11.3).
///
/// - empty `requested` → the gRPC peer's IP with `default_port`;
/// - `requested` with an **unspecified** IP (`0.0.0.0:p`, `[::]:p`) → the
///   gRPC peer's IP, keeping `p`;
/// - anything else → taken as given (a hostname is left alone: the joiner
///   knows its own name better than the socket does).
pub fn resolve_join_addr(
    requested: &str,
    peer: Option<SocketAddr>,
    default_port: u16,
) -> Result<String, JoinAddrError> {
    let requested = requested.trim();
    if requested.is_empty() {
        let peer = peer.ok_or(JoinAddrError::Unresolvable)?;
        return Ok(format_addr(peer.ip(), default_port));
    }

    if let Ok(socket) = requested.parse::<SocketAddr>() {
        if socket.ip().is_unspecified() {
            let peer = peer.ok_or(JoinAddrError::Unresolvable)?;
            return Ok(format_addr(peer.ip(), socket.port()));
        }
        return Ok(socket.to_string());
    }

    // Not a literal socket address: must still be host:port.
    let (host, port) = requested
        .rsplit_once(':')
        .ok_or_else(|| JoinAddrError::MissingPort {
            addr: requested.to_owned(),
        })?;
    if host.is_empty() {
        return Err(JoinAddrError::Malformed {
            addr: requested.to_owned(),
            reason: "empty host".to_owned(),
        });
    }
    port.parse::<u16>().map_err(|e| JoinAddrError::Malformed {
        addr: requested.to_owned(),
        reason: e.to_string(),
    })?;
    Ok(requested.to_owned())
}

/// `host:port`, bracketing IPv6 literals.
fn format_addr(ip: IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
}

/// One member's contribution to the quorum-safety count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberHealth {
    /// The member's raft ID.
    pub raft_id: u64,
    /// Whether it answered recently (the local node counts as reachable).
    pub reachable: bool,
}

/// SwarmKit's `CanRemoveMember` (SWK §11.5).
///
/// `members` is the membership **including** the member about to go. The
/// removal is allowed only if at least `(n−1)/2 + 1` of the members that
/// remain are reachable — you cannot remove a member if that loses quorum.
///
/// Note the quorum is computed from `n`, the size *before* the removal: that
/// is SwarmKit's arithmetic, and it is the conservative one (removing the
/// third of three members needs both survivors alive).
pub fn can_remove_member(members: &[MemberHealth], raft_id: u64) -> Result<(), MembershipError> {
    let total = members.len();
    let needed = total.saturating_sub(1) / 2 + 1;
    let remaining: Vec<MemberHealth> = members
        .iter()
        .copied()
        .filter(|m| m.raft_id != raft_id)
        .collect();
    let reachable = remaining.iter().filter(|m| m.reachable).count();
    if reachable < needed {
        return Err(MembershipError::QuorumWouldBreak {
            raft_id,
            remaining: remaining.len(),
            reachable,
            needed,
        });
    }
    Ok(())
}

/// Draws a raft ID that is nonzero, unused and not blacklisted (SWK §11.1).
///
/// `draw` is the source of candidates — [`random_raft_id`] in production, a
/// rigged one in tests. Taking it as a closure keeps this the pure, testable
/// half of "pick an ID nobody has ever had".
pub fn pick_raft_id(
    used: &BTreeSet<u64>,
    blacklist: &BTreeSet<u64>,
    mut draw: impl FnMut() -> u64,
) -> Result<u64, MembershipError> {
    for _ in 0..RAFT_ID_ATTEMPTS {
        let candidate = draw();
        if candidate != 0 && !used.contains(&candidate) && !blacklist.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(MembershipError::NoRaftId {
        attempts: RAFT_ID_ATTEMPTS,
    })
}

/// The production candidate source for [`pick_raft_id`].
#[must_use]
pub fn random_raft_id() -> u64 {
    rand::rng().random()
}

/// The membership as [`can_remove_member`] wants it: every member plus
/// whether it answered inside [`LIVENESS_WINDOW`]. The local node is always
/// reachable — it is the one doing the counting.
#[must_use]
pub fn member_health(
    members: &[RaftMember],
    local_raft_id: u64,
    liveness: &PeerLiveness,
    window: Duration,
) -> Vec<MemberHealth> {
    members
        .iter()
        .map(|m| MemberHealth {
            raft_id: m.raft_id,
            reachable: m.raft_id == local_raft_id || liveness.is_active(m.raft_id, window),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Probes `Health.Check(service)` on `addr` over mTLS, within `budget`.
///
/// This is step 2 of the join sequence and the reason a partitioned joiner
/// never reaches the quorum count.
pub async fn health_check_peer(
    ctx: &ManagerContext,
    node_id: &str,
    addr: &str,
    service: &'static str,
    budget: Duration,
) -> Result<(), MembershipError> {
    let unreachable = |reason: String| MembershipError::JoinerUnreachable {
        node_id: node_id.to_owned(),
        addr: addr.to_owned(),
        service,
        budget,
        reason,
    };

    let channel = ctx
        .require_channels("the JoinRaft health probe")
        .map_err(|e| unreachable(e.message().to_owned()))?
        .channel(addr)
        .map_err(|e| unreachable(e.to_string()))?;
    let mut client = HealthClient::new(channel)
        .max_decoding_message_size(MAX_MESSAGE_SIZE)
        .max_encoding_message_size(MAX_MESSAGE_SIZE);

    let call = client.check(HealthCheckRequest {
        service: service.to_owned(),
    });
    let response = tokio::time::timeout(budget, call)
        .await
        .map_err(|_| unreachable(format!("no answer within {budget:?}")))?
        .map_err(|status| unreachable(format!("{:?}: {}", status.code(), status.message())))?;

    let status = response.into_inner().status();
    if status != ServingStatus::Serving {
        return Err(unreachable(format!("health status is {status:?}")));
    }
    tracing::debug!(node_id, addr, service, "joiner answered its health check");
    Ok(())
}

/// Admits a manager into the raft group, or updates an existing member's
/// address. Leader-only; the caller has already authenticated the joiner.
///
/// Returns the raft ID the joiner must persist and the committed membership.
pub async fn admit_member(
    ctx: &ManagerContext,
    node_id: &Id,
    addr: &str,
) -> Result<(u64, Vec<RaftMember>), MembershipError> {
    let members = ctx.store.raft_members();
    let known: BTreeSet<u64> = members.iter().map(|m| m.raft_id).collect();

    // Step 3: dedupe by node ID. The node object carries the mapping from
    // node ID to raft ID (`manager_status.raft_id`), so a re-join finds its
    // own slot instead of consuming a second one.
    let existing = ctx
        .store
        .view()
        .node(node_id)
        .and_then(|n| n.manager_status.as_ref().map(|m| m.raft_id))
        .filter(|raft_id| known.contains(raft_id));

    if let Some(raft_id) = existing {
        let current = members.iter().find(|m| m.raft_id == raft_id);
        if current.is_some_and(|m| m.addr == addr) {
            tracing::info!(node_id = %node_id, raft_id, addr, "re-join of a known member; nothing to change");
        } else {
            tracing::info!(node_id = %node_id, raft_id, addr, "re-join of a known member; updating its address");
            change_membership(
                ctx,
                "update member address",
                raft_id,
                ChangeMembers::SetNodes(BTreeMap::from([(
                    raft_id,
                    BasicNode::new(addr.to_owned()),
                )])),
                true,
            )
            .await?;
        }
        record_manager_status(ctx, node_id, raft_id, addr).await?;
        // A re-join also heals a promotion that never completed (the leader
        // died between admitting the learner and committing it as a voter).
        if !current.is_some_and(|m| m.voter) {
            spawn_promotion(ctx.clone(), raft_id);
        }
        return Ok((raft_id, ctx.store.raft_members()));
    }

    // Step 4: an unused, non-blacklisted ID. Also excludes IDs already
    // recorded on other node objects, so a member whose membership entry has
    // not been applied here yet cannot have its ID handed out twice.
    let mut used = known;
    used.extend(
        ctx.store
            .view()
            .nodes()
            .iter()
            .filter_map(|n| n.manager_status.as_ref().map(|m| m.raft_id)),
    );
    let blacklist = ctx.store.removed_raft_ids();
    let raft_id = pick_raft_id(&used, &blacklist, random_raft_id)?;

    // Step 5: admit as a **learner**, and promote to voter in the background
    // once the joiner is replicating.
    //
    // The two steps cannot be one, and the reason is openraft-specific:
    // openraft changes the voter set through **joint consensus**, so the
    // joint entry needs a majority of the *new* configuration — which
    // includes the joiner. The joiner, meanwhile, cannot start its raft node
    // until this RPC has told it which raft ID it owns. Committing the
    // promotion inside this call would therefore deadlock.
    //
    // A learner does not count towards any quorum, so admitting one is safe
    // for the leader alone to commit; [`spawn_promotion`] finishes the job as
    // soon as the joiner acknowledges its first entry. (etcd/raft, which
    // SwarmKit uses, commits a conf change against the *old* configuration
    // and so gets away with a single step — that is the difference, not a
    // deviation from SWK §11.3's sequence.)
    tracing::info!(node_id = %node_id, raft_id, addr, "admitting a new raft member as a learner");
    change_membership(
        ctx,
        "add learner",
        raft_id,
        ChangeMembers::AddNodes(BTreeMap::from([(raft_id, BasicNode::new(addr.to_owned()))])),
        true,
    )
    .await?;

    record_manager_status(ctx, node_id, raft_id, addr).await?;
    spawn_promotion(ctx.clone(), raft_id);

    let members = ctx.store.raft_members();
    tracing::info!(
        node_id = %node_id,
        raft_id,
        addr,
        members = members.len(),
        "raft member admitted"
    );
    Ok((raft_id, members))
}

/// Promotes a learner to voter once it is replicating (see [`admit_member`]).
///
/// Runs in the background because the joiner only starts its raft node after
/// `JoinRaft` has answered. Gives up — loudly — if the leader changes, the
/// member disappears, or the joiner never acknowledges anything.
fn spawn_promotion(ctx: ManagerContext, raft_id: u64) {
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + PROMOTION_TIMEOUT;
        loop {
            if tokio::time::Instant::now() >= deadline {
                tracing::error!(
                    raft_id,
                    timeout = ?PROMOTION_TIMEOUT,
                    "learner never acknowledged replication; it stays a learner and does not \
                     count towards quorum. Check the internal gRPC connectivity to it"
                );
                return;
            }
            if !ctx.store.metrics().is_leader {
                tracing::info!(
                    raft_id,
                    "no longer the leader; the new leader promotes this learner on its re-join"
                );
                return;
            }
            let members = ctx.store.raft_members();
            match members.iter().find(|m| m.raft_id == raft_id) {
                None => {
                    tracing::info!(raft_id, "learner disappeared before it could be promoted");
                    return;
                }
                Some(member) if member.voter => return,
                Some(_) => {}
            }

            if learner_is_replicating(&ctx, raft_id) {
                let mut voters: BTreeSet<u64> = members
                    .iter()
                    .filter(|m| m.voter)
                    .map(|m| m.raft_id)
                    .collect();
                voters.insert(raft_id);
                // `retain: true` — nothing is being removed here, and a voter
                // that somehow fell out of the set must not be evicted by a
                // promotion.
                match change_membership(
                    &ctx,
                    "promote to voter",
                    raft_id,
                    ChangeMembers::ReplaceAllVoters(voters),
                    true,
                )
                .await
                {
                    Ok(()) => {
                        tracing::info!(raft_id, "learner promoted to voter");
                        return;
                    }
                    Err(err) => {
                        tracing::warn!(raft_id, error = %err, "promoting the learner failed; retrying");
                    }
                }
            }
            tokio::time::sleep(PROMOTION_POLL).await;
        }
    });
}

/// Whether the leader has seen `raft_id` acknowledge at least one entry.
fn learner_is_replicating(ctx: &ManagerContext, raft_id: u64) -> bool {
    ctx.raft
        .metrics()
        .borrow_watched()
        .replication
        .as_ref()
        .and_then(|progress| progress.get(&raft_id).copied())
        .is_some_and(|matched| matched.is_some())
}

/// Removes a member from the raft group, refusing if quorum would break.
///
/// **The decision is the leader's.** On a non-leader manager the removal is
/// forwarded to the leader over `Control.LeaveRaft` rather than evaluated
/// here, because the quorum-safety arithmetic reads the *local*
/// [`PeerLiveness`] map — outbound RPC outcomes — and a follower sends
/// almost nothing: counting quorum from its map refuses every removal with a
/// phantom "only 1 reachable", permanently, while the cluster is perfectly
/// healthy (found live by the `ca_rotate` cluster scenario demoting a node
/// through a manager that had just lost leadership).
///
/// A leader asked to remove **itself** hands leadership over first — a
/// departing leader cannot reliably observe its own removal commit
/// (SWK §11.5) — and then forwards to whoever won, so the caller gets the
/// removal, not a "retry elsewhere".
///
/// SWK §11.5 transfers to the *longest-active* peer. [`yield_leadership`]
/// picks the *most caught-up* one instead, because openraft's
/// `TransferLeaderRequest` names a `last_log_id` the target must have reached
/// before it may campaign: a long-lived but lagging peer would be handed a
/// request it cannot act on. Liveness still gates the removal itself, through
/// `can_remove_member`'s quorum check.
pub async fn remove_member(
    ctx: &ManagerContext,
    raft_id: u64,
    departing: Departing,
) -> Result<Vec<RaftMember>, MembershipError> {
    if !ctx.store.metrics().is_leader {
        return remove_member_via_leader(ctx, raft_id, departing).await;
    }
    let members = ctx.store.raft_members();
    let Some(target) = members.iter().find(|m| m.raft_id == raft_id) else {
        return Err(MembershipError::UnknownMember {
            message: format!("raft member {raft_id} is not part of this cluster's membership"),
        });
    };

    // Quorum arithmetic is about **voters**. Dropping a learner cannot cost
    // the cluster its quorum, because a learner never counted towards one.
    if target.voter {
        let voters: Vec<RaftMember> = members.iter().filter(|m| m.voter).cloned().collect();
        can_remove_member(
            &member_health(&voters, ctx.raft_id, &ctx.liveness, ctx.liveness_window),
            raft_id,
        )?;
    }

    if raft_id == ctx.raft_id {
        tracing::info!(
            raft_id,
            "asked to remove the current leader; handing leadership over first"
        );
        yield_leadership(&ctx.raft).await?;
        return remove_member_via_leader(ctx, raft_id, departing).await;
    }

    // Two steps, because openraft models "stop voting" and "leave the
    // configuration" separately. The second is what puts the raft ID on the
    // removal blacklist: the state machine records IDs that disappear from
    // the node set, and `ReplaceAllVoters` alone leaves a former voter behind
    // as a node.
    if target.voter {
        let voters: BTreeSet<u64> = members
            .iter()
            .filter(|m| m.voter && m.raft_id != raft_id)
            .map(|m| m.raft_id)
            .collect();
        change_membership(
            ctx,
            "remove voter",
            raft_id,
            ChangeMembers::ReplaceAllVoters(voters),
            false,
        )
        .await?;
    }
    if ctx
        .store
        .raft_members()
        .iter()
        .any(|m| m.raft_id == raft_id)
    {
        change_membership(
            ctx,
            "remove member",
            raft_id,
            ChangeMembers::RemoveNodes(BTreeSet::from([raft_id])),
            false,
        )
        .await?;
    }
    ctx.liveness.forget(raft_id);

    finish_departure(ctx, raft_id, departing).await?;
    let members = ctx.store.raft_members();
    tracing::info!(raft_id, members = members.len(), "raft member removed");
    Ok(members)
}

/// Deadline on a forwarded `Control.LeaveRaft` call: the membership change
/// budget plus slack for the hop itself.
const LEAVE_FORWARD_DEADLINE: Duration = Duration::from_secs(40);

/// Redirect hops a forwarded removal follows before giving up: the first
/// dial, plus a leader that moved, plus a leader that yielded because it was
/// itself the target.
const LEAVE_FORWARD_HOPS: usize = 3;

/// Forwards a member removal to the raft leader over `Control.LeaveRaft`,
/// following the `satl-leader-addr` redirect (architecture §6.5). See
/// [`remove_member`] for why a non-leader must never decide this locally.
async fn remove_member_via_leader(
    ctx: &ManagerContext,
    raft_id: u64,
    departing: Departing,
) -> Result<Vec<RaftMember>, MembershipError> {
    let refused = |addr: &str, message: String| MembershipError::ForwardedRemove {
        addr: addr.to_owned(),
        raft_id,
        message,
    };
    // The node ID the member belongs to, read from the same replicated store
    // the leader validates the pair against.
    let node_id = ctx
        .store
        .view()
        .nodes()
        .into_iter()
        .find(|node| {
            node.manager_status
                .as_ref()
                .is_some_and(|status| status.raft_id == raft_id)
        })
        .map(|node| node.id.to_string())
        .unwrap_or_default();
    let channels = ctx
        .channels
        .as_ref()
        .ok_or_else(|| refused("(none)", "this node has no internal transport".to_owned()))?;

    let mut addr = ctx
        .store
        .leader_addr()
        .ok_or(MembershipError::NotLeader { leader_addr: None })?;
    for _hop in 0..LEAVE_FORWARD_HOPS {
        let channel = channels
            .channel(&addr)
            .map_err(|error| refused(&addr, error.to_string()))?;
        let mut client = pb::control_client::ControlClient::new(channel)
            .max_decoding_message_size(MAX_MESSAGE_SIZE)
            .max_encoding_message_size(MAX_MESSAGE_SIZE);
        let mut request = tonic::Request::new(pb::LeaveRaftRequest {
            raft_id,
            node_id: node_id.clone(),
            demote: matches!(departing, Departing::BecomesWorker { .. }),
        });
        request.set_timeout(LEAVE_FORWARD_DEADLINE);
        match client.leave_raft(request).await {
            Ok(response) => {
                tracing::info!(
                    raft_id,
                    leader = %addr,
                    "raft member removed by the leader (forwarded)"
                );
                // `LeaveRaftResponse` carries the post-removal membership
                // without the voter bit; no caller of a forwarded removal
                // reads it (the join path, which does, is always local to
                // the leader), so it is carried as voters.
                return Ok(response
                    .into_inner()
                    .members
                    .iter()
                    .map(|member| RaftMember {
                        raft_id: member.raft_id,
                        addr: member.addr.clone(),
                        voter: true,
                        leader: member.leader,
                    })
                    .collect());
            }
            Err(status) => {
                if let Some(leader) = forward::leader_addr_from_status(&status) {
                    tracing::debug!(from = %addr, to = %leader, "LeaveRaft redirected to the leader");
                    addr = leader;
                    continue;
                }
                return Err(refused(&addr, status.message().to_owned()));
            }
        }
    }
    Err(refused(
        &addr,
        format!("every manager redirected without answering ({LEAVE_FORWARD_HOPS} hops)"),
    ))
}

/// Two-phase demotion, **raft first** (SWK §12.3, architecture §6.6).
///
/// Leaves consensus (re-checking quorum safety), and only once the node is no
/// longer a member flips `Node.spec.role` to worker — issuing a worker
/// certificate to a live raft member could cost the cluster its quorum.
pub async fn demote_to_worker(ctx: &ManagerContext, node_id: &Id) -> Result<(), MembershipError> {
    let node = ctx
        .store
        .view()
        .node(node_id)
        .ok_or_else(|| MembershipError::UnknownMember {
            message: format!("node {node_id} does not exist"),
        })?;

    // Phase 1: out of consensus. A node with no manager status, or one whose
    // raft ID is already gone from the membership, is already out.
    if let Some(status) = node.manager_status.as_ref() {
        let raft_id = status.raft_id;
        if ctx
            .store
            .raft_members()
            .iter()
            .any(|m| m.raft_id == raft_id)
        {
            tracing::info!(node_id = %node_id, raft_id, "demotion phase 1: leaving consensus");
            remove_member(
                ctx,
                raft_id,
                Departing::BecomesWorker {
                    node_id: node_id.clone(),
                },
            )
            .await?;
            // The leader wrote the role in the same breath as the membership
            // change (`finish_departure`), because this node may be the one
            // leaving and a node out of consensus has a store that no longer
            // moves. Nothing left to do here.
            return Ok(());
        }
    }

    // Phase 2: only now is the role safe to change.
    //
    // Retried from a fresh read on a sequence conflict, because the node
    // object is *busy*: the new leader writes its own manager status the
    // moment phase 1 hands leadership over, and every node's description
    // refresh rewrites it periodically. Optimistic concurrency turns those
    // into `SequenceConflict` (architecture §3), and a single-shot write loses
    // that race often enough to be the normal outcome -- measured on the
    // testbed, where the first demote of a live leader after the transfer fix
    // failed with `store has version 1185, caller wrote from version 1081`,
    // leaving the node out of consensus but still holding the manager role:
    // exactly the half-demoted state the phase ordering exists to prevent.
    //
    // The local view is read each pass rather than once, and it is the
    // *applied* store, which lags the leader — so the loop also gives this
    // node time to catch up with the write it lost to.
    let deadline = Instant::now() + DEPARTURE_WRITE_BUDGET;
    loop {
        let node =
            ctx.store
                .view()
                .node(node_id)
                .ok_or_else(|| MembershipError::UnknownMember {
                    message: format!("node {node_id} disappeared while it was being demoted"),
                })?;
        if node.spec.role == NodeRole::Worker && node.manager_status.is_none() {
            return Ok(());
        }
        let mut updated = (*node).clone();
        updated.spec.role = NodeRole::Worker;
        updated.manager_status = None;
        // Through the leader, wherever it is: after phase 1 this manager may
        // be a follower (it may even be the node being demoted), and a local
        // propose would refuse with "not the raft leader".
        let outcome = forward::propose_via(
            ctx,
            vec![StoreAction::Update(StoreObject::Node(updated))],
            forward::local_identity(),
        )
        .await;
        match outcome {
            Ok(_) => {
                tracing::info!(node_id = %node_id, "demotion phase 2: role set to worker");
                return Ok(());
            }
            Err(forward::ForwardError::Rejected(ProposalRejection::SequenceConflict {
                expected,
                found,
                ..
            })) if Instant::now() < deadline => {
                tracing::debug!(
                    node_id = %node_id,
                    expected,
                    found,
                    "the node object moved under the demotion; re-reading and retrying"
                );
                tokio::time::sleep(MEMBERSHIP_RETRY_DELAY).await;
            }
            Err(source) => return Err(MembershipError::ForwardedStore { source }),
        }
    }
}

/// Hands leadership to another manager (openraft 0.9 has no
/// `TransferLeadership`; see the module docs).
///
/// Stops the local ticker so this node neither heartbeats nor campaigns, and
/// waits for a different leader to appear. The ticker is restored either way
/// — a node that failed to hand over must go back to participating normally.
pub async fn yield_leadership(raft: &Raft) -> Result<(), MembershipError> {
    let (me, target) = {
        let metrics = raft.metrics().borrow_watched().clone();
        let me = metrics.id;
        // Prefer the most caught-up voter: it needs the fewest entries before
        // it can serve, and openraft refuses to hand leadership to a node
        // behind the `last_log_id` it names in the request.
        let target = metrics
            .membership_config
            .voter_ids()
            .filter(|id| *id != me)
            .max_by_key(|id| {
                metrics
                    .replication
                    .as_ref()
                    .and_then(|r| r.get(id).copied().flatten())
                    .map(|log_id| log_id.index)
            });
        (me, target)
    };
    let Some(target) = target else {
        return Err(MembershipError::LeadershipTransfer {
            budget: LEADERSHIP_TRANSFER_TIMEOUT,
        });
    };

    tracing::info!(
        previous_leader = me,
        target,
        "asking openraft to transfer leadership"
    );
    raft.trigger()
        .transfer_leader(target)
        .await
        .map_err(|e| MembershipError::Raft {
            op: "transfer_leader",
            raft_id: target,
            message: e.to_string(),
        })?;

    // `transfer_leader` only submits the command; the handover is observed on
    // the metrics watch. No ticker fiddling here: 0.10 broadcasts a request
    // that disarms the target's leader lease, which is the whole reason this
    // terminates where the 0.9 stand-in could not.
    let result = tokio::time::timeout(LEADERSHIP_TRANSFER_TIMEOUT, async {
        let mut rx = raft.metrics();
        loop {
            let leader = rx.borrow_watched().current_leader;
            if leader.is_some_and(|id| id != me) {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    })
    .await;

    if result.is_err() {
        return Err(MembershipError::LeadershipTransfer {
            budget: LEADERSHIP_TRANSFER_TIMEOUT,
        });
    }
    tracing::info!(
        previous_leader = me,
        new_leader = ?raft.metrics().borrow_watched().current_leader,
        "leadership handed over"
    );
    Ok(())
}

/// One bounded `change_membership` call with uniform error reporting.
///
/// openraft serializes configuration changes: a second one raised while the
/// first has not committed is refused with `InProgress`. That is a *timing*
/// condition, not an operator error — a demotion issued moments after a join
/// must not fail because the join's promotion is still committing — so it is
/// retried inside the same budget.
async fn change_membership(
    ctx: &ManagerContext,
    op: &'static str,
    raft_id: u64,
    change: ChangeMembers<u64, BasicNode>,
    retain: bool,
) -> Result<(), MembershipError> {
    let deadline = tokio::time::Instant::now() + MEMBERSHIP_CHANGE_TIMEOUT;
    loop {
        let call = ctx.raft.change_membership(change.clone(), retain);
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let timed_out = || MembershipError::Timeout {
            op,
            raft_id,
            budget: MEMBERSHIP_CHANGE_TIMEOUT,
        };
        if remaining.is_zero() {
            return Err(timed_out());
        }
        match tokio::time::timeout(remaining, call).await {
            Err(_) => return Err(timed_out()),
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(err)) => {
                if let Some(forward) = err.forward_to_leader() {
                    return Err(MembershipError::NotLeader {
                        leader_addr: forward
                            .leader_node
                            .as_ref()
                            .map(|node| node.addr.clone())
                            .filter(|addr| !addr.is_empty()),
                    });
                }
                if matches!(
                    &err,
                    RaftError::APIError(ClientWriteError::ChangeMembershipError(
                        ChangeMembershipError::InProgress(_)
                    ))
                ) {
                    tracing::debug!(
                        op,
                        raft_id,
                        "another configuration change is still committing; retrying"
                    );
                    tokio::time::sleep(MEMBERSHIP_RETRY_DELAY).await;
                    continue;
                }
                return Err(MembershipError::Raft {
                    op,
                    raft_id,
                    message: err.to_string(),
                });
            }
        }
    }
}

/// Records a member's raft ID and address on its node object, creating the
/// object if the CA flow has not produced one yet.
///
/// Node objects are normally born at certificate issuance (architecture
/// §12.2). A manager that joined a cluster whose CA service is not running —
/// a manually provisioned cluster, or the in-process test harness — would
/// otherwise have no place to record its raft ID, and the join could not be
/// deduplicated on re-join. Creating a minimal object here is the same
/// concession `RaftNode::start` already makes for the first manager.
async fn record_manager_status(
    ctx: &ManagerContext,
    node_id: &Id,
    raft_id: u64,
    addr: &str,
) -> Result<(), MembershipError> {
    let action = if let Some(node) = ctx.store.view().node(node_id) {
        let status = ManagerStatus {
            raft_id,
            addr: addr.to_owned(),
            leader: false,
            reachability: Reachability::Reachable,
        };
        if node.manager_status.as_ref() == Some(&status) && node.spec.role == NodeRole::Manager {
            return Ok(());
        }
        let mut updated = (*node).clone();
        updated.spec.role = NodeRole::Manager;
        updated.manager_status = Some(status);
        StoreAction::Update(StoreObject::Node(updated))
    } else {
        tracing::warn!(
            node_id = %node_id,
            raft_id,
            "no node object for the joining manager; creating a placeholder (the CA flow \
             normally creates it at certificate issuance)"
        );
        StoreAction::Create(StoreObject::Node(placeholder_node(node_id, raft_id, addr)))
    };
    ctx.store
        .propose(vec![action])
        .await
        .map_err(|source| MembershipError::Store { source })?;
    Ok(())
}

/// What a departure writes on the node object it removes from consensus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Departing {
    /// Node removal or `swarm leave --force`: drop the manager status only.
    ///
    /// The node is identified by its raft id, through the `manager_status`
    /// that records it -- which is all this case needs.
    LeavesConsensus,
    /// Demotion (SWK §12.3 phase 2): drop the manager status **and** set the
    /// role to worker, so certificate renewal issues a worker certificate.
    ///
    /// Carries the node id because the raft id is not enough: once the manager
    /// status is cleared, nothing on the node object records which raft member
    /// it was, and a role write that guessed -- "some node whose role is
    /// manager and whose status is empty" -- would demote a node that is
    /// merely mid-promotion. The caller always knows the id; asking for it is
    /// cheaper than being clever.
    BecomesWorker {
        /// The node being demoted.
        node_id: Id,
    },
}

/// Writes the node object's half of a departure, on the leader.
///
/// This runs where the store is still moving. That is the whole point: phase 1
/// takes the node out of consensus, and a node out of consensus stops
/// receiving replication, so if the *departing* node tried to write this from
/// its own applied store it would re-read the same frozen version and lose the
/// optimistic-concurrency check every time (architecture §3). Measured on the
/// testbed before this moved here: ten seconds of retries against a store
/// stuck at version 25 while the leader was at 45.
///
/// Retried from a fresh read because the node object is contended right after
/// a handover -- the new leader writes its own manager status, description
/// refreshes land -- so a sequence conflict is an expected first outcome, not
/// an error.
async fn finish_departure(
    ctx: &ManagerContext,
    raft_id: u64,
    departing: Departing,
) -> Result<(), MembershipError> {
    let deadline = Instant::now() + DEPARTURE_WRITE_BUDGET;
    loop {
        // Keyed on the node id for a demotion, because the manager status this
        // would otherwise match on is exactly what the write clears: a retry
        // after a partial success would have nothing left to find. Matching
        // "some node whose role is manager and whose status is empty" instead
        // would be worse than useless -- it is a description of a node that is
        // merely mid-promotion, and demoting that one is a silent disaster.
        let node = {
            let view = ctx.store.view();
            match &departing {
                Departing::BecomesWorker { node_id } => view.node(node_id),
                Departing::LeavesConsensus => view.nodes().into_iter().find(|n| {
                    n.manager_status
                        .as_ref()
                        .is_some_and(|m| m.raft_id == raft_id)
                }),
            }
        };
        let Some(node) = node else {
            return Ok(());
        };
        let becomes_worker = matches!(departing, Departing::BecomesWorker { .. });
        let done = node.manager_status.is_none()
            && (!becomes_worker || node.spec.role == NodeRole::Worker);
        if done {
            return Ok(());
        }
        let mut updated = (*node).clone();
        updated.manager_status = None;
        if becomes_worker {
            updated.spec.role = NodeRole::Worker;
        }
        match ctx
            .store
            .propose(vec![StoreAction::Update(StoreObject::Node(updated))])
            .await
        {
            Ok(_) => return Ok(()),
            Err(ProposeError::Rejected(ProposalRejection::SequenceConflict {
                expected,
                found,
                ..
            })) if Instant::now() < deadline => {
                tracing::debug!(
                    raft_id,
                    expected,
                    found,
                    "the node object moved under the departure; re-reading and retrying"
                );
                tokio::time::sleep(MEMBERSHIP_RETRY_DELAY).await;
            }
            Err(source) => return Err(MembershipError::Store { source }),
        }
    }
}

/// The minimal node object a joining manager gets when none exists.
fn placeholder_node(node_id: &Id, raft_id: u64, addr: &str) -> Node {
    Node {
        id: node_id.clone(),
        meta: Meta::new(),
        spec: NodeSpec {
            name: None,
            labels: std::collections::BTreeMap::new(),
            role: NodeRole::Manager,
            availability: Availability::Active,
        },
        description: Some(NodeDescription {
            hostname: String::new(),
            platform: Platform {
                os: String::new(),
                arch: String::new(),
            },
            resources: Resources::default(),
            engine: satl_core::EngineDescription {
                version: String::new(),
                labels: std::collections::BTreeMap::new(),
            },
            linux_emulation: false,
            racct_enabled: false,
            data_addr: None,
        }),
        status: NodeStatus {
            state: NodeState::Ready,
            message: String::new(),
            addr: addr.to_owned(),
        },
        manager_status: Some(ManagerStatus {
            raft_id,
            addr: addr.to_owned(),
            leader: false,
            reachability: Reachability::Reachable,
        }),
        certificate_status: CertificateStatus::default(),
        certificate_issuer: None,
    }
}

// ---------------------------------------------------------------------------
// The Control service
// ---------------------------------------------------------------------------

/// The `Control` gRPC service: membership, leader-forwarded proposals and
/// cluster info (architecture §6.5, §6.6).
#[derive(Clone, Debug)]
pub struct ControlService {
    manager: ManagerSlot,
}

impl ControlService {
    /// Builds the service around a (possibly not yet installed) manager
    /// context.
    #[must_use]
    pub fn new(manager: ManagerSlot) -> Self {
        Self { manager }
    }

    /// The leader-only guard: resolves the context and refuses politely, with
    /// the redirect metadata, if this node is not the leader.
    fn leader_context(&self, op: &'static str) -> Result<ManagerContext, Status> {
        let ctx = self.manager.require(op)?;
        if !ctx.store.metrics().is_leader {
            return Err(MembershipError::NotLeader {
                leader_addr: ctx.store.leader_addr(),
            }
            .into());
        }
        Ok(ctx)
    }
}

/// Every `Control` RPC except `JoinRaft` is manager-only; the interceptor
/// admits workers for `JoinRaft`'s sake, so the rest re-check here.
fn require_manager(peer: &satl_ca::PeerIdentity, op: &str) -> Result<(), Status> {
    if peer.role == NodeRole::Manager {
        return Ok(());
    }
    Err(Status::permission_denied(format!(
        "node {node} presented OU={ou} but Control.{op} requires {manager}: a worker forwards \
         nothing and joins no quorum",
        node = peer.node_id,
        ou = peer.ou(),
        manager = satl_ca::OU_MANAGER
    )))
}

#[tonic::async_trait]
impl Control for ControlService {
    async fn join_raft(
        &self,
        request: Request<pb::JoinRaftRequest>,
    ) -> Result<Response<pb::JoinRaftResponse>, Status> {
        let peer = peer_identity(&request)?.clone();
        let remote = peer_addr(&request);
        let req = request.into_inner();

        // The joiner's claimed node ID must be the CN it authenticated with:
        // otherwise a manager could admit a slot on someone else's behalf.
        if req.node_id != peer.node_id.as_str() {
            return Err(Status::permission_denied(format!(
                "JoinRaft claims node {claimed:?} but the caller's certificate says {actual}: \
                 a node may only join as itself",
                claimed = req.node_id,
                actual = peer.node_id
            )));
        }

        let ctx = self.leader_context("JoinRaft")?;

        // Step 1: resolve the address.
        let addr = resolve_join_addr(&req.addr, remote, DEFAULT_PORT)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        // The node object's role is the authority here, not the OU: a
        // promoted node still carries a worker certificate at this point
        // (`proto/control.proto`).
        if let Some(node) = ctx.store.view().node(&peer.node_id)
            && node.spec.role != NodeRole::Manager
        {
            return Err(Status::failed_precondition(format!(
                "node {id} is a worker in this cluster's state: promote it before it joins the \
                 raft group",
                id = peer.node_id
            )));
        }

        // Step 2: health-check the joiner back.
        health_check_peer(
            &ctx,
            &req.node_id,
            &addr,
            HEALTH_SERVICE_RAFT,
            HEALTH_CHECK_BUDGET,
        )
        .await?;

        // Steps 3-5.
        let (raft_id, members) = admit_member(&ctx, &peer.node_id, &addr).await?;
        Ok(Response::new(pb::JoinRaftResponse {
            raft_id,
            members: members.iter().map(proto_member).collect(),
            removed_members: ctx.store.removed_raft_ids().into_iter().collect(),
        }))
    }

    async fn leave_raft(
        &self,
        request: Request<pb::LeaveRaftRequest>,
    ) -> Result<Response<pb::LeaveRaftResponse>, Status> {
        require_manager(peer_identity(&request)?, "LeaveRaft")?;
        let req = request.into_inner();
        let ctx = self.leader_context("LeaveRaft")?;

        // The node ID must match the raft ID: that is what stops a stale
        // caller from evicting whoever inherited the slot.
        let owner = ctx.store.view().nodes().into_iter().find(|n| {
            n.manager_status
                .as_ref()
                .is_some_and(|m| m.raft_id == req.raft_id)
        });
        let owner_id = match owner {
            Some(node) if node.id.as_str() == req.node_id => Some(node.id.clone()),
            Some(node) => {
                return Err(Status::failed_precondition(format!(
                    "raft member {raft_id} belongs to node {actual}, not to {claimed:?}; \
                     re-read the membership before removing a member",
                    raft_id = req.raft_id,
                    actual = node.id,
                    claimed = req.node_id
                )));
            }
            None => {
                // No node object records this raft ID. Still removable (the
                // membership is the authority), but say so.
                tracing::warn!(
                    raft_id = req.raft_id,
                    node_id = %req.node_id,
                    "removing a raft member with no matching node object"
                );
                None
            }
        };

        // The id comes from the node object the membership check just matched,
        // not from the request: a demotion writes the role of the node this
        // store says owns that raft member, and of no other. With no matching
        // object there is nothing to demote, so the removal is a plain
        // departure.
        let departing = match (req.demote, owner_id) {
            (true, Some(node_id)) => Departing::BecomesWorker { node_id },
            _ => Departing::LeavesConsensus,
        };
        let members = remove_member(&ctx, req.raft_id, departing).await?;
        Ok(Response::new(pb::LeaveRaftResponse {
            members: members.iter().map(proto_member).collect(),
        }))
    }

    async fn propose_actions(
        &self,
        request: Request<pb::ProposeActionsRequest>,
    ) -> Result<Response<pb::ProposeActionsResponse>, Status> {
        require_manager(peer_identity(&request)?, "ProposeActions")?;
        forward::serve_propose_actions(&self.manager, request).await
    }

    async fn cluster_info(
        &self,
        request: Request<pb::ClusterInfoRequest>,
    ) -> Result<Response<pb::ClusterInfoResponse>, Status> {
        require_manager(peer_identity(&request)?, "ClusterInfo")?;
        // Answered locally by any manager from its applied store; it may be
        // slightly stale, which is what `applied` reports.
        let ctx = self.manager.require("ClusterInfo")?;
        let members = ctx.store.raft_members();
        let metrics = ctx.store.metrics();
        let cluster = cluster_object(&ctx.store);
        Ok(Response::new(pb::ClusterInfoResponse {
            cluster_id: cluster
                .as_ref()
                .map(|(id, _, _)| id.clone())
                .unwrap_or_default(),
            leader_raft_id: metrics.leader_id.unwrap_or_default(),
            members: members.iter().map(proto_member).collect(),
            cluster: cluster.map(|(id, meta, payload)| pb::Object {
                kind: pb::ObjectKind::Cluster as i32,
                id,
                meta: Some(meta),
                payload,
            }),
            applied: ctx.store.is_caught_up(),
        }))
    }
}

/// The cluster object as `(id, meta, CBOR payload)`, with the encrypted root
/// CA key stripped — that key never leaves the store, not even to another
/// manager (`proto/control.proto`).
fn cluster_object(store: &ClusterStore) -> Option<(String, pb::Meta, Vec<u8>)> {
    let cluster = store.view().cluster()?;
    let mut sanitized = (*cluster).clone();
    sanitized.encrypted_root_ca_key = None;
    let id = sanitized.id.to_string();
    let meta = proto_meta(&sanitized.meta);
    let mut payload = Vec::new();
    if let Err(err) = ciborium::ser::into_writer(&StoreObject::Cluster(sanitized), &mut payload) {
        tracing::error!(error = %err, "encoding the cluster object for ClusterInfo");
        return None;
    }
    Some((id, meta, payload))
}

fn proto_meta(meta: &Meta) -> pb::Meta {
    pb::Meta {
        version: Some(pb::Version {
            index: meta.version.0,
        }),
        created_at: Some(timestamp(meta.created_at)),
        updated_at: Some(timestamp(meta.updated_at)),
    }
}

fn timestamp(time: std::time::SystemTime) -> prost_types::Timestamp {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => prost_types::Timestamp {
            seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
        },
        Err(err) => prost_types::Timestamp {
            seconds: -i64::try_from(err.duration().as_secs()).unwrap_or(i64::MAX),
            nanos: 0,
        },
    }
}

fn proto_member(member: &RaftMember) -> pb::RaftMember {
    pb::RaftMember {
        raft_id: member.raft_id,
        // The node ID is carried on the node object, not in the raft
        // membership; the responder fills what it knows.
        node_id: String::new(),
        addr: member.addr.clone(),
        leader: member.leader,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(members: &[(u64, bool)]) -> Vec<MemberHealth> {
        members
            .iter()
            .map(|(raft_id, reachable)| MemberHealth {
                raft_id: *raft_id,
                reachable: *reachable,
            })
            .collect()
    }

    #[test]
    fn join_address_resolution_table() {
        let peer: SocketAddr = "10.0.0.5:41234".parse().expect("peer");
        let v6: SocketAddr = "[fd00::5]:41234".parse().expect("peer");

        // Explicit address wins, untouched.
        assert_eq!(
            resolve_join_addr("10.0.0.9:2377", Some(peer), 2377).expect("explicit"),
            "10.0.0.9:2377"
        );
        // Hostnames are left alone: the joiner knows its own name.
        assert_eq!(
            resolve_join_addr("mgr-2.internal:2377", Some(peer), 2377).expect("hostname"),
            "mgr-2.internal:2377"
        );
        // Unspecified IP: peer IP, joiner's port.
        assert_eq!(
            resolve_join_addr("0.0.0.0:2377", Some(peer), 9999).expect("unspecified v4"),
            "10.0.0.5:2377"
        );
        assert_eq!(
            resolve_join_addr("[::]:2400", Some(peer), 9999).expect("unspecified v6"),
            "10.0.0.5:2400"
        );
        // Nothing at all: peer IP, default port.
        assert_eq!(
            resolve_join_addr("", Some(peer), 2377).expect("empty"),
            "10.0.0.5:2377"
        );
        assert_eq!(
            resolve_join_addr("  ", Some(v6), 2377).expect("blank"),
            "[fd00::5]:2377"
        );
        // Nothing to substitute from.
        assert_eq!(
            resolve_join_addr("", None, 2377),
            Err(JoinAddrError::Unresolvable)
        );
        assert_eq!(
            resolve_join_addr("0.0.0.0:2377", None, 2377),
            Err(JoinAddrError::Unresolvable)
        );
        // Malformed.
        assert!(matches!(
            resolve_join_addr("mgr-2.internal", Some(peer), 2377),
            Err(JoinAddrError::MissingPort { .. })
        ));
        assert!(matches!(
            resolve_join_addr("mgr-2.internal:http", Some(peer), 2377),
            Err(JoinAddrError::Malformed { .. })
        ));
        assert!(matches!(
            resolve_join_addr(":2377", Some(peer), 2377),
            Err(JoinAddrError::Malformed { .. })
        ));
    }

    /// SwarmKit's arithmetic: quorum is computed from the size *before* the
    /// removal, and only the members that would remain and are reachable are
    /// counted (SWK §11.5).
    #[test]
    fn quorum_safety_table() {
        // One member removing itself: 0 remain, 1 needed -> refused.
        assert!(can_remove_member(&health(&[(1, true)]), 1).is_err());

        // Two members, both up: (2-1)/2+1 = 1 needed, 1 remains -> allowed.
        can_remove_member(&health(&[(1, true), (2, true)]), 2).expect("2 -> 1 with both up");
        // Two members, the survivor is down -> refused.
        assert!(can_remove_member(&health(&[(1, true), (2, false)]), 1).is_err());

        // Three members, all up: 2 needed, 2 remain -> allowed.
        can_remove_member(&health(&[(1, true), (2, true), (3, true)]), 3)
            .expect("3 -> 2 with all up");
        // Three members, one already down, remove another: 2 needed, only 1
        // reachable remains -> refused. This is the case that keeps an
        // operator from turning a degraded cluster into a dead one.
        let err = can_remove_member(&health(&[(1, true), (2, false), (3, true)]), 3)
            .expect_err("must refuse");
        match err {
            MembershipError::QuorumWouldBreak {
                raft_id,
                remaining,
                reachable,
                needed,
            } => {
                assert_eq!((raft_id, remaining, reachable, needed), (3, 2, 1, 2));
            }
            other => panic!("unexpected error: {other}"),
        }
        // Removing the member that is already down is fine.
        can_remove_member(&health(&[(1, true), (2, false), (3, true)]), 2)
            .expect("dropping the dead member is always safe");

        // Five members, two down: 3 needed, 3 reachable remain -> allowed.
        can_remove_member(
            &health(&[(1, true), (2, true), (3, true), (4, false), (5, false)]),
            5,
        )
        .expect("5 -> 4 with three up");
        // Five members, three down -> refused.
        assert!(
            can_remove_member(
                &health(&[(1, true), (2, true), (3, false), (4, false), (5, false)]),
                5,
            )
            .is_err()
        );

        // An empty membership cannot lose anything.
        assert!(can_remove_member(&[], 7).is_err());
    }

    #[test]
    fn quorum_errors_name_the_numbers() {
        let err = can_remove_member(&health(&[(1, true), (2, false), (3, false)]), 3)
            .expect_err("refuse");
        let msg = err.to_string();
        assert!(msg.contains('3'), "{msg}");
        assert!(msg.contains("quorum"), "{msg}");
    }

    #[test]
    fn picked_raft_ids_avoid_used_and_blacklisted_ids() {
        let used = BTreeSet::from([1_u64, 2, 3]);
        let blacklist = BTreeSet::from([4_u64, 5]);
        for _ in 0..200 {
            let id = pick_raft_id(&used, &blacklist, random_raft_id).expect("draw");
            assert_ne!(id, 0);
            assert!(!used.contains(&id));
            assert!(!blacklist.contains(&id));
        }
    }

    /// A blacklisted ID is never handed out, even if it is the only thing the
    /// draw ever produces — and the loop gives up instead of spinning.
    #[test]
    fn picking_a_raft_id_gives_up_instead_of_hanging() {
        let err = pick_raft_id(&BTreeSet::new(), &BTreeSet::from([9_u64]), || 9)
            .expect_err("a blacklisted-only draw must give up");
        assert!(matches!(err, MembershipError::NoRaftId { .. }), "{err}");

        // Zero is never a valid member ID either.
        let err = pick_raft_id(&BTreeSet::new(), &BTreeSet::new(), || 0)
            .expect_err("zero is not a member ID");
        assert!(matches!(err, MembershipError::NoRaftId { .. }), "{err}");

        // A draw that eventually produces a usable value succeeds.
        let mut sequence = [7_u64, 7, 11].into_iter();
        let id = pick_raft_id(&BTreeSet::from([7_u64]), &BTreeSet::new(), || {
            sequence.next().unwrap_or(0)
        })
        .expect("the third draw is free");
        assert_eq!(id, 11);
    }

    #[test]
    fn member_health_counts_the_local_node_as_reachable() {
        let liveness = PeerLiveness::new();
        let members = vec![
            RaftMember {
                raft_id: 1,
                addr: "a:2377".to_owned(),
                voter: true,
                leader: true,
            },
            RaftMember {
                raft_id: 2,
                addr: "b:2377".to_owned(),
                voter: true,
                leader: false,
            },
        ];
        let health = member_health(&members, 1, &liveness, Duration::from_secs(10));
        assert!(health[0].reachable, "the local node always counts");
        assert!(!health[1].reachable, "a peer that never answered does not");
        liveness.record_success(2);
        let health = member_health(&members, 1, &liveness, Duration::from_secs(10));
        assert!(health[1].reachable);
    }

    #[test]
    fn membership_errors_map_to_the_documented_status_codes() {
        let redirect: Status = MembershipError::NotLeader {
            leader_addr: Some("10.0.0.1:2377".to_owned()),
        }
        .into();
        assert_eq!(redirect.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            redirect
                .metadata()
                .get(forward::LEADER_ADDR_METADATA)
                .and_then(|v| v.to_str().ok()),
            Some("10.0.0.1:2377")
        );

        let quorum: Status = MembershipError::QuorumWouldBreak {
            raft_id: 7,
            remaining: 2,
            reachable: 1,
            needed: 2,
        }
        .into();
        assert_eq!(quorum.code(), tonic::Code::FailedPrecondition);

        let unknown: Status = MembershipError::UnknownMember {
            message: "nope".to_owned(),
        }
        .into();
        assert_eq!(unknown.code(), tonic::Code::NotFound);
    }
}
