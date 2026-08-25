// SPDX-License-Identifier: BSD-2-Clause
//! Follower → leader forwarding of store mutations (architecture §6.5,
//! SWK §11.7).
//!
//! A non-leader manager accepts a REST mutation, turns it into the same
//! `Vec<StoreAction>` its local store would have applied, and forwards it to
//! the leader over `Control.ProposeActions`. The leader re-validates and
//! proposes. Reads are answered locally.
//!
//! # One redirect, never a chain
//!
//! A leader-only RPC answered by a non-leader comes back as
//! `FAILED_PRECONDITION` with the leader's internal gRPC address in the
//! [`LEADER_ADDR_METADATA`] response metadata (empty when there is no
//! leader). The caller retries against that address **once**. Chasing a chain
//! of redirects is how a partitioned cluster turns one client request into a
//! loop, so [`LeaderClient`] counts hops and gives up after the second
//! attempt — SwarmKit's one-hop loop protection.
//!
//! # Identity forwarding
//!
//! The forwarded request carries the *original* caller's certificate subject
//! in [`pb::ForwardedIdentity`]. The leader authorizes the **forwarding
//! manager** (its certificate is the one on the connection) and additionally
//! **logs** the original caller. Keeping the two distinguishable is a
//! privilege-escalation guard: a manager forwarding its own request must not
//! be confusable with a manager forwarding a worker's. The REST surface has
//! no per-user authorization in v1, so this is an audit mechanism, not an
//! access-control one — do not start making decisions on it without
//! revisiting architecture §12.5.
//!
//! # No proposal timeout
//!
//! There is none, by design (SWK §11.6, architecture §6.2): a timeout cannot
//! retract an appended entry and would desync store from log. The gRPC
//! deadline a caller sets is a *transport* bound; its expiry means "unknown
//! outcome, re-read before retrying", never "did not apply".

use std::time::Duration;

use tonic::metadata::MetadataValue;
use tonic::{Request, Response, Status};

use satl_ca::PeerIdentity;
use satl_core::defaults::{MAX_TX_ACTIONS, MAX_TX_BYTES};
use satl_core::{StoreAction, Version};
use satl_proto::MAX_MESSAGE_SIZE;
use satl_proto::v2::control_client::ControlClient;
use satl_proto::v2::{self as pb};

use crate::server::{ManagerContext, ManagerSlot, peer_identity};
use crate::store::ProposeError;
use crate::transport::{PeerChannels, TransportError, decode, encode};
use crate::types::{ProposalRejection, ProposalResponse};

/// Response-metadata key carrying the current leader's internal gRPC address
/// on a `FAILED_PRECONDITION` from a leader-only RPC.
pub const LEADER_ADDR_METADATA: &str = "satl-leader-addr";

/// How many times a forwarded call is attempted: the first try plus exactly
/// one redirect (SWK §11.7).
const MAX_ATTEMPTS: usize = 2;

/// Transport deadline for a forwarded proposal. Generous, and its expiry
/// means "unknown outcome" — see the module docs.
const FORWARD_DEADLINE: Duration = Duration::from_secs(30);

/// Builds the `FAILED_PRECONDITION` a non-leader answers with.
///
/// `leader_addr` is `None` when this node knows of no leader; the metadata
/// key is then set to the empty string, which the contract defines as "no
/// leader right now" and is what stops a caller from retrying blindly.
#[must_use]
pub fn leader_redirect_status(leader_addr: Option<&str>, message: &str) -> Status {
    let mut status = Status::failed_precondition(message.to_owned());
    let value = leader_addr.unwrap_or_default();
    match MetadataValue::try_from(value) {
        Ok(value) => {
            status.metadata_mut().insert(LEADER_ADDR_METADATA, value);
        }
        Err(err) => {
            // A leader address that is not ASCII cannot have come from a
            // membership entry we wrote; say so rather than silently drop it.
            tracing::error!(
                leader_addr = value,
                error = %err,
                "leader address is not valid gRPC metadata; sending the redirect without it"
            );
        }
    }
    status
}

/// The leader address a redirect carried, if any and non-empty.
#[must_use]
pub fn leader_addr_from_status(status: &Status) -> Option<String> {
    status
        .metadata()
        .get(LEADER_ADDR_METADATA)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|addr| !addr.is_empty())
        .map(str::to_owned)
}

/// The identity envelope a forwarding manager attaches to a proposal.
#[must_use]
pub fn forwarded_identity(peer: &PeerIdentity) -> pb::ForwardedIdentity {
    pb::ForwardedIdentity {
        cn: peer.node_id.to_string(),
        ou: peer.ou().to_owned(),
        org: peer.cluster_id.clone(),
    }
}

/// The identity envelope for a caller that reached the REST API over the
/// local unix socket: no certificate, so an empty CN (`proto/control.proto`).
#[must_use]
pub fn local_identity() -> pb::ForwardedIdentity {
    pb::ForwardedIdentity::default()
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// Server side of `Control.ProposeActions`.
///
/// The leader applies; anyone else answers the redirect. A deterministic
/// rejection is a **successful RPC** carrying `Rejected` in the payload — a
/// sequence conflict is a normal outcome the caller retries from a fresh
/// read, not a transport failure.
pub async fn serve_propose_actions(
    manager: &ManagerSlot,
    request: Request<pb::ProposeActionsRequest>,
) -> Result<Response<pb::ProposeActionsResponse>, Status> {
    let forwarder = peer_identity(&request)?.clone();
    let req = request.into_inner();

    let ctx = manager.require("ProposeActions")?;
    if !ctx.store.metrics().is_leader {
        return Err(leader_redirect_status(
            ctx.store.leader_addr().as_deref(),
            "this manager is not the raft leader; retry against the address in the \
             satl-leader-addr metadata",
        ));
    }

    let actions: Vec<StoreAction> = decode("propose_actions", "Vec<StoreAction>", &req.actions)
        .map_err(|e| Status::invalid_argument(e.to_string()))?;

    // Identity forwarding: the connection's certificate is what authorized
    // this call; the original caller is logged (architecture §6.5).
    let origin = req.forwarded.unwrap_or_default();
    tracing::info!(
        forwarded_by = %forwarder.node_id,
        forwarded_by_role = forwarder.ou(),
        origin_cn = %origin.cn,
        origin_ou = %origin.ou,
        actions = actions.len(),
        "applying a forwarded store transaction"
    );

    let response = apply_locally(&ctx, actions).await?;
    let payload = encode("propose_actions", "ProposalResponse", &response)
        .map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(pb::ProposeActionsResponse {
        response: payload,
    }))
}

/// Re-validates the transaction limits and proposes it.
///
/// The limits are re-checked here even though the state machine enforces them
/// deterministically: catching an oversized transaction before it is appended
/// keeps it out of every replica's log.
async fn apply_locally(
    ctx: &ManagerContext,
    actions: Vec<StoreAction>,
) -> Result<ProposalResponse, Status> {
    if actions.len() > MAX_TX_ACTIONS {
        return Ok(ProposalResponse::Rejected(
            ProposalRejection::TooManyActions {
                count: actions.len(),
            },
        ));
    }
    let encoded = encode("propose_actions", "Vec<StoreAction>", &actions)
        .map_err(|e| Status::internal(e.to_string()))?;
    if encoded.len() > MAX_TX_BYTES {
        return Ok(ProposalResponse::Rejected(ProposalRejection::TooLarge {
            bytes: encoded.len(),
        }));
    }

    match ctx.store.propose(actions).await {
        Ok(version) => Ok(ProposalResponse::Applied { version }),
        Err(ProposeError::Rejected(rejection)) => Ok(ProposalResponse::Rejected(rejection)),
        Err(ProposeError::NotLeader { leader_hint }) => Err(leader_redirect_status(
            ctx.store.leader_addr().as_deref(),
            &format!(
                "leadership changed while the transaction was being proposed (leader hint \
                 {leader_hint:?}); the outcome is unknown. Re-read before retrying"
            ),
        )),
        Err(err @ ProposeError::Raft(_)) => Err(Status::internal(err.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// A forwarded proposal failed.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    /// The transaction was evaluated and deterministically rejected. Nothing
    /// applied; retry from a fresh read.
    #[error(transparent)]
    Rejected(#[from] ProposalRejection),
    /// No manager currently leads, so there is nowhere to forward to.
    #[error(
        "no raft leader is known right now, so the mutation cannot be forwarded; the cluster is \
         electing or has lost quorum"
    )]
    NoLeader,
    /// The redirect chain did not terminate.
    #[error(
        "forwarding to leader {addr} was redirected again after {attempts} attempts; refusing to \
         chase the leader further. Re-read and retry"
    )]
    RedirectLoop {
        /// The last address that redirected.
        addr: String,
        /// How many attempts were made.
        attempts: usize,
    },
    /// The leader could not be reached.
    #[error("forwarding a store transaction to the leader at {addr}: {reason}")]
    Transport {
        /// The leader address that was dialed.
        addr: String,
        /// What went wrong.
        reason: String,
    },
    /// A payload could not be encoded or decoded.
    #[error(transparent)]
    Codec(#[from] crate::transport::CodecError),
    /// The local proposal path failed (this node is the leader).
    #[error(transparent)]
    Local(#[from] ProposeError),
}

impl From<TransportError> for ForwardError {
    fn from(err: TransportError) -> Self {
        let addr = match &err {
            TransportError::Address { addr, .. } => addr.clone(),
            TransportError::Tls { .. } => String::from("<unknown>"),
        };
        Self::Transport {
            addr,
            reason: err.to_string(),
        }
    }
}

/// Forwards store mutations to the leader on behalf of a follower's REST
/// backend (architecture §6.5).
///
/// Applies locally when this node *is* the leader, so callers do not have to
/// branch on leadership themselves.
#[derive(Clone, Debug)]
pub struct LeaderClient {
    manager: ManagerSlot,
}

impl LeaderClient {
    /// Builds the client over the local manager context.
    #[must_use]
    pub fn new(manager: ManagerSlot) -> Self {
        Self { manager }
    }

    /// Proposes `actions` as one atomic transaction, forwarding to the leader
    /// if this node is not it.
    ///
    /// `origin` is the identity of whoever asked — [`forwarded_identity`] for
    /// a remote client certificate, [`local_identity`] for the unix socket.
    /// It is logged by the leader, never used for authorization.
    pub async fn propose(
        &self,
        actions: Vec<StoreAction>,
        origin: pb::ForwardedIdentity,
    ) -> Result<Version, ForwardError> {
        let ctx = self.manager.get().ok_or(ForwardError::NoLeader)?;
        propose_via(&ctx, actions, origin).await
    }
}

/// [`LeaderClient::propose`] over a borrowed [`ManagerContext`] — for callers
/// inside this crate that hold the context rather than the slot (the
/// membership operations, whose store writes must land wherever the leader
/// is, exactly like the REST backend's).
pub async fn propose_via(
    ctx: &ManagerContext,
    actions: Vec<StoreAction>,
    origin: pb::ForwardedIdentity,
) -> Result<Version, ForwardError> {
    {
        // (Block kept for the borrow scopes of the original method body.)
        if ctx.store.metrics().is_leader {
            return ctx.store.propose(actions).await.map_err(|err| match err {
                ProposeError::Rejected(rejection) => ForwardError::Rejected(rejection),
                other => ForwardError::Local(other),
            });
        }

        let payload = encode("propose_actions", "Vec<StoreAction>", &actions)?;
        let mut addr = ctx.store.leader_addr().ok_or(ForwardError::NoLeader)?;
        let channels = ctx
            .require_channels("forwarding a store transaction")
            .map_err(|status| ForwardError::Transport {
                addr: addr.clone(),
                reason: status.message().to_owned(),
            })?;

        for attempt in 1..=MAX_ATTEMPTS {
            match call_once(channels, &addr, &payload, &origin).await {
                Ok(response) => return response,
                Err(status) => {
                    let redirect = (status.code() == tonic::Code::FailedPrecondition)
                        .then(|| leader_addr_from_status(&status))
                        .flatten();
                    match redirect {
                        Some(next) if attempt < MAX_ATTEMPTS && next != addr => {
                            tracing::debug!(
                                from = %addr,
                                to = %next,
                                "forwarded proposal redirected to the current leader"
                            );
                            addr = next;
                        }
                        Some(_) => {
                            return Err(ForwardError::RedirectLoop {
                                addr,
                                attempts: attempt,
                            });
                        }
                        None if status.code() == tonic::Code::FailedPrecondition => {
                            return Err(ForwardError::NoLeader);
                        }
                        None => {
                            // Same rule as the raft transport's
                            // `discard_broken_connection`, over the same pool:
                            // a connection that did not carry the request is
                            // not trusted with the next one. Without this, a
                            // pooled connection left unusable would fail every
                            // forwarded write to that leader for the life of
                            // the process.
                            if matches!(
                                status.code(),
                                tonic::Code::Unavailable
                                    | tonic::Code::Internal
                                    | tonic::Code::Unknown
                            ) {
                                channels.forget(&addr);
                            }
                            return Err(ForwardError::Transport {
                                addr,
                                reason: format!("{:?}: {}", status.code(), status.message()),
                            });
                        }
                    }
                }
            }
        }
        Err(ForwardError::RedirectLoop {
            addr,
            attempts: MAX_ATTEMPTS,
        })
    }
}

/// One `ProposeActions` call. The outer `Result` is the transport
/// outcome; the inner one is the transaction's.
async fn call_once(
    channels: &PeerChannels,
    addr: &str,
    payload: &[u8],
    origin: &pb::ForwardedIdentity,
) -> Result<Result<Version, ForwardError>, Status> {
    let channel = channels
        .channel(addr)
        .map_err(|e| Status::unavailable(e.to_string()))?;
    let mut client = ControlClient::new(channel)
        .max_decoding_message_size(MAX_MESSAGE_SIZE)
        .max_encoding_message_size(MAX_MESSAGE_SIZE);

    let mut request = Request::new(pb::ProposeActionsRequest {
        actions: payload.to_vec(),
        forwarded: Some(origin.clone()),
    });
    request.set_timeout(FORWARD_DEADLINE);

    let response = client.propose_actions(request).await?.into_inner();
    let outcome: ProposalResponse =
        match decode("propose_actions", "ProposalResponse", &response.response) {
            Ok(outcome) => outcome,
            Err(err) => return Ok(Err(ForwardError::Codec(err))),
        };
    Ok(match outcome {
        ProposalResponse::Applied { version } => Ok(version),
        ProposalResponse::Rejected(rejection) => Err(ForwardError::Rejected(rejection)),
    })
}

#[cfg(test)]
mod tests {
    use satl_core::{Id, NodeRole};

    use super::*;

    #[test]
    fn redirect_metadata_round_trips() {
        let status = leader_redirect_status(Some("10.0.0.3:2377"), "not the leader");
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            leader_addr_from_status(&status),
            Some("10.0.0.3:2377".to_owned())
        );
        assert!(status.message().contains("not the leader"));
    }

    #[test]
    fn no_leader_sends_an_empty_redirect_rather_than_none() {
        // The contract says the key is present and empty when there is no
        // leader: a caller must be able to tell "no leader" from "not a
        // leader-only RPC".
        let status = leader_redirect_status(None, "no leader");
        assert!(
            status.metadata().contains_key(LEADER_ADDR_METADATA),
            "the key must be present even with no leader"
        );
        assert_eq!(leader_addr_from_status(&status), None);
    }

    #[test]
    fn a_non_redirect_status_carries_no_leader_address() {
        let status = Status::internal("boom");
        assert_eq!(leader_addr_from_status(&status), None);
    }

    #[test]
    fn forwarded_identity_carries_the_full_subject() {
        let peer = PeerIdentity {
            node_id: Id::generate(),
            role: NodeRole::Worker,
            cluster_id: "3n2ff1rvrc4mn3s2fu6zlt6tw".to_owned(),
        };
        let forwarded = forwarded_identity(&peer);
        assert_eq!(forwarded.cn, peer.node_id.to_string());
        assert_eq!(forwarded.ou, satl_ca::OU_WORKER);
        assert_eq!(forwarded.org, peer.cluster_id);

        // A unix-socket caller has no certificate at all.
        let local = local_identity();
        assert!(local.cn.is_empty());
        assert!(local.ou.is_empty());
    }

    #[test]
    fn proposal_responses_round_trip_as_cbor() {
        let applied = ProposalResponse::Applied {
            version: Version(41),
        };
        let bytes = encode("propose_actions", "ProposalResponse", &applied).expect("encode");
        let back: ProposalResponse =
            decode("propose_actions", "ProposalResponse", &bytes).expect("decode");
        assert_eq!(back, applied);

        let rejected = ProposalResponse::Rejected(ProposalRejection::NotFound {
            kind: satl_core::ObjectKind::Service,
            id: Id::generate(),
        });
        let bytes = encode("propose_actions", "ProposalResponse", &rejected).expect("encode");
        let back: ProposalResponse =
            decode("propose_actions", "ProposalResponse", &bytes).expect("decode");
        assert_eq!(back, rejected);
    }
}
