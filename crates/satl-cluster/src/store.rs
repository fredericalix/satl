// SPDX-License-Identifier: BSD-2-Clause
//! The public store façade: reads, proposals, watch feed, metrics
//! (architecture §6).

use std::collections::BTreeSet;
use std::sync::Arc;

use openraft::ServerState;
use openraft::error::{ClientWriteError, RaftError};
use parking_lot::{RwLock, RwLockReadGuard};
use tokio::sync::broadcast;

use satl_core::{
    Cluster, Config, Id, Network, Node, ObjectKind, Secret, Service, StoreAction, StoreEvent,
    StoreObject, Task, Version,
};

use crate::state_machine::StoreInner;
use openraft::async_runtime::watch::WatchReceiver;

use crate::types::{Proposal, ProposalRejection, ProposalResponse, Raft, TypeConfig};

/// Why a proposal could not be committed.
#[derive(Debug, thiserror::Error)]
pub enum ProposeError {
    /// This node is not the Raft leader; retry against `leader_hint` (M2
    /// forwards automatically — architecture §6.5).
    #[error("not the raft leader{}", match leader_hint {
        Some(id) => format!("; current leader is raft node {id}"),
        None => String::from("; no leader is currently known"),
    })]
    NotLeader {
        /// The leader this node believes in, if any.
        leader_hint: Option<u64>,
    },
    /// The transaction was replicated and deterministically rejected by the
    /// state machine (stale version, missing object, ...). Nothing was
    /// applied; retry from a fresh read.
    #[error(transparent)]
    Rejected(#[from] ProposalRejection),
    /// Raft itself failed (shutting down, storage fatal). Pending proposals
    /// are cancelled when leadership is lost — there is deliberately **no
    /// proposal timeout** (architecture §6.2: a timeout cannot retract an
    /// appended entry and desyncs store vs log).
    #[error("raft error: {0}")]
    Raft(#[source] Box<RaftError<TypeConfig, ClientWriteError<TypeConfig>>>),
}

/// Point-in-time metrics of the local Raft node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMetrics {
    /// This node's Raft ID.
    pub node_raft_id: u64,
    /// Raft's own server state (leader/follower/candidate/learner/shutdown).
    pub state: ServerState,
    /// Whether this node is currently the leader.
    pub is_leader: bool,
    /// The leader this node currently believes in, if any.
    pub leader_id: Option<u64>,
    /// Current Raft term.
    pub term: u64,
    /// Index of the last log entry applied to the store.
    pub last_applied: Option<u64>,
}

impl ClusterMetrics {
    /// This node's raft role as the metrics exporter's `role=` label value
    /// (`satl-metrics`' `RAFT_ROLES`; shutdown reads as `none` — the node has
    /// no live raft identity worth a label).
    #[must_use]
    pub fn role(&self) -> &'static str {
        match self.state {
            ServerState::Leader => "leader",
            ServerState::Follower => "follower",
            ServerState::Candidate => "candidate",
            ServerState::Learner => "learner",
            ServerState::Shutdown => "none",
        }
    }
}

/// Cheap-clone handle to the replicated cluster store.
///
/// Reads are served from the local in-memory replica (possibly stale on
/// followers — architecture §6.4); writes go through
/// [`ClusterStore::propose`] and Raft.
#[derive(Clone)]
pub struct ClusterStore {
    inner: Arc<RwLock<StoreInner>>,
    events: broadcast::Sender<StoreEvent>,
    raft: Raft,
}

impl ClusterStore {
    /// Assembles the façade from the state machine's shared handles and the
    /// running Raft instance.
    pub(crate) fn new(
        inner: Arc<RwLock<StoreInner>>,
        events: broadcast::Sender<StoreEvent>,
        raft: Raft,
    ) -> Self {
        Self {
            inner,
            events,
            raft,
        }
    }

    /// A consistent read view of the store.
    ///
    /// The view holds the store read lock. The guard is `!Send`
    /// (`parking_lot`), so holding it across an `.await` in a spawned task
    /// is a compile error — take the view, clone the `Arc`s you need, drop
    /// it (architecture §6.2).
    #[must_use]
    pub fn view(&self) -> StoreView<'_> {
        StoreView {
            guard: self.inner.read(),
        }
    }

    /// Proposes one atomic store transaction and waits until it is
    /// committed and applied (leader only).
    ///
    /// There is **no artificial timeout**: the only failure modes are
    /// losing leadership (which cancels pending proposals) and a
    /// deterministic rejection by the state machine. On success, returns
    /// the [`Version`] (Raft log index) stamped on every written object.
    pub async fn propose(&self, actions: Vec<StoreAction>) -> Result<Version, ProposeError> {
        let response =
            self.raft
                .client_write(Proposal { actions })
                .await
                .map_err(|err| match err {
                    // A ForwardToLeader outcome is the caller's business
                    // (architecture §6.5), not an opaque Raft failure.
                    RaftError::APIError(ClientWriteError::ForwardToLeader(forward)) => {
                        ProposeError::NotLeader {
                            leader_hint: forward.leader_id,
                        }
                    }
                    other => ProposeError::Raft(Box::new(other)),
                })?;
        match response.data {
            ProposalResponse::Applied { version } => Ok(version),
            ProposalResponse::Rejected(rejection) => Err(ProposeError::Rejected(rejection)),
        }
    }

    /// Subscribes to the store watch feed.
    ///
    /// Events arrive per applied transaction: one `Created`/`Updated`/
    /// `Removed` per action, then a `Commit(version)` marker. A receiver
    /// that observes [`broadcast::error::RecvError::Lagged`] has lost
    /// events and must re-sync from a fresh [`ClusterStore::view`] before
    /// resuming.
    #[must_use]
    pub fn watch(&self) -> broadcast::Receiver<StoreEvent> {
        self.events.subscribe()
    }

    /// Point-in-time Raft metrics of this node.
    #[must_use]
    pub fn metrics(&self) -> ClusterMetrics {
        let metrics = self.raft.metrics().borrow_watched().clone();
        ClusterMetrics {
            node_raft_id: metrics.id,
            state: metrics.state,
            is_leader: metrics.state == ServerState::Leader,
            leader_id: metrics.current_leader,
            term: metrics.current_term,
            last_applied: metrics.last_applied.map(|log_id| log_id.index),
        }
    }

    /// The current Raft membership as this node sees it (architecture §6.6).
    ///
    /// Read from the **effective** configuration in the Raft metrics, not
    /// from the applied state machine: during a joint consensus change the
    /// effective config is the one that matters for quorum arithmetic.
    #[must_use]
    pub fn raft_members(&self) -> Vec<RaftMember> {
        let metrics = self.raft.metrics().borrow_watched().clone();
        let voters: BTreeSet<u64> = metrics.membership_config.voter_ids().collect();
        metrics
            .membership_config
            .nodes()
            .map(|(raft_id, node)| RaftMember {
                raft_id: *raft_id,
                addr: node.addr.clone(),
                voter: voters.contains(raft_id),
                leader: metrics.current_leader == Some(*raft_id),
            })
            .collect()
    }

    /// The internal gRPC address of the Raft leader, if one is known and its
    /// address is in the membership. Empty means "no leader right now"
    /// (`satl-leader-addr` response metadata, architecture §6.5).
    #[must_use]
    pub fn leader_addr(&self) -> Option<String> {
        let metrics = self.raft.metrics().borrow_watched().clone();
        let leader = metrics.current_leader?;
        metrics
            .membership_config
            .nodes()
            .find(|(id, _)| **id == leader)
            .map(|(_, node)| node.addr.clone())
            .filter(|addr| !addr.is_empty())
    }

    /// Whether this replica has applied everything it has stored — SwarmKit's
    /// "caught up" test (`applied_index >= last_index`, SWK §11.4 step 9).
    /// A `false` here is a REST backend's cue to answer "cluster is not
    /// ready" rather than serve an empty list as if it were the truth.
    #[must_use]
    pub fn is_caught_up(&self) -> bool {
        let metrics = self.raft.metrics().borrow_watched().clone();
        match (
            metrics.last_applied.map(|l| l.index),
            metrics.last_log_index,
        ) {
            (_, None) => true,
            (Some(applied), Some(last)) => applied >= last,
            (None, Some(_)) => false,
        }
    }

    /// Raft IDs that have been removed from the group and must never be
    /// re-admitted or reused (SWK §11.1). Replicated through the state
    /// machine and carried in snapshots.
    #[must_use]
    pub fn removed_raft_ids(&self) -> BTreeSet<u64> {
        self.inner.read().removed_raft_ids.clone()
    }
}

/// One member of the Raft group, as the local node sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftMember {
    /// Raft member ID: a random `u64`, never reused (architecture §6.6).
    pub raft_id: u64,
    /// `host:port` the raft transport dials.
    pub addr: String,
    /// Whether this member votes (a learner catching up does not).
    pub voter: bool,
    /// Whether this member leads, as seen by the responder.
    pub leader: bool,
}

/// A read view over the store. Holds the read lock for its lifetime; the
/// guard is `!Send`, so it cannot be held across `.await` in spawned tasks
/// — scope it tightly (architecture §6.2).
pub struct StoreView<'a> {
    guard: RwLockReadGuard<'a, StoreInner>,
}

impl StoreView<'_> {
    /// The singleton cluster object, once seeded.
    #[must_use]
    pub fn cluster(&self) -> Option<Arc<Cluster>> {
        self.guard.clusters.values().next().cloned()
    }

    /// Looks up a node by ID.
    #[must_use]
    pub fn node(&self, id: &Id) -> Option<Arc<Node>> {
        self.guard.nodes.get(id).cloned()
    }

    /// Looks up a service by ID.
    #[must_use]
    pub fn service(&self, id: &Id) -> Option<Arc<Service>> {
        self.guard.services.get(id).cloned()
    }

    /// Looks up a task by ID.
    #[must_use]
    pub fn task(&self, id: &Id) -> Option<Arc<Task>> {
        self.guard.tasks.get(id).cloned()
    }

    /// Looks up a network by ID.
    #[must_use]
    pub fn network(&self, id: &Id) -> Option<Arc<Network>> {
        self.guard.networks.get(id).cloned()
    }

    /// Looks up a secret by ID.
    #[must_use]
    pub fn secret(&self, id: &Id) -> Option<Arc<Secret>> {
        self.guard.secrets.get(id).cloned()
    }

    /// Looks up a config by ID.
    #[must_use]
    pub fn config(&self, id: &Id) -> Option<Arc<Config>> {
        self.guard.configs.get(id).cloned()
    }

    /// All nodes (unordered).
    #[must_use]
    pub fn nodes(&self) -> Vec<Arc<Node>> {
        self.guard.nodes.values().cloned().collect()
    }

    /// All services (unordered).
    #[must_use]
    pub fn services(&self) -> Vec<Arc<Service>> {
        self.guard.services.values().cloned().collect()
    }

    /// All tasks (unordered).
    #[must_use]
    pub fn tasks(&self) -> Vec<Arc<Task>> {
        self.guard.tasks.values().cloned().collect()
    }

    /// All networks (unordered).
    #[must_use]
    pub fn networks(&self) -> Vec<Arc<Network>> {
        self.guard.networks.values().cloned().collect()
    }

    /// All secrets (unordered).
    #[must_use]
    pub fn secrets(&self) -> Vec<Arc<Secret>> {
        self.guard.secrets.values().cloned().collect()
    }

    /// All configs (unordered).
    #[must_use]
    pub fn configs(&self) -> Vec<Arc<Config>> {
        self.guard.configs.values().cloned().collect()
    }

    /// Kind-generic lookup, deep-cloning the object.
    #[must_use]
    pub fn get(&self, kind: ObjectKind, id: &Id) -> Option<StoreObject> {
        self.guard.get_object(kind, id)
    }

    /// Looks up a node by its operator-assigned name.
    #[must_use]
    pub fn node_by_name(&self, name: &str) -> Option<Arc<Node>> {
        self.by_name(ObjectKind::Node, name)
            .and_then(|id| self.guard.nodes.get(&id).cloned())
    }

    /// Looks up a service by name.
    #[must_use]
    pub fn service_by_name(&self, name: &str) -> Option<Arc<Service>> {
        self.by_name(ObjectKind::Service, name)
            .and_then(|id| self.guard.services.get(&id).cloned())
    }

    /// Looks up a network by name.
    #[must_use]
    pub fn network_by_name(&self, name: &str) -> Option<Arc<Network>> {
        self.by_name(ObjectKind::Network, name)
            .and_then(|id| self.guard.networks.get(&id).cloned())
    }

    /// Looks up a secret by name.
    #[must_use]
    pub fn secret_by_name(&self, name: &str) -> Option<Arc<Secret>> {
        self.by_name(ObjectKind::Secret, name)
            .and_then(|id| self.guard.secrets.get(&id).cloned())
    }

    /// Looks up a config by name.
    #[must_use]
    pub fn config_by_name(&self, name: &str) -> Option<Arc<Config>> {
        self.by_name(ObjectKind::Config, name)
            .and_then(|id| self.guard.configs.get(&id).cloned())
    }

    /// Resolves a `(kind, name)` pair through the name index.
    fn by_name(&self, kind: ObjectKind, name: &str) -> Option<Id> {
        self.guard.names.get(&(kind, name.to_owned())).cloned()
    }
}
