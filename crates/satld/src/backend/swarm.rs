// SPDX-License-Identifier: BSD-2-Clause
//! The cluster half of the REST backend: `/swarm`, `/nodes`, `/services`,
//! `/tasks` (architecture §6.5, §7, §12; Docker Engine API v1.43).
//!
//! Three rules shape every handler here, and they are the same three the
//! container half follows:
//!
//! - **reads are local.** A follower answers from its own applied store, which
//!   may lag the leader by a round-trip. That is SwarmKit's model (§6.4) and it
//!   is safe because every mutation re-validates through optimistic
//!   concurrency at commit time.
//! - **writes go to the leader.** A follower forwards through
//!   [`LeaderClient`](satl_cluster::LeaderClient) (§6.5); when there is no
//!   leader to forward to, the error names the address the client should talk
//!   to instead of pretending the write happened.
//! - **membership changes are not store writes.** Promotion, demotion and
//!   removal move Raft voters around, so they go through `satl_cluster`'s
//!   membership operations — which enforce quorum safety and, for a demotion,
//!   the two-phase "raft first, role second" order (§6.6, SWK §12.3).
//!
//! # What `swarm init` means here
//!
//! A SatL node self-initializes at first boot (§1.2), so by the time anyone
//! can call `POST /swarm/init` the node is already a single-node cluster.
//! The call is therefore idempotent — it reports the node id — and is only a
//! *re-initialization* when `force_new_cluster` is set. Recorded in
//! `docs/api-compat.md` by the API crate.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use satl_api::model::{
    BackendError, LocalNodeState, ManagerPeer, NodeDetail, NodeSpecUpdate, NodeSummary, Result,
    ServiceCreateOptions, ServiceCreated, ServiceDetail, ServiceSummary, ServiceTaskCounts,
    ServiceUpdateOptions, SwarmDetail, SwarmInitOptions, SwarmInitResult, SwarmJoinOptions,
    SwarmStatus, TaskDetail, TaskFilters, TaskSummary, TokenRole,
};
use satl_cluster::{ForwardError, ProposalRejection};
use satl_core::{
    Availability, DesiredState, Id, Meta, Node, NodeRole, Service, StoreAction, StoreObject, Task,
    Version,
};

use super::{DaemonBackend, names};
use crate::cluster::ControlRequest;

/// How long a `swarm join` / `swarm leave` waits for the cluster supervisor.
///
/// Generous: a join runs the whole CA flow, wipes the raft directory and
/// brings a new runtime up. Shorter than a client's patience, longer than the
/// work.
const CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(2);

impl DaemonBackend {
    /// Proposes `actions` on the leader, forwarding when this node is not it
    /// (architecture §6.5).
    ///
    /// The `origin` recorded on the leader is the local one: the REST socket
    /// has no per-user identity in v1 (§12.5), so "the manager that forwarded
    /// it" is the whole truth there is to log.
    pub(super) async fn propose_via_leader(
        &self,
        what: &str,
        actions: Vec<StoreAction>,
    ) -> Result<Version> {
        let manager = self.manager()?;
        manager
            .leader
            .propose(actions, satl_cluster::forward::local_identity())
            .await
            .map_err(|err| forward_error(what, &manager, &err))
    }

    /// Sends a runtime-replacing request to the cluster supervisor and waits
    /// for its outcome.
    async fn control<T>(
        &self,
        what: &str,
        request: impl FnOnce(
            tokio::sync::oneshot::Sender<std::result::Result<T, String>>,
        ) -> ControlRequest,
    ) -> Result<T> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cluster
            .control(request(tx))
            .await
            .map_err(|reason| BackendError::internal(format!("cannot {what}: {reason}")))?;
        match tokio::time::timeout(CONTROL_TIMEOUT, rx).await {
            Ok(Ok(Ok(value))) => Ok(value),
            Ok(Ok(Err(message))) => {
                Err(BackendError::internal(format!("cannot {what}: {message}")))
            }
            Ok(Err(_)) => Err(BackendError::internal(format!(
                "cannot {what}: the cluster supervisor stopped without answering"
            ))),
            Err(_) => Err(BackendError::internal(format!(
                "cannot {what}: the cluster supervisor did not finish within {}s",
                CONTROL_TIMEOUT.as_secs()
            ))),
        }
    }

    // -- swarm --------------------------------------------------------------

    pub(super) async fn swarm_init_impl(
        &self,
        options: &SwarmInitOptions,
    ) -> Result<SwarmInitResult> {
        let cluster = self.cluster()?;
        if cluster.manager.is_none() {
            // Docker's own wording for `swarm init` on a node already in a
            // swarm (moby `errSwarmExists`, 503). A manager answers the
            // idempotent success recorded in api-compat #42; a worker cannot,
            // because turning it into a cluster of its own is exactly the
            // split-brain `swarm leave` exists to make deliberate.
            return Err(BackendError::unavailable(
                "This node is already part of a swarm. Use \"docker swarm leave\" to leave this \
                 swarm and try again.",
            ));
        }
        if options.force_new_cluster {
            return Err(BackendError::not_implemented(
                "ForceNewCluster is not implemented: this node cannot rebuild a cluster from its \
                 own raft state by discarding the other members. A manager that still has its \
                 raft directory needs no forcing -- restart satld and it resumes. A manager \
                 that lost it is recovered by restoring that directory from a backup (the 'dek' \
                 key file included) or, on a cluster with other managers, by discarding this \
                 node's identity and re-joining it. Both procedures are in the backup and \
                 restore section of docs/operations.md.",
            ));
        }
        if options.advertise_addr.is_some() || options.listen_addr.is_some() {
            // Changing these means rebinding the internal listener, which is a
            // restart, not a request. Refuse rather than silently ignore.
            let configured = &cluster.advertise_addr;
            return Err(BackendError::invalid(format!(
                "this node is already initialized and advertises {configured}; set advertise_addr \
                 / listen_addr in satld.toml and restart satld to change them"
            )));
        }
        // Already a cluster: architecture §1.2 makes first boot the init.
        // `--autolock` is the one init option that still means something on
        // the idempotent path: it is a cluster setting, not a bootstrap one.
        if options.auto_lock {
            self.swarm_set_autolock_impl(true).await?;
        }
        tracing::info!(node_id = %cluster.node_id, "swarm init: this node is already a cluster");
        Ok(SwarmInitResult {
            node_id: cluster.node_id.to_string(),
        })
    }

    pub(super) async fn swarm_join_impl(&self, options: SwarmJoinOptions) -> Result<()> {
        if options.remote_addrs.is_empty() {
            return Err(BackendError::invalid(
                "RemoteAddrs is empty: pass at least one manager address (host:2377)",
            ));
        }
        if options.join_token.trim().is_empty() {
            return Err(BackendError::invalid(
                "JoinToken is empty: a join needs the cluster's worker or manager token",
            ));
        }
        // Refuse to throw away real state. `satl_cluster`'s dirty-state rule
        // is about the raft directory; this is the operator-facing half of it,
        // and it is checked *before* anything is destroyed. On a worker the
        // state that matters is its assigned tasks — it holds nothing else.
        let cluster = self.cluster()?;
        let dirty = if let Some(manager) = &cluster.manager {
            dirty_reason(manager, &cluster.node_id)
        } else {
            let tasks = self.local_tasks().await?.len();
            (tasks > 0).then(|| format!("it runs {tasks} task(s) of its current cluster"))
        };
        if let Some(reason) = dirty {
            return Err(BackendError::conflict(format!(
                "this node cannot join a cluster: {reason}. Remove them first, or reinstall the \
                 node; joining discards this node's cluster state."
            )));
        }
        self.control("join the cluster", |reply| ControlRequest::Join {
            remote_addrs: options.remote_addrs.clone(),
            token: options.join_token.clone(),
            advertise_addr: options.advertise_addr.clone(),
            listen_addr: options.listen_addr.clone(),
            availability: Availability::Active,
            reply,
        })
        .await
        .map(|_node_id| ())
    }

    pub(super) async fn swarm_leave_impl(&self, force: bool) -> Result<()> {
        let cluster = self.cluster()?;
        // A manager that is still part of a multi-member raft group must
        // leave consensus before it discards its state, or the cluster keeps
        // counting it towards quorum (SWK §11.5). A worker counts towards
        // nothing and leaves without force, exactly as Docker's does.
        if let Some(manager) = &cluster.manager {
            let members = manager.store.raft_members();
            if members.len() > 1 && !force {
                return Err(BackendError::conflict(format!(
                    "this node is one of {} managers: removing it would need a quorum-safe \
                     membership change. Demote it from another manager first \
                     (`satl node update --role worker`), or pass force to leave anyway.",
                    members.len()
                )));
            }
            if members.len() > 1
                && let Some(ctx) = manager.membership.get()
                && let Err(error) = satl_cluster::membership::remove_member(
                    &ctx,
                    ctx.raft_id,
                    satl_cluster::membership::Departing::LeavesConsensus,
                )
                .await
            {
                tracing::warn!(%error, "leaving consensus before a forced leave failed");
            }
        }
        self.control("leave the cluster", |reply| ControlRequest::Leave {
            force,
            reply,
        })
        .await
    }

    pub(super) fn swarm_inspect_impl(&self) -> Result<SwarmDetail> {
        let manager = self.manager()?;
        let object = cluster_object(&manager)?;
        Ok(swarm_detail(&object))
    }

    pub(super) async fn swarm_rotate_token_impl(&self, role: TokenRole) -> Result<SwarmDetail> {
        let manager = self.manager()?;
        let role = match role {
            TokenRole::Worker => NodeRole::Worker,
            TokenRole::Manager => NodeRole::Manager,
        };
        let object = cluster_object(&manager)?;
        let tokens = satl_ca::JoinTokens::try_from(&object.join_tokens).map_err(|err| {
            BackendError::internal(format!("this cluster's join tokens are unusable: {err}"))
        })?;
        let rotated = tokens.rotate(role);

        let mut updated = object;
        updated.join_tokens = satl_core::JoinTokens::from(&rotated);
        updated.meta.updated_at = SystemTime::now();
        self.propose_via_leader(
            "rotate the join token",
            vec![StoreAction::Update(StoreObject::Cluster(updated))],
        )
        .await?;
        // Never log the token itself.
        tracing::info!(role = satl_ca::role_ou(role), "join token rotated");

        let manager = self.manager()?;
        let object = cluster_object(&manager)?;
        Ok(swarm_detail(&object))
    }

    /// Turns manager autolock on or off (SWK §12.4, architecture §14→§12).
    ///
    /// Enabling mints the unlock key **here, once**: every manager must seal
    /// its DEK under the *same* key, so the key is generated where the update
    /// is handled and replicated through the store — which is DEK-encrypted
    /// at rest, and that is exactly where Docker keeps it too. The per-manager
    /// watcher ([`crate::autolock`]) does the sealing on each node. The key
    /// itself is never logged.
    pub(super) async fn swarm_set_autolock_impl(&self, enabled: bool) -> Result<SwarmDetail> {
        let manager = self.manager()?;
        let object = cluster_object(&manager)?;
        if object.spec.autolock == enabled {
            return Ok(swarm_detail(&object));
        }
        let mut updated = object;
        updated.spec.autolock = enabled;
        // On enable: a fresh key. On disable: the key leaves the store; the
        // watchers write the plain DEK back from memory.
        updated.spec.unlock_key = enabled.then(satl_cluster::generate_unlock_key);
        updated.meta.updated_at = SystemTime::now();
        self.propose_via_leader(
            "toggle manager autolock",
            vec![StoreAction::Update(StoreObject::Cluster(updated))],
        )
        .await?;
        tracing::info!(enabled, "manager autolock toggled");

        let manager = self.manager()?;
        let object = cluster_object(&manager)?;
        Ok(swarm_detail(&object))
    }

    /// The current unlock key, for `GET /swarm/unlockkey`.
    pub(super) fn swarm_unlock_key_impl(&self) -> Result<String> {
        let manager = self.manager()?;
        let object = cluster_object(&manager)?;
        if !object.spec.autolock {
            return Err(BackendError::unavailable(
                "this swarm does not have manager autolock enabled; there is no unlock key",
            ));
        }
        object.spec.unlock_key.clone().ok_or_else(|| {
            BackendError::internal("autolock is on but the store holds no unlock key")
        })
    }

    /// Rotates the unlock key: a fresh one into the store, and every
    /// manager's watcher reseals its DEK against it.
    pub(super) async fn swarm_rotate_unlock_key_impl(&self) -> Result<SwarmDetail> {
        let manager = self.manager()?;
        let object = cluster_object(&manager)?;
        if !object.spec.autolock {
            return Err(BackendError::invalid(
                "cannot rotate the unlock key: manager autolock is not enabled",
            ));
        }
        let mut updated = object;
        updated.spec.unlock_key = Some(satl_cluster::generate_unlock_key());
        updated.meta.updated_at = SystemTime::now();
        self.propose_via_leader(
            "rotate the manager unlock key",
            vec![StoreAction::Update(StoreObject::Cluster(updated))],
        )
        .await?;
        // Never log the key.
        tracing::info!("manager unlock key rotated");

        let manager = self.manager()?;
        let object = cluster_object(&manager)?;
        Ok(swarm_detail(&object))
    }

    /// Starts a root CA rotation (architecture §12.3, SWK §16.5): mints the
    /// new root, cross-signs it with the old one, installs the transitional
    /// two-root trust bundle and regenerates both join tokens, all in one
    /// store transaction. The leader's rotation reconciler drives it to
    /// completion from there; this returns as soon as the start committed.
    pub(super) async fn swarm_rotate_ca_impl(&self, force_rotate: u64) -> Result<SwarmDetail> {
        let manager = self.manager()?;
        let cluster = cluster_object(&manager)?;
        let updated =
            crate::rotation::start_rotation(&cluster, force_rotate).map_err(|err| match err {
                crate::rotation::RotationError::InProgress { .. } => {
                    BackendError::conflict(err.to_string())
                }
                other => BackendError::internal(other.to_string()),
            })?;
        self.propose_via_leader(
            "rotate the root CA",
            vec![StoreAction::Update(StoreObject::Cluster(updated))],
        )
        .await?;
        tracing::info!(force_rotate, "root CA rotation started");

        let manager = self.manager()?;
        let object = cluster_object(&manager)?;
        Ok(swarm_detail(&object))
    }

    pub(super) fn swarm_status_impl(&self) -> Result<SwarmStatus> {
        let cluster = self.cluster()?;
        let Some(manager) = &cluster.manager else {
            // The worker's `/info.Swarm`: state active, control unavailable,
            // the managers its session last reported as `RemoteManagers`.
            // `Nodes`/`Managers` stay zero — Docker only fills them on a
            // manager, and a worker genuinely does not know.
            let remote_managers: Vec<ManagerPeer> = cluster
                .agent
                .borrow()
                .managers
                .iter()
                .map(|peer| ManagerPeer {
                    node_id: peer.node_id.to_string(),
                    addr: peer.addr.clone(),
                })
                .collect();
            return Ok(SwarmStatus {
                node_id: cluster.node_id.to_string(),
                node_addr: cluster.advertise_addr.clone(),
                local_node_state: LocalNodeState::Active,
                control_available: false,
                error: String::new(),
                remote_managers,
                nodes: 0,
                managers: 0,
            });
        };
        let metrics = manager.store.metrics();
        let (nodes, managers, remote_managers) = {
            let view = manager.store.view();
            let nodes = view.nodes();
            let managers: Vec<ManagerPeer> = nodes
                .iter()
                .filter_map(|node| {
                    let status = node.manager_status.as_ref()?;
                    Some(ManagerPeer {
                        node_id: node.id.to_string(),
                        addr: status.addr.clone(),
                    })
                })
                .collect();
            (
                i64::try_from(nodes.len()).unwrap_or(i64::MAX),
                i64::try_from(managers.len()).unwrap_or(i64::MAX),
                managers,
            )
        };
        Ok(SwarmStatus {
            node_id: cluster.node_id.to_string(),
            node_addr: cluster.advertise_addr.clone(),
            local_node_state: LocalNodeState::Active,
            control_available: cluster.role == NodeRole::Manager,
            error: if metrics.leader_id.is_some() {
                String::new()
            } else {
                "this cluster has no raft leader".to_owned()
            },
            remote_managers,
            nodes,
            managers,
        })
    }

    // -- nodes --------------------------------------------------------------

    pub(super) fn list_nodes_impl(&self) -> Result<Vec<NodeSummary>> {
        let manager = self.manager()?;
        let members = manager.store.raft_members();
        let view = manager.store.view();
        let mut nodes: Vec<Node> = view
            .nodes()
            .into_iter()
            .map(|node| (*node).clone())
            .collect();
        nodes.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        for node in &mut nodes {
            refresh_manager_status(node, &members);
        }
        Ok(nodes.into_iter().map(NodeSummary::from).collect())
    }

    pub(super) fn inspect_node_impl(&self, id_or_name: &str) -> Result<NodeDetail> {
        let manager = self.manager()?;
        let members = manager.store.raft_members();
        let view = manager.store.view();
        let mut node = resolve_node(&view, id_or_name)?;
        refresh_manager_status(&mut node, &members);
        Ok(NodeDetail::from(node))
    }

    pub(super) async fn update_node_impl(
        &self,
        id: &str,
        version: Version,
        spec: NodeSpecUpdate,
    ) -> Result<()> {
        let manager = self.manager()?;
        let node = {
            let view = manager.store.view();
            resolve_node(&view, id)?
        };
        if node.meta.version != version {
            return Err(BackendError::conflict(format!(
                "node {} has moved on (version {}, you sent {}); re-read it and retry",
                node.id, node.meta.version.0, version.0
            )));
        }

        // Role changes are membership changes, not spec edits (§6.6). They are
        // handled first and separately, because a demotion must leave raft
        // *before* the role flips and a promotion must join it after.
        if node.spec.role != spec.role {
            self.change_role(&manager, &node, spec.role).await?;
        }

        // The rest of the spec is a plain store write, rebuilt from a fresh
        // read because the role change above may have bumped the version.
        let node_id = node.id.clone();
        let name = spec.name.clone();
        let labels = spec.labels.clone();
        let availability = spec.availability;
        let actions = {
            let view = manager.store.view();
            let Some(current) = view.node(&node_id) else {
                return Err(BackendError::not_found(format!("node {node_id} is gone")));
            };
            if current.spec.name == name
                && current.spec.labels == labels
                && current.spec.availability == availability
            {
                Vec::new()
            } else {
                let mut updated = (*current).clone();
                updated.spec.name = name;
                updated.spec.labels = labels;
                updated.spec.availability = availability;
                updated.meta.updated_at = SystemTime::now();
                vec![StoreAction::Update(StoreObject::Node(updated))]
            }
        };
        if !actions.is_empty() {
            self.propose_via_leader("update the node", actions).await?;
        }
        tracing::info!(
            node_id = %node_id,
            role = satl_ca::role_ou(spec.role),
            availability = ?availability,
            labels = spec.labels.len(),
            "node spec updated"
        );
        Ok(())
    }

    /// Promotion and demotion (architecture §6.6, §12.3, SWK §12.3) — both
    /// apply **live** on the target node, no restart.
    ///
    /// A **demotion** is two-phase and raft-first: `satl_cluster` removes the
    /// node from consensus (refusing if quorum would break, transferring
    /// leadership if the target is the leader) and only then flips the role,
    /// so a worker certificate is never issued to a live voter.
    ///
    /// A **promotion** is the opposite order and only the first half happens
    /// here: the role flip. The rest is the target node's: its session
    /// pushes the changed node object, its role watcher renews into a
    /// manager certificate (the CA signs the role the store records) and its
    /// supervisor rebuilds the runtime, joining raft learner-first through
    /// `Control.JoinRaft` (`crate::cluster::spawn_role_watch`).
    async fn change_role(
        &self,
        manager: &crate::cluster::ManagerCore,
        node: &Node,
        desired: NodeRole,
    ) -> Result<()> {
        let ctx = manager.membership.get().ok_or_else(|| {
            BackendError::internal("this node is not a manager; it cannot change a node's role")
        })?;
        match desired {
            NodeRole::Worker => {
                satl_cluster::demote_to_worker(&ctx, &node.id)
                    .await
                    .map_err(|err| membership_error("demote the node", &err))?;
                tracing::info!(
                    node_id = %node.id,
                    "node demoted to worker; it applies the change through its session (renewed \
                     certificate, worker runtime)"
                );
            }
            NodeRole::Manager => {
                let mut updated = node.clone();
                updated.spec.role = NodeRole::Manager;
                updated.meta.updated_at = SystemTime::now();
                self.propose_via_leader(
                    "promote the node",
                    vec![StoreAction::Update(StoreObject::Node(updated))],
                )
                .await?;
                tracing::info!(
                    node_id = %node.id,
                    "node promoted to manager; it renews its certificate and joins the raft \
                     group through its session, no restart"
                );
            }
        }
        Ok(())
    }

    pub(super) async fn remove_node_impl(&self, id: &str, force: bool) -> Result<()> {
        let cluster = self.cluster()?;
        let manager = Self::manager_of(&cluster)?;
        let node = {
            let view = manager.store.view();
            resolve_node(&view, id)?
        };
        if node.id == cluster.node_id {
            return Err(BackendError::conflict(
                "a node cannot remove itself: run `satl swarm leave` on it, or remove it from \
                 another manager",
            ));
        }
        if !force && node.status.state != satl_core::NodeState::Down {
            return Err(BackendError::conflict(format!(
                "node {} is {:?}: only a down node can be removed without force",
                node.id, node.status.state
            )));
        }

        // Managers leave consensus first — quorum-safely — and only then is
        // the object removed.
        if node.manager_status.is_some() {
            let ctx = manager.membership.get().ok_or_else(|| {
                BackendError::internal("this node is not a manager; it cannot remove a member")
            })?;
            satl_cluster::demote_to_worker(&ctx, &node.id)
                .await
                .map_err(|err| membership_error("remove the manager from consensus", &err))?;
        }

        // Blacklist the certificate for its remaining life plus the grace
        // period (§12.3): a removed node must not be able to come back with
        // the identity it still holds.
        let actions = {
            let view = manager.store.view();
            let Some(object) = view.cluster() else {
                return Err(BackendError::internal("this node has no Cluster object"));
            };
            let mut updated = (*object).clone();
            updated.blacklisted_certs.insert(
                node.id.to_string(),
                SystemTime::now() + satl_ca::NODE_CERT_VALIDITY + BLACKLIST_GRACE,
            );
            updated.meta.updated_at = SystemTime::now();
            vec![
                StoreAction::Update(StoreObject::Cluster(updated)),
                StoreAction::Remove {
                    kind: satl_core::ObjectKind::Node,
                    id: node.id.clone(),
                },
            ]
        };
        self.propose_via_leader("remove the node", actions).await?;
        tracing::info!(node_id = %node.id, force, "node removed and its certificate blacklisted");
        Ok(())
    }

    // -- services -----------------------------------------------------------

    pub(super) async fn create_service_impl(
        &self,
        mut options: ServiceCreateOptions,
    ) -> Result<ServiceCreated> {
        let manager = self.manager()?;
        let name = options.spec.annotations.name.clone();
        if name.is_empty() {
            return Err(BackendError::invalid("a service needs a name"));
        }
        {
            let view = manager.store.view();
            if view.service_by_name(&name).is_some() {
                return Err(BackendError::conflict(format!(
                    "a service named {name} already exists"
                )));
            }
            super::secrets::resolve_spec_references(&view, &mut options.spec)?;
        }
        let warnings = harden_probe(&name, &mut options.spec);
        let service = Service {
            id: Id::generate(),
            meta: Meta::new(),
            spec: options.spec,
            endpoint: None,
            spec_version: satl_core::Version(0),
            previous_spec: None,
            update_status: None,
        };
        let id = service.id.clone();
        self.propose_via_leader(
            "create the service",
            vec![StoreAction::Create(StoreObject::Service(service))],
        )
        .await?;
        tracing::info!(service_id = %id, name = %name, "service created");
        Ok(ServiceCreated {
            id: id.to_string(),
            warnings,
        })
    }

    pub(super) fn list_services_impl(&self) -> Result<Vec<ServiceSummary>> {
        let manager = self.manager()?;
        let view = manager.store.view();
        let tasks = view.tasks();
        let mut services: Vec<Service> = view
            .services()
            .into_iter()
            .map(|service| (*service).clone())
            .collect();
        services.sort_by(|a, b| a.spec.annotations.name.cmp(&b.spec.annotations.name));
        Ok(services
            .into_iter()
            .map(|service| {
                let counts = task_counts(&service, &tasks);
                ServiceSummary {
                    service,
                    tasks: counts,
                }
            })
            .collect())
    }

    pub(super) fn inspect_service_impl(&self, id_or_name: &str) -> Result<ServiceDetail> {
        let manager = self.manager()?;
        let view = manager.store.view();
        Ok(ServiceDetail {
            service: names::resolve_service(&view, id_or_name)?,
        })
    }

    pub(super) async fn update_service_impl(
        &self,
        id: &str,
        version: Version,
        mut options: ServiceUpdateOptions,
    ) -> Result<Vec<String>> {
        let manager = self.manager()?;
        let service = {
            let view = manager.store.view();
            super::secrets::resolve_spec_references(&view, &mut options.spec)?;
            names::resolve_service(&view, id)?
        };
        if service.meta.version != version {
            return Err(BackendError::conflict(format!(
                "service {} has moved on (version {}, you sent {}); re-read it and retry",
                service.id, service.meta.version.0, version.0
            )));
        }

        let was = describe_update_state(service.update_status.as_ref());
        // The same pass as on create, and for the same reason: an update is how
        // a port gets published on a service that had none, and how a
        // healthcheck is added or taken away.
        let warnings = harden_probe(&service.spec.annotations.name, &mut options.spec);
        let updated = updated_service(&service, options.rollback, options.spec, SystemTime::now())?;
        let became = describe_update_state(updated.update_status.as_ref());
        self.propose_via_leader(
            "update the service",
            vec![StoreAction::Update(StoreObject::Service(updated))],
        )
        .await?;
        tracing::info!(
            service_id = %service.id,
            rollback = options.rollback,
            from = was,
            to = became,
            "service spec updated; the rolling updater starts a fresh rollout"
        );
        Ok(warnings)
    }

    pub(super) async fn remove_service_impl(&self, id_or_name: &str) -> Result<()> {
        let manager = self.manager()?;
        let service = {
            let view = manager.store.view();
            names::resolve_service(&view, id_or_name)?
        };
        // Only the Service object is removed: its tasks are marked for
        // removal by the orchestrator's reconcile pass, which is the one
        // component allowed to decide when a task's resources are released
        // (architecture §4 rule 5).
        self.propose_via_leader(
            "remove the service",
            vec![StoreAction::Remove {
                kind: satl_core::ObjectKind::Service,
                id: service.id.clone(),
            }],
        )
        .await?;
        tracing::info!(
            service_id = %service.id,
            name = %service.spec.annotations.name,
            "service removed"
        );
        Ok(())
    }

    // -- tasks --------------------------------------------------------------

    pub(super) fn list_tasks_impl(&self, filters: &TaskFilters) -> Result<Vec<TaskSummary>> {
        let manager = self.manager()?;
        let view = manager.store.view();
        let services: BTreeMap<Id, String> = view
            .services()
            .into_iter()
            .map(|service| (service.id.clone(), service.spec.annotations.name.clone()))
            .collect();
        let nodes: BTreeMap<Id, String> = view
            .nodes()
            .into_iter()
            .map(|node| {
                let name = node
                    .spec
                    .name
                    .clone()
                    .or_else(|| node.description.as_ref().map(|d| d.hostname.clone()))
                    .unwrap_or_default();
                (node.id.clone(), name)
            })
            .collect();

        let mut tasks: Vec<Task> = view
            .tasks()
            .into_iter()
            .map(|task| (*task).clone())
            .filter(|task| matches_filters(task, filters, &services, &nodes))
            .collect();
        tasks.sort_by(|a, b| {
            (&a.service_annotations.name, a.slot, a.id.as_str()).cmp(&(
                &b.service_annotations.name,
                b.slot,
                b.id.as_str(),
            ))
        });
        Ok(tasks.into_iter().map(TaskSummary::from).collect())
    }

    pub(super) fn inspect_task_impl(&self, id: &str) -> Result<TaskDetail> {
        let manager = self.manager()?;
        let view = manager.store.view();
        Ok(TaskDetail::from((*names::resolve_task(&view, id)?).clone()))
    }
}

/// Extra time a removed node's certificate stays blacklisted after it would
/// have expired anyway (architecture §12.3).
const BLACKLIST_GRACE: std::time::Duration = std::time::Duration::from_hours(7 * 24);

/// Whether this node holds cluster state that a join would destroy.
///
/// The operator-facing half of SwarmKit's `IsStateDirty` (SWK §12.3): the
/// default cluster object and this node's own node object are what a
/// self-initialized node always has, so they do not count. Anything else is
/// somebody's work.
#[must_use]
pub fn dirty_reason(manager: &crate::cluster::ManagerCore, node_id: &Id) -> Option<String> {
    let view = manager.store.view();
    let services = view.services().len();
    if services > 0 {
        return Some(format!("it runs {services} service(s)"));
    }
    let tasks = view.tasks().len();
    if tasks > 0 {
        return Some(format!("it holds {tasks} task(s)"));
    }
    let others = view
        .nodes()
        .into_iter()
        .filter(|node| node.id != *node_id)
        .count();
    if others > 0 {
        return Some(format!("it is a manager of a {}-node cluster", others + 1));
    }
    let secrets = view.secrets().len();
    if secrets > 0 {
        return Some(format!("it holds {secrets} secret(s)"));
    }
    None
}

/// Reads the cluster object, or explains why there is none.
fn cluster_object(manager: &crate::cluster::ManagerCore) -> Result<satl_core::Cluster> {
    let view = manager.store.view();
    view.cluster().map(|c| (*c).clone()).ok_or_else(|| {
        BackendError::internal(
            "this node has no Cluster object yet; it has not caught up with the leader",
        )
    })
}

/// The `GET /swarm` document for a cluster object.
fn swarm_detail(cluster: &satl_core::Cluster) -> SwarmDetail {
    SwarmDetail {
        cluster_id: cluster.id.to_string(),
        created_at: cluster.meta.created_at,
        updated_at: cluster.meta.updated_at,
        version: cluster.meta.version,
        join_tokens: cluster.join_tokens.clone(),
        root_ca_cert_pem: cluster
            .root_ca_cert
            .as_ref()
            .map(|pem| String::from_utf8_lossy(pem).into_owned())
            .unwrap_or_default(),
        root_rotation_in_progress: cluster.root_rotation.is_some(),
        spec: cluster.spec.clone(),
    }
}

/// The `Service` object a `POST /services/{id}/update` writes, spec swap and
/// `update_status` together.
///
/// Pure, and separate from the handler, because the interesting part is a
/// decision rather than a store write: whether the rolling updater will see a
/// rollout at all depends entirely on the `update_status` this leaves behind.
///
/// # Why the status is rewritten here
///
/// The updater treats `paused` and `rollback_paused` as "do nothing for this
/// service" (SWK §7.3 step 1), and it is the only component that ever leaves a
/// service in one of those states. If the control API did not touch
/// `update_status`, an update that its own `failure_action: pause` halted would
/// stay halted in the object forever: pushing a corrected spec would mark every
/// task dirty and the updater would still skip the service, so the only way out
/// would be removing and recreating it.
///
/// Both arms mirror SwarmKit's control API verbatim
/// (`manager/controlapi/service.go`, `UpdateService`), which was read rather
/// than remembered:
///
/// - a normal update **clears** the status, unconditionally — not "when the spec
///   changed". Whether the spec really changed is decided under the applied
///   state by [`stamp_spec_version`](satl_cluster) when the transaction commits,
///   not by a proposer comparing objects, and a no-op update that clears the
///   status replaces no task anyway (nothing becomes dirty).
/// - a **manual rollback** (`?rollback=previous`) announces itself as
///   `rollback_started`, with SwarmKit's own message. Without it a manual
///   rollback of a *paused* service would be accepted, swap the spec, and then
///   be ignored by the updater — the same trap in the other direction. It also
///   makes the updater apply `spec.rollback` rather than `spec.update`, which is
///   what an operator asking for a rollback means.
///
/// Recorded as api-compat 92.
fn updated_service(
    service: &Service,
    rollback: bool,
    spec: satl_core::ServiceSpec,
    now: SystemTime,
) -> Result<Service> {
    let mut updated = service.clone();
    if rollback {
        let Some(previous) = service.previous_spec.clone() else {
            return Err(BackendError::conflict(format!(
                "service {} has no previous spec to roll back to",
                service.id
            )));
        };
        updated.spec = previous;
        updated.previous_spec = Some(service.spec.clone());
        updated.update_status = Some(satl_core::UpdateStatus {
            state: satl_core::UpdateStateKind::RollbackStarted,
            started_at: Some(now),
            completed_at: None,
            message: "manually requested rollback".to_owned(),
        });
    } else {
        updated.previous_spec = Some(service.spec.clone());
        updated.spec = spec;
        updated.update_status = None;
    }
    updated.meta.updated_at = now;
    Ok(updated)
}

/// One `update_status` as a log field, in the API's own spelling, with `none`
/// for a service that has no rollout on record.
///
/// `satl-core`'s enum carries no `Display` and the wire spelling lives in the
/// API crate's renderer, so a log line an operator can grep alongside
/// `satl service inspect` needs the mapping here.
fn describe_update_state(status: Option<&satl_core::UpdateStatus>) -> &'static str {
    use satl_core::UpdateStateKind as Kind;
    match status.map(|status| status.state) {
        None => "none",
        Some(Kind::Updating) => "updating",
        Some(Kind::Completed) => "completed",
        Some(Kind::Paused) => "paused",
        Some(Kind::RollbackStarted) => "rollback_started",
        Some(Kind::RollbackCompleted) => "rollback_completed",
        Some(Kind::RollbackPaused) => "rollback_paused",
    }
}

/// Replica counts for one service's `ServiceStatus`.
///
/// For a **job** the pair is reported as completions over the goal —
/// `running_tasks` carries the completed count and `desired_tasks` the total
/// completions — because that is the number `service ls`'s `REPLICAS` cell
/// should show for a run-to-completion service ("2/3 done"), and it is what
/// the store can compute.
fn task_counts(service: &Service, tasks: &[Arc<Task>]) -> ServiceTaskCounts {
    let mut running = 0_u64;
    let mut completed = 0_u64;
    for task in tasks {
        if task.service_id.as_ref() != Some(&service.id) {
            continue;
        }
        match task.status.state {
            satl_core::TaskState::Running => running += 1,
            // Only the current spec's completions count: an update re-runs
            // the job, and the previous run's tasks would inflate the count
            // past the goal ("4/2" measured on the cluster).
            satl_core::TaskState::Complete
                if !service.spec.mode.is_job()
                    || task.spec_version == Some(service.spec_version) =>
            {
                completed += 1;
            }
            _ => {}
        }
    }
    let desired = match service.spec.mode {
        satl_core::ServiceMode::Replicated { replicas } => replicas,
        satl_core::ServiceMode::ReplicatedJob {
            total_completions, ..
        } => {
            // A job's progress is its completions, not its runners.
            running = completed;
            total_completions.unwrap_or(1)
        }
        // A global service wants one task per eligible node; the honest
        // answer without re-running placement is "as many as it has".
        satl_core::ServiceMode::Global => live_tasks(service, tasks),
        satl_core::ServiceMode::GlobalJob => {
            running = completed;
            live_tasks(service, tasks)
        }
    };
    ServiceTaskCounts {
        running,
        desired,
        completed,
    }
}

/// How many of the service's tasks the cluster still wants running — the
/// denominator a global service's count falls back to.
fn live_tasks(service: &Service, tasks: &[Arc<Task>]) -> u64 {
    tasks
        .iter()
        .filter(|task| {
            task.service_id.as_ref() == Some(&service.id)
                && task.desired_state <= DesiredState::Running
        })
        .count() as u64
}

/// Docker's task filters (OR within a key, AND across keys).
fn matches_filters(
    task: &Task,
    filters: &TaskFilters,
    services: &BTreeMap<Id, String>,
    nodes: &BTreeMap<Id, String>,
) -> bool {
    if filters.is_empty() {
        return true;
    }
    if !filters.ids.is_empty()
        && !filters
            .ids
            .iter()
            .any(|wanted| task.id.as_str().starts_with(wanted.as_str()))
    {
        return false;
    }
    if !filters.names.is_empty() {
        let name = task_name(task);
        if !filters.names.iter().any(|wanted| name.starts_with(wanted)) {
            return false;
        }
    }
    if !filters.services.is_empty() {
        let matched = task.service_id.as_ref().is_some_and(|id| {
            let name = services.get(id);
            filters.services.iter().any(|wanted| {
                id.as_str().starts_with(wanted.as_str()) || name.is_some_and(|n| n == wanted)
            })
        });
        if !matched {
            return false;
        }
    }
    if !filters.nodes.is_empty() {
        let matched = task.node_id.as_ref().is_some_and(|id| {
            let name = nodes.get(id);
            filters.nodes.iter().any(|wanted| {
                id.as_str().starts_with(wanted.as_str()) || name.is_some_and(|n| n == wanted)
            })
        });
        if !matched {
            return false;
        }
    }
    if !filters.desired_states.is_empty() && !filters.desired_states.contains(&task.desired_state) {
        return false;
    }
    for (key, value) in &filters.labels {
        let Some(found) = task.spec.container.labels.get(key) else {
            return false;
        };
        // A key with no value means "the label is set, whatever it says".
        if value.as_ref().is_some_and(|wanted| wanted != found) {
            return false;
        }
    }
    true
}

/// Docker's task name: `<service>.<slot>` for a replicated task, the task id
/// for an anonymous one.
fn task_name(task: &Task) -> String {
    let service = &task.service_annotations.name;
    if service.is_empty() {
        return task.id.to_string();
    }
    if task.slot == 0 {
        return format!("{service}.{}", task.id);
    }
    format!("{service}.{}", task.slot)
}

/// Overwrite a node's `manager_status` from the **live** raft membership.
///
/// `Node.manager_status` is a stored field, written when a node joins and
/// whenever its own daemon updates it — which means it says nothing about the
/// present. After a leader dies, every node object still names the dead node
/// as leader, permanently, even once it rejoins as a follower: exactly what an
/// operator running `satl node ls` must not be told. SwarmKit avoids this by
/// enriching every `ListNodes` response from the raft memberlist rather than
/// trusting the stored copy (SWK §6.2); this does the same.
///
/// A node absent from the membership keeps whatever the store holds: it is a
/// worker (never a raft member) or a manager this node cannot see.
fn refresh_manager_status(node: &mut Node, members: &[satl_cluster::RaftMember]) {
    let Some(status) = node.manager_status.as_mut() else {
        return;
    };
    let Some(member) = members.iter().find(|m| m.raft_id == status.raft_id) else {
        return;
    };
    status.leader = member.leader;
    status.addr = member.addr.clone();
    status.reachability = if member.voter {
        satl_core::Reachability::Reachable
    } else {
        // A learner is still catching up: reachable enough to replicate to,
        // but it votes for nothing, so calling it a peer would overstate it.
        satl_core::Reachability::Unknown
    };
}

/// A node by id, id prefix, name or hostname.
fn resolve_node(view: &satl_cluster::StoreView<'_>, id_or_name: &str) -> Result<Node> {
    if id_or_name.is_empty() {
        return Err(BackendError::invalid("no node id given"));
    }
    if let Ok(id) = id_or_name.parse::<Id>()
        && let Some(node) = view.node(&id)
    {
        return Ok((*node).clone());
    }
    if let Some(node) = view.node_by_name(id_or_name) {
        return Ok((*node).clone());
    }
    let matches: Vec<Arc<Node>> = view
        .nodes()
        .into_iter()
        .filter(|node| {
            node.id.as_str().starts_with(id_or_name)
                || node
                    .description
                    .as_ref()
                    .is_some_and(|d| d.hostname == id_or_name)
        })
        .collect();
    match matches.len() {
        0 => Err(BackendError::not_found(format!(
            "no such node: {id_or_name}"
        ))),
        1 => Ok((*matches[0]).clone()),
        n => Err(BackendError::invalid(format!(
            "node id {id_or_name} is ambiguous: it matches {n} nodes"
        ))),
    }
}

/// Apply the published-service probe defaults and say what happened.
///
/// Three outcomes, and each one is visible to the operator on purpose
/// (`docs/api-compat.md` #125-#128; `docs/operations.md`, "Published ports and
/// healthchecks"):
///
/// - not published: nothing is touched and nothing is said.
/// - published with a probe: the fields the healthcheck left unset are filled
///   with the tighter values and **logged**, because a default nobody can read
///   is magic; the stored spec then shows them in `satl service inspect`.
/// - published with no probe: no defaults to apply, and a warning that goes
///   back to the client as well as into the log — without a probe, `RUNNING`
///   means only "the jail started", so the task is published before it can serve
///   and stays published after it stops serving.
fn harden_probe(name: &str, spec: &mut satl_core::ServiceSpec) -> Vec<String> {
    match satl_core::harden_published_probe(spec) {
        satl_core::PublishedProbe::NotPublished => Vec::new(),
        satl_core::PublishedProbe::Unprobed { ports } => {
            let warning = format!(
                "service {name} publishes {ports} and has no healthcheck: its tasks are \
                 published as soon as the jail starts, before the workload can answer, and stay \
                 published while a dead container keeps its share of the traffic (pf does not \
                 probe a redirect pool). Give it a healthcheck: an unhealthy task is stopped and \
                 replaced, which is what takes it out of the pool."
            );
            tracing::warn!(name = %name, published = %ports, "{warning}");
            vec![warning]
        }
        satl_core::PublishedProbe::Probed { ports, applied } => {
            if applied.any() {
                tracing::info!(
                    name = %name,
                    published = %ports,
                    applied = %applied.describe(),
                    "tighter health probe defaults applied to a published service; an explicitly \
                     set value is never overridden (api-compat 125)"
                );
            }
            Vec::new()
        }
    }
}

/// Turn a forwarding failure into an operator-actionable Docker error.
///
/// The leader's address is the point: a client told "not the leader" with no
/// address has nothing to do with the answer.
pub(super) fn forward_error(
    what: &str,
    manager: &crate::cluster::ManagerCore,
    err: &ForwardError,
) -> BackendError {
    match err {
        ForwardError::Rejected(ProposalRejection::SequenceConflict { .. }) => {
            BackendError::conflict(format!(
                "cannot {what}: the object changed underneath ({err})"
            ))
        }
        ForwardError::Rejected(ProposalRejection::NotFound { kind, id }) => {
            BackendError::not_found(format!("cannot {what}: no such {kind} {id}"))
        }
        ForwardError::Rejected(rejection) => {
            BackendError::conflict(format!("cannot {what}: {rejection}"))
        }
        ForwardError::NoLeader => BackendError::internal(format!(
            "cannot {what}: this cluster has no raft leader right now; writes are refused until \
             one is elected"
        )),
        other => {
            let leader = manager
                .store
                .leader_addr()
                .unwrap_or_else(|| "unknown".to_owned());
            BackendError::internal(format!(
                "cannot {what}: forwarding to the leader at {leader} failed ({other})"
            ))
        }
    }
}

/// Turn a membership failure into a Docker error, keeping the quorum
/// arithmetic in the message: "would break quorum" is the whole answer.
fn membership_error(what: &str, err: &satl_cluster::MembershipError) -> BackendError {
    match err {
        satl_cluster::MembershipError::NotLeader { leader_addr } => {
            BackendError::internal(format!(
                "cannot {what}: this manager is not the raft leader; retry against {}",
                leader_addr.as_deref().unwrap_or("the current leader")
            ))
        }
        satl_cluster::MembershipError::UnknownMember { message } => {
            BackendError::not_found(format!("cannot {what}: {message}"))
        }
        other => BackendError::conflict(format!("cannot {what}: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager_node(raft_id: u64, leader: bool, addr: &str) -> Node {
        let mut node = Node {
            id: Id::generate(),
            meta: satl_core::Meta::new(),
            spec: satl_core::NodeSpec {
                name: None,
                labels: BTreeMap::new(),
                role: NodeRole::Manager,
                availability: Availability::Active,
            },
            description: None,
            status: satl_core::NodeStatus {
                state: satl_core::NodeState::Ready,
                message: String::new(),
                addr: String::new(),
            },
            manager_status: None,
            certificate_status: satl_core::CertificateStatus::default(),
            certificate_issuer: None,
        };
        node.manager_status = Some(satl_core::ManagerStatus {
            raft_id,
            addr: addr.to_owned(),
            leader,
            reachability: satl_core::Reachability::Reachable,
        });
        node
    }

    fn member(raft_id: u64, leader: bool, addr: &str) -> satl_cluster::RaftMember {
        satl_cluster::RaftMember {
            raft_id,
            addr: addr.to_owned(),
            voter: true,
            leader,
        }
    }

    /// The stored `manager_status` says who led when it was last written. A
    /// node that has since lost leadership must not still be reported as
    /// leader — the symptom was `satl node ls` naming a killed node `Leader`
    /// forever, including after it rejoined as a follower.
    #[test]
    fn manager_status_is_refreshed_from_the_live_membership() {
        let mut stale = manager_node(7, true, "10.2.2.47:2377");
        let members = [
            member(7, false, "10.2.2.47:2377"),
            member(9, true, "10.2.1.50:2377"),
        ];
        refresh_manager_status(&mut stale, &members);
        let status = stale.manager_status.expect("a manager status");
        assert!(!status.leader, "the stored leader flag must not survive");
    }

    #[test]
    fn manager_status_picks_up_a_changed_address() {
        let mut node = manager_node(7, false, "old:2377");
        refresh_manager_status(&mut node, &[member(7, false, "10.2.2.47:2377")]);
        assert_eq!(
            node.manager_status.expect("a manager status").addr,
            "10.2.2.47:2377"
        );
    }

    /// A worker is not a raft member and has no manager status to refresh;
    /// a manager missing from this node's view keeps what the store holds.
    #[test]
    fn nodes_outside_the_membership_are_left_alone() {
        let mut worker = manager_node(7, true, "10.2.2.47:2377");
        worker.manager_status = None;
        refresh_manager_status(&mut worker, &[member(9, true, "other:2377")]);
        assert!(worker.manager_status.is_none());

        let mut unseen = manager_node(11, true, "gone:2377");
        refresh_manager_status(&mut unseen, &[member(9, true, "other:2377")]);
        let status = unseen.manager_status.expect("a manager status");
        assert!(status.leader, "an unseen manager keeps its stored status");
    }

    #[test]
    fn a_learner_is_not_reported_reachable() {
        let mut node = manager_node(7, false, "addr:2377");
        let learner = satl_cluster::RaftMember {
            raft_id: 7,
            addr: "addr:2377".to_owned(),
            voter: false,
            leader: false,
        };
        refresh_manager_status(&mut node, &[learner]);
        assert_eq!(
            node.manager_status.expect("a manager status").reachability,
            satl_core::Reachability::Unknown
        );
    }

    fn task(name: &str, slot: u64) -> Task {
        let mut task = super::super::tests::sample_task(name);
        task.slot = slot;
        task.node_id = Some(Id::generate());
        task.desired_state = DesiredState::Running;
        task
    }

    #[test]
    fn a_replicated_task_is_named_service_dot_slot() {
        assert_eq!(task_name(&task("web", 3)), "web.3");
    }

    #[test]
    fn an_unslotted_task_falls_back_to_its_id() {
        let unslotted = task("web", 0);
        assert_eq!(task_name(&unslotted), format!("web.{}", unslotted.id));
        let anonymous = task("", 0);
        assert_eq!(task_name(&anonymous), anonymous.id.to_string());
    }

    #[test]
    fn an_empty_filter_set_matches_everything() {
        let task = task("web", 1);
        assert!(matches_filters(
            &task,
            &TaskFilters::default(),
            &BTreeMap::new(),
            &BTreeMap::new()
        ));
    }

    #[test]
    fn filters_and_across_keys_and_or_within_one() {
        let mut task = task("web", 1);
        let service_id = task.service_id.clone().expect("service");
        let node_id = task.node_id.clone().expect("node");
        task.spec
            .container
            .labels
            .insert("tier".to_owned(), "front".to_owned());
        let services = BTreeMap::from([(service_id.clone(), "web".to_owned())]);
        let nodes = BTreeMap::from([(node_id.clone(), "alpha".to_owned())]);

        // Service by name, node by name: both must match.
        let filters = TaskFilters {
            services: vec!["web".to_owned()],
            nodes: vec!["alpha".to_owned()],
            ..TaskFilters::default()
        };
        assert!(matches_filters(&task, &filters, &services, &nodes));

        // One key that does not match rejects the task.
        let filters = TaskFilters {
            services: vec!["web".to_owned()],
            nodes: vec!["beta".to_owned()],
            ..TaskFilters::default()
        };
        assert!(!matches_filters(&task, &filters, &services, &nodes));

        // Several values in one key are alternatives.
        let filters = TaskFilters {
            nodes: vec!["beta".to_owned(), "alpha".to_owned()],
            ..TaskFilters::default()
        };
        assert!(matches_filters(&task, &filters, &services, &nodes));

        // Desired state and labels.
        let filters = TaskFilters {
            desired_states: vec![DesiredState::Shutdown],
            ..TaskFilters::default()
        };
        assert!(!matches_filters(&task, &filters, &services, &nodes));
        let filters = TaskFilters {
            labels: BTreeMap::from([("tier".to_owned(), Some("front".to_owned()))]),
            ..TaskFilters::default()
        };
        assert!(matches_filters(&task, &filters, &services, &nodes));
        let filters = TaskFilters {
            labels: BTreeMap::from([("tier".to_owned(), Some("back".to_owned()))]),
            ..TaskFilters::default()
        };
        assert!(!matches_filters(&task, &filters, &services, &nodes));
        // A key with no value means "the label exists".
        let filters = TaskFilters {
            labels: BTreeMap::from([("tier".to_owned(), None)]),
            ..TaskFilters::default()
        };
        assert!(matches_filters(&task, &filters, &services, &nodes));
        let filters = TaskFilters {
            labels: BTreeMap::from([("absent".to_owned(), None)]),
            ..TaskFilters::default()
        };
        assert!(!matches_filters(&task, &filters, &services, &nodes));
    }

    #[test]
    fn a_task_id_prefix_matches() {
        let task = task("web", 1);
        let prefix = task.id.as_str()[..6].to_owned();
        let filters = TaskFilters {
            ids: vec![prefix],
            ..TaskFilters::default()
        };
        assert!(matches_filters(
            &task,
            &filters,
            &BTreeMap::new(),
            &BTreeMap::new()
        ));
    }

    /// A service with `image` in its task template and nothing else set.
    fn service_named(name: &str, image: &str) -> Service {
        let mut spec = satl_core::ServiceSpec {
            annotations: satl_core::Annotations {
                name: name.to_owned(),
                labels: BTreeMap::new(),
            },
            task: super::super::tests::empty_task_spec(),
            mode: satl_core::ServiceMode::Replicated { replicas: 3 },
            update: None,
            rollback: None,
            endpoint: None,
        };
        spec.task.container.image = image.to_owned();
        Service {
            id: Id::generate(),
            meta: Meta::new(),
            spec,
            endpoint: None,
            spec_version: satl_core::Version(0),
            previous_spec: None,
            update_status: None,
        }
    }

    fn paused(service: &mut Service, state: satl_core::UpdateStateKind) {
        service.update_status = Some(satl_core::UpdateStatus {
            state,
            started_at: Some(SystemTime::now()),
            completed_at: None,
            message: "update paused: 2 of 6 tasks failed".to_owned(),
        });
    }

    /// The defect this exists for: an update its own failure action paused stays
    /// paused in the object, so the corrected spec an operator pushes next never
    /// starts a rollout — the updater skips a paused service by design. Both
    /// paused states, because a failed rollback lands in the other one.
    #[test]
    fn a_new_spec_clears_a_paused_update() {
        for state in [
            satl_core::UpdateStateKind::Paused,
            satl_core::UpdateStateKind::RollbackPaused,
        ] {
            let mut service = service_named("web", "nginx:broken");
            paused(&mut service, state);
            let mut fixed = service.spec.clone();
            fixed.task.container.image = "nginx:1.27".to_owned();

            let updated = updated_service(&service, false, fixed, SystemTime::now())
                .expect("a spec update is accepted");
            assert!(
                updated.update_status.is_none(),
                "a {state:?} update must not survive a new spec"
            );
            assert_eq!(updated.spec.task.container.image, "nginx:1.27");
            assert_eq!(
                updated
                    .previous_spec
                    .as_ref()
                    .expect("the spec that was there")
                    .task
                    .container
                    .image,
                "nginx:broken"
            );
        }
    }

    /// SwarmKit clears the status on every update, not only on one that really
    /// changes the spec: what "really changed" means is decided by the store's
    /// `spec_version` stamping when the transaction commits, and a no-op update
    /// marks no task dirty, so clearing costs nothing and needs no comparison
    /// here.
    #[test]
    fn even_an_unchanged_spec_clears_the_status() {
        let mut service = service_named("web", "nginx:1.27");
        paused(&mut service, satl_core::UpdateStateKind::Paused);
        let same = service.spec.clone();
        let updated = updated_service(&service, false, same, SystemTime::now()).expect("accepted");
        assert!(updated.update_status.is_none());
    }

    /// A manual rollback has to announce itself, or the updater ignores it for
    /// the same reason: it decides between `spec.update` and `spec.rollback`,
    /// and whether to act at all, from this field.
    #[test]
    fn a_manual_rollback_announces_a_rollback() {
        let mut service = service_named("web", "nginx:broken");
        let mut working = service.spec.clone();
        working.task.container.image = "nginx:1.27".to_owned();
        service.previous_spec = Some(working);
        paused(&mut service, satl_core::UpdateStateKind::Paused);

        let updated = updated_service(&service, true, service.spec.clone(), SystemTime::now())
            .expect("a rollback with a previous spec is accepted");
        let status = updated.update_status.expect("a rollback status");
        assert_eq!(status.state, satl_core::UpdateStateKind::RollbackStarted);
        assert_eq!(status.message, "manually requested rollback");
        assert!(status.completed_at.is_none());
        // The specs are swapped, so a second rollback returns to the first.
        assert_eq!(updated.spec.task.container.image, "nginx:1.27");
        assert_eq!(
            updated
                .previous_spec
                .expect("the spec rolled away from")
                .task
                .container
                .image,
            "nginx:broken"
        );
    }

    #[test]
    fn a_rollback_without_a_previous_spec_is_refused() {
        let service = service_named("web", "nginx:1.27");
        let error = updated_service(&service, true, service.spec.clone(), SystemTime::now())
            .expect_err("nothing to roll back to");
        assert!(format!("{error}").contains("no previous spec"), "{error}");
    }

    #[test]
    fn replica_counts_come_from_the_mode_and_the_task_states() {
        let mut service = Service {
            id: Id::generate(),
            meta: Meta::new(),
            spec: satl_core::ServiceSpec {
                annotations: satl_core::Annotations {
                    name: "web".to_owned(),
                    labels: BTreeMap::new(),
                },
                task: super::super::tests::empty_task_spec(),
                mode: satl_core::ServiceMode::Replicated { replicas: 3 },
                update: None,
                rollback: None,
                endpoint: None,
            },
            endpoint: None,
            spec_version: satl_core::Version(0),
            previous_spec: None,
            update_status: None,
        };
        let mut running = task("web", 1);
        running.service_id = Some(service.id.clone());
        running.status.state = satl_core::TaskState::Running;
        let mut done = task("web", 2);
        done.service_id = Some(service.id.clone());
        done.status.state = satl_core::TaskState::Complete;
        let mut elsewhere = task("db", 1);
        elsewhere.status.state = satl_core::TaskState::Running;
        let tasks = vec![Arc::new(running), Arc::new(done), Arc::new(elsewhere)];

        let counts = task_counts(&service, &tasks);
        assert_eq!(counts.desired, 3);
        assert_eq!(counts.running, 1);
        assert_eq!(counts.completed, 1);

        // A global service reports the tasks it actually has.
        service.spec.mode = satl_core::ServiceMode::Global;
        assert_eq!(task_counts(&service, &tasks).desired, 2);
    }

    #[test]
    fn the_swarm_document_carries_the_ca_and_the_tokens() {
        let root = satl_ca::RootCa::generate(Id::generate().as_ref()).expect("root");
        let tokens = satl_ca::JoinTokens::generate(root.bundle());
        let cluster = satl_core::Cluster {
            id: Id::generate(),
            meta: Meta::new(),
            spec: satl_core::ClusterSpec {
                annotations: satl_core::Annotations {
                    name: "default".to_owned(),
                    labels: BTreeMap::new(),
                },
                raft: satl_core::RaftConfig::default(),
                dispatcher: satl_core::DispatcherConfig::default(),
                ca: satl_core::CaConfig::default(),
                task_defaults: satl_core::TaskDefaults::default(),
                // A cluster with no pool would leave the allocator falling back to
                // its compiled-in default, so the operator could never see or
                // change what overlay networks are carved from. Seed the
                // documented defaults (architecture §15) explicitly.
                default_address_pool: vec![satl_core::defaults::DEFAULT_OVERLAY_POOL.to_owned()],
                subnet_size: satl_core::defaults::DEFAULT_SUBNET_SIZE,
                autolock: false,
                unlock_key: None,
            },
            join_tokens: satl_core::JoinTokens::from(&tokens),
            blacklisted_certs: BTreeMap::new(),
            root_ca_cert: Some(root.cert_pem().as_bytes().to_vec()),
            encrypted_root_ca_key: Some(root.key_pem().as_bytes().to_vec()),
            root_rotation: None,
        };
        let detail = swarm_detail(&cluster);
        assert_eq!(detail.cluster_id, cluster.id.to_string());
        assert!(
            detail
                .root_ca_cert_pem
                .starts_with("-----BEGIN CERTIFICATE")
        );
        assert_eq!(detail.join_tokens.manager, tokens.manager.to_string());
        assert_eq!(detail.join_tokens.worker, tokens.worker.to_string());
        // The private key is not in the document, and must never be.
        assert!(!detail.root_ca_cert_pem.contains("PRIVATE KEY"));
    }

    // ---- published-service probe defaults (api-compat 125-128) ------------

    /// A spec publishing 8080->80 in ingress mode, with `health` as its
    /// healthcheck.
    fn published(health: Option<satl_core::HealthConfig>) -> satl_core::ServiceSpec {
        let mut spec = satl_core::ServiceSpec {
            annotations: satl_core::Annotations {
                name: "web".to_owned(),
                labels: BTreeMap::new(),
            },
            task: super::super::tests::empty_task_spec(),
            mode: satl_core::ServiceMode::Replicated { replicas: 1 },
            update: None,
            rollback: None,
            endpoint: Some(satl_core::EndpointSpec {
                mode: satl_core::EndpointMode::DnsRR,
                ports: vec![satl_core::PortConfig {
                    name: String::new(),
                    protocol: satl_core::PortProtocol::Tcp,
                    target_port: 80,
                    published_port: 8080,
                    publish_mode: satl_core::PublishMode::Ingress,
                }],
            }),
        };
        spec.task.container.healthcheck = health;
        spec
    }

    fn probe(test: &[&str]) -> satl_core::HealthConfig {
        satl_core::HealthConfig {
            test: test.iter().map(|word| (*word).to_owned()).collect(),
            interval: None,
            timeout: None,
            retries: 0,
            start_period: None,
        }
    }

    /// The warning fires when a published service has no probe, and it names
    /// the consequence rather than just the fact.
    #[test]
    fn a_published_service_with_no_healthcheck_is_warned_about() {
        let mut spec = published(None);
        let warnings = harden_probe("web", &mut spec);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let warning = &warnings[0];
        for expected in [
            "web",
            "8080->80/tcp",
            "no healthcheck",
            "before the workload can",
            "a dead container keeps its share of the traffic",
        ] {
            assert!(
                warning.contains(expected),
                "{expected:?} missing: {warning}"
            );
        }
        assert!(warning.is_ascii(), "operator-facing text must be ASCII");
    }

    /// And it does not fire for a probed one, nor for an unpublished one --
    /// exactly those two cases, so the warning stays worth reading.
    #[test]
    fn nothing_is_warned_about_when_there_is_a_probe_or_no_port() {
        let mut probed = published(Some(probe(&["CMD", "/bin/true"])));
        assert!(harden_probe("web", &mut probed).is_empty());

        let mut unpublished = published(None);
        unpublished.endpoint = None;
        assert!(harden_probe("web", &mut unpublished).is_empty());
    }

    /// The values the prober will use are in the *stored* spec, which is what
    /// makes them readable with `satl service inspect` instead of magic.
    #[test]
    fn the_tighter_defaults_are_written_into_the_stored_spec() {
        let mut spec = published(Some(probe(&["CMD-SHELL", "test -f /tmp/ready"])));
        assert!(harden_probe("web", &mut spec).is_empty());
        let health = spec
            .task
            .container
            .healthcheck
            .expect("the healthcheck survives");
        assert_eq!(
            health.interval,
            Some(satl_core::defaults::PUBLISHED_PROBE_INTERVAL)
        );
        assert_eq!(
            health.timeout,
            Some(satl_core::defaults::PUBLISHED_PROBE_TIMEOUT)
        );
        assert_eq!(health.retries, satl_core::defaults::PUBLISHED_PROBE_RETRIES);
    }
}
