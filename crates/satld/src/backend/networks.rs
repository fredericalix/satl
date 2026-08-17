// SPDX-License-Identifier: BSD-2-Clause
//! The network half of the REST backend: `/networks` (architecture §11,
//! `docs/api-compat.md`, Docker Engine API v1.43).
//!
//! Same three rules as `backend/swarm.rs` — reads are local, writes go to the
//! leader, and nothing bypasses the store (invariant #1: a network is created by
//! writing a `Network` object and letting the allocator give it a subnet, a VNI
//! and one gateway per participating node). Three things are specific to
//! networks:
//!
//! - **The gateway in a Docker document is this node's.** An overlay has one
//!   gateway address per participating node (`Network::node_gateways`,
//!   `docs/vxlan.md` §8), so there is no cluster-wide value to report; the API
//!   crate deliberately does not know which node is answering, which is why the
//!   address is passed in from here. A node running no task on the network
//!   reports none.
//! - **`Containers` comes from the tasks**, cluster-wide, and their MACs are
//!   *derived* from their addresses ([`satl_core::MacAddr::from_ipv4`]) — both
//!   ends of the overlay do the same derivation, so a stored MAC would be a
//!   second source of truth for something that is a wire format.
//! - **Attachment is not hot-pluggable.** `connect`/`disconnect` are refused
//!   with a reason rather than half-applied; see [`DaemonBackend::connect_network_impl`].

use std::collections::BTreeMap;
use std::sync::Arc;

use satl_api::model::{
    BackendError, CreateNetworkOptions, NetworkConnectOptions, NetworkCreated, NetworkDetail,
    NetworkDisconnectOptions, NetworkEndpointInfo, NetworkSummary, Result,
};
use satl_cluster::StoreView;
use satl_core::{
    Id, Ipv4Cidr, MacAddr, Meta, Network, NetworkDriver, Service, StoreAction, StoreObject, Task,
};

use super::{DaemonBackend, names};

impl DaemonBackend {
    // -- reads --------------------------------------------------------------

    pub(super) fn list_networks_impl(&self) -> Result<Vec<NetworkSummary>> {
        let cluster = self.cluster()?;
        let manager = Self::manager_of(&cluster)?;
        let view = manager.store.view();
        let mut networks: Vec<Network> = view
            .networks()
            .into_iter()
            .map(|network| (*network).clone())
            .collect();
        networks.sort_by(|a, b| {
            (&a.spec.annotations.name, a.id.as_str())
                .cmp(&(&b.spec.annotations.name, b.id.as_str()))
        });
        Ok(networks
            .into_iter()
            .map(|network| NetworkSummary {
                gateway: gateway_of(&network, &cluster.node_id),
                network,
            })
            .collect())
    }

    pub(super) fn inspect_network_impl(&self, id_or_name: &str) -> Result<NetworkDetail> {
        let cluster = self.cluster()?;
        let manager = Self::manager_of(&cluster)?;
        let view = manager.store.view();
        let network = resolve_network(&view, id_or_name)?;
        let endpoints = endpoints_of(&network, &view.tasks());
        Ok(NetworkDetail {
            gateway: gateway_of(&network, &cluster.node_id),
            network,
            endpoints,
        })
    }

    // -- writes -------------------------------------------------------------

    /// Creates a network object; the allocator fills in the addressing.
    ///
    /// Both refusals are re-checked here under the store view, not because the
    /// API's checks are wrong but because they are *fast paths*: the API asked a
    /// possibly-stale follower, and the object it is about to write is the one
    /// the allocator will act on. Two `ingress` networks or two networks with
    /// one name are states no later pass can repair.
    pub(super) async fn create_network_impl(
        &self,
        options: CreateNetworkOptions,
    ) -> Result<NetworkCreated> {
        let manager = self.manager()?;
        let mut spec = options.spec;
        {
            let view = manager.store.view();
            if spec.annotations.name.trim().is_empty() {
                // Same contract as `POST /containers/create` without `?name=`.
                spec.annotations.name =
                    names::generate_name(|candidate| view.network_by_name(candidate).is_some());
            }
            let name = spec.annotations.name.clone();
            if view.network_by_name(&name).is_some() {
                return Err(BackendError::conflict(format!(
                    "network with name {name} already exists"
                )));
            }
            if spec.ingress
                && let Some(reason) = ingress_conflict(&view.networks())
            {
                return Err(BackendError::invalid(reason));
            }
        }

        let warning = create_warning(&spec, &self.network_name);
        let network = Network {
            id: Id::generate(),
            meta: Meta::new(),
            spec,
            // The allocator owns all three (architecture §11.3): it carves the
            // subnet out of the cluster pool, hands out the VNI and gives each
            // participating node a gateway address as its first task lands.
            vni: None,
            vxlan_port: None,
            subnet: None,
            node_gateways: BTreeMap::new(),
            // The keyring starts empty; the leader populates it when the spec
            // asks for encryption.
            keys: Vec::new(),
            keys_updated_at: None,
        };
        let id = network.id.clone();
        let name = network.spec.annotations.name.clone();
        let driver = network.spec.driver;
        self.propose_via_leader(
            "create the network",
            vec![StoreAction::Create(StoreObject::Network(network))],
        )
        .await?;
        tracing::info!(
            network_id = %id,
            name = %name,
            driver = ?driver,
            "network created; the allocator assigns its subnet and vni"
        );
        Ok(NetworkCreated {
            id: id.to_string(),
            warning,
        })
    }

    /// Removes a network, refusing one that anything still uses.
    ///
    /// Docker's own refusal ("has active endpoints") is a 409, and it is the
    /// right answer for more than the letter of it: a network deleted from under
    /// a live task leaves that task's data plane pointing at a network object
    /// that no longer exists, and the allocator would hand the subnet out again.
    /// A service that references the network is refused too — its next task
    /// could not be allocated (SwarmKit refuses the same way).
    pub(super) async fn remove_network_impl(&self, id_or_name: &str) -> Result<()> {
        let manager = self.manager()?;
        let network = {
            let view = manager.store.view();
            let network = resolve_network(&view, id_or_name)?;
            if let Some(reason) = in_use_reason(&network, &view.tasks(), &view.services()) {
                return Err(BackendError::conflict(reason));
            }
            network
        };
        self.propose_via_leader(
            "remove the network",
            vec![StoreAction::Remove {
                kind: satl_core::ObjectKind::Network,
                id: network.id.clone(),
            }],
        )
        .await?;
        tracing::info!(
            network_id = %network.id,
            name = %network.spec.annotations.name,
            "network removed"
        );
        Ok(())
    }

    /// `POST /networks/{id}/connect` — refused, with the reason.
    ///
    /// Docker attaches a *running* container to a network. SatL cannot do that
    /// yet, and every way of pretending otherwise is worse than saying so:
    ///
    /// - A task's spec is immutable and its attachments are allocated once, at
    ///   task creation (architecture §5 step 3). Attaching it to another network
    ///   means a *new* task — a different container ID than the one the client
    ///   named, which Docker's API cannot express (same root cause as
    ///   `docs/api-compat.md` #30).
    /// - Mutating the owning service's network list instead would return 200 and
    ///   change nothing: the rolling updater that replaces running tasks after a
    ///   spec change is M4 (`satl-orchestrator`'s `TODO(M4)`), so the container
    ///   would stay attached to exactly the networks it had, with the store
    ///   claiming otherwise.
    ///
    /// The network and the container are resolved first, so a typo is still a
    /// 404 rather than a lecture about M4.
    pub(super) fn connect_network_impl(
        &self,
        id_or_name: &str,
        options: &NetworkConnectOptions,
    ) -> Result<()> {
        let (network, task) = self.resolve_attachment(id_or_name, &options.container)?;
        tracing::warn!(
            network_id = %network.id,
            task_id = %task.id,
            aliases = options.aliases.len(),
            "refusing to attach a running container to a network: a task's attachments are \
             allocated once, at creation"
        );
        Err(BackendError::not_implemented(format!(
            "cannot attach container {} to network {}: a task's network attachments are allocated \
             once, at creation, and attaching a live task would mean replacing it under a \
             different container ID (docs/api-compat.md #30). Declare the network when the \
             service is created (`--network {}`); recorded in docs/api-compat.md",
            names::container_name(&task),
            network.spec.annotations.name,
            network.spec.annotations.name,
        )))
    }

    /// `POST /networks/{id}/disconnect` — refused, for the mirror of the reason
    /// in [`DaemonBackend::connect_network_impl`]. Detaching a live task would
    /// leave it running with no route to the network its peers expect it on,
    /// which is the black-holed-traffic failure the overlay work exists to avoid
    /// (`docs/vxlan.md` §8). `Force` does not change that.
    pub(super) fn disconnect_network_impl(
        &self,
        id_or_name: &str,
        options: &NetworkDisconnectOptions,
    ) -> Result<()> {
        let (network, task) = self.resolve_attachment(id_or_name, &options.container)?;
        tracing::warn!(
            network_id = %network.id,
            task_id = %task.id,
            force = options.force,
            "refusing to detach a running container from a network: a task's attachments are \
             allocated once, at creation"
        );
        Err(BackendError::not_implemented(format!(
            "cannot detach container {} from network {}: a task's network attachments are \
             allocated once, at creation, and detaching a live task would leave it running with \
             no path to the network its peers expect it on. Remove the container, or update the \
             service's networks so its tasks are replaced; recorded in \
             docs/api-compat.md",
            names::container_name(&task),
            network.spec.annotations.name,
        )))
    }

    /// The network and the container a connect/disconnect names, so an unknown
    /// one is a 404 before anything else is judged.
    fn resolve_attachment(&self, network: &str, container: &str) -> Result<(Network, Arc<Task>)> {
        let manager = self.manager()?;
        let view = manager.store.view();
        let network = resolve_network(&view, network)?;
        let task = names::resolve_task(&view, container)?;
        Ok((network, task))
    }
}

/// What a create accepts but does not honour the way a Docker user would expect.
///
/// Docker's `NetworkCreate` answer has a single `Warning` field, so these are
/// joined rather than listed. `bridge_name` is the node's own bridge
/// (`network_name` in `satld.toml`).
fn create_warning(spec: &satl_core::NetworkSpec, bridge_name: &str) -> String {
    let mut warnings: Vec<String> = Vec::new();
    if spec.driver == NetworkDriver::Bridge {
        warnings.push(format!(
            "a bridge network is node-local and SatL programs one bridge per node \
             ({bridge_name}): this object is recorded and can be referenced, but tasks attach to \
             that bridge, not to a bridge of their own"
        ));
    }
    if spec.driver == NetworkDriver::Overlay
        && let Some(gateway) = spec.ipam.as_ref().and_then(|ipam| ipam.gateway.as_deref())
    {
        warnings.push(format!(
            "gateway {gateway} is reserved, not assigned: an overlay has one gateway per \
             participating node, so the requested address is kept out of the pool and handed to \
             nobody (docs/vxlan.md section 8)"
        ));
    }
    warnings.join("; ")
}

/// Why a second `ingress` network cannot be created, or `None` when the cluster
/// has none yet.
///
/// A cluster has exactly one ingress network (SWK §9.5). The API refuses this
/// too, off its own store read; this is the copy that runs on the node about to
/// write the object, which is the one that has to hold.
fn ingress_conflict(networks: &[Arc<Network>]) -> Option<String> {
    let existing = networks.iter().find(|network| network.spec.ingress)?;
    Some(format!(
        "network {:?} is already the cluster's ingress network: there can be only one",
        existing.spec.annotations.name
    ))
}

/// The gateway address `node_id` holds on `network`; `None` when it holds none
/// (it runs no task there, so the allocator has given it no address).
fn gateway_of(network: &Network, node_id: &Id) -> Option<String> {
    network.node_gateways.get(node_id).cloned()
}

/// A network by ID, ID prefix or name — the three forms Docker accepts, in the
/// order [`names::resolve_task`] uses, so a name is never shadowed by a prefix.
fn resolve_network(view: &StoreView<'_>, id_or_name: &str) -> Result<Network> {
    let reference = id_or_name.trim();
    if reference.is_empty() {
        return Err(BackendError::not_found("no network id or name given"));
    }
    if let Ok(id) = reference.parse::<Id>()
        && let Some(network) = view.network(&id)
    {
        return Ok((*network).clone());
    }
    if let Some(network) = view.network_by_name(reference) {
        return Ok((*network).clone());
    }
    let matches: Vec<Arc<Network>> = view
        .networks()
        .into_iter()
        .filter(|network| network.id.as_str().starts_with(reference))
        .collect();
    match matches.len() {
        0 => Err(BackendError::not_found(format!(
            "network {reference} not found"
        ))),
        1 => Ok((*matches[0]).clone()),
        n => Err(BackendError::conflict(format!(
            "network {reference} is ambiguous: it matches {n} networks"
        ))),
    }
}

/// The tasks Docker renders as a network's `Containers`: every live task with an
/// allocated attachment on it, cluster-wide.
///
/// Terminal tasks are left out. They keep their attachment records until the
/// reaper deletes them (that history is what `satl ps -a` shows), but a stopped
/// container is not an endpoint of a network, and listing restart history here
/// would make one replica look like five.
fn endpoints_of(network: &Network, tasks: &[Arc<Task>]) -> Vec<NetworkEndpointInfo> {
    let mut endpoints: Vec<NetworkEndpointInfo> = tasks
        .iter()
        .filter(|task| !task.status.state.is_terminal())
        .filter_map(|task| {
            let attachment = task
                .networks
                .iter()
                .find(|attachment| attachment.network_id == network.id)?;
            let address = attachment.addresses.first().cloned().unwrap_or_default();
            // The MAC is derived from the address by the manager, the node and
            // the FDB alike — never stored, never allocated.
            let mac_address = address
                .parse::<Ipv4Cidr>()
                .map(|cidr| MacAddr::from_ipv4(cidr.addr()).to_string())
                .unwrap_or_default();
            Some(NetworkEndpointInfo {
                task_id: task.id.to_string(),
                name: task.annotations.name.clone(),
                address,
                mac_address,
            })
        })
        .collect();
    endpoints.sort_by(|a, b| (&a.name, &a.task_id).cmp(&(&b.name, &b.task_id)));
    endpoints
}

/// Why `network` cannot be removed, or `None` when nothing uses it.
///
/// "Uses it" is wider than an allocated attachment on purpose: a task that has
/// not been allocated yet (`NEW`) names the network in its *spec*, and deleting
/// the network under it turns a pending task into an allocation failure the
/// operator never asked for.
fn in_use_reason(
    network: &Network,
    tasks: &[Arc<Task>],
    services: &[Arc<Service>],
) -> Option<String> {
    let name = &network.spec.annotations.name;
    let attached: Vec<&Arc<Task>> = tasks
        .iter()
        .filter(|task| !task.status.state.is_terminal() && task_uses(task, network))
        .collect();
    if let Some(first) = attached.first() {
        return Some(format!(
            "network {name} has active endpoints: {} task(s) are still attached, starting with {}. \
             Remove the container or the service first",
            attached.len(),
            names::container_name(first)
        ));
    }
    let service = services
        .iter()
        .find(|service| service_uses(service, network))?;
    Some(format!(
        "network {name} is in use by service {}: its next task could not be placed without it",
        service.spec.annotations.name
    ))
}

/// Whether a task holds an attachment on `network` or asks for one.
fn task_uses(task: &Task, network: &Network) -> bool {
    task.networks
        .iter()
        .any(|attachment| attachment.network_id == network.id)
        || task
            .spec
            .networks
            .iter()
            .any(|config| targets(&config.target, network))
}

/// Whether a service's task template asks for `network`.
fn service_uses(service: &Service, network: &Network) -> bool {
    service
        .spec
        .task
        .networks
        .iter()
        .any(|config| targets(&config.target, network))
}

/// Whether a spec's network target names `network` — by ID or by name, the two
/// forms the allocator resolves (`allocator::plan::resolve_network`).
fn targets(target: &str, network: &Network) -> bool {
    target == network.id.as_str() || target == network.spec.annotations.name
}

#[cfg(test)]
mod tests {
    use satl_core::{
        Annotations, IpamConfig, NetworkAttachment, NetworkAttachmentConfig, NetworkSpec,
        ServiceMode, ServiceSpec, TaskState, TaskStatus,
    };

    use super::*;

    fn network(name: &str, driver: NetworkDriver) -> Network {
        Network {
            id: Id::generate(),
            meta: Meta::new(),
            spec: NetworkSpec {
                annotations: Annotations {
                    name: name.to_owned(),
                    labels: BTreeMap::new(),
                },
                driver,
                ipam: None,
                internal: false,
                attachable: false,
                ingress: false,
                encrypted: false,
            },
            vni: Some(4_096),
            vxlan_port: None,
            subnet: Some("10.100.4.0/24".to_owned()),
            node_gateways: BTreeMap::new(),
            keys: Vec::new(),
            keys_updated_at: None,
        }
    }

    fn attached_task(network: &Network, address: &str, state: TaskState) -> Task {
        let mut task = super::super::tests::sample_task("web");
        task.status = TaskStatus::new(state, "test");
        task.networks = vec![NetworkAttachment {
            network_id: network.id.clone(),
            addresses: vec![address.to_owned()],
            aliases: Vec::new(),
        }];
        task
    }

    fn service_on(target: &str) -> Service {
        Service {
            id: Id::generate(),
            meta: Meta::new(),
            spec: ServiceSpec {
                annotations: Annotations {
                    name: "web".to_owned(),
                    labels: BTreeMap::new(),
                },
                task: {
                    let mut spec = super::super::tests::empty_task_spec();
                    spec.networks = vec![NetworkAttachmentConfig {
                        target: target.to_owned(),
                        aliases: Vec::new(),
                    }];
                    spec
                },
                mode: ServiceMode::Replicated { replicas: 1 },
                update: None,
                rollback: None,
                endpoint: None,
            },
            endpoint: None,
            spec_version: satl_core::Version(0),
            previous_spec: None,
            update_status: None,
        }
    }

    /// The gateway a document reports is the answering node's own. Reporting
    /// another node's would be worse than reporting none: it is an address that
    /// exists, on somebody else's bridge, and a client would route to it.
    #[test]
    fn the_gateway_is_this_nodes_or_nothing() {
        let mut net = network("blue", NetworkDriver::Overlay);
        let mine = Id::generate();
        let theirs = Id::generate();
        net.node_gateways
            .insert(theirs.clone(), "10.100.4.3".to_owned());
        assert_eq!(
            gateway_of(&net, &mine),
            None,
            "this node runs no task on the network, so it holds no gateway"
        );

        net.node_gateways
            .insert(mine.clone(), "10.100.4.2".to_owned());
        assert_eq!(gateway_of(&net, &mine).as_deref(), Some("10.100.4.2"));
        assert_eq!(gateway_of(&net, &theirs).as_deref(), Some("10.100.4.3"));
    }

    #[test]
    fn endpoints_carry_the_derived_mac_and_skip_terminal_tasks() {
        let net = network("blue", NetworkDriver::Overlay);
        let live = attached_task(&net, "10.100.4.5/24", TaskState::Running);
        let gone = attached_task(&net, "10.100.4.6/24", TaskState::Shutdown);
        let elsewhere = {
            let other = network("green", NetworkDriver::Overlay);
            attached_task(&other, "10.100.5.5/24", TaskState::Running)
        };
        let tasks = vec![Arc::new(live.clone()), Arc::new(gone), Arc::new(elsewhere)];

        let endpoints = endpoints_of(&net, &tasks);
        assert_eq!(endpoints.len(), 1, "{endpoints:?}");
        assert_eq!(endpoints[0].task_id, live.id.to_string());
        assert_eq!(endpoints[0].name, live.annotations.name);
        assert_eq!(endpoints[0].address, "10.100.4.5/24");
        assert_eq!(
            endpoints[0].mac_address, "02:42:0a:64:04:05",
            "derived from the address, exactly as the FDB derives it"
        );
    }

    /// The 409 the CLI turns into exit 1: removing a network under a live task
    /// would black-hole it and let the allocator re-hand-out its subnet.
    #[test]
    fn a_network_with_live_tasks_or_a_service_cannot_be_removed() {
        let net = network("blue", NetworkDriver::Overlay);
        let live = Arc::new(attached_task(&net, "10.100.4.5/24", TaskState::Running));
        let reason = in_use_reason(&net, &[Arc::clone(&live)], &[]).expect("a refusal");
        assert!(reason.contains("has active endpoints"), "{reason}");
        assert!(reason.contains("1 task(s)"), "{reason}");

        // A task that has not been allocated yet names the network in its spec
        // only — and is just as much a reason to refuse.
        let mut pending = super::super::tests::sample_task("web");
        pending.status = TaskStatus::new(TaskState::New, "created");
        pending.spec.networks = vec![NetworkAttachmentConfig {
            target: net.spec.annotations.name.clone(),
            aliases: Vec::new(),
        }];
        assert!(in_use_reason(&net, &[Arc::new(pending)], &[]).is_some());

        // No tasks, but a service that would need it.
        let by_name = Arc::new(service_on(&net.spec.annotations.name));
        let reason = in_use_reason(&net, &[], &[by_name]).expect("a refusal");
        assert!(reason.contains("in use by service web"), "{reason}");
        let by_id = Arc::new(service_on(net.id.as_str()));
        assert!(in_use_reason(&net, &[], &[by_id]).is_some());

        // Nothing uses it: removable. A terminal task is history, not a use.
        let dead = Arc::new(attached_task(&net, "10.100.4.7/24", TaskState::Failed));
        assert_eq!(in_use_reason(&net, &[dead], &[]), None);
        let other_service = Arc::new(service_on("green"));
        assert_eq!(in_use_reason(&net, &[], &[other_service]), None);
    }

    /// A requested `--gateway` on an overlay is reserved and handed to nobody,
    /// and a bridge network has no data plane of its own yet. Both are accepted;
    /// neither may pass silently.
    /// The API refuses a second ingress network off its own store read; this is
    /// the check that runs on the node that is about to write the object, and it
    /// is the one that has to hold — a follower's copy can be a round-trip stale
    /// (architecture §6.4), and two ingress networks are a state no later pass
    /// can repair.
    #[test]
    fn a_second_ingress_network_is_refused_under_the_store_view() {
        let plain = Arc::new(network("blue", NetworkDriver::Overlay));
        assert_eq!(ingress_conflict(&[Arc::clone(&plain)]), None);

        let mut ingress = network("ingress", NetworkDriver::Overlay);
        ingress.spec.ingress = true;
        let reason = ingress_conflict(&[plain, Arc::new(ingress)]).expect("a refusal");
        assert!(
            reason.contains("already the cluster's ingress network"),
            "{reason}"
        );
        assert!(reason.contains("ingress"), "{reason}");
    }

    #[test]
    fn create_warnings_name_what_is_accepted_but_not_honoured() {
        let mut spec = network("blue", NetworkDriver::Overlay).spec;
        assert!(create_warning(&spec, "satl0").is_empty());

        spec.ipam = Some(IpamConfig {
            subnet: Some("10.100.4.0/24".to_owned()),
            gateway: Some("10.100.4.1".to_owned()),
            ip_range: None,
        });
        let warning = create_warning(&spec, "satl0");
        assert!(warning.contains("10.100.4.1"), "{warning}");
        assert!(warning.contains("reserved, not assigned"), "{warning}");

        let bridge = network("local", NetworkDriver::Bridge).spec;
        let warning = create_warning(&bridge, "satl0");
        assert!(warning.contains("node-local"), "{warning}");
        assert!(warning.contains("satl0"), "{warning}");
    }
}
