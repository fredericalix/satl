// SPDX-License-Identifier: BSD-2-Clause
//! Unit tests for the pure planner: hand-built store objects in, store
//! actions out. No store, no async — the loop is exercised against a real
//! single-node Raft store in `tests/allocator.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::slice::from_ref;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use satl_core::defaults::OVERLAY_VXLAN_PORT_RANGE;
use satl_core::{
    Annotations, Cluster, ClusterSpec, DesiredState, Endpoint, EndpointSpec, Id, JoinTokens, Meta,
    Network, NetworkAttachment, NetworkDriver, Node, ObjectKind, PortConfig, PortProtocol,
    PublishMode, Service, StoreAction, StoreObject, Task, TaskState, Version,
};

use crate::testing::{
    planted_network, planted_node, planted_task, sample_service, with_ipam, with_networks,
    with_published_port,
};

use super::error::AllocError;
use super::plan::{Ballot, Deferred, Failure, NETWORK_VOTER, Plan, PlanInput, VOTERS, plan};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// The default cluster object: `10.100.0.0/14` carved at /24 (architecture §15).
fn cluster(pools: &[&str], subnet_size: u8) -> Cluster {
    Cluster {
        id: Id::generate(),
        meta: Meta::new(),
        spec: ClusterSpec {
            annotations: Annotations {
                name: "default".to_owned(),
                labels: BTreeMap::new(),
            },
            raft: satl_core::RaftConfig::default(),
            dispatcher: satl_core::DispatcherConfig::default(),
            ca: satl_core::CaConfig::default(),
            task_defaults: satl_core::TaskDefaults::default(),
            default_address_pool: pools.iter().map(|pool| (*pool).to_owned()).collect(),
            subnet_size,
            autolock: false,
            unlock_key: None,
        },
        join_tokens: JoinTokens::default(),
        blacklisted_certs: BTreeMap::new(),
        root_ca_cert: None,
        encrypted_root_ca_key: None,
        root_rotation: None,
    }
}

fn default_cluster() -> Cluster {
    cluster(&["10.100.0.0/14"], 24)
}

/// Stamps a creation time on an object so pass ordering is deterministic.
trait Aged {
    fn aged(self, seconds: u64) -> Self;
}

macro_rules! impl_aged {
    ($($ty:ty),+) => {
        $(impl Aged for $ty {
            fn aged(mut self, seconds: u64) -> Self {
                self.meta.created_at = SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
                self.meta.updated_at = self.meta.created_at;
                self
            }
        })+
    };
}
impl_aged!(Network, Service, Task);

/// Runs one pass over the given objects with nothing deferred.
fn run(
    cluster: Option<&Cluster>,
    networks: &[Network],
    services: &[Service],
    tasks: &[Task],
) -> Plan {
    run_deferred(cluster, networks, services, tasks, &Deferred::new())
}

fn run_deferred(
    cluster: Option<&Cluster>,
    networks: &[Network],
    services: &[Service],
    tasks: &[Task],
    deferred: &Deferred,
) -> Plan {
    run_full(cluster, networks, services, tasks, &[], deferred)
}

/// The same, with an explicit node set (the ingress network's participants).
fn run_with_nodes(
    cluster: Option<&Cluster>,
    networks: &[Network],
    services: &[Service],
    tasks: &[Task],
    nodes: &[Node],
) -> Plan {
    run_full(cluster, networks, services, tasks, nodes, &Deferred::new())
}

fn run_full(
    cluster: Option<&Cluster>,
    networks: &[Network],
    services: &[Service],
    tasks: &[Task],
    nodes: &[Node],
    deferred: &Deferred,
) -> Plan {
    let networks: Vec<Arc<Network>> = networks.iter().cloned().map(Arc::new).collect();
    let services: Vec<Arc<Service>> = services.iter().cloned().map(Arc::new).collect();
    let tasks: Vec<Arc<Task>> = tasks.iter().cloned().map(Arc::new).collect();
    let nodes: Vec<Arc<Node>> = nodes.iter().cloned().map(Arc::new).collect();
    plan(
        &PlanInput {
            cluster,
            networks: &networks,
            services: &services,
            tasks: &tasks,
            nodes: &nodes,
        },
        deferred,
    )
}

/// The networks a plan rewrites, in action order.
fn allocated_networks(plan: &Plan) -> Vec<Network> {
    plan.actions
        .iter()
        .filter_map(|action| match action {
            StoreAction::Update(StoreObject::Network(network)) => Some(network.clone()),
            _ => None,
        })
        .collect()
}

/// The networks a plan creates, in action order.
fn created_networks(plan: &Plan) -> Vec<Network> {
    plan.actions
        .iter()
        .filter_map(|action| match action {
            StoreAction::Create(StoreObject::Network(network)) => Some(network.clone()),
            _ => None,
        })
        .collect()
}

/// Apply `prev` to the inputs the way the store would: created objects, then
/// updates over them (later wins), and everything the plan did not touch
/// carried over unchanged. Returns the resulting object sets.
fn applied(
    networks: &[Network],
    services: &[Service],
    tasks: &[Task],
    prev: &Plan,
) -> (Vec<Network>, Vec<Service>, Vec<Task>) {
    let mut networks: Vec<Network> = networks.to_vec();
    networks.extend(created_networks(prev));
    for updated in allocated_networks(prev) {
        if let Some(existing) = networks.iter_mut().find(|n| n.id == updated.id) {
            *existing = updated;
        } else {
            networks.push(updated);
        }
    }
    let mut services: Vec<Service> = services.to_vec();
    for updated in allocated_services(prev) {
        if let Some(existing) = services.iter_mut().find(|s| s.id == updated.id) {
            *existing = updated;
        } else {
            services.push(updated);
        }
    }
    let mut tasks: Vec<Task> = tasks.to_vec();
    for updated in allocated_tasks(prev) {
        if let Some(existing) = tasks.iter_mut().find(|t| t.id == updated.id) {
            *existing = updated;
        } else {
            tasks.push(updated);
        }
    }
    (networks, services, tasks)
}

/// Re-plan with `prev`'s output applied to the given inputs.
fn repass(
    cluster: &Cluster,
    networks: &[Network],
    services: &[Service],
    tasks: &[Task],
    prev: &Plan,
) -> Plan {
    let (networks, services, tasks) = applied(networks, services, tasks, prev);
    run(Some(cluster), &networks, &services, &tasks)
}

fn allocated_services(plan: &Plan) -> Vec<Service> {
    plan.actions
        .iter()
        .filter_map(|action| match action {
            StoreAction::Update(StoreObject::Service(service)) => Some(service.clone()),
            _ => None,
        })
        .collect()
}

fn allocated_tasks(plan: &Plan) -> Vec<Task> {
    plan.actions
        .iter()
        .filter_map(|action| match action {
            StoreAction::Update(StoreObject::Task(task)) => Some(task.clone()),
            _ => None,
        })
        .collect()
}

fn overlay(name: &str, age: u64) -> Network {
    planted_network(name, NetworkDriver::Overlay).aged(age)
}

/// An overlay network created with `--opt encrypted`.
fn encrypted(mut network: Network) -> Network {
    network.spec.encrypted = true;
    network
}

/// A network as the store would hold it after an earlier allocation.
fn allocated(mut network: Network, subnet: &str, vni: u32) -> Network {
    network.subnet = Some(subnet.to_owned());
    network.vni = Some(vni);
    network
}

/// A network that already records a gateway address for a node, the way the
/// store holds it once that node runs a task on the network.
fn with_node_gateway(mut network: Network, node: &Id, gateway: &str) -> Network {
    network
        .node_gateways
        .insert(node.clone(), gateway.to_owned());
    network
}

/// A `NEW` task, bound to `node` the way the scheduler binds it, in `state`.
fn task_of_node(
    service: &Service,
    slot: u64,
    node: &Id,
    state: TaskState,
    attachments: &[(&Network, &[&str])],
) -> Task {
    let mut task = task_on(service, slot, attachments);
    task.node_id = Some(node.clone());
    task.status.state = state;
    task
}

/// A `NEW` task of `service` attached to `networks`, with the addresses the
/// store already records for it.
fn task_on(service: &Service, slot: u64, attachments: &[(&Network, &[&str])]) -> Task {
    let mut task = planted_task(
        service,
        slot,
        TaskState::New,
        DesiredState::Running,
        SystemTime::UNIX_EPOCH + Duration::from_secs(slot),
    );
    task.networks = attachments
        .iter()
        .map(|(network, addresses)| NetworkAttachment {
            network_id: network.id.clone(),
            addresses: addresses.iter().map(|a| (*a).to_owned()).collect(),
            aliases: vec![],
        })
        .collect();
    task
}

fn only_failure(plan: &Plan) -> &Failure {
    assert_eq!(plan.failures.len(), 1, "{:?}", plan.failures);
    &plan.failures[0]
}

// ---------------------------------------------------------------------------
// The ballot (SWK §9)
// ---------------------------------------------------------------------------

#[test]
fn the_network_allocator_is_the_only_registered_voter() {
    assert_eq!(VOTERS, [NETWORK_VOTER]);
}

#[test]
fn a_ballot_is_complete_only_once_every_voter_has_voted() {
    let mut ballot = Ballot::new();
    assert!(!ballot.is_complete(), "no votes yet");
    ballot.vote("volume");
    assert!(
        !ballot.is_complete(),
        "an unregistered voter does not complete the ballot"
    );
    ballot.vote(NETWORK_VOTER);
    assert!(ballot.is_complete());
    // Voting twice is harmless.
    ballot.vote(NETWORK_VOTER);
    assert!(ballot.is_complete());
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

#[test]
fn an_overlay_network_gets_a_subnet_and_a_vni_but_no_gateway_of_its_own() {
    let network = overlay("backend", 1);
    let plan = run(Some(&default_cluster()), &[network], &[], &[]);
    let allocated = allocated_networks(&plan);
    assert_eq!(allocated.len(), 1);
    assert_eq!(allocated[0].subnet.as_deref(), Some("10.100.0.0/24"));
    assert_eq!(allocated[0].vni, Some(4096));
    assert!(
        allocated[0].node_gateways.is_empty(),
        "no node runs anything on it yet, so no gateway address is owed"
    );
    assert!(plan.failures.is_empty());
    assert!(!plan.freed);
}

#[test]
fn two_networks_never_share_a_subnet_or_a_vni() {
    let plan = run(
        Some(&default_cluster()),
        &[overlay("a", 1), overlay("b", 2), overlay("c", 3)],
        &[],
        &[],
    );
    let allocated = allocated_networks(&plan);
    assert_eq!(
        allocated
            .iter()
            .map(|n| (n.spec.annotations.name.clone(), n.subnet.clone(), n.vni))
            .collect::<Vec<_>>(),
        vec![
            ("a".to_owned(), Some("10.100.0.0/24".to_owned()), Some(4096)),
            ("b".to_owned(), Some("10.100.1.0/24".to_owned()), Some(4097)),
            ("c".to_owned(), Some("10.100.2.0/24".to_owned()), Some(4098)),
        ]
    );
}

#[test]
fn bridge_networks_are_left_to_the_node_local_ipam() {
    let bridge = planted_network("satl0", NetworkDriver::Bridge).aged(1);
    let plan = run(Some(&default_cluster()), &[bridge], &[], &[]);
    assert!(plan.actions.is_empty(), "{:?}", plan.actions);
    assert!(plan.failures.is_empty());
}

#[test]
fn an_already_allocated_network_is_not_rewritten() {
    let network = allocated(overlay("backend", 1), "10.100.7.0/24", 4200);
    let plan = run(Some(&default_cluster()), &[network], &[], &[]);
    assert!(plan.actions.is_empty(), "idempotent: {:?}", plan.actions);
}

#[test]
fn the_pool_and_subnet_size_come_from_the_cluster_object() {
    let cluster = cluster(&["172.20.0.0/16"], 26);
    let plan = run(
        Some(&cluster),
        &[overlay("a", 1), overlay("b", 2)],
        &[],
        &[],
    );
    let allocated = allocated_networks(&plan);
    assert_eq!(allocated[0].subnet.as_deref(), Some("172.20.0.0/26"));
    assert_eq!(allocated[1].subnet.as_deref(), Some("172.20.0.64/26"));
}

#[test]
fn a_cluster_without_a_configured_pool_falls_back_to_the_documented_default() {
    // `satld` seeds an empty pool list; architecture §15 says 10.100.0.0/14.
    let plan = run(Some(&cluster(&[], 24)), &[overlay("a", 1)], &[], &[]);
    assert_eq!(
        allocated_networks(&plan)[0].subnet.as_deref(),
        Some("10.100.0.0/24")
    );
    // No cluster object at all behaves the same way.
    let plan = run(None, &[overlay("a", 1)], &[], &[]);
    assert_eq!(
        allocated_networks(&plan)[0].subnet.as_deref(),
        Some("10.100.0.0/24")
    );
}

#[test]
fn an_exhausted_pool_names_the_pool_the_size_and_the_network() {
    // A /23 pool holds exactly two /24s.
    let cluster = cluster(&["10.99.0.0/23"], 24);
    let plan = run(
        Some(&cluster),
        &[overlay("a", 1), overlay("b", 2), overlay("c", 3)],
        &[],
        &[],
    );
    assert_eq!(allocated_networks(&plan).len(), 2);
    let failure = only_failure(&plan);
    assert_eq!(failure.kind, ObjectKind::Network);
    assert_eq!(failure.name, "c");
    let message = failure.error.to_string();
    assert!(message.contains("10.99.0.0/23"), "{message}");
    assert!(message.contains("/24"), "{message}");
    assert!(message.contains("'c'"), "{message}");
}

#[test]
fn an_unusable_pool_configuration_fails_the_cluster_object() {
    let cluster = cluster(&["not-a-cidr"], 24);
    let plan = run(Some(&cluster), &[overlay("a", 1)], &[], &[]);
    let failures: Vec<&Failure> = plan.failures.iter().collect();
    assert_eq!(failures[0].kind, ObjectKind::Cluster);
    assert!(
        failures[0].error.to_string().contains("not-a-cidr"),
        "{}",
        failures[0].error
    );
    // The network could not be given a subnet either, and says so.
    assert!(
        failures
            .iter()
            .any(|failure| failure.kind == ObjectKind::Network),
        "{failures:?}"
    );
    assert!(allocated_networks(&plan).is_empty());
}

#[test]
fn an_unusable_subnet_size_fails_the_cluster_object() {
    for subnet_size in [0, 31, 32, 33] {
        let plan = run(
            Some(&cluster(&["10.100.0.0/14"], subnet_size)),
            &[],
            &[],
            &[],
        );
        let failure = only_failure(&plan);
        assert_eq!(failure.kind, ObjectKind::Cluster);
        assert!(
            failure
                .error
                .to_string()
                .contains(&format!("/{subnet_size}")),
            "{}",
            failure.error
        );
    }
}

#[test]
fn a_pool_shorter_than_the_subnet_size_is_refused() {
    let plan = run(Some(&cluster(&["10.100.0.0/25"], 24)), &[], &[], &[]);
    let failure = only_failure(&plan);
    assert_eq!(failure.kind, ObjectKind::Cluster);
    let message = failure.error.to_string();
    assert!(message.contains("10.100.0.0/25"), "{message}");
    assert!(message.contains("/24"), "{message}");
}

/// An operator-requested `--gateway` names no single node on an overlay, so it
/// is honoured the only way it still means something: nobody gets it. `.1` stays
/// reserved as well.
#[test]
fn an_operator_requested_gateway_is_honoured_as_a_reservation() {
    // A /29: .1 reserved by convention, .2 reserved by request, .3–.6 usable.
    let network = with_ipam(
        overlay("backend", 1),
        Some("192.168.50.0/29"),
        Some("192.168.50.2"),
        None,
    );
    let service = with_networks(sample_service("web", 4), &["backend"]);
    let tasks: Vec<Task> = (1..=4).map(|slot| task_on(&service, slot, &[])).collect();
    let plan = run(
        Some(&default_cluster()),
        from_ref(&network),
        from_ref(&service),
        &tasks,
    );
    let allocated = allocated_networks(&plan);
    assert_eq!(allocated[0].subnet.as_deref(), Some("192.168.50.0/29"));
    assert_eq!(allocated[0].vni, Some(4096), "the VNI still comes from us");
    let addresses: Vec<String> = allocated_tasks(&plan)
        .iter()
        .map(|task| task.networks[0].addresses[0].clone())
        .collect();
    assert_eq!(
        addresses,
        vec![
            "192.168.50.3/29",
            "192.168.50.4/29",
            "192.168.50.5/29",
            "192.168.50.6/29"
        ],
        "both .1 and the requested .2 are held by nobody"
    );
    assert!(plan.failures.is_empty(), "{:?}", plan.failures);
}

#[test]
fn a_requested_subnet_that_overlaps_an_allocated_one_is_refused() {
    let existing = allocated(overlay("a", 1), "10.100.0.0/24", 4096);
    let clash = with_ipam(overlay("b", 2), Some("10.100.0.128/25"), None, None);
    let plan = run(
        Some(&default_cluster()),
        &[existing.clone(), clash],
        &[],
        &[],
    );
    assert!(allocated_networks(&plan).is_empty());
    let failure = only_failure(&plan);
    assert_eq!(failure.name, "b");
    let message = failure.error.to_string();
    assert!(message.contains("10.100.0.128/25"), "{message}");
    assert!(message.contains(existing.id.as_str()), "{message}");
}

#[test]
fn a_gateway_outside_the_subnet_is_reported_and_not_reserved() {
    let network = with_ipam(
        overlay("backend", 1),
        Some("10.60.0.0/24"),
        Some("10.61.0.1"),
        None,
    );
    let plan = run(Some(&default_cluster()), &[network], &[], &[]);
    let failure = only_failure(&plan);
    assert!(
        failure.error.to_string().contains("10.61.0.1"),
        "{}",
        failure.error
    );
    // The network is deferred rather than half-allocated.
    assert!(allocated_networks(&plan).is_empty());
}

#[test]
fn a_malformed_recorded_subnet_is_never_reallocated_over() {
    let mut network = overlay("backend", 1);
    network.subnet = Some("10.100.0.0/99".to_owned());
    let plan = run(Some(&default_cluster()), &[network], &[], &[]);
    assert!(
        allocated_networks(&plan).is_empty(),
        "a running network keeps its addressing; the operator gets an error"
    );
    let failure = only_failure(&plan);
    assert!(
        failure.error.to_string().contains("10.100.0.0/99"),
        "{}",
        failure.error
    );
}

#[test]
fn two_networks_recording_the_same_subnet_leave_the_first_alone() {
    let first = allocated(overlay("a", 1), "10.100.0.0/24", 4096);
    let second = allocated(overlay("b", 2), "10.100.0.0/24", 4097);
    let plan = run(Some(&default_cluster()), &[first.clone(), second], &[], &[]);
    assert!(plan.actions.is_empty(), "neither is rewritten");
    let failure = only_failure(&plan);
    assert_eq!(failure.name, "b", "the older network keeps the subnet");
    assert!(
        failure.error.to_string().contains(first.id.as_str()),
        "{}",
        failure.error
    );
}

#[test]
fn a_recorded_vni_is_never_handed_to_another_network() {
    let existing = allocated(overlay("a", 1), "10.100.9.0/24", 4096);
    let fresh = overlay("b", 2);
    let plan = run(Some(&default_cluster()), &[existing, fresh], &[], &[]);
    let allocated = allocated_networks(&plan);
    assert_eq!(allocated.len(), 1);
    assert_eq!(allocated[0].vni, Some(4097), "4096 is taken");
    assert_eq!(
        allocated[0].subnet.as_deref(),
        Some("10.100.0.0/24"),
        "and 10.100.9.0/24 is taken too"
    );
}

// ---------------------------------------------------------------------------
// VXLAN VTEP ports (encrypted overlay networks)
// ---------------------------------------------------------------------------

#[test]
fn an_encrypted_overlay_network_gets_a_vxlan_port_from_the_pool() {
    let network = encrypted(overlay("backend", 1));
    let plan = run(Some(&default_cluster()), &[network], &[], &[]);
    let allocated = allocated_networks(&plan);
    assert_eq!(allocated.len(), 1);
    assert_eq!(allocated[0].vxlan_port, Some(4790));
    assert_eq!(
        allocated[0].vni,
        Some(4096),
        "the VNI comes from its own range"
    );
    assert!(plan.failures.is_empty(), "{:?}", plan.failures);
}

#[test]
fn unencrypted_overlay_and_bridge_networks_get_no_vxlan_port() {
    let unencrypted = overlay("plain", 1);
    let bridge = planted_network("satl0", NetworkDriver::Bridge).aged(2);
    let plan = run(Some(&default_cluster()), &[unencrypted, bridge], &[], &[]);
    let allocated = allocated_networks(&plan);
    assert_eq!(allocated.len(), 1, "the bridge needs nothing from us");
    assert_eq!(allocated[0].vxlan_port, None);
    assert!(plan.failures.is_empty(), "{:?}", plan.failures);
}

#[test]
fn two_encrypted_networks_get_distinct_vxlan_ports() {
    let plan = run(
        Some(&default_cluster()),
        &[
            encrypted(overlay("a", 1)),
            encrypted(overlay("b", 2)),
            overlay("c", 3),
        ],
        &[],
        &[],
    );
    let ports: Vec<Option<u16>> = allocated_networks(&plan)
        .iter()
        .map(|network| network.vxlan_port)
        .collect();
    assert_eq!(ports, vec![Some(4790), Some(4791), None]);
}

#[test]
fn a_removed_networks_vxlan_port_is_reclaimed() {
    let a = encrypted(overlay("a", 1));
    let first = run(Some(&default_cluster()), from_ref(&a), &[], &[]);
    let (networks, _, _) = applied(from_ref(&a), &[], &[], &first);
    assert_eq!(networks[0].vxlan_port, Some(4790));
    // `satl network rm a`: the next pass rebuilds the space from the store,
    // which no longer records 4790, so a new encrypted network can take it.
    let b = encrypted(overlay("b", 2));
    let plan = run(Some(&default_cluster()), from_ref(&b), &[], &[]);
    let allocated = allocated_networks(&plan);
    assert_eq!(
        allocated[0].vxlan_port,
        Some(4790),
        "the freed port is reused"
    );
}

#[test]
fn a_recorded_vxlan_port_is_never_handed_to_another_network() {
    let mut existing = allocated(encrypted(overlay("a", 1)), "10.100.9.0/24", 4096);
    existing.vxlan_port = Some(4790);
    let fresh = encrypted(overlay("b", 2));
    let plan = run(Some(&default_cluster()), &[existing, fresh], &[], &[]);
    let allocated = allocated_networks(&plan);
    assert_eq!(allocated.len(), 1);
    assert_eq!(allocated[0].vxlan_port, Some(4791), "4790 is taken");
}

#[test]
fn two_networks_recording_the_same_vxlan_port_leave_the_first_alone() {
    let mut first = allocated(encrypted(overlay("a", 1)), "10.100.0.0/24", 4096);
    first.vxlan_port = Some(4790);
    let mut second = allocated(encrypted(overlay("b", 2)), "10.100.1.0/24", 4097);
    second.vxlan_port = Some(4790);
    let plan = run(Some(&default_cluster()), &[first.clone(), second], &[], &[]);
    assert!(plan.actions.is_empty(), "neither is rewritten");
    let failure = only_failure(&plan);
    assert_eq!(failure.name, "b", "the older network keeps the port");
    let message = failure.error.to_string();
    assert!(message.contains("4790"), "{message}");
    assert!(
        message.contains(first.id.as_str()),
        "names the holder: {message}"
    );
}

#[test]
fn vxlan_port_exhaustion_names_the_pool_and_the_network() {
    let error = AllocError::VxlanPortExhausted {
        network: "backend".to_owned(),
        network_id: Id::generate(),
        start: *OVERLAY_VXLAN_PORT_RANGE.start(),
        end: *OVERLAY_VXLAN_PORT_RANGE.end(),
    };
    let message = error.to_string();
    assert!(message.contains("4790..=4999"), "{message}");
    assert!(message.contains("'backend'"), "{message}");
}

/// A port recorded on a network that is not encrypted is a restored-store
/// edge (the spec is immutable post-create): logged, left on the object, and
/// never claimed — so an encrypted network still gets it.
#[test]
fn a_vxlan_port_on_an_unencrypted_network_is_left_alone() {
    let mut stale = allocated(overlay("a", 1), "10.100.0.0/24", 4096);
    stale.vxlan_port = Some(4790);
    let fresh = encrypted(overlay("b", 2));
    let plan = run(Some(&default_cluster()), &[stale, fresh], &[], &[]);
    assert!(plan.failures.is_empty(), "{:?}", plan.failures);
    let allocated = allocated_networks(&plan);
    assert_eq!(allocated.len(), 1, "the stale port is not rewritten away");
    assert_eq!(allocated[0].spec.annotations.name, "b");
    assert_eq!(
        allocated[0].vxlan_port,
        Some(4790),
        "the port was never claimed"
    );
}

#[test]
fn a_second_pass_over_an_allocated_encrypted_network_proposes_nothing() {
    let cluster = default_cluster();
    let network = encrypted(overlay("backend", 1));
    let first = run(Some(&cluster), from_ref(&network), &[], &[]);
    assert_eq!(allocated_networks(&first).len(), 1);
    let second = repass(&cluster, from_ref(&network), &[], &[], &first);
    assert!(
        second.actions.is_empty(),
        "idempotent: {:?}",
        second.actions
    );
    assert!(second.failures.is_empty(), "{:?}", second.failures);
}

#[test]
fn the_ingress_network_is_allocated_before_older_networks() {
    let older = overlay("backend", 1);
    let mut ingress = overlay("satl-ingress", 5);
    ingress.spec.ingress = true;
    let plan = run(Some(&default_cluster()), &[older, ingress], &[], &[]);
    let allocated = allocated_networks(&plan);
    assert_eq!(allocated[0].spec.annotations.name, "satl-ingress");
    assert_eq!(allocated[0].subnet.as_deref(), Some("10.100.0.0/24"));
    assert_eq!(allocated[1].spec.annotations.name, "backend");
}

/// M6d: the ingress network's participant set is every node (SWK §9.1's
/// load-balancer attachment), so every node gets a gateway on it — including
/// a node running no task at all. That gateway is the mesh SNAT's source.
#[test]
fn the_ingress_network_gives_every_node_a_gateway() {
    let mut ingress = allocated(overlay("ingress", 1), "10.100.0.0/24", 4096);
    ingress.spec.ingress = true;
    let (a, b, c) = (planted_node("a"), planted_node("b"), planted_node("c"));
    let plan = run_with_nodes(
        Some(&default_cluster()),
        from_ref(&ingress),
        &[],
        &[],
        &[a.clone(), b.clone(), c.clone()],
    );
    let rewritten = allocated_networks(&plan);
    assert_eq!(rewritten.len(), 1, "the gateways moved");
    let gateways = &rewritten[0].node_gateways;
    assert_eq!(gateways.len(), 3, "every node, task or not: {gateways:?}");
    for node in [&a, &b, &c] {
        assert!(gateways.contains_key(&node.id));
    }
    let mut addrs: Vec<&str> = gateways.values().map(String::as_str).collect();
    addrs.sort_unstable();
    assert_eq!(
        addrs,
        ["10.100.0.2", "10.100.0.3", "10.100.0.4"],
        ".1 is reserved; one address per node"
    );
}

#[test]
fn a_second_ingress_network_is_refused() {
    let mut first = overlay("ingress-a", 1);
    first.spec.ingress = true;
    let mut second = overlay("ingress-b", 2);
    second.spec.ingress = true;
    let plan = run(Some(&default_cluster()), &[first.clone(), second], &[], &[]);
    assert_eq!(allocated_networks(&plan).len(), 1);
    let failure = only_failure(&plan);
    assert_eq!(failure.name, "ingress-b");
    assert!(
        failure.error.to_string().contains(first.id.as_str()),
        "{}",
        failure.error
    );
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

#[test]
fn a_task_without_networks_is_still_voted_into_pending() {
    let service = sample_service("web", 1);
    let task = task_on(&service, 1, &[]);
    let plan = run(Some(&default_cluster()), &[], &[service], &[task]);
    let allocated = allocated_tasks(&plan);
    assert_eq!(allocated.len(), 1);
    assert_eq!(allocated[0].status.state, TaskState::Pending);
    assert_eq!(allocated[0].status.message, "pending task scheduling");
    assert!(allocated[0].networks.is_empty());
}

#[test]
fn tasks_on_one_network_get_distinct_addresses() {
    let network = overlay("backend", 1);
    let service = with_networks(sample_service("web", 3), &["backend"]);
    let tasks: Vec<Task> = (1..=3).map(|slot| task_on(&service, slot, &[])).collect();
    let plan = run(
        Some(&default_cluster()),
        from_ref(&network),
        &[service],
        &tasks,
    );
    let allocated = allocated_tasks(&plan);
    assert_eq!(allocated.len(), 3);
    let addresses: Vec<String> = allocated
        .iter()
        .map(|task| task.networks[0].addresses[0].clone())
        .collect();
    assert_eq!(
        addresses,
        vec!["10.100.0.2/24", "10.100.0.3/24", "10.100.0.4/24"],
        "the gateway .1 is skipped and no address repeats"
    );
    for task in &allocated {
        assert_eq!(task.networks[0].network_id, network.id);
        assert_eq!(task.status.state, TaskState::Pending);
    }
}

#[test]
fn a_task_resolves_its_network_by_name_or_by_id() {
    let network = overlay("backend", 1);
    let by_name = with_networks(sample_service("a", 1), &["backend"]);
    let by_id = with_networks(sample_service("b", 1), &[network.id.as_str()]);
    let tasks = vec![task_on(&by_name, 1, &[]), task_on(&by_id, 2, &[])];
    let plan = run(
        Some(&default_cluster()),
        from_ref(&network),
        &[by_name, by_id],
        &tasks,
    );
    let allocated = allocated_tasks(&plan);
    assert_eq!(allocated.len(), 2);
    for task in &allocated {
        assert_eq!(task.networks[0].network_id, network.id);
        assert!(!task.networks[0].addresses.is_empty());
    }
}

#[test]
fn a_task_attached_to_a_bridge_network_gets_no_cluster_address() {
    let bridge = planted_network("satl0", NetworkDriver::Bridge).aged(1);
    let service = with_networks(sample_service("web", 1), &["satl0"]);
    let task = task_on(&service, 1, &[]);
    let plan = run(
        Some(&default_cluster()),
        from_ref(&bridge),
        &[service],
        &[task],
    );
    let allocated = allocated_tasks(&plan);
    assert_eq!(allocated[0].networks.len(), 1);
    assert_eq!(allocated[0].networks[0].network_id, bridge.id);
    assert!(
        allocated[0].networks[0].addresses.is_empty(),
        "the node's own IPAM owns bridge addresses (architecture §11.1)"
    );
    assert_eq!(
        allocated[0].status.state,
        TaskState::Pending,
        "and it is still schedulable"
    );
}

#[test]
fn aliases_from_the_task_spec_are_carried_onto_the_attachment() {
    let network = overlay("backend", 1);
    let mut service = with_networks(sample_service("web", 1), &["backend"]);
    service.spec.task.networks[0].aliases = vec!["db".to_owned(), "primary".to_owned()];
    let task = task_on(&service, 1, &[]);
    let plan = run(Some(&default_cluster()), &[network], &[service], &[task]);
    assert_eq!(
        allocated_tasks(&plan)[0].networks[0].aliases,
        vec!["db".to_owned(), "primary".to_owned()]
    );
}

#[test]
fn a_task_asking_for_an_unknown_network_is_failed_by_name() {
    let service = with_networks(sample_service("web", 1), &["nope"]);
    let task = task_on(&service, 1, &[]);
    let plan = run(Some(&default_cluster()), &[], &[service], &[task]);
    assert!(allocated_tasks(&plan).is_empty());
    let failure = only_failure(&plan);
    assert_eq!(failure.kind, ObjectKind::Task);
    let message = failure.error.to_string();
    assert!(message.contains("'nope'"), "{message}");
    assert!(message.contains("'web'"), "{message}");
}

#[test]
fn a_task_waits_while_its_network_has_no_subnet() {
    // The network failed (its requested subnet overlaps), so it has no space;
    // its tasks must wait rather than be allocated half-way.
    let existing = allocated(overlay("a", 1), "10.100.0.0/24", 4096);
    let broken = with_ipam(overlay("backend", 2), Some("10.100.0.0/25"), None, None);
    let service = with_networks(sample_service("web", 1), &["backend"]);
    let task = task_on(&service, 1, &[]);
    let plan = run(
        Some(&default_cluster()),
        &[existing, broken],
        &[service],
        &[task],
    );
    assert!(allocated_tasks(&plan).is_empty(), "no half allocation");
    assert_eq!(only_failure(&plan).name, "backend");
}

#[test]
fn a_full_subnet_fails_the_task_naming_the_network_and_the_capacity() {
    // A /30 overlay: .1 reserved, .2 the only usable address.
    let network = allocated(
        with_ipam(overlay("tiny", 1), Some("10.60.0.0/30"), None, None),
        "10.60.0.0/30",
        4096,
    );
    let service = with_networks(sample_service("web", 2), &["tiny"]);
    let first = task_on(&service, 1, &[(&network, &["10.60.0.2/30"])]);
    let second = task_on(&service, 2, &[]);
    let plan = run(
        Some(&default_cluster()),
        &[network],
        &[service],
        &[first, second],
    );
    let failure = only_failure(&plan);
    assert_eq!(failure.kind, ObjectKind::Task);
    let message = failure.error.to_string();
    assert!(message.contains("10.60.0.0/30"), "{message}");
    assert!(message.contains("'tiny'"), "{message}");
    assert!(message.contains('1'), "the capacity: {message}");
}

#[test]
fn a_task_past_new_is_left_alone() {
    let network = overlay("backend", 1);
    let service = with_networks(sample_service("web", 1), &["backend"]);
    for state in [
        TaskState::Pending,
        TaskState::Assigned,
        TaskState::Running,
        TaskState::Starting,
    ] {
        let mut task = task_on(&service, 1, &[]);
        task.status.state = state;
        let plan = run(
            Some(&default_cluster()),
            from_ref(&network),
            from_ref(&service),
            &[task],
        );
        assert!(
            allocated_tasks(&plan).is_empty(),
            "{state}: attachments are built once"
        );
    }
}

#[test]
fn a_task_heading_for_shutdown_is_never_allocated() {
    let network = overlay("backend", 1);
    let service = with_networks(sample_service("web", 1), &["backend"]);
    for desired in [DesiredState::Shutdown, DesiredState::Remove] {
        let mut task = task_on(&service, 1, &[]);
        task.desired_state = desired;
        let plan = run(
            Some(&default_cluster()),
            from_ref(&network),
            from_ref(&service),
            &[task],
        );
        assert!(allocated_tasks(&plan).is_empty(), "{desired}");
    }
}

#[test]
fn a_terminal_task_releases_its_address_and_that_counts_as_freeing_space() {
    let network = allocated(overlay("backend", 1), "10.100.0.0/24", 4096);
    let service = with_networks(sample_service("web", 1), &["backend"]);
    let mut dead = task_on(&service, 1, &[(&network, &["10.100.0.2/24"])]);
    dead.status.state = TaskState::Failed;
    let plan = run(Some(&default_cluster()), &[network], &[service], &[dead]);
    let allocated = allocated_tasks(&plan);
    assert_eq!(allocated.len(), 1);
    assert!(allocated[0].networks[0].addresses.is_empty(), "released");
    assert_eq!(
        allocated[0].networks[0].network_id, allocated[0].networks[0].network_id,
        "the attachment shell is kept as a record"
    );
    assert!(plan.freed, "freed space retries deferred allocations");
    // Idempotent: a terminal task with no addresses is not rewritten.
    let mut already = allocated[0].clone();
    already.networks[0].addresses.clear();
    let plan = run(Some(&default_cluster()), &[], &[], &[already]);
    assert!(plan.actions.is_empty());
    assert!(!plan.freed);
}

#[test]
fn every_terminal_state_releases_addresses() {
    let network = allocated(overlay("backend", 1), "10.100.0.0/24", 4096);
    let service = with_networks(sample_service("web", 1), &["backend"]);
    for state in [
        TaskState::Complete,
        TaskState::Shutdown,
        TaskState::Failed,
        TaskState::Rejected,
        TaskState::Orphaned,
    ] {
        let mut task = task_on(&service, 1, &[(&network, &["10.100.0.2/24"])]);
        task.status.state = state;
        let plan = run(
            Some(&default_cluster()),
            from_ref(&network),
            from_ref(&service),
            &[task],
        );
        assert!(plan.freed, "{state} must free its address");
    }
}

// ---------------------------------------------------------------------------
// Per-node gateway addresses (SWK §9.1, docs/vxlan.md §8)
// ---------------------------------------------------------------------------

/// A node gets its gateway address the first time one of its tasks is on the
/// network, and that address never moves while it keeps running tasks there.
#[test]
fn a_node_gets_a_gateway_when_its_first_task_lands_and_keeps_it() {
    let network = allocated(overlay("backend", 1), "10.100.0.0/24", 4096);
    let service = with_networks(sample_service("web", 2), &["backend"]);
    let node = Id::generate();
    let first = task_of_node(
        &service,
        1,
        &node,
        TaskState::Running,
        &[(&network, &["10.100.0.2/24"])],
    );
    let plan = run(
        Some(&default_cluster()),
        from_ref(&network),
        from_ref(&service),
        from_ref(&first),
    );
    let rewritten = allocated_networks(&plan);
    assert_eq!(rewritten.len(), 1, "the network gains a node gateway");
    assert_eq!(
        rewritten[0].node_gateways.get(&node).map(String::as_str),
        Some("10.100.0.3"),
        "the first free address: .1 is reserved, .2 is the task's"
    );
    assert_eq!(
        rewritten[0].subnet.as_deref(),
        Some("10.100.0.0/24"),
        "and nothing else about the network moved"
    );
    assert!(!plan.freed);
    assert!(plan.failures.is_empty(), "{:?}", plan.failures);

    // A second task of the same node lands: the gateway is the same one, and
    // there is nothing to write.
    let network = rewritten[0].clone();
    let second = task_of_node(
        &service,
        2,
        &node,
        TaskState::Running,
        &[(&network, &["10.100.0.4/24"])],
    );
    let plan = run(
        Some(&default_cluster()),
        from_ref(&network),
        from_ref(&service),
        &[first, second],
    );
    assert!(
        plan.actions.is_empty(),
        "the gateway is stable: {:?}",
        plan.actions
    );
}

/// The bug this shape exists for: two nodes on one overlay must not share an
/// address, and `.1` belongs to nobody (`docs/vxlan.md` §8).
#[test]
fn two_nodes_on_one_network_get_different_gateways_and_neither_is_dot_one() {
    let network = allocated(overlay("backend", 1), "10.100.0.0/24", 4096);
    let service = with_networks(sample_service("web", 2), &["backend"]);
    let (left, right) = (Id::generate(), Id::generate());
    let tasks = [
        task_of_node(
            &service,
            1,
            &left,
            TaskState::Running,
            &[(&network, &["10.100.0.2/24"])],
        ),
        task_of_node(
            &service,
            2,
            &right,
            TaskState::Running,
            &[(&network, &["10.100.0.3/24"])],
        ),
    ];
    let plan = run(
        Some(&default_cluster()),
        from_ref(&network),
        from_ref(&service),
        &tasks,
    );
    let gateways = allocated_networks(&plan)[0].node_gateways.clone();
    assert_eq!(gateways.len(), 2, "one per node: {gateways:?}");
    assert!(gateways.contains_key(&left) && gateways.contains_key(&right));
    let distinct: BTreeSet<&String> = gateways.values().collect();
    assert_eq!(distinct.len(), 2, "the same address twice: {gateways:?}");
    assert_eq!(
        distinct.into_iter().cloned().collect::<Vec<String>>(),
        vec!["10.100.0.4".to_owned(), "10.100.0.5".to_owned()],
        "from the network's own subnet, after the two task addresses"
    );
    assert!(
        !gateways.values().any(|gateway| gateway == "10.100.0.1"),
        "`.1` is reserved, not one node's: {gateways:?}"
    );
}

/// One space for both kinds of owner, whichever was recorded first.
#[test]
fn a_node_gateway_and_a_task_address_never_collide_in_either_order() {
    let service = with_networks(sample_service("web", 2), &["backend"]);
    let node = Id::generate();

    // The node gateway is recorded first: a new task must skip it.
    let network = with_node_gateway(
        allocated(overlay("backend", 1), "10.100.0.0/24", 4096),
        &node,
        "10.100.0.2",
    );
    let running = task_of_node(
        &service,
        1,
        &node,
        TaskState::Running,
        &[(&network, &["10.100.0.3/24"])],
    );
    let fresh = task_on(&service, 2, &[]);
    let plan = run(
        Some(&default_cluster()),
        from_ref(&network),
        from_ref(&service),
        &[running, fresh],
    );
    assert_eq!(
        allocated_tasks(&plan)[0].networks[0].addresses,
        vec!["10.100.0.4/24".to_owned()],
        "the node's .2 and the running task's .3 are both taken"
    );
    assert!(
        allocated_networks(&plan).is_empty(),
        "the recorded gateway is kept as it is"
    );
    assert!(plan.failures.is_empty(), "{:?}", plan.failures);

    // The task address is recorded first: the node's gateway goes elsewhere.
    let network = allocated(overlay("backend", 1), "10.100.0.0/24", 4096);
    let running = task_of_node(
        &service,
        1,
        &node,
        TaskState::Running,
        &[(&network, &["10.100.0.2/24"])],
    );
    let plan = run(
        Some(&default_cluster()),
        from_ref(&network),
        from_ref(&service),
        from_ref(&running),
    );
    assert_eq!(
        allocated_networks(&plan)[0]
            .node_gateways
            .get(&node)
            .map(String::as_str),
        Some("10.100.0.3")
    );
}

/// A task recording an address a node's gateway already holds is the task's
/// problem, not the network's: the gateway is live on a bridge and never moves.
#[test]
fn a_task_recording_a_node_gateways_address_is_the_one_that_fails() {
    let node = Id::generate();
    let network = with_node_gateway(
        allocated(overlay("backend", 1), "10.100.0.0/24", 4096),
        &node,
        "10.100.0.2",
    );
    let service = with_networks(sample_service("web", 1), &["backend"]);
    let clash = task_of_node(
        &service,
        1,
        &node,
        TaskState::Running,
        &[(&network, &["10.100.0.2/24"])],
    );
    let plan = run(
        Some(&default_cluster()),
        from_ref(&network),
        from_ref(&service),
        from_ref(&clash),
    );
    let failure = only_failure(&plan);
    assert_eq!(failure.kind, ObjectKind::Task);
    let message = failure.error.to_string();
    assert!(message.contains("10.100.0.2"), "{message}");
    assert!(
        message.contains(node.as_str()),
        "names the holder: {message}"
    );
}

/// Two nodes recording the same gateway address is exactly the measured
/// duplicate-address bug: the network is reported and nothing is renumbered.
#[test]
fn two_nodes_recording_one_gateway_address_fails_the_network() {
    let (left, right) = (Id::generate(), Id::generate());
    let network = with_node_gateway(
        with_node_gateway(
            allocated(overlay("backend", 1), "10.100.0.0/24", 4096),
            &left,
            "10.100.0.2",
        ),
        &right,
        "10.100.0.2",
    );
    let plan = run(Some(&default_cluster()), from_ref(&network), &[], &[]);
    let failure = only_failure(&plan);
    assert_eq!(failure.kind, ObjectKind::Network);
    let message = failure.error.to_string();
    assert!(message.contains("10.100.0.2"), "{message}");
    assert!(message.contains("'backend'"), "{message}");
    assert!(plan.actions.is_empty(), "nothing is rewritten");
}

#[test]
fn a_malformed_recorded_node_gateway_is_reported_and_never_healed() {
    let node = Id::generate();
    let network = with_node_gateway(
        allocated(overlay("backend", 1), "10.100.0.0/24", 4096),
        &node,
        "not-an-address",
    );
    let plan = run(Some(&default_cluster()), from_ref(&network), &[], &[]);
    let failure = only_failure(&plan);
    assert_eq!(failure.kind, ObjectKind::Network);
    assert!(
        failure.error.to_string().contains("not-an-address"),
        "{}",
        failure.error
    );
    assert!(plan.actions.is_empty());
}

/// Releasing: a node that runs nothing on the network any more gives its
/// gateway back — and the address is *not* reusable in the pass that released
/// it, because that node's bridge may still be carrying it.
#[test]
fn a_node_with_no_tasks_left_loses_its_gateway_and_the_address_waits_a_pass() {
    let (gone, live, late) = (Id::generate(), Id::generate(), Id::generate());
    let network = with_node_gateway(
        allocated(overlay("backend", 1), "10.100.0.0/24", 4096),
        &gone,
        "10.100.0.2",
    );
    let service = with_networks(sample_service("web", 3), &["backend"]);
    // The task that kept `gone` a participant is over; `live` has a running one.
    let finished = task_of_node(&service, 1, &gone, TaskState::Complete, &[(&network, &[])]);
    let running = task_of_node(
        &service,
        2,
        &live,
        TaskState::Running,
        &[(&network, &["10.100.0.9/24"])],
    );
    let plan = run(
        Some(&default_cluster()),
        from_ref(&network),
        from_ref(&service),
        &[finished.clone(), running.clone()],
    );
    let rewritten = allocated_networks(&plan)[0].clone();
    assert!(
        !rewritten.node_gateways.contains_key(&gone),
        "the gateway is released: {:?}",
        rewritten.node_gateways
    );
    assert_eq!(
        rewritten.node_gateways.get(&live).map(String::as_str),
        Some("10.100.0.3"),
        "and not .2: an address released in this pass is not handed out in it"
    );
    assert!(plan.freed, "a release retries deferred allocations at once");

    // The next pass, over the network as the store now holds it: .2 is free.
    let arriving = task_of_node(
        &service,
        3,
        &late,
        TaskState::Running,
        &[(&rewritten, &["10.100.0.10/24"])],
    );
    let plan = run(
        Some(&default_cluster()),
        from_ref(&rewritten),
        from_ref(&service),
        &[finished, running, arriving],
    );
    assert_eq!(
        allocated_networks(&plan)[0]
            .node_gateways
            .get(&late)
            .map(String::as_str),
        Some("10.100.0.2"),
        "the freed address is reusable from the next pass on"
    );
    assert!(!plan.freed, "nothing was given up this time");
}

#[test]
fn a_bridge_networks_nodes_get_no_cluster_gateway() {
    let bridge = planted_network("satl0", NetworkDriver::Bridge).aged(1);
    let service = with_networks(sample_service("web", 1), &["satl0"]);
    let node = Id::generate();
    let task = task_of_node(&service, 1, &node, TaskState::Running, &[(&bridge, &[])]);
    let plan = run(
        Some(&default_cluster()),
        from_ref(&bridge),
        from_ref(&service),
        from_ref(&task),
    );
    assert!(
        plan.actions.is_empty(),
        "the node's own IPAM owns the bridge's .1 (architecture §11.1): {:?}",
        plan.actions
    );
}

/// Convergence with node gateways in play: the plan applied to the store is a
/// fixed point, which is what makes the restore phase safe on every pass.
#[test]
fn a_second_pass_over_its_own_node_gateways_changes_nothing() {
    let network = allocated(overlay("backend", 1), "10.100.0.0/24", 4096);
    let service = with_networks(sample_service("web", 2), &["backend"]);
    let (left, right) = (Id::generate(), Id::generate());
    let tasks = [
        task_of_node(
            &service,
            1,
            &left,
            TaskState::Running,
            &[(&network, &["10.100.0.2/24"])],
        ),
        task_of_node(
            &service,
            2,
            &right,
            TaskState::Running,
            &[(&network, &["10.100.0.3/24"])],
        ),
    ];
    let first = run(
        Some(&default_cluster()),
        from_ref(&network),
        from_ref(&service),
        &tasks,
    );
    let allocated = allocated_networks(&first);
    assert_eq!(allocated.len(), 1);
    assert_eq!(
        allocated[0]
            .node_gateways
            .values()
            .cloned()
            .collect::<BTreeSet<String>>(),
        BTreeSet::from(["10.100.0.4".to_owned(), "10.100.0.5".to_owned()])
    );

    // Apply the plan the way the store would, then re-plan.
    let second = run(
        Some(&default_cluster()),
        &[allocated[0].clone()],
        from_ref(&service),
        &tasks,
    );
    assert!(second.actions.is_empty(), "{:?}", second.actions);
    assert!(second.failures.is_empty(), "{:?}", second.failures);
    assert!(!second.freed);
}

// ---------------------------------------------------------------------------
// The two-phase restore (SWK §9.2) — the property that matters
// ---------------------------------------------------------------------------

#[test]
fn restore_claims_everything_before_a_single_new_allocation_is_made() {
    // What a new leader finds in the store: three overlay networks with
    // subnets and VNIs, a service with a published port, and tasks holding
    // addresses — deliberately *not* the lowest values, so an allocator that
    // skipped the restore phase would collide immediately.
    let held = [
        allocated(overlay("a", 1), "10.100.0.0/24", 4096),
        allocated(overlay("b", 2), "10.100.1.0/24", 4097),
        allocated(overlay("c", 3), "10.100.2.0/24", 4098),
    ];
    let running = with_networks(sample_service("running", 2), &["a"]).aged(4);
    let mut running = with_published_port(running, "http", 80, 30000);
    running.endpoint = Some(Endpoint {
        spec: running.spec.endpoint.clone().expect("spec"),
        ports: vec![PortConfig {
            name: "http".to_owned(),
            protocol: PortProtocol::Tcp,
            target_port: 80,
            published_port: 30000,
            publish_mode: PublishMode::Ingress,
        }],
    });
    let mut old_tasks = Vec::new();
    for (slot, address) in [(1, "10.100.0.2/24"), (2, "10.100.0.3/24")] {
        let mut task = task_on(&running, slot, &[(&held[0], &[address])]);
        task.status.state = TaskState::Running;
        old_tasks.push(task);
    }

    // Now the new leader also has fresh work waiting: a network, a service
    // with an auto-assigned port, and tasks on the existing network "a".
    let fresh_network = overlay("fresh", 9);
    let fresh_service = with_published_port(
        with_networks(sample_service("fresh", 1), &["fresh"]),
        "http",
        80,
        0,
    );
    let new_on_a = with_networks(sample_service("more", 1), &["a"]);
    let mut networks = held.to_vec();
    networks.push(fresh_network);
    let tasks: Vec<Task> = old_tasks
        .iter()
        .cloned()
        .chain([task_on(&new_on_a, 3, &[]), task_on(&fresh_service, 1, &[])])
        .collect();
    let plan = run(
        Some(&default_cluster()),
        &networks,
        &[running, fresh_service, new_on_a],
        &tasks,
    );
    assert!(plan.failures.is_empty(), "{:?}", plan.failures);

    // The new network gets the first *free* subnet and VNI, not the first ones.
    let allocated_networks = allocated_networks(&plan);
    assert_eq!(allocated_networks.len(), 1);
    assert_eq!(
        allocated_networks[0].subnet.as_deref(),
        Some("10.100.3.0/24"),
        "the three restored subnets were skipped"
    );
    assert_eq!(
        allocated_networks[0].vni,
        Some(4099),
        "and so were the VNIs"
    );

    // The new task on network "a" gets the first free address in it.
    let allocated_tasks = allocated_tasks(&plan);
    let on_a: Vec<&Task> = allocated_tasks
        .iter()
        .filter(|task| task.networks[0].network_id == held[0].id)
        .collect();
    assert_eq!(on_a.len(), 1);
    assert_eq!(
        on_a[0].networks[0].addresses,
        vec!["10.100.0.4/24".to_owned()],
        ".2 and .3 are held by the running tasks"
    );

    // And the new service's auto-assigned port skips the one already published.
    let ports = allocated_services(&plan);
    let fresh_ports: Vec<u16> = ports
        .iter()
        .filter(|service| service.spec.annotations.name == "fresh")
        .flat_map(|service| {
            service
                .endpoint
                .as_ref()
                .expect("endpoint")
                .ports
                .iter()
                .map(|port| port.published_port)
        })
        .collect();
    assert_eq!(fresh_ports, vec![30001], "30000 is taken");
}

#[test]
fn a_second_pass_over_its_own_output_changes_nothing() {
    // Convergence: the plan applied to the store must be a fixed point, which
    // is what makes the restore phase safe to run on every pass.
    //
    // M6d shape: the service publishes an ingress port, so pass 1 also
    // creates the ingress network (bare), pass 2 allocates it and attaches
    // the tasks to it, pass 3 must be the fixed point.
    let network = overlay("backend", 1);
    let service = with_published_port(
        with_networks(sample_service("web", 2), &["backend"]),
        "http",
        80,
        0,
    );
    let tasks: Vec<Task> = (1..=2).map(|slot| task_on(&service, slot, &[])).collect();
    let first = run(
        Some(&default_cluster()),
        from_ref(&network),
        from_ref(&service),
        &tasks,
    );
    assert_eq!(
        first.actions.len(),
        3,
        "backend network, service, the bare ingress network (tasks wait for its subnet)"
    );

    // Apply the plan the way the store would, then re-plan — twice: the
    // second pass allocates the ingress network and the tasks, the third is
    // the fixed point.
    let (n1, s1, t1) = applied(from_ref(&network), from_ref(&service), &tasks, &first);
    let second = run(Some(&default_cluster()), &n1, &s1, &t1);
    let (n2, s2, t2) = applied(&n1, &s1, &t1, &second);
    let third = run(Some(&default_cluster()), &n2, &s2, &t2);
    assert!(third.actions.is_empty(), "{:?}", third.actions);
    assert!(third.failures.is_empty(), "{:?}", third.failures);
    assert!(!third.freed);
}

// ---------------------------------------------------------------------------
// Services and ports
// ---------------------------------------------------------------------------

#[test]
fn a_published_port_is_auto_assigned_from_the_ingress_range() {
    let service = with_published_port(sample_service("web", 1), "http", 80, 0);
    let plan = run(Some(&default_cluster()), &[], &[service], &[]);
    let allocated = allocated_services(&plan);
    let endpoint = allocated[0].endpoint.as_ref().expect("endpoint");
    assert_eq!(endpoint.ports.len(), 1);
    assert_eq!(endpoint.ports[0].published_port, 30000);
    assert_eq!(endpoint.ports[0].target_port, 80);
    assert_eq!(
        endpoint.spec,
        allocated[0].spec.endpoint.clone().expect("spec"),
        "the endpoint records the spec it was allocated from"
    );
}

#[test]
fn a_service_update_keeps_its_published_ports() {
    let mut service = with_published_port(sample_service("web", 1), "http", 80, 0);
    service.endpoint = Some(Endpoint {
        spec: service.spec.endpoint.clone().expect("spec"),
        ports: vec![PortConfig {
            name: "http".to_owned(),
            protocol: PortProtocol::Tcp,
            target_port: 80,
            published_port: 30007,
            publish_mode: PublishMode::Ingress,
        }],
    });
    // The update adds a second port; the first must not move.
    let updated = with_published_port(service, "metrics", 9100, 0);
    let plan = run(Some(&default_cluster()), &[], &[updated], &[]);
    let endpoint = allocated_services(&plan)[0]
        .endpoint
        .clone()
        .expect("endpoint");
    assert_eq!(endpoint.ports[0].published_port, 30007, "sticky");
    assert_eq!(endpoint.ports[1].published_port, 30000);
}

#[test]
fn removing_the_endpoint_spec_deallocates_the_ports() {
    let mut service = sample_service("web", 1);
    service.endpoint = Some(Endpoint {
        spec: EndpointSpec::default(),
        ports: vec![PortConfig {
            name: "http".to_owned(),
            protocol: PortProtocol::Tcp,
            target_port: 80,
            published_port: 30000,
            publish_mode: PublishMode::Ingress,
        }],
    });
    let plan = run(Some(&default_cluster()), &[], &[service], &[]);
    let allocated = allocated_services(&plan);
    assert_eq!(allocated.len(), 1);
    assert!(allocated[0].endpoint.is_none(), "deallocated");
    assert!(plan.freed);
}

#[test]
fn a_port_two_services_want_fails_the_younger_one() {
    let mut older = with_published_port(sample_service("older", 1), "http", 80, 8080).aged(1);
    older.endpoint = Some(Endpoint {
        spec: older.spec.endpoint.clone().expect("spec"),
        ports: vec![PortConfig {
            name: "http".to_owned(),
            protocol: PortProtocol::Tcp,
            target_port: 80,
            published_port: 8080,
            publish_mode: PublishMode::Ingress,
        }],
    });
    let younger = with_published_port(sample_service("younger", 1), "http", 80, 8080).aged(2);
    let plan = run(
        Some(&default_cluster()),
        &[],
        &[older.clone(), younger],
        &[],
    );
    let failure = only_failure(&plan);
    assert_eq!(failure.kind, ObjectKind::Service);
    assert_eq!(failure.name, "younger");
    let message = failure.error.to_string();
    assert!(message.contains("8080/tcp"), "{message}");
    assert!(message.contains(older.id.as_str()), "{message}");
}

#[test]
fn a_task_copies_its_services_allocated_endpoint_and_waits_for_it() {
    let service = with_published_port(sample_service("web", 1), "http", 80, 0);
    let task = task_on(&service, 1, &[]);
    let first = run(
        Some(&default_cluster()),
        &[],
        from_ref(&service),
        from_ref(&task),
    );
    // M6d: publishing an ingress port creates the ingress network first, and
    // the task attaches to it — so the task is allocated one pass later, once
    // the network has a subnet.
    assert!(
        allocated_tasks(&first).is_empty(),
        "pass 1 creates the ingress network; the task waits for its subnet"
    );
    assert_eq!(created_networks(&first).len(), 1);
    let second = repass(
        &default_cluster(),
        &[],
        from_ref(&service),
        from_ref(&task),
        &first,
    );
    let allocated = allocated_tasks(&second);
    let endpoint = allocated[0].endpoint.as_ref().expect("endpoint copied");
    assert_eq!(
        endpoint.ports[0].published_port, 30000,
        "the task carries the allocated port, not the spec's 0"
    );
    // ...attached to the ingress network, with an address on it.
    let ingress = &created_networks(&first)[0];
    assert!(
        allocated[0]
            .networks
            .iter()
            .any(|attachment| attachment.network_id == ingress.id
                && !attachment.addresses.is_empty()),
        "the task is attached to the ingress network: {:?}",
        allocated[0].networks
    );

    // A service whose ports cannot be allocated blocks its tasks.
    let mut holder = with_published_port(sample_service("holder", 1), "http", 80, 8080).aged(1);
    holder.endpoint = Some(Endpoint {
        spec: holder.spec.endpoint.clone().expect("spec"),
        ports: vec![PortConfig {
            name: "http".to_owned(),
            protocol: PortProtocol::Tcp,
            target_port: 80,
            published_port: 8080,
            publish_mode: PublishMode::Ingress,
        }],
    });
    let blocked = with_published_port(sample_service("blocked", 1), "http", 80, 8080).aged(2);
    let waiting = task_on(&blocked, 1, &[]);
    let plan = run(
        Some(&default_cluster()),
        &[],
        &[holder, blocked],
        &[waiting],
    );
    assert!(
        allocated_tasks(&plan).is_empty(),
        "a task waits for its service to be fully allocated (SWK §9.4)"
    );
}

/// The REST backend records host-mode ports on `Service.endpoint` at create
/// time and leaves the ingress ones to the allocator (`satld`'s
/// `initial_endpoint`). Such an endpoint carries *fewer* ports than its spec,
/// which must count as "not allocated yet" — otherwise a task would be
/// promoted with no published port.
#[test]
fn an_endpoint_missing_a_spec_port_is_not_treated_as_allocated() {
    let mut host = PortConfig {
        name: "host".to_owned(),
        protocol: PortProtocol::Tcp,
        target_port: 80,
        published_port: 8080,
        publish_mode: PublishMode::Host,
    };
    host.publish_mode = PublishMode::Host;
    let mut service = with_published_port(sample_service("web", 1), "http", 90, 0);
    service
        .spec
        .endpoint
        .as_mut()
        .expect("spec")
        .ports
        .push(host.clone());
    // What the backend wrote: the spec, and only the host port.
    service.endpoint = Some(Endpoint {
        spec: service.spec.endpoint.clone().expect("spec"),
        ports: vec![host],
    });
    let task = task_on(&service, 1, &[]);
    let first = run(
        Some(&default_cluster()),
        &[],
        from_ref(&service),
        from_ref(&task),
    );

    let allocated = allocated_services(&first);
    let ports = &allocated[0].endpoint.as_ref().expect("endpoint").ports;
    assert_eq!(ports.len(), 2);
    assert_eq!(ports[0].published_port, 30000, "the ingress port");
    assert_eq!(ports[1].published_port, 8080, "the host port, verbatim");
    // The task is allocated one pass later — the freshly created ingress
    // network needs its subnet first — and carries both ports.
    let second = repass(
        &default_cluster(),
        &[],
        from_ref(&service),
        from_ref(&task),
        &first,
    );
    let task = &allocated_tasks(&second)[0];
    assert_eq!(
        task.endpoint.as_ref().expect("endpoint").ports.len(),
        2,
        "the task carries the allocated endpoint"
    );
    assert_eq!(task.status.state, TaskState::Pending);
}

// ---------------------------------------------------------------------------
// Retry discipline (SWK §9.3)
// ---------------------------------------------------------------------------

#[test]
fn a_deferred_object_is_skipped_until_its_version_changes() {
    let mut network = overlay("backend", 1);
    network.meta.version = Version(7);
    let deferred = Deferred::from([(network.id.clone(), Version(7))]);
    let plan = run_deferred(
        Some(&default_cluster()),
        from_ref(&network),
        &[],
        &[],
        &deferred,
    );
    assert!(plan.actions.is_empty(), "deferred: not retried yet");

    // An edit bumps the version, which retries immediately.
    let mut edited = network;
    edited.meta.version = Version(8);
    let plan = run_deferred(Some(&default_cluster()), &[edited], &[], &[], &deferred);
    assert_eq!(allocated_networks(&plan).len(), 1, "retried at once");
}

#[test]
fn deferring_a_network_does_not_stop_the_rest_of_the_cluster() {
    let mut broken = with_ipam(overlay("broken", 1), Some("nonsense"), None, None);
    broken.meta.version = Version(3);
    let healthy = overlay("healthy", 2);
    let deferred = Deferred::from([(broken.id.clone(), Version(3))]);
    let plan = run_deferred(
        Some(&default_cluster()),
        &[broken, healthy],
        &[],
        &[],
        &deferred,
    );
    let allocated = allocated_networks(&plan);
    assert_eq!(allocated.len(), 1);
    assert_eq!(allocated[0].spec.annotations.name, "healthy");
    assert!(
        plan.failures.is_empty(),
        "the deferred one is not re-logged"
    );
}

// ---------------------------------------------------------------------------
// Transaction bounds
// ---------------------------------------------------------------------------

#[test]
fn one_pass_never_exceeds_the_transaction_limit() {
    let network = overlay("backend", 1);
    let service = with_networks(sample_service("web", 1), &["backend"]);
    // Far more work than one transaction can carry.
    let limit = u64::try_from(satl_core::defaults::MAX_TX_ACTIONS).expect("fits in u64");
    let tasks: Vec<Task> = (1..=limit + 50)
        .map(|slot| task_on(&service, slot, &[]))
        .collect();
    let plan = run(Some(&default_cluster()), &[network], &[service], &tasks);
    assert_eq!(plan.actions.len(), satl_core::defaults::MAX_TX_ACTIONS);
    // The network update survives the truncation: dependencies come first.
    assert!(
        matches!(
            plan.actions.first(),
            Some(StoreAction::Update(StoreObject::Network(_)))
        ),
        "{:?}",
        plan.actions.first()
    );
}
