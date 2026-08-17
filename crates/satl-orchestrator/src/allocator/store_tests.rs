// SPDX-License-Identifier: BSD-2-Clause
//! The allocator loop against a real single-node store.
//!
//! `TestCluster` is `satl-cluster`'s in-process Raft harness (a genuine FSM in
//! a temp dir, ~20 ms to start), so these exercise the actual watch feed, the
//! actual optimistic concurrency and the actual proposal path. The allocator is
//! spawned **alone**: the other loops would create and reap tasks underneath
//! these assertions, and what is under test here is allocation. The end-to-end
//! wiring with all four loops is `tests/allocator.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use satl_cluster::ClusterStore;
use satl_core::{
    DesiredState, Endpoint, Id, Network, NetworkDriver, ObjectKind, RestartCondition, Service,
    StoreAction, StoreObject, Task, TaskState, TaskStatus,
};
use tokio_util::sync::CancellationToken;

use crate::testing::{
    TestCluster, planted_network, planted_task, sample_service, set_task_state, with_ipam,
    with_networks, with_published_port, with_restart,
};

use super::Allocator;

/// A quick full pass, and a retry window long enough that nothing is ever
/// retried *because of the timer*: every retry these tests observe is the
/// deallocation path (SWK §9.3).
fn spawn(store: &ClusterStore, shutdown: &CancellationToken) -> tokio::task::JoinHandle<()> {
    tokio::spawn(
        Allocator::new(
            store.clone(),
            Duration::from_millis(50),
            Duration::from_hours(1),
        )
        .run(shutdown.clone()),
    )
}

async fn create(store: &ClusterStore, object: StoreObject) {
    store
        .propose(vec![StoreAction::Create(object)])
        .await
        .expect("object created");
}

async fn remove(store: &ClusterStore, kind: ObjectKind, id: &Id) {
    store
        .propose(vec![StoreAction::Remove {
            kind,
            id: id.clone(),
        }])
        .await
        .expect("object removed");
}

/// Narrows the cluster's address pool, the way `satl swarm init
/// --default-addr-pool` would have.
async fn set_pool(store: &ClusterStore, pools: &[&str], subnet_size: u8) {
    for _ in 0..50 {
        let mut cluster = {
            let view = store.view();
            (*view.cluster().expect("cluster object")).clone()
        };
        cluster.spec.default_address_pool = pools.iter().map(|pool| (*pool).to_owned()).collect();
        cluster.spec.subnet_size = subnet_size;
        match store
            .propose(vec![StoreAction::Update(StoreObject::Cluster(cluster))])
            .await
        {
            Ok(_) => return,
            Err(satl_cluster::ProposeError::Rejected(_)) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(err) => panic!("failed to set the address pool: {err}"),
        }
    }
    panic!("never won the race to set the address pool");
}

fn overlay(name: &str) -> Network {
    planted_network(name, NetworkDriver::Overlay)
}

/// The allocated network, once the allocator has written it.
async fn allocated_network(cluster: &TestCluster, id: &Id) -> Network {
    cluster
        .wait_for("the network to be allocated", |view| {
            view.network(id)
                .filter(|network| network.subnet.is_some() && network.vni.is_some())
                .map(|network| (*network).clone())
        })
        .await
}

/// The task, once it has been allocated and voted into `PENDING`.
async fn allocated_task(cluster: &TestCluster, id: &Id) -> Task {
    cluster
        .wait_for("the task to be allocated", |view| {
            view.task(id)
                .filter(|task| task.status.state == TaskState::Pending)
                .map(|task| (*task).clone())
        })
        .await
}

/// A `NEW` task of `service`, as the replicated orchestrator would create it.
fn new_task(service: &Service, slot: u64) -> Task {
    planted_task(
        service,
        slot,
        TaskState::New,
        DesiredState::Running,
        std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(slot),
    )
}

// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_overlay_network_gets_a_subnet_and_a_vni() {
    let cluster = TestCluster::start().await;
    let network = overlay("backend");
    let id = network.id.clone();
    create(cluster.store(), StoreObject::Network(network)).await;

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);

    let allocated = allocated_network(&cluster, &id).await;
    assert_eq!(allocated.subnet.as_deref(), Some("10.100.0.0/24"));
    assert_eq!(allocated.vni, Some(4096));
    assert!(
        allocated.node_gateways.is_empty(),
        "nothing runs on it, so no node is owed a gateway address"
    );

    // And it is not rewritten on every pass.
    let version = allocated.meta.version;
    cluster
        .stays(
            Duration::from_millis(300),
            "an allocated network is left alone",
            |view| {
                view.network(&id)
                    .is_some_and(|network| network.meta.version == version)
            },
        )
        .await;

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bridge_network_is_left_to_the_node() {
    let cluster = TestCluster::start().await;
    let bridge = planted_network("satl0", NetworkDriver::Bridge);
    let id = bridge.id.clone();
    create(cluster.store(), StoreObject::Network(bridge)).await;

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);

    cluster
        .stays(
            Duration::from_millis(300),
            "a bridge network gets no cluster subnet or VNI",
            |view| {
                view.network(&id).is_some_and(|network| {
                    network.subnet.is_none()
                        && network.vni.is_none()
                        && network.node_gateways.is_empty()
                })
            },
        )
        .await;

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn two_networks_never_collide() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);

    let mut ids = Vec::new();
    for name in ["a", "b", "c"] {
        let network = overlay(name);
        ids.push(network.id.clone());
        create(cluster.store(), StoreObject::Network(network)).await;
        // Created one at a time, so each allocation sees the previous ones.
        allocated_network(&cluster, ids.last().expect("id")).await;
    }
    let allocated: Vec<Network> = {
        let view = cluster.store().view();
        ids.iter()
            .map(|id| (*view.network(id).expect("network")).clone())
            .collect()
    };
    let subnets: Vec<&str> = allocated
        .iter()
        .map(|network| network.subnet.as_deref().expect("subnet"))
        .collect();
    let vnis: Vec<u32> = allocated
        .iter()
        .map(|network| network.vni.expect("vni"))
        .collect();
    assert_eq!(
        subnets,
        vec!["10.100.0.0/24", "10.100.1.0/24", "10.100.2.0/24"]
    );
    assert_eq!(vnis, vec![4096, 4097, 4098]);

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tasks_on_a_network_get_distinct_addresses() {
    let cluster = TestCluster::start().await;
    let network = overlay("backend");
    let network_id = network.id.clone();
    let service = with_networks(sample_service("web", 3), &["backend"]);
    create(cluster.store(), StoreObject::Network(network)).await;
    create(cluster.store(), StoreObject::Service(service.clone())).await;
    let mut task_ids = Vec::new();
    for slot in 1..=3 {
        let task = new_task(&service, slot);
        task_ids.push(task.id.clone());
        create(cluster.store(), StoreObject::Task(task)).await;
    }

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);

    let mut addresses = Vec::new();
    for id in &task_ids {
        let task = allocated_task(&cluster, id).await;
        assert_eq!(task.networks.len(), 1);
        assert_eq!(task.networks[0].network_id, network_id);
        assert_eq!(task.networks[0].addresses.len(), 1);
        assert_eq!(task.status.message, "pending task scheduling");
        addresses.push(task.networks[0].addresses[0].clone());
    }
    addresses.sort();
    assert_eq!(
        addresses,
        vec!["10.100.0.2/24", "10.100.0.3/24", "10.100.0.4/24"],
        "distinct, and the gateway .1 is not handed out"
    );

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

/// The ballot (SWK §9): a task is promoted only once the network allocator can
/// actually give it what it asks for.
#[tokio::test(flavor = "multi_thread")]
async fn the_ballot_gates_new_to_pending() {
    let cluster = TestCluster::start().await;
    let service = with_networks(sample_service("web", 1), &["late"]);
    let task = new_task(&service, 1);
    let task_id = task.id.clone();
    create(cluster.store(), StoreObject::Service(service)).await;
    create(cluster.store(), StoreObject::Task(task)).await;

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);

    // The network does not exist: the allocator cannot vote, so the task stays
    // NEW — unschedulable — instead of being promoted without an address.
    cluster
        .stays(
            Duration::from_millis(300),
            "a task whose network is missing is not promoted",
            |view| {
                view.task(&task_id)
                    .is_some_and(|task| task.status.state == TaskState::New)
            },
        )
        .await;

    // Creating the network unblocks it at once, without waiting for the retry
    // window.
    create(cluster.store(), StoreObject::Network(overlay("late"))).await;
    let allocated = allocated_task(&cluster, &task_id).await;
    assert_eq!(allocated.networks[0].addresses, vec!["10.100.0.2/24"]);

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_terminal_task_releases_its_address() {
    let cluster = TestCluster::start().await;
    let network = overlay("backend");
    // Restart condition `none` so nothing else reacts to the failure.
    let service = with_restart(
        with_networks(sample_service("web", 1), &["backend"]),
        RestartCondition::None,
        Duration::ZERO,
        0,
    );
    let task = new_task(&service, 1);
    let task_id = task.id.clone();
    create(cluster.store(), StoreObject::Network(network)).await;
    create(cluster.store(), StoreObject::Service(service.clone())).await;
    create(cluster.store(), StoreObject::Task(task)).await;

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);

    let allocated = allocated_task(&cluster, &task_id).await;
    let address = allocated.networks[0].addresses[0].clone();
    assert_eq!(address, "10.100.0.2/24");

    // The agent reports it failed.
    set_task_state(cluster.store(), &task_id, TaskState::Failed).await;
    let released = cluster
        .wait_for("the address to be released", |view| {
            view.task(&task_id)
                .filter(|task| task.networks.iter().all(|a| a.addresses.is_empty()))
                .map(|task| (*task).clone())
        })
        .await;
    assert_eq!(
        released.networks.len(),
        1,
        "the attachment shell is kept as a record of what it was on"
    );

    // And the freed address is handed to the next task.
    let replacement = new_task(&service, 2);
    let replacement_id = replacement.id.clone();
    create(cluster.store(), StoreObject::Task(replacement)).await;
    let allocated = allocated_task(&cluster, &replacement_id).await;
    assert_eq!(
        allocated.networks[0].addresses,
        vec![address],
        "the released address is reused"
    );

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

/// A deleted network gives its subnet *and* its VNI back — and, because a
/// deallocation retries deferred allocations immediately (SWK §9.3), a network
/// that had failed for want of space gets them without waiting for the retry
/// window (an hour, in these tests).
#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_network_frees_its_subnet_and_vni_for_the_next_one() {
    let cluster = TestCluster::start().await;
    // A /24 pool carved at /24: room for exactly one network.
    set_pool(cluster.store(), &["10.99.0.0/24"], 24).await;
    let first = overlay("first");
    let first_id = first.id.clone();
    create(cluster.store(), StoreObject::Network(first)).await;

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);

    let allocated = allocated_network(&cluster, &first_id).await;
    assert_eq!(allocated.subnet.as_deref(), Some("10.99.0.0/24"));
    assert_eq!(allocated.vni, Some(4096));

    // The second network cannot be allocated: the pool is full.
    let second = overlay("second");
    let second_id = second.id.clone();
    create(cluster.store(), StoreObject::Network(second)).await;
    cluster
        .stays(
            Duration::from_millis(300),
            "the second network waits for space",
            |view| {
                view.network(&second_id)
                    .is_some_and(|network| network.subnet.is_none())
            },
        )
        .await;

    // Deleting the first frees both, and the deferred allocation is retried at
    // once.
    remove(cluster.store(), ObjectKind::Network, &first_id).await;
    let allocated = allocated_network(&cluster, &second_id).await;
    assert_eq!(
        allocated.subnet.as_deref(),
        Some("10.99.0.0/24"),
        "the freed subnet is handed out again"
    );
    assert_eq!(allocated.vni, Some(4096), "and so is the freed VNI");

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

/// The two-phase restore (SWK §9.2), as a leadership change: an allocator is
/// stopped — exactly what happens to a leader-only component on leadership loss
/// — and a fresh one is started against the same store. It must reconstruct
/// every allocation the store records *before* handing out anything new.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_leader_restores_before_it_allocates() {
    let cluster = TestCluster::start().await;
    let store = cluster.store();

    // What the old leader allocated before losing leadership.
    let network_ids = seed_an_allocated_cluster(&cluster).await;
    let before = subnets_and_vnis(store, &network_ids);
    let held_addresses = held_addresses(store);
    let published = published_ports(store);
    // 2 tasks x 2 attachments: network "a" and the ingress network each task
    // is auto-attached to (the service publishes an ingress port, M6d).
    assert_eq!(held_addresses.len(), 4, "{held_addresses:?}");
    assert_eq!(published, vec![30000]);

    // The new leader starts with fresh, empty in-memory state — and work
    // waiting for it: another network, another service, more tasks.
    let shutdown = CancellationToken::new();
    let allocator = spawn(store, &shutdown);

    let fresh_network = overlay("c");
    let fresh_network_id = fresh_network.id.clone();
    create(store, StoreObject::Network(fresh_network)).await;
    let fresh_service = with_published_port(
        with_networks(sample_service("api", 1), &["a"]),
        "http",
        80,
        0,
    );
    let fresh_service_id = fresh_service.id.clone();
    create(store, StoreObject::Service(fresh_service.clone())).await;
    let fresh_task = new_task(&fresh_service, 1);
    let fresh_task_id = fresh_task.id.clone();
    create(store, StoreObject::Task(fresh_task)).await;

    let allocated = allocated_network(&cluster, &fresh_network_id).await;
    let allocated_task = allocated_task(&cluster, &fresh_task_id).await;
    let allocated_service = cluster
        .wait_for("the new service's port", |view| {
            view.service(&fresh_service_id)
                .and_then(|service| service.endpoint.clone())
                .filter(|endpoint| endpoint.ports.iter().all(|port| port.published_port != 0))
                .map(|endpoint| endpoint.ports[0].published_port)
        })
        .await;

    // Nothing the store already recorded was handed out a second time.
    assert!(
        !before
            .iter()
            .any(|(subnet, _)| Some(subnet.as_str()) == allocated.subnet.as_deref()),
        "the new network reused a live subnet: {:?} vs {before:?}",
        allocated.subnet
    );
    assert!(
        !before.iter().any(|(_, vni)| Some(*vni) == allocated.vni),
        "the new network reused a live VNI: {:?} vs {before:?}",
        allocated.vni
    );
    // The service publishing an ingress port created the ingress network on
    // the way (M6d), which holds 10.100.2.0/24 and VNI 4098.
    assert_eq!(allocated.subnet.as_deref(), Some("10.100.3.0/24"));
    assert_eq!(allocated.vni, Some(4099));
    let fresh_address = allocated_task.networks[0].addresses[0].clone();
    assert!(
        !held_addresses.contains(&fresh_address),
        "the new task was given a live address: {fresh_address} vs {held_addresses:?}"
    );
    assert_eq!(fresh_address, "10.100.0.4/24", "the first free address");
    assert!(
        !published.contains(&allocated_service),
        "the new service was given a live published port: {allocated_service}"
    );
    assert_eq!(allocated_service, 30001);

    // And the restore did not rewrite the objects it restored.
    assert_eq!(
        subnets_and_vnis(store, &network_ids),
        before,
        "restored networks are left untouched"
    );

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

/// Runs an allocator over two overlay networks, a service with a published port
/// and two tasks, then stops it — the state a new leader inherits. Returns the
/// network IDs.
async fn seed_an_allocated_cluster(cluster: &TestCluster) -> Vec<Id> {
    let store = cluster.store();
    let shutdown = CancellationToken::new();
    let allocator = spawn(store, &shutdown);
    let mut ids = Vec::new();
    for name in ["a", "b"] {
        let network = overlay(name);
        ids.push(network.id.clone());
        create(store, StoreObject::Network(network)).await;
        allocated_network(cluster, ids.last().expect("id")).await;
    }
    let service = with_published_port(
        with_networks(sample_service("web", 2), &["a"]),
        "http",
        80,
        0,
    );
    create(store, StoreObject::Service(service.clone())).await;
    for slot in 1..=2 {
        let task = new_task(&service, slot);
        let id = task.id.clone();
        create(store, StoreObject::Task(task)).await;
        let allocated = allocated_task(cluster, &id).await;
        assert!(!allocated.networks[0].addresses.is_empty());
        // Pretend the agent got them running, so the new leader has no reason
        // to touch them.
        set_task_state(store, &id, TaskState::Running).await;
    }
    // Leadership loss: the leader-only loops stop.
    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    ids
}

/// The recorded subnet and VNI of each network, in the given order.
fn subnets_and_vnis(store: &ClusterStore, ids: &[Id]) -> Vec<(String, u32)> {
    let view = store.view();
    ids.iter()
        .map(|id| {
            let network = view.network(id).expect("network");
            (
                network.subnet.clone().expect("subnet"),
                network.vni.expect("vni"),
            )
        })
        .collect()
}

/// Every address any task in the store holds.
fn held_addresses(store: &ClusterStore) -> Vec<String> {
    let view = store.view();
    view.tasks()
        .iter()
        .flat_map(|task| task.networks.clone())
        .flat_map(|attachment| attachment.addresses)
        .collect()
}

/// Every published port any service in the store holds.
fn published_ports(store: &ClusterStore) -> Vec<u16> {
    let view = store.view();
    view.services()
        .iter()
        .filter_map(|service| service.endpoint.clone())
        .flat_map(|endpoint: Endpoint| endpoint.ports)
        .map(|port| port.published_port)
        .collect()
}

/// Sticky reallocation (SWK §9.5) through the store: a service update must not
/// move the port an operator already published.
#[tokio::test(flavor = "multi_thread")]
async fn a_service_update_keeps_its_published_port() {
    let cluster = TestCluster::start().await;
    let service = with_published_port(sample_service("web", 1), "http", 80, 0);
    let service_id = service.id.clone();
    create(cluster.store(), StoreObject::Service(service)).await;

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);

    let first = cluster
        .wait_for("the published port", |view| {
            view.service(&service_id)
                .and_then(|service| service.endpoint.clone())
                .filter(|endpoint| !endpoint.ports.is_empty())
                .map(|endpoint| endpoint.ports[0].published_port)
        })
        .await;
    assert_eq!(first, 30000);

    // The operator adds a second port.
    for _ in 0..50 {
        let updated = {
            let view = cluster.store().view();
            let service = (*view.service(&service_id).expect("service")).clone();
            with_published_port(service, "metrics", 9100, 0)
        };
        match cluster
            .store()
            .propose(vec![StoreAction::Update(StoreObject::Service(updated))])
            .await
        {
            Ok(_) => break,
            Err(satl_cluster::ProposeError::Rejected(_)) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(err) => panic!("failed to update the service: {err}"),
        }
    }

    let ports = cluster
        .wait_for("both ports allocated", |view| {
            view.service(&service_id)
                .and_then(|service| service.endpoint.clone())
                .filter(|endpoint| {
                    endpoint.ports.len() == 2
                        && endpoint.ports.iter().all(|port| port.published_port != 0)
                })
                .map(|endpoint| {
                    endpoint
                        .ports
                        .iter()
                        .map(|port| (port.name.clone(), port.published_port))
                        .collect::<Vec<_>>()
                })
        })
        .await;
    assert_eq!(
        ports,
        vec![("http".to_owned(), 30000), ("metrics".to_owned(), 30001)],
        "the http port did not move"
    );

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

/// A network whose requested subnet is unusable must not stall the rest of the
/// cluster, and must be retried the moment the operator fixes it.
#[tokio::test(flavor = "multi_thread")]
async fn a_broken_network_is_deferred_and_retried_when_it_is_fixed() {
    let cluster = TestCluster::start().await;
    let broken = with_ipam(overlay("broken"), Some("not-a-subnet"), None, None);
    let broken_id = broken.id.clone();
    create(cluster.store(), StoreObject::Network(broken)).await;

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);

    // A healthy network created afterwards is allocated regardless.
    let healthy = overlay("healthy");
    let healthy_id = healthy.id.clone();
    create(cluster.store(), StoreObject::Network(healthy)).await;
    allocated_network(&cluster, &healthy_id).await;
    {
        let view = cluster.store().view();
        assert!(
            view.network(&broken_id)
                .is_some_and(|network| network.subnet.is_none()),
            "the broken network is still unallocated"
        );
    }

    // Fixing the spec retries it immediately (its version moved).
    for _ in 0..50 {
        let fixed = {
            let view = cluster.store().view();
            let network = (*view.network(&broken_id).expect("network")).clone();
            with_ipam(network, Some("10.77.0.0/24"), None, None)
        };
        match cluster
            .store()
            .propose(vec![StoreAction::Update(StoreObject::Network(fixed))])
            .await
        {
            Ok(_) => break,
            Err(satl_cluster::ProposeError::Rejected(_)) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(err) => panic!("failed to fix the network: {err}"),
        }
    }
    let allocated = allocated_network(&cluster, &broken_id).await;
    assert_eq!(allocated.subnet.as_deref(), Some("10.77.0.0/24"));

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

/// A task whose status the agent is rewriting while the allocator works: the
/// proposal loses the optimistic-concurrency race, re-reads, and the task is
/// still allocated exactly once (architecture §6.4, SWK §9.3's targeted merge).
#[tokio::test(flavor = "multi_thread")]
async fn a_competing_writer_does_not_stall_allocation() {
    let cluster = TestCluster::start().await;
    let network = overlay("backend");
    let service = with_networks(sample_service("web", 1), &["backend"]);
    create(cluster.store(), StoreObject::Network(network)).await;
    create(cluster.store(), StoreObject::Service(service.clone())).await;
    let mut ids = Vec::new();
    for slot in 1..=4 {
        let task = new_task(&service, slot);
        ids.push(task.id.clone());
        create(cluster.store(), StoreObject::Task(task)).await;
    }

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);

    // Rewrite the tasks' labels from another writer, the way a spec edit or a
    // status report would.
    let store = cluster.store().clone();
    let racing = ids.clone();
    let racer = tokio::spawn(async move {
        for round in 0..40_u32 {
            for id in &racing {
                let task = {
                    let view = store.view();
                    view.task(id).map(|task| (*task).clone())
                };
                let Some(mut task) = task else { continue };
                if task.status.state != TaskState::New {
                    continue;
                }
                task.annotations
                    .labels
                    .insert("round".to_owned(), round.to_string());
                // Rejections are the point of the exercise.
                let _ = store
                    .propose(vec![StoreAction::Update(StoreObject::Task(task))])
                    .await;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });

    let mut addresses = Vec::new();
    for id in &ids {
        let task = allocated_task(&cluster, id).await;
        addresses.push(task.networks[0].addresses[0].clone());
    }
    racer.await.expect("racing writer finished");
    addresses.sort();
    addresses.dedup();
    assert_eq!(addresses.len(), 4, "no address was handed out twice");

    // The competing writer's labels survived where they were written last.
    let view = cluster.store().view();
    for id in &ids {
        let task = view.task(id).expect("task");
        assert_eq!(task.status.state, TaskState::Pending);
        assert_eq!(task.networks[0].addresses.len(), 1);
    }
    drop(view);

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

/// Restarting the allocator over a store whose tasks already hold addresses
/// must not renumber them: the restore phase claims them, and a task past `NEW`
/// is never rewritten.
#[tokio::test(flavor = "multi_thread")]
async fn restarting_the_allocator_never_renumbers_a_running_task() {
    let cluster = TestCluster::start().await;
    let network = overlay("backend");
    let service = with_networks(sample_service("web", 2), &["backend"]);
    create(cluster.store(), StoreObject::Network(network)).await;
    create(cluster.store(), StoreObject::Service(service.clone())).await;
    let mut ids = Vec::new();
    for slot in 1..=2 {
        let task = new_task(&service, slot);
        ids.push(task.id.clone());
        create(cluster.store(), StoreObject::Task(task)).await;
    }

    // The first leader allocates them; the agent then reports them running.
    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);
    let mut before = Vec::new();
    for id in &ids {
        let task = allocated_task(&cluster, id).await;
        before.push(task.networks[0].addresses[0].clone());
    }
    for id in &ids {
        set_task_state(cluster.store(), id, TaskState::Running).await;
    }
    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    assert_eq!(before, vec!["10.100.0.2/24", "10.100.0.3/24"]);

    // Two more leadership changes: each new allocator restores what the store
    // records and leaves the running tasks exactly as they are.
    let expected = before.clone();
    for round in 0..2 {
        let shutdown = CancellationToken::new();
        let allocator = spawn(cluster.store(), &shutdown);
        let ids = ids.clone();
        let expected = expected.clone();
        cluster
            .stays(
                Duration::from_millis(300),
                "a restart renumbered a running task",
                move |view| {
                    ids.iter().enumerate().all(|(index, id)| {
                        view.task(id).is_some_and(|task| {
                            task.networks.len() == 1
                                && task.networks[0].addresses == vec![expected[index].clone()]
                        })
                    })
                },
            )
            .await;
        shutdown.cancel();
        allocator
            .await
            .unwrap_or_else(|err| panic!("allocator {round} stopped: {err}"));
    }

    // A status write must not have lost the allocated attachments either.
    let view = cluster.store().view();
    for id in &ids {
        let task: Task = (*view.task(id).expect("task")).clone();
        assert_eq!(task.status.state, TaskState::Running);
        assert_eq!(task.networks.len(), 1);
    }
    drop(view);

    cluster.shutdown().await;
}

// ---------------------------------------------------------------------------
// Per-node gateway addresses (SWK §9.1, docs/vxlan.md §8)
// ---------------------------------------------------------------------------

/// Binds a task to a node and reports it running — the scheduler's write plus
/// the agent's, which is what makes the node a participant in the network.
async fn schedule(store: &ClusterStore, task_id: &Id, node_id: &Id) {
    for _ in 0..50 {
        let current = {
            let view = store.view();
            view.task(task_id).map(|task| (*task).clone())
        };
        let mut task = current.unwrap_or_else(|| panic!("task {task_id} is gone"));
        task.node_id = Some(node_id.clone());
        task.status = TaskStatus::new(TaskState::Running, "reported by the test agent");
        match store
            .propose(vec![StoreAction::Update(StoreObject::Task(task))])
            .await
        {
            Ok(_) => return,
            Err(satl_cluster::ProposeError::Rejected(_)) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(err) => panic!("failed to schedule task {task_id}: {err}"),
        }
    }
    panic!("never won the race to schedule task {task_id}");
}

/// The network's per-node gateways, once there are `count` of them.
async fn node_gateways(cluster: &TestCluster, id: &Id, count: usize) -> BTreeMap<Id, String> {
    cluster
        .wait_for("the node gateways to be allocated", |view| {
            view.network(id)
                .map(|network| network.node_gateways.clone())
                .filter(|gateways| gateways.len() == count)
        })
        .await
}

/// Two nodes running tasks on one overlay get **one address each** from its
/// subnet, never `.1` and never a task's — the duplicate address measured in
/// `docs/vxlan.md` §8 is what this prevents.
#[tokio::test(flavor = "multi_thread")]
async fn each_node_running_a_task_gets_a_gateway_address_of_its_own() {
    let cluster = TestCluster::start().await;
    let network = overlay("backend");
    let network_id = network.id.clone();
    let service = with_networks(sample_service("web", 2), &["backend"]);
    create(cluster.store(), StoreObject::Network(network)).await;
    create(cluster.store(), StoreObject::Service(service.clone())).await;
    let mut task_ids = Vec::new();
    for slot in 1..=2 {
        let task = new_task(&service, slot);
        task_ids.push(task.id.clone());
        create(cluster.store(), StoreObject::Task(task)).await;
    }

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);

    let mut addresses = Vec::new();
    for id in &task_ids {
        addresses.push(allocated_task(&cluster, id).await.networks[0].addresses[0].clone());
    }
    {
        // No task has been scheduled yet, so no node is owed anything.
        let view = cluster.store().view();
        assert!(
            view.network(&network_id)
                .is_some_and(|network| network.node_gateways.is_empty())
        );
    }

    // The scheduler's job, by hand: one task per node.
    let left = cluster.node_id().clone();
    let right = Id::generate();
    schedule(cluster.store(), &task_ids[0], &left).await;
    schedule(cluster.store(), &task_ids[1], &right).await;

    let gateways = node_gateways(&cluster, &network_id, 2).await;
    let distinct: BTreeSet<&String> = gateways.values().collect();
    assert_eq!(distinct.len(), 2, "one address for two nodes: {gateways:?}");
    for (node, gateway) in &gateways {
        assert!(
            *node == left || *node == right,
            "an unexpected node: {gateways:?}"
        );
        assert!(gateway.starts_with("10.100.0."), "{gateway}");
        assert_ne!(gateway, "10.100.0.1", "`.1` is reserved for nobody");
        assert!(
            !addresses.contains(&format!("{gateway}/24")),
            "{gateway} is also a task's address: {addresses:?}"
        );
    }

    // And they are not rewritten on every pass.
    let version = {
        let view = cluster.store().view();
        view.network(&network_id).expect("network").meta.version
    };
    let expected = gateways.clone();
    cluster
        .stays(
            Duration::from_millis(300),
            "the node gateways are rewritten on every pass",
            move |view| {
                view.network(&network_id).is_some_and(|network| {
                    network.meta.version == version && network.node_gateways == expected
                })
            },
        )
        .await;

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

/// A node that runs no more tasks on a network gives its gateway address back,
/// and it is handed to the next node — the release half of on-demand allocation.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_with_no_tasks_left_gives_its_gateway_address_back() {
    let cluster = TestCluster::start().await;
    let network = overlay("backend");
    let network_id = network.id.clone();
    // Restart condition `none` so nothing replaces the task we terminate.
    let service = with_restart(
        with_networks(sample_service("web", 1), &["backend"]),
        RestartCondition::None,
        Duration::ZERO,
        0,
    );
    let task = new_task(&service, 1);
    let task_id = task.id.clone();
    create(cluster.store(), StoreObject::Network(network)).await;
    create(cluster.store(), StoreObject::Service(service.clone())).await;
    create(cluster.store(), StoreObject::Task(task)).await;

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);

    allocated_task(&cluster, &task_id).await;
    let node = Id::generate();
    schedule(cluster.store(), &task_id, &node).await;
    let gateway = node_gateways(&cluster, &network_id, 1).await;
    let address = gateway.get(&node).expect("the node's gateway").clone();

    // The agent reports the task failed: the node runs nothing on the network.
    set_task_state(cluster.store(), &task_id, TaskState::Failed).await;
    cluster
        .wait_for("the node gateway to be released", |view| {
            view.network(&network_id)
                .filter(|network| network.node_gateways.is_empty())
                .map(|_| ())
        })
        .await;

    // A task on another node then gets the freed address.
    let replacement = new_task(&service, 2);
    let replacement_id = replacement.id.clone();
    create(cluster.store(), StoreObject::Task(replacement)).await;
    allocated_task(&cluster, &replacement_id).await;
    let other = Id::generate();
    schedule(cluster.store(), &replacement_id, &other).await;
    let gateways = node_gateways(&cluster, &network_id, 1).await;
    assert_eq!(
        gateways.get(&other).map(String::as_str),
        Some(address.as_str()),
        "the released address is reusable: {gateways:?}"
    );

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}

/// Restarting the allocator — what a leadership change does — must not move a
/// node's gateway address: it is live on that node's bridge, and moving it under
/// running jails is a silent black hole (`docs/vxlan.md` §8).
#[tokio::test(flavor = "multi_thread")]
async fn restarting_the_allocator_never_moves_a_node_gateway() {
    let cluster = TestCluster::start().await;
    let network = overlay("backend");
    let network_id = network.id.clone();
    let service = with_networks(sample_service("web", 2), &["backend"]);
    create(cluster.store(), StoreObject::Network(network)).await;
    create(cluster.store(), StoreObject::Service(service.clone())).await;
    let mut task_ids = Vec::new();
    for slot in 1..=2 {
        let task = new_task(&service, slot);
        task_ids.push(task.id.clone());
        create(cluster.store(), StoreObject::Task(task)).await;
    }

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);
    for id in &task_ids {
        allocated_task(&cluster, id).await;
    }
    let nodes = [cluster.node_id().clone(), Id::generate()];
    for (id, node) in task_ids.iter().zip(&nodes) {
        schedule(cluster.store(), id, node).await;
    }
    let before = node_gateways(&cluster, &network_id, 2).await;
    shutdown.cancel();
    allocator.await.expect("allocator stopped");

    // Two more leadership changes: each new allocator restores what the store
    // records and leaves every node's gateway exactly where it is.
    for round in 0..2 {
        let shutdown = CancellationToken::new();
        let allocator = spawn(cluster.store(), &shutdown);
        let expected = before.clone();
        let id = network_id.clone();
        cluster
            .stays(
                Duration::from_millis(300),
                "a restart moved a node gateway",
                move |view| {
                    view.network(&id)
                        .is_some_and(|network| network.node_gateways == expected)
                },
            )
            .await;
        shutdown.cancel();
        allocator
            .await
            .unwrap_or_else(|err| panic!("allocator {round} stopped: {err}"));
    }

    cluster.shutdown().await;
}

/// The status the allocator writes is the one the scheduler waits for; nothing
/// else about the task is touched.
#[tokio::test(flavor = "multi_thread")]
async fn allocation_only_writes_the_allocated_fields() {
    let cluster = TestCluster::start().await;
    let network = overlay("backend");
    let service = with_networks(sample_service("web", 1), &["backend"]);
    let mut task = new_task(&service, 1);
    task.annotations
        .labels
        .insert("kept".to_owned(), "yes".to_owned());
    task.status = TaskStatus::new(TaskState::New, "created");
    let task_id = task.id.clone();
    let spec = task.spec.clone();
    create(cluster.store(), StoreObject::Network(network)).await;
    create(cluster.store(), StoreObject::Service(service)).await;
    create(cluster.store(), StoreObject::Task(task)).await;

    let shutdown = CancellationToken::new();
    let allocator = spawn(cluster.store(), &shutdown);
    let allocated = allocated_task(&cluster, &task_id).await;

    assert_eq!(allocated.spec, spec, "the spec snapshot is untouched");
    assert_eq!(
        allocated.annotations.labels.get("kept").map(String::as_str),
        Some("yes")
    );
    assert_eq!(allocated.desired_state, DesiredState::Running);
    assert!(allocated.node_id.is_none(), "the scheduler binds nodes");

    shutdown.cancel();
    allocator.await.expect("allocator stopped");
    cluster.shutdown().await;
}
