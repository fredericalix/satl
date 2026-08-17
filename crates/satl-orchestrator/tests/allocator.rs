// SPDX-License-Identifier: BSD-2-Clause
//! The allocator wired next to the other loops, against a real single-node
//! store — the shape `satld` runs (architecture §5).
//!
//! The allocator's own behaviour is covered exhaustively in the crate's unit
//! tests (pure planner) and its store-backed tests (the loop alone). What is
//! under test here is the pipeline: a service on an overlay network turns into
//! tasks that carry an address and are schedulable, and deleting the service
//! gives the addresses back.

use std::collections::BTreeSet;
use std::time::Duration;

use satl_core::{
    Id, Network, NetworkDriver, ObjectKind, StoreAction, StoreObject, TaskState, TaskStatus,
};
use satl_orchestrator::{Cadence, Orchestrator, OrchestratorConfig};
use satl_sched::{Scheduler, SchedulerConfig};
use tokio_util::sync::CancellationToken;

#[path = "../src/testing.rs"]
mod testing;

use testing::{TestCluster, planted_network, sample_service, with_networks, with_published_port};

/// Short windows so the tests are quick; the shape is unchanged.
fn fast() -> OrchestratorConfig {
    OrchestratorConfig {
        reconcile_interval: Duration::from_millis(100),
        reaper_batch: Duration::from_millis(20),
        reaper_force_at: 1000,
        // Long enough that every retry these tests see comes from a
        // deallocation or an object edit, not from the timer.
        allocator_retry: Duration::from_hours(1),
        keyring_cadence: Cadence::default(),
    }
}

fn fast_scheduler() -> SchedulerConfig {
    SchedulerConfig {
        debounce: Duration::from_millis(10),
        max_debounce: Duration::from_millis(100),
    }
}

async fn create(store: &satl_cluster::ClusterStore, object: StoreObject) {
    store
        .propose(vec![StoreAction::Create(object)])
        .await
        .expect("object created");
}

fn overlay(name: &str) -> Network {
    planted_network(name, NetworkDriver::Overlay)
}

/// Service create → tasks → addresses → `PENDING` → scheduled: the M3 control
/// plane end to end (architecture §5 steps 2–4, SWK §9.4).
#[tokio::test(flavor = "multi_thread")]
async fn a_service_on_an_overlay_network_gets_addressed_and_scheduled() {
    let cluster = TestCluster::start().await;
    let network = overlay("backend");
    let network_id = network.id.clone();
    create(cluster.store(), StoreObject::Network(network)).await;
    let service = with_published_port(
        with_networks(sample_service("web", 3), &["backend"]),
        "http",
        80,
        0,
    );
    let service_id = service.id.clone();
    create(cluster.store(), StoreObject::Service(service)).await;

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());
    let scheduler =
        Scheduler::spawn_with_config(cluster.store().clone(), fast_scheduler(), shutdown.clone());

    // The network is allocated a subnet and a VNI.
    let allocated = cluster
        .wait_for("the network to be allocated", |view| {
            view.network(&network_id)
                .filter(|network| network.subnet.is_some() && network.vni.is_some())
                .map(|network| (*network).clone())
        })
        .await;
    assert_eq!(allocated.subnet.as_deref(), Some("10.100.0.0/24"));
    assert_eq!(allocated.vni, Some(4096));

    // Every task ends up bound to the node with an address of its own.
    cluster
        .wait_for("all three tasks assigned", |view| {
            let tasks: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|task| task.service_id.as_ref() == Some(&service_id))
                .collect();
            let done = tasks.len() == 3
                && tasks
                    .iter()
                    .all(|task| task.status.state == TaskState::Assigned);
            done.then_some(())
        })
        .await;

    let tasks = cluster.tasks_of(&service_id);
    let addresses: BTreeSet<String> = tasks
        .iter()
        .map(|task| {
            // M6d: the service publishes an ingress port, so each task is
            // also attached to the ingress network. The address asserted here
            // is the one on the backend network.
            let attachment = task
                .networks
                .iter()
                .find(|attachment| attachment.network_id == network_id)
                .expect("an attachment to the backend network");
            assert_eq!(task.node_id.as_ref(), Some(cluster.node_id()));
            attachment.addresses[0].clone()
        })
        .collect();
    assert_eq!(addresses.len(), 3, "one address each: {addresses:?}");
    assert!(
        addresses
            .iter()
            .all(|address| address.starts_with("10.100.0.") && address.ends_with("/24")),
        "{addresses:?}"
    );

    // And the node the tasks landed on has a gateway address of its own on the
    // network — one per (node, network), never the shared `.1` (docs/vxlan.md
    // §8).
    let gateway = cluster
        .wait_for("the node's gateway address on the network", |view| {
            view.network(&network_id)
                .and_then(|network| network.node_gateways.get(cluster.node_id()).cloned())
        })
        .await;
    assert!(
        gateway.starts_with("10.100.0.") && !gateway.ends_with(".1"),
        "{gateway} must come from the subnet and never be the reserved .1"
    );
    assert!(
        !addresses.contains(&format!("{gateway}/24")),
        "the gateway {gateway} collides with a task address: {addresses:?}"
    );
    {
        let view = cluster.store().view();
        let network = view.network(&network_id).expect("network");
        assert_eq!(network.node_gateways.len(), 1, "one node, one gateway");
    }

    // And each task carries the service's allocated published port.
    for task in &tasks {
        let endpoint = task
            .endpoint
            .as_ref()
            .expect("endpoint copied onto the task");
        assert_eq!(endpoint.ports.len(), 1);
        assert_eq!(endpoint.ports[0].published_port, 30000);
        assert_eq!(endpoint.ports[0].target_port, 80);
    }

    shutdown.cancel();
    scheduler.join().await;
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// Deleting the service releases its tasks' addresses — via the reaper, which
/// deletes the task objects — so the space is available again.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_service_frees_its_addresses_for_the_next_one() {
    let cluster = TestCluster::start().await;
    create(cluster.store(), StoreObject::Network(overlay("backend"))).await;
    let first = with_networks(sample_service("web", 2), &["backend"]);
    let first_id = first.id.clone();
    create(cluster.store(), StoreObject::Service(first)).await;

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let taken = wait_for_addresses(&cluster, &first_id, 2).await;
    assert_eq!(
        taken,
        BTreeSet::from(["10.100.0.2/24".to_owned(), "10.100.0.3/24".to_owned()])
    );

    // The tasks never ran, so the reaper deletes them outright once the
    // replicated orchestrator marks them for removal.
    cluster
        .store()
        .propose(vec![StoreAction::Remove {
            kind: ObjectKind::Service,
            id: first_id.clone(),
        }])
        .await
        .expect("service deleted");
    cluster
        .wait_for("the tasks to be reaped", |view| {
            let gone = !view
                .tasks()
                .iter()
                .any(|task| task.service_id.as_ref() == Some(&first_id));
            gone.then_some(())
        })
        .await;

    // A new service gets the freed addresses.
    let second = with_networks(sample_service("api", 2), &["backend"]);
    let second_id = second.id.clone();
    create(cluster.store(), StoreObject::Service(second)).await;
    let reused = wait_for_addresses(&cluster, &second_id, 2).await;
    assert_eq!(reused, taken, "the freed addresses are handed out again");

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// A task that fails gets its address back, and the restart supervisor's
/// replacement is allocated one of its own.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_task_hands_its_address_to_its_replacement() {
    let cluster = TestCluster::start().await;
    create(cluster.store(), StoreObject::Network(overlay("backend"))).await;
    let service = with_networks(sample_service("web", 1), &["backend"]);
    let service_id = service.id.clone();
    create(cluster.store(), StoreObject::Service(service)).await;

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let first = wait_for_addresses(&cluster, &service_id, 1).await;
    let original = cluster.tasks_of(&service_id)[0].clone();

    // Run it, then fail it, the way the agent would.
    let node = cluster.node_id().clone();
    for _ in 0..50 {
        let mut task = {
            let view = cluster.store().view();
            (*view.task(&original.id).expect("task")).clone()
        };
        task.node_id = Some(node.clone());
        task.status = TaskStatus::new(TaskState::Failed, "exited 1 (reported by the test agent)");
        match cluster
            .store()
            .propose(vec![StoreAction::Update(StoreObject::Task(task))])
            .await
        {
            Ok(_) => break,
            Err(satl_cluster::ProposeError::Rejected(_)) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(err) => panic!("failed to fail the task: {err}"),
        }
    }

    // Its address is released…
    cluster
        .wait_for("the failed task's address to be released", |view| {
            view.task(&original.id)
                .filter(|task| task.networks.iter().all(|a| a.addresses.is_empty()))
                .map(|_| ())
        })
        .await;
    // …and the replacement the restart supervisor creates is allocated one.
    let replacement: Id = cluster
        .wait_for("the replacement task", |view| {
            view.tasks()
                .into_iter()
                .find(|task| {
                    task.service_id.as_ref() == Some(&service_id)
                        && task.id != original.id
                        && !task.networks.is_empty()
                        && !task.networks[0].addresses.is_empty()
                })
                .map(|task| task.id.clone())
        })
        .await;
    let address = {
        let view = cluster.store().view();
        view.task(&replacement).expect("task").networks[0].addresses[0].clone()
    };
    assert_eq!(
        BTreeSet::from([address]),
        first,
        "the replacement reuses the freed address"
    );

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// The addresses of a service's tasks, once `count` of them carry one.
async fn wait_for_addresses(
    cluster: &TestCluster,
    service_id: &Id,
    count: usize,
) -> BTreeSet<String> {
    cluster
        .wait_for("the tasks to be addressed", |view| {
            let addresses: BTreeSet<String> = view
                .tasks()
                .iter()
                .filter(|task| task.service_id.as_ref() == Some(service_id))
                .flat_map(|task| task.networks.clone())
                .flat_map(|attachment| attachment.addresses)
                .collect();
            (addresses.len() == count).then_some(addresses)
        })
        .await
}
