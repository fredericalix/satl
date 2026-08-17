// SPDX-License-Identifier: BSD-2-Clause
//! Scheduler scenarios against a real single-node store (SWK §8).
//!
//! The store is `satl-cluster`'s in-process single-node Raft harness (a real
//! FSM in a temp dir, ~20 ms to start), so these exercise the actual watch
//! feed, the actual optimistic concurrency and the actual proposal path.
//!
//! Multi-node scenarios are *synthetic*: extra `Node` objects are written
//! into that one store by hand. The scheduler only ever reads node objects,
//! so a three-node cluster and three node objects are the same thing to it —
//! and the alternative (three real Raft members) belongs in
//! `make cluster-test`, not in `make check`.

use std::collections::BTreeMap;
use std::time::Duration;

use satl_cluster::ClusterStore;
use satl_core::{
    Availability, DesiredState, Id, Node, Service, StoreAction, StoreObject, Task, TaskState,
    TaskStatus,
};
use satl_sched::{Scheduler, SchedulerConfig};
use tokio_util::sync::CancellationToken;

#[path = "../src/testing.rs"]
mod testing;

use testing::{NodeBuilder, TestCluster, gib, planted_task, reserve, sample_service};

/// Short windows so the tests are quick; the shape is unchanged.
fn fast() -> SchedulerConfig {
    SchedulerConfig {
        debounce: Duration::from_millis(10),
        max_debounce: Duration::from_millis(100),
    }
}

/// Creates a service with one `PENDING`, unbound task and returns both IDs.
async fn seed_pending_task(store: &ClusterStore) -> (Id, Id) {
    let service = sample_service("web", 1);
    let task = planted_task(
        &service,
        1,
        TaskState::Pending,
        DesiredState::Running,
        std::time::SystemTime::now(),
    );
    let ids = (service.id.clone(), task.id.clone());
    store
        .propose(vec![
            StoreAction::Create(StoreObject::Service(service)),
            StoreAction::Create(StoreObject::Task(task)),
        ])
        .await
        .expect("seed committed");
    ids
}

/// Sets the seeded node's availability, returning once committed.
async fn set_availability(cluster: &TestCluster, availability: Availability) {
    set_node_availability(cluster.store(), cluster.node_id(), availability).await;
}

/// Sets any node's availability, returning once committed.
async fn set_node_availability(store: &ClusterStore, node_id: &Id, availability: Availability) {
    let mut node = {
        let view = store.view();
        (*view.node(node_id).expect("node exists")).clone()
    };
    node.spec.availability = availability;
    store
        .propose(vec![StoreAction::Update(StoreObject::Node(node))])
        .await
        .expect("node update committed");
}

/// Moves a task's desired state, retrying while the scheduler writes to the
/// same object underneath (optimistic concurrency, architecture §3).
async fn set_desired_state(store: &ClusterStore, task_id: &Id, desired: DesiredState) {
    for _ in 0..100 {
        let mut task = {
            let view = store.view();
            (*view.task(task_id).expect("task exists")).clone()
        };
        task.desired_state = desired;
        if store
            .propose(vec![StoreAction::Update(StoreObject::Task(task))])
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("could not set the desired state of {task_id}");
}

/// Writes synthetic node objects into the store and returns their IDs, in
/// the order given.
async fn plant_nodes(store: &ClusterStore, nodes: Vec<Node>) -> Vec<Id> {
    let ids: Vec<Id> = nodes.iter().map(|node| node.id.clone()).collect();
    let actions = nodes
        .into_iter()
        .map(|node| StoreAction::Create(StoreObject::Node(node)))
        .collect();
    store.propose(actions).await.expect("nodes committed");
    ids
}

/// Creates a service and `replicas` unbound `PENDING` tasks for it, all of
/// the same spec version so the scheduler treats them as one group.
async fn seed_service(store: &ClusterStore, service: Service, replicas: u64) -> (Id, Vec<Id>) {
    let mut actions = vec![StoreAction::Create(StoreObject::Service(service.clone()))];
    let mut task_ids = Vec::new();
    for slot in 1..=replicas {
        let task = planted_task(
            &service,
            slot,
            TaskState::Pending,
            DesiredState::Running,
            std::time::SystemTime::now(),
        );
        task_ids.push(task.id.clone());
        actions.push(StoreAction::Create(StoreObject::Task(task)));
    }
    store.propose(actions).await.expect("service committed");
    (service.id, task_ids)
}

/// Waits until every task in `task_ids` reached `ASSIGNED`, then returns how
/// many of them landed on each node.
async fn wait_for_placement(cluster: &TestCluster, task_ids: &[Id]) -> BTreeMap<Id, usize> {
    cluster
        .wait_for("every task to be assigned", |view| {
            let mut per_node: BTreeMap<Id, usize> = BTreeMap::new();
            for id in task_ids {
                let task = view.task(id)?;
                if task.status.state != TaskState::Assigned {
                    return None;
                }
                *per_node.entry(task.node_id.clone()?).or_default() += 1;
            }
            Some(per_node)
        })
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_task_is_assigned_to_the_ready_node() {
    let cluster = TestCluster::start().await;
    let (_service_id, task_id) = seed_pending_task(cluster.store()).await;

    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let task: Task = cluster
        .wait_for("the task to be assigned", |view| {
            view.task(&task_id)
                .filter(|t| t.status.state == TaskState::Assigned)
                .map(|t| (*t).clone())
        })
        .await;

    assert_eq!(task.node_id.as_ref(), Some(cluster.node_id()));
    assert_eq!(task.status.message, "scheduler assigned task to node");
    assert!(task.status.err.is_none());
    assert_eq!(
        task.desired_state,
        DesiredState::Running,
        "the scheduler never touches desired state"
    );

    shutdown.cancel();
    scheduler.join().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unschedulable_task_records_the_reason_and_is_retried() {
    let cluster = TestCluster::start().await;
    // Drain the only node before the task exists: nothing can be placed.
    set_availability(&cluster, Availability::Drain).await;
    let (_service_id, task_id) = seed_pending_task(cluster.store()).await;

    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let err: String = cluster
        .wait_for("the unschedulable reason", |view| {
            view.task(&task_id).and_then(|t| t.status.err.clone())
        })
        .await;
    assert_eq!(err, "no suitable node (1 node not available for new tasks)");

    {
        let view = cluster.store().view();
        let task = view.task(&task_id).expect("task");
        assert_eq!(task.status.state, TaskState::Pending, "still queued");
        assert!(task.node_id.is_none());
    }

    // The node comes back: the task is retried without any other trigger.
    set_availability(&cluster, Availability::Active).await;
    let task: Task = cluster
        .wait_for("the retried assignment", |view| {
            view.task(&task_id)
                .filter(|t| t.status.state == TaskState::Assigned)
                .map(|t| (*t).clone())
        })
        .await;
    assert_eq!(task.node_id.as_ref(), Some(cluster.node_id()));
    assert!(task.status.err.is_none(), "the error is cleared on success");

    shutdown.cancel();
    scheduler.join().await;
    cluster.shutdown().await;
}

/// A competing writer racing the scheduler: every decision the scheduler
/// commits is validated against the version it read (SWK §8.9), so a task
/// touched mid-flight is re-queued and assigned on a later tick instead of
/// being lost or double-written.
#[tokio::test(flavor = "multi_thread")]
async fn a_competing_writer_only_delays_the_assignment() {
    let cluster = TestCluster::start().await;
    let (_service_id, task_id) = seed_pending_task(cluster.store()).await;

    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    // Hammer the same object from another writer while the scheduler works.
    let store = cluster.store().clone();
    let racing_id = task_id.clone();
    let racer = tokio::spawn(async move {
        for round in 0..50_u32 {
            let current = {
                let view = store.view();
                view.task(&racing_id).map(|t| (*t).clone())
            };
            let Some(mut task) = current else { break };
            if task.status.state != TaskState::Pending {
                break;
            }
            task.status = TaskStatus::new(TaskState::Pending, format!("racing write {round}"));
            // Rejections are the point of the exercise; both writers retry.
            let _ = store
                .propose(vec![StoreAction::Update(StoreObject::Task(task))])
                .await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });

    let task: Task = cluster
        .wait_for("the assignment to win the race", |view| {
            view.task(&task_id)
                .filter(|t| t.status.state == TaskState::Assigned)
                .map(|t| (*t).clone())
        })
        .await;
    assert_eq!(task.node_id.as_ref(), Some(cluster.node_id()));
    racer.await.expect("racing writer finished");

    shutdown.cancel();
    scheduler.join().await;
    cluster.shutdown().await;
}

/// The spread criterion end to end (SWK §8.4): six interchangeable replicas
/// over three usable nodes land 2/2/2, and the drained fourth node — the one
/// the harness seeded — gets nothing.
#[tokio::test(flavor = "multi_thread")]
async fn six_replicas_spread_evenly_over_three_nodes() {
    let cluster = TestCluster::start().await;
    set_availability(&cluster, Availability::Drain).await;
    let node_ids = plant_nodes(
        cluster.store(),
        vec![
            NodeBuilder::new("alpha").build(),
            NodeBuilder::new("beta").build(),
            NodeBuilder::new("gamma").build(),
        ],
    )
    .await;
    let (_service_id, task_ids) = seed_service(cluster.store(), sample_service("web", 6), 6).await;

    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let per_node = wait_for_placement(&cluster, &task_ids).await;
    assert_eq!(
        per_node.len(),
        3,
        "every usable node was used: {per_node:?}"
    );
    for id in &node_ids {
        assert_eq!(
            per_node.get(id).copied(),
            Some(2),
            "node {id}: {per_node:?}"
        );
    }
    assert!(
        !per_node.contains_key(cluster.node_id()),
        "the drained node took tasks: {per_node:?}"
    );

    shutdown.cancel();
    scheduler.join().await;
    cluster.shutdown().await;
}

/// A drained node is simply not a candidate, whatever its capacity: the two
/// remaining nodes absorb everything (SWK §8.3 filter 1).
#[tokio::test(flavor = "multi_thread")]
async fn a_drained_node_gets_nothing() {
    let cluster = TestCluster::start().await;
    set_availability(&cluster, Availability::Drain).await;
    let node_ids = plant_nodes(
        cluster.store(),
        vec![
            NodeBuilder::new("alpha").build(),
            NodeBuilder::new("beta").build(),
            NodeBuilder::new("gamma").build(),
        ],
    )
    .await;
    set_node_availability(cluster.store(), &node_ids[1], Availability::Drain).await;
    let (_service_id, task_ids) = seed_service(cluster.store(), sample_service("web", 4), 4).await;

    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let per_node = wait_for_placement(&cluster, &task_ids).await;
    assert_eq!(
        per_node.get(&node_ids[1]),
        None,
        "the drained node took tasks: {per_node:?}"
    );
    assert_eq!(per_node.get(&node_ids[0]).copied(), Some(2));
    assert_eq!(per_node.get(&node_ids[2]).copied(), Some(2));

    shutdown.cancel();
    scheduler.join().await;
    cluster.shutdown().await;
}

/// Constraints exclude nodes (SWK §8.3 filter 4, §8.7): with
/// `node.labels.zone == b`, every replica lands on the one node in zone b,
/// however unbalanced that leaves the cluster.
#[tokio::test(flavor = "multi_thread")]
async fn constraints_exclude_nodes() {
    let cluster = TestCluster::start().await;
    set_availability(&cluster, Availability::Drain).await;
    let node_ids = plant_nodes(
        cluster.store(),
        vec![
            NodeBuilder::new("alpha").label("zone", "a").build(),
            NodeBuilder::new("beta").label("zone", "b").build(),
            NodeBuilder::new("gamma").label("zone", "c").build(),
        ],
    )
    .await;

    let mut service = sample_service("web", 3);
    service.spec.task.placement.constraints = vec!["node.labels.zone == b".to_owned()];
    let (_service_id, task_ids) = seed_service(cluster.store(), service, 3).await;

    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let per_node = wait_for_placement(&cluster, &task_ids).await;
    assert_eq!(
        per_node,
        BTreeMap::from([(node_ids[1].clone(), 3)]),
        "all three replicas belong in zone b"
    );

    shutdown.cancel();
    scheduler.join().await;
    cluster.shutdown().await;
}

/// A constraint no node satisfies leaves every task pending with the filter's
/// explanation (SWK §8.3, §8.8).
#[tokio::test(flavor = "multi_thread")]
async fn an_unsatisfiable_constraint_explains_itself() {
    let cluster = TestCluster::start().await;
    set_availability(&cluster, Availability::Drain).await;
    plant_nodes(
        cluster.store(),
        vec![
            NodeBuilder::new("alpha").label("zone", "a").build(),
            NodeBuilder::new("beta").label("zone", "b").build(),
        ],
    )
    .await;

    let mut service = sample_service("web", 1);
    service.spec.task.placement.constraints = vec!["node.labels.zone == nowhere".to_owned()];
    let (_service_id, task_ids) = seed_service(cluster.store(), service, 1).await;

    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let err: String = cluster
        .wait_for("the unschedulable reason", |view| {
            view.task(&task_ids[0]).and_then(|t| t.status.err.clone())
        })
        .await;
    assert_eq!(
        err,
        "no suitable node (scheduling constraints not satisfied on 2 nodes; \
         1 node not available for new tasks)"
    );

    shutdown.cancel();
    scheduler.join().await;
    cluster.shutdown().await;
}

/// Resource exhaustion (SWK §8.3 filter 2): the node fits two reserving
/// tasks, the third stays `PENDING` and says why — and the accounting is
/// batch-local, so the third is refused within the same pass that placed the
/// first two.
#[tokio::test(flavor = "multi_thread")]
async fn resource_exhaustion_leaves_the_last_task_pending() {
    let cluster = TestCluster::start().await;
    set_availability(&cluster, Availability::Drain).await;
    let node_ids = plant_nodes(
        cluster.store(),
        vec![
            NodeBuilder::new("alpha")
                .resources(2_000_000_000, gib(4))
                .build(),
        ],
    )
    .await;

    let service = sample_service("web", 3);
    let mut actions = vec![StoreAction::Create(StoreObject::Service(service.clone()))];
    let mut task_ids = Vec::new();
    for slot in 1..=3 {
        let mut task = planted_task(
            &service,
            slot,
            TaskState::Pending,
            DesiredState::Running,
            std::time::SystemTime::now(),
        );
        reserve(&mut task, 1_000_000_000, gib(2));
        task_ids.push(task.id.clone());
        actions.push(StoreAction::Create(StoreObject::Task(task)));
    }
    cluster
        .store()
        .propose(actions)
        .await
        .expect("service committed");

    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let placed: usize = cluster
        .wait_for("two tasks placed and one refused", |view| {
            let assigned = task_ids
                .iter()
                .filter_map(|id| view.task(id))
                .filter(|task| task.status.state == TaskState::Assigned)
                .count();
            let explained = task_ids
                .iter()
                .filter_map(|id| view.task(id))
                .filter(|task| task.status.err.is_some())
                .count();
            (assigned == 2 && explained == 1).then_some(assigned)
        })
        .await;
    assert_eq!(placed, 2);

    let view = cluster.store().view();
    let refused = task_ids
        .iter()
        .filter_map(|id| view.task(id))
        .find(|task| task.status.state == TaskState::Pending)
        .expect("one task stayed pending");
    assert!(refused.node_id.is_none());
    assert_eq!(
        refused.status.err.as_deref(),
        Some("no suitable node (insufficient resources on 1 node)")
    );
    for id in &task_ids {
        let task = view.task(id).expect("task");
        if task.status.state == TaskState::Assigned {
            assert_eq!(task.node_id.as_ref(), Some(&node_ids[0]));
        }
    }
    drop(view);

    shutdown.cancel();
    scheduler.join().await;
    cluster.shutdown().await;
}

/// Preassigned tasks (SWK §8.6): a task that arrives with `node_id` already
/// set is validated against that one node before the general queue. While the
/// node refuses it the task stays `PENDING` with the reason; once the node
/// accepts, it moves to `ASSIGNED` with the preassigned message — and never
/// moves to another node.
#[tokio::test(flavor = "multi_thread")]
async fn a_preassigned_task_is_validated_against_its_own_node() {
    let cluster = TestCluster::start().await;
    set_availability(&cluster, Availability::Drain).await;
    let node_ids = plant_nodes(
        cluster.store(),
        vec![
            NodeBuilder::new("alpha")
                .availability(Availability::Pause)
                .build(),
            NodeBuilder::new("beta").build(),
        ],
    )
    .await;

    let service = sample_service("global", 1);
    let mut task = planted_task(
        &service,
        1,
        TaskState::Pending,
        DesiredState::Running,
        std::time::SystemTime::now(),
    );
    task.node_id = Some(node_ids[0].clone());
    let task_id = task.id.clone();
    cluster
        .store()
        .propose(vec![
            StoreAction::Create(StoreObject::Service(service)),
            StoreAction::Create(StoreObject::Task(task)),
        ])
        .await
        .expect("seed committed");

    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    // Paused node: refused, with the filter's own explanation and no
    // "no suitable node" wrapper — nothing was searched for (SWK §8.6).
    let err: String = cluster
        .wait_for("the preassigned refusal", |view| {
            view.task(&task_id).and_then(|t| t.status.err.clone())
        })
        .await;
    assert_eq!(err, "1 node not available for new tasks");
    {
        let view = cluster.store().view();
        let task = view.task(&task_id).expect("task");
        assert_eq!(task.status.state, TaskState::Pending);
        assert_eq!(
            task.node_id.as_ref(),
            Some(&node_ids[0]),
            "the scheduler never re-homes a preassigned task"
        );
    }

    // The node comes back: the task is confirmed on it, not moved to beta.
    set_node_availability(cluster.store(), &node_ids[0], Availability::Active).await;
    let task: Task = cluster
        .wait_for("the preassigned confirmation", |view| {
            view.task(&task_id)
                .filter(|t| t.status.state == TaskState::Assigned)
                .map(|t| (*t).clone())
        })
        .await;
    assert_eq!(task.node_id.as_ref(), Some(&node_ids[0]));
    assert_eq!(
        task.status.message,
        "scheduler confirmed task can run on preassigned node"
    );
    assert!(task.status.err.is_none());

    shutdown.cancel();
    scheduler.join().await;
    cluster.shutdown().await;
}

/// The `max_replicas` cap is per node (SWK §8.3 filter 7): with two nodes and
/// a cap of one, the third replica has nowhere to go and says so.
#[tokio::test(flavor = "multi_thread")]
async fn max_replicas_per_node_caps_placement() {
    let cluster = TestCluster::start().await;
    set_availability(&cluster, Availability::Drain).await;
    plant_nodes(
        cluster.store(),
        vec![
            NodeBuilder::new("alpha").build(),
            NodeBuilder::new("beta").build(),
        ],
    )
    .await;

    let mut service = sample_service("web", 3);
    service.spec.task.placement.max_replicas = 1;
    let (_service_id, task_ids) = seed_service(cluster.store(), service, 3).await;

    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let err: String = cluster
        .wait_for("the capped task's reason", |view| {
            let assigned = task_ids
                .iter()
                .filter_map(|id| view.task(id))
                .filter(|task| task.status.state == TaskState::Assigned)
                .count();
            if assigned != 2 {
                return None;
            }
            task_ids
                .iter()
                .filter_map(|id| view.task(id))
                .find(|task| task.status.state == TaskState::Pending)
                .and_then(|task| task.status.err.clone())
        })
        .await;
    assert_eq!(err, "no suitable node (max replicas per node limit exceed)");

    shutdown.cancel();
    scheduler.join().await;
    cluster.shutdown().await;
}

/// SWK §8.8: a task whose service was deleted is forgotten — no store write,
/// no error message, no retry loop.
#[tokio::test(flavor = "multi_thread")]
async fn a_task_of_a_deleted_service_is_forgotten() {
    let cluster = TestCluster::start().await;
    set_availability(&cluster, Availability::Drain).await;

    let service = sample_service("web", 1);
    let service_id = service.id.clone();
    let task = planted_task(
        &service,
        1,
        TaskState::Pending,
        DesiredState::Running,
        std::time::SystemTime::now(),
    );
    let task_id = task.id.clone();
    cluster
        .store()
        .propose(vec![
            StoreAction::Create(StoreObject::Service(service)),
            StoreAction::Create(StoreObject::Task(task)),
        ])
        .await
        .expect("seed committed");
    cluster
        .store()
        .propose(vec![StoreAction::Remove {
            kind: satl_core::ObjectKind::Service,
            id: service_id,
        }])
        .await
        .expect("service removed");

    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    cluster
        .stays(
            Duration::from_millis(300),
            "the orphan task is left alone",
            |view| {
                let task = view.task(&task_id).expect("task still exists");
                task.status.state == TaskState::Pending
                    && task.status.err.is_none()
                    && task.node_id.is_none()
            },
        )
        .await;

    shutdown.cancel();
    scheduler.join().await;
    cluster.shutdown().await;
}

/// SWK §8.8: a task of a superseded revision that is already meant to stop is
/// never going to run, so the scheduler completes its shutdown itself instead
/// of retrying forever.
#[tokio::test(flavor = "multi_thread")]
async fn an_outdated_task_that_must_stop_is_shut_down() {
    let cluster = TestCluster::start().await;
    set_availability(&cluster, Availability::Drain).await;

    let service = sample_service("web", 1);
    let mut task = planted_task(
        &service,
        1,
        TaskState::Pending,
        DesiredState::Running,
        std::time::SystemTime::now(),
    );
    // Stamped from an older revision than the service will end up at.
    task.spec_version = Some(satl_core::Version(1));
    let task_id = task.id.clone();
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![
            StoreAction::Create(StoreObject::Service(service)),
            StoreAction::Create(StoreObject::Task(task)),
        ])
        .await
        .expect("seed committed");
    // Bump the service so the task is demonstrably behind it.
    let mut updated = {
        let view = cluster.store().view();
        (*view.service(&service_id).expect("service")).clone()
    };
    updated.spec.task.force_update += 1;
    cluster
        .store()
        .propose(vec![StoreAction::Update(StoreObject::Service(updated))])
        .await
        .expect("service updated");

    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    // It is unschedulable first (the only node is drained), and reported as
    // such — the scheduler still expects to place it one day.
    cluster
        .wait_for("the unschedulable reason", |view| {
            view.task(&task_id).and_then(|t| t.status.err.clone())
        })
        .await;

    // Then the updater gives up on it: desired state SHUTDOWN, still pending
    // and still behind the service. Now the scheduler finishes the job.
    set_desired_state(cluster.store(), &task_id, DesiredState::Shutdown).await;

    let task: Task = cluster
        .wait_for("the outdated task to be shut down", |view| {
            view.task(&task_id)
                .filter(|t| t.status.state == TaskState::Shutdown)
                .map(|t| (*t).clone())
        })
        .await;
    assert!(task.node_id.is_none(), "it was never placed");
    assert!(task.status.err.is_none());
    assert_eq!(
        task.status.message,
        "scheduler shut down a task of an outdated service revision"
    );

    shutdown.cancel();
    scheduler.join().await;
    cluster.shutdown().await;
}
