// SPDX-License-Identifier: BSD-2-Clause
//! Node-state enforcement (SWK §7.1 `InvalidNode`, SWK §7.8) against a real
//! single-node store, with synthetic `Node` objects standing in for a 3-node
//! cluster.
//!
//! The regression these pin down: on a live 3-node cluster, stopping `satld` on
//! one node made the dispatcher mark it `Down`, but its tasks stayed `Running`
//! in the store forever and were never replaced — the service ran at 4
//! effective replicas while reporting 6/6.
//!
//! "Runnable" below is that effective replica count: tasks the cluster still
//! wants (`desired_state <= Running`) that have not finished.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use satl_cluster::StoreView;
use satl_core::{
    Availability, DesiredState, Id, NodeState, ObjectKind, RestartCondition, StoreAction,
    StoreObject, Task, TaskState,
};
use satl_orchestrator::{Cadence, Orchestrator, OrchestratorConfig};
use satl_sched::{Scheduler, SchedulerConfig};
use tokio_util::sync::CancellationToken;

#[path = "../src/testing.rs"]
mod testing;

use testing::{
    TestCluster, assigned_to, planted_node, planted_task, sample_service, set_task_state,
    update_node, with_restart,
};

/// Short windows so the tests are quick; the shape is unchanged.
fn fast() -> OrchestratorConfig {
    OrchestratorConfig {
        reconcile_interval: Duration::from_millis(200),
        reaper_batch: Duration::from_millis(20),
        reaper_force_at: 1000,
        allocator_retry: Duration::from_millis(200),
        keyring_cadence: Cadence::default(),
    }
}

fn fast_scheduler() -> SchedulerConfig {
    SchedulerConfig {
        debounce: Duration::from_millis(10),
        max_debounce: Duration::from_millis(100),
    }
}

/// Restart delay used by the eviction tests: long enough to be measurable,
/// short enough to keep tests fast.
const RESTART_DELAY: Duration = Duration::from_millis(600);

/// Long enough that a node can flap well inside it.
const SLOW_RESTART_DELAY: Duration = Duration::from_millis(800);

/// How long a "nothing happens" assertion watches for.
const QUIET: Duration = Duration::from_millis(500);

/// Tasks of one service, from a store view.
fn service_tasks(view: &StoreView<'_>, service_id: &Id) -> Vec<Arc<Task>> {
    view.tasks()
        .into_iter()
        .filter(|task| task.service_id.as_ref() == Some(service_id))
        .collect()
}

/// The slots holding a task the cluster still wants and that has not finished,
/// ascending — the service's effective replicas.
fn runnable_slots(view: &StoreView<'_>, service_id: &Id) -> Vec<u64> {
    let mut slots: Vec<u64> = service_tasks(view, service_id)
        .iter()
        .filter(|task| {
            task.desired_state <= DesiredState::Running && !task.status.state.is_terminal()
        })
        .map(|task| task.slot)
        .collect();
    slots.sort_unstable();
    slots
}

/// IDs of the service's tasks bound to `node_id`.
fn task_ids_on(cluster: &TestCluster, service_id: &Id, node_id: &Id) -> Vec<Id> {
    cluster
        .tasks_of(service_id)
        .into_iter()
        .filter(|task| task.node_id.as_ref() == Some(node_id))
        .map(|task| task.id)
        .collect()
}

/// Plants `replicas` tasks of one service, all `RUNNING`, spread evenly over
/// `names.len()` synthetic nodes — the state a healthy cluster is in.
///
/// The service is written first so the planted tasks can snapshot the version
/// the store actually stamped on it: `max_attempts` is counted per
/// `(service, slot, spec_version)`, so tasks at a stale spec version would get
/// a budget of their own.
///
/// Returns the service ID and the node IDs, in `names` order.
async fn planted_cluster(
    cluster: &TestCluster,
    names: &[&str],
    replicas: u64,
    condition: RestartCondition,
    delay: Duration,
    max_attempts: u64,
) -> (Id, Vec<Id>) {
    let mut service = with_restart(
        sample_service("web", replicas),
        condition,
        delay,
        max_attempts,
    );
    let service_id = service.id.clone();
    service.meta.version = cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(
            service.clone(),
        ))])
        .await
        .expect("service created");

    let nodes: Vec<_> = names.iter().copied().map(planted_node).collect();
    let node_ids: Vec<Id> = nodes.iter().map(|node| node.id.clone()).collect();
    let mut actions: Vec<StoreAction> = nodes
        .into_iter()
        .map(|node| StoreAction::Create(StoreObject::Node(node)))
        .collect();
    let per_node = replicas / node_ids.len() as u64;
    let now = SystemTime::now();
    for slot in 1..=replicas {
        let node = &node_ids[usize::try_from((slot - 1) / per_node).expect("small")];
        let task = planted_task(
            &service,
            slot,
            TaskState::Running,
            DesiredState::Running,
            now,
        );
        actions.push(StoreAction::Create(StoreObject::Task(assigned_to(
            task, node,
        ))));
    }
    cluster
        .store()
        .propose(actions)
        .await
        .expect("cluster planted");
    (service_id, node_ids)
}

/// The bug: a `Down` node's tasks must be shut down *and* replaced in their own
/// slots, on nodes that are still alive.
#[tokio::test(flavor = "multi_thread")]
async fn a_down_node_gives_up_its_tasks_and_they_are_replaced_in_the_same_slots() {
    let cluster = TestCluster::start().await;
    let (service_id, nodes) = planted_cluster(
        &cluster,
        &["n1", "n2", "n3"],
        6,
        RestartCondition::Any,
        RESTART_DELAY,
        0,
    )
    .await;
    let down = nodes[2].clone();

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());
    let scheduler =
        Scheduler::spawn_with_config(cluster.store().clone(), fast_scheduler(), shutdown.clone());

    let stranded = task_ids_on(&cluster, &service_id, &down);
    assert_eq!(stranded.len(), 2, "the spread was 2/2/2");

    // The dispatcher's heartbeat TTL expires.
    update_node(cluster.store(), &down, |node| {
        node.status.state = NodeState::Down;
        node.status.message = "heartbeat TTL expired".to_owned();
    })
    .await;

    cluster
        .wait_for("the stranded tasks to be replaced", |view| {
            (service_tasks(view, &service_id).len() == 8
                && runnable_slots(view, &service_id) == vec![1, 2, 3, 4, 5, 6])
            .then_some(())
        })
        .await;

    let all = cluster.tasks_of(&service_id);
    assert_eq!(all.len(), 8, "6 originals + 2 replacements");
    for id in &stranded {
        let old = all.iter().find(|t| &t.id == id).expect("predecessor kept");
        assert_eq!(
            old.desired_state,
            DesiredState::Shutdown,
            "the agent stops the container if the node ever comes back"
        );
        assert_eq!(
            old.status.state,
            TaskState::Running,
            "the observed state is the agent's to report, not ours to invent"
        );
        assert_eq!(old.node_id.as_ref(), Some(&down));
    }

    let replacements: Vec<&Task> = all.iter().filter(|t| !stranded.contains(&t.id)).collect();
    let mut slots: Vec<u64> = replacements
        .iter()
        .filter(|t| t.slot >= 5)
        .map(|t| t.slot)
        .collect();
    slots.sort_unstable();
    assert_eq!(slots, vec![5, 6], "replacements reuse the stranded slots");

    // The scheduler places them anywhere but the dead node.
    cluster
        .wait_for("the replacements to be scheduled elsewhere", |view| {
            let placed = service_tasks(view, &service_id)
                .iter()
                .filter(|t| t.slot >= 5 && !stranded.contains(&t.id))
                .all(|t| t.node_id.is_some() && t.node_id.as_ref() != Some(&down));
            placed.then_some(())
        })
        .await;

    // And exactly one replacement per slot: the reconcile pass must not add a
    // second task to a slot the eviction already refilled.
    cluster
        .stays(QUIET, "no double-create in an evicted slot", |view| {
            service_tasks(view, &service_id).len() == 8
                && runnable_slots(view, &service_id) == vec![1, 2, 3, 4, 5, 6]
        })
        .await;

    shutdown.cancel();
    scheduler.join().await;
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// `DRAIN` evicts exactly like `DOWN`, and (SWK §7.4) without waiting out the
/// restart delay.
#[tokio::test(flavor = "multi_thread")]
async fn a_draining_node_gives_up_its_tasks_without_the_restart_delay() {
    let cluster = TestCluster::start().await;
    let (service_id, nodes) = planted_cluster(
        &cluster,
        &["n1", "n2", "n3"],
        6,
        RestartCondition::Any,
        SLOW_RESTART_DELAY,
        0,
    )
    .await;
    let drained = nodes[0].clone();

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());
    let scheduler =
        Scheduler::spawn_with_config(cluster.store().clone(), fast_scheduler(), shutdown.clone());

    let stranded = task_ids_on(&cluster, &service_id, &drained);
    assert_eq!(stranded.len(), 2);

    // The node stays perfectly alive; the operator just wants it empty.
    let started = Instant::now();
    update_node(cluster.store(), &drained, |node| {
        node.spec.availability = Availability::Drain;
    })
    .await;

    cluster
        .wait_for("the drained tasks to be replaced", |view| {
            (service_tasks(view, &service_id).len() == 8
                && runnable_slots(view, &service_id) == vec![1, 2, 3, 4, 5, 6])
            .then_some(())
        })
        .await;
    assert!(
        started.elapsed() < SLOW_RESTART_DELAY,
        "a drain is not paced by the restart delay (SWK §7.4), took {:?}",
        started.elapsed()
    );

    let all = cluster.tasks_of(&service_id);
    assert_eq!(all.len(), 8);
    for id in &stranded {
        let old = all.iter().find(|t| &t.id == id).expect("predecessor kept");
        assert_eq!(old.desired_state, DesiredState::Shutdown);
    }
    cluster
        .wait_for("the replacements to leave the drained node", |view| {
            let placed = service_tasks(view, &service_id)
                .iter()
                .filter(|t| t.slot <= 2 && !stranded.contains(&t.id))
                .all(|t| t.node_id.is_some() && t.node_id.as_ref() != Some(&drained));
            placed.then_some(())
        })
        .await;

    shutdown.cancel();
    scheduler.join().await;
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// `PAUSE` is "no new tasks, leave the running ones alone" — it must never
/// evict (SWK §7.8).
#[tokio::test(flavor = "multi_thread")]
async fn a_paused_node_keeps_its_tasks() {
    let cluster = TestCluster::start().await;
    let (service_id, nodes) = planted_cluster(
        &cluster,
        &["n1", "n2", "n3"],
        6,
        RestartCondition::Any,
        Duration::from_millis(20),
        0,
    )
    .await;
    let paused = nodes[1].clone();

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    update_node(cluster.store(), &paused, |node| {
        node.spec.availability = Availability::Pause;
    })
    .await;

    cluster
        .stays(QUIET, "pause changes nothing at all", |view| {
            let tasks = service_tasks(view, &service_id);
            tasks.len() == 6
                && tasks
                    .iter()
                    .all(|t| t.desired_state == DesiredState::Running)
                && runnable_slots(view, &service_id) == vec![1, 2, 3, 4, 5, 6]
        })
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// A deleted node object is `InvalidNode` too (SWK §7.1 `n == nil`).
#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_node_gives_up_its_tasks() {
    let cluster = TestCluster::start().await;
    let (service_id, nodes) = planted_cluster(
        &cluster,
        &["n1", "n2"],
        2,
        RestartCondition::Any,
        Duration::from_millis(20),
        0,
    )
    .await;
    let gone = nodes[1].clone();

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let stranded = task_ids_on(&cluster, &service_id, &gone);
    assert_eq!(stranded.len(), 1);
    cluster
        .store()
        .propose(vec![StoreAction::Remove {
            kind: ObjectKind::Node,
            id: gone.clone(),
        }])
        .await
        .expect("node removed");

    cluster
        .wait_for("the orphaned slot to be refilled", |view| {
            (service_tasks(view, &service_id).len() == 3
                && runnable_slots(view, &service_id) == vec![1, 2])
            .then_some(())
        })
        .await;
    let all = cluster.tasks_of(&service_id);
    let old = all
        .iter()
        .find(|t| t.id == stranded[0])
        .expect("predecessor kept");
    assert_eq!(old.desired_state, DesiredState::Shutdown);

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// A node that flaps inside the restart delay must not lose its task, and must
/// not leave a duplicate live task behind in the slot — the eviction is
/// re-derived from a fresh view when it fires, not remembered.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_that_recovers_during_the_delay_keeps_its_task() {
    let cluster = TestCluster::start().await;
    let (service_id, nodes) = planted_cluster(
        &cluster,
        &["n1", "n2"],
        2,
        RestartCondition::Any,
        SLOW_RESTART_DELAY,
        0,
    )
    .await;
    let flapping = nodes[0].clone();

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    update_node(cluster.store(), &flapping, |node| {
        node.status.state = NodeState::Down;
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    update_node(cluster.store(), &flapping, |node| {
        node.status.state = NodeState::Ready;
    })
    .await;

    // The queued eviction fires while the node is healthy again and finds
    // nothing to do.
    cluster
        .stays(SLOW_RESTART_DELAY + QUIET, "the flap is absorbed", |view| {
            let tasks = service_tasks(view, &service_id);
            tasks.len() == 2
                && tasks
                    .iter()
                    .all(|t| t.desired_state == DesiredState::Running)
        })
        .await;

    // The verdict was forgotten with the recovery, so a real failure of the
    // same node still evicts.
    update_node(cluster.store(), &flapping, |node| {
        node.status.state = NodeState::Down;
    })
    .await;
    cluster
        .wait_for("the stranded task to be replaced after the flap", |view| {
            (service_tasks(view, &service_id).len() == 3).then_some(())
        })
        .await;
    let all = cluster.tasks_of(&service_id);
    assert_eq!(
        all.iter().filter(|t| t.slot == 1).count(),
        2,
        "the shut-down predecessor plus its replacement (SWK §4.5)"
    );
    let view = cluster.store().view();
    assert_eq!(
        runnable_slots(&view, &service_id),
        vec![1, 2],
        "one live task per slot"
    );
    drop(view);

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// The restart policy decides the *replacement*, not the shutdown (SWK §7.4
/// step 2): `restart-condition = none` never gets a replacement, however dead
/// its node is, but the stranded task is still given up — otherwise draining a
/// node would leave that service's containers running on it forever.
#[tokio::test(flavor = "multi_thread")]
async fn restart_condition_none_gives_up_its_task_but_gets_no_replacement() {
    let cluster = TestCluster::start().await;
    let (service_id, nodes) = planted_cluster(
        &cluster,
        &["n1", "n2"],
        2,
        RestartCondition::None,
        Duration::from_millis(20),
        0,
    )
    .await;
    let down = nodes[1].clone();

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let stranded = task_ids_on(&cluster, &service_id, &down);
    assert_eq!(stranded.len(), 1);
    update_node(cluster.store(), &down, |node| {
        node.status.state = NodeState::Down;
    })
    .await;

    // The stranded task is given up (SWK §7.4 step 2, unconditional).
    cluster
        .wait_for("the stranded task to be given up", |view| {
            service_tasks(view, &service_id)
                .iter()
                .find(|t| t.id == stranded[0])
                .filter(|t| t.desired_state == DesiredState::Shutdown)
                .map(|_| ())
        })
        .await;

    // Neither the eviction nor the reconcile pass may resurrect the slot, and
    // the task on the *healthy* node is untouched.
    cluster
        .stays(QUIET, "no replacement for restart-condition none", |view| {
            let tasks = service_tasks(view, &service_id);
            tasks.len() == 2
                && tasks
                    .iter()
                    .filter(|t| t.node_id.as_ref() != Some(&down))
                    .all(|t| t.desired_state == DesiredState::Running)
        })
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// The constraint enforcer (SWK §7.6): a node whose labels stop satisfying the
/// service's placement gives up the task, which is then rescheduled on a node
/// that still qualifies.
///
/// The gap this closes: constraints were checked only at *scheduling* time, so a
/// task kept running on a node that no longer qualified for as long as it lived.
#[tokio::test(flavor = "multi_thread")]
async fn a_relabelled_node_gives_up_the_task_that_no_longer_belongs_there() {
    let cluster = TestCluster::start().await;
    let mut service = with_restart(
        sample_service("web", 2),
        RestartCondition::Any,
        RESTART_DELAY,
        0,
    );
    service.spec.task.placement.constraints = vec!["node.labels.zone == a".to_owned()];
    let service_id = service.id.clone();
    service.meta.version = cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(
            service.clone(),
        ))])
        .await
        .expect("service created");

    // Two nodes in zone a, one task each. The manager's own node is unlabelled,
    // so it never satisfies the constraint.
    let mut nodes = Vec::new();
    let mut actions = Vec::new();
    for name in ["n1", "n2"] {
        let mut node = planted_node(name);
        node.spec.labels.insert("zone".to_owned(), "a".to_owned());
        nodes.push(node.id.clone());
        actions.push(StoreAction::Create(StoreObject::Node(node)));
    }
    let now = SystemTime::now();
    for (slot, node) in (1..=2).zip(&nodes) {
        let task = planted_task(
            &service,
            slot,
            TaskState::Running,
            DesiredState::Running,
            now,
        );
        actions.push(StoreAction::Create(StoreObject::Task(assigned_to(
            task, node,
        ))));
    }
    cluster
        .store()
        .propose(actions)
        .await
        .expect("cluster planted");
    let (moved_from, stays) = (nodes[0].clone(), nodes[1].clone());
    let stranded = task_ids_on(&cluster, &service_id, &moved_from).remove(0);

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());
    let scheduler =
        Scheduler::spawn_with_config(cluster.store().clone(), fast_scheduler(), shutdown.clone());

    // Nothing moves while the labels still match.
    cluster
        .stays(QUIET, "a matching node keeps its task", |view| {
            service_tasks(view, &service_id).len() == 2
                && runnable_slots(view, &service_id) == vec![1, 2]
        })
        .await;

    // The operator moves the node to another zone.
    update_node(cluster.store(), &moved_from, |node| {
        node.spec.labels.insert("zone".to_owned(), "b".to_owned());
    })
    .await;

    cluster
        .wait_for("the stranded task to be replaced", |view| {
            (service_tasks(view, &service_id).len() == 3
                && runnable_slots(view, &service_id) == vec![1, 2])
            .then_some(())
        })
        .await;

    let all = cluster.tasks_of(&service_id);
    let old = all
        .iter()
        .find(|task| task.id == stranded)
        .expect("predecessor kept");
    assert_eq!(
        old.desired_state,
        DesiredState::Shutdown,
        "the agent stops a container whose node no longer qualifies"
    );
    assert_eq!(old.node_id.as_ref(), Some(&moved_from));

    // The replacement is in the same slot, and on the node that still matches.
    cluster
        .wait_for("the replacement to land on a qualifying node", |view| {
            let replacement = service_tasks(view, &service_id)
                .into_iter()
                .find(|task| task.slot == 1 && task.id != stranded)?;
            (replacement.node_id.as_ref() == Some(&stays)).then_some(())
        })
        .await;

    shutdown.cancel();
    scheduler.join().await;
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// One `max_attempts` budget per `(service, slot, spec_version)`, shared by
/// both triggers: an eviction spends the same attempt a crash would.
#[tokio::test(flavor = "multi_thread")]
async fn evictions_and_crashes_share_one_max_attempts_budget() {
    let cluster = TestCluster::start().await;
    // One replica, one attempt.
    let (service_id, nodes) = planted_cluster(
        &cluster,
        &["n1"],
        1,
        RestartCondition::Any,
        Duration::from_millis(20),
        1,
    )
    .await;
    let down = nodes[0].clone();
    let first = task_ids_on(&cluster, &service_id, &down).remove(0);

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    update_node(cluster.store(), &down, |node| {
        node.status.state = NodeState::Down;
    })
    .await;

    // Attempt 1 of 1, spent on the node eviction.
    let replacement: Task = cluster
        .wait_for("the one allowed replacement", |view| {
            service_tasks(view, &service_id)
                .into_iter()
                .find(|t| t.id != first)
                .map(|t| (*t).clone())
        })
        .await;
    assert_eq!(replacement.slot, 1);

    // The same budget now refuses a crash-driven restart of the replacement.
    set_task_state(cluster.store(), &replacement.id, TaskState::Failed).await;
    cluster
        .stays(QUIET, "the eviction consumed the only attempt", |view| {
            service_tasks(view, &service_id).len() == 2
        })
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// A label that flaps inside the restart delay must not cost the task its
/// place, and must not leave a duplicate live task in the slot: the eviction is
/// re-derived from a fresh view when it fires, and the verdict is forgotten with
/// the node change that voided it.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_relabelled_back_inside_the_delay_keeps_its_task() {
    let cluster = TestCluster::start().await;
    let mut service = with_restart(
        sample_service("web", 1),
        RestartCondition::Any,
        SLOW_RESTART_DELAY,
        0,
    );
    service.spec.task.placement.constraints = vec!["node.labels.zone == a".to_owned()];
    let service_id = service.id.clone();
    service.meta.version = cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(
            service.clone(),
        ))])
        .await
        .expect("service created");

    let mut node = planted_node("n1");
    node.spec.labels.insert("zone".to_owned(), "a".to_owned());
    let node_id = node.id.clone();
    let task = assigned_to(
        planted_task(
            &service,
            1,
            TaskState::Running,
            DesiredState::Running,
            SystemTime::now(),
        ),
        &node_id,
    );
    cluster
        .store()
        .propose(vec![
            StoreAction::Create(StoreObject::Node(node)),
            StoreAction::Create(StoreObject::Task(task)),
        ])
        .await
        .expect("cluster planted");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    // Relabelled away and back well inside the delay.
    update_node(cluster.store(), &node_id, |node| {
        node.spec.labels.insert("zone".to_owned(), "b".to_owned());
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    update_node(cluster.store(), &node_id, |node| {
        node.spec.labels.insert("zone".to_owned(), "a".to_owned());
    })
    .await;

    cluster
        .stays(
            SLOW_RESTART_DELAY + QUIET,
            "the relabel flap is absorbed",
            |view| {
                let tasks = service_tasks(view, &service_id);
                tasks.len() == 1
                    && tasks
                        .iter()
                        .all(|t| t.desired_state == DesiredState::Running)
            },
        )
        .await;

    // The verdict was forgotten with the label that voided it, so a real
    // relabel still evicts.
    update_node(cluster.store(), &node_id, |node| {
        node.spec.labels.insert("zone".to_owned(), "b".to_owned());
    })
    .await;
    cluster
        .wait_for("the task to be given up after the flap", |view| {
            (service_tasks(view, &service_id).len() == 2
                && runnable_slots(view, &service_id) == vec![1])
            .then_some(())
        })
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}
