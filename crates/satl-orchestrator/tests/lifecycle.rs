// SPDX-License-Identifier: BSD-2-Clause
//! Service → tasks → scheduling, against a real single-node store.
//!
//! The store is `satl-cluster`'s in-process single-node Raft harness (a real
//! FSM in a temp dir, ~20 ms to start), so these exercise the actual watch
//! feed, the actual optimistic concurrency and the actual proposal path —
//! the loops are wired exactly as `satld` will wire them.

use std::collections::BTreeSet;
use std::time::Duration;

use satl_core::{DesiredState, ObjectKind, StoreAction, StoreObject, Task, TaskState, TaskStatus};
use satl_orchestrator::{AUTOSTART_LABEL, Cadence, Orchestrator, OrchestratorConfig};
use satl_sched::{Scheduler, SchedulerConfig};
use tokio_util::sync::CancellationToken;

#[path = "../src/testing.rs"]
mod testing;

use testing::{TestCluster, sample_service, scale_service, with_label};

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

/// How long a "nothing happens" assertion watches for.
const QUIET: Duration = Duration::from_millis(400);

/// Binds a task to `node` and reports it `RUNNING`, the way the scheduler and
/// then the agent do — retrying the optimistic-concurrency race against the
/// loops under test.
async fn run_task(
    store: &satl_cluster::ClusterStore,
    task_id: &satl_core::Id,
    node: &satl_core::Id,
) {
    for _ in 0..50 {
        let current = {
            let view = store.view();
            view.task(task_id).map(|task| (*task).clone())
        };
        let mut task = current.unwrap_or_else(|| panic!("task {task_id} is gone"));
        task.node_id = Some(node.clone());
        task.status = TaskStatus::new(TaskState::Running, "running (reported by the test agent)");
        match store
            .propose(vec![StoreAction::Update(StoreObject::Task(task))])
            .await
        {
            Ok(_) => return,
            Err(satl_cluster::ProposeError::Rejected(_)) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(err) => panic!("failed to run task: {err}"),
        }
    }
    panic!("never won the race to run task {task_id}");
}

#[tokio::test(flavor = "multi_thread")]
async fn service_create_fills_every_slot_and_allocates_the_tasks() {
    let cluster = TestCluster::start().await;
    let service = sample_service("web", 3);
    let service_id = service.id.clone();
    let service_version = cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    cluster
        .wait_for("three tasks", |view| {
            let count = view
                .tasks()
                .iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .count();
            (count == 3).then_some(())
        })
        .await;

    let tasks = cluster.tasks_of(&service_id);
    let slots: BTreeSet<u64> = tasks.iter().map(|t| t.slot).collect();
    assert_eq!(slots, BTreeSet::from([1, 2, 3]), "slots 1..=replicas");
    for task in &tasks {
        assert_eq!(
            task.desired_state,
            DesiredState::Running,
            "autostart default"
        );
        assert_eq!(
            task.spec_version,
            Some(service_version),
            "spec version snapshotted from the service"
        );
        assert_eq!(task.service_annotations.name, "web");
        assert!(task.node_id.is_none(), "the scheduler binds nodes, not us");
        assert_eq!(
            task.annotations.name,
            format!("web.{}.{}", task.slot, task.id)
        );
    }

    // The allocator votes every NEW task into PENDING (M1: unconditionally).
    cluster
        .wait_for("all tasks allocated", |view| {
            let all_pending = view
                .tasks()
                .iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .all(|t| t.status.state == TaskState::Pending);
            all_pending.then_some(())
        })
        .await;
    assert_eq!(cluster.tasks_of(&service_id).len(), 3, "no extra tasks");

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn autostart_false_creates_the_task_at_desired_ready() {
    let cluster = TestCluster::start().await;
    let service = with_label(sample_service("created", 1), AUTOSTART_LABEL, "false");
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let task: Task = cluster
        .wait_for("the created task", |view| {
            view.tasks()
                .into_iter()
                .find(|t| t.service_id.as_ref() == Some(&service_id))
                .map(|t| (*t).clone())
        })
        .await;
    assert_eq!(
        task.desired_state,
        DesiredState::Ready,
        "docker `created`: prepared but not started"
    );

    // It is still allocated (it must be prepared), and no loop ever promotes
    // it: only the API backend does, on `container start`.
    cluster
        .wait_for("the task to be allocated", |view| {
            view.task(&task.id)
                .filter(|t| t.status.state == TaskState::Pending)
                .map(|_| ())
        })
        .await;
    cluster
        .stays(QUIET, "desired state stays Ready", |view| {
            view.task(&task.id)
                .is_some_and(|t| t.desired_state == DesiredState::Ready)
        })
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// The M1 control-plane pipeline end to end (architecture §5 steps 2–4):
/// orchestrator creates the task, allocator votes it `PENDING`, scheduler
/// binds it to the only node.
#[tokio::test(flavor = "multi_thread")]
async fn new_pending_assigned_end_to_end() {
    let cluster = TestCluster::start().await;
    let service = sample_service("web", 2);
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());
    let scheduler =
        Scheduler::spawn_with_config(cluster.store().clone(), fast_scheduler(), shutdown.clone());

    cluster
        .wait_for("both tasks assigned to the node", |view| {
            let tasks: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .collect();
            let done = tasks.len() == 2
                && tasks
                    .iter()
                    .all(|t| t.status.state == TaskState::Assigned && t.node_id.is_some());
            done.then_some(())
        })
        .await;

    for task in cluster.tasks_of(&service_id) {
        assert_eq!(task.node_id.as_ref(), Some(cluster.node_id()));
        assert_eq!(task.status.message, "scheduler assigned task to node");
        assert_eq!(task.desired_state, DesiredState::Running);
    }

    shutdown.cancel();
    scheduler.join().await;
    orchestrator.join().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn scaling_down_removes_and_reaps_the_excess_slots() {
    let cluster = TestCluster::start().await;
    let service = sample_service("web", 3);
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    cluster
        .wait_for("three tasks", |view| {
            let count = view
                .tasks()
                .iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .count();
            (count == 3).then_some(())
        })
        .await;
    let slot_one = cluster
        .tasks_of(&service_id)
        .into_iter()
        .find(|t| t.slot == 1)
        .expect("slot 1")
        .id;

    scale_service(cluster.store(), &service_id, 1).await;

    // Slots 2 and 3 are marked Remove and — since they never ran — deleted
    // by the reaper. Slot 1 is untouched.
    cluster
        .wait_for("the excess slots to be reaped", |view| {
            let tasks: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .collect();
            (tasks.len() == 1 && tasks[0].slot == 1).then_some(())
        })
        .await;
    let remaining = cluster.tasks_of(&service_id);
    assert_eq!(remaining[0].id, slot_one, "the low slot is kept");
    assert_eq!(
        remaining[0].desired_state,
        DesiredState::Running,
        "scale-down never lowers a surviving task's desired state"
    );

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// Scale-down of a service whose tasks are actually **running** on a node —
/// the shape the cluster has and the one the "6/3 forever" report was about.
///
/// The excess slots must be marked `Remove` in the store (that is the whole of
/// the orchestrator's job: the agent stops the container, and only then may the
/// reaper delete the task — architecture §4 rule 5), while the surviving slots
/// are left strictly alone. The previous test covers slots that never ran, and
/// those are deleted outright, so it could not tell a working scale-down from
/// one that only ever manages to delete never-started tasks.
#[tokio::test(flavor = "multi_thread")]
async fn scaling_down_marks_running_tasks_for_removal_and_keeps_them_until_they_stop() {
    let cluster = TestCluster::start().await;
    let service = sample_service("web", 6);
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    cluster
        .wait_for("six tasks", |view| {
            let count = view
                .tasks()
                .iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .count();
            (count == 6).then_some(())
        })
        .await;

    // Bind and run every task, the way the scheduler and then the agent would.
    let node = cluster.node_id().clone();
    for task in cluster.tasks_of(&service_id) {
        run_task(cluster.store(), &task.id, &node).await;
    }

    scale_service(cluster.store(), &service_id, 3).await;

    cluster
        .wait_for("the excess slots to be marked for removal", |view| {
            let tasks: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .collect();
            let marked = tasks
                .iter()
                .filter(|t| t.slot > 3 && t.desired_state == DesiredState::Remove)
                .count();
            (tasks.len() == 6 && marked == 3).then_some(())
        })
        .await;

    for task in cluster.tasks_of(&service_id) {
        let expected = if task.slot > 3 {
            DesiredState::Remove
        } else {
            DesiredState::Running
        };
        assert_eq!(
            task.desired_state, expected,
            "slot {} of a 6→3 scale-down",
            task.slot
        );
        assert_eq!(
            task.status.state,
            TaskState::Running,
            "the orchestrator never touches observed state"
        );
    }
    // A running task marked for removal keeps its object — and with it its
    // jail, clone and epairs — until the agent reports it stopped.
    cluster
        .stays(
            QUIET,
            "a running task is not deleted under the agent",
            |view| {
                view.tasks()
                    .iter()
                    .filter(|t| t.service_id.as_ref() == Some(&service_id))
                    .count()
                    == 6
            },
        )
        .await;

    // The agent stops them; now the reaper may collect them.
    for task in cluster.tasks_of(&service_id) {
        if task.slot > 3 {
            testing::set_task_state(cluster.store(), &task.id, TaskState::Shutdown).await;
        }
    }
    cluster
        .wait_for("the stopped tasks to be reaped", |view| {
            let tasks: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .collect();
            (tasks.len() == 3 && tasks.iter().all(|t| t.slot <= 3)).then_some(())
        })
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_service_removes_every_task() {
    let cluster = TestCluster::start().await;
    let service = sample_service("web", 2);
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    cluster
        .wait_for("two tasks", |view| {
            let count = view
                .tasks()
                .iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .count();
            (count == 2).then_some(())
        })
        .await;

    cluster
        .store()
        .propose(vec![StoreAction::Remove {
            kind: ObjectKind::Service,
            id: service_id.clone(),
        }])
        .await
        .expect("service deleted");

    cluster
        .wait_for("every task to be gone", |view| {
            let count = view
                .tasks()
                .iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .count();
            (count == 0).then_some(())
        })
        .await;
    cluster
        .stays(
            QUIET,
            "no task is recreated for a deleted service",
            |view| {
                !view
                    .tasks()
                    .iter()
                    .any(|t| t.service_id.as_ref() == Some(&service_id))
            },
        )
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// A competing writer touching the very objects a reconciliation decided on:
/// the transaction is rejected, the loop re-reads and re-decides, and the
/// service still converges (architecture §6.4).
#[tokio::test(flavor = "multi_thread")]
async fn a_competing_writer_does_not_stall_reconciliation() {
    let cluster = TestCluster::start().await;
    let service = sample_service("web", 4);
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    cluster
        .wait_for("four tasks", |view| {
            let count = view
                .tasks()
                .iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .count();
            (count == 4).then_some(())
        })
        .await;

    // Rewrite the tasks the scale-down is about to touch, from another
    // writer, while it runs.
    let store = cluster.store().clone();
    let racing_service = service_id.clone();
    let racer = tokio::spawn(async move {
        for round in 0..80_u32 {
            let victims: Vec<Task> = {
                let view = store.view();
                view.tasks()
                    .into_iter()
                    .filter(|t| t.service_id.as_ref() == Some(&racing_service) && t.slot > 1)
                    .map(|t| (*t).clone())
                    .collect()
            };
            for mut task in victims {
                task.status = TaskStatus::new(task.status.state, format!("racing write {round}"));
                // Rejections are the point of the exercise.
                let _ = store
                    .propose(vec![StoreAction::Update(StoreObject::Task(task))])
                    .await;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });

    scale_service(cluster.store(), &service_id, 1).await;
    cluster
        .wait_for("the service to converge to one slot", |view| {
            let tasks: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .collect();
            (tasks.len() == 1 && tasks[0].slot == 1).then_some(())
        })
        .await;
    racer.await.expect("racing writer finished");

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// Cancelling the token stops every loop (leadership loss, shutdown).
#[tokio::test(flavor = "multi_thread")]
async fn cancelling_the_token_stops_the_loops() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());
    shutdown.cancel();
    // `join` returning is the assertion: it awaits all four tasks.
    tokio::time::timeout(Duration::from_secs(5), orchestrator.join())
        .await
        .expect("loops stopped");

    let service = sample_service("web", 1);
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");
    cluster
        .stays(QUIET, "no task is created once the loops stopped", |view| {
            !view
                .tasks()
                .iter()
                .any(|t: &std::sync::Arc<Task>| t.service_id.as_ref() == Some(&service_id))
        })
        .await;

    cluster.shutdown().await;
}
