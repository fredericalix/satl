// SPDX-License-Identifier: BSD-2-Clause
//! Restart supervisor (SWK §7.4) and task reaper (SWK §7.5) scenarios
//! against a real single-node store.
//!
//! The "agent" is the test itself: it reports terminal task states through
//! the store exactly as the dispatcher would.

use std::time::{Duration, SystemTime};

use satl_core::{DesiredState, Id, RestartCondition, StoreAction, StoreObject, Task, TaskState};
use satl_orchestrator::{Cadence, Orchestrator, OrchestratorConfig};
use tokio_util::sync::CancellationToken;

#[path = "../src/testing.rs"]
mod testing;

use testing::{TestCluster, planted_task, sample_service, set_task_state, with_restart};

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

/// Restart delay used by the restart tests: long enough to observe that the
/// replacement waits, short enough to keep tests fast.
const RESTART_DELAY: Duration = Duration::from_millis(300);

/// How long a "nothing happens" assertion watches for.
const QUIET: Duration = Duration::from_millis(500);

/// Tasks of a service, newest last.
fn tasks(cluster: &TestCluster, service_id: &Id) -> Vec<Task> {
    cluster.tasks_of(service_id)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_task_is_replaced_in_the_same_slot_after_the_delay() {
    let cluster = TestCluster::start().await;
    let service = with_restart(
        sample_service("web", 1),
        RestartCondition::Any,
        RESTART_DELAY,
        0,
    );
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let first: Task = cluster
        .wait_for("the first task", |view| {
            view.tasks()
                .into_iter()
                .find(|t| t.service_id.as_ref() == Some(&service_id))
                .map(|t| (*t).clone())
        })
        .await;

    // The agent reports a crash.
    set_task_state(cluster.store(), &first.id, TaskState::Failed).await;

    // Nothing happens during the restart delay.
    cluster
        .stays(
            RESTART_DELAY / 2,
            "no replacement before the delay",
            |view| {
                view.tasks()
                    .iter()
                    .filter(|t| t.service_id.as_ref() == Some(&service_id))
                    .count()
                    == 1
            },
        )
        .await;

    cluster
        .wait_for("the replacement task", |view| {
            let count = view
                .tasks()
                .iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .count();
            (count == 2).then_some(())
        })
        .await;

    let all = tasks(&cluster, &service_id);
    let old = all.iter().find(|t| t.id == first.id).expect("old task");
    let new = all.iter().find(|t| t.id != first.id).expect("replacement");
    assert_eq!(
        old.desired_state,
        DesiredState::Shutdown,
        "the predecessor is shut down"
    );
    assert_eq!(new.slot, first.slot, "replacements reuse the slot");
    assert_eq!(
        new.desired_state,
        DesiredState::Running,
        "M1 creates the replacement at RUNNING directly"
    );
    assert_eq!(new.spec_version, first.spec_version);
    assert!(new.status.state <= TaskState::Pending, "a fresh task");

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_condition_none_never_replaces() {
    let cluster = TestCluster::start().await;
    let service = with_restart(
        sample_service("oneshot", 1),
        RestartCondition::None,
        Duration::from_millis(10),
        0,
    );
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let first: Task = cluster
        .wait_for("the first task", |view| {
            view.tasks()
                .into_iter()
                .find(|t| t.service_id.as_ref() == Some(&service_id))
                .map(|t| (*t).clone())
        })
        .await;
    set_task_state(cluster.store(), &first.id, TaskState::Failed).await;

    // Neither the supervisor nor the reconcile pass may resurrect the slot.
    cluster
        .stays(QUIET, "no replacement for restart-condition none", |view| {
            let of_service: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .collect();
            of_service.len() == 1 && of_service[0].id == first.id
        })
        .await;
    let survivor = cluster.tasks_of(&service_id).remove(0);
    assert_eq!(survivor.status.state, TaskState::Failed);
    assert_eq!(
        survivor.desired_state,
        DesiredState::Running,
        "a task nobody restarts keeps its desired state"
    );

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn on_failure_ignores_a_clean_exit() {
    let cluster = TestCluster::start().await;
    let service = with_restart(
        sample_service("batch", 1),
        RestartCondition::OnFailure,
        Duration::from_millis(10),
        0,
    );
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let first: Task = cluster
        .wait_for("the first task", |view| {
            view.tasks()
                .into_iter()
                .find(|t| t.service_id.as_ref() == Some(&service_id))
                .map(|t| (*t).clone())
        })
        .await;
    set_task_state(cluster.store(), &first.id, TaskState::Complete).await;

    cluster
        .stays(QUIET, "a clean exit is not a failure", |view| {
            view.tasks()
                .iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .count()
                == 1
        })
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn max_attempts_caps_the_number_of_replacements() {
    let cluster = TestCluster::start().await;
    let service = with_restart(
        sample_service("flaky", 1),
        RestartCondition::Any,
        Duration::from_millis(20),
        1,
    );
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let first: Task = cluster
        .wait_for("the first task", |view| {
            view.tasks()
                .into_iter()
                .find(|t| t.service_id.as_ref() == Some(&service_id))
                .map(|t| (*t).clone())
        })
        .await;
    set_task_state(cluster.store(), &first.id, TaskState::Failed).await;

    // Attempt 1 of 1.
    let second: Task = cluster
        .wait_for("the one allowed replacement", |view| {
            view.tasks()
                .into_iter()
                .find(|t| t.service_id.as_ref() == Some(&service_id) && t.id != first.id)
                .map(|t| (*t).clone())
        })
        .await;
    set_task_state(cluster.store(), &second.id, TaskState::Failed).await;

    cluster
        .stays(QUIET, "max_attempts is not exceeded", |view| {
            view.tasks()
                .iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .count()
                == 2
        })
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_reaper_prunes_slot_history_beyond_the_limit() {
    let cluster = TestCluster::start().await;
    // restart-condition none: the supervisor stays out of this test.
    let service = with_restart(
        sample_service("web", 1),
        RestartCondition::None,
        Duration::from_millis(10),
        0,
    );
    let service_id = service.id.clone();
    let base = SystemTime::now() - Duration::from_hours(1);

    // One live task in slot 1 plus seven terminated ones, oldest first.
    let live = planted_task(
        &service,
        1,
        TaskState::Running,
        DesiredState::Running,
        SystemTime::now(),
    );
    let history: Vec<Task> = (0..7_u64)
        .map(|age| {
            planted_task(
                &service,
                1,
                TaskState::Failed,
                DesiredState::Shutdown,
                base + Duration::from_secs(age),
            )
        })
        .collect();
    let oldest: Vec<Id> = history.iter().take(2).map(|t| t.id.clone()).collect();
    let kept: Vec<Id> = history.iter().skip(2).map(|t| t.id.clone()).collect();

    let mut actions = vec![
        StoreAction::Create(StoreObject::Service(service)),
        StoreAction::Create(StoreObject::Task(live.clone())),
    ];
    actions.extend(
        history
            .into_iter()
            .map(|t| StoreAction::Create(StoreObject::Task(t))),
    );
    cluster
        .store()
        .propose(actions)
        .await
        .expect("history planted");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    cluster
        .wait_for("history pruned to the retention limit", |view| {
            let count = view
                .tasks()
                .iter()
                .filter(|t| t.service_id.as_ref() == Some(&service_id))
                .count();
            // 5 retained terminal tasks + the live one.
            (count == 6).then_some(())
        })
        .await;

    let view = cluster.store().view();
    for id in &oldest {
        assert!(view.task(id).is_none(), "oldest history is pruned first");
    }
    for id in &kept {
        assert!(view.task(id).is_some(), "the newest 5 are retained");
    }
    assert!(view.task(&live.id).is_some(), "live tasks are never pruned");
    drop(view);

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn removed_tasks_are_deleted_only_once_they_stopped() {
    let cluster = TestCluster::start().await;
    let service = sample_service("web", 1);
    let service_id = service.id.clone();
    // Two occupied slots for a one-replica service, so the orchestrator owns a
    // removal; both are running, so the reaper must wait for one to stop. Which
    // one goes is not a guess: neither is more loaded than the other and both
    // serve, so the tie rule decides and the higher slot number loses
    // (`satl_orchestrator::task::slots_to_remove`, SWK §7.8).
    let keeper = planted_task(
        &service,
        1,
        TaskState::Running,
        DesiredState::Running,
        SystemTime::now(),
    );
    let running = planted_task(
        &service,
        9,
        TaskState::Running,
        DesiredState::Running,
        SystemTime::now(),
    );
    let keeper_id = keeper.id.clone();
    let running_id = running.id.clone();
    cluster
        .store()
        .propose(vec![
            StoreAction::Create(StoreObject::Service(service)),
            StoreAction::Create(StoreObject::Task(keeper)),
            StoreAction::Create(StoreObject::Task(running)),
        ])
        .await
        .expect("tasks planted");

    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    // The orchestrator marks the out-of-range slot for removal...
    cluster
        .wait_for("the task to be marked for removal", |view| {
            view.task(&running_id)
                .filter(|t| t.desired_state == DesiredState::Remove)
                .map(|_| ())
        })
        .await;
    // ...but the reaper leaves it alone while it may still hold a jail.
    cluster
        .stays(QUIET, "a running task is never deleted", |view| {
            view.task(&running_id).is_some()
        })
        .await;

    // The agent reports the shutdown; now it can go.
    set_task_state(cluster.store(), &running_id, TaskState::Shutdown).await;
    cluster
        .wait_for("the stopped task to be deleted", |view| {
            view.task(&running_id).is_none().then_some(())
        })
        .await;

    // The surviving slot is untouched: a scale-down never disturbs what it keeps.
    let remaining = cluster.tasks_of(&service_id);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, keeper_id);
    assert_eq!(remaining[0].slot, 1);
    assert_eq!(remaining[0].desired_state, DesiredState::Running);

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// The newest task of a service's history, once it holds exactly `count` tasks.
async fn nth_task(cluster: &TestCluster, service_id: &Id, count: usize) -> Task {
    cluster
        .wait_for("the next task of the slot", |view| {
            let mut tasks: Vec<Task> = view
                .tasks()
                .into_iter()
                .filter(|t| t.service_id.as_ref() == Some(service_id))
                .map(|t| (*t).clone())
                .collect();
            tasks.sort_by(|a, b| {
                a.meta
                    .created_at
                    .cmp(&b.meta.created_at)
                    .then(a.id.cmp(&b.id))
            });
            (tasks.len() == count).then(|| tasks.pop().expect("count >= 1"))
        })
        .await
}

/// The carried gap (SWK §7.9): `max_attempts` must survive a leadership change.
///
/// A supervisor that keeps its attempt history in memory hands every slot a
/// fresh budget when a new leader takes over — so a task that crash-loops
/// through an election restarts forever, and `max_attempts` becomes "per
/// leader" rather than "per replica". Here the history is derived from the
/// store's own task history on every pass, so the second supervisor reaches the
/// same verdict as the first.
///
/// "A new leader" is exactly what this does: cancel the running loops and start
/// a fresh set against the same store, the way the allocator's tests simulate an
/// election.
#[tokio::test(flavor = "multi_thread")]
async fn the_restart_budget_survives_a_leader_change() {
    let cluster = TestCluster::start().await;
    // Two attempts, so the budget is spent across the election rather than
    // before it: one restart under the first leader, one under the second.
    let service = with_restart(
        sample_service("web", 1),
        RestartCondition::Any,
        Duration::from_millis(20),
        2,
    );
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");

    // Leader 1: the original task fails and spends the first attempt.
    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());
    let first = nth_task(&cluster, &service_id, 1).await;
    set_task_state(cluster.store(), &first.id, TaskState::Failed).await;
    let second = nth_task(&cluster, &service_id, 2).await;
    shutdown.cancel();
    orchestrator.join().await;

    // The election: a brand-new set of loops, with nothing in memory.
    let shutdown = CancellationToken::new();
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    // The second attempt is still available, and is spent.
    set_task_state(cluster.store(), &second.id, TaskState::Failed).await;
    let third = nth_task(&cluster, &service_id, 3).await;
    assert_eq!(third.slot, 1, "replacements stay in the slot");

    // And now the budget is gone — which is the whole point: under the old
    // in-memory history this third failure would have been the new leader's
    // first, and the slot would have restarted forever.
    set_task_state(cluster.store(), &third.id, TaskState::Failed).await;
    cluster
        .stays(
            QUIET,
            "the budget did not reset with the election",
            |view| {
                view.tasks()
                    .iter()
                    .filter(|t| t.service_id.as_ref() == Some(&service_id))
                    .count()
                    == 3
            },
        )
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    cluster.shutdown().await;
}
