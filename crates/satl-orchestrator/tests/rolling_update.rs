// SPDX-License-Identifier: BSD-2-Clause
//! Rolling updates and rollbacks, against a real single-node store.
//!
//! The store is `satl-cluster`'s in-process Raft harness (a real FSM in a temp
//! dir), so these exercise the real watch feed, the real optimistic concurrency
//! and the real proposal path — the loops are wired exactly as `satld` wires
//! them.
//!
//! The other half of the setup is [`Agent`]: a deliberately minimal stand-in
//! for `satl-agent`, which walks every task towards its desired state and
//! reports the result back into the store. It is what makes these tests about
//! the *manager's* decisions: the updater cannot tell this agent from a real
//! one, and a broken image is expressed the way a node would express it — the
//! task reports `FAILED`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use satl_cluster::ClusterStore;
use satl_core::{
    DesiredState, FailureAction, Id, StoreAction, StoreObject, Task, TaskState, TaskStatus,
    UpdateConfig, UpdateOrder, UpdateStateKind,
};
use satl_orchestrator::{Cadence, Orchestrator, OrchestratorConfig};
use tokio_util::sync::CancellationToken;

#[path = "../src/testing.rs"]
mod testing;

use testing::{TestCluster, sample_service, update_spec, with_restart, with_update};

/// The image every service starts on, and the two it is updated to.
const WORKING: &str = "127.0.0.1:5000/freebsd-nginx:1";
const NEXT: &str = "127.0.0.1:5000/freebsd-nginx:2";
const BROKEN: &str = "127.0.0.1:5000/freebsd-nginx:broken";

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

/// An update configuration with test-sized windows.
fn config(parallelism: u64, order: UpdateOrder, failure_action: FailureAction) -> UpdateConfig {
    UpdateConfig {
        parallelism,
        delay: Duration::ZERO,
        failure_action,
        monitor: Duration::from_millis(200),
        max_failure_ratio: 0.0,
        order,
    }
}

/// How long a "nothing happens" assertion watches for.
const QUIET: Duration = Duration::from_millis(600);

/// A stand-in for `satl-agent`: drives every task of the cluster towards its
/// desired state and reports what happened.
///
/// - desired `READY` and not prepared yet ⇒ report `READY`;
/// - desired `RUNNING` and not running yet ⇒ report `RUNNING`, unless the
///   task's image is the broken one (or [`Agent::break_everything`] has been
///   called), in which case report `FAILED` — which is exactly what a node does
///   with an image whose entrypoint dies;
/// - desired `SHUTDOWN` or `REMOVE` and still alive ⇒ report `SHUTDOWN`.
///
/// Every task it touches is also bound to a node, since a real task reaches
/// `RUNNING` only on one.
struct Agent {
    store: ClusterStore,
    node: Id,
    /// Tasks whose image contains this are failed instead of started.
    broken_image: String,
    /// Fails every task, whatever its image: how a rollback is made to fail.
    fail_everything: Arc<AtomicBool>,
    /// How many tasks this agent has reported `RUNNING`.
    started: Arc<AtomicUsize>,
}

impl Agent {
    fn new(cluster: &TestCluster) -> Self {
        Self {
            store: cluster.store().clone(),
            node: cluster.node_id().clone(),
            broken_image: BROKEN.to_owned(),
            fail_everything: Arc::new(AtomicBool::new(false)),
            started: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Spawns the agent loop; it stops when `shutdown` is cancelled.
    fn spawn(self, shutdown: CancellationToken) -> (tokio::task::JoinHandle<()>, AgentHandle) {
        let handle = AgentHandle {
            fail_everything: Arc::clone(&self.fail_everything),
            started: Arc::clone(&self.started),
        };
        let join = tokio::spawn(async move {
            while !shutdown.is_cancelled() {
                self.step().await;
                // 25 ms: fast against a 200 ms monitor window, and cheap enough
                // that eight of these agents in parallel do not saturate the
                // machine every test file runs on.
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        });
        (join, handle)
    }

    /// One pass over every task in the store.
    async fn step(&self) {
        let tasks: Vec<Task> = {
            let view = self.store.view();
            view.tasks().iter().map(|task| (**task).clone()).collect()
        };
        for task in tasks {
            let Some(next) = self.next_state(&task) else {
                continue;
            };
            if next == TaskState::Running {
                self.started.fetch_add(1, Ordering::SeqCst);
            }
            let mut updated = task;
            updated.node_id = Some(self.node.clone());
            updated.status = TaskStatus::new(next, "reported by the test agent");
            // Stamped the way `satl_dispatcher::status` stamps it on the way
            // into the store, because that is the field the updater's monitor
            // window reads (`task_timestamp`): without it these tests would
            // exercise the fallback to the agent's own clock and prove nothing
            // about the path the cluster takes.
            updated.status.applied_at = Some(std::time::SystemTime::now());
            // A lost race is a non-event: the next pass sees the new state.
            let _ = self
                .store
                .propose(vec![StoreAction::Update(StoreObject::Task(updated))])
                .await;
        }
    }

    /// What this task's node would report next, or `None` when it is already
    /// where the manager wants it.
    fn next_state(&self, task: &Task) -> Option<TaskState> {
        let observed = task.status.state;
        if observed.is_terminal() {
            return None;
        }
        if task.desired_state >= DesiredState::Shutdown {
            return Some(TaskState::Shutdown);
        }
        let step = match task.desired_state {
            DesiredState::Ready if observed < TaskState::Ready => TaskState::Ready,
            DesiredState::Running if observed < TaskState::Running => TaskState::Running,
            // Already where the manager wants it: a node reports nothing, and in
            // particular a *running* task is never disturbed by the failure
            // injection below.
            _ => return None,
        };
        // A broken image fails while the task is being *prepared*, before any
        // promotion: that is what a pull that 404s does, and it is the shape the
        // cluster produced — terminal at desired READY, which no restart policy
        // will replace. Failing only at the RUNNING transition would be a
        // gentler and less realistic agent.
        if self.fail_everything.load(Ordering::SeqCst)
            || task.spec.container.image.contains(&self.broken_image)
        {
            return Some(TaskState::Failed);
        }
        Some(step)
    }
}

/// The knobs a test turns while the agent runs.
struct AgentHandle {
    fail_everything: Arc<AtomicBool>,
    started: Arc<AtomicUsize>,
}

impl AgentHandle {
    /// From now on, every task fails to start.
    fn break_everything(&self) {
        self.fail_everything.store(true, Ordering::SeqCst);
    }

    fn started(&self) -> usize {
        self.started.load(Ordering::SeqCst)
    }
}

/// The live tasks of a service, by slot: desired at most `RUNNING` and not
/// terminal — what the cluster is actually trying to run.
fn live(cluster: &TestCluster, service_id: &Id) -> Vec<Task> {
    cluster
        .tasks_of(service_id)
        .into_iter()
        .filter(|task| {
            task.desired_state <= DesiredState::Running && !task.status.state.is_terminal()
        })
        .collect()
}

/// The images the service is actually serving, one entry per serving task.
fn serving_images(cluster: &TestCluster, service_id: &Id) -> Vec<String> {
    live(cluster, service_id)
        .into_iter()
        .filter(|task| task.status.state == TaskState::Running)
        .map(|task| task.spec.container.image)
        .collect()
}

/// The `UpdateStatus` state of a service, if it has one.
fn update_state(cluster: &TestCluster, service_id: &Id) -> Option<UpdateStateKind> {
    let view = cluster.store().view();
    view.service(service_id)
        .and_then(|service| service.update_status.as_ref().map(|status| status.state))
}

/// A service with `replicas` tasks, all reported running, and the loops going.
async fn running_service(
    cluster: &TestCluster,
    service: satl_core::Service,
    replicas: usize,
) -> Id {
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");
    cluster
        .wait_for("every slot running the working image", |_| {
            (serving_images(cluster, &service_id).len() == replicas).then_some(())
        })
        .await;
    service_id
}

/// The whole of a plain rolling update: every slot ends on the new image, the
/// predecessors are stopped rather than deleted, and the status says so.
#[tokio::test(flavor = "multi_thread")]
async fn an_image_update_replaces_every_slot_and_reports_completed() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let (agent, _handle) = Agent::new(&cluster).spawn(shutdown.clone());
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let service = with_update(
        sample_service("web", 3),
        config(1, UpdateOrder::StopFirst, FailureAction::Pause),
    );
    let service_id = running_service(&cluster, service, 3).await;
    assert_eq!(
        update_state(&cluster, &service_id),
        None,
        "creating a service is not an update"
    );

    update_spec(cluster.store(), &service_id, |spec| {
        spec.task.container.image = NEXT.to_owned();
    })
    .await;

    cluster
        .wait_for("the update to report itself completed", |_| {
            (update_state(&cluster, &service_id) == Some(UpdateStateKind::Completed)).then_some(())
        })
        .await;

    let images = serving_images(&cluster, &service_id);
    assert_eq!(images.len(), 3, "still three replicas: {images:?}");
    assert!(
        images.iter().all(|image| image == NEXT),
        "every slot is on the new image: {images:?}"
    );
    let slots: Vec<u64> = live(&cluster, &service_id).iter().map(|t| t.slot).collect();
    assert_eq!(slots, vec![1, 2, 3], "the same slots, not new ones");

    // The predecessors are stopped and kept as history (SWK §4.6): the reaper
    // prunes them, the updater never deletes a task.
    let stopped: Vec<Task> = cluster
        .tasks_of(&service_id)
        .into_iter()
        .filter(|task| task.spec.container.image == WORKING)
        .collect();
    assert_eq!(stopped.len(), 3);
    for task in &stopped {
        assert_eq!(
            task.desired_state,
            DesiredState::Shutdown,
            "slot {}",
            task.slot
        );
        assert_eq!(task.status.state, TaskState::Shutdown);
    }

    let view = cluster.store().view();
    let service = view.service(&service_id).expect("service");
    let status = service.update_status.as_ref().expect("status");
    assert!(status.started_at.is_some() && status.completed_at.is_some());
    assert_eq!(status.message, "update completed: 3 slots updated");
    drop(view);

    shutdown.cancel();
    orchestrator.join().await;
    agent.await.expect("agent stops");
    cluster.shutdown().await;
}

/// `parallelism = 1` means one slot at a time, and this asserts the property
/// that gives the update its name: at every instant, at most one slot of the
/// service is not serving.
#[tokio::test(flavor = "multi_thread")]
async fn one_slot_at_a_time_leaves_every_other_slot_serving() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let (agent, _handle) = Agent::new(&cluster).spawn(shutdown.clone());
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let service = with_update(
        sample_service("web", 4),
        config(1, UpdateOrder::StopFirst, FailureAction::Pause),
    );
    let service_id = running_service(&cluster, service, 4).await;

    update_spec(cluster.store(), &service_id, |spec| {
        spec.task.container.image = NEXT.to_owned();
    })
    .await;

    // Sampled from outside, while the update runs: how many of the four slots
    // hold no serving task. `stays` polls every 5 ms.
    let watch = async {
        loop {
            let serving: std::collections::BTreeSet<u64> = live(&cluster, &service_id)
                .into_iter()
                .filter(|task| task.status.state == TaskState::Running)
                .map(|task| task.slot)
                .collect();
            assert!(
                serving.len() >= 3,
                "only {} of 4 slots serving: a parallelism of 1 must never take \
                 two slots out at once (serving {serving:?})",
                serving.len()
            );
            if update_state(&cluster, &service_id) == Some(UpdateStateKind::Completed) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(20), watch)
        .await
        .expect("the update completes");

    let images = serving_images(&cluster, &service_id);
    assert_eq!(images.len(), 4);
    assert!(images.iter().all(|image| image == NEXT), "{images:?}");

    shutdown.cancel();
    orchestrator.join().await;
    agent.await.expect("agent stops");
    cluster.shutdown().await;
}

/// A broken image: the new tasks fail, the ratio is exceeded, and the service
/// goes back to the spec that worked — with no operator involved.
#[tokio::test(flavor = "multi_thread")]
async fn a_broken_image_rolls_back_to_the_working_spec_on_its_own() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let (agent, _handle) = Agent::new(&cluster).spawn(shutdown.clone());
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    // Bounded restarts, so the supervisor's replacements do not churn forever
    // while the assertions run.
    let service = with_update(
        with_restart(
            sample_service("web", 3),
            satl_core::RestartCondition::Any,
            Duration::from_millis(50),
            2,
        ),
        config(1, UpdateOrder::StopFirst, FailureAction::Rollback),
    );
    let service_id = running_service(&cluster, service, 3).await;

    update_spec(cluster.store(), &service_id, |spec| {
        spec.task.container.image = BROKEN.to_owned();
    })
    .await;

    cluster
        .wait_for("the rollback to complete", |_| {
            (update_state(&cluster, &service_id) == Some(UpdateStateKind::RollbackCompleted))
                .then_some(())
        })
        .await;

    cluster
        .wait_for("every slot serving the working image again", |_| {
            let images = serving_images(&cluster, &service_id);
            (images.len() == 3 && images.iter().all(|image| image == WORKING)).then_some(())
        })
        .await;

    let view = cluster.store().view();
    let service = view.service(&service_id).expect("service");
    assert_eq!(service.spec.task.container.image, WORKING);
    assert!(
        service.previous_spec.is_none(),
        "cleared on rollback, so nothing can roll forward into the broken spec"
    );
    let status = service.update_status.as_ref().expect("status");
    assert!(
        status.message.starts_with("rollback completed"),
        "{status:?}"
    );
    drop(view);

    // And it stays there: no second rollback, no oscillation.
    cluster
        .stays(QUIET, "the service stays on the working spec", |view| {
            view.service(&service_id)
                .is_some_and(|service| service.spec.task.container.image == WORKING)
        })
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    agent.await.expect("agent stops");
    cluster.shutdown().await;
}

/// A rollback that fails pauses, and never rolls back again (architecture §5).
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_that_fails_pauses_instead_of_rolling_back_again() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let (agent, handle) = Agent::new(&cluster).spawn(shutdown.clone());
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let mut service = with_update(
        with_restart(
            sample_service("web", 2),
            satl_core::RestartCondition::Any,
            Duration::from_millis(50),
            1,
        ),
        config(1, UpdateOrder::StopFirst, FailureAction::Rollback),
    );
    service.spec.rollback = Some(config(1, UpdateOrder::StopFirst, FailureAction::Rollback));
    let service_id = running_service(&cluster, service, 2).await;

    // The node is broken as well as the image, from here on: every task that
    // still has to be started fails, whatever its spec, while the two that are
    // already running are left alone. Set *before* the update rather than
    // between the rollback's start and its first task, because that window is
    // now microseconds wide — the tasks a rollback keeps settle immediately —
    // and a test must not depend on winning a race.
    handle.break_everything();
    update_spec(cluster.store(), &service_id, |spec| {
        spec.task.container.image = BROKEN.to_owned();
    })
    .await;
    cluster
        .wait_for("the rollback to start", |_| {
            matches!(
                update_state(&cluster, &service_id),
                Some(UpdateStateKind::RollbackStarted | UpdateStateKind::RollbackPaused)
            )
            .then_some(())
        })
        .await;

    cluster
        .wait_for("the rollback to pause", |_| {
            (update_state(&cluster, &service_id) == Some(UpdateStateKind::RollbackPaused))
                .then_some(())
        })
        .await;

    let image = {
        let view = cluster.store().view();
        let service = view.service(&service_id).expect("service");
        service.spec.task.container.image.clone()
    };
    assert_eq!(image, WORKING, "the rollback's own spec, not swapped again");

    // A paused rollback is inert: no further spec change, no state change.
    cluster
        .stays(QUIET, "a paused rollback does nothing further", |view| {
            view.service(&service_id).is_some_and(|service| {
                service.spec.task.container.image == image
                    && service.update_status.as_ref().map(|status| status.state)
                        == Some(UpdateStateKind::RollbackPaused)
            })
        })
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    agent.await.expect("agent stops");
    cluster.shutdown().await;
}

/// `start-first`: the replacement serves before the predecessor is stopped, so
/// the slot is never without a serving task.
#[tokio::test(flavor = "multi_thread")]
async fn start_first_never_leaves_a_slot_without_a_serving_task() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let (agent, _handle) = Agent::new(&cluster).spawn(shutdown.clone());
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let service = with_update(
        sample_service("web", 3),
        config(1, UpdateOrder::StartFirst, FailureAction::Pause),
    );
    let service_id = running_service(&cluster, service, 3).await;

    update_spec(cluster.store(), &service_id, |spec| {
        spec.task.container.image = NEXT.to_owned();
    })
    .await;

    let watch = async {
        loop {
            let serving: std::collections::BTreeSet<u64> = live(&cluster, &service_id)
                .into_iter()
                .filter(|task| task.status.state == TaskState::Running)
                .map(|task| task.slot)
                .collect();
            assert_eq!(
                serving.len(),
                3,
                "start-first must keep every slot serving throughout: {serving:?}"
            );
            if update_state(&cluster, &service_id) == Some(UpdateStateKind::Completed) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(20), watch)
        .await
        .expect("the update completes");

    let images = serving_images(&cluster, &service_id);
    assert_eq!(images.len(), 3);
    assert!(images.iter().all(|image| image == NEXT), "{images:?}");

    shutdown.cancel();
    orchestrator.join().await;
    agent.await.expect("agent stops");
    cluster.shutdown().await;
}

/// A leadership change in the middle of an update: the new leader **resumes**.
///
/// The update's whole state is in the store, so this is the same test as
/// "another manager takes over": the old leader's loops are cancelled and a
/// fresh set is started on the same store, with no hand-over of any kind. What
/// must not happen is a restart — a second replacement per slot — which is why
/// the assertion counts the tasks the update created rather than watching it
/// finish.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_interrupted_by_a_leadership_change_resumes_without_rolling_twice() {
    let cluster = TestCluster::start().await;
    let agent_stop = CancellationToken::new();
    let (agent, handle) = Agent::new(&cluster).spawn(agent_stop.clone());

    let first_term = CancellationToken::new();
    let first =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), first_term.clone());

    let service = with_update(
        sample_service("web", 4),
        config(1, UpdateOrder::StopFirst, FailureAction::Pause),
    );
    let service_id = running_service(&cluster, service, 4).await;
    let before = handle.started();

    update_spec(cluster.store(), &service_id, |spec| {
        spec.task.container.image = NEXT.to_owned();
    })
    .await;

    // Interrupt as soon as the update has actually started a slot, so the
    // hand-over lands mid-batch.
    cluster
        .wait_for("the first slot to be updated", |_| {
            serving_images(&cluster, &service_id)
                .iter()
                .any(|image| image == NEXT)
                .then_some(())
        })
        .await;
    let started_at = {
        let view = cluster.store().view();
        view.service(&service_id)
            .and_then(|service| service.update_status.as_ref().and_then(|s| s.started_at))
            .expect("an update in flight has a start time")
    };

    // Leadership lost: every loop stops where it is.
    first_term.cancel();
    first.join().await;
    assert_eq!(
        update_state(&cluster, &service_id),
        Some(UpdateStateKind::Updating),
        "the update is in flight and unfinished when the leader goes"
    );

    // Leadership gained elsewhere: a fresh set of loops, same store.
    let second_term = CancellationToken::new();
    let second =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), second_term.clone());

    cluster
        .wait_for("the new leader to finish the update", |_| {
            (update_state(&cluster, &service_id) == Some(UpdateStateKind::Completed)).then_some(())
        })
        .await;

    let images = serving_images(&cluster, &service_id);
    assert_eq!(images.len(), 4, "{images:?}");
    assert!(images.iter().all(|image| image == NEXT), "{images:?}");

    // The anti-double-roll assertion: one replacement per slot, ever. A leader
    // that restarted the update instead of resuming it would have created a
    // second task on the new spec somewhere.
    let on_new_spec: Vec<Task> = cluster
        .tasks_of(&service_id)
        .into_iter()
        .filter(|task| task.spec.container.image == NEXT)
        .collect();
    assert_eq!(
        on_new_spec.len(),
        4,
        "four slots, four replacements: {:?}",
        on_new_spec
            .iter()
            .map(|task| (task.slot, task.status.state))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        handle.started() - before,
        4,
        "and each of them was started exactly once"
    );

    let view = cluster.store().view();
    let status = view
        .service(&service_id)
        .and_then(|service| service.update_status.clone())
        .expect("status");
    assert_eq!(
        status.started_at,
        Some(started_at),
        "the update kept its start time: resumed, not restarted"
    );
    drop(view);

    second_term.cancel();
    second.join().await;
    agent_stop.cancel();
    agent.await.expect("agent stops");
    cluster.shutdown().await;
}

/// The trap the `spec_version` contract exists for: tasks written before the
/// field existed carry `None`, which is *unequal* to every service version. If
/// the dirtiness check read that as "dirty", the first pass of the first leader
/// after an upgrade would replace every task of every service in the cluster.
#[tokio::test(flavor = "multi_thread")]
async fn tasks_with_no_spec_version_are_not_replaced() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let (agent, _handle) = Agent::new(&cluster).spawn(shutdown.clone());
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let service = with_update(
        sample_service("web", 3),
        config(1, UpdateOrder::StopFirst, FailureAction::Pause),
    );
    let service_id = running_service(&cluster, service, 3).await;
    let ids: Vec<Id> = live(&cluster, &service_id)
        .into_iter()
        .map(|task| task.id)
        .collect();

    // Strip the field behind everyone's back, the way an upgrade would leave it.
    for id in &ids {
        for _ in 0..50 {
            let mut task = {
                let view = cluster.store().view();
                (*view.task(id).expect("task")).clone()
            };
            task.spec_version = None;
            match cluster
                .store()
                .propose(vec![StoreAction::Update(StoreObject::Task(task))])
                .await
            {
                Ok(_) => break,
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
    }

    cluster
        .stays(
            QUIET,
            "no task is replaced and no update is invented",
            |view| {
                let tasks: Vec<_> = view
                    .tasks()
                    .into_iter()
                    .filter(|task| task.service_id.as_ref() == Some(&service_id))
                    .collect();
                tasks.len() == 3
                    && tasks.iter().all(|task| ids.contains(&task.id))
                    && view
                        .service(&service_id)
                        .is_some_and(|service| service.update_status.is_none())
            },
        )
        .await;

    shutdown.cancel();
    orchestrator.join().await;
    agent.await.expect("agent stops");
    cluster.shutdown().await;
}

/// A change to the service that is not a change to its tasks: labels are part
/// of the spec (so `spec_version` moves) but not of the task spec, so nothing
/// is replaced. `docker service update --label-add` does not restart tasks
/// either.
#[tokio::test(flavor = "multi_thread")]
async fn a_label_only_update_replaces_nothing() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let (agent, _handle) = Agent::new(&cluster).spawn(shutdown.clone());
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let service = with_update(
        sample_service("web", 2),
        config(1, UpdateOrder::StopFirst, FailureAction::Pause),
    );
    let service_id = running_service(&cluster, service, 2).await;
    let ids: Vec<Id> = live(&cluster, &service_id)
        .into_iter()
        .map(|task| task.id)
        .collect();

    update_spec(cluster.store(), &service_id, |spec| {
        spec.annotations
            .labels
            .insert("tier".to_owned(), "front".to_owned());
    })
    .await;

    let moved = {
        let view = cluster.store().view();
        view.service(&service_id).expect("service").spec_version
    };
    cluster
        .stays(QUIET, "the tasks are left alone", |view| {
            let tasks: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|task| task.service_id.as_ref() == Some(&service_id))
                .collect();
            tasks.len() == 2 && tasks.iter().all(|task| ids.contains(&task.id))
        })
        .await;
    let view = cluster.store().view();
    let service = view.service(&service_id).expect("service");
    assert_ne!(
        Some(service.spec_version),
        live(&cluster, &service_id)[0].spec_version,
        "the spec version did move, so this really went through the deep comparison"
    );
    assert_eq!(service.spec_version, moved);
    assert!(
        service.update_status.is_none(),
        "and no update was invented"
    );
    drop(view);

    shutdown.cancel();
    orchestrator.join().await;
    agent.await.expect("agent stops");
    cluster.shutdown().await;
}
