// SPDX-License-Identifier: BSD-2-Clause
//! Global services (SWK §7.8, global orchestrator) against a real single-node
//! store, with synthetic `Node` objects standing in for a multi-node cluster.
//!
//! The store is `satl-cluster`'s in-process Raft harness (a real FSM in a temp
//! dir), and the loops are wired exactly as `satld` wires them — including the
//! real scheduler, because a global task is *preassigned* (SWK §8.6) and the
//! whole point of the eligibility rules is that this orchestrator never creates
//! a task the scheduler would refuse.
//!
//! The other half of the setup is [`Agent`], a minimal stand-in for
//! `satl-agent`: it walks tasks towards their desired state and reports back.
//! Unlike the one in `rolling_update.rs` it never *binds* a task to a node —
//! that is the scheduler's job for a replicated task and the global
//! orchestrator's for a global one, and rebinding would hide the bug these
//! tests are about.

use std::collections::BTreeSet;
use std::time::Duration;

use satl_cluster::{ClusterStore, StoreView};
use satl_core::{
    Availability, DesiredState, Id, Node, NodeState, Service, ServiceMode, StoreAction,
    StoreObject, Task, TaskState, TaskStatus, UpdateConfig, UpdateOrder, UpdateStateKind,
};
use satl_orchestrator::{Cadence, Orchestrator, OrchestratorConfig};
use satl_sched::{Scheduler, SchedulerConfig};
use tokio_util::sync::CancellationToken;

#[path = "../src/testing.rs"]
mod testing;

use testing::{
    TestCluster, planted_node, sample_service, set_task_state, update_node, update_spec,
    with_restart, with_update,
};

/// The image every service starts on, and the one it is updated to.
const WORKING: &str = "127.0.0.1:5000/freebsd-nginx:1";
const NEXT: &str = "127.0.0.1:5000/freebsd-nginx:2";

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
const QUIET: Duration = Duration::from_millis(500);

/// A global service with the default (unlimited, `any`) restart policy.
fn global_service(name: &str) -> Service {
    let mut service = sample_service(name, 1);
    service.spec.mode = ServiceMode::Global;
    service
}

/// Writes a service and returns its ID.
async fn create_service(store: &ClusterStore, service: Service) -> Id {
    let id = service.id.clone();
    store
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");
    id
}

/// Adds a synthetic node and returns its ID.
async fn add_node(store: &ClusterStore, mutate: impl FnOnce(&mut Node)) -> Id {
    let mut node = planted_node("n");
    mutate(&mut node);
    let id = node.id.clone();
    store
        .propose(vec![StoreAction::Create(StoreObject::Node(node))])
        .await
        .expect("node created");
    id
}

/// The nodes carrying a task of `service_id` that the cluster still wants there
/// — the service's effective footprint.
fn live_nodes(view: &StoreView<'_>, service_id: &Id) -> BTreeSet<Id> {
    view.tasks()
        .into_iter()
        .filter(|task| task.service_id.as_ref() == Some(service_id))
        .filter(|task| {
            task.desired_state <= DesiredState::Running && !task.status.state.is_terminal()
        })
        .filter_map(|task| task.node_id.clone())
        .collect()
}

/// Live tasks of the service, whatever their node.
fn live_tasks(view: &StoreView<'_>, service_id: &Id) -> Vec<Task> {
    view.tasks()
        .into_iter()
        .filter(|task| task.service_id.as_ref() == Some(service_id))
        .filter(|task| {
            task.desired_state <= DesiredState::Running && !task.status.state.is_terminal()
        })
        .map(|task| (*task).clone())
        .collect()
}

/// Waits until the service's footprint is exactly `expected`, and returns the
/// live tasks at that moment.
async fn wait_for_footprint(
    cluster: &TestCluster,
    service_id: &Id,
    expected: &BTreeSet<Id>,
    what: &str,
) -> Vec<Task> {
    cluster
        .wait_for(what, |view| {
            (live_nodes(view, service_id) == *expected).then(|| live_tasks(view, service_id))
        })
        .await
}

/// A stand-in for `satl-agent`: reports what a node would report, and nothing
/// else. It never assigns a node — that decision belongs to the manager.
struct Agent {
    store: ClusterStore,
}

impl Agent {
    fn spawn(store: ClusterStore, shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
        let agent = Self { store };
        tokio::spawn(async move {
            while !shutdown.is_cancelled() {
                agent.step().await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    }

    async fn step(&self) {
        let tasks: Vec<Task> = {
            let view = self.store.view();
            view.tasks().iter().map(|task| (**task).clone()).collect()
        };
        for mut task in tasks {
            if task.node_id.is_none() || task.status.state < TaskState::Assigned {
                // Not placed yet: the scheduler has not spoken.
                continue;
            }
            let next = if task.desired_state >= DesiredState::Shutdown {
                (!task.status.state.is_terminal()).then_some(TaskState::Shutdown)
            } else if task.desired_state == DesiredState::Ready {
                (task.status.state < TaskState::Ready).then_some(TaskState::Ready)
            } else {
                (task.status.state < TaskState::Running).then_some(TaskState::Running)
            };
            let Some(next) = next else { continue };
            task.status = TaskStatus::new(next, "reported by the test agent");
            // The field the updater's monitor window reads, stamped as the
            // dispatcher stamps it on the way into the store.
            task.status.applied_at = Some(std::time::SystemTime::now());
            // A lost race is a non-event: the next pass sees the new state.
            let _ = self
                .store
                .propose(vec![StoreAction::Update(StoreObject::Task(task))])
                .await;
        }
    }
}

/// Everything a test needs running: the orchestration loops, the scheduler and
/// the agent, all cancelled by one token.
struct Cluster {
    shutdown: CancellationToken,
    orchestrator: Orchestrator,
    scheduler: Scheduler,
    agent: tokio::task::JoinHandle<()>,
}

impl Cluster {
    fn spawn(cluster: &TestCluster) -> Self {
        let shutdown = CancellationToken::new();
        Self {
            orchestrator: Orchestrator::spawn_with_config(
                cluster.store().clone(),
                fast(),
                shutdown.clone(),
            ),
            scheduler: Scheduler::spawn_with_config(
                cluster.store().clone(),
                fast_scheduler(),
                shutdown.clone(),
            ),
            agent: Agent::spawn(cluster.store().clone(), shutdown.clone()),
            shutdown,
        }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        self.scheduler.join().await;
        self.orchestrator.join().await;
        self.agent.await.expect("agent stopped");
    }
}

/// One task per eligible node, each pinned to its node, each named after it,
/// and each confirmed by the scheduler on the node it was born on (SWK §7.8,
/// §8.6, §4.5).
#[tokio::test(flavor = "multi_thread")]
async fn a_global_service_gets_one_task_per_eligible_node() {
    let cluster = TestCluster::start().await;
    let n1 = add_node(cluster.store(), |_| {}).await;
    let n2 = add_node(cluster.store(), |_| {}).await;
    let service_id = create_service(cluster.store(), global_service("agent")).await;
    // The manager's own node counts: it is `Ready` and `Active` like any other.
    let expected = BTreeSet::from([cluster.node_id().clone(), n1.clone(), n2.clone()]);

    let running = Cluster::spawn(&cluster);
    let tasks = wait_for_footprint(
        &cluster,
        &service_id,
        &expected,
        "one task per eligible node",
    )
    .await;

    assert_eq!(tasks.len(), 3, "exactly one task per node: {tasks:?}");
    for task in &tasks {
        let node_id = task.node_id.as_ref().expect("born bound to a node");
        assert_eq!(task.slot, 0, "global tasks carry slot 0 (SWK §4.5)");
        assert_eq!(
            task.annotations.name,
            format!("agent.{node_id}.{}", task.id),
            "the node ID takes the slot's place in the name"
        );
    }

    // The scheduler validates the node it was given rather than choosing one.
    cluster
        .wait_for(
            "every global task to be confirmed on its own node",
            |view| {
                let tasks = live_tasks(view, &service_id);
                (tasks.len() == 3
                    && tasks
                        .iter()
                        .all(|task| task.status.state >= TaskState::Assigned))
                .then_some(())
            },
        )
        .await;

    // And no second task anywhere: the loop is idempotent.
    cluster
        .stays(QUIET, "no duplicate global task", |view| {
            live_nodes(view, &service_id) == expected && live_tasks(view, &service_id).len() == 3
        })
        .await;

    running.stop().await;
    cluster.shutdown().await;
}

/// A node joining gains a task; a node draining loses its own and gets no
/// replacement anywhere — a global task has no other node to move to.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_that_joins_gains_a_task_and_a_draining_one_loses_its_own() {
    let cluster = TestCluster::start().await;
    let n1 = add_node(cluster.store(), |_| {}).await;
    let service_id = create_service(cluster.store(), global_service("agent")).await;
    let manager = cluster.node_id().clone();

    let running = Cluster::spawn(&cluster);
    let before = wait_for_footprint(
        &cluster,
        &service_id,
        &BTreeSet::from([manager.clone(), n1.clone()]),
        "a task on each of the two nodes",
    )
    .await;
    let on_n1 = before
        .iter()
        .find(|task| task.node_id.as_ref() == Some(&n1))
        .expect("a task on n1")
        .id
        .clone();

    // A third node joins.
    let n2 = add_node(cluster.store(), |_| {}).await;
    wait_for_footprint(
        &cluster,
        &service_id,
        &BTreeSet::from([manager.clone(), n1.clone(), n2.clone()]),
        "the new node to gain a task",
    )
    .await;

    // The operator drains n1.
    update_node(cluster.store(), &n1, |node| {
        node.spec.availability = Availability::Drain;
    })
    .await;
    wait_for_footprint(
        &cluster,
        &service_id,
        &BTreeSet::from([manager.clone(), n2.clone()]),
        "the drained node to lose its task",
    )
    .await;

    let stopped = cluster
        .tasks_of(&service_id)
        .into_iter()
        .find(|task| task.id == on_n1)
        .expect("the drained node's task is kept as history");
    assert_eq!(stopped.desired_state, DesiredState::Shutdown);
    assert_eq!(
        stopped.node_id.as_ref(),
        Some(&n1),
        "it is not moved: a global task's node is its identity"
    );

    // Nothing takes its place, on n1 or anywhere else.
    cluster
        .stays(QUIET, "a drained global task gets no replacement", |view| {
            live_nodes(view, &service_id) == BTreeSet::from([manager.clone(), n2.clone()])
        })
        .await;

    // Bringing n1 back gives it a task again — the shut-down predecessor does
    // not make the node look occupied forever.
    update_node(cluster.store(), &n1, |node| {
        node.spec.availability = Availability::Active;
    })
    .await;
    wait_for_footprint(
        &cluster,
        &service_id,
        &BTreeSet::from([manager, n1, n2]),
        "the returning node to gain a task again",
    )
    .await;

    running.stop().await;
    cluster.shutdown().await;
}

/// `PAUSE` is "no new tasks, leave the running ones alone" (SWK §7.8), and a
/// `DOWN` node is not a node the service runs on.
#[tokio::test(flavor = "multi_thread")]
async fn a_paused_node_keeps_its_task_and_a_down_one_gives_it_up() {
    let cluster = TestCluster::start().await;
    let paused = add_node(cluster.store(), |_| {}).await;
    let dying = add_node(cluster.store(), |_| {}).await;
    let service_id = create_service(cluster.store(), global_service("agent")).await;
    let manager = cluster.node_id().clone();

    let running = Cluster::spawn(&cluster);
    wait_for_footprint(
        &cluster,
        &service_id,
        &BTreeSet::from([manager.clone(), paused.clone(), dying.clone()]),
        "a task on each of the three nodes",
    )
    .await;

    update_node(cluster.store(), &paused, |node| {
        node.spec.availability = Availability::Pause;
    })
    .await;
    cluster
        .stays(QUIET, "pause changes nothing at all", |view| {
            live_nodes(view, &service_id)
                == BTreeSet::from([manager.clone(), paused.clone(), dying.clone()])
        })
        .await;

    // The dispatcher's heartbeat TTL expires on the other node.
    update_node(cluster.store(), &dying, |node| {
        node.status.state = NodeState::Down;
    })
    .await;
    wait_for_footprint(
        &cluster,
        &service_id,
        &BTreeSet::from([manager, paused]),
        "the down node to give up its task",
    )
    .await;

    running.stop().await;
    cluster.shutdown().await;
}

/// A global service whose constraints no node satisfies runs nothing at all,
/// and starts running the moment one node qualifies.
#[tokio::test(flavor = "multi_thread")]
async fn a_global_service_with_no_eligible_node_runs_nothing() {
    let cluster = TestCluster::start().await;
    let mut service = global_service("agent");
    service.spec.task.placement.constraints = vec!["node.labels.role == agent".to_owned()];
    let candidate = add_node(cluster.store(), |_| {}).await;
    let service_id = create_service(cluster.store(), service).await;

    let running = Cluster::spawn(&cluster);
    cluster
        .stays(QUIET, "no node qualifies, so no task exists", |view| {
            view.tasks()
                .iter()
                .all(|task| task.service_id.as_ref() != Some(&service_id))
        })
        .await;

    // The operator labels one node.
    update_node(cluster.store(), &candidate, |node| {
        node.spec
            .labels
            .insert("role".to_owned(), "agent".to_owned());
    })
    .await;
    wait_for_footprint(
        &cluster,
        &service_id,
        &BTreeSet::from([candidate.clone()]),
        "the newly labelled node to gain a task",
    )
    .await;

    // And taking the label away takes the task away (SWK §7.8: a node that
    // fails the constraints has its tasks shut down).
    update_node(cluster.store(), &candidate, |node| {
        node.spec.labels.remove("role");
    })
    .await;
    wait_for_footprint(
        &cluster,
        &service_id,
        &BTreeSet::new(),
        "the relabelled node to give up its task",
    )
    .await;

    running.stop().await;
    cluster.shutdown().await;
}

/// A crash *is* the restart supervisor's, and its replacement stays on the same
/// node (SWK §7.4 step 4) — one budget per node, one task per node.
#[tokio::test(flavor = "multi_thread")]
async fn a_crashed_global_task_is_replaced_on_the_same_node() {
    let cluster = TestCluster::start().await;
    let mut service = with_restart(
        global_service("agent"),
        satl_core::RestartCondition::Any,
        Duration::from_millis(20),
        0,
    );
    service.spec.task.placement.constraints = vec!["node.labels.role == agent".to_owned()];
    let node = add_node(cluster.store(), |node| {
        node.spec
            .labels
            .insert("role".to_owned(), "agent".to_owned());
    })
    .await;
    let service_id = create_service(cluster.store(), service).await;

    let running = Cluster::spawn(&cluster);
    let first = wait_for_footprint(
        &cluster,
        &service_id,
        &BTreeSet::from([node.clone()]),
        "the node to gain its task",
    )
    .await
    .remove(0);
    cluster
        .wait_for("the task to be running", |view| {
            view.task(&first.id)
                .filter(|task| task.status.state == TaskState::Running)
                .map(|_| ())
        })
        .await;

    set_task_state(cluster.store(), &first.id, TaskState::Failed).await;

    let replacement = cluster
        .wait_for("the replacement", |view| {
            live_tasks(view, &service_id)
                .into_iter()
                .find(|task| task.id != first.id)
        })
        .await;
    assert_eq!(
        replacement.node_id.as_ref(),
        Some(&node),
        "a global replacement stays on its node"
    );
    assert_eq!(replacement.slot, 0);

    cluster
        .stays(QUIET, "exactly one live task on the node", |view| {
            live_nodes(view, &service_id) == BTreeSet::from([node.clone()])
                && live_tasks(view, &service_id).len() == 1
        })
        .await;

    running.stop().await;
    cluster.shutdown().await;
}

/// A rolling update of a global service advances **node by node** (SWK §7.8:
/// one slot per node), and finishes with every node on the new spec.
#[tokio::test(flavor = "multi_thread")]
async fn a_rolling_update_of_a_global_service_advances_node_by_node() {
    let cluster = TestCluster::start().await;
    let service = with_update(
        global_service("agent"),
        UpdateConfig {
            parallelism: 1,
            delay: Duration::ZERO,
            failure_action: satl_core::FailureAction::Pause,
            monitor: Duration::from_millis(150),
            max_failure_ratio: 0.0,
            order: UpdateOrder::StopFirst,
        },
    );
    let n1 = add_node(cluster.store(), |_| {}).await;
    let n2 = add_node(cluster.store(), |_| {}).await;
    let service_id = create_service(cluster.store(), service).await;
    let nodes = BTreeSet::from([cluster.node_id().clone(), n1, n2]);

    let running = Cluster::spawn(&cluster);
    let before = wait_for_footprint(&cluster, &service_id, &nodes, "the initial footprint").await;
    assert!(
        before
            .iter()
            .all(|task| task.spec.container.image == WORKING)
    );
    cluster
        .wait_for("every task running before the update", |view| {
            live_tasks(view, &service_id)
                .iter()
                .all(|task| task.status.state == TaskState::Running)
                .then_some(())
        })
        .await;

    update_spec(cluster.store(), &service_id, |spec| {
        spec.task.container.image = NEXT.to_owned();
    })
    .await;

    // Never more than one node in flight at a time: with `parallelism = 1` a
    // second node is not disturbed until the first has settled.
    let watched = tokio::spawn({
        let store = cluster.store().clone();
        let service_id = service_id.clone();
        async move {
            let mut worst = 0usize;
            for _ in 0..200 {
                {
                    let view = store.view();
                    let in_flight = live_tasks(&view, &service_id)
                        .iter()
                        .filter(|task| task.spec.container.image == NEXT)
                        .filter(|task| task.status.state < TaskState::Running)
                        .count();
                    worst = worst.max(in_flight);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            worst
        }
    });

    let message = cluster
        .wait_for("the update to complete", |view| {
            let service = view.service(&service_id)?;
            let status = service.update_status.as_ref()?;
            (status.state == UpdateStateKind::Completed).then(|| status.message.clone())
        })
        .await;
    assert_eq!(
        message, "update completed: 3 nodes updated",
        "the progress line counts nodes: a global service has no slots"
    );

    let after = live_tasks(&cluster.store().view(), &service_id);
    assert_eq!(after.len(), 3, "one task per node, still: {after:?}");
    assert_eq!(live_nodes(&cluster.store().view(), &service_id), nodes);
    for task in &after {
        assert_eq!(task.spec.container.image, NEXT);
        assert_eq!(task.slot, 0);
    }
    assert!(
        watched.await.expect("watcher") <= 1,
        "parallelism 1 means one node at a time"
    );

    running.stop().await;
    cluster.shutdown().await;
}

/// Deleting a global service takes every one of its tasks with it. The sweep is
/// the replicated loop's orphan handling, which is mode-agnostic on purpose —
/// this pins that a global service is not left behind by it.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_global_service_removes_every_task() {
    let cluster = TestCluster::start().await;
    let n1 = add_node(cluster.store(), |_| {}).await;
    let service_id = create_service(cluster.store(), global_service("agent")).await;

    let running = Cluster::spawn(&cluster);
    wait_for_footprint(
        &cluster,
        &service_id,
        &BTreeSet::from([cluster.node_id().clone(), n1]),
        "a task on each node",
    )
    .await;

    cluster
        .store()
        .propose(vec![StoreAction::Remove {
            kind: satl_core::ObjectKind::Service,
            id: service_id.clone(),
        }])
        .await
        .expect("service removed");

    cluster
        .wait_for("every task of the deleted service to go", |view| {
            view.tasks()
                .iter()
                .all(|task| task.service_id.as_ref() != Some(&service_id))
                .then_some(())
        })
        .await;
    cluster
        .stays(
            QUIET,
            "nothing is recreated for a service that is gone",
            |view| {
                view.tasks()
                    .iter()
                    .all(|task| task.service_id.as_ref() != Some(&service_id))
            },
        )
        .await;

    running.stop().await;
    cluster.shutdown().await;
}
