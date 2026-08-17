// SPDX-License-Identifier: BSD-2-Clause
//! Job services (`ReplicatedJob`/`GlobalJob`, SWK §3.4) against a real
//! single-node Raft store, driven by the same stand-in agent pattern as
//! `rolling_update.rs` — extended so that a task that reaches `RUNNING`
//! reports `COMPLETE` a step later, the way a short-lived batch process
//! would. What is asserted is the manager's decision: a finished run is
//! never restarted, a failed one is retried, an update re-runs the job.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use satl_cluster::ClusterStore;
use satl_core::{
    DesiredState, Id, Service, ServiceMode, StoreAction, StoreObject, Task, TaskState, TaskStatus,
};
use satl_orchestrator::{Cadence, Orchestrator, OrchestratorConfig};
use tokio_util::sync::CancellationToken;

#[path = "../src/testing.rs"]
mod testing;

use testing::{TestCluster, planted_node, sample_service, update_spec};

/// The image the service starts on, and the one test 3 updates it to.
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

/// How long a "nothing happens" assertion watches for.
const QUIET: Duration = Duration::from_millis(600);

/// A replicated job with the given totals.
fn job_service(name: &str, max_concurrent: u64, total: u64) -> Service {
    let mut service = sample_service(name, 1);
    service.spec.mode = ServiceMode::ReplicatedJob {
        max_concurrent: Some(max_concurrent),
        total_completions: Some(total),
    };
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

/// The smallest agent that runs a *batch* workload: tasks walk to their
/// desired state, and a task observed where the cluster wants it exits —
/// `COMPLETE`, unless a failure was armed for it. Tasks are only bound to
/// the local node when nothing bound them first, so a global job's
/// preassignment (SWK §8.6) shows through untouched.
struct Agent {
    store: ClusterStore,
    node: Id,
    /// Runs still to fail once they are up.
    fail: Arc<AtomicU64>,
    /// Whether a running task exits 0 (off: it stays up, so a test can
    /// update the job mid-run).
    completes: Arc<AtomicBool>,
}

impl Agent {
    fn spawn(cluster: &TestCluster, shutdown: CancellationToken) -> Controls {
        let fail = Arc::new(AtomicU64::new(0));
        let completes = Arc::new(AtomicBool::new(true));
        let agent = Self {
            store: cluster.store().clone(),
            node: cluster.node_id().clone(),
            fail: Arc::clone(&fail),
            completes: Arc::clone(&completes),
        };
        let handle = tokio::spawn(async move {
            while !shutdown.is_cancelled() {
                agent.step().await;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        });
        Controls {
            fail,
            completes,
            handle: Some(handle),
        }
    }

    async fn step(&self) {
        let tasks: Vec<Task> = {
            let view = self.store.view();
            view.tasks().iter().map(|task| (**task).clone()).collect()
        };
        for task in tasks {
            let observed = task.status.state;
            if observed.is_terminal() {
                continue;
            }
            let next = if task.desired_state >= DesiredState::Shutdown {
                TaskState::Shutdown
            } else if observed < task.desired_state.as_task_state() {
                task.desired_state.as_task_state()
            } else if self.completes.load(Ordering::SeqCst) {
                if self.fail.load(Ordering::SeqCst) > 0 {
                    self.fail.fetch_sub(1, Ordering::SeqCst);
                    TaskState::Failed
                } else {
                    TaskState::Complete
                }
            } else {
                continue;
            };
            let mut updated = task;
            if updated.node_id.is_none() {
                updated.node_id = Some(self.node.clone());
            }
            updated.status = TaskStatus::new(next, "reported by the test agent");
            updated.status.applied_at = Some(std::time::SystemTime::now());
            let _ = self
                .store
                .propose(vec![StoreAction::Update(StoreObject::Task(updated))])
                .await;
        }
    }
}

/// The test's handle on the agent: fail injections, the completion switch
/// and the task to join at the end.
struct Controls {
    fail: Arc<AtomicU64>,
    completes: Arc<AtomicBool>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl Controls {
    async fn join(mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

/// A replicated job runs its completions, and then nothing ever happens
/// again: no replacement for a finished run, no restart of a `COMPLETE`
/// task, no churn.
#[tokio::test(flavor = "multi_thread")]
async fn a_replicated_job_runs_to_completion_and_goes_quiet() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let agent = Agent::spawn(&cluster, shutdown.clone());
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let service_id = create_service(cluster.store(), job_service("batch", 2, 2)).await;
    cluster
        .wait_for("both runs to complete", |view| {
            let tasks: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|task| task.service_id.as_ref() == Some(&service_id))
                .collect();
            (tasks.len() == 2
                && tasks
                    .iter()
                    .all(|task| task.status.state == TaskState::Complete))
            .then_some(())
        })
        .await;

    cluster
        .stays(QUIET, "a finished job takes no further action", |view| {
            let tasks: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|task| task.service_id.as_ref() == Some(&service_id))
                .collect();
            tasks.len() == 2
                && tasks
                    .iter()
                    .all(|task| task.status.state == TaskState::Complete)
        })
        .await;

    shutdown.cancel();
    agent.join().await;
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// A failed run is replaced in the same slot, and the retry's clean exit
/// finishes the job.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_run_is_retried_and_the_retry_completes_the_job() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let agent = Agent::spawn(&cluster, shutdown.clone());
    agent.fail.store(1, Ordering::SeqCst);
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let service_id = create_service(cluster.store(), job_service("flaky", 1, 1)).await;
    cluster
        .wait_for("the retry to complete", |view| {
            let tasks: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|task| task.service_id.as_ref() == Some(&service_id))
                .collect();
            (tasks.len() == 2
                && tasks
                    .iter()
                    .any(|task| task.status.state == TaskState::Complete))
            .then_some(())
        })
        .await;

    let tasks = cluster.tasks_of(&service_id);
    assert_eq!(tasks.len(), 2, "the failure and the retry, no more");
    assert_eq!(tasks[0].slot, 1);
    assert_eq!(tasks[1].slot, 1, "the retry lands in the same slot");
    assert!(
        tasks
            .iter()
            .any(|task| task.status.state == TaskState::Failed),
        "the first run failed"
    );

    cluster
        .stays(QUIET, "a completed slot is never retried again", |view| {
            view.tasks()
                .iter()
                .filter(|task| task.service_id.as_ref() == Some(&service_id))
                .count()
                == 2
        })
        .await;

    shutdown.cancel();
    agent.join().await;
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// Updating a job re-runs it: the old run is stopped, and a fresh task runs
/// the new spec — with no rolling-update machinery involved at all.
#[tokio::test(flavor = "multi_thread")]
async fn updating_a_job_re_runs_it() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let agent = Agent::spawn(&cluster, shutdown.clone());
    // Hold the first run up, so the update lands mid-run.
    agent.completes.store(false, Ordering::SeqCst);
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let service_id = create_service(cluster.store(), job_service("rerun", 1, 1)).await;
    let old = cluster
        .wait_for("the first run to start", |view| {
            view.tasks()
                .into_iter()
                .find(|task| {
                    task.service_id.as_ref() == Some(&service_id)
                        && task.status.state == TaskState::Running
                })
                .map(|task| (*task).clone())
        })
        .await;
    assert_eq!(old.spec.container.image, WORKING);

    update_spec(cluster.store(), &service_id, |spec| {
        spec.task.container.image = NEXT.to_owned();
    })
    .await;

    let new = cluster
        .wait_for("the job to re-run on the new spec", |view| {
            view.tasks().into_iter().find_map(|task| {
                (task.service_id.as_ref() == Some(&service_id)
                    && task.id != old.id
                    && task.spec.container.image == NEXT
                    && task.status.state == TaskState::Running)
                    .then(|| (*task).clone())
            })
        })
        .await;
    assert_eq!(new.slot, old.slot, "the re-run takes the slot over");

    cluster
        .wait_for("the old run to be stopped", |view| {
            view.task(&old.id).and_then(|task| {
                (task.desired_state == DesiredState::Shutdown
                    && task.status.state == TaskState::Shutdown)
                    .then_some(())
            })
        })
        .await;
    {
        let view = cluster.store().view();
        let service = view.service(&service_id).expect("service");
        assert!(
            service.update_status.is_none(),
            "a job re-run is not a rollout: the updater never engages"
        );
    }

    agent.completes.store(true, Ordering::SeqCst);
    cluster
        .wait_for("the re-run to complete", |view| {
            view.task(&new.id)
                .and_then(|task| (task.status.state == TaskState::Complete).then_some(()))
        })
        .await;

    shutdown.cancel();
    agent.join().await;
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// A global job runs once per eligible node, and the completions do not
/// multiply.
#[tokio::test(flavor = "multi_thread")]
async fn a_global_job_runs_once_per_eligible_node() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let agent = Agent::spawn(&cluster, shutdown.clone());
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    // A second synthetic node, as eligible as the seeded one.
    let other = planted_node("beta");
    let other_id = other.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Node(other))])
        .await
        .expect("node created");

    let mut service = sample_service("sweep", 1);
    service.spec.mode = ServiceMode::GlobalJob;
    let service_id = create_service(cluster.store(), service).await;

    let nodes = [cluster.node_id().clone(), other_id];
    cluster
        .wait_for("one completed run per node", |view| {
            let tasks: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|task| task.service_id.as_ref() == Some(&service_id))
                .collect();
            (tasks.len() == 2
                && tasks
                    .iter()
                    .all(|task| task.status.state == TaskState::Complete)
                && nodes
                    .iter()
                    .all(|node| tasks.iter().any(|task| task.node_id.as_ref() == Some(node))))
            .then_some(())
        })
        .await;

    cluster
        .stays(QUIET, "a finished global job starts nothing new", |view| {
            view.tasks()
                .iter()
                .filter(|task| task.service_id.as_ref() == Some(&service_id))
                .count()
                == 2
        })
        .await;

    shutdown.cancel();
    agent.join().await;
    orchestrator.join().await;
    cluster.shutdown().await;
}
