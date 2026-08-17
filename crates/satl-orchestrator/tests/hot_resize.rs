// SPDX-License-Identifier: BSD-2-Clause
//! Hot vertical resize (M6g): a resources-only spec change is pushed into the
//! live tasks — the agent re-applies rctl to the running jail — instead of
//! going through the rolling updater. Same harness as `rolling_update.rs`: a
//! real single-node Raft store and a stand-in agent, so what is asserted here
//! is the manager's decision, not a mock of it.

use std::time::Duration;

use satl_cluster::ClusterStore;
use satl_core::{
    DesiredState, Id, ResourceRequirements, Resources, StoreAction, StoreObject, Task, TaskState,
    TaskStatus, UpdateStateKind,
};
use satl_orchestrator::{Cadence, Orchestrator, OrchestratorConfig};
use tokio_util::sync::CancellationToken;

#[path = "../src/testing.rs"]
mod testing;

use testing::{TestCluster, sample_service, update_spec};

const NEXT: &str = "127.0.0.1:5000/freebsd-nginx:2";

/// 128 MiB and 256 MiB: the two caps the service moves between.
const OLD_CAP: i64 = 128 * 1024 * 1024;
const NEW_CAP: i64 = 256 * 1024 * 1024;

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

fn with_memory(mut requirements: ResourceRequirements, bytes: i64) -> ResourceRequirements {
    requirements.limits = Some(Resources {
        nano_cpus: 0,
        memory_bytes: bytes,
    });
    requirements
}

/// The smallest agent that walks every task to where the manager wants it —
/// `rolling_update.rs`'s, minus the failure injection this file never uses.
struct Agent {
    store: ClusterStore,
    node: Id,
}

impl Agent {
    fn spawn(cluster: &TestCluster, shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
        let agent = Self {
            store: cluster.store().clone(),
            node: cluster.node_id().clone(),
        };
        tokio::spawn(async move {
            while !shutdown.is_cancelled() {
                agent.step().await;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
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
            } else {
                continue;
            };
            let mut updated = task;
            updated.node_id = Some(self.node.clone());
            updated.status = TaskStatus::new(next, "reported by the test agent");
            // Stamped the way the dispatcher stamps it, because the updater's
            // monitor window reads `applied_at`.
            updated.status.applied_at = Some(std::time::SystemTime::now());
            let _ = self
                .store
                .propose(vec![StoreAction::Update(StoreObject::Task(updated))])
                .await;
        }
    }
}

/// The service's one live task (these tests run a single replica).
fn live_task(cluster: &TestCluster, service_id: &Id) -> Option<Task> {
    cluster.tasks_of(service_id).into_iter().find(|task| {
        task.desired_state <= DesiredState::Running && !task.status.state.is_terminal()
    })
}

/// A memory-cap change leaves the same task serving, on the new limits,
/// stamped from the new spec — and never starts a rollout.
#[tokio::test(flavor = "multi_thread")]
async fn a_resources_only_update_resizes_the_live_task_without_replacing_it() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let agent = Agent::spawn(&cluster, shutdown.clone());
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let mut service = sample_service("db", 1);
    service.spec.task.resources = with_memory(service.spec.task.resources, OLD_CAP);
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");
    let before = cluster
        .wait_for("the task to run with the original cap", |_| {
            let task = live_task(&cluster, &service_id)?;
            (task.status.state == TaskState::Running
                && task.spec.resources.limits.expect("limits").memory_bytes == OLD_CAP)
                .then_some(task)
        })
        .await;

    update_spec(cluster.store(), &service_id, |spec| {
        spec.task.resources = with_memory(spec.task.resources, NEW_CAP);
    })
    .await;

    let after = cluster
        .wait_for("the live task to carry the new cap", |_| {
            let task = live_task(&cluster, &service_id)?;
            (task.spec.resources.limits.expect("limits").memory_bytes == NEW_CAP).then_some(task)
        })
        .await;
    assert_eq!(after.id, before.id, "the resize must not replace the task");
    assert_eq!(
        after.status.state,
        TaskState::Running,
        "the task kept serving through the resize"
    );

    let service_version = {
        let view = cluster.store().view();
        view.service(&service_id).expect("service").spec_version
    };
    assert_eq!(
        after.spec_version,
        Some(service_version),
        "the resized task is stamped from the current spec, so nothing rolls it later"
    );

    // And nothing else happens: no replacement, no rollout status.
    cluster
        .stays(QUIET, "no second task and no rollout", |view| {
            let tasks: Vec<_> = view
                .tasks()
                .into_iter()
                .filter(|task| task.service_id.as_ref() == Some(&service_id))
                .collect();
            let service = view.service(&service_id).expect("service");
            tasks.len() == 1 && service.update_status.is_none()
        })
        .await;

    shutdown.cancel();
    let _ = agent.await;
    orchestrator.join().await;
    cluster.shutdown().await;
}

/// A resources change riding an image change is an ordinary roll — and the
/// replacement lands on the new limits whole.
#[tokio::test(flavor = "multi_thread")]
async fn a_resources_change_riding_an_image_change_still_rolls() {
    let cluster = TestCluster::start().await;
    let shutdown = CancellationToken::new();
    let agent = Agent::spawn(&cluster, shutdown.clone());
    let orchestrator =
        Orchestrator::spawn_with_config(cluster.store().clone(), fast(), shutdown.clone());

    let mut service = sample_service("db", 1);
    service.spec.task.resources = with_memory(service.spec.task.resources, OLD_CAP);
    let service_id = service.id.clone();
    cluster
        .store()
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .expect("service created");
    let before = cluster
        .wait_for("the task to run", |_| {
            let task = live_task(&cluster, &service_id)?;
            (task.status.state == TaskState::Running).then_some(task)
        })
        .await;

    update_spec(cluster.store(), &service_id, |spec| {
        spec.task.container.image = NEXT.to_owned();
        spec.task.resources = with_memory(spec.task.resources, NEW_CAP);
    })
    .await;

    let after = cluster
        .wait_for("the replacement to run on the new image and cap", |_| {
            let task = live_task(&cluster, &service_id)?;
            (task.status.state == TaskState::Running
                && task.spec.container.image == NEXT
                && task.spec.resources.limits.expect("limits").memory_bytes == NEW_CAP)
                .then_some(task)
        })
        .await;
    assert_ne!(
        after.id, before.id,
        "a mixed change replaces the task — the resize exemption covers resources only"
    );
    cluster
        .wait_for("the roll to complete", |_| {
            let view = cluster.store().view();
            let service = view.service(&service_id).expect("service");
            (service.update_status.as_ref().map(|status| status.state)
                == Some(UpdateStateKind::Completed))
            .then_some(())
        })
        .await;

    shutdown.cancel();
    let _ = agent.await;
    orchestrator.join().await;
    cluster.shutdown().await;
}
