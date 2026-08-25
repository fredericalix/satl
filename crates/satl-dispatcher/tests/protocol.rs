// SPDX-License-Identifier: BSD-2-Clause
//! The dispatcher protocol, end to end, over a real tonic server on
//! loopback — manager side and worker side driven against each other with
//! nothing stubbed but the two seams that need root: the jail-driving
//! [`AssignmentSink`] and the TLS transport.
//!
//! # Why there is no TLS here
//!
//! Authentication is a property of the *connection*, and `satld` owns the
//! server assembly (it holds the node identity and the rustls configs). What
//! this crate owns is what happens **after** authentication: the dispatcher
//! reads an authenticated [`PeerIdentity`] out of the request extensions,
//! which in production `satl_dispatcher::manager::identity_interceptor` puts
//! there from the mTLS peer certificate. These tests install an interceptor
//! that puts a chosen identity there instead — same code path in the service,
//! one fixed input. The certificate → identity step itself is `satl-ca`'s and
//! is tested there.
//!
//! Each simulated node gets its own loopback listener (and therefore its own
//! interceptor and identity) over **one shared** [`Dispatcher`], which is
//! exactly the manager's real shape: one dispatcher, many agents.

#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use satl_ca::PeerIdentity;
use satl_core::{
    Availability, DesiredState, Id, NodeRole, NodeState, StoreObject, TaskState, TaskStatus,
};
use satl_dispatcher::agent::{Agent, AgentConfig, ChannelFactory, ConnectError, SessionReporter};
use satl_dispatcher::liveness::HeartbeatConfig;
use satl_dispatcher::manager::{Dispatcher, DispatcherConfig};
use satl_dispatcher::peer::{Endpoint, ManagerPeer};
use satl_proto::v2;
use tokio::net::TcpListener;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_util::sync::CancellationToken;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

#[path = "../src/testing.rs"]
mod testing;

use testing::{RecordingSink, TestCluster};

/// Timings that keep the suite fast without changing any semantics.
fn fast_dispatcher_config() -> DispatcherConfig {
    DispatcherConfig {
        heartbeat: HeartbeatConfig {
            period: Duration::from_millis(80),
            // No jitter: the tests assert on TTL boundaries, and jitter is
            // covered exhaustively by the unit tests.
            jitter: Duration::ZERO,
            ttl_factor: 3,
            unknown_grace_factor: 2,
            orphan_after: Duration::from_hours(1),
        },
        assignment_batch_max: 100,
        assignment_quiescence: Duration::from_millis(20),
        status_flush_interval: Duration::from_millis(20),
        status_flush_max: 10_000,
    }
}

fn fast_agent_config(node_id: Id, manager: &Id, addr: SocketAddr) -> AgentConfig {
    AgentConfig {
        bootstrap_managers: vec![ManagerPeer::new(manager.clone(), addr.to_string())],
        rpc_timeout: Duration::from_secs(5),
        status_flush_interval: Duration::from_millis(20),
        status_flush_max: 10_000,
        description_refresh: Duration::from_hours(1),
        ..AgentConfig::new(node_id)
    }
}

/// Serves `dispatcher` on a fresh loopback port, injecting `identity` as the
/// authenticated caller for every request that arrives on it.
async fn serve(
    dispatcher: Dispatcher,
    identity: PeerIdentity,
    shutdown: CancellationToken,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let service = tonic::service::interceptor::InterceptedService::new(
        dispatcher.server(),
        move |mut request: Request<()>| {
            request.extensions_mut().insert(identity.clone());
            Ok(request)
        },
    );
    tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                shutdown.cancelled().await;
            })
            .await;
    });
    addr
}

/// Serves a hand-written misbehaving dispatcher (the gap test).
async fn serve_raw<T>(service: T, identity: PeerIdentity, shutdown: CancellationToken) -> SocketAddr
where
    T: v2::dispatcher_server::Dispatcher,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let service = tonic::service::interceptor::InterceptedService::new(
        v2::dispatcher_server::DispatcherServer::new(service),
        move |mut request: Request<()>| {
            request.extensions_mut().insert(identity.clone());
            Ok(request)
        },
    );
    tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                shutdown.cancelled().await;
            })
            .await;
    });
    addr
}

/// A connector that always hands back the same loopback channel.
struct Loopback(Channel);

impl Loopback {
    async fn to(addr: SocketAddr) -> Self {
        let channel = Channel::from_shared(format!("http://{addr}"))
            .expect("uri")
            .connect_timeout(Duration::from_secs(5))
            .connect()
            .await
            .expect("connect");
        Self(channel)
    }
}

impl ChannelFactory for Loopback {
    async fn connect(&self, _endpoint: &Endpoint) -> Result<Channel, ConnectError> {
        Ok(self.0.clone())
    }
}

fn identity_of(node_id: &Id, cluster_id: &str, role: NodeRole) -> PeerIdentity {
    PeerIdentity {
        node_id: node_id.clone(),
        role,
        cluster_id: cluster_id.to_owned(),
    }
}

fn cluster_id_of(cluster: &TestCluster) -> String {
    let view = cluster.store().view();
    view.cluster().expect("cluster object").id.to_string()
}

/// The full happy path: register, snapshot, incremental update, status
/// round-trip, and dependency shipping/withdrawal.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_delivers_assignments_and_carries_statuses_back() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    let dispatcher = Dispatcher::new(
        cluster.store().clone(),
        node_id.clone(),
        fast_dispatcher_config(),
    );
    let loops = dispatcher.spawn(shutdown.clone());
    let addr = serve(
        dispatcher.clone(),
        identity_of(&node_id, &cluster_id, NodeRole::Manager),
        shutdown.clone(),
    )
    .await;

    // A task and the secret it needs, both already in the store.
    let secret = testing::secret("db.password", b"hunter2");
    let task = testing::with_secret(
        testing::task_on(Some(&node_id), TaskState::Assigned, DesiredState::Running),
        &secret,
    );
    let task_id = task.id.clone();
    cluster.create(StoreObject::Secret(secret.clone())).await;
    cluster.create(StoreObject::Task(task)).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let db = satl_agent::TaskDb::open(dir.path()).expect("task db");
    let sink = RecordingSink::new();
    let reporter = SessionReporter::new();
    let agent = Agent::new(
        fast_agent_config(node_id.clone(), &node_id, addr),
        Arc::clone(&sink),
        Loopback::to(addr).await,
        db,
        Arc::clone(&reporter),
        Arc::new(|| testing::description("worker-1")),
    );
    let agent_handle = agent.spawn(shutdown.clone());

    // 1. The COMPLETE snapshot brings the task *and* its secret.
    testing::eventually("the task to reach the worker", || {
        sink.tasks().contains_key(&task_id)
    })
    .await;
    assert!(
        sink.secrets().contains_key(&secret.id),
        "the secret must ship with its first dependent task"
    );

    // 2. A status reported by the worker reaches the store, stamped by the
    //    manager.
    reporter.enqueue(&task_id, TaskStatus::new(TaskState::Running, "started"));
    let applied = cluster
        .wait_for("the status to reach the store", |view| {
            let task = view.task(&task_id)?;
            (task.status.state == TaskState::Running).then(|| task.status.clone())
        })
        .await;
    assert_eq!(applied.applied_by, Some(node_id.clone()));
    assert!(applied.applied_at.is_some());

    // 3. A desired-state move reaches the worker as an INCREMENTAL change.
    cluster
        .update_task(&task_id, |task| {
            task.desired_state = DesiredState::Shutdown;
        })
        .await;
    testing::eventually("the desired state to reach the worker", || {
        sink.tasks()
            .get(&task_id)
            .is_some_and(|task| task.desired_state == DesiredState::Shutdown)
    })
    .await;

    // 4. Past RUNNING the task releases its secret, even though the task
    //    object itself stays assigned (SWK §13.4).
    cluster
        .update_task(&task_id, |task| {
            task.status = TaskStatus::new(TaskState::Shutdown, "stopped");
        })
        .await;
    testing::eventually("the secret to be withdrawn", || sink.secrets().is_empty()).await;
    assert!(
        sink.tasks().contains_key(&task_id),
        "the task itself stays until it is deleted"
    );

    shutdown.cancel();
    let _ = agent_handle.await;
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}

/// A task created after registration arrives as an incremental change, and a
/// deleted task is released.
#[tokio::test(flavor = "multi_thread")]
async fn tasks_created_and_deleted_later_flow_incrementally() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    let dispatcher = Dispatcher::new(
        cluster.store().clone(),
        node_id.clone(),
        fast_dispatcher_config(),
    );
    let loops = dispatcher.spawn(shutdown.clone());
    let addr = serve(
        dispatcher.clone(),
        identity_of(&node_id, &cluster_id, NodeRole::Manager),
        shutdown.clone(),
    )
    .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let db = satl_agent::TaskDb::open(dir.path()).expect("task db");
    let sink = RecordingSink::new();
    let agent = Agent::new(
        fast_agent_config(node_id.clone(), &node_id, addr),
        Arc::clone(&sink),
        Loopback::to(addr).await,
        db,
        SessionReporter::new(),
        Arc::new(|| testing::description("worker-1")),
    );
    let agent_handle = agent.spawn(shutdown.clone());

    // Registered with an empty snapshot.
    testing::eventually("the startup pass to run", || {
        sink.calls()
            .iter()
            .any(|call| matches!(call, testing::SinkCall::Init(_)))
    })
    .await;

    let task = testing::task_on(Some(&node_id), TaskState::Assigned, DesiredState::Running);
    let task_id = task.id.clone();
    cluster.create(StoreObject::Task(task)).await;
    testing::eventually("the new task to arrive", || {
        sink.tasks().contains_key(&task_id)
    })
    .await;

    cluster
        .commit(vec![satl_core::StoreAction::Remove {
            kind: satl_core::ObjectKind::Task,
            id: task_id.clone(),
        }])
        .await;
    testing::eventually("the deleted task to be released", || {
        !sink.tasks().contains_key(&task_id)
    })
    .await;

    shutdown.cancel();
    let _ = agent_handle.await;
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}

/// On (re-)registration the agent re-reports every persisted task status —
/// the manager it just met may have missed everything since the last one.
#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_registration_re_reports_every_persisted_status() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    // The store thinks the task is merely assigned…
    let task = testing::task_on(Some(&node_id), TaskState::Assigned, DesiredState::Running);
    let task_id = task.id.clone();
    cluster.create(StoreObject::Task(task.clone())).await;

    // …while the worker's local db knows it reached RUNNING before the
    // previous session died. The local status is canonical.
    let dir = tempfile::tempdir().expect("tempdir");
    let db = satl_agent::TaskDb::open(dir.path()).expect("task db");
    db.put(&satl_agent::TaskRecord {
        task,
        status: TaskStatus::new(TaskState::Running, "started before the manager went away"),
    })
    .await
    .expect("persist");

    let dispatcher = Dispatcher::new(
        cluster.store().clone(),
        node_id.clone(),
        fast_dispatcher_config(),
    );
    let loops = dispatcher.spawn(shutdown.clone());
    let addr = serve(
        dispatcher.clone(),
        identity_of(&node_id, &cluster_id, NodeRole::Manager),
        shutdown.clone(),
    )
    .await;

    let sink = RecordingSink::new();
    let agent = Agent::new(
        fast_agent_config(node_id.clone(), &node_id, addr),
        Arc::clone(&sink),
        Loopback::to(addr).await,
        db,
        SessionReporter::new(),
        Arc::new(|| testing::description("worker-1")),
    );
    let agent_handle = agent.spawn(shutdown.clone());

    let status = cluster
        .wait_for("the replayed status to reach the store", |view| {
            let task = view.task(&task_id)?;
            (task.status.state == TaskState::Running).then(|| task.status.clone())
        })
        .await;
    assert_eq!(status.applied_by, Some(node_id.clone()));

    shutdown.cancel();
    let _ = agent_handle.await;
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}

/// A node comes back from a failure with its containers still running, and the
/// manager has moved on: one of its tasks was evicted (desired `SHUTDOWN`), the
/// other was scaled away (desired `REMOVE`). Both moves happened while this
/// agent had no session, so they arrive in the `COMPLETE` snapshot rather than
/// as a diff — and both must still reach the worker.
///
/// Get this wrong and the symptom is not a failure but a silence: the node
/// re-attaches its containers, reports `RUNNING`, and the jails outlive their
/// tasks forever (`satl service ls` stuck at 7/6, or at 6/3 after a
/// scale-down).
#[tokio::test(flavor = "multi_thread")]
async fn a_returning_agent_is_told_the_desired_states_that_moved_while_it_was_away() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    // Two tasks this node is running, as its local task db remembers them.
    let evicted = testing::task_on(Some(&node_id), TaskState::Running, DesiredState::Running);
    let scaled_away = testing::task_on(Some(&node_id), TaskState::Running, DesiredState::Running);
    let evicted_id = evicted.id.clone();
    let scaled_away_id = scaled_away.id.clone();

    let sink = RecordingSink::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = satl_agent::TaskDb::open(dir.path()).expect("task db");
    for task in [&evicted, &scaled_away] {
        sink.persist(task.clone());
        db.put(&satl_agent::TaskRecord {
            task: task.clone(),
            status: TaskStatus::new(TaskState::Running, "started before the node went away"),
        })
        .await
        .expect("persist");
    }

    // What the cluster decided in the meantime.
    let mut evicted_now = evicted.clone();
    evicted_now.desired_state = DesiredState::Shutdown;
    let mut scaled_away_now = scaled_away.clone();
    scaled_away_now.desired_state = DesiredState::Remove;
    cluster.create(StoreObject::Task(evicted_now)).await;
    cluster.create(StoreObject::Task(scaled_away_now)).await;

    let dispatcher = Dispatcher::new(
        cluster.store().clone(),
        node_id.clone(),
        fast_dispatcher_config(),
    );
    let loops = dispatcher.spawn(shutdown.clone());
    let addr = serve(
        dispatcher.clone(),
        identity_of(&node_id, &cluster_id, NodeRole::Manager),
        shutdown.clone(),
    )
    .await;

    let agent = Agent::new(
        fast_agent_config(node_id.clone(), &node_id, addr),
        Arc::clone(&sink),
        Loopback::to(addr).await,
        db,
        SessionReporter::new(),
        Arc::new(|| testing::description("worker-1")),
    );
    let agent_handle = agent.spawn(shutdown.clone());

    testing::eventually("both desired states to reach the worker", || {
        let tasks = sink.tasks();
        tasks
            .get(&evicted_id)
            .is_some_and(|task| task.desired_state == DesiredState::Shutdown)
            && tasks
                .get(&scaled_away_id)
                .is_some_and(|task| task.desired_state == DesiredState::Remove)
    })
    .await;

    // The startup pass ran, and it ran before the hand-overs: a task is only
    // resumed once, and only then re-driven at the state the cluster wants.
    let calls = sink.calls();
    let init = calls
        .iter()
        .position(|call| matches!(call, testing::SinkCall::Init(_)))
        .expect("the startup pass ran");
    for id in [&evicted_id, &scaled_away_id] {
        let applied = calls
            .iter()
            .position(|call| call == &testing::SinkCall::ApplyTask(id.clone()))
            .unwrap_or_else(|| panic!("task {id} was never handed to the worker: {calls:?}"));
        assert!(applied > init, "resume first, then re-drive: {calls:?}");
    }

    shutdown.cancel();
    let _ = agent_handle.await;
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}

/// Re-registering with a manager must not re-run the startup pass: `init`
/// re-spawns a task manager per record, which against a live container means
/// tearing down the one that is driving it and re-attaching from scratch. It is
/// a once-per-process operation (the sink's contract), and the applier that
/// remembers it now lives as long as the agent, not as long as one session.
#[tokio::test(flavor = "multi_thread")]
async fn a_re_registration_does_not_re_run_the_startup_pass() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    let task = testing::task_on(Some(&node_id), TaskState::Running, DesiredState::Running);
    let task_id = task.id.clone();
    cluster.create(StoreObject::Task(task.clone())).await;

    let sink = RecordingSink::new();
    sink.persist(task);
    let dir = tempfile::tempdir().expect("tempdir");
    let db = satl_agent::TaskDb::open(dir.path()).expect("task db");

    let dispatcher = Dispatcher::new(
        cluster.store().clone(),
        node_id.clone(),
        fast_dispatcher_config(),
    );
    let loops = dispatcher.spawn(shutdown.clone());
    let addr = serve(
        dispatcher.clone(),
        identity_of(&node_id, &cluster_id, NodeRole::Manager),
        shutdown.clone(),
    )
    .await;

    // A description the test changes on demand: the agent notices at its next
    // refresh, drops the session (a description only travels in a
    // registration) and registers again — a session flap with no failure.
    let renamed = Arc::new(AtomicUsize::new(0));
    let describer = {
        let renamed = Arc::clone(&renamed);
        Arc::new(move || {
            if renamed.load(Ordering::SeqCst) == 0 {
                testing::description("worker-1")
            } else {
                testing::description("worker-1-renamed")
            }
        })
    };
    let mut config = fast_agent_config(node_id.clone(), &node_id, addr);
    config.description_refresh = Duration::from_millis(10);
    let agent = Agent::new(
        config,
        Arc::clone(&sink),
        Loopback::to(addr).await,
        db,
        SessionReporter::new(),
        describer,
    );
    let agent_handle = agent.spawn(shutdown.clone());

    testing::eventually("the first session's startup pass", || {
        sink.calls()
            .iter()
            .any(|call| matches!(call, testing::SinkCall::Init(_)))
    })
    .await;

    // Force the re-registration; the node description in the store is the
    // manager's proof that it happened.
    renamed.store(1, Ordering::SeqCst);
    cluster
        .wait_for("the agent to register with its new description", |view| {
            let node = view.node(&node_id)?;
            let hostname = node.description.as_ref()?.hostname.clone();
            (hostname == "worker-1-renamed").then_some(())
        })
        .await;

    // A task created now can only reach the worker through the new session, and
    // the first message on that session's assignment stream is by contract the
    // COMPLETE snapshot — so once it lands, the second snapshot has been
    // applied and the `Init` count is final.
    let later = testing::task_on(Some(&node_id), TaskState::Assigned, DesiredState::Running);
    let later_id = later.id.clone();
    cluster.create(StoreObject::Task(later)).await;
    testing::eventually("the new session to deliver assignments", || {
        sink.tasks().contains_key(&later_id)
    })
    .await;

    let inits = sink
        .calls()
        .into_iter()
        .filter(|call| matches!(call, testing::SinkCall::Init(_)))
        .count();
    assert_eq!(inits, 1, "the startup pass is once per process");
    assert!(
        sink.tasks().contains_key(&task_id),
        "the worker still holds the resumed task"
    );

    shutdown.cancel();
    let _ = agent_handle.await;
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}

/// A node with a live session converges to `READY` even when the write that
/// should have said so never landed — the manager re-asserts its sessions onto
/// the node objects on every sweep instead of only on the transition.
///
/// This is the M3 leader bug. The leader's own agent reaches the **co-located
/// unix socket** in microseconds (no dial, no TLS handshake, `addr` empty), so
/// it registered *before* the sweep loop's leadership-gain pass had finished
/// walking the store; that pass then overwrote its fresh `READY` with
/// `UNKNOWN`, and nothing wrote it again, because heartbeats only refresh the
/// in-memory TTL. `satl node ls` showed the leader `Unknown` on all three
/// nodes while its own agent was streaming assignments, the scheduler skipped
/// it (`satl_sched` filters on `READY`), and the cluster suite's readiness gate
/// timed out. Only a second daemon restart cleared it.
///
/// Both halves of the fix are pinned here, and the second is the one that
/// matters:
///
/// 1. registering before the loops exist is the production ordering, and it
///    must survive the leadership-gain pass;
/// 2. a `READY` destroyed behind the manager's back — no transition, nothing to
///    be edge-triggered by — must come back on its own. No bring-up ordering
///    can satisfy this half, which is the point: the race can reappear on a
///    faster or slower host without the symptom reappearing with it.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_session_drags_its_node_back_to_ready_without_re_registering() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    let dispatcher = Dispatcher::new(
        cluster.store().clone(),
        node_id.clone(),
        fast_dispatcher_config(),
    );
    let addr = serve(
        dispatcher.clone(),
        identity_of(&node_id, &cluster_id, NodeRole::Manager),
        shutdown.clone(),
    )
    .await;

    // Phase 1: register while the background loops do not exist yet, then start
    // them — the leader's own agent beating the sweep loop to it.
    let channel = Channel::from_shared(format!("http://{addr}"))
        .expect("uri")
        .connect()
        .await
        .expect("connect");
    let mut client = v2::dispatcher_client::DispatcherClient::new(channel);
    let mut session = client
        .session(v2::SessionRequest {
            description: Vec::new(),
            session_id: String::new(),
        })
        .await
        .expect("session")
        .into_inner();
    let session_id = session
        .message()
        .await
        .expect("stream")
        .expect("a first message")
        .session_id;
    assert!(!session_id.is_empty());
    cluster
        .wait_for("the registration to record the node as ready", |view| {
            (view.node(&node_id)?.status.state == NodeState::Ready).then_some(())
        })
        .await;

    // A real agent keeps beating throughout; the TTL is 3 x 80 ms here.
    let beater = {
        let mut client = client.clone();
        let session_id = session_id.clone();
        let stop = shutdown.clone();
        tokio::spawn(async move {
            while !stop.is_cancelled() {
                if client
                    .heartbeat(v2::HeartbeatRequest {
                        session_id: session_id.clone(),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    };

    let loops = dispatcher.spawn(shutdown.clone());

    // The leadership-gain pass has no business demoting a node it has already
    // heard from, and even if it did, the sweep puts it back.
    cluster
        .wait_for("the node to be ready once the loops are up", |view| {
            (view.node(&node_id)?.status.state == NodeState::Ready).then_some(())
        })
        .await;

    // Phase 2: destroy the READY behind the manager's back. Nothing on the
    // manager side transitions, so only a level-triggered pass can repair it.
    cluster
        .update_node(&node_id, |node| {
            node.status.state = NodeState::Unknown;
            node.status.message = "clobbered by a racing write".to_owned();
        })
        .await;

    let message = cluster
        .wait_for("the live session to reassert itself", |view| {
            let node = view.node(&node_id)?;
            (node.status.state == NodeState::Ready).then(|| node.status.message.clone())
        })
        .await;
    assert_eq!(
        message, "session registered",
        "the healed message is the same one the registration writes, or the two would \
         overwrite each other on every sweep"
    );
    assert_eq!(
        dispatcher.node_state(&node_id),
        Some(NodeState::Ready),
        "the session was never touched: no re-registration was needed"
    );

    shutdown.cancel();
    let _ = beater.await;
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}

/// A store node the leader has never heard from converges to `DOWN` once the
/// leadership-change grace period runs out — through the ordinary TTL sweep
/// and [`mark_down`], not a second path.
///
/// This is the killed-*leader* debt. A killed follower was always handled: the
/// surviving leader held a session for it, the TTL expired, `mark_down` fired,
/// the orchestrator evicted. But the node that dies *with* the leadership
/// leaves the new leader's dispatcher with no session, no TTL, nothing —
/// `mark_unknown` wrote `UNKNOWN` once and nothing ever moved it again, so a
/// three-node cluster that lost its leader ran the dead node's replicas
/// nowhere, indefinitely. Now leadership gain seeds an expectation for every
/// non-`DOWN`, non-drained store node (SWK §13.2 seeds the dispatcher's node
/// set from the store for exactly this reason), and a node that never
/// registers expires into `DOWN`, orphan timer and all.
///
/// The two exclusions are pinned by *absence of writes*, not just by final
/// state: a node already `DOWN` keeps its original status message, which any
/// resurrection round-trip (`UNKNOWN`, then `DOWN` again) would have
/// clobbered.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_the_new_leader_never_heard_from_goes_down_after_the_grace() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let shutdown = CancellationToken::new();

    // Three store nodes whose agents never call: the dead ex-leader (READY at
    // the moment of the election), a node already DOWN, and a drained node.
    let mut dead = testing::node(NodeRole::Manager);
    dead.status.state = NodeState::Ready;
    dead.status.message = "session registered".to_owned();
    let dead_id = dead.id.clone();
    let mut down = testing::node(NodeRole::Worker);
    down.status.state = NodeState::Down;
    down.status.message = "down before the election".to_owned();
    let down_id = down.id.clone();
    let mut drained = testing::node(NodeRole::Worker);
    drained.status.state = NodeState::Ready;
    drained.spec.availability = Availability::Drain;
    let drained_id = drained.id.clone();
    cluster.create(StoreObject::Node(dead)).await;
    cluster.create(StoreObject::Node(down)).await;
    cluster.create(StoreObject::Node(drained)).await;

    // A task riding on the dead node, to see the DOWN feed the orphan timer.
    let task = testing::task_on(Some(&dead_id), TaskState::Running, DesiredState::Running);
    let task_id = task.id.clone();
    cluster.create(StoreObject::Task(task)).await;

    // The dispatcher starts as leader (single-node raft): the startup pass is
    // the leadership-gain pass. Grace = 2 x 3 x 80 ms, orphaning 300 ms later.
    let mut config = fast_dispatcher_config();
    config.heartbeat.orphan_after = Duration::from_millis(300);
    let dispatcher = Dispatcher::new(cluster.store().clone(), node_id.clone(), config);
    let loops = dispatcher.spawn(shutdown.clone());

    let message = cluster
        .wait_for("the never-seen node to be marked down", |view| {
            let node = view.node(&dead_id)?;
            (node.status.state == NodeState::Down).then(|| node.status.message.clone())
        })
        .await;
    assert_eq!(
        message, "heartbeat failure",
        "the expectation must expire through the ordinary mark_down, not a parallel path"
    );

    // The DOWN that came from the expectation arms the same orphaning timer a
    // session's DOWN does.
    cluster
        .wait_for("the dead node's task to be orphaned", |view| {
            (view.task(&task_id)?.status.state == TaskState::Orphaned).then_some(())
        })
        .await;

    // By now any clock wrongly armed at leadership gain would have fired: all
    // expectations share the same deadline, and the orphaning above needed a
    // further sweep pass 300 ms past it. Absence of writes is the assertion.
    let view = cluster.store().view();
    let down_node = view.node(&down_id).expect("the down node object");
    assert_eq!(down_node.status.state, NodeState::Down);
    assert_eq!(
        down_node.status.message, "down before the election",
        "a node already down was written to: seeding resurrected it"
    );
    let drained_node = view.node(&drained_id).expect("the drained node object");
    assert_ne!(
        drained_node.status.state,
        NodeState::Down,
        "a drained node owes nobody a registration and must not be declared down"
    );
    drop(view);

    shutdown.cancel();
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}

/// A node that registers and then stops beating is marked `DOWN` when its TTL
/// expires, and its session stops being valid.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_agent_is_marked_down_when_its_ttl_expires() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    let dispatcher = Dispatcher::new(
        cluster.store().clone(),
        node_id.clone(),
        fast_dispatcher_config(),
    );
    let loops = dispatcher.spawn(shutdown.clone());
    let addr = serve(
        dispatcher.clone(),
        identity_of(&node_id, &cluster_id, NodeRole::Manager),
        shutdown.clone(),
    )
    .await;

    // Register by hand and then say nothing: no heartbeat activity at all.
    let channel = Channel::from_shared(format!("http://{addr}"))
        .expect("uri")
        .connect()
        .await
        .expect("connect");
    let mut client = v2::dispatcher_client::DispatcherClient::new(channel);
    let mut session = client
        .session(v2::SessionRequest {
            description: Vec::new(),
            session_id: String::new(),
        })
        .await
        .expect("session")
        .into_inner();
    let first = session
        .message()
        .await
        .expect("stream")
        .expect("a first message");
    let session_id = first.session_id;
    assert!(!session_id.is_empty());

    cluster
        .wait_for("the node to be marked ready", |view| {
            let node = view.node(&node_id)?;
            (node.status.state == NodeState::Ready).then_some(())
        })
        .await;

    // TTL = 3 × 80 ms.
    cluster
        .wait_for("the node to be marked down", |view| {
            let node = view.node(&node_id)?;
            (node.status.state == NodeState::Down).then(|| node.status.message.clone())
        })
        .await;
    assert_eq!(dispatcher.node_state(&node_id), Some(NodeState::Down));

    // The session is void: the agent's only correct move is to re-register.
    let error = client
        .heartbeat(v2::HeartbeatRequest {
            session_id: session_id.clone(),
        })
        .await
        .expect_err("a down node's session is invalid");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{error}");

    // And re-registering brings it back.
    let mut session = client
        .session(v2::SessionRequest {
            description: Vec::new(),
            session_id: String::new(),
        })
        .await
        .expect("re-register")
        .into_inner();
    let message = session.message().await.expect("stream").expect("message");
    assert_ne!(
        message.session_id, session_id,
        "session ids are never reused"
    );
    client
        .heartbeat(v2::HeartbeatRequest {
            session_id: message.session_id,
        })
        .await
        .expect("the fresh session beats");

    shutdown.cancel();
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}

/// After a node has been down long enough (24 h in production, milliseconds
/// here), its tasks in `[ASSIGNED, RUNNING]` are marked `ORPHANED` — released
/// without being deleted, so the history survives. Terminal tasks are left
/// alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_long_down_node_has_its_live_tasks_orphaned() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    let mut config = fast_dispatcher_config();
    config.heartbeat.orphan_after = Duration::from_millis(150);
    let dispatcher = Dispatcher::new(cluster.store().clone(), node_id.clone(), config);
    let loops = dispatcher.spawn(shutdown.clone());
    let addr = serve(
        dispatcher.clone(),
        identity_of(&node_id, &cluster_id, NodeRole::Manager),
        shutdown.clone(),
    )
    .await;

    let live = testing::task_on(Some(&node_id), TaskState::Running, DesiredState::Running);
    let live_id = live.id.clone();
    let done = testing::task_on(Some(&node_id), TaskState::Complete, DesiredState::Running);
    let done_id = done.id.clone();
    let elsewhere = testing::task_on(
        Some(&Id::generate()),
        TaskState::Running,
        DesiredState::Running,
    );
    let elsewhere_id = elsewhere.id.clone();
    cluster.create(StoreObject::Task(live)).await;
    cluster.create(StoreObject::Task(done)).await;
    cluster.create(StoreObject::Task(elsewhere)).await;

    // Register once, then go silent.
    let channel = Channel::from_shared(format!("http://{addr}"))
        .expect("uri")
        .connect()
        .await
        .expect("connect");
    let mut client = v2::dispatcher_client::DispatcherClient::new(channel);
    let mut session = client
        .session(v2::SessionRequest {
            description: Vec::new(),
            session_id: String::new(),
        })
        .await
        .expect("session")
        .into_inner();
    session.message().await.expect("stream").expect("message");

    let orphaned = cluster
        .wait_for("the live task to be orphaned", |view| {
            let task = view.task(&live_id)?;
            (task.status.state == TaskState::Orphaned).then(|| task.status.clone())
        })
        .await;
    assert_eq!(orphaned.applied_by, Some(node_id.clone()));

    let view = cluster.store().view();
    assert_eq!(
        view.task(&done_id).expect("task").status.state,
        TaskState::Complete,
        "a terminal task is already accounted for and must not be touched"
    );
    assert_eq!(
        view.task(&elsewhere_id).expect("task").status.state,
        TaskState::Running,
        "another node's tasks are not this node's business"
    );
    drop(view);

    shutdown.cancel();
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}

/// A status for a task assigned to another node is `PERMISSION_DENIED`, and
/// the desired-only `REMOVE` state is refused outright.
#[tokio::test(flavor = "multi_thread")]
async fn the_manager_refuses_spoofed_and_illegal_status_updates() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    let dispatcher = Dispatcher::new(
        cluster.store().clone(),
        node_id.clone(),
        fast_dispatcher_config(),
    );
    let loops = dispatcher.spawn(shutdown.clone());
    let addr = serve(
        dispatcher.clone(),
        identity_of(&node_id, &cluster_id, NodeRole::Manager),
        shutdown.clone(),
    )
    .await;

    let elsewhere = Id::generate();
    let theirs = testing::task_on(Some(&elsewhere), TaskState::Assigned, DesiredState::Running);
    let theirs_id = theirs.id.clone();
    let mine = testing::task_on(Some(&node_id), TaskState::Assigned, DesiredState::Running);
    let mine_id = mine.id.clone();
    cluster.create(StoreObject::Task(theirs)).await;
    cluster.create(StoreObject::Task(mine)).await;

    let channel = Channel::from_shared(format!("http://{addr}"))
        .expect("uri")
        .connect()
        .await
        .expect("connect");
    let mut client = v2::dispatcher_client::DispatcherClient::new(channel);
    let mut session = client
        .session(v2::SessionRequest {
            description: Vec::new(),
            session_id: String::new(),
        })
        .await
        .expect("session")
        .into_inner();
    let session_id = session
        .message()
        .await
        .expect("stream")
        .expect("message")
        .session_id;

    let update = |task_id: &Id, state: TaskState| {
        let status = TaskStatus::new(state, "reported");
        let mut bytes = Vec::new();
        ciborium::into_writer(&status, &mut bytes).expect("cbor");
        v2::TaskStatusUpdate {
            task_id: task_id.to_string(),
            state: state.value().into(),
            status: bytes,
        }
    };

    let error = client
        .update_task_status(v2::UpdateTaskStatusRequest {
            session_id: session_id.clone(),
            updates: vec![update(&theirs_id, TaskState::Running)],
        })
        .await
        .expect_err("anti-spoofing");
    assert_eq!(error.code(), tonic::Code::PermissionDenied, "{error}");

    let error = client
        .update_task_status(v2::UpdateTaskStatusRequest {
            session_id: session_id.clone(),
            updates: vec![update(&mine_id, TaskState::Remove)],
        })
        .await
        .expect_err("REMOVE is desired-only");
    assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");

    // An unknown task is skipped, not an error.
    client
        .update_task_status(v2::UpdateTaskStatusRequest {
            session_id: session_id.clone(),
            updates: vec![update(&Id::generate(), TaskState::Running)],
        })
        .await
        .expect("unknown tasks are skipped");

    // A stale session is refused.
    let error = client
        .update_task_status(v2::UpdateTaskStatusRequest {
            session_id: "not-the-session".to_owned(),
            updates: vec![update(&mine_id, TaskState::Running)],
        })
        .await
        .expect_err("stale session");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{error}");

    shutdown.cancel();
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}

/// A manager that loses its place in the sequence chain must not be believed:
/// the agent drops the stream, re-opens it, and applies the fresh snapshot.
/// This needs a deliberately broken manager, so the server here is
/// hand-written.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequence_gap_makes_the_agent_re_sync_from_a_fresh_snapshot() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    let task = testing::task_on(Some(&node_id), TaskState::Assigned, DesiredState::Running);
    let task_id = task.id.clone();
    let opens = Arc::new(AtomicUsize::new(0));
    let gappy = GappyManager {
        task: task.clone(),
        opens: Arc::clone(&opens),
    };
    let addr = serve_raw(
        gappy,
        identity_of(&node_id, &cluster_id, NodeRole::Worker),
        shutdown.clone(),
    )
    .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let db = satl_agent::TaskDb::open(dir.path()).expect("task db");
    let sink = RecordingSink::new();
    let agent = Agent::new(
        fast_agent_config(node_id.clone(), &node_id, addr),
        Arc::clone(&sink),
        Loopback::to(addr).await,
        db,
        SessionReporter::new(),
        Arc::new(|| testing::description("worker-1")),
    );
    let agent_handle = agent.spawn(shutdown.clone());

    testing::eventually(
        "the assignment stream to be re-opened after the gap",
        || opens.load(Ordering::SeqCst) >= 2,
    )
    .await;
    testing::eventually("the re-synced task to be applied", || {
        sink.tasks().contains_key(&task_id)
    })
    .await;

    // The bogus diff must never have been applied: it carried a task the
    // agent should not have.
    assert!(
        !sink
            .calls()
            .iter()
            .any(|call| matches!(call, testing::SinkCall::RemoveTask(_))),
        "the gapped diff was applied: {:?}",
        sink.calls()
    );

    shutdown.cancel();
    let _ = agent_handle.await;
    cluster.shutdown().await;
}

/// A manager whose second assignment message claims to apply to a state the
/// agent was never in.
struct GappyManager {
    task: satl_core::Task,
    opens: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl v2::dispatcher_server::Dispatcher for GappyManager {
    type SessionStream = ReceiverStream<Result<v2::SessionMessage, Status>>;
    type AssignmentsStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<v2::AssignmentsMessage, Status>> + Send>>;

    async fn session(
        &self,
        _request: Request<v2::SessionRequest>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let _ = tx
                .send(Ok(v2::SessionMessage {
                    session_id: "gappy-session".to_owned(),
                    node: None,
                    managers: Vec::new(),
                    root_ca_bundle: None,
                }))
                .await;
            // Hold the stream open.
            tokio::time::sleep(Duration::from_hours(1)).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn heartbeat(
        &self,
        _request: Request<v2::HeartbeatRequest>,
    ) -> Result<Response<v2::HeartbeatResponse>, Status> {
        Ok(Response::new(v2::HeartbeatResponse {
            period: Some(prost_types::Duration {
                seconds: 1,
                nanos: 0,
            }),
        }))
    }

    async fn update_task_status(
        &self,
        _request: Request<v2::UpdateTaskStatusRequest>,
    ) -> Result<Response<v2::UpdateTaskStatusResponse>, Status> {
        Ok(Response::new(v2::UpdateTaskStatusResponse {}))
    }

    async fn assignments(
        &self,
        _request: Request<v2::AssignmentsRequest>,
    ) -> Result<Response<Self::AssignmentsStream>, Status> {
        let open = self.opens.fetch_add(1, Ordering::SeqCst);
        let task = self.task.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let encoded = satl_dispatcher::codec::encode_task(&task).expect("encode");
            let change = v2::AssignmentChange {
                assignment: Some(v2::Assignment {
                    item: Some(v2::assignment::Item::Task(encoded)),
                }),
                action: v2::assignment_change::Action::Update as i32,
            };
            if open == 0 {
                // A correct snapshot with nothing in it…
                let _ = tx
                    .send(Ok(v2::AssignmentsMessage {
                        r#type: v2::assignments_message::Type::Complete as i32,
                        applies_to: String::new(),
                        results_in: "chain-1".to_owned(),
                        changes: Vec::new(),
                    }))
                    .await;
                // …then a diff that applies to a state the agent was never
                // in. It carries a removal so that applying it would be
                // visible in the sink.
                let _ = tx
                    .send(Ok(v2::AssignmentsMessage {
                        r#type: v2::assignments_message::Type::Incremental as i32,
                        applies_to: "chain-99".to_owned(),
                        results_in: "chain-100".to_owned(),
                        changes: vec![v2::AssignmentChange {
                            assignment: Some(v2::Assignment {
                                item: Some(v2::assignment::Item::Task(
                                    satl_dispatcher::codec::task_removal(&task.id),
                                )),
                            }),
                            action: v2::assignment_change::Action::Remove as i32,
                        }],
                    }))
                    .await;
                tokio::time::sleep(Duration::from_hours(1)).await;
            } else {
                // The re-opened stream: a fresh, correct snapshot.
                let _ = tx
                    .send(Ok(v2::AssignmentsMessage {
                        r#type: v2::assignments_message::Type::Complete as i32,
                        applies_to: String::new(),
                        results_in: "chain-2".to_owned(),
                        changes: vec![change],
                    }))
                    .await;
                tokio::time::sleep(Duration::from_hours(1)).await;
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// A worker that is not the leader gets told where the leader is, rather than
/// a generic failure — and the assignment set of a node with no tasks is an
/// empty snapshot, not an absent one.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_node_still_gets_a_complete_snapshot() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    let dispatcher = Dispatcher::new(
        cluster.store().clone(),
        node_id.clone(),
        fast_dispatcher_config(),
    );
    let loops = dispatcher.spawn(shutdown.clone());
    let addr = serve(
        dispatcher.clone(),
        identity_of(&node_id, &cluster_id, NodeRole::Manager),
        shutdown.clone(),
    )
    .await;

    let channel = Channel::from_shared(format!("http://{addr}"))
        .expect("uri")
        .connect()
        .await
        .expect("connect");
    let mut client = v2::dispatcher_client::DispatcherClient::new(channel);
    let mut session = client
        .session(v2::SessionRequest {
            description: satl_dispatcher::codec::encode_description(&testing::description(
                "worker-1",
            ))
            .expect("encode"),
            session_id: String::new(),
        })
        .await
        .expect("session")
        .into_inner();
    let first = session
        .message()
        .await
        .expect("stream")
        .expect("a first message");
    assert!(first.node.is_some(), "the node object rides the session");

    let mut assignments = client
        .assignments(v2::AssignmentsRequest {
            session_id: first.session_id.clone(),
        })
        .await
        .expect("assignments")
        .into_inner();
    let snapshot = assignments
        .message()
        .await
        .expect("stream")
        .expect("a snapshot");
    assert_eq!(
        snapshot.r#type(),
        v2::assignments_message::Type::Complete,
        "the first message on the stream is always a complete snapshot"
    );
    assert!(snapshot.applies_to.is_empty());
    assert!(!snapshot.results_in.is_empty());
    assert!(snapshot.changes.is_empty());

    // The description reached the store.
    cluster
        .wait_for("the description to be recorded", |view| {
            let node = view.node(&node_id)?;
            node.description.clone()
        })
        .await;

    // An unregistered node cannot open an assignment stream.
    let error = client
        .assignments(v2::AssignmentsRequest {
            session_id: "bogus".to_owned(),
        })
        .await
        .expect_err("a stale session cannot stream assignments");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{error}");

    let _ = BTreeSet::<Id>::new();
    shutdown.cancel();
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}

/// Overlay networks over the real protocol: a network is shipped with the first
/// task that attaches to it, re-shipped when a peer's endpoint appears or
/// disappears, and torn down with the last attached task.
///
/// The peer endpoint is simulated the only way a single-node test can: a second
/// node object with an underlay address, and a task bound to it. That is exactly
/// what the endpoint table is built from, so the manager cannot tell the
/// difference.
#[tokio::test(flavor = "multi_thread")]
async fn a_network_is_shipped_with_its_first_task_updated_on_endpoints_and_removed_with_the_last() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    let dispatcher = Dispatcher::new(
        cluster.store().clone(),
        node_id.clone(),
        fast_dispatcher_config(),
    );
    let loops = dispatcher.spawn(shutdown.clone());
    let addr = serve(
        dispatcher.clone(),
        identity_of(&node_id, &cluster_id, NodeRole::Manager),
        shutdown.clone(),
    )
    .await;

    // The overlay, a peer node with an underlay address, and one task on each
    // node attached to that network — the state the allocator and the scheduler
    // leave behind.
    let network =
        testing::with_node_gateway(testing::overlay_network("blue"), &node_id, "10.100.4.2");
    let network_id = network.id.clone();
    let mut peer_node = testing::node(NodeRole::Worker);
    peer_node.status.addr = "10.2.0.9:54321".to_owned();
    let peer_id = peer_node.id.clone();

    let mine = testing::with_network(
        testing::task_on(Some(&node_id), TaskState::Assigned, DesiredState::Running),
        &network,
        "10.100.4.5/24",
    );
    let peer_task = testing::with_network(
        testing::task_on(Some(&peer_id), TaskState::Assigned, DesiredState::Running),
        &network,
        "10.100.4.9/24",
    );
    let my_task_id = mine.id.clone();
    let peer_task_id = peer_task.id.clone();

    cluster.create(StoreObject::Network(network)).await;
    cluster.create(StoreObject::Node(peer_node)).await;
    cluster.create(StoreObject::Task(mine)).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let db = satl_agent::TaskDb::open(dir.path()).expect("task db");
    let sink = RecordingSink::new();
    let agent = Agent::new(
        fast_agent_config(node_id.clone(), &node_id, addr),
        Arc::clone(&sink),
        Loopback::to(addr).await,
        db,
        SessionReporter::new(),
        Arc::new(|| testing::description("worker-1")),
    );
    let agent_handle = agent.spawn(shutdown.clone());

    // 1. The network arrives with its first attached task, and its own endpoint
    //    is in the table.
    testing::eventually("the network to reach the worker", || {
        sink.networks().contains_key(&network_id)
    })
    .await;
    assert!(
        sink.tasks().contains_key(&my_task_id),
        "the task must arrive with (never before) its network"
    );
    let held = sink.networks();
    let held = held.get(&network_id).expect("the network is held");
    assert_eq!(held.network.spec.annotations.name, "blue");
    assert_eq!(
        held.network.node_gateways.get(&node_id).map(String::as_str),
        Some("10.100.4.2"),
        "the node's own gateway address rides along with the network"
    );
    let own = held.endpoints.get(&my_task_id).expect("own endpoint");
    assert_eq!(
        own.addr,
        "10.100.4.5".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert!(
        held.remote_endpoints(&node_id).next().is_none(),
        "no peer has a task on it yet"
    );

    // 2. A peer's task on the same network re-ships it: that is FDB
    //    distribution (architecture §11.2).
    cluster.create(StoreObject::Task(peer_task)).await;
    testing::eventually("the peer endpoint to reach the worker", || {
        sink.networks()
            .get(&network_id)
            .is_some_and(|held| held.endpoints.contains_key(&peer_task_id))
    })
    .await;
    let held = sink.networks();
    let held = held.get(&network_id).expect("the network is held");
    let remote: Vec<_> = held.remote_endpoints(&node_id).collect();
    assert_eq!(remote.len(), 1, "exactly one remote endpoint to program");
    assert_eq!(
        remote[0].vtep,
        "10.2.0.9".parse::<std::net::Ipv4Addr>().unwrap(),
        "the peer's underlay address, without its ephemeral control-plane port"
    );
    assert_eq!(
        remote[0].mac().to_string(),
        "02:42:0a:64:04:09",
        "the mac is derived from the overlay address, never distributed"
    );

    // 3. The peer's task stops: its endpoint goes, the network stays.
    cluster
        .update_task(&peer_task_id, |task| {
            task.status = TaskStatus::new(TaskState::Shutdown, "stopped");
        })
        .await;
    testing::eventually("the peer endpoint to be withdrawn", || {
        sink.networks()
            .get(&network_id)
            .is_some_and(|held| !held.endpoints.contains_key(&peer_task_id))
    })
    .await;
    assert!(
        sink.networks().contains_key(&network_id),
        "this node still has a task on the network"
    );

    // 4. The last attached task on THIS node releases the network, and the
    //    teardown happens after the task is released.
    sink.clear_calls();
    cluster
        .commit(vec![satl_core::StoreAction::Remove {
            kind: satl_core::ObjectKind::Task,
            id: my_task_id.clone(),
        }])
        .await;
    testing::eventually("the network to be torn down", || {
        !sink.networks().contains_key(&network_id)
    })
    .await;
    let calls = sink.calls();
    let task_at = calls
        .iter()
        .position(|call| matches!(call, testing::SinkCall::RemoveTask(id) if *id == my_task_id))
        .expect("the task was released");
    let network_at = calls
        .iter()
        .position(|call| matches!(call, testing::SinkCall::RemoveNetwork(id) if *id == network_id))
        .expect("the network was torn down");
    assert!(
        task_at < network_at,
        "the jail must be released before its network: {calls:?}"
    );

    shutdown.cancel();
    let _ = agent_handle.await;
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}

/// A `COMPLETE` snapshot orders a network ahead of the tasks that need it — the
/// property a worker relies on when it programs an overlay before handing a jail
/// over to the executor.
#[tokio::test(flavor = "multi_thread")]
async fn a_complete_snapshot_puts_the_network_ahead_of_its_tasks_on_the_wire() {
    let cluster = TestCluster::start().await;
    let node_id = cluster.node_id().clone();
    let cluster_id = cluster_id_of(&cluster);
    let shutdown = CancellationToken::new();

    let dispatcher = Dispatcher::new(
        cluster.store().clone(),
        node_id.clone(),
        fast_dispatcher_config(),
    );
    let loops = dispatcher.spawn(shutdown.clone());
    let addr = serve(
        dispatcher.clone(),
        identity_of(&node_id, &cluster_id, NodeRole::Manager),
        shutdown.clone(),
    )
    .await;

    let secret = testing::secret("db.password", b"hunter2");
    let network = testing::overlay_network("blue");
    let network_id = network.id.clone();
    let task = testing::with_network(
        testing::with_secret(
            testing::task_on(Some(&node_id), TaskState::Assigned, DesiredState::Running),
            &secret,
        ),
        &network,
        "10.100.4.5/24",
    );
    let task_id = task.id.clone();
    cluster.create(StoreObject::Secret(secret.clone())).await;
    cluster.create(StoreObject::Network(network)).await;
    cluster.create(StoreObject::Task(task)).await;

    // Read the snapshot off the wire, unmediated by the agent.
    let channel = Channel::from_shared(format!("http://{addr}"))
        .expect("uri")
        .connect()
        .await
        .expect("connect");
    let mut client = v2::dispatcher_client::DispatcherClient::new(channel);
    let session = client
        .session(v2::SessionRequest {
            description: satl_dispatcher::codec::encode_description(&testing::description(
                "worker-1",
            ))
            .expect("encode"),
            session_id: String::new(),
        })
        .await
        .expect("session")
        .into_inner()
        .message()
        .await
        .expect("stream")
        .expect("a first message");
    let snapshot = client
        .assignments(v2::AssignmentsRequest {
            session_id: session.session_id.clone(),
        })
        .await
        .expect("assignments")
        .into_inner()
        .message()
        .await
        .expect("stream")
        .expect("a snapshot");
    assert_eq!(snapshot.r#type(), v2::assignments_message::Type::Complete);

    let kinds: Vec<&str> = snapshot
        .changes
        .iter()
        .map(|change| {
            match change
                .assignment
                .as_ref()
                .and_then(|assignment| assignment.item.as_ref())
            {
                Some(v2::assignment::Item::Secret(_)) => "secret",
                Some(v2::assignment::Item::Config(_)) => "config",
                Some(v2::assignment::Item::Network(_)) => "network",
                Some(v2::assignment::Item::Task(_)) => "task",
                None => "empty",
            }
        })
        .collect();
    assert_eq!(
        kinds,
        vec!["secret", "network", "task"],
        "dependencies before dependents, networks included"
    );

    // The network envelope decodes to the object plus the endpoint table.
    let Some(v2::assignment::Item::Network(wire)) = snapshot.changes[1]
        .assignment
        .as_ref()
        .and_then(|assignment| assignment.item.as_ref())
    else {
        panic!("expected a network envelope second: {kinds:?}");
    };
    assert_eq!(wire.id, network_id.to_string());
    let decoded = satl_dispatcher::codec::decode_network(wire).expect("decode");
    assert_eq!(*decoded.id(), network_id);
    assert!(
        decoded.endpoints.contains_key(&task_id),
        "the node's own task is an endpoint of the network"
    );

    shutdown.cancel();
    for handle in loops {
        let _ = handle.await;
    }
    cluster.shutdown().await;
}
