// SPDX-License-Identifier: BSD-2-Clause
//! The worker side: one session with one manager (architecture §7.2,
//! SWK §14).
//!
//! ```text
//!   ┌─ choose endpoint ── local socket if this node is a manager, else a
//!   │                     weighted-random manager from the session list
//!   ├─ Session ─────────▶ registration; the manager mints the session id
//!   │                     ├── re-report every persisted task status
//!   │                     └── reset the reconnect backoff
//!   ├─ four activities running concurrently, all bound to that session:
//!   │    heartbeat        beat, then sleep the period the SERVER dictated
//!   │    session          node object / manager list / root CA updates,
//!   │                     plus the 20 s node-description refresh
//!   │    assignments      COMPLETE, then INCREMENTAL; gap ⇒ re-open
//!   │    status           coalesced UpdateTaskStatus batches
//!   └─ any error tears the whole session down; back off and re-register
//! ```
//!
//! Three rules are easy to get wrong and are therefore explicit here:
//!
//! - **The server dictates the heartbeat period.** The agent sleeps what the
//!   last `HeartbeatResponse` said, never a period of its own choosing.
//! - **A sequence gap re-opens the assignment stream**, it does not patch the
//!   diff and does not (by itself) drop the session — see [`crate::sequence`].
//! - **On every registration the agent re-reports every persisted status.**
//!   The manager it just met may have missed everything since the last one.
//!
//! Everything that touches the network is behind [`ChannelFactory`], and
//! everything that touches jails is behind
//! [`AssignmentSink`](crate::sink::AssignmentSink), so the whole loop runs in
//! a unit test.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use satl_core::defaults::DESCRIPTION_REFRESH;
use satl_core::{DesiredState, Id, Node, NodeDescription, ResourceRequirements, Task, TaskStatus};
use satl_proto::v2;
use satl_proto::v2::dispatcher_client::DispatcherClient;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;
use tracing::Instrument as _;

use crate::assignment::{AssignmentChange, AssignmentItem, ChangeAction, ObjectRef};
use crate::codec;
use crate::error::{ApplyError, SessionError};
use crate::peer::{Endpoint, ManagerPeer, choose_endpoint_with};
use crate::sequence::{MessageKind, SequenceTracker};
use crate::sink::AssignmentSink;
use crate::status::StatusQueue;
use crate::{Backoff, RPC_TIMEOUT, STATUS_FLUSH_INTERVAL, STATUS_FLUSH_MAX};

/// Dialing a manager failed.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct ConnectError {
    /// Whatever the connector's transport reported.
    #[source]
    pub source: Box<dyn std::error::Error + Send + Sync>,
}

impl ConnectError {
    /// Wraps a transport error.
    pub fn new(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            source: Box::new(source),
        }
    }
}

/// How the agent obtains a gRPC channel to an endpoint.
///
/// `satld` implements this with the cluster's mTLS client config for remote
/// managers and a unix-socket connector for the local one; tests implement it
/// with a loopback channel. Keeping it out of this crate is what lets the
/// session loop be tested without TLS, and keeps the crate free of the
/// hyper/tower plumbing a unix connector needs.
pub trait ChannelFactory: Send + Sync + 'static {
    /// Connect to `endpoint`.
    fn connect(
        &self,
        endpoint: &Endpoint,
    ) -> impl Future<Output = Result<Channel, ConnectError>> + Send;
}

/// Produces the node description sent at registration (architecture §8.3).
///
/// Refreshed every 20 s; a change closes the session so the next registration
/// carries it.
///
/// The description is also how a node publishes its **own underlay address**
/// ([`NodeDescription::data_addr`]): managers derive VXLAN tunnel endpoints from
/// it (architecture §11.2), and nothing else on the node object is that address —
/// what the dispatcher observes is where the *control plane* connection came
/// from. An implementation that leaves it `None` therefore gets a node whose
/// tasks no peer can reach over an overlay, and the manager says so in its log.
pub trait NodeDescriber: Send + Sync + 'static {
    /// This node's current description.
    fn describe(&self) -> NodeDescription;
}

impl<F> NodeDescriber for F
where
    F: Fn() -> NodeDescription + Send + Sync + 'static,
{
    fn describe(&self) -> NodeDescription {
        self()
    }
}

/// Agent tuning. The defaults are architecture §15.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// This node's ID (its certificate CN).
    pub node_id: Id,
    /// The local dispatcher socket, when this node is itself a manager.
    /// Preferred over every remote manager (architecture §7.2).
    pub local_socket: Option<PathBuf>,
    /// Managers to try before the first session message arrives.
    pub bootstrap_managers: Vec<ManagerPeer>,
    /// Timeout on session initiation and on every unary RPC.
    pub rpc_timeout: Duration,
    /// How often queued statuses are flushed to the manager.
    pub status_flush_interval: Duration,
    /// Queued statuses that force an immediate flush.
    pub status_flush_max: usize,
    /// How often the node description is recomputed.
    pub description_refresh: Duration,
}

impl AgentConfig {
    /// Defaults for `node_id`.
    #[must_use]
    pub fn new(node_id: Id) -> Self {
        Self {
            node_id,
            local_socket: None,
            bootstrap_managers: Vec::new(),
            rpc_timeout: RPC_TIMEOUT,
            status_flush_interval: STATUS_FLUSH_INTERVAL,
            status_flush_max: STATUS_FLUSH_MAX,
            description_refresh: DESCRIPTION_REFRESH,
        }
    }
}

/// What the session stream last told this agent.
///
/// Published on a watch channel so the rest of the daemon (node runtime, CA
/// renewal, `satl info`) can react without knowing about sessions.
#[derive(Debug, Clone, Default)]
pub struct AgentState {
    /// The session currently held, if any.
    pub session_id: Option<String>,
    /// This node's own object, as the manager sees it.
    pub node: Option<Node>,
    /// The managers to choose from.
    pub managers: Vec<ManagerPeer>,
    /// The current root CA bundle (PEM) — how root rotation reaches workers.
    pub root_ca: Option<Vec<u8>>,
}

impl AgentState {
    /// Whether a session is currently established.
    #[must_use]
    pub fn connected(&self) -> bool {
        self.session_id.is_some()
    }
}

/// The agent's status sink: a coalescing queue drained by the session's
/// status activity (SWK §14.5).
///
/// It outlives individual sessions on purpose — a status produced while the
/// agent is between managers is kept and delivered to the next one, and the
/// local task DB is the backstop for anything lost beyond that.
#[derive(Debug)]
pub struct SessionReporter {
    queue: Mutex<StatusQueue>,
    ready: Notify,
    flush_at: usize,
}

impl Default for SessionReporter {
    fn default() -> Self {
        Self {
            queue: Mutex::new(StatusQueue::new()),
            ready: Notify::new(),
            flush_at: STATUS_FLUSH_MAX,
        }
    }
}

impl SessionReporter {
    /// A reporter flushing at the default threshold.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Queues a status for delivery.
    pub fn enqueue(&self, task_id: &Id, status: TaskStatus) {
        let pending = {
            let mut queue = self.queue();
            queue.push(task_id, status);
            queue.len()
        };
        if pending >= self.flush_at {
            self.ready.notify_one();
        }
    }

    /// How many statuses are waiting.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.queue().len()
    }

    fn take(&self, max: usize) -> Vec<(Id, TaskStatus)> {
        self.queue().take(max)
    }

    fn requeue(&self, batch: Vec<(Id, TaskStatus)>) {
        self.queue().requeue(batch);
    }

    fn queue(&self) -> MutexGuard<'_, StatusQueue> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl satl_agent::StatusReporter for SessionReporter {
    async fn report(&self, task_id: &Id, status: TaskStatus) {
        tracing::debug!(
            task_id = %task_id,
            state = %status.state,
            "queueing a task status for the dispatcher"
        );
        self.enqueue(task_id, status);
    }
}

/// Applies decoded assignment messages to the worker in the pinned order.
///
/// Pure except for the sink calls, so the whole application contract —
/// order, snapshot reset, desired-state suppression — is unit-testable.
#[derive(Debug, Default)]
pub struct AssignmentApplier {
    /// Desired state and resources last handed to the worker, per task.
    ///
    /// Re-applying a task the worker already drives cancels the controller
    /// operation in flight (a `TaskManager` treats an update as
    /// "re-dispatch"), and every status the agent reports comes back as a
    /// task update. The only parts of a task the worker can act on are its
    /// desired state and — since M6g's hot resize — its resources (rctl
    /// limits re-apply to the live jail); the rest of the spec is immutable,
    /// so that is what is compared.
    applied: BTreeMap<Id, (DesiredState, ResourceRequirements)>,
    /// Network assignments last handed to the sink, keyed by network ID.
    ///
    /// Kept whole rather than as a version, because a network assignment's
    /// version does not move when its endpoint table does
    /// (`proto/dispatcher.proto`). This is also the only record of which
    /// networks the node holds: unlike secrets and configs, a `COMPLETE`
    /// snapshot does not reset them wholesale (see
    /// [`AssignmentSink::apply_network`]), so the applier is what knows which
    /// ones a snapshot no longer mentions.
    networks: BTreeMap<Id, crate::assignment::NetworkAssignment>,
    /// Whether the startup pass over the local task DB has run.
    initialized: bool,
}

impl AssignmentApplier {
    /// A fresh applier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the local task DB has been reconciled yet.
    #[must_use]
    pub fn initialized(&self) -> bool {
        self.initialized
    }

    /// The desired states and resources currently handed to the worker.
    #[must_use]
    pub fn applied(&self) -> &BTreeMap<Id, (DesiredState, ResourceRequirements)> {
        &self.applied
    }

    /// The network assignments currently programmed on this node.
    #[must_use]
    pub fn networks(&self) -> &BTreeMap<Id, crate::assignment::NetworkAssignment> {
        &self.networks
    }

    /// Applies one message.
    ///
    /// # Errors
    ///
    /// [`ApplyError`] when the worker refuses a task; the caller drops the
    /// session, because an agent that cannot apply what it was told is not
    /// running what the cluster believes it is running.
    pub async fn apply<S: AssignmentSink>(
        &mut self,
        kind: MessageKind,
        changes: Vec<AssignmentChange>,
        sink: &S,
    ) -> Result<(), ApplyError> {
        match kind {
            MessageKind::Complete => self.apply_snapshot(changes, sink).await,
            MessageKind::Incremental => self.apply_diff(changes, sink).await,
        }
    }

    #[tracing::instrument(skip_all, fields(changes = changes.len()))]
    async fn apply_snapshot<S: AssignmentSink>(
        &mut self,
        changes: Vec<AssignmentChange>,
        sink: &S,
    ) -> Result<(), ApplyError> {
        let mut secrets = Vec::new();
        let mut configs = Vec::new();
        let mut networks = Vec::new();
        let mut tasks = Vec::new();
        for change in changes {
            match change.item {
                Some(AssignmentItem::Secret(secret)) => secrets.push(*secret),
                Some(AssignmentItem::Config(config)) => configs.push(*config),
                Some(AssignmentItem::Network(network)) => networks.push(*network),
                Some(AssignmentItem::Task(task)) => tasks.push(*task),
                None => tracing::warn!(
                    kind = ?change.key.kind,
                    id = %change.key.id,
                    "a complete snapshot carried a removal; ignoring it"
                ),
            }
        }

        // Dependencies first, and wholesale: the snapshot is authoritative.
        sink.reset_secrets(secrets);
        sink.reset_configs(configs);

        // Networks are *not* reset wholesale — tearing down a live VTEP on
        // every re-registration would flap the jails attached to it. Each one
        // is re-applied (suppressed when identical), and the ones this snapshot
        // no longer mentions are removed after their tasks, below.
        let live_networks: BTreeSet<Id> = networks
            .iter()
            .map(|network| network.id().clone())
            .collect();
        for network in networks {
            self.apply_network(network, sink).await?;
        }

        let live: BTreeSet<Id> = tasks.iter().map(|task| task.id.clone()).collect();
        if !self.initialized {
            // The startup pass: tasks still assigned resume from their
            // persisted status (a running jail is re-attached, not
            // restarted); the rest are released (architecture §7.2).
            let resumed = sink
                .init(&live)
                .await
                .map_err(|source| ApplyError::Init { source })?;
            self.initialized = true;
            // Anything the worker resumed is already being driven — handing it
            // over again would cancel the operation the resumed task manager
            // just started. But it is driven at the desired state the *local
            // DB* held, which is what this seed must record: seeding it with
            // the desired state of the snapshot instead claimed the worker had
            // already been told something it had never heard, and the loop
            // below then skipped it as "already applied".
            //
            // What that looked like to an operator: a node comes back from a
            // failure, re-attaches its surviving container ("re-armed exit
            // watch"), the manager had meanwhile moved that task to desired
            // `Shutdown` — and the jail ran forever, outliving its task, with
            // the service stuck at 7/6. Same suppression for a scale-down
            // whose `Remove` landed while the agent was between sessions:
            // `satl service ls` sat at 6/3 and nothing was ever asked to stop.
            self.applied.extend(resumed);
        }

        for task in tasks {
            self.apply_task(task, sink).await?;
        }

        // Tasks absent from the snapshot are gone (SWK §14.2).
        let mut local = sink.task_ids().await;
        local.extend(self.applied.keys().cloned());
        for task_id in local {
            if live.contains(&task_id) {
                continue;
            }
            self.remove_task(&task_id, sink, "absent from the assignment snapshot")
                .await?;
        }

        // Networks last, and only after their tasks: dependents before
        // dependencies on the way down.
        let stale: Vec<Id> = self
            .networks
            .keys()
            .filter(|id| !live_networks.contains(*id))
            .cloned()
            .collect();
        for network_id in stale {
            self.remove_network(&network_id, sink, "absent from the assignment snapshot")
                .await?;
        }

        // The loop above removes what this *process* knew; a host interface a
        // previous process programmed is invisible to it. Hand the complete
        // set to the sink so it can reconcile host state — awaited here, so
        // no incremental can race the sweep.
        sink.networks_synced(self.networks.values().cloned().collect())
            .await;
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(changes = changes.len()))]
    async fn apply_diff<S: AssignmentSink>(
        &mut self,
        changes: Vec<AssignmentChange>,
        sink: &S,
    ) -> Result<(), ApplyError> {
        // The sender already orders the batch; re-imposing the order here makes
        // it independent of the sender's good behaviour. Removals go first,
        // dependents before dependencies, then updates the other way round —
        // the same two orders `ObjectRef` documents and `take_changes` sorts by.
        for kind in ObjectRef::teardown_order() {
            for change in changes
                .iter()
                .filter(|change| change.key.kind == kind && change.action == ChangeAction::Remove)
            {
                match kind {
                    ObjectRef::Secret => sink.remove_secret(&change.key.id),
                    ObjectRef::Config => sink.remove_config(&change.key.id),
                    ObjectRef::Network => {
                        self.remove_network(
                            &change.key.id,
                            sink,
                            "no task on this node is attached to it any more",
                        )
                        .await?;
                    }
                    ObjectRef::Task => {
                        self.remove_task(&change.key.id, sink, "no longer assigned to this node")
                            .await?;
                    }
                }
            }
        }

        for kind in ObjectRef::apply_order() {
            for change in changes
                .iter()
                .filter(|change| change.key.kind == kind && change.action == ChangeAction::Update)
            {
                match &change.item {
                    Some(AssignmentItem::Secret(secret)) => sink.put_secret((**secret).clone()),
                    Some(AssignmentItem::Config(config)) => sink.put_config((**config).clone()),
                    Some(AssignmentItem::Network(network)) => {
                        self.apply_network((**network).clone(), sink).await?;
                    }
                    Some(AssignmentItem::Task(task)) => {
                        self.apply_task((**task).clone(), sink).await?;
                    }
                    None => tracing::warn!(
                        kind = ?kind,
                        id = %change.key.id,
                        "an update change carried no object; ignoring it"
                    ),
                }
            }
        }
        Ok(())
    }

    async fn apply_task<S: AssignmentSink>(
        &mut self,
        task: Task,
        sink: &S,
    ) -> Result<(), ApplyError> {
        let previous = self.applied.get(&task.id).copied();
        let current = (task.desired_state, task.spec.resources);
        if previous == Some(current) {
            tracing::trace!(task_id = %task.id, "task already applied as it stands");
            return Ok(());
        }
        let task_id = task.id.clone();
        let desired = task.desired_state;
        tracing::info!(
            task_id = %task_id,
            service_id = ?task.service_id,
            from = ?previous.map(|(state, _)| state.to_string()),
            to = %desired,
            observed = %task.status.state,
            "applying an assigned task"
        );
        sink.apply_task(task)
            .await
            .map_err(|source| ApplyError::Task {
                task_id: task_id.to_string(),
                source,
            })?;
        self.applied.insert(task_id, current);
        Ok(())
    }

    /// Hands a network to the sink unless the sink already holds exactly it.
    ///
    /// The suppression matters more here than for a task: an unchanged network
    /// arrives again on every re-registration, and re-programming a live VTEP
    /// is work (and log noise) for nothing. It has to be a full comparison —
    /// the version does not move with the endpoint table.
    async fn apply_network<S: AssignmentSink>(
        &mut self,
        assignment: crate::assignment::NetworkAssignment,
        sink: &S,
    ) -> Result<(), ApplyError> {
        let network_id = assignment.id().clone();
        match self.networks.get(&network_id) {
            Some(held) if *held == assignment => {
                tracing::trace!(network_id = %network_id, "network already programmed as assigned");
                return Ok(());
            }
            Some(held) => {
                let changes = assignment.endpoint_changes(held);
                tracing::info!(
                    network_id = %network_id,
                    endpoints = assignment.endpoints.len(),
                    added = changes.added.len(),
                    removed = changes.removed.len(),
                    moved = changes.moved.len(),
                    "re-programming a network: its endpoint table moved"
                );
            }
            None => tracing::info!(
                network_id = %network_id,
                name = %assignment.network.spec.annotations.name,
                endpoints = assignment.endpoints.len(),
                "programming a newly assigned network"
            ),
        }
        sink.apply_network(assignment.clone())
            .await
            .map_err(|source| ApplyError::Network {
                network_id: network_id.to_string(),
                source,
            })?;
        self.networks.insert(network_id, assignment);
        Ok(())
    }

    async fn remove_network<S: AssignmentSink>(
        &mut self,
        network_id: &Id,
        sink: &S,
        why: &'static str,
    ) -> Result<(), ApplyError> {
        if !self.networks.contains_key(network_id) {
            tracing::debug!(
                network_id = %network_id,
                "asked to remove a network this node never programmed; nothing to do"
            );
            return Ok(());
        }
        tracing::info!(network_id = %network_id, why, "tearing down a network");
        sink.remove_network(network_id)
            .await
            .map_err(|source| ApplyError::NetworkRemove {
                network_id: network_id.to_string(),
                source,
            })?;
        self.networks.remove(network_id);
        Ok(())
    }

    async fn remove_task<S: AssignmentSink>(
        &mut self,
        task_id: &Id,
        sink: &S,
        why: &'static str,
    ) -> Result<(), ApplyError> {
        tracing::info!(task_id = %task_id, why, "releasing a task");
        sink.remove_task(task_id)
            .await
            .map_err(|source| ApplyError::Remove {
                task_id: task_id.to_string(),
                source,
            })?;
        self.applied.remove(task_id);
        Ok(())
    }
}

/// Decodes one assignment message into domain changes.
fn decode_message(
    message: &v2::AssignmentsMessage,
) -> Result<(MessageKind, Vec<AssignmentChange>), codec::CodecError> {
    let kind = match message.r#type() {
        v2::assignments_message::Type::Complete => MessageKind::Complete,
        v2::assignments_message::Type::Incremental => MessageKind::Incremental,
        v2::assignments_message::Type::Unspecified => {
            return Err(codec::CodecError::Enum {
                enum_name: "AssignmentsMessage.Type",
                value: message.r#type,
            });
        }
    };
    let mut changes = Vec::with_capacity(message.changes.len());
    for change in &message.changes {
        let action = match change.action() {
            v2::assignment_change::Action::Update => ChangeAction::Update,
            v2::assignment_change::Action::Remove => ChangeAction::Remove,
            v2::assignment_change::Action::Unspecified => {
                return Err(codec::CodecError::Enum {
                    enum_name: "AssignmentChange.Action",
                    value: change.action,
                });
            }
        };
        let item = change
            .assignment
            .as_ref()
            .and_then(|assignment| assignment.item.as_ref())
            .ok_or(codec::CodecError::Missing {
                kind: "AssignmentChange",
                field: "assignment",
            })?;
        changes.push(decode_change(action, item)?);
    }
    Ok((kind, changes))
}

fn decode_change(
    action: ChangeAction,
    item: &v2::assignment::Item,
) -> Result<AssignmentChange, codec::CodecError> {
    // A removal carries only an ID by contract, so it is never decoded as a
    // payload — doing so would reject perfectly legal messages.
    match (action, item) {
        (ChangeAction::Remove, v2::assignment::Item::Task(task)) => Ok(AssignmentChange::remove(
            ObjectRef::Task,
            parse_id("Task", &task.id)?,
        )),
        (ChangeAction::Remove, v2::assignment::Item::Secret(secret)) => Ok(
            AssignmentChange::remove(ObjectRef::Secret, parse_id("Secret", &secret.id)?),
        ),
        (ChangeAction::Remove, v2::assignment::Item::Config(config)) => Ok(
            AssignmentChange::remove(ObjectRef::Config, parse_id("Config", &config.id)?),
        ),
        (ChangeAction::Remove, v2::assignment::Item::Network(network)) => {
            Ok(AssignmentChange::remove(
                ObjectRef::Network,
                parse_id("NetworkAssignment", &network.id)?,
            ))
        }
        (ChangeAction::Update, v2::assignment::Item::Network(network)) => {
            Ok(AssignmentChange::update(AssignmentItem::Network(Box::new(
                codec::decode_network(network)?,
            ))))
        }
        (ChangeAction::Update, v2::assignment::Item::Task(task)) => Ok(AssignmentChange::update(
            AssignmentItem::Task(Box::new(codec::decode_task(task)?)),
        )),
        (ChangeAction::Update, v2::assignment::Item::Secret(secret)) => {
            Ok(AssignmentChange::update(AssignmentItem::Secret(Box::new(
                codec::decode_secret(secret)?,
            ))))
        }
        (ChangeAction::Update, v2::assignment::Item::Config(config)) => {
            Ok(AssignmentChange::update(AssignmentItem::Config(Box::new(
                codec::decode_config(config)?,
            ))))
        }
    }
}

fn parse_id(kind: &'static str, value: &str) -> Result<Id, codec::CodecError> {
    value.parse::<Id>().map_err(|error| codec::CodecError::Id {
        kind,
        field: "id",
        value: value.to_owned(),
        reason: error.to_string(),
    })
}

/// The worker-side session client.
pub struct Agent<S: AssignmentSink, C: ChannelFactory> {
    config: AgentConfig,
    sink: Arc<S>,
    connector: C,
    db: satl_agent::TaskDb,
    reporter: Arc<SessionReporter>,
    describer: Arc<dyn NodeDescriber>,
    state: watch::Sender<AgentState>,
}

impl<S: AssignmentSink, C: ChannelFactory> Agent<S, C> {
    /// An agent that applies assignments to `sink`, dials through
    /// `connector`, and re-reports the statuses persisted in `db`.
    pub fn new(
        config: AgentConfig,
        sink: Arc<S>,
        connector: C,
        db: satl_agent::TaskDb,
        reporter: Arc<SessionReporter>,
        describer: Arc<dyn NodeDescriber>,
    ) -> Self {
        let managers = config.bootstrap_managers.clone();
        Self {
            config,
            sink,
            connector,
            db,
            reporter,
            describer,
            state: watch::Sender::new(AgentState {
                managers,
                ..AgentState::default()
            }),
        }
    }

    /// Subscribes to the session state (node object, manager list, root CA).
    #[must_use]
    pub fn state(&self) -> watch::Receiver<AgentState> {
        self.state.subscribe()
    }

    /// Runs the session loop until `shutdown` is cancelled.
    #[must_use]
    pub fn spawn(self, shutdown: CancellationToken) -> JoinHandle<()>
    where
        S: 'static,
        C: 'static,
    {
        tokio::spawn(async move { self.run(shutdown).await })
    }

    /// The session loop: connect, register, run, back off, repeat.
    ///
    /// The span is attached to the future with [`tracing::Instrument`] rather
    /// than entered with a guard: an `Entered` held across an await stays
    /// entered on the worker thread while this future is parked, so every
    /// unrelated task the runtime later polls on that thread inherits it as a
    /// parent. Instrumenting enters and exits the span around each poll.
    pub async fn run(self, shutdown: CancellationToken) {
        let span = tracing::info_span!("agent.session", node_id = %self.config.node_id);
        self.run_inner(shutdown).instrument(span).await;
    }

    /// The body of [`Agent::run`], separated only so the span can wrap the
    /// future.
    async fn run_inner(self, shutdown: CancellationToken) {
        let mut backoff = Backoff::new();
        // One applier for the life of the process, not one per session: the
        // startup pass over the local task DB must run once (the sink's
        // contract), and what the worker has already been handed does not
        // become unknown just because the agent changed managers. A per-session
        // applier re-ran `init` on every re-registration — re-spawning every
        // task manager against a live container — and forgot which desired
        // states the worker had already been told about.
        let mut applier = AssignmentApplier::new();
        // Where a follower told us the leader is. Followed once, ahead of the
        // normal choice (including the local socket: a co-located manager
        // that is not the leader redirects like any other).
        let mut redirect: Option<String> = None;
        tracing::info!("agent session loop started");
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            let endpoint = if let Some(addr) = redirect.take() {
                Some(Endpoint::Redirect(addr))
            } else {
                let managers = self.state.borrow().managers.clone();
                let mut rng = rand::rng();
                choose_endpoint_with(self.config.local_socket.as_ref(), &managers, &mut rng)
            };
            let outcome = match endpoint {
                Some(endpoint) => {
                    self.session(&endpoint, &mut backoff, &shutdown, &mut applier)
                        .await
                }
                None => Err(SessionError::NoManager),
            };
            self.state.send_modify(|state| {
                state.session_id = None;
            });
            match outcome {
                Ok(()) => tracing::info!("agent session ended cleanly"),
                Err(error) => {
                    if let SessionError::Rpc { status, .. } = &error
                        && let Some(addr) = satl_cluster::forward::leader_addr_from_status(status)
                    {
                        tracing::info!(
                            leader_addr = %addr,
                            "a follower redirected us to the leader; dialing it next"
                        );
                        redirect = Some(addr);
                    }
                    tracing::warn!(%error, "agent session ended");
                }
            }
            if shutdown.is_cancelled() {
                break;
            }
            let delay = {
                let mut rng = rand::rng();
                backoff.fail(&mut rng)
            };
            tracing::debug!(
                delay_ms = delay.as_millis(),
                "backing off before re-registering"
            );
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep(delay) => {}
            }
        }
        tracing::info!("agent session loop stopped");
    }

    /// One session, from `Session` to the first error.
    async fn session(
        &self,
        endpoint: &Endpoint,
        backoff: &mut Backoff,
        shutdown: &CancellationToken,
        applier: &mut AssignmentApplier,
    ) -> Result<(), SessionError> {
        tracing::info!(endpoint = %endpoint, "connecting to a manager");
        let channel =
            self.connector
                .connect(endpoint)
                .await
                .map_err(|source| SessionError::Connect {
                    endpoint: endpoint.to_string(),
                    source,
                })?;
        let client = DispatcherClient::new(channel)
            .max_decoding_message_size(satl_proto::MAX_MESSAGE_SIZE)
            .max_encoding_message_size(satl_proto::MAX_MESSAGE_SIZE);

        let description = self.describer.describe();
        let encoded = codec::encode_description(&description)?;
        let mut stream = tokio::time::timeout(
            self.config.rpc_timeout,
            client.clone().session(v2::SessionRequest {
                description: encoded,
                // Session IDs are never persisted and never reused
                // (SWK §13.1): a fresh process always registers.
                session_id: String::new(),
            }),
        )
        .await
        .map_err(|_| SessionError::rpc("Session", tonic::Status::deadline_exceeded("timed out")))?
        .map_err(|status| SessionError::rpc("Session", status))?
        .into_inner();

        let first = stream
            .message()
            .await
            .map_err(|status| SessionError::rpc("Session", status))?
            .ok_or(SessionError::StreamEnded { stream: "session" })?;
        if first.session_id.is_empty() {
            return Err(SessionError::rpc(
                "Session",
                tonic::Status::internal("the manager issued an empty session id"),
            ));
        }
        let session_id = first.session_id.clone();
        backoff.reset();
        // The underlay address is logged here because this line is the node's
        // half of an overlay diagnosis: the manager's log says which VTEP it
        // programmed for this node, and this one says what the node claimed.
        // `None` is the interesting case — it means no peer can reach this
        // node's tasks over an overlay (see `NodeDescriber`).
        tracing::info!(
            session_id = %session_id,
            data_addr = description.data_addr.as_deref().unwrap_or("<none>"),
            "registered with a manager"
        );
        self.absorb(&session_id, &first);

        // On (re-)registration, re-report every persisted task status: this
        // manager may have missed everything since the last one (SWK §14.1).
        self.replay_persisted_statuses().await;

        // The four activities run concurrently and none of them returns while
        // the session is healthy. `select!` is the teardown rule from SWK
        // §14.1 expressed directly: the first one to return — with an error,
        // or because the daemon is shutting down — drops the other three, and
        // with them the streams and the RPCs in flight.
        tokio::select! {
            () = shutdown.cancelled() => Ok(()),
            result = self.heartbeat_activity(client.clone(), &session_id) => result,
            result = self.session_activity(stream, &session_id, description) => result,
            result = self.assignment_activity(client.clone(), &session_id, applier) => result,
            result = self.status_activity(client, &session_id) => result,
        }
    }

    /// Beats at the period the server dictates, forever.
    async fn heartbeat_activity(
        &self,
        mut client: DispatcherClient<Channel>,
        session_id: &str,
    ) -> Result<(), SessionError> {
        loop {
            let response = tokio::time::timeout(
                self.config.rpc_timeout,
                client.heartbeat(v2::HeartbeatRequest {
                    session_id: session_id.to_owned(),
                }),
            )
            .await
            .map_err(|_| {
                SessionError::rpc("Heartbeat", tonic::Status::deadline_exceeded("timed out"))
            })?
            .map_err(|status| SessionError::rpc("Heartbeat", status))?;
            let period = codec::duration_from_proto(response.into_inner().period)?;
            tracing::trace!(period_ms = period.as_millis(), "heartbeat accepted");
            tokio::time::sleep(period).await;
        }
    }

    /// Consumes session messages and refreshes the node description.
    async fn session_activity(
        &self,
        mut stream: tonic::Streaming<v2::SessionMessage>,
        session_id: &str,
        description: NodeDescription,
    ) -> Result<(), SessionError> {
        let mut refresh = tokio::time::interval(self.config.description_refresh);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        refresh.tick().await; // the first tick is immediate
        loop {
            tokio::select! {
                message = stream.message() => {
                    let message = message
                        .map_err(|status| SessionError::rpc("Session", status))?
                        .ok_or(SessionError::StreamEnded { stream: "session" })?;
                    if message.session_id != session_id {
                        return Err(SessionError::SessionSuperseded {
                            held: session_id.to_owned(),
                            new: message.session_id,
                        });
                    }
                    self.absorb(session_id, &message);
                }
                _ = refresh.tick() => {
                    // The description travels in the `SessionRequest`, so the
                    // only way to publish a change is to register again.
                    if self.describer.describe() != description {
                        return Err(SessionError::DescriptionChanged);
                    }
                }
            }
        }
    }

    /// Consumes the assignment stream, re-opening it on a sequence gap.
    async fn assignment_activity(
        &self,
        mut client: DispatcherClient<Channel>,
        session_id: &str,
        applier: &mut AssignmentApplier,
    ) -> Result<(), SessionError> {
        loop {
            let mut sequence = SequenceTracker::new();
            let mut stream = client
                .assignments(v2::AssignmentsRequest {
                    session_id: session_id.to_owned(),
                })
                .await
                .map_err(|status| SessionError::rpc("Assignments", status))?
                .into_inner();

            let gap = loop {
                let message = stream
                    .message()
                    .await
                    .map_err(|status| SessionError::rpc("Assignments", status))?
                    .ok_or(SessionError::StreamEnded {
                        stream: "assignments",
                    })?;
                let (kind, changes) = decode_message(&message)?;
                if let Err(gap) = sequence.accept(kind, &message.applies_to, &message.results_in) {
                    break gap;
                }
                tracing::debug!(
                    ?kind,
                    changes = changes.len(),
                    results_in = %message.results_in,
                    "applying assignments"
                );
                applier.apply(kind, changes, self.sink.as_ref()).await?;
            };

            // Never patch the gap: drop the stream and take a fresh COMPLETE
            // snapshot (`proto/dispatcher.proto`).
            tracing::warn!(%gap, "re-opening the assignment stream");
        }
    }

    /// Flushes coalesced statuses to the manager.
    async fn status_activity(
        &self,
        mut client: DispatcherClient<Channel>,
        session_id: &str,
    ) -> Result<(), SessionError> {
        loop {
            tokio::select! {
                () = self.reporter.ready.notified() => {}
                () = tokio::time::sleep(self.config.status_flush_interval) => {}
            }
            loop {
                let batch = self.reporter.take(self.config.status_flush_max);
                if batch.is_empty() {
                    break;
                }
                let size = batch.len();
                let mut updates = Vec::with_capacity(size);
                for (task_id, status) in &batch {
                    match codec::encode_status(task_id, status) {
                        Ok(update) => updates.push(update),
                        Err(error) => {
                            tracing::error!(task_id = %task_id, %error, "cannot encode a status");
                        }
                    }
                }
                let result = tokio::time::timeout(
                    self.config.rpc_timeout,
                    client.update_task_status(v2::UpdateTaskStatusRequest {
                        session_id: session_id.to_owned(),
                        updates,
                    }),
                )
                .await;
                match result {
                    Ok(Ok(_)) => tracing::debug!(updates = size, "task statuses delivered"),
                    // "The dispatcher no longer cares about this task"
                    // (SWK §14.1): treated as success, the batch is dropped.
                    Ok(Err(status)) if status.code() == tonic::Code::NotFound => {
                        tracing::debug!(updates = size, "the manager does not know these tasks");
                    }
                    Ok(Err(status)) => {
                        self.reporter.requeue(batch);
                        return Err(SessionError::rpc("UpdateTaskStatus", status));
                    }
                    Err(_) => {
                        self.reporter.requeue(batch);
                        return Err(SessionError::rpc(
                            "UpdateTaskStatus",
                            tonic::Status::deadline_exceeded("timed out"),
                        ));
                    }
                }
                if size < self.config.status_flush_max {
                    break;
                }
            }
        }
    }

    /// Folds a session message into the published state.
    fn absorb(&self, session_id: &str, message: &v2::SessionMessage) {
        let node = match message.node.as_ref().map(codec::decode_node) {
            Some(Ok(node)) => Some(node),
            Some(Err(error)) => {
                tracing::error!(%error, "the manager sent an undecodable node object");
                None
            }
            None => None,
        };
        let managers: Option<Vec<ManagerPeer>> = if message.managers.is_empty() {
            None
        } else {
            Some(
                message
                    .managers
                    .iter()
                    .filter_map(|peer| {
                        let node_id = peer.node_id.parse::<Id>().ok().or_else(|| {
                            tracing::warn!(
                                node_id = %peer.node_id,
                                "ignoring a manager with an unparseable node id"
                            );
                            None
                        })?;
                        Some(ManagerPeer {
                            node_id,
                            addr: peer.addr.clone(),
                            weight: peer.weight,
                        })
                    })
                    .collect(),
            )
        };
        self.state.send_modify(|state| {
            state.session_id = Some(session_id.to_owned());
            if let Some(node) = node {
                state.node = Some(node);
            }
            if let Some(managers) = managers {
                tracing::debug!(managers = managers.len(), "manager list updated");
                state.managers = managers;
            }
            if let Some(bundle) = message.root_ca_bundle.clone() {
                if state.root_ca.as_ref() != Some(&bundle) {
                    tracing::info!(bytes = bundle.len(), "root ca bundle updated");
                }
                state.root_ca = Some(bundle);
            }
        });
    }

    /// Re-reports every status the local task DB holds (SWK §14.1).
    async fn replay_persisted_statuses(&self) {
        match self.db.list().await {
            Ok(records) => {
                let count = records.len();
                for record in records {
                    self.reporter.enqueue(&record.task.id, record.status);
                }
                if count > 0 {
                    tracing::info!(
                        tasks = count,
                        "re-reporting every persisted task status to the new manager"
                    );
                }
            }
            Err(error) => tracing::error!(
                %error,
                "cannot read the local task db; statuses will not be re-reported"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{self, RecordingSink, SinkCall};
    use satl_core::{Config, Secret, TaskState};

    fn changes_of(tasks: &[Task], secrets: &[Secret], configs: &[Config]) -> Vec<AssignmentChange> {
        let mut changes = Vec::new();
        for secret in secrets {
            changes.push(AssignmentChange::update(AssignmentItem::Secret(Box::new(
                secret.clone(),
            ))));
        }
        for config in configs {
            changes.push(AssignmentChange::update(AssignmentItem::Config(Box::new(
                config.clone(),
            ))));
        }
        for task in tasks {
            changes.push(AssignmentChange::update(AssignmentItem::Task(Box::new(
                task.clone(),
            ))));
        }
        changes
    }

    #[tokio::test]
    async fn a_snapshot_applies_secrets_then_configs_then_tasks() {
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let secret = testing::secret("s", b"x");
        let config = testing::config("c", b"y");
        let task = testing::with_config(
            testing::with_secret(
                testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running),
                &secret,
            ),
            &config,
        );

        applier
            .apply(
                MessageKind::Complete,
                changes_of(
                    std::slice::from_ref(&task),
                    std::slice::from_ref(&secret),
                    std::slice::from_ref(&config),
                ),
                sink.as_ref(),
            )
            .await
            .expect("applied");

        assert_eq!(
            sink.calls(),
            vec![
                SinkCall::ResetSecrets(BTreeSet::from([secret.id.clone()])),
                SinkCall::ResetConfigs(BTreeSet::from([config.id.clone()])),
                SinkCall::Init(BTreeSet::from([task.id.clone()])),
                SinkCall::ApplyTask(task.id.clone()),
            ],
            "dependencies must be in place before the task that needs them"
        );
        assert!(applier.initialized());
    }

    #[tokio::test]
    async fn a_snapshot_removes_local_tasks_it_does_not_mention() {
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let gone = testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running);
        let kept = testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running);

        applier
            .apply(
                MessageKind::Complete,
                changes_of(&[gone.clone(), kept.clone()], &[], &[]),
                sink.as_ref(),
            )
            .await
            .expect("applied");
        sink.clear_calls();

        applier
            .apply(
                MessageKind::Complete,
                changes_of(std::slice::from_ref(&kept), &[], &[]),
                sink.as_ref(),
            )
            .await
            .expect("applied");
        assert!(
            sink.calls()
                .contains(&SinkCall::RemoveTask(gone.id.clone())),
            "{:?}",
            sink.calls()
        );
        assert!(!sink.calls().contains(&SinkCall::ApplyTask(kept.id.clone())));
        assert_eq!(sink.tasks().keys().collect::<Vec<_>>(), vec![&kept.id]);
    }

    #[tokio::test]
    async fn the_startup_pass_runs_once_and_only_once() {
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let task = testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running);
        for _ in 0..3 {
            applier
                .apply(
                    MessageKind::Complete,
                    changes_of(std::slice::from_ref(&task), &[], &[]),
                    sink.as_ref(),
                )
                .await
                .expect("applied");
        }
        let inits = sink
            .calls()
            .into_iter()
            .filter(|call| matches!(call, SinkCall::Init(_)))
            .count();
        assert_eq!(inits, 1);
    }

    /// The bug this file's seeding comment describes: the worker resumed a
    /// re-attached container at the desired state its **local DB** held, while
    /// the snapshot that triggered the resume already said `SHUTDOWN`. Unless
    /// the task is handed over again, nothing ever asks that container to stop.
    #[tokio::test]
    async fn a_desired_state_that_moved_while_the_agent_was_away_reaches_the_worker() {
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();

        // What the worker kept across the restart: RUNNING, desired RUNNING.
        let mut task = testing::task_on(Some(&node), TaskState::Running, DesiredState::Running);
        sink.persist(task.clone());
        // What the manager decided meanwhile (node down ⇒ evict the task).
        task.desired_state = DesiredState::Shutdown;

        applier
            .apply(
                MessageKind::Complete,
                changes_of(std::slice::from_ref(&task), &[], &[]),
                sink.as_ref(),
            )
            .await
            .expect("applied");

        assert!(
            sink.calls().contains(&SinkCall::ApplyTask(task.id.clone())),
            "the resumed task must be handed over at its new desired state: {:?}",
            sink.calls()
        );
        assert_eq!(
            sink.tasks()
                .get(&task.id)
                .map(|task| task.desired_state)
                .expect("the worker holds the task"),
            DesiredState::Shutdown
        );
        assert_eq!(
            applier.applied().get(&task.id),
            Some(&(DesiredState::Shutdown, task.spec.resources))
        );
    }

    /// The other half of the same rule, and the reason the seed exists at all:
    /// a resumed task whose desired state did *not* move must not be handed
    /// over, because that cancels the operation the resumed manager just
    /// started (re-arming an exit watch, finishing a `prepare`).
    #[tokio::test]
    async fn a_resumed_task_at_an_unchanged_desired_state_is_left_alone() {
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let task = testing::task_on(Some(&node), TaskState::Running, DesiredState::Running);
        sink.persist(task.clone());

        applier
            .apply(
                MessageKind::Complete,
                changes_of(std::slice::from_ref(&task), &[], &[]),
                sink.as_ref(),
            )
            .await
            .expect("applied");

        assert_eq!(
            sink.calls(),
            vec![
                SinkCall::ResetSecrets(BTreeSet::new()),
                SinkCall::ResetConfigs(BTreeSet::new()),
                SinkCall::Init(BTreeSet::from([task.id.clone()])),
            ],
            "a resumed task at the same desired state needs nothing"
        );
        assert_eq!(
            applier.applied().get(&task.id),
            Some(&(DesiredState::Running, task.spec.resources))
        );
    }

    #[tokio::test]
    async fn a_resources_move_is_re_applied_at_an_unchanged_desired_state() {
        // M6g: the hot resize rides the same channel — same desired state,
        // new limits, and the worker must hear about it or the live jail
        // keeps its old rctl rules forever.
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let mut task = testing::task_on(Some(&node), TaskState::Running, DesiredState::Running);
        applier
            .apply(
                MessageKind::Incremental,
                changes_of(std::slice::from_ref(&task), &[], &[]),
                sink.as_ref(),
            )
            .await
            .expect("applied");

        task.spec.resources.limits = Some(satl_core::Resources {
            nano_cpus: 0,
            memory_bytes: 512 * 1024 * 1024,
        });
        applier
            .apply(
                MessageKind::Incremental,
                changes_of(std::slice::from_ref(&task), &[], &[]),
                sink.as_ref(),
            )
            .await
            .expect("applied");

        let applications = sink
            .calls()
            .iter()
            .filter(|call| matches!(call, SinkCall::ApplyTask(id) if *id == task.id))
            .count();
        assert_eq!(applications, 2, "a resources move must reach the worker");
        assert_eq!(
            applier.applied().get(&task.id),
            Some(&(DesiredState::Running, task.spec.resources))
        );
    }

    #[tokio::test]
    async fn a_status_echo_is_not_re_applied_but_a_desired_state_move_is() {
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let mut task = testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running);
        applier
            .apply(
                MessageKind::Incremental,
                changes_of(std::slice::from_ref(&task), &[], &[]),
                sink.as_ref(),
            )
            .await
            .expect("applied");
        sink.clear_calls();

        // The same task, further along: nothing for the worker to do.
        task.status.state = TaskState::Running;
        applier
            .apply(
                MessageKind::Incremental,
                changes_of(std::slice::from_ref(&task), &[], &[]),
                sink.as_ref(),
            )
            .await
            .expect("applied");
        assert!(sink.calls().is_empty(), "{:?}", sink.calls());

        task.desired_state = DesiredState::Shutdown;
        applier
            .apply(
                MessageKind::Incremental,
                changes_of(std::slice::from_ref(&task), &[], &[]),
                sink.as_ref(),
            )
            .await
            .expect("applied");
        assert_eq!(sink.calls(), vec![SinkCall::ApplyTask(task.id.clone())]);
    }

    #[tokio::test]
    async fn an_incremental_batch_applies_dependencies_before_tasks_whatever_the_order() {
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let secret = testing::secret("s", b"x");
        let task = testing::with_secret(
            testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running),
            &secret,
        );
        // Deliberately mis-ordered by the sender.
        let changes = vec![
            AssignmentChange::update(AssignmentItem::Task(Box::new(task.clone()))),
            AssignmentChange::update(AssignmentItem::Secret(Box::new(secret.clone()))),
        ];
        applier
            .apply(MessageKind::Incremental, changes, sink.as_ref())
            .await
            .expect("applied");
        assert_eq!(
            sink.calls(),
            vec![
                SinkCall::PutSecret(secret.id.clone()),
                SinkCall::ApplyTask(task.id.clone())
            ]
        );
    }

    #[tokio::test]
    async fn a_removal_releases_the_task_and_its_dependencies() {
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let secret = testing::secret("s", b"x");
        let task = testing::with_secret(
            testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running),
            &secret,
        );
        applier
            .apply(
                MessageKind::Incremental,
                changes_of(
                    std::slice::from_ref(&task),
                    std::slice::from_ref(&secret),
                    &[],
                ),
                sink.as_ref(),
            )
            .await
            .expect("applied");
        sink.clear_calls();

        applier
            .apply(
                MessageKind::Incremental,
                vec![
                    AssignmentChange::remove(ObjectRef::Secret, secret.id.clone()),
                    AssignmentChange::remove(ObjectRef::Task, task.id.clone()),
                ],
                sink.as_ref(),
            )
            .await
            .expect("applied");
        assert_eq!(
            sink.calls(),
            vec![
                SinkCall::RemoveTask(task.id.clone()),
                SinkCall::RemoveSecret(secret.id.clone())
            ],
            "teardown releases dependents before dependencies, whatever order the \
             batch arrived in"
        );
        assert!(sink.secrets().is_empty());
        assert!(applier.applied().is_empty());
    }

    #[tokio::test]
    async fn a_complete_snapshot_resets_the_dependency_sets_wholesale() {
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let stale = testing::secret("stale", b"old");
        let task = testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running);
        applier
            .apply(
                MessageKind::Incremental,
                changes_of(
                    std::slice::from_ref(&task),
                    std::slice::from_ref(&stale),
                    &[],
                ),
                sink.as_ref(),
            )
            .await
            .expect("applied");
        assert_eq!(sink.secrets().len(), 1);

        applier
            .apply(
                MessageKind::Complete,
                changes_of(&[task], &[], &[]),
                sink.as_ref(),
            )
            .await
            .expect("applied");
        assert!(
            sink.secrets().is_empty(),
            "a snapshot without the secret means the node must not hold it"
        );
    }

    // ---- networks ----------------------------------------------------------

    fn network_change(assignment: &crate::assignment::NetworkAssignment) -> AssignmentChange {
        AssignmentChange::update(AssignmentItem::Network(Box::new(assignment.clone())))
    }

    #[tokio::test]
    async fn a_network_is_programmed_before_the_task_attached_to_it() {
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let network = testing::overlay_network("blue");
        let assignment = crate::assignment::NetworkAssignment::new(network.clone());
        let task = testing::with_network(
            testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.5/24",
        );

        // Deliberately mis-ordered by the sender.
        let changes = vec![
            AssignmentChange::update(AssignmentItem::Task(Box::new(task.clone()))),
            network_change(&assignment),
        ];
        applier
            .apply(MessageKind::Incremental, changes, sink.as_ref())
            .await
            .expect("applied");
        assert_eq!(
            sink.calls(),
            vec![
                SinkCall::ApplyNetwork(network.id.clone()),
                SinkCall::ApplyTask(task.id.clone())
            ],
            "a jail must never be handed over before its network exists"
        );
        assert_eq!(applier.networks().len(), 1);
    }

    #[tokio::test]
    async fn a_network_is_torn_down_only_after_the_tasks_attached_to_it() {
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let network = testing::overlay_network("blue");
        let assignment = crate::assignment::NetworkAssignment::new(network.clone());
        let task = testing::with_network(
            testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.5/24",
        );
        applier
            .apply(
                MessageKind::Incremental,
                vec![
                    network_change(&assignment),
                    AssignmentChange::update(AssignmentItem::Task(Box::new(task.clone()))),
                ],
                sink.as_ref(),
            )
            .await
            .expect("applied");
        sink.clear_calls();

        // Again mis-ordered: the network removal comes first on the wire.
        applier
            .apply(
                MessageKind::Incremental,
                vec![
                    AssignmentChange::remove(ObjectRef::Network, network.id.clone()),
                    AssignmentChange::remove(ObjectRef::Task, task.id.clone()),
                ],
                sink.as_ref(),
            )
            .await
            .expect("applied");
        assert_eq!(
            sink.calls(),
            vec![
                SinkCall::RemoveTask(task.id.clone()),
                SinkCall::RemoveNetwork(network.id.clone())
            ],
            "tearing the vxlan down under a live jail black-holes it (docs/vxlan.md §8)"
        );
        assert!(sink.networks().is_empty());
        assert!(applier.networks().is_empty());
    }

    /// The endpoint table is why a network is re-applied at all: the object is
    /// unchanged, the peers are not.
    #[tokio::test]
    async fn an_unchanged_network_is_suppressed_but_an_endpoint_change_is_applied() {
        let peer = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let network = testing::overlay_network("blue");
        let assignment = crate::assignment::NetworkAssignment::new(network.clone());

        applier
            .apply(
                MessageKind::Incremental,
                vec![network_change(&assignment)],
                sink.as_ref(),
            )
            .await
            .expect("applied");
        sink.clear_calls();

        applier
            .apply(
                MessageKind::Incremental,
                vec![network_change(&assignment)],
                sink.as_ref(),
            )
            .await
            .expect("applied");
        assert!(
            sink.calls().is_empty(),
            "re-programming an unchanged network is work for nothing: {:?}",
            sink.calls()
        );

        let with_peer = assignment
            .clone()
            .with_endpoint(crate::assignment::NetworkEndpoint {
                task_id: Id::generate(),
                node_id: peer,
                addr: "10.100.4.9".parse().expect("addr"),
                vtep: "10.2.0.2".parse().expect("addr"),
                service_name: "web".to_owned(),
                task_name: String::new(),
                aliases: Vec::new(),
                state: satl_core::TaskState::Running,
            });
        applier
            .apply(
                MessageKind::Incremental,
                vec![network_change(&with_peer)],
                sink.as_ref(),
            )
            .await
            .expect("applied");
        assert_eq!(
            sink.calls(),
            vec![SinkCall::ApplyNetwork(network.id.clone())]
        );
        assert_eq!(
            sink.networks()
                .get(&network.id)
                .map(|held| held.endpoints.len()),
            Some(1)
        );
    }

    /// A `COMPLETE` snapshot must not reset the overlay wholesale — that would
    /// flap every attached jail on every re-registration — but it is still
    /// authoritative about which networks the node should hold.
    #[tokio::test]
    async fn a_snapshot_keeps_the_networks_it_repeats_and_removes_the_ones_it_drops() {
        let node = Id::generate();
        let sink = RecordingSink::new();
        let mut applier = AssignmentApplier::new();
        let kept = testing::overlay_network("blue");
        let dropped = testing::overlay_network("green");
        let kept_assignment = crate::assignment::NetworkAssignment::new(kept.clone());
        let dropped_assignment = crate::assignment::NetworkAssignment::new(dropped.clone());
        let task = testing::with_network(
            testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running),
            &kept,
            "10.100.4.5/24",
        );

        applier
            .apply(
                MessageKind::Complete,
                vec![
                    network_change(&kept_assignment),
                    network_change(&dropped_assignment),
                    AssignmentChange::update(AssignmentItem::Task(Box::new(task.clone()))),
                ],
                sink.as_ref(),
            )
            .await
            .expect("applied");
        assert_eq!(sink.networks().len(), 2);
        sink.clear_calls();

        applier
            .apply(
                MessageKind::Complete,
                vec![
                    network_change(&kept_assignment),
                    AssignmentChange::update(AssignmentItem::Task(Box::new(task.clone()))),
                ],
                sink.as_ref(),
            )
            .await
            .expect("applied");
        assert_eq!(
            sink.calls(),
            vec![
                SinkCall::ResetSecrets(BTreeSet::new()),
                SinkCall::ResetConfigs(BTreeSet::new()),
                SinkCall::RemoveNetwork(dropped.id.clone()),
            ],
            "the repeated network must be left alone and the dropped one torn down"
        );
        assert_eq!(sink.networks().keys().collect::<Vec<_>>(), vec![&kept.id]);
    }

    #[test]
    fn the_reporter_coalesces_and_drops_regressions() {
        let reporter = SessionReporter::new();
        let task = Id::generate();
        reporter.enqueue(&task, TaskStatus::new(TaskState::Preparing, "preparing"));
        reporter.enqueue(&task, TaskStatus::new(TaskState::Running, "started"));
        reporter.enqueue(&task, TaskStatus::new(TaskState::Assigned, "stale"));
        assert_eq!(reporter.pending(), 1);
        let batch = reporter.take(10);
        assert_eq!(batch[0].1.state, TaskState::Running);
        assert_eq!(reporter.pending(), 0);
    }

    #[test]
    fn an_unspecified_message_type_is_a_protocol_error() {
        let message = v2::AssignmentsMessage {
            r#type: v2::assignments_message::Type::Unspecified as i32,
            applies_to: String::new(),
            results_in: "s-1".to_owned(),
            changes: Vec::new(),
        };
        assert!(matches!(
            decode_message(&message),
            Err(codec::CodecError::Enum { .. })
        ));
    }

    #[test]
    fn an_unspecified_action_is_a_protocol_error() {
        let message = v2::AssignmentsMessage {
            r#type: v2::assignments_message::Type::Incremental as i32,
            applies_to: "s-1".to_owned(),
            results_in: "s-2".to_owned(),
            changes: vec![v2::AssignmentChange {
                assignment: Some(v2::Assignment {
                    item: Some(v2::assignment::Item::Secret(v2::Secret {
                        id: Id::generate().to_string(),
                        meta: None,
                        payload: Vec::new(),
                    })),
                }),
                action: v2::assignment_change::Action::Unspecified as i32,
            }],
        };
        assert!(matches!(
            decode_message(&message),
            Err(codec::CodecError::Enum { .. })
        ));
    }

    #[test]
    fn a_removal_decodes_from_the_id_alone() {
        let id = Id::generate();
        let message = v2::AssignmentsMessage {
            r#type: v2::assignments_message::Type::Incremental as i32,
            applies_to: "s-1".to_owned(),
            results_in: "s-2".to_owned(),
            changes: vec![v2::AssignmentChange {
                assignment: Some(v2::Assignment {
                    item: Some(v2::assignment::Item::Task(codec::task_removal(&id))),
                }),
                action: v2::assignment_change::Action::Remove as i32,
            }],
        };
        let (kind, changes) = decode_message(&message).expect("decode");
        assert_eq!(kind, MessageKind::Incremental);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].action, ChangeAction::Remove);
        assert_eq!(changes[0].key.id, id);
        assert!(changes[0].item.is_none());
    }
}
