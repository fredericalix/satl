// SPDX-License-Identifier: BSD-2-Clause
// Test support shared by this crate's unit tests and its integration tests
// (the latter include this file with `#[path = "../src/testing.rs"]`, so it
// must stay self-contained: no `crate::` paths).
//
// Each test target uses a subset of the helpers.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use satl_cluster::{ClusterStore, ProposeError, RaftNode, RaftNodeConfig, StoreView};
use satl_core::{
    Annotations, Availability, CertificateStatus, Config, ConfigReference, ConfigSpec,
    ContainerSpec, DesiredState, EngineDescription, FileTarget, Id, IpamConfig, Meta, Network,
    NetworkAttachment, NetworkAttachmentConfig, NetworkDriver, NetworkKey, NetworkSpec, Node,
    NodeDescription, NodeRole, NodeSpec, NodeState, NodeStatus, Placement, Platform,
    ResourceRequirements, Resources, RestartPolicy, Secret, SecretReference, SecretSpec,
    StoreAction, StoreObject, Task, TaskSpec, TaskState, TaskStatus,
};
use satl_dispatcher::assignment::NetworkAssignment;
use tempfile::TempDir;

/// Every observed state, ascending.
pub const ALL_STATES: [TaskState; 14] = [
    TaskState::New,
    TaskState::Pending,
    TaskState::Assigned,
    TaskState::Accepted,
    TaskState::Preparing,
    TaskState::Ready,
    TaskState::Starting,
    TaskState::Running,
    TaskState::Complete,
    TaskState::Shutdown,
    TaskState::Failed,
    TaskState::Rejected,
    TaskState::Remove,
    TaskState::Orphaned,
];

/// The states a task can legitimately be observed in, ascending.
pub const OBSERVABLE_STATES: [TaskState; 13] = [
    TaskState::New,
    TaskState::Pending,
    TaskState::Assigned,
    TaskState::Accepted,
    TaskState::Preparing,
    TaskState::Ready,
    TaskState::Starting,
    TaskState::Running,
    TaskState::Complete,
    TaskState::Shutdown,
    TaskState::Failed,
    TaskState::Rejected,
    TaskState::Orphaned,
];

/// How long the polling helpers wait before failing a test.
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval for the waiting helpers.
pub const POLL: Duration = Duration::from_millis(5);

/// A bare container spec.
pub fn container_spec() -> ContainerSpec {
    ContainerSpec {
        image: "127.0.0.1:5000/freebsd-nginx:1".to_owned(),
        labels: BTreeMap::new(),
        command: Vec::new(),
        args: Vec::new(),
        hostname: None,
        env: Vec::new(),
        dir: None,
        user: None,
        groups: Vec::new(),
        tty: false,
        open_stdin: false,
        read_only: false,
        stop_signal: None,
        stop_grace_period: None,
        healthcheck: None,
        hosts: Vec::new(),
        dns_config: None,
        mounts: Vec::new(),
        secrets: Vec::new(),
        configs: Vec::new(),
        pull_options: None,
        platform: None,
    }
}

/// A task spec around [`container_spec`].
pub fn task_spec() -> TaskSpec {
    TaskSpec {
        container: container_spec(),
        resources: ResourceRequirements::default(),
        restart: RestartPolicy::default(),
        placement: Placement::default(),
        networks: Vec::new(),
        force_update: 0,
    }
}

/// A task bound to nothing, in `state`/`desired`.
pub fn task_at(state: TaskState, desired: DesiredState) -> Task {
    task_on(None, state, desired)
}

/// A task bound to `node`, in `state`/`desired`.
pub fn task_on(node: Option<&Id>, state: TaskState, desired: DesiredState) -> Task {
    let id = Id::generate();
    Task {
        annotations: Annotations {
            name: format!("web.1.{id}"),
            labels: BTreeMap::new(),
        },
        id,
        meta: Meta::new(),
        spec: task_spec(),
        spec_version: None,
        service_id: None,
        slot: 1,
        node_id: node.cloned(),
        service_annotations: Annotations {
            name: "web".to_owned(),
            labels: BTreeMap::new(),
        },
        status: TaskStatus::new(state, "test"),
        desired_state: desired,
        networks: Vec::new(),
        endpoint: None,
        job_iteration: None,
    }
}

/// Adds a secret reference to a task's container spec.
pub fn with_secret(mut task: Task, secret: &Secret) -> Task {
    task.spec.container.secrets.push(SecretReference {
        secret_id: secret.id.clone(),
        secret_name: secret.spec.annotations.name.clone(),
        file: FileTarget {
            name: secret.spec.annotations.name.clone(),
            uid: "0".to_owned(),
            gid: "0".to_owned(),
            mode: 0o444,
        },
    });
    task
}

/// Adds a config reference to a task's container spec.
pub fn with_config(mut task: Task, config: &Config) -> Task {
    task.spec.container.configs.push(ConfigReference {
        config_id: config.id.clone(),
        config_name: config.spec.annotations.name.clone(),
        file: FileTarget {
            name: config.spec.annotations.name.clone(),
            uid: "0".to_owned(),
            gid: "0".to_owned(),
            mode: 0o444,
        },
    });
    task
}

/// A secret with a payload.
pub fn secret(name: &str, data: &[u8]) -> Secret {
    Secret {
        id: Id::generate(),
        meta: Meta::new(),
        spec: SecretSpec::new(
            Annotations {
                name: name.to_owned(),
                labels: BTreeMap::new(),
            },
            data.to_vec(),
        )
        .expect("valid secret"),
    }
}

/// A config with a payload.
pub fn config(name: &str, data: &[u8]) -> Config {
    Config {
        id: Id::generate(),
        meta: Meta::new(),
        spec: ConfigSpec::new(
            Annotations {
                name: name.to_owned(),
                labels: BTreeMap::new(),
            },
            data.to_vec(),
        )
        .expect("valid config"),
    }
}

/// An overlay network with a subnet and a VNI, as the allocator would leave it.
///
/// This is the only construction site of a `Network` in the crate, on purpose:
/// nothing in `satl-dispatcher`'s production code reads a single field of one —
/// a network travels as one opaque CBOR payload — so the object's shape is a
/// test-fixture concern here and nothing more.
pub fn overlay_network(name: &str) -> Network {
    Network {
        id: Id::generate(),
        meta: Meta::new(),
        spec: NetworkSpec {
            annotations: Annotations {
                name: name.to_owned(),
                labels: BTreeMap::new(),
            },
            driver: NetworkDriver::Overlay,
            ipam: Some(IpamConfig::default()),
            internal: false,
            attachable: false,
            ingress: false,
            encrypted: false,
        },
        vni: Some(4_096),
        vxlan_port: None,
        subnet: Some("10.100.4.0/24".to_owned()),
        node_gateways: BTreeMap::new(),
        keys: Vec::new(),
        keys_updated_at: None,
    }
}

/// An encrypted overlay network with a steady-state two-key ring (primary
/// plus previous, libnetwork's shape), as the leader's keyring loop leaves it
/// mid-life (`crates/satl-orchestrator/src/keyring.rs`). The key material is
/// fixed: this is a distribution fixture, not an entropy test.
pub fn encrypted_overlay(name: &str) -> Network {
    let mut network = overlay_network(name);
    network.spec.encrypted = true;
    network.keys = vec![
        network_key(0x5a71_0001, false),
        network_key(0x5a71_0002, true),
    ];
    network.keys_updated_at = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
    network
}

/// A deterministic ring key, derived from its tag.
pub fn network_key(tag: u32, primary: bool) -> NetworkKey {
    let mut bytes = [0xa5_u8; 16];
    bytes[..4].copy_from_slice(&tag.to_le_bytes());
    NetworkKey {
        tag,
        key: bytes,
        primary,
    }
}

/// The same network with a gateway address on `node_id`'s bridge, the way the
/// allocator leaves it once a task of that node attaches (`docs/vxlan.md` §8:
/// one gateway address per node per overlay, never one shared address).
pub fn with_node_gateway(mut network: Network, node_id: &Id, address: &str) -> Network {
    network
        .node_gateways
        .insert(node_id.clone(), address.to_owned());
    network
}

/// Attaches a task to `network` at `address` (CIDR form), the way the allocator
/// does: a spec-level request plus the resolved attachment.
pub fn with_network(mut task: Task, network: &Network, address: &str) -> Task {
    task.spec.networks.push(NetworkAttachmentConfig {
        target: network.spec.annotations.name.clone(),
        aliases: Vec::new(),
    });
    task.networks.push(NetworkAttachment {
        network_id: network.id.clone(),
        addresses: vec![address.to_owned()],
        aliases: Vec::new(),
    });
    task
}

/// A node object in `role`, `READY`/`ACTIVE`.
pub fn node(role: NodeRole) -> Node {
    node_with_id(Id::generate(), role)
}

/// A node object with a chosen ID.
pub fn node_with_id(id: Id, role: NodeRole) -> Node {
    Node {
        id,
        meta: Meta::new(),
        spec: NodeSpec {
            name: None,
            labels: BTreeMap::new(),
            role,
            availability: Availability::Active,
        },
        description: None,
        status: NodeStatus {
            state: NodeState::Unknown,
            message: String::new(),
            addr: String::new(),
        },
        manager_status: None,
        certificate_status: CertificateStatus::Issued,
        certificate_issuer: None,
    }
}

/// A node description.
pub fn description(hostname: &str) -> NodeDescription {
    NodeDescription {
        hostname: hostname.to_owned(),
        platform: Platform {
            os: "freebsd".to_owned(),
            arch: "amd64".to_owned(),
        },
        resources: Resources {
            nano_cpus: 4_000_000_000,
            memory_bytes: 8 * 1024 * 1024 * 1024,
        },
        engine: EngineDescription {
            version: "0.1.0".to_owned(),
            labels: BTreeMap::new(),
        },
        linux_emulation: true,
        racct_enabled: false,
        data_addr: None,
    }
}

/// A fixed instant to anchor the pure time-driven tests.
pub fn epoch() -> Instant {
    Instant::now()
}

/// A real single-node cluster store in a temp dir, as used by `satl-cluster`'s
/// own tests: a genuine Raft FSM, no network.
pub struct TestCluster {
    store: ClusterStore,
    node: RaftNode,
    _dir: TempDir,
}

impl TestCluster {
    /// Starts a fresh single-node cluster; it is leader on return, with the
    /// `default` cluster object and its own node seeded.
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = RaftNodeConfig {
            raft_dir: dir.path().join("raft"),
            node_name: "alpha".to_owned(),
            ..RaftNodeConfig::default()
        };
        let (store, node) = RaftNode::start(cfg).await.expect("raft node starts");
        Self {
            store,
            node,
            _dir: dir,
        }
    }

    /// The store handle.
    pub fn store(&self) -> &ClusterStore {
        &self.store
    }

    /// The seeded node's ID (this manager, which also runs an agent).
    pub fn node_id(&self) -> &Id {
        self.node.node_id()
    }

    /// Stops Raft (and with it the temp dir).
    pub async fn shutdown(self) {
        self.node.shutdown().await.expect("clean shutdown");
    }

    /// Commits one transaction, panicking on failure.
    pub async fn commit(&self, actions: Vec<StoreAction>) {
        self.store.propose(actions).await.expect("commit");
    }

    /// Creates an object.
    pub async fn create(&self, object: StoreObject) {
        self.commit(vec![StoreAction::Create(object)]).await;
    }

    /// Re-reads `task_id` and applies `edit`, retrying sequence conflicts.
    pub async fn update_task(&self, task_id: &Id, mut edit: impl FnMut(&mut Task)) {
        for _ in 0..50 {
            let current = {
                let view = self.store.view();
                view.task(task_id).map(|task| (*task).clone())
            };
            let mut task = current.unwrap_or_else(|| panic!("task {task_id} is gone"));
            edit(&mut task);
            task.meta.updated_at = SystemTime::now();
            match self
                .store
                .propose(vec![StoreAction::Update(StoreObject::Task(task))])
                .await
            {
                Ok(_) => return,
                Err(ProposeError::Rejected(_)) => tokio::time::sleep(POLL).await,
                Err(err) => panic!("failed to update task: {err}"),
            }
        }
        panic!("never won the race to update task {task_id}");
    }

    /// Re-reads `node_id` and applies `edit`, retrying sequence conflicts.
    ///
    /// Writing a node object from outside the dispatcher is how a test
    /// simulates a status write that was lost or overwritten: no transition
    /// happens on the manager side, so only a level-triggered pass can notice.
    pub async fn update_node(&self, node_id: &Id, mut edit: impl FnMut(&mut Node)) {
        for _ in 0..50 {
            let current = {
                let view = self.store.view();
                view.node(node_id).map(|node| (*node).clone())
            };
            let mut node = current.unwrap_or_else(|| panic!("node {node_id} is gone"));
            edit(&mut node);
            node.meta.updated_at = SystemTime::now();
            match self
                .store
                .propose(vec![StoreAction::Update(StoreObject::Node(node))])
                .await
            {
                Ok(_) => return,
                Err(ProposeError::Rejected(_)) => tokio::time::sleep(POLL).await,
                Err(err) => panic!("failed to update node: {err}"),
            }
        }
        panic!("never won the race to update node {node_id}");
    }

    /// Polls the store until `probe` yields a value, panicking on timeout.
    pub async fn wait_for<T, F>(&self, what: &str, mut probe: F) -> T
    where
        F: FnMut(&StoreView<'_>) -> Option<T>,
    {
        let deadline = Instant::now() + WAIT_TIMEOUT;
        loop {
            let found = {
                let view = self.store.view();
                probe(&view)
            };
            if let Some(value) = found {
                return value;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(POLL).await;
        }
    }
}

/// Polls `probe` until it returns true, panicking on timeout.
pub async fn eventually(what: &str, mut probe: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    while Instant::now() < deadline {
        if probe() {
            return;
        }
        tokio::time::sleep(POLL).await;
    }
    panic!("timed out waiting for {what}");
}

/// Polls an async `probe` until it returns true, panicking on timeout.
pub async fn eventually_async<F, Fut>(what: &str, mut probe: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + WAIT_TIMEOUT;
    while Instant::now() < deadline {
        if probe().await {
            return;
        }
        tokio::time::sleep(POLL).await;
    }
    panic!("timed out waiting for {what}");
}

/// What a [`RecordingSink`] was told to do, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkCall {
    /// `init(live)` — the startup pass over the local task db.
    Init(BTreeSet<Id>),
    /// Secrets were reset wholesale (COMPLETE snapshot).
    ResetSecrets(BTreeSet<Id>),
    /// Configs were reset wholesale (COMPLETE snapshot).
    ResetConfigs(BTreeSet<Id>),
    /// A secret was added or replaced.
    PutSecret(Id),
    /// A secret was dropped.
    RemoveSecret(Id),
    /// A config was added or replaced.
    PutConfig(Id),
    /// A config was dropped.
    RemoveConfig(Id),
    /// A network was programmed (or re-programmed on an endpoint change).
    ApplyNetwork(Id),
    /// A network was torn down.
    RemoveNetwork(Id),
    /// A task was assigned or updated.
    ApplyTask(Id),
    /// A task was released.
    RemoveTask(Id),
}

/// An [`AssignmentSink`](satl_dispatcher::sink::AssignmentSink) that records calls
/// instead of driving jails.
///
/// It models the one part of the real worker the protocol depends on: a
/// **local task DB** that survives a restart ([`RecordingSink::persist`]) and
/// an `init` that resumes those records at the desired state they were
/// persisted with — never at the one the incoming snapshot carries. A double
/// that resumed tasks at the snapshot's desired state would agree with the
/// agent about a task nobody is driving, which is precisely the bug this
/// models away from.
#[derive(Debug, Default)]
pub struct RecordingSink {
    state: Mutex<RecordingState>,
}

#[derive(Debug, Default)]
struct RecordingState {
    calls: Vec<SinkCall>,
    /// What the worker is driving, as last handed over.
    tasks: BTreeMap<Id, Task>,
    /// What the local task DB holds, i.e. what survives a restart.
    records: BTreeMap<Id, Task>,
    secrets: BTreeMap<Id, Secret>,
    configs: BTreeMap<Id, Config>,
    networks: BTreeMap<Id, NetworkAssignment>,
}

impl RecordingSink {
    /// A fresh sink.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Plants a task in the modelled local task DB: the worker restarted and
    /// this is the definition it kept, desired state included.
    pub fn persist(&self, task: Task) {
        let mut state = self.state.lock().expect("sink lock");
        state.records.insert(task.id.clone(), task);
    }

    /// Every call so far, in order.
    pub fn calls(&self) -> Vec<SinkCall> {
        self.state.lock().expect("sink lock").calls.clone()
    }

    /// Drops the recorded call log, keeping the applied state.
    pub fn clear_calls(&self) {
        self.state.lock().expect("sink lock").calls.clear();
    }

    /// The tasks the sink currently holds.
    pub fn tasks(&self) -> BTreeMap<Id, Task> {
        self.state.lock().expect("sink lock").tasks.clone()
    }

    /// The secrets the sink currently holds.
    pub fn secrets(&self) -> BTreeMap<Id, Secret> {
        self.state.lock().expect("sink lock").secrets.clone()
    }

    /// The configs the sink currently holds.
    pub fn configs(&self) -> BTreeMap<Id, Config> {
        self.state.lock().expect("sink lock").configs.clone()
    }

    /// The networks the sink currently programs, endpoint tables included.
    pub fn networks(&self) -> BTreeMap<Id, NetworkAssignment> {
        self.state.lock().expect("sink lock").networks.clone()
    }

    fn record(&self, call: SinkCall) {
        self.state.lock().expect("sink lock").calls.push(call);
    }
}

impl satl_dispatcher::sink::AssignmentSink for RecordingSink {
    async fn init(
        &self,
        live: &BTreeSet<Id>,
    ) -> Result<BTreeMap<Id, (DesiredState, ResourceRequirements)>, satl_dispatcher::sink::SinkError>
    {
        let mut state = self.state.lock().expect("sink lock");
        state.calls.push(SinkCall::Init(live.clone()));
        // Records still assigned resume (the worker drives them from here on);
        // the rest are released, exactly like `Worker::init_from_disk`.
        state.records.retain(|id, _| live.contains(id));
        let mut driving = BTreeMap::new();
        for (id, task) in &state.records {
            driving.insert(id.clone(), (task.desired_state, task.spec.resources));
        }
        let resumed: Vec<(Id, Task)> = state
            .records
            .iter()
            .map(|(id, task)| (id.clone(), task.clone()))
            .collect();
        state.tasks.extend(resumed);
        Ok(driving)
    }

    async fn task_ids(&self) -> BTreeSet<Id> {
        self.state
            .lock()
            .expect("sink lock")
            .tasks
            .keys()
            .cloned()
            .collect()
    }

    async fn apply_task(&self, task: Task) -> Result<(), satl_dispatcher::sink::SinkError> {
        let mut state = self.state.lock().expect("sink lock");
        state.calls.push(SinkCall::ApplyTask(task.id.clone()));
        state.records.insert(task.id.clone(), task.clone());
        state.tasks.insert(task.id.clone(), task);
        Ok(())
    }

    async fn remove_task(&self, task_id: &Id) -> Result<(), satl_dispatcher::sink::SinkError> {
        let mut state = self.state.lock().expect("sink lock");
        state.calls.push(SinkCall::RemoveTask(task_id.clone()));
        state.tasks.remove(task_id);
        state.records.remove(task_id);
        Ok(())
    }

    fn reset_secrets(&self, secrets: Vec<Secret>) {
        let mut state = self.state.lock().expect("sink lock");
        state.calls.push(SinkCall::ResetSecrets(
            secrets.iter().map(|s| s.id.clone()).collect(),
        ));
        state.secrets = secrets.into_iter().map(|s| (s.id.clone(), s)).collect();
    }

    fn put_secret(&self, secret: Secret) {
        let mut state = self.state.lock().expect("sink lock");
        state.calls.push(SinkCall::PutSecret(secret.id.clone()));
        state.secrets.insert(secret.id.clone(), secret);
    }

    fn remove_secret(&self, id: &Id) {
        let mut state = self.state.lock().expect("sink lock");
        state.calls.push(SinkCall::RemoveSecret(id.clone()));
        state.secrets.remove(id);
    }

    fn reset_configs(&self, configs: Vec<Config>) {
        let mut state = self.state.lock().expect("sink lock");
        state.calls.push(SinkCall::ResetConfigs(
            configs.iter().map(|c| c.id.clone()).collect(),
        ));
        state.configs = configs.into_iter().map(|c| (c.id.clone(), c)).collect();
    }

    fn put_config(&self, config: Config) {
        let mut state = self.state.lock().expect("sink lock");
        state.calls.push(SinkCall::PutConfig(config.id.clone()));
        state.configs.insert(config.id.clone(), config);
    }

    fn remove_config(&self, id: &Id) {
        let mut state = self.state.lock().expect("sink lock");
        state.calls.push(SinkCall::RemoveConfig(id.clone()));
        state.configs.remove(id);
    }

    async fn apply_network(
        &self,
        assignment: NetworkAssignment,
    ) -> Result<(), satl_dispatcher::sink::SinkError> {
        let mut state = self.state.lock().expect("sink lock");
        state
            .calls
            .push(SinkCall::ApplyNetwork(assignment.id().clone()));
        state.networks.insert(assignment.id().clone(), assignment);
        Ok(())
    }

    async fn remove_network(&self, id: &Id) -> Result<(), satl_dispatcher::sink::SinkError> {
        let mut state = self.state.lock().expect("sink lock");
        state.calls.push(SinkCall::RemoveNetwork(id.clone()));
        state.networks.remove(id);
        Ok(())
    }
}
