// SPDX-License-Identifier: BSD-2-Clause
// Test support shared by this crate's unit tests and its integration tests
// (the latter include this file with `#[path = "../src/testing.rs"]`, so it
// must stay self-contained: no `crate::` paths).
//
// Each test target uses a subset of the helpers.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime};

use satl_cluster::{ClusterStore, ProposeError, RaftNode, RaftNodeConfig, StoreView};
use satl_core::{
    Annotations, Availability, CertificateStatus, ContainerSpec, DesiredState, EndpointMode,
    EndpointSpec, EngineDescription, Id, IpamConfig, Meta, Network, NetworkAttachmentConfig,
    NetworkDriver, NetworkSpec, Node, NodeDescription, NodeRole, NodeSpec, NodeState, NodeStatus,
    Placement, Platform, PortConfig, PortProtocol, PublishMode, ResourceRequirements, Resources,
    RestartCondition, RestartPolicy, Service, ServiceMode, ServiceSpec, StoreAction, StoreObject,
    Task, TaskSpec, TaskState, TaskStatus,
};
use tempfile::TempDir;

/// How long the polling helpers wait before failing a test.
///
/// A safety net rather than a measurement: nothing here is expected to take
/// seconds. It is 20 s because a test *file* runs its cases in parallel and each
/// one starts a real Raft node with real fsyncs, so a loaded machine can push a
/// convergence that normally takes 200 ms past a tighter bound and turn a
/// correct loop into a flake.
const WAIT_TIMEOUT: Duration = Duration::from_secs(20);

/// Poll interval for the waiting helpers.
const POLL: Duration = Duration::from_millis(5);

/// A real single-node cluster store in a temp dir (~20 ms to start), as used
/// by `satl-cluster`'s own tests: a genuine Raft FSM, no network.
pub struct TestCluster {
    store: ClusterStore,
    node: RaftNode,
    _dir: TempDir,
}

impl TestCluster {
    /// Starts a fresh single-node cluster; it is leader on return, with the
    /// `default` cluster object and its own `Ready`/`Active` node seeded.
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = RaftNodeConfig {
            raft_dir: dir.path().join("raft"),
            node_name: "alpha".to_owned(),
            ..Default::default()
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

    /// The seeded node's ID.
    pub fn node_id(&self) -> &Id {
        self.node.node_id()
    }

    /// Stops Raft (and with it the temp dir).
    pub async fn shutdown(self) {
        self.node.shutdown().await.expect("clean shutdown");
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

    /// Asserts that `predicate` holds continuously for `duration` — the
    /// negative assertions ("no replacement task appears").
    pub async fn stays<F>(&self, duration: Duration, what: &str, mut predicate: F)
    where
        F: FnMut(&StoreView<'_>) -> bool,
    {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            {
                let view = self.store.view();
                assert!(predicate(&view), "{what}");
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// All tasks of a service, sorted by slot then creation time.
    pub fn tasks_of(&self, service_id: &Id) -> Vec<Task> {
        let view = self.store.view();
        let mut tasks: Vec<Task> = view
            .tasks()
            .into_iter()
            .filter(|t| t.service_id.as_ref() == Some(service_id))
            .map(|t| (*t).clone())
            .collect();
        tasks.sort_by(|a, b| {
            a.slot
                .cmp(&b.slot)
                .then(a.meta.created_at.cmp(&b.meta.created_at))
                .then(a.id.cmp(&b.id))
        });
        tasks
    }
}

/// Writes a task status the way an agent would, retrying the optimistic
/// concurrency race against the loops under test.
pub async fn set_task_state(store: &ClusterStore, task_id: &Id, state: TaskState) {
    for _ in 0..50 {
        let current = {
            let view = store.view();
            view.task(task_id).map(|task| (*task).clone())
        };
        let mut task = current.unwrap_or_else(|| panic!("task {task_id} is gone"));
        task.status = TaskStatus::new(state, "reported by the test agent");
        match store
            .propose(vec![StoreAction::Update(StoreObject::Task(task))])
            .await
        {
            Ok(_) => return,
            Err(ProposeError::Rejected(_)) => tokio::time::sleep(POLL).await,
            Err(err) => panic!("failed to report task status: {err}"),
        }
    }
    panic!("never won the race to report the status of task {task_id}");
}

/// Rewrites a node the way the dispatcher (liveness) or the operator
/// (availability) would, retrying the optimistic concurrency race against the
/// loops under test.
pub async fn update_node(store: &ClusterStore, node_id: &Id, mutate: impl Fn(&mut Node)) {
    for _ in 0..50 {
        let current = {
            let view = store.view();
            view.node(node_id).map(|node| (*node).clone())
        };
        let mut node = current.unwrap_or_else(|| panic!("node {node_id} is gone"));
        mutate(&mut node);
        match store
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

/// Rewrites a service's replica count, retrying on sequence conflicts.
pub async fn scale_service(store: &ClusterStore, service_id: &Id, replicas: u64) {
    for _ in 0..50 {
        let current = {
            let view = store.view();
            view.service(service_id).map(|service| (*service).clone())
        };
        let mut service = current.unwrap_or_else(|| panic!("service {service_id} is gone"));
        service.spec.mode = ServiceMode::Replicated { replicas };
        match store
            .propose(vec![StoreAction::Update(StoreObject::Service(service))])
            .await
        {
            Ok(_) => return,
            Err(ProposeError::Rejected(_)) => tokio::time::sleep(POLL).await,
            Err(err) => panic!("failed to scale service: {err}"),
        }
    }
    panic!("never won the race to scale service {service_id}");
}

/// Rewrites a service's spec the way the control backend does
/// (`satld::backend::swarm::update_service_impl`): the spec that was there
/// becomes `previous_spec`, so a rollback has somewhere to go. Retries the
/// optimistic concurrency race against the loops under test.
pub async fn update_spec(
    store: &ClusterStore,
    service_id: &Id,
    mutate: impl Fn(&mut satl_core::ServiceSpec),
) {
    for _ in 0..50 {
        let current = {
            let view = store.view();
            view.service(service_id).map(|service| (*service).clone())
        };
        let mut service = current.unwrap_or_else(|| panic!("service {service_id} is gone"));
        service.previous_spec = Some(service.spec.clone());
        mutate(&mut service.spec);
        service.meta.updated_at = std::time::SystemTime::now();
        match store
            .propose(vec![StoreAction::Update(StoreObject::Service(service))])
            .await
        {
            Ok(_) => return,
            Err(ProposeError::Rejected(_)) => tokio::time::sleep(POLL).await,
            Err(err) => panic!("failed to update service spec: {err}"),
        }
    }
    panic!("never won the race to update service {service_id}");
}

/// Gives a service a rolling-update configuration (and the same one for
/// rollbacks unless the caller overrides it).
pub fn with_update(mut service: Service, update: satl_core::UpdateConfig) -> Service {
    service.spec.update = Some(update);
    service
}

/// A minimal replicated service spec.
pub fn sample_service(name: &str, replicas: u64) -> Service {
    Service {
        id: Id::generate(),
        meta: Meta::new(),
        spec: ServiceSpec {
            annotations: Annotations {
                name: name.to_owned(),
                labels: BTreeMap::new(),
            },
            task: sample_task_spec(),
            mode: ServiceMode::Replicated { replicas },
            update: None,
            rollback: None,
            endpoint: None,
        },
        endpoint: None,
        spec_version: satl_core::Version(0),
        previous_spec: None,
        update_status: None,
    }
}

/// The task template used by [`sample_service`].
pub fn sample_task_spec() -> TaskSpec {
    TaskSpec {
        container: ContainerSpec {
            image: "127.0.0.1:5000/freebsd-nginx:1".to_owned(),
            labels: BTreeMap::new(),
            command: vec![],
            args: vec![],
            hostname: None,
            env: vec![],
            dir: None,
            user: None,
            groups: vec![],
            tty: false,
            open_stdin: false,
            read_only: false,
            stop_signal: None,
            stop_grace_period: None,
            healthcheck: None,
            hosts: vec![],
            dns_config: None,
            mounts: vec![],
            secrets: vec![],
            configs: vec![],
            pull_options: None,
            platform: None,
        },
        resources: ResourceRequirements::default(),
        restart: RestartPolicy::default(),
        placement: Placement::default(),
        networks: vec![],
        force_update: 0,
    }
}

/// Sets a service label (the `satl.autostart` contract lives in labels).
pub fn with_label(mut service: Service, key: &str, value: &str) -> Service {
    service
        .spec
        .annotations
        .labels
        .insert(key.to_owned(), value.to_owned());
    service
}

/// Sets the restart policy of a service's task template.
pub fn with_restart(
    mut service: Service,
    condition: RestartCondition,
    delay: Duration,
    max_attempts: u64,
) -> Service {
    service.spec.task.restart = RestartPolicy {
        condition,
        delay,
        max_attempts,
        window: Duration::ZERO,
    };
    service
}

/// Sets the networks a service's tasks attach to (by name or ID).
pub fn with_networks(mut service: Service, targets: &[&str]) -> Service {
    service.spec.task.networks = targets
        .iter()
        .map(|target| NetworkAttachmentConfig {
            target: (*target).to_owned(),
            aliases: vec![],
        })
        .collect();
    service
}

/// Gives a service one published port; `published == 0` asks the allocator to
/// pick one from the ingress range.
pub fn with_published_port(
    mut service: Service,
    name: &str,
    target: u16,
    published: u16,
) -> Service {
    let port = PortConfig {
        name: name.to_owned(),
        protocol: PortProtocol::Tcp,
        target_port: target,
        published_port: published,
        publish_mode: PublishMode::Ingress,
    };
    let spec = service.spec.endpoint.get_or_insert(EndpointSpec {
        mode: EndpointMode::DnsRR,
        ports: vec![],
    });
    spec.ports.push(port);
    service
}

/// An unallocated network object, as `satl network create` writes it.
pub fn planted_network(name: &str, driver: NetworkDriver) -> Network {
    Network {
        id: Id::generate(),
        meta: Meta::new(),
        spec: NetworkSpec {
            annotations: Annotations {
                name: name.to_owned(),
                labels: BTreeMap::new(),
            },
            driver,
            ipam: None,
            internal: false,
            attachable: false,
            ingress: false,
            encrypted: false,
        },
        vni: None,
        vxlan_port: None,
        subnet: None,
        node_gateways: BTreeMap::new(),
        keys: Vec::new(),
        keys_updated_at: None,
    }
}

/// A network with operator-requested addressing (`--subnet`, `--gateway`,
/// `--ip-range`).
pub fn with_ipam(
    mut network: Network,
    subnet: Option<&str>,
    gateway: Option<&str>,
    ip_range: Option<&str>,
) -> Network {
    network.spec.ipam = Some(IpamConfig {
        subnet: subnet.map(str::to_owned),
        gateway: gateway.map(str::to_owned),
        ip_range: ip_range.map(str::to_owned),
    });
    network
}

/// A synthetic node object, built the way the scheduler's tests build them:
/// `Ready`, `Active`, `freebsd/amd64`, 4 CPUs and 8 GiB.
///
/// Mutate `status.state` / `spec.availability` for the node-state cases.
pub fn planted_node(name: &str) -> Node {
    Node {
        id: Id::generate(),
        meta: Meta::new(),
        spec: NodeSpec {
            name: Some(name.to_owned()),
            labels: BTreeMap::new(),
            role: NodeRole::Worker,
            availability: Availability::Active,
        },
        description: Some(NodeDescription {
            hostname: name.to_owned(),
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
            linux_emulation: false,
            racct_enabled: true,
            data_addr: None,
        }),
        status: NodeStatus {
            state: NodeState::Ready,
            message: String::new(),
            addr: "10.2.0.10".to_owned(),
        },
        manager_status: None,
        certificate_status: CertificateStatus::Issued,
        certificate_issuer: None,
    }
}

/// Binds a planted task to a node, the way the scheduler would.
pub fn assigned_to(mut task: Task, node_id: &Id) -> Task {
    task.node_id = Some(node_id.clone());
    task
}

/// A task belonging to `service`, in an arbitrary observed/desired state —
/// used to plant history the loops must react to.
pub fn planted_task(
    service: &Service,
    slot: u64,
    state: TaskState,
    desired: DesiredState,
    created_at: SystemTime,
) -> Task {
    let id = Id::generate();
    let mut meta = Meta::new();
    meta.created_at = created_at;
    meta.updated_at = created_at;
    let mut status = TaskStatus::new(state, "planted");
    status.timestamp = created_at;
    Task {
        annotations: Annotations {
            name: satl_core::naming::task_name(
                &service.spec.annotations.name,
                &slot.to_string(),
                &id,
            ),
            labels: BTreeMap::new(),
        },
        id,
        meta,
        spec: service.spec.task.clone(),
        spec_version: Some(service.meta.version),
        service_id: Some(service.id.clone()),
        slot,
        node_id: None,
        service_annotations: service.spec.annotations.clone(),
        status,
        desired_state: desired,
        networks: vec![],
        endpoint: None,
        job_iteration: None,
    }
}
