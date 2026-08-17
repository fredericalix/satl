// SPDX-License-Identifier: BSD-2-Clause
// Test support shared by this crate's unit tests and its integration tests
// (the latter include this file with `#[path = "../src/testing.rs"]`, so it
// must stay self-contained: no `crate::` paths).
//
// Each test target uses a subset of the helpers.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime};

use satl_cluster::{ClusterStore, RaftNode, RaftNodeConfig, StoreView};
use satl_core::{
    Annotations, Availability, CertificateStatus, ContainerSpec, DesiredState, Endpoint,
    EndpointSpec, EngineDescription, Id, Meta, Node, NodeDescription, NodeRole, NodeSpec,
    NodeState, NodeStatus, Placement, Platform, PortConfig, PortProtocol, PublishMode,
    ResourceRequirements, Resources, RestartPolicy, Service, ServiceMode, ServiceSpec, Task,
    TaskSpec, TaskState, TaskStatus,
};
use tempfile::TempDir;

/// How long the polling helpers wait before failing a test.
const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval for the waiting helpers.
const POLL: Duration = Duration::from_millis(5);

/// A real single-node cluster store in a temp dir (~20 ms to start): a
/// genuine Raft FSM, no network.
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

    /// Asserts that `predicate` holds continuously for `duration`.
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

/// A task belonging to `service`, in an arbitrary observed/desired state.
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

/// A node object in an arbitrary liveness/availability combination — for
/// filter tests, which never touch the store.
pub fn planted_node(state: NodeState, availability: Availability) -> Node {
    NodeBuilder::new("alpha")
        .state(state)
        .availability(availability)
        .build()
}

/// Builds synthetic [`Node`] objects for filter, ranking and multi-node
/// scheduling tests.
///
/// Defaults are "a healthy node the scheduler will happily use": `Ready`,
/// `Active`, manager, `freebsd/amd64`, 4 CPUs and 8 GiB.
pub struct NodeBuilder {
    node: Node,
}

impl NodeBuilder {
    /// A ready, active node named `name` (hostname and spec name alike).
    pub fn new(name: &str) -> Self {
        Self {
            node: Node {
                id: Id::generate(),
                meta: Meta::new(),
                spec: NodeSpec {
                    name: Some(name.to_owned()),
                    labels: BTreeMap::new(),
                    role: NodeRole::Manager,
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
                        memory_bytes: gib(8),
                    },
                    engine: EngineDescription {
                        version: "0.1.0".to_owned(),
                        labels: BTreeMap::new(),
                    },
                    linux_emulation: false,
                    racct_enabled: false,
                    data_addr: None,
                }),
                status: NodeStatus {
                    state: NodeState::Ready,
                    message: String::new(),
                    addr: "10.2.0.11".to_owned(),
                },
                manager_status: None,
                certificate_status: CertificateStatus::Issued,
                certificate_issuer: None,
            },
        }
    }

    /// Derives the node ID from its name, so a set of nodes sorts in a
    /// predictable order (IDs break comparator ties).
    #[must_use]
    pub fn id_from_name(mut self) -> Self {
        let name = self.node.spec.name.clone().unwrap_or_default();
        let mut id: String = name
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .take(25)
            .collect();
        while id.len() < 25 {
            id.push('0');
        }
        self.node.id = id.parse().expect("derived id is 25 base36 chars");
        self
    }

    /// Sets the observed liveness state.
    #[must_use]
    pub fn state(mut self, state: NodeState) -> Self {
        self.node.status.state = state;
        self
    }

    /// Sets the scheduling availability.
    #[must_use]
    pub fn availability(mut self, availability: Availability) -> Self {
        self.node.spec.availability = availability;
        self
    }

    /// Sets the cluster role.
    #[must_use]
    pub fn role(mut self, role: NodeRole) -> Self {
        self.node.spec.role = role;
        self
    }

    /// Adds a node spec label (`node.labels.<key>`).
    #[must_use]
    pub fn label(mut self, key: &str, value: &str) -> Self {
        self.node
            .spec
            .labels
            .insert(key.to_owned(), value.to_owned());
        self
    }

    /// Adds an engine label (`engine.labels.<key>`).
    #[must_use]
    pub fn engine_label(mut self, key: &str, value: &str) -> Self {
        if let Some(description) = self.node.description.as_mut() {
            description
                .engine
                .labels
                .insert(key.to_owned(), value.to_owned());
        }
        self
    }

    /// Sets the reported platform.
    #[must_use]
    pub fn platform(mut self, os: &str, arch: &str) -> Self {
        if let Some(description) = self.node.description.as_mut() {
            description.platform = Platform {
                os: os.to_owned(),
                arch: arch.to_owned(),
            };
        }
        self
    }

    /// Sets the reported capacity.
    #[must_use]
    pub fn resources(mut self, nano_cpus: i64, memory_bytes: i64) -> Self {
        if let Some(description) = self.node.description.as_mut() {
            description.resources = Resources {
                nano_cpus,
                memory_bytes,
            };
        }
        self
    }

    /// Sets the advertised address (`node.ip` constraints).
    #[must_use]
    pub fn addr(mut self, addr: &str) -> Self {
        addr.clone_into(&mut self.node.status.addr);
        self
    }

    /// Drops the description entirely: a node that has never registered.
    #[must_use]
    pub fn no_description(mut self) -> Self {
        self.node.description = None;
        self
    }

    /// The finished node.
    #[must_use]
    pub fn build(self) -> Node {
        self.node
    }
}

/// `n` gibibytes in bytes.
pub fn gib(n: i64) -> i64 {
    n * 1024 * 1024 * 1024
}

/// Gives a task a resource reservation (what the scheduler places against).
pub fn reserve(task: &mut Task, nano_cpus: i64, memory_bytes: i64) {
    task.spec.resources.reservations = Some(Resources {
        nano_cpus,
        memory_bytes,
    });
}

/// Publishes a host-mode port on a task's endpoint.
pub fn host_port(task: &mut Task, protocol: PortProtocol, published_port: u16) {
    let endpoint = task.endpoint.get_or_insert_with(|| Endpoint {
        spec: EndpointSpec::default(),
        ports: Vec::new(),
    });
    endpoint.ports.push(PortConfig {
        name: String::new(),
        protocol,
        target_port: published_port,
        published_port,
        publish_mode: PublishMode::Host,
    });
}
