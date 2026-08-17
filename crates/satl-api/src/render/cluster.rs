// SPDX-License-Identifier: BSD-2-Clause
//! `satl-core` cluster objects → Docker cluster documents (M2).
//!
//! The inverse of `crate::convert::cluster`: every store object is rendered
//! into the exact v1.43 shape, with Go's conventions honoured — nanosecond
//! durations, `{"Index": n}` versions, RFC 3339 nanosecond timestamps and
//! Docker's lower-case enum spellings.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine as _;
use satl_core::{
    Availability, ClusterSpec, Config, ConfigReference, ContainerSpec, Endpoint, EndpointMode,
    EndpointSpec, FailureAction, FileTarget, HealthConfig, Meta, Mount, MountType, Network,
    NetworkDriver, Node, NodeRole, NodeState, PortConfig, PortProtocol, PublishMode, Reachability,
    RestartCondition, RestartPolicy, Secret, SecretReference, Service, ServiceMode, ServiceSpec,
    Task, TaskSpec, UpdateConfig, UpdateOrder, UpdateStatus,
};

use crate::backend::model::{
    NetworkDetail, NetworkEndpointInfo, NetworkSummary, ServiceTaskCounts, SwarmDetail, SwarmStatus,
};
use crate::timefmt;
use crate::types::{
    CaConfigWire, ConfigReferenceWire, ConfigResponse, ConfigSpecWire, ContainerSpecWire,
    DispatcherConfigWire, DnsConfigWire, EncryptionConfigWire, EndpointSpecWire, EndpointWire,
    EngineDescriptionWire, FileTargetWire, GlobalModeWire, HealthcheckWire, IpamConfigWire,
    IpamWire, JoinTokensWire, LimitWire, ManagerStatusWire, MountWire, NetworkAttachmentConfigWire,
    NetworkAttachmentWire, NetworkConfigFromWire, NetworkContainerWire, NetworkRefWire,
    NetworkResponse, NodeDescriptionWire, NodeResponse, NodeSpecWire, NodeStatusWire,
    ObjectVersionWire, OrchestrationConfigWire, PlacementWire, PlatformWire, PortConfigWire,
    RaftConfigWire, RemoteManagerWire, ReplicatedJobModeWire, ReplicatedModeWire,
    ResourceRequirementsWire, ResourcesWire, SecretReferenceWire, SecretResponse, SecretSpecWire,
    ServiceModeWire, ServiceResponse, ServiceSpecWire, ServiceStatusWire, SwarmInfo,
    SwarmInfoResponse, SwarmResponse, SwarmSpecWire, TaskContainerStatusWire, TaskDefaultsWire,
    TaskPortStatusWire, TaskResponse, TaskRestartPolicyWire, TaskStatusWire, TaskTemplateWire,
    TlsInfoWire, UpdateConfigWire, UpdateStatusWire,
};

/// A Go `time.Duration`: nanoseconds, saturating rather than wrapping.
#[must_use]
pub fn nanos(duration: Duration) -> i64 {
    i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
}

/// The `{"Index": n}` version envelope.
fn version(meta: &Meta) -> ObjectVersionWire {
    ObjectVersionWire {
        index: meta.version.0,
    }
}

/// Docker's spelling of a node role.
#[must_use]
pub fn node_role_name(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Worker => "worker",
        NodeRole::Manager => "manager",
    }
}

/// Docker's spelling of a node availability.
#[must_use]
pub fn availability_name(availability: Availability) -> &'static str {
    match availability {
        Availability::Active => "active",
        Availability::Pause => "pause",
        Availability::Drain => "drain",
    }
}

/// Docker's spelling of a node liveness state.
#[must_use]
pub fn node_state_name(state: NodeState) -> &'static str {
    match state {
        NodeState::Unknown => "unknown",
        NodeState::Down => "down",
        NodeState::Ready => "ready",
        NodeState::Disconnected => "disconnected",
    }
}

/// Docker's spelling of a Raft-member reachability.
#[must_use]
pub fn reachability_name(reachability: Reachability) -> &'static str {
    match reachability {
        Reachability::Unknown => "unknown",
        Reachability::Unreachable => "unreachable",
        Reachability::Reachable => "reachable",
    }
}

/// Docker's spelling of a mount type.
fn mount_type_name(kind: MountType) -> &'static str {
    match kind {
        MountType::Bind => "bind",
        MountType::Volume => "volume",
        MountType::Tmpfs => "tmpfs",
    }
}

/// Docker's spelling of a port protocol.
fn protocol_name(protocol: PortProtocol) -> &'static str {
    match protocol {
        PortProtocol::Tcp => "tcp",
        PortProtocol::Udp => "udp",
    }
}

/// Docker's spelling of a publish mode.
fn publish_mode_name(mode: PublishMode) -> &'static str {
    match mode {
        PublishMode::Ingress => "ingress",
        PublishMode::Host => "host",
    }
}

// ---------------------------------------------------------------------------
// Swarm
// ---------------------------------------------------------------------------

/// `GET /swarm`.
#[must_use]
pub fn swarm(detail: &SwarmDetail) -> SwarmResponse {
    SwarmResponse {
        id: detail.cluster_id.clone(),
        version: ObjectVersionWire {
            index: detail.version.0,
        },
        created_at: timefmt::rfc3339_nano(detail.created_at),
        updated_at: timefmt::rfc3339_nano(detail.updated_at),
        spec: cluster_spec(&detail.spec),
        tls_info: TlsInfoWire {
            trust_root: detail.root_ca_cert_pem.clone(),
        },
        root_rotation_in_progress: detail.root_rotation_in_progress,
        default_addr_pool: detail.spec.default_address_pool.clone(),
        subnet_size: u32::from(detail.spec.subnet_size),
        data_path_port: 0,
        join_tokens: JoinTokensWire {
            worker: detail.join_tokens.worker.clone(),
            manager: detail.join_tokens.manager.clone(),
        },
    }
}

/// The `Spec` of a swarm document.
fn cluster_spec(spec: &ClusterSpec) -> SwarmSpecWire {
    SwarmSpecWire {
        name: spec.annotations.name.clone(),
        labels: spec.annotations.labels.clone(),
        orchestration: OrchestrationConfigWire {
            task_history_retention_limit: satl_core::defaults::TASK_HISTORY_LIMIT,
        },
        raft: RaftConfigWire {
            snapshot_interval: spec.raft.snapshot_interval,
            log_entries_for_slow_followers: spec.raft.log_entries_for_slow_followers,
            election_tick: spec.raft.election_tick,
            heartbeat_tick: spec.raft.heartbeat_tick,
        },
        dispatcher: DispatcherConfigWire {
            heartbeat_period: nanos(spec.dispatcher.heartbeat_period),
        },
        ca_config: CaConfigWire {
            node_cert_expiry: nanos(spec.ca.node_cert_expiry),
            force_rotate: spec.ca.force_rotate,
        },
        task_defaults: TaskDefaultsWire {},
        encryption_config: EncryptionConfigWire {
            auto_lock_managers: spec.autolock,
        },
    }
}

/// The `Swarm` section of `GET /info`, from live cluster state.
#[must_use]
pub fn swarm_info(status: &SwarmStatus) -> SwarmInfoResponse {
    SwarmInfoResponse {
        node_id: status.node_id.clone(),
        node_addr: status.node_addr.clone(),
        local_node_state: status.local_node_state.as_str().to_owned(),
        control_available: status.control_available,
        error: status.error.clone(),
        remote_managers: (!status.remote_managers.is_empty()).then(|| {
            status
                .remote_managers
                .iter()
                .map(|peer| RemoteManagerWire {
                    node_id: peer.node_id.clone(),
                    addr: peer.addr.clone(),
                })
                .collect()
        }),
        nodes: status.nodes,
        managers: status.managers,
    }
}

/// The `Swarm` section of `GET /info`, from the static identity `satld`
/// injected at startup (served until the backend reports live state).
#[must_use]
pub fn swarm_info_static(info: &SwarmInfo) -> SwarmInfoResponse {
    SwarmInfoResponse {
        node_id: info.node_id.clone(),
        node_addr: info.node_addr.clone(),
        local_node_state: info.local_node_state.clone(),
        control_available: info.control_available,
        error: info.error.clone(),
        remote_managers: info.remote_managers.as_ref().map(|managers| {
            managers
                .iter()
                .map(|value| RemoteManagerWire {
                    node_id: value
                        .get("NodeID")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    addr: value
                        .get("Addr")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                })
                .collect()
        }),
        nodes: 0,
        managers: 0,
    }
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

/// A Docker `Node` document.
#[must_use]
pub fn node(node: &Node) -> NodeResponse {
    NodeResponse {
        id: node.id.as_str().to_owned(),
        version: version(&node.meta),
        created_at: timefmt::rfc3339_nano(node.meta.created_at),
        updated_at: timefmt::rfc3339_nano(node.meta.updated_at),
        spec: NodeSpecWire {
            name: node.spec.name.clone().unwrap_or_default(),
            labels: node.spec.labels.clone(),
            role: node_role_name(node.spec.role).to_owned(),
            availability: availability_name(node.spec.availability).to_owned(),
        },
        description: node
            .description
            .as_ref()
            .map(|description| NodeDescriptionWire {
                hostname: description.hostname.clone(),
                platform: PlatformWire {
                    architecture: description.platform.arch.clone(),
                    os: description.platform.os.clone(),
                },
                resources: ResourcesWire {
                    nano_cpus: description.resources.nano_cpus,
                    memory_bytes: description.resources.memory_bytes,
                },
                engine: EngineDescriptionWire {
                    engine_version: description.engine.version.clone(),
                    labels: description.engine.labels.clone(),
                    plugins: Vec::new(),
                },
            })
            .unwrap_or_default(),
        status: NodeStatusWire {
            state: node_state_name(node.status.state).to_owned(),
            message: node.status.message.clone(),
            addr: node.status.addr.clone(),
        },
        manager_status: node
            .manager_status
            .as_ref()
            .map(|status| ManagerStatusWire {
                leader: status.leader,
                reachability: reachability_name(status.reachability).to_owned(),
                addr: status.addr.clone(),
            }),
    }
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

/// Docker's spelling of a network driver.
#[must_use]
pub fn network_driver_name(driver: NetworkDriver) -> &'static str {
    match driver {
        NetworkDriver::Bridge => "bridge",
        NetworkDriver::Overlay => "overlay",
    }
}

/// The scope a driver implies: an overlay spans the cluster, a bridge does not.
#[must_use]
pub fn network_scope_name(driver: NetworkDriver) -> &'static str {
    match driver {
        NetworkDriver::Bridge => "local",
        NetworkDriver::Overlay => "swarm",
    }
}

/// A network list row.
#[must_use]
pub fn network_summary(summary: &NetworkSummary) -> NetworkResponse {
    network_document(&summary.network, summary.gateway.as_deref(), &[])
}

/// A network inspect document, with its attached tasks.
#[must_use]
pub fn network_detail(detail: &NetworkDetail) -> NetworkResponse {
    network_document(
        &detail.network,
        detail.gateway.as_deref(),
        &detail.endpoints,
    )
}

/// Docker's `NetworkResource`.
///
/// `IPAM.Config[0].Gateway` is **this node's** gateway on the network, not a
/// cluster-wide one: an overlay has one gateway per participating node
/// (`Network.node_gateways`, `docs/vxlan.md` §8). Docker's document has one
/// field, so the only honest value for it is the address of the node answering
/// the request; the deviation is recorded in `docs/api-compat.md`.
fn network_document(
    network: &Network,
    gateway: Option<&str>,
    endpoints: &[NetworkEndpointInfo],
) -> NetworkResponse {
    let subnet = network
        .subnet
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    let ip_range = network
        .spec
        .ipam
        .as_ref()
        .and_then(|ipam| ipam.ip_range.as_ref())
        .map(ToString::to_string)
        .unwrap_or_default();
    let config = if subnet.is_empty() && gateway.is_none() {
        // Docker omits IPAM.Config on a network with no addressing rather than
        // listing an entry of empty strings.
        Vec::new()
    } else {
        vec![IpamConfigWire {
            subnet,
            ip_range,
            gateway: gateway.unwrap_or_default().to_owned(),
        }]
    };
    NetworkResponse {
        name: network.spec.annotations.name.clone(),
        id: network.id.as_str().to_owned(),
        created: timefmt::rfc3339_nano(network.meta.created_at),
        scope: network_scope_name(network.spec.driver).to_owned(),
        driver: network_driver_name(network.spec.driver).to_owned(),
        enable_ipv6: false,
        ipam: IpamWire {
            driver: "default".to_owned(),
            options: BTreeMap::new(),
            config,
        },
        internal: network.spec.internal,
        attachable: network.spec.attachable,
        ingress: network.spec.ingress,
        config_from: NetworkConfigFromWire::default(),
        config_only: false,
        containers: endpoints
            .iter()
            .map(|endpoint| {
                (
                    endpoint.task_id.clone(),
                    NetworkContainerWire {
                        name: endpoint.name.clone(),
                        endpoint_id: endpoint.task_id.clone(),
                        mac_address: endpoint.mac_address.clone(),
                        ipv4_address: endpoint.address.clone(),
                        ipv6_address: String::new(),
                    },
                )
            })
            .collect(),
        // Docker's exact inspect shape: `--opt encrypted` round-trips as the
        // sole driver option.
        options: if network.spec.encrypted {
            BTreeMap::from([("encrypted".to_owned(), "true".to_owned())])
        } else {
            BTreeMap::new()
        },
        labels: network.spec.annotations.labels.clone(),
        vni: network.vni,
    }
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

/// A Docker `Service` document; `counts` fills `ServiceStatus` when the
/// client asked for it (`GET /services?status=1`).
#[must_use]
pub fn service(service: &Service, counts: Option<ServiceTaskCounts>) -> ServiceResponse {
    ServiceResponse {
        id: service.id.as_str().to_owned(),
        version: version(&service.meta),
        created_at: timefmt::rfc3339_nano(service.meta.created_at),
        updated_at: timefmt::rfc3339_nano(service.meta.updated_at),
        spec: service_spec(&service.spec),
        previous_spec: service.previous_spec.as_ref().map(service_spec),
        endpoint: service.endpoint.as_ref().map(endpoint).unwrap_or_default(),
        update_status: service.update_status.as_ref().map(update_status),
        service_status: counts.map(|counts| ServiceStatusWire {
            running_tasks: counts.running,
            desired_tasks: counts.desired,
            completed_tasks: counts.completed,
        }),
    }
}

/// A Docker `ServiceSpec` document.
#[must_use]
pub fn service_spec(spec: &ServiceSpec) -> ServiceSpecWire {
    ServiceSpecWire {
        name: spec.annotations.name.clone(),
        labels: spec.annotations.labels.clone(),
        task_template: task_template(&spec.task),
        mode: match spec.mode {
            ServiceMode::Replicated { replicas } => ServiceModeWire {
                replicated: Some(ReplicatedModeWire {
                    replicas: Some(replicas),
                }),
                ..ServiceModeWire::default()
            },
            ServiceMode::Global => ServiceModeWire {
                global: Some(GlobalModeWire {}),
                ..ServiceModeWire::default()
            },
            ServiceMode::ReplicatedJob {
                max_concurrent,
                total_completions,
            } => ServiceModeWire {
                replicated_job: Some(ReplicatedJobModeWire {
                    max_concurrent,
                    total_completions,
                }),
                ..ServiceModeWire::default()
            },
            ServiceMode::GlobalJob => ServiceModeWire {
                global_job: Some(GlobalModeWire {}),
                ..ServiceModeWire::default()
            },
        },
        update_config: spec.update.as_ref().map(update_config),
        rollback_config: spec.rollback.as_ref().map(update_config),
        networks: Vec::new(),
        endpoint_spec: spec.endpoint.as_ref().map(endpoint_spec),
    }
}

/// A Docker `TaskTemplate` document.
#[must_use]
pub fn task_template(spec: &TaskSpec) -> TaskTemplateWire {
    TaskTemplateWire {
        container_spec: container_spec(&spec.container),
        resources: Some(ResourceRequirementsWire {
            limits: spec.resources.limits.map(|limits| LimitWire {
                nano_cpus: limits.nano_cpus,
                memory_bytes: limits.memory_bytes,
                pids: 0,
            }),
            reservations: spec
                .resources
                .reservations
                .map(|reservations| ResourcesWire {
                    nano_cpus: reservations.nano_cpus,
                    memory_bytes: reservations.memory_bytes,
                }),
        }),
        restart_policy: Some(restart_policy(&spec.restart)),
        placement: Some(PlacementWire {
            constraints: spec.placement.constraints.clone(),
            preferences: spec
                .placement
                .preferences
                .iter()
                .map(|preference| crate::types::PlacementPreferenceWire {
                    spread: preference.spread.as_ref().map(|spread| {
                        crate::types::SpreadPreferenceWire {
                            spread_descriptor: spread.spread_descriptor.clone(),
                        }
                    }),
                })
                .collect(),
            max_replicas: spec.placement.max_replicas,
            platforms: spec
                .placement
                .platforms
                .iter()
                .map(|platform| PlatformWire {
                    architecture: platform.arch.clone(),
                    os: platform.os.clone(),
                })
                .collect(),
        }),
        networks: spec
            .networks
            .iter()
            .map(|network| NetworkAttachmentConfigWire {
                target: network.target.clone(),
                aliases: network.aliases.clone(),
            })
            .collect(),
        force_update: spec.force_update,
        runtime: "container".to_owned(),
        log_driver: None,
    }
}

/// A Docker `ContainerSpec` document.
fn container_spec(spec: &ContainerSpec) -> ContainerSpecWire {
    ContainerSpecWire {
        image: spec.image.clone(),
        labels: spec.labels.clone(),
        command: spec.command.clone(),
        args: spec.args.clone(),
        hostname: spec.hostname.clone().unwrap_or_default(),
        env: spec.env.clone(),
        dir: spec.dir.clone().unwrap_or_default(),
        user: spec.user.clone().unwrap_or_default(),
        groups: spec.groups.clone(),
        tty: spec.tty,
        open_stdin: spec.open_stdin,
        read_only: spec.read_only,
        mounts: spec.mounts.iter().map(mount).collect(),
        stop_signal: spec.stop_signal.clone().unwrap_or_default(),
        stop_grace_period: spec.stop_grace_period.map_or(0, nanos),
        healthcheck: spec.healthcheck.as_ref().map(healthcheck),
        hosts: spec.hosts.clone(),
        dns_config: spec.dns_config.as_ref().map(|dns| DnsConfigWire {
            nameservers: dns.nameservers.clone(),
            search: dns.search.clone(),
            options: dns.options.clone(),
        }),
        secrets: spec.secrets.iter().map(secret_reference).collect(),
        configs: spec.configs.iter().map(config_reference).collect(),
        ..ContainerSpecWire::default()
    }
}

/// One `Secrets` entry of a container spec. The reference is rendered in full
/// — it names a secret, it does not carry one.
fn secret_reference(reference: &SecretReference) -> SecretReferenceWire {
    SecretReferenceWire {
        file: Some(file_target(&reference.file)),
        secret_id: reference.secret_id.as_str().to_owned(),
        secret_name: reference.secret_name.clone(),
    }
}

/// One `Configs` entry of a container spec.
fn config_reference(reference: &ConfigReference) -> ConfigReferenceWire {
    ConfigReferenceWire {
        file: Some(file_target(&reference.file)),
        config_id: reference.config_id.as_str().to_owned(),
        config_name: reference.config_name.clone(),
    }
}

/// `File` of a secret/config reference. `Mode` is a Go `os.FileMode`, so
/// `0o444` goes out as the decimal `292`.
fn file_target(target: &FileTarget) -> FileTargetWire {
    FileTargetWire {
        name: target.name.clone(),
        uid: target.uid.clone(),
        gid: target.gid.clone(),
        mode: target.mode,
    }
}

/// One `Mounts` entry of a container spec.
fn mount(mount: &Mount) -> MountWire {
    MountWire {
        kind: mount_type_name(mount.kind).to_owned(),
        source: mount.source.clone().unwrap_or_default(),
        target: mount.target.clone(),
        read_only: mount.read_only,
        ..MountWire::default()
    }
}

/// A Docker `Healthcheck` document.
fn healthcheck(check: &HealthConfig) -> HealthcheckWire {
    HealthcheckWire {
        test: check.test.clone(),
        interval: check.interval.map_or(0, nanos),
        timeout: check.timeout.map_or(0, nanos),
        retries: check.retries,
        start_period: check.start_period.map_or(0, nanos),
    }
}

/// A Docker task `RestartPolicy` document.
fn restart_policy(policy: &RestartPolicy) -> TaskRestartPolicyWire {
    let condition = match policy.condition {
        RestartCondition::None => "none",
        RestartCondition::OnFailure => "on-failure",
        RestartCondition::Any => "any",
    };
    TaskRestartPolicyWire {
        condition: condition.to_owned(),
        delay: nanos(policy.delay),
        max_attempts: policy.max_attempts,
        window: nanos(policy.window),
    }
}

/// A Docker `UpdateConfig` document.
fn update_config(config: &UpdateConfig) -> UpdateConfigWire {
    let failure_action = match config.failure_action {
        FailureAction::Pause => "pause",
        FailureAction::Continue => "continue",
        FailureAction::Rollback => "rollback",
    };
    let order = match config.order {
        UpdateOrder::StopFirst => "stop-first",
        UpdateOrder::StartFirst => "start-first",
    };
    UpdateConfigWire {
        parallelism: config.parallelism,
        delay: nanos(config.delay),
        failure_action: failure_action.to_owned(),
        monitor: nanos(config.monitor),
        max_failure_ratio: config.max_failure_ratio,
        order: order.to_owned(),
    }
}

/// A Docker `EndpointSpec` document.
fn endpoint_spec(spec: &EndpointSpec) -> EndpointSpecWire {
    let mode = match spec.mode {
        EndpointMode::DnsRR => "dnsrr",
    };
    EndpointSpecWire {
        mode: mode.to_owned(),
        ports: spec.ports.iter().map(port_config).collect(),
    }
}

/// A Docker `Endpoint` document.
fn endpoint(endpoint: &Endpoint) -> EndpointWire {
    EndpointWire {
        spec: endpoint_spec(&endpoint.spec),
        ports: endpoint.ports.iter().map(port_config).collect(),
        virtual_ips: Vec::new(),
    }
}

/// One `PortConfig` document.
fn port_config(port: &PortConfig) -> PortConfigWire {
    PortConfigWire {
        name: port.name.clone(),
        protocol: protocol_name(port.protocol).to_owned(),
        target_port: u32::from(port.target_port),
        published_port: u32::from(port.published_port),
        publish_mode: publish_mode_name(port.publish_mode).to_owned(),
    }
}

/// A Docker `UpdateStatus` document.
fn update_status(status: &UpdateStatus) -> UpdateStatusWire {
    UpdateStatusWire {
        state: format!("{:?}", status.state)
            .chars()
            .enumerate()
            .flat_map(|(index, ch)| {
                let mut out = Vec::new();
                if ch.is_uppercase() && index > 0 {
                    out.push('_');
                }
                out.extend(ch.to_lowercase());
                out
            })
            .collect(),
        started_at: status
            .started_at
            .map(timefmt::rfc3339_nano)
            .unwrap_or_default(),
        completed_at: status
            .completed_at
            .map(timefmt::rfc3339_nano)
            .unwrap_or_default(),
        message: status.message.clone(),
    }
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

/// A Docker `Task` document.
#[must_use]
pub fn task(task: &Task) -> TaskResponse {
    let status = &task.status;
    TaskResponse {
        id: task.id.as_str().to_owned(),
        version: version(&task.meta),
        created_at: timefmt::rfc3339_nano(task.meta.created_at),
        updated_at: timefmt::rfc3339_nano(task.meta.updated_at),
        name: task.annotations.name.clone(),
        labels: task.annotations.labels.clone(),
        spec: task_template(&task.spec),
        service_id: task
            .service_id
            .as_ref()
            .map(|id| id.as_str().to_owned())
            .unwrap_or_default(),
        slot: task.slot,
        node_id: task
            .node_id
            .as_ref()
            .map(|id| id.as_str().to_owned())
            .unwrap_or_default(),
        status: TaskStatusWire {
            timestamp: timefmt::rfc3339_nano(status.timestamp),
            state: status.state.to_string(),
            message: status.message.clone(),
            err: status.err.clone().unwrap_or_default(),
            container_status: status
                .container
                .as_ref()
                .map(|container| TaskContainerStatusWire {
                    container_id: container.jail_id.clone().unwrap_or_default(),
                    pid: container.pid.unwrap_or(0),
                    exit_code: container.exit_code.unwrap_or(0),
                }),
            port_status: TaskPortStatusWire {
                ports: status.port_status.iter().map(port_config).collect(),
            },
        },
        desired_state: task.desired_state.to_string(),
        networks_attachments: task
            .networks
            .iter()
            .map(|attachment| NetworkAttachmentWire {
                network: NetworkRefWire {
                    id: attachment.network_id.as_str().to_owned(),
                },
                addresses: attachment.addresses.clone(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Secrets / configs
// ---------------------------------------------------------------------------

/// A Docker `Secret` document — **never** with its payload.
///
/// `Spec.Data` is not merely empty, it is absent: a secret leaves the store
/// only into a task's tmpfs (invariant #7), so there is no request, and no
/// query parameter, that makes this function render one. Docker behaves the
/// same way (`SecretSpec.Data` is `omitempty` and the daemon clears it).
#[must_use]
pub fn secret(secret: &Secret) -> SecretResponse {
    SecretResponse {
        id: secret.id.as_str().to_owned(),
        version: version(&secret.meta),
        created_at: timefmt::rfc3339_nano(secret.meta.created_at),
        updated_at: timefmt::rfc3339_nano(secret.meta.updated_at),
        spec: SecretSpecWire {
            name: secret.spec.annotations.name.clone(),
            labels: secret.spec.annotations.labels.clone(),
            data: None,
            driver: None,
            templating: None,
        },
    }
}

/// A Docker `Config` document, payload included.
///
/// A config is not a secret: Docker returns `Spec.Data` on both list and
/// inspect, and `satl config inspect --pretty` has nothing to print without
/// it.
#[must_use]
pub fn config(config: &Config) -> ConfigResponse {
    ConfigResponse {
        id: config.id.as_str().to_owned(),
        version: version(&config.meta),
        created_at: timefmt::rfc3339_nano(config.meta.created_at),
        updated_at: timefmt::rfc3339_nano(config.meta.updated_at),
        spec: ConfigSpecWire {
            name: config.spec.annotations.name.clone(),
            labels: config.spec.annotations.labels.clone(),
            data: Some(base64::engine::general_purpose::STANDARD.encode(config.spec.data())),
            templating: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use satl_core::{
        Annotations, ConfigSpec, ContainerStatus, DesiredState, DnsConfig, EngineDescription, Id,
        ManagerStatus, NetworkAttachmentConfig, NodeDescription, NodeSpec, NodeStatus, Placement,
        Platform, Resources, SecretSpec, TaskState, TaskStatus, UpdateStateKind, Version,
    };

    use super::*;
    use crate::convert::cluster::service_spec as parse_service_spec;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn meta() -> Meta {
        Meta {
            version: Version(7),
            created_at: at(1_770_000_000),
            updated_at: at(1_770_000_600),
        }
    }

    fn sample_spec() -> ServiceSpec {
        ServiceSpec {
            annotations: Annotations {
                name: "web".to_owned(),
                labels: BTreeMap::from([("tier".to_owned(), "front".to_owned())]),
            },
            task: TaskSpec {
                container: ContainerSpec {
                    image: "nginx:1.27".to_owned(),
                    labels: BTreeMap::new(),
                    command: vec!["/entry".to_owned()],
                    args: vec!["-g".to_owned()],
                    hostname: Some("web-1".to_owned()),
                    env: vec!["A=1".to_owned()],
                    dir: Some("/srv".to_owned()),
                    user: Some("www".to_owned()),
                    groups: vec![],
                    tty: false,
                    open_stdin: false,
                    read_only: true,
                    stop_signal: Some("SIGQUIT".to_owned()),
                    stop_grace_period: Some(Duration::from_secs(15)),
                    healthcheck: Some(HealthConfig {
                        test: vec!["CMD".to_owned(), "true".to_owned()],
                        interval: Some(Duration::from_secs(5)),
                        timeout: Some(Duration::from_secs(2)),
                        retries: 3,
                        start_period: None,
                    }),
                    hosts: vec![],
                    dns_config: Some(DnsConfig {
                        nameservers: vec!["10.0.0.53".to_owned()],
                        ..DnsConfig::default()
                    }),
                    mounts: vec![Mount {
                        kind: MountType::Volume,
                        source: Some("assets".to_owned()),
                        target: "/srv/assets".to_owned(),
                        read_only: false,
                    }],
                    secrets: vec![],
                    configs: vec![],
                    pull_options: None,
                    platform: None,
                },
                resources: satl_core::ResourceRequirements {
                    limits: Some(Resources {
                        nano_cpus: 1_500_000_000,
                        memory_bytes: 536_870_912,
                    }),
                    reservations: None,
                },
                restart: RestartPolicy {
                    condition: RestartCondition::OnFailure,
                    delay: Duration::from_secs(5),
                    max_attempts: 3,
                    window: Duration::from_mins(1),
                },
                placement: Placement {
                    constraints: vec!["node.labels.zone == a".to_owned()],
                    max_replicas: 2,
                    platforms: vec![Platform {
                        os: "freebsd".to_owned(),
                        arch: "amd64".to_owned(),
                    }],
                    preferences: vec![],
                },
                networks: vec![NetworkAttachmentConfig {
                    target: "backend".to_owned(),
                    aliases: vec!["app".to_owned()],
                }],
                force_update: 1,
            },
            mode: ServiceMode::Replicated { replicas: 3 },
            update: Some(UpdateConfig {
                parallelism: 2,
                delay: Duration::from_secs(10),
                failure_action: FailureAction::Rollback,
                monitor: Duration::from_secs(20),
                max_failure_ratio: 0.25,
                order: UpdateOrder::StartFirst,
            }),
            rollback: None,
            endpoint: Some(EndpointSpec {
                mode: EndpointMode::DnsRR,
                ports: vec![PortConfig {
                    name: "http".to_owned(),
                    protocol: PortProtocol::Tcp,
                    target_port: 80,
                    published_port: 8080,
                    publish_mode: PublishMode::Ingress,
                }],
            }),
        }
    }

    #[test]
    fn service_specs_round_trip_through_the_wire_shape() {
        let original = sample_spec();
        let wire = service_spec(&original);
        let back = parse_service_spec(wire).expect("the rendered shape must parse back");
        assert_eq!(back, original);
    }

    #[test]
    fn service_spec_uses_docker_keys_and_nanosecond_durations() {
        let json = serde_json::to_value(service_spec(&sample_spec())).expect("serializable");
        assert_eq!(json["Name"], "web");
        assert_eq!(json["Labels"]["tier"], "front");
        assert_eq!(json["Mode"]["Replicated"]["Replicas"], 3);
        assert!(json["Mode"].get("Global").is_none());
        let template = &json["TaskTemplate"];
        assert_eq!(template["ContainerSpec"]["Image"], "nginx:1.27");
        assert_eq!(
            template["ContainerSpec"]["StopGracePeriod"],
            15_000_000_000_i64
        );
        assert_eq!(
            template["ContainerSpec"]["Healthcheck"]["Interval"],
            5_000_000_000_i64
        );
        assert_eq!(template["ContainerSpec"]["Mounts"][0]["Type"], "volume");
        assert_eq!(
            template["ContainerSpec"]["DNSConfig"]["Nameservers"][0],
            "10.0.0.53"
        );
        assert_eq!(
            template["Resources"]["Limits"]["NanoCPUs"],
            1_500_000_000_i64
        );
        assert_eq!(template["RestartPolicy"]["Condition"], "on-failure");
        assert_eq!(template["RestartPolicy"]["Delay"], 5_000_000_000_i64);
        assert_eq!(
            template["Placement"]["Constraints"][0],
            "node.labels.zone == a"
        );
        assert_eq!(template["Placement"]["Platforms"][0]["OS"], "freebsd");
        assert_eq!(template["Networks"][0]["Target"], "backend");
        assert_eq!(template["Runtime"], "container");
        assert_eq!(json["UpdateConfig"]["FailureAction"], "rollback");
        assert_eq!(json["UpdateConfig"]["Order"], "start-first");
        assert_eq!(json["UpdateConfig"]["Monitor"], 20_000_000_000_i64);
        assert_eq!(json["EndpointSpec"]["Mode"], "dnsrr");
        assert_eq!(json["EndpointSpec"]["Ports"][0]["PublishedPort"], 8080);
        assert_eq!(json["EndpointSpec"]["Ports"][0]["PublishMode"], "ingress");
    }

    #[test]
    fn global_services_render_the_global_member_only() {
        let mut spec = sample_spec();
        spec.mode = ServiceMode::Global;
        let json = serde_json::to_value(service_spec(&spec)).expect("serializable");
        assert!(json["Mode"]["Global"].is_object());
        assert!(json["Mode"].get("Replicated").is_none());
        assert_eq!(
            parse_service_spec(service_spec(&spec))
                .expect("round trip")
                .mode,
            ServiceMode::Global
        );
    }

    #[test]
    fn node_documents_use_docker_enum_spellings() {
        let node_object = Node {
            id: Id::generate(),
            meta: meta(),
            spec: NodeSpec {
                name: Some("alpha".to_owned()),
                labels: BTreeMap::from([("zone".to_owned(), "a".to_owned())]),
                role: NodeRole::Manager,
                availability: Availability::Drain,
            },
            description: Some(NodeDescription {
                hostname: "alpha".to_owned(),
                platform: Platform {
                    os: "freebsd".to_owned(),
                    arch: "amd64".to_owned(),
                },
                resources: Resources {
                    nano_cpus: 8_000_000_000,
                    memory_bytes: 34_359_738_368,
                },
                engine: EngineDescription {
                    version: "0.1.0".to_owned(),
                    labels: BTreeMap::new(),
                },
                linux_emulation: true,
                racct_enabled: false,
                data_addr: Some("10.2.0.11".to_owned()),
            }),
            status: NodeStatus {
                state: NodeState::Ready,
                message: String::new(),
                addr: "10.2.0.11".to_owned(),
            },
            manager_status: Some(ManagerStatus {
                raft_id: 42,
                addr: "10.2.0.11:2377".to_owned(),
                leader: true,
                reachability: Reachability::Reachable,
            }),
            certificate_status: satl_core::CertificateStatus::Issued,
            certificate_issuer: None,
        };

        let json = serde_json::to_value(node(&node_object)).expect("serializable");
        assert_eq!(json["ID"], node_object.id.as_str());
        assert_eq!(json["Version"]["Index"], 7);
        assert_eq!(json["CreatedAt"], "2026-02-02T02:40:00Z");
        assert_eq!(json["Spec"]["Name"], "alpha");
        assert_eq!(json["Spec"]["Role"], "manager");
        assert_eq!(json["Spec"]["Availability"], "drain");
        assert_eq!(json["Spec"]["Labels"]["zone"], "a");
        assert_eq!(json["Description"]["Hostname"], "alpha");
        assert_eq!(json["Description"]["Platform"]["OS"], "freebsd");
        assert_eq!(json["Description"]["Platform"]["Architecture"], "amd64");
        assert_eq!(
            json["Description"]["Resources"]["NanoCPUs"],
            8_000_000_000_i64
        );
        assert_eq!(json["Description"]["Engine"]["EngineVersion"], "0.1.0");
        assert_eq!(json["Status"]["State"], "ready");
        assert_eq!(json["Status"]["Addr"], "10.2.0.11");
        assert_eq!(json["ManagerStatus"]["Leader"], true);
        assert_eq!(json["ManagerStatus"]["Reachability"], "reachable");

        // A worker with no description keeps Docker's empty-object shape.
        let mut worker = node_object;
        worker.spec.role = NodeRole::Worker;
        worker.spec.name = None;
        worker.description = None;
        worker.manager_status = None;
        worker.status.state = NodeState::Down;
        let json = serde_json::to_value(node(&worker)).expect("serializable");
        assert_eq!(json["Spec"]["Role"], "worker");
        assert!(
            json["Spec"].get("Name").is_none(),
            "an unnamed node omits Spec.Name, as Docker does"
        );
        assert_eq!(json["Status"]["State"], "down");
        assert!(json["ManagerStatus"].is_null());
        assert_eq!(json["Description"]["Hostname"], "");
    }

    #[test]
    fn task_documents_carry_status_and_desired_state() {
        let service_id = Id::generate();
        let task_object = Task {
            id: Id::generate(),
            meta: meta(),
            spec: sample_spec().task,
            spec_version: Some(Version(3)),
            service_id: Some(service_id.clone()),
            slot: 2,
            node_id: Some(Id::generate()),
            annotations: Annotations {
                name: "web.2.abc".to_owned(),
                labels: BTreeMap::from([("tier".to_owned(), "front".to_owned())]),
            },
            service_annotations: Annotations::default(),
            status: TaskStatus {
                timestamp: at(1_770_000_300),
                state: TaskState::Running,
                message: "started".to_owned(),
                err: None,
                container: Some(ContainerStatus {
                    jail_id: Some("1hvy0lj3x0b883f8e30fyp217".to_owned()),
                    pid: Some(4242),
                    exit_code: None,
                }),
                port_status: vec![PortConfig {
                    name: String::new(),
                    protocol: PortProtocol::Tcp,
                    target_port: 80,
                    published_port: 8080,
                    publish_mode: PublishMode::Host,
                }],
                applied_by: None,
                applied_at: None,
            },
            desired_state: DesiredState::Running,
            networks: vec![satl_core::NetworkAttachment {
                network_id: Id::generate(),
                addresses: vec!["10.100.0.5/24".to_owned()],
                aliases: vec![],
            }],
            endpoint: None,
            job_iteration: None,
        };

        let json = serde_json::to_value(task(&task_object)).expect("serializable");
        assert_eq!(json["ID"], task_object.id.as_str());
        assert_eq!(json["Name"], "web.2.abc");
        assert_eq!(json["ServiceID"], service_id.as_str());
        assert_eq!(json["Slot"], 2);
        assert_eq!(json["DesiredState"], "running");
        assert_eq!(json["Status"]["State"], "running");
        assert_eq!(json["Status"]["Message"], "started");
        assert_eq!(json["Status"]["Timestamp"], "2026-02-02T02:45:00Z");
        assert_eq!(
            json["Status"]["ContainerStatus"]["ContainerID"],
            "1hvy0lj3x0b883f8e30fyp217"
        );
        assert_eq!(json["Status"]["ContainerStatus"]["PID"], 4242);
        assert_eq!(
            json["Status"]["PortStatus"]["Ports"][0]["PublishMode"],
            "host"
        );
        assert_eq!(json["Spec"]["ContainerSpec"]["Image"], "nginx:1.27");
        assert_eq!(
            json["NetworksAttachments"][0]["Addresses"][0],
            "10.100.0.5/24"
        );
        assert!(json["Status"].get("Err").is_none(), "empty Err is omitted");
    }

    #[test]
    fn service_documents_expose_status_only_when_asked() {
        let service_object = Service {
            id: Id::generate(),
            meta: meta(),
            spec: sample_spec(),
            endpoint: Some(Endpoint {
                spec: EndpointSpec::default(),
                ports: vec![PortConfig {
                    name: String::new(),
                    protocol: PortProtocol::Tcp,
                    target_port: 80,
                    published_port: 8080,
                    publish_mode: PublishMode::Ingress,
                }],
            }),
            spec_version: satl_core::Version(0),
            previous_spec: None,
            update_status: Some(UpdateStatus {
                state: UpdateStateKind::RollbackStarted,
                started_at: Some(at(1_770_000_100)),
                completed_at: None,
                message: "rolling back".to_owned(),
            }),
        };

        let plain = serde_json::to_value(service(&service_object, None)).expect("serializable");
        assert!(plain.get("ServiceStatus").is_none());
        assert_eq!(plain["Endpoint"]["Ports"][0]["PublishedPort"], 8080);
        assert_eq!(plain["UpdateStatus"]["State"], "rollback_started");
        assert_eq!(
            plain["UpdateStatus"]["CompletedAt"],
            serde_json::Value::Null
        );

        let counted = serde_json::to_value(service(
            &service_object,
            Some(ServiceTaskCounts {
                running: 2,
                desired: 3,
                completed: 0,
            }),
        ))
        .expect("serializable");
        assert_eq!(counted["ServiceStatus"]["RunningTasks"], 2);
        assert_eq!(counted["ServiceStatus"]["DesiredTasks"], 3);
    }

    #[test]
    fn swarm_document_carries_tokens_and_spec() {
        let detail = SwarmDetail {
            cluster_id: "cluster-1".to_owned(),
            created_at: at(1_770_000_000),
            updated_at: at(1_770_000_600),
            version: Version(11),
            join_tokens: satl_core::JoinTokens {
                worker: "SATL-1-worker".to_owned(),
                manager: "SATL-1-manager".to_owned(),
            },
            root_ca_cert_pem: "-----BEGIN CERTIFICATE-----\n".to_owned(),
            root_rotation_in_progress: false,
            spec: ClusterSpec {
                annotations: Annotations {
                    name: "default".to_owned(),
                    labels: BTreeMap::new(),
                },
                raft: satl_core::RaftConfig::default(),
                dispatcher: satl_core::DispatcherConfig::default(),
                ca: satl_core::CaConfig::default(),
                task_defaults: satl_core::TaskDefaults::default(),
                default_address_pool: vec!["10.100.0.0/14".to_owned()],
                subnet_size: 24,
                autolock: false,
                unlock_key: None,
            },
        };
        let json = serde_json::to_value(swarm(&detail)).expect("serializable");
        assert_eq!(json["ID"], "cluster-1");
        assert_eq!(json["Version"]["Index"], 11);
        assert_eq!(json["JoinTokens"]["Worker"], "SATL-1-worker");
        assert_eq!(json["JoinTokens"]["Manager"], "SATL-1-manager");
        assert_eq!(json["Spec"]["Name"], "default");
        assert_eq!(json["Spec"]["Raft"]["SnapshotInterval"], 10_000);
        assert_eq!(
            json["Spec"]["Dispatcher"]["HeartbeatPeriod"],
            5_000_000_000_i64
        );
        assert_eq!(
            json["Spec"]["Orchestration"]["TaskHistoryRetentionLimit"],
            5
        );
        assert_eq!(
            json["TLSInfo"]["TrustRoot"],
            "-----BEGIN CERTIFICATE-----\n"
        );
        assert_eq!(json["DefaultAddrPool"][0], "10.100.0.0/14");
        assert_eq!(json["SubnetSize"], 24);
        assert_eq!(json["RootRotationInProgress"], false);
    }

    #[test]
    fn info_swarm_section_reports_membership() {
        use crate::backend::model::{LocalNodeState, ManagerPeer};

        let status = SwarmStatus {
            node_id: "node-1".to_owned(),
            node_addr: "10.2.0.11".to_owned(),
            local_node_state: LocalNodeState::Active,
            control_available: true,
            error: String::new(),
            remote_managers: vec![ManagerPeer {
                node_id: "node-1".to_owned(),
                addr: "10.2.0.11:2377".to_owned(),
            }],
            nodes: 3,
            managers: 1,
        };
        let json = serde_json::to_value(swarm_info(&status)).expect("serializable");
        assert_eq!(json["NodeID"], "node-1");
        assert_eq!(json["LocalNodeState"], "active");
        assert_eq!(json["ControlAvailable"], true);
        assert_eq!(json["Nodes"], 3);
        assert_eq!(json["Managers"], 1);
        assert_eq!(json["RemoteManagers"][0]["NodeID"], "node-1");
        assert_eq!(json["RemoteManagers"][0]["Addr"], "10.2.0.11:2377");

        let inactive = swarm_info(&SwarmStatus::default());
        let json = serde_json::to_value(inactive).expect("serializable");
        assert_eq!(json["LocalNodeState"], "inactive");
        assert!(json["RemoteManagers"].is_null());
        assert!(json.get("Nodes").is_none(), "zero counts are omitted");
    }

    fn annotations(name: &str) -> Annotations {
        Annotations {
            name: name.to_owned(),
            labels: BTreeMap::from([("env".to_owned(), "prod".to_owned())]),
        }
    }

    /// The one rendering rule that is a security property, not a compatibility
    /// one: a secret document carries no payload — not an empty `Data`, no
    /// `Data` key at all — while a config document carries its own, base64, as
    /// Docker's does.
    #[test]
    fn a_secret_document_never_carries_its_payload_and_a_config_does() {
        let id = Id::generate();
        let object = satl_core::Secret {
            id: id.clone(),
            meta: meta(),
            spec: SecretSpec::new(annotations("db_password"), b"s3cr3t".to_vec())
                .expect("a valid secret"),
        };
        let document = secret(&object);
        let encoded = serde_json::to_string(&document).expect("serializable");
        assert!(
            !encoded.contains("s3cr3t") && !encoded.contains("czNjcjN0"),
            "neither the payload nor its base64 may appear: {encoded}"
        );
        let json: serde_json::Value = serde_json::from_str(&encoded).expect("valid json");
        assert_eq!(json["ID"], id.as_str());
        assert_eq!(json["Version"]["Index"], 7);
        assert_eq!(json["CreatedAt"], "2026-02-02T02:40:00Z");
        assert_eq!(json["Spec"]["Name"], "db_password");
        assert_eq!(json["Spec"]["Labels"]["env"], "prod");
        assert!(
            json["Spec"].get("Data").is_none(),
            "the Data key itself must be absent: {json}"
        );

        let object = satl_core::Config {
            id: Id::generate(),
            meta: meta(),
            spec: ConfigSpec::new(annotations("nginx_conf"), b"server {}".to_vec())
                .expect("a valid config"),
        };
        let json = serde_json::to_value(config(&object)).expect("serializable");
        assert_eq!(json["Spec"]["Name"], "nginx_conf");
        assert_eq!(
            json["Spec"]["Data"], "c2VydmVyIHt9",
            "a config payload is standard base64"
        );
    }

    /// Docker's inspect shape: an encrypted overlay network reports
    /// `Options: {"encrypted": "true"}`, a plaintext one an empty map.
    #[test]
    fn an_encrypted_network_reports_the_option_in_its_document() {
        let mut network = Network {
            id: Id::generate(),
            meta: meta(),
            spec: satl_core::NetworkSpec {
                annotations: annotations("blue"),
                driver: NetworkDriver::Overlay,
                ipam: None,
                internal: false,
                attachable: false,
                ingress: false,
                encrypted: true,
            },
            vni: Some(4_096),
            vxlan_port: None,
            subnet: Some("10.100.4.0/24".to_owned()),
            node_gateways: BTreeMap::new(),
            keys: Vec::new(),
            keys_updated_at: None,
        };
        let detail = NetworkDetail {
            network: network.clone(),
            gateway: None,
            endpoints: Vec::new(),
        };
        let document = network_detail(&detail);
        assert_eq!(document.options["encrypted"], "true");

        network.spec.encrypted = false;
        let detail = NetworkDetail {
            network,
            gateway: None,
            endpoints: Vec::new(),
        };
        assert!(network_detail(&detail).options.is_empty());
    }

    /// `Mode` is a Go `os.FileMode`: decimal on the wire. `0o444` is `292`, and
    /// a client that reads `444` there would create a world-writable file.
    #[test]
    fn secret_and_config_references_render_with_dockers_decimal_mode() {
        let secret_id = Id::generate();
        let config_id = Id::generate();
        let mut spec = sample_spec();
        spec.task.container.secrets = vec![SecretReference {
            secret_id: secret_id.clone(),
            secret_name: "db_password".to_owned(),
            file: FileTarget {
                name: "db_password".to_owned(),
                uid: "0".to_owned(),
                gid: "0".to_owned(),
                mode: 0o444,
            },
        }];
        spec.task.container.configs = vec![ConfigReference {
            config_id: config_id.clone(),
            config_name: "nginx_conf".to_owned(),
            file: FileTarget {
                name: "/etc/nginx/nginx.conf".to_owned(),
                uid: "80".to_owned(),
                gid: "80".to_owned(),
                mode: 0o600,
            },
        }];
        let json = serde_json::to_value(service_spec(&spec)).expect("serializable");
        let container = &json["TaskTemplate"]["ContainerSpec"];
        assert_eq!(container["Secrets"][0]["SecretID"], secret_id.as_str());
        assert_eq!(container["Secrets"][0]["SecretName"], "db_password");
        assert_eq!(container["Secrets"][0]["File"]["Name"], "db_password");
        assert_eq!(container["Secrets"][0]["File"]["UID"], "0");
        assert_eq!(container["Secrets"][0]["File"]["GID"], "0");
        assert_eq!(container["Secrets"][0]["File"]["Mode"], 292);
        assert_eq!(container["Configs"][0]["ConfigID"], config_id.as_str());
        assert_eq!(
            container["Configs"][0]["File"]["Name"],
            "/etc/nginx/nginx.conf"
        );
        assert_eq!(container["Configs"][0]["File"]["Mode"], 384);

        // A spec with no references renders neither key (Docker omits both).
        let json = serde_json::to_value(service_spec(&sample_spec())).expect("serializable");
        let container = &json["TaskTemplate"]["ContainerSpec"];
        assert!(container.get("Secrets").is_none(), "{container}");
        assert!(container.get("Configs").is_none(), "{container}");
    }
}
