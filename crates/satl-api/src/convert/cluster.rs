// SPDX-License-Identifier: BSD-2-Clause
//! Docker cluster documents → [`backend::model`](crate::backend::model) and
//! `satl-core` types (M2: swarm, nodes, services, tasks).
//!
//! Same contract as the container conversions in the parent module: Docker's
//! vocabulary becomes SatL's, and anything SatL cannot honour is rejected with
//! [`BackendError::InvalidParameter`] (HTTP 400, Docker's `{"message": …}`
//! shape) rather than silently dropped. A service that quietly ignores
//! `CapabilityAdd`, a placement preference or a `vip` endpoint mode would
//! schedule something the operator did not ask for.

use std::collections::BTreeMap;
use std::time::Duration;

use satl_core::{
    Annotations, Availability, ConfigReference, ConfigSpec, Constraint, ContainerSpec,
    DesiredState, DnsConfig, EndpointMode, EndpointSpec, FailureAction, FileTarget, HealthConfig,
    Id, IpamConfig, Ipv4Cidr, Mount, MountType, NetworkDriver, NetworkSpec, NodeRole, Placement,
    Platform, PortConfig, PortProtocol, PublishMode, ResourceRequirements, Resources,
    RestartCondition, RestartPolicy, SecretReference, SecretSpec, ServiceMode, ServiceSpec,
    TaskSpec, UpdateConfig, UpdateOrder, Version, naming,
};

use crate::backend::model::{
    BackendError, NetworkConnectOptions, NetworkDisconnectOptions, NodeSpecUpdate, Result,
    SwarmInitOptions, SwarmJoinOptions, TaskFilters,
};
use crate::types::{
    ConfigReferenceWire, ConfigSpecWire, ContainerSpecWire, EndpointSpecWire, FileTargetWire,
    HealthcheckWire, IpamWire, MountWire, NetworkConnectBody, NetworkCreateBody,
    NetworkDisconnectBody, NodeSpecWire, PlacementWire, PortConfigWire, ResourceRequirementsWire,
    SecretReferenceWire, SecretSpecWire, ServiceModeWire, ServiceSpecWire, TaskRestartPolicyWire,
    TaskTemplateWire, UpdateConfigWire,
};

/// The only task runtime SatL drives (invariant #6): containers as jails.
const TASK_RUNTIME: &str = "container";

/// Rejects a Docker feature SatL cannot honour, naming the field and why.
fn unsupported<T>(field: &str, reason: &str) -> Result<T> {
    Err(BackendError::invalid(format!(
        "{field} is not supported by SatL: {reason}"
    )))
}

/// A Go `time.Duration` (nanoseconds) from the wire.
fn duration(nanos: i64, field: &str) -> Result<Duration> {
    u64::try_from(nanos).map(Duration::from_nanos).map_err(|_| {
        BackendError::invalid(format!(
            "invalid {field}: {nanos} is not a positive duration"
        ))
    })
}

/// A port number from Docker's `uint32` port fields.
fn port_number(value: u32, field: &str) -> Result<u16> {
    u16::try_from(value).map_err(|_| {
        BackendError::invalid(format!("invalid {field}: {value} is not a port number"))
    })
}

/// `?version=` — the caller's copy of the object version, required by every
/// Docker update endpoint (optimistic concurrency).
pub fn object_version(value: Option<&str>) -> Result<Version> {
    let value = value.ok_or_else(|| {
        BackendError::invalid("invalid parameter: version is required for this update")
    })?;
    value.parse::<u64>().map(Version).map_err(|_| {
        BackendError::invalid(format!(
            "invalid version {value:?}: expected the object's version index"
        ))
    })
}

// ---------------------------------------------------------------------------
// Swarm
// ---------------------------------------------------------------------------

/// `POST /swarm/init` body → init options.
pub fn swarm_init_options(body: &crate::types::SwarmInitBody) -> Result<SwarmInitOptions> {
    availability_or_default(&body.availability)?;
    Ok(SwarmInitOptions {
        advertise_addr: non_empty(&body.advertise_addr),
        listen_addr: non_empty(&body.listen_addr),
        force_new_cluster: body.force_new_cluster,
        auto_lock: body.auto_lock_managers,
    })
}

/// `POST /swarm/join` body → join options.
pub fn swarm_join_options(body: crate::types::SwarmJoinBody) -> Result<SwarmJoinOptions> {
    let remote_addrs: Vec<String> = body
        .remote_addrs
        .into_iter()
        .map(|addr| addr.trim().to_owned())
        .filter(|addr| !addr.is_empty())
        .collect();
    if remote_addrs.is_empty() {
        return Err(BackendError::invalid(
            "invalid parameter: RemoteAddrs must name at least one manager address",
        ));
    }
    if body.join_token.trim().is_empty() {
        return Err(BackendError::invalid(
            "invalid parameter: JoinToken is required (run `satl swarm join-token` on a manager)",
        ));
    }
    availability_or_default(&body.availability)?;
    Ok(SwarmJoinOptions {
        remote_addrs,
        join_token: body.join_token.trim().to_owned(),
        advertise_addr: non_empty(&body.advertise_addr),
        listen_addr: non_empty(&body.listen_addr),
    })
}

/// `Some(value)` when `value` is not blank.
fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

/// Docker's node role name → [`NodeRole`].
pub fn node_role(value: &str) -> Result<NodeRole> {
    match value.trim() {
        "worker" => Ok(NodeRole::Worker),
        "manager" => Ok(NodeRole::Manager),
        other => Err(BackendError::invalid(format!(
            "invalid role {other:?}: must be one of worker, manager"
        ))),
    }
}

/// Docker's availability name → [`Availability`].
pub fn availability(value: &str) -> Result<Availability> {
    match value.trim() {
        "active" => Ok(Availability::Active),
        "pause" => Ok(Availability::Pause),
        "drain" => Ok(Availability::Drain),
        other => Err(BackendError::invalid(format!(
            "invalid availability {other:?}: must be one of active, pause, drain"
        ))),
    }
}

/// An availability that may be left unset (`""` = "keep the default").
fn availability_or_default(value: &str) -> Result<Option<Availability>> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    availability(value).map(Some)
}

/// `POST /nodes/{id}/update` body → the replacement spec.
pub fn node_spec_update(body: NodeSpecWire) -> Result<NodeSpecUpdate> {
    Ok(NodeSpecUpdate {
        name: non_empty(&body.name),
        labels: body.labels,
        role: node_role(&body.role)?,
        availability: availability(&body.availability)?,
    })
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

/// Docker's network driver name → [`NetworkDriver`].
///
/// `bridge` and `overlay` are Docker's own names for the two data planes SatL
/// has (architecture §11.1, §11.2). `local` is accepted as a synonym for
/// `bridge` because that is the *scope* SatL reports for it and operators type
/// it; everything else is refused rather than quietly bridged — a network whose
/// driver is not what was asked for is not a network anybody can reason about.
pub fn network_driver(value: &str) -> Result<NetworkDriver> {
    match value.trim() {
        "bridge" | "local" => Ok(NetworkDriver::Bridge),
        "overlay" => Ok(NetworkDriver::Overlay),
        other => Err(BackendError::invalid(format!(
            "invalid driver {other:?}: SatL has two network drivers, bridge (node-local) and \
             overlay (cluster-wide)"
        ))),
    }
}

/// `POST /networks/create` body → [`satl_core::NetworkSpec`].
///
/// Everything Docker can express that SatL cannot honour is a 400 here. The
/// alternative — accepting and ignoring — hands the operator a network that is
/// not the one they asked for: an `internal` network with egress, an
/// `attachable` one nothing can attach to, an IPv6 one with no IPv6.
pub fn network_spec(body: NetworkCreateBody) -> Result<NetworkSpec> {
    let name = body.name.trim();
    if !name.is_empty() {
        naming::validate_network_name(name).map_err(|err| {
            BackendError::invalid(format!("invalid network name {name:?}: {err}"))
        })?;
    }

    if body.enable_ipv6 {
        return unsupported(
            "EnableIPv6",
            "SatL's IPAM and overlay data plane are IPv4-only in v1",
        );
    }
    if body.internal {
        return unsupported(
            "Internal",
            "every SatL network has egress through the node's pf NAT anchor; an \
             internal network would need a rule set SatL does not write yet",
        );
    }
    if body.attachable {
        return unsupported(
            "Attachable",
            "standalone containers cannot attach to a SatL network: every container is a \
             task of a service (invariant #2), and the attachment API is deferred",
        );
    }
    if body.config_only {
        return unsupported("ConfigOnly", "SatL has no configuration-only networks");
    }
    if body
        .config_from
        .as_ref()
        .is_some_and(|from| !from.network.trim().is_empty())
    {
        return unsupported(
            "ConfigFrom",
            "SatL has no configuration-only networks to inherit from",
        );
    }
    let driver = network_driver(body.driver.as_deref().unwrap_or("bridge"))?;
    let encrypted = driver_options(&body.options, driver)?;
    if body.ingress && encrypted {
        return Err(BackendError::invalid(
            "driver option \"encrypted\" cannot be set on the ingress network: ingress \
             assignments go to every node, so the network's keyring would be shipped \
             cluster-wide instead of to participants only",
        ));
    }
    if let Some(scope) = body
        .scope
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        // Docker derives the scope from the driver and so does SatL; a request
        // that contradicts the driver would silently get the other one.
        let expected = match driver {
            NetworkDriver::Overlay => "swarm",
            NetworkDriver::Bridge => "local",
        };
        if scope != expected {
            return Err(BackendError::invalid(format!(
                "invalid scope {scope:?}: the scope follows the driver, which implies \
                 {expected:?}"
            )));
        }
    }

    let ipam = body.ipam.map(ipam_config).transpose()?.flatten();

    Ok(NetworkSpec {
        annotations: Annotations {
            name: name.to_owned(),
            labels: body.labels,
        },
        driver,
        ipam,
        internal: false,
        attachable: false,
        ingress: body.ingress,
        encrypted,
    })
}

/// The driver `Options` map of a create body → whether the network is
/// encrypted. SatL reads exactly one option: `encrypted`, Docker's spelling
/// of `--opt encrypted` (`"true"` encrypts, `"false"` — Docker's own no-op —
/// does not), and only on the overlay driver: encryption wraps the VXLAN
/// datagrams between nodes, and a bridge network never leaves its node.
/// Every other key stays a 400, as before: an option SatL would store and
/// never read hands the operator a network that is not the one they asked for.
fn driver_options(options: &BTreeMap<String, String>, driver: NetworkDriver) -> Result<bool> {
    let rejected: Vec<&str> = options
        .keys()
        .filter(|key| key.as_str() != "encrypted")
        .map(String::as_str)
        .collect();
    if !rejected.is_empty() {
        return Err(BackendError::invalid(format!(
            "driver options are not supported by SatL: {} would be stored and never read \
             (the only driver option SatL reads is \"encrypted\")",
            rejected.join(", ")
        )));
    }
    let encrypted = match options.get("encrypted").map(String::as_str) {
        None | Some("false") => false,
        Some("true") => true,
        Some(other) => {
            return Err(BackendError::invalid(format!(
                "invalid driver option \"encrypted\"={other:?}: expected \"true\" or \"false\""
            )));
        }
    };
    if encrypted && driver != NetworkDriver::Overlay {
        return Err(BackendError::invalid(
            "driver option \"encrypted\" requires the overlay driver: encryption wraps the \
             VXLAN datagrams between nodes; a bridge network never leaves its node",
        ));
    }
    Ok(encrypted)
}

/// Docker's `IPAM` → [`satl_core::IpamConfig`]; `None` when nothing was asked
/// for and the allocator is free to choose.
fn ipam_config(body: IpamWire) -> Result<Option<IpamConfig>> {
    let driver = body.driver.trim();
    if !driver.is_empty() && driver != "default" {
        return Err(BackendError::invalid(format!(
            "invalid IPAM driver {driver:?}: SatL has one address allocator, in the Raft \
             store (architecture section 11.3)"
        )));
    }
    if !body.options.is_empty() {
        return unsupported("IPAM.Options", "SatL's allocator reads no driver options");
    }
    if body.config.len() > 1 {
        return Err(BackendError::invalid(format!(
            "IPAM.Config has {} entries: a SatL network has exactly one subnet",
            body.config.len()
        )));
    }
    let Some(entry) = body.config.into_iter().next() else {
        return Ok(None);
    };
    let subnet = ipv4_cidr(&entry.subnet, "IPAM.Config.Subnet")?;
    let ip_range = ipv4_cidr(&entry.ip_range, "IPAM.Config.IPRange")?;
    let gateway = non_empty(&entry.gateway)
        .map(|value| {
            value
                .parse::<std::net::Ipv4Addr>()
                .map(|addr| addr.to_string())
                .map_err(|_| {
                    BackendError::invalid(format!(
                        "invalid IPAM.Config.Gateway {value:?}: expected an IPv4 address"
                    ))
                })
        })
        .transpose()?;
    if subnet.is_none() && (ip_range.is_some() || gateway.is_some()) {
        return Err(BackendError::invalid(
            "invalid IPAM.Config: an IPRange or a Gateway without a Subnet has nothing to \
             be inside of",
        ));
    }
    Ok(Some(IpamConfig {
        subnet,
        gateway,
        ip_range,
    }))
}

/// An optional IPv4 CIDR field, rejecting IPv6 explicitly rather than as a
/// parse failure — an operator who typed an IPv6 prefix wants to know why.
fn ipv4_cidr(value: &str, field: &str) -> Result<Option<String>> {
    let Some(value) = non_empty(value) else {
        return Ok(None);
    };
    if value.contains(':') {
        return Err(BackendError::invalid(format!(
            "invalid {field} {value:?}: SatL's IPAM and overlay data plane are IPv4-only in v1"
        )));
    }
    let cidr: Ipv4Cidr = value
        .parse()
        .map_err(|err| BackendError::invalid(format!("invalid {field} {value:?}: {err}")))?;
    Ok(Some(cidr.to_string()))
}

/// `POST /networks/{id}/connect` body → connect options.
pub fn network_connect(body: NetworkConnectBody) -> Result<NetworkConnectOptions> {
    let container = body.container.trim();
    if container.is_empty() {
        return Err(BackendError::invalid(
            "invalid parameter: Container is required to attach to a network",
        ));
    }
    let config = body.endpoint_config.unwrap_or_default();
    if config
        .ipam_config
        .as_ref()
        .is_some_and(|value| !value.is_null())
    {
        return unsupported(
            "EndpointConfig.IPAMConfig",
            "addresses on a SatL network come from the cluster allocator, not from the \
             client (architecture section 11.3)",
        );
    }
    if !config.links.is_empty() {
        return unsupported("EndpointConfig.Links", "SatL has no container links");
    }
    if !config.driver_opts.is_empty() {
        return unsupported(
            "EndpointConfig.DriverOpts",
            "SatL reads no per-endpoint driver options",
        );
    }
    Ok(NetworkConnectOptions {
        container: container.to_owned(),
        aliases: config.aliases,
    })
}

/// `POST /networks/{id}/disconnect` body → disconnect options.
pub fn network_disconnect(body: &NetworkDisconnectBody) -> Result<NetworkDisconnectOptions> {
    let container = body.container.trim();
    if container.is_empty() {
        return Err(BackendError::invalid(
            "invalid parameter: Container is required to detach from a network",
        ));
    }
    Ok(NetworkDisconnectOptions {
        container: container.to_owned(),
        force: body.force,
    })
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

/// Docker's `ServiceSpec` → [`satl_core::ServiceSpec`].
///
/// An empty `Name` is accepted and asks the daemon to generate one, the way
/// `POST /containers/create` does without `?name=`.
pub fn service_spec(body: ServiceSpecWire) -> Result<ServiceSpec> {
    let name = body.name.trim();
    if !name.is_empty() {
        naming::validate_service_name(name).map_err(|err| {
            BackendError::invalid(format!("invalid service name {name:?}: {err}"))
        })?;
    }

    let mut task = task_spec(body.task_template)?;
    if task.networks.is_empty() && !body.networks.is_empty() {
        // Docker's deprecated service-level `Networks`; the daemon folds it
        // into the task template.
        task.networks = body
            .networks
            .into_iter()
            .map(|network| satl_core::NetworkAttachmentConfig {
                target: network.target,
                aliases: network.aliases,
            })
            .collect();
    }

    let mode = service_mode(body.mode)?;
    job_restart_policy(&mode, &mut task)?;

    Ok(ServiceSpec {
        annotations: Annotations {
            name: name.to_owned(),
            labels: body.labels,
        },
        task,
        mode,
        update: body.update_config.as_ref().map(update_config).transpose()?,
        rollback: body
            .rollback_config
            .as_ref()
            .map(update_config)
            .transpose()?,
        endpoint: body.endpoint_spec.map(endpoint_spec).transpose()?,
    })
}

/// Docker's `Mode` → [`ServiceMode`]; the default is one replica.
fn service_mode(mode: ServiceModeWire) -> Result<ServiceMode> {
    let set = [
        mode.replicated.is_some(),
        mode.global.is_some(),
        mode.replicated_job.is_some(),
        mode.global_job.is_some(),
    ];
    if set.iter().filter(|set| **set).count() > 1 {
        return Err(BackendError::invalid(
            "invalid parameter: Mode must set exactly one of Replicated, Global, ReplicatedJob, GlobalJob",
        ));
    }
    if let Some(job) = mode.replicated_job {
        if job.max_concurrent == Some(0) || job.total_completions == Some(0) {
            return Err(BackendError::invalid(
                "invalid parameter: ReplicatedJob MaxConcurrent and TotalCompletions must be at least 1",
            ));
        }
        return Ok(ServiceMode::ReplicatedJob {
            max_concurrent: job.max_concurrent,
            total_completions: job.total_completions,
        });
    }
    if mode.global_job.is_some() {
        return Ok(ServiceMode::GlobalJob);
    }
    match (mode.replicated, mode.global) {
        (Some(_), Some(_)) => Err(BackendError::invalid(
            "invalid parameter: Mode must set exactly one of Replicated, Global, ReplicatedJob, GlobalJob",
        )),
        (None, Some(_)) => Ok(ServiceMode::Global),
        (replicated, None) => Ok(ServiceMode::Replicated {
            replicas: replicated.and_then(|mode| mode.replicas).unwrap_or(1),
        }),
    }
}

/// Jobs force `on-failure` restart semantics (SWK §3.4: a job's task runs to
/// completion, so "restart it when it exits 0" is a contradiction): `none`
/// is rejected, and `any` is read as `on-failure` — which for a job is the
/// same promise, since a clean exit is what the job is waiting for.
fn job_restart_policy(mode: &ServiceMode, task: &mut TaskSpec) -> Result<()> {
    if !mode.is_job() {
        return Ok(());
    }
    match task.restart.condition {
        RestartCondition::None => Err(BackendError::invalid(
            "invalid parameter: restart condition \"none\" is not valid for a job: \
             failed tasks are retried (on-failure semantics are forced)",
        )),
        RestartCondition::Any => {
            task.restart.condition = RestartCondition::OnFailure;
            Ok(())
        }
        RestartCondition::OnFailure => Ok(()),
    }
}

/// Docker's `TaskTemplate` → [`TaskSpec`].
fn task_spec(template: TaskTemplateWire) -> Result<TaskSpec> {
    if !template.runtime.is_empty() && template.runtime != TASK_RUNTIME {
        return Err(BackendError::invalid(format!(
            "unknown task runtime {:?}: SatL runs containers as jails only",
            template.runtime
        )));
    }
    if template
        .log_driver
        .as_ref()
        .is_some_and(|driver| !driver.is_null())
    {
        return unsupported(
            "TaskTemplate.LogDriver",
            "per-service log drivers are not supported: a task's logs are its captured stdio",
        );
    }

    Ok(TaskSpec {
        container: container_spec(template.container_spec)?,
        resources: resources(template.resources)?,
        restart: restart_policy(template.restart_policy)?,
        placement: placement(template.placement)?,
        networks: template
            .networks
            .into_iter()
            .map(|network| satl_core::NetworkAttachmentConfig {
                target: network.target,
                aliases: network.aliases,
            })
            .collect(),
        force_update: template.force_update,
    })
}

/// Docker's `ContainerSpec` → [`satl_core::ContainerSpec`].
fn container_spec(spec: ContainerSpecWire) -> Result<ContainerSpec> {
    if spec.image.trim().is_empty() {
        return Err(BackendError::invalid("no image specified"));
    }
    if spec
        .privileges
        .as_ref()
        .is_some_and(|value| !value.is_null() && value != &serde_json::json!({}))
    {
        return unsupported(
            "ContainerSpec.Privileges",
            "credential specs and SELinux contexts do not exist on FreeBSD",
        );
    }
    if spec.init == Some(true) {
        return unsupported(
            "ContainerSpec.Init",
            "SatL does not inject an init process into jails",
        );
    }
    if !spec.isolation.is_empty() && spec.isolation != "default" {
        return unsupported(
            "ContainerSpec.Isolation",
            "isolation modes are a Windows concept",
        );
    }
    if !spec.sysctls.is_empty() {
        return unsupported(
            "ContainerSpec.Sysctls",
            "per-jail sysctls are not configurable",
        );
    }
    if !spec.capability_add.is_empty() || !spec.capability_drop.is_empty() {
        return unsupported(
            "ContainerSpec.CapabilityAdd/CapabilityDrop",
            "Linux capabilities do not exist on FreeBSD",
        );
    }
    if !spec.ulimits.is_empty() {
        return unsupported(
            "ContainerSpec.Ulimits",
            "use Resources.Limits, which map to rctl(8) rules",
        );
    }

    Ok(ContainerSpec {
        image: spec.image.trim().to_owned(),
        labels: spec.labels,
        command: spec.command,
        args: spec.args,
        hostname: non_empty(&spec.hostname),
        env: spec.env,
        dir: non_empty(&spec.dir),
        user: non_empty(&spec.user),
        groups: spec.groups,
        tty: spec.tty,
        open_stdin: spec.open_stdin,
        read_only: spec.read_only,
        stop_signal: non_empty(&spec.stop_signal),
        stop_grace_period: (spec.stop_grace_period != 0)
            .then(|| duration(spec.stop_grace_period, "ContainerSpec.StopGracePeriod"))
            .transpose()?,
        healthcheck: spec.healthcheck.map(healthcheck).transpose()?,
        hosts: spec.hosts,
        dns_config: spec.dns_config.map(|dns| DnsConfig {
            nameservers: dns.nameservers,
            search: dns.search,
            options: dns.options,
        }),
        mounts: spec
            .mounts
            .into_iter()
            .map(mount)
            .collect::<Result<Vec<_>>>()?,
        secrets: secret_references(spec.secrets)?,
        configs: config_references(spec.configs)?,
        pull_options: None,
        // Filled by the daemon once the manifest is resolved (architecture §9).
        platform: None,
    })
}

/// Docker's `Healthcheck` → [`HealthConfig`].
fn healthcheck(check: HealthcheckWire) -> Result<HealthConfig> {
    Ok(HealthConfig {
        test: check.test,
        interval: (check.interval != 0)
            .then(|| duration(check.interval, "Healthcheck.Interval"))
            .transpose()?,
        timeout: (check.timeout != 0)
            .then(|| duration(check.timeout, "Healthcheck.Timeout"))
            .transpose()?,
        retries: check.retries,
        start_period: (check.start_period != 0)
            .then(|| duration(check.start_period, "Healthcheck.StartPeriod"))
            .transpose()?,
    })
}

/// One Docker `Mounts` entry → a [`Mount`].
fn mount(mount: MountWire) -> Result<Mount> {
    if !mount.consistency.is_empty() {
        return unsupported(
            "Mounts.Consistency",
            "nullfs has no consistency modes on FreeBSD",
        );
    }
    if mount.bind_options.is_some()
        || mount.volume_options.is_some()
        || mount.tmpfs_options.is_some()
    {
        return unsupported(
            "Mounts.BindOptions/VolumeOptions/TmpfsOptions",
            "mount propagation and driver options are not configurable",
        );
    }
    let kind = match mount.kind.as_str() {
        "" | "volume" => MountType::Volume,
        "bind" => MountType::Bind,
        "tmpfs" => MountType::Tmpfs,
        other => {
            return Err(BackendError::invalid(format!(
                "invalid mount type {other:?}: SatL supports bind, volume and tmpfs"
            )));
        }
    };
    if !mount.target.starts_with('/') {
        return Err(BackendError::invalid(format!(
            "invalid mount target {:?}: the destination must be an absolute path",
            mount.target
        )));
    }
    if kind == MountType::Bind && mount.source.is_empty() {
        return Err(BackendError::invalid(
            "invalid bind mount: the source is empty",
        ));
    }
    Ok(Mount {
        kind,
        source: non_empty(&mount.source),
        target: mount.target,
        read_only: mount.read_only,
    })
}

/// Docker's `Resources` → [`ResourceRequirements`].
fn resources(requirements: Option<ResourceRequirementsWire>) -> Result<ResourceRequirements> {
    let Some(requirements) = requirements else {
        return Ok(ResourceRequirements::default());
    };
    let limits = match requirements.limits {
        None => None,
        Some(limits) => {
            if limits.pids > 0 {
                return unsupported(
                    "Resources.Limits.Pids",
                    "process caps are not mapped to rctl(8)",
                );
            }
            Some(Resources {
                nano_cpus: limits.nano_cpus,
                memory_bytes: limits.memory_bytes,
            })
        }
    };
    Ok(ResourceRequirements {
        limits,
        reservations: requirements.reservations.map(|reservations| Resources {
            nano_cpus: reservations.nano_cpus,
            memory_bytes: reservations.memory_bytes,
        }),
    })
}

/// Docker's task `RestartPolicy` → [`RestartPolicy`]; an absent policy is
/// SwarmKit's default (`any`, 5 s).
fn restart_policy(policy: Option<TaskRestartPolicyWire>) -> Result<RestartPolicy> {
    let Some(policy) = policy else {
        return Ok(RestartPolicy::default());
    };
    let condition = match policy.condition.as_str() {
        "" | "any" => RestartCondition::Any,
        "none" => RestartCondition::None,
        "on-failure" => RestartCondition::OnFailure,
        other => {
            return Err(BackendError::invalid(format!(
                "invalid restart condition {other:?}: must be one of none, on-failure, any"
            )));
        }
    };
    // Docker fills an absent Delay with 5 s even when the rest of the policy
    // is present (SWK §3.9). The wire carries a plain i64, so an explicit 0
    // is indistinguishable from absent and gets the default too — zero-delay
    // restarts are not expressible (api-compat 153).
    let delay = if policy.delay == 0 {
        satl_core::defaults::RESTART_DELAY
    } else {
        duration(policy.delay, "RestartPolicy.Delay")?
    };
    Ok(RestartPolicy {
        condition,
        delay,
        max_attempts: policy.max_attempts,
        window: duration(policy.window, "RestartPolicy.Window")?,
    })
}

/// The descriptor forms a spread preference can group by. Anything else is a
/// 400 — an unknown descriptor would group every node under one empty value
/// and spread nothing, silently.
fn validate_spread_descriptor(descriptor: &str) -> Result<()> {
    const FIXED: [&str; 2] = ["node.id", "node.hostname"];
    const PREFIXES: [&str; 2] = ["node.labels.", "engine.labels."];
    let valid = FIXED.contains(&descriptor)
        || PREFIXES
            .iter()
            .any(|prefix| descriptor.len() > prefix.len() && descriptor.starts_with(prefix));
    if valid {
        return Ok(());
    }
    Err(BackendError::invalid(format!(
        "invalid spread descriptor {descriptor:?}: expected node.id, node.hostname, \
         node.labels.<key> or engine.labels.<key>"
    )))
}

/// Docker's `Placement` → [`Placement`], with every constraint parsed.
fn placement(placement: Option<PlacementWire>) -> Result<Placement> {
    let Some(placement) = placement else {
        return Ok(Placement::default());
    };
    let mut preferences = Vec::with_capacity(placement.preferences.len());
    for preference in placement.preferences {
        let Some(spread) = preference.spread else {
            return unsupported("Placement.Preferences", "only `spread` is implemented");
        };
        validate_spread_descriptor(&spread.spread_descriptor)?;
        preferences.push(satl_core::PlacementPreference {
            spread: Some(satl_core::SpreadPreference {
                spread_descriptor: spread.spread_descriptor,
            }),
        });
    }
    for expression in &placement.constraints {
        Constraint::parse(expression).map_err(|err| {
            BackendError::invalid(format!("invalid constraint {expression:?}: {err}"))
        })?;
    }
    Ok(Placement {
        constraints: placement.constraints,
        preferences,
        max_replicas: placement.max_replicas,
        platforms: placement
            .platforms
            .into_iter()
            .map(|platform| Platform {
                os: platform.os,
                arch: platform.architecture,
            })
            .collect(),
    })
}

/// Docker's `UpdateConfig` → [`UpdateConfig`].
fn update_config(config: &UpdateConfigWire) -> Result<UpdateConfig> {
    let defaults = UpdateConfig::default();
    let failure_action = match config.failure_action.as_str() {
        "" | "pause" => FailureAction::Pause,
        "continue" => FailureAction::Continue,
        "rollback" => FailureAction::Rollback,
        other => {
            return Err(BackendError::invalid(format!(
                "invalid failure action {other:?}: must be one of pause, continue, rollback"
            )));
        }
    };
    let order = match config.order.as_str() {
        "" | "stop-first" => UpdateOrder::StopFirst,
        "start-first" => UpdateOrder::StartFirst,
        other => {
            return Err(BackendError::invalid(format!(
                "invalid update order {other:?}: must be one of stop-first, start-first"
            )));
        }
    };
    if !(0.0..=1.0).contains(&config.max_failure_ratio) {
        return Err(BackendError::invalid(format!(
            "invalid max failure ratio {}: must be between 0 and 1",
            config.max_failure_ratio
        )));
    }
    Ok(UpdateConfig {
        parallelism: config.parallelism,
        delay: duration(config.delay, "UpdateConfig.Delay")?,
        failure_action,
        monitor: if config.monitor == 0 {
            defaults.monitor
        } else {
            duration(config.monitor, "UpdateConfig.Monitor")?
        },
        max_failure_ratio: config.max_failure_ratio,
        order,
    })
}

/// Docker's `EndpointSpec` → [`EndpointSpec`].
fn endpoint_spec(spec: EndpointSpecWire) -> Result<EndpointSpec> {
    match spec.mode.as_str() {
        "" | "dnsrr" => {}
        "vip" => {
            return unsupported(
                "EndpointSpec.Mode=vip",
                "FreeBSD has no IPVS; SatL resolves services with DNS round-robin \
                 (architecture section 11.5)",
            );
        }
        other => {
            return Err(BackendError::invalid(format!(
                "invalid endpoint mode {other:?}: SatL supports dnsrr"
            )));
        }
    }
    Ok(EndpointSpec {
        mode: EndpointMode::DnsRR,
        ports: spec
            .ports
            .into_iter()
            .map(port_config)
            .collect::<Result<Vec<_>>>()?,
    })
}

/// One Docker `PortConfig` → a [`PortConfig`].
fn port_config(port: PortConfigWire) -> Result<PortConfig> {
    let protocol = match port.protocol.as_str() {
        "" | "tcp" => PortProtocol::Tcp,
        "udp" => PortProtocol::Udp,
        other => {
            return Err(BackendError::invalid(format!(
                "invalid port protocol {other:?}: SatL supports tcp and udp"
            )));
        }
    };
    let publish_mode = match port.publish_mode.as_str() {
        "" | "ingress" => PublishMode::Ingress,
        "host" => PublishMode::Host,
        other => {
            return Err(BackendError::invalid(format!(
                "invalid publish mode {other:?}: must be one of ingress, host"
            )));
        }
    };
    let target_port = port_number(port.target_port, "TargetPort")?;
    if target_port == 0 {
        return Err(BackendError::invalid(
            "invalid TargetPort: port 0 is not a valid target port",
        ));
    }
    Ok(PortConfig {
        name: port.name,
        protocol,
        target_port,
        published_port: port_number(port.published_port, "PublishedPort")?,
        publish_mode,
    })
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

/// Docker's `?filters=` JSON → [`TaskFilters`].
///
/// Both encodings Docker's daemon accepts are understood: the modern map form
/// `{"service":{"web":true}}` that `filters.Args` marshals, and the legacy
/// list form `{"service":["web"]}`.
pub fn task_filters(raw: Option<&str>) -> Result<TaskFilters> {
    let Some(raw) = raw else {
        return Ok(TaskFilters::default());
    };
    let parsed: BTreeMap<String, serde_json::Value> = serde_json::from_str(raw)
        .map_err(|err| BackendError::invalid(format!("invalid filters {raw:?}: {err}")))?;

    let mut filters = TaskFilters::default();
    for (key, value) in parsed {
        let values = filter_values(&key, &value)?;
        match key.as_str() {
            "id" => filters.ids = values,
            "name" => filters.names = values,
            "service" => filters.services = values,
            "node" => filters.nodes = values,
            "desired-state" => {
                filters.desired_states = values
                    .iter()
                    .map(|value| desired_state(value))
                    .collect::<Result<Vec<_>>>()?;
            }
            "label" => {
                for value in values {
                    let (key, value) = match value.split_once('=') {
                        Some((key, value)) => (key.to_owned(), Some(value.to_owned())),
                        None => (value, None),
                    };
                    filters.labels.insert(key, value);
                }
            }
            other => {
                return Err(BackendError::invalid(format!(
                    "invalid filter {other:?}: SatL supports id, name, service, node, \
                     desired-state and label on tasks"
                )));
            }
        }
    }
    Ok(filters)
}

/// The values of one filter key, in either of Docker's two encodings.
fn filter_values(key: &str, value: &serde_json::Value) -> Result<Vec<String>> {
    let invalid = || {
        BackendError::invalid(format!(
            "invalid filter {key:?}: expected a list of values or a value/flag map"
        ))
    };
    match value {
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or_else(invalid))
            .collect(),
        serde_json::Value::Object(map) => Ok(map
            .iter()
            .filter(|(_, enabled)| enabled.as_bool() != Some(false))
            .map(|(value, _)| value.clone())
            .collect()),
        _ => Err(invalid()),
    }
}

/// Docker's desired-state filter value → [`DesiredState`].
fn desired_state(value: &str) -> Result<DesiredState> {
    match value {
        "ready" => Ok(DesiredState::Ready),
        "running" => Ok(DesiredState::Running),
        "complete" => Ok(DesiredState::Complete),
        "shutdown" => Ok(DesiredState::Shutdown),
        "remove" => Ok(DesiredState::Remove),
        other => Err(BackendError::invalid(format!(
            "invalid desired-state filter {other:?}: must be one of ready, running, \
             complete, shutdown, remove"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Secrets / configs
// ---------------------------------------------------------------------------
//
// Two rules run through this whole section. First: **an error never quotes a
// payload.** A rejection names the secret, its size or its target, never a byte
// of `Data` — a 400 body is written to the client's terminal and to the
// daemon's log. Second: what SatL cannot honour is refused, not dropped, which
// for secrets is not merely tidiness — silently ignoring `Driver` would store
// the payload of a secret the operator believes lives in an external store.

/// Where a secret's file target is materialized on the worker (invariant #7:
/// tmpfs only). Named here because the refusal message has to say it.
const SECRET_MOUNTPOINT: &str = "/run/secrets";

/// Largest permission bit pattern a file target may carry (`0o7777`).
const MAX_FILE_MODE: u32 = 0o7777;

/// `POST /secrets/create` body → [`SecretSpec`].
pub fn secret_spec(wire: SecretSpecWire) -> Result<SecretSpec> {
    let name = wire.name.trim().to_owned();
    naming::validate_secret_name(&name)
        .map_err(|err| BackendError::invalid(format!("invalid secret name: {err}")))?;
    if is_set(wire.driver.as_ref()) {
        return unsupported(
            "SecretSpec.Driver",
            "secret drivers are not supported; SatL keeps every payload in its own store",
        );
    }
    reject_templating("secret", wire.templating.as_ref())?;
    let data = payload("secret", wire.data.as_deref())?;
    SecretSpec::new(annotations(name.clone(), wire.labels), data)
        .map_err(|err| BackendError::invalid(format!("invalid secret {name}: {err}")))
}

/// `POST /configs/create` body → [`ConfigSpec`].
pub fn config_spec(wire: ConfigSpecWire) -> Result<ConfigSpec> {
    let name = wire.name.trim().to_owned();
    naming::validate_config_name(&name)
        .map_err(|err| BackendError::invalid(format!("invalid config name: {err}")))?;
    reject_templating("config", wire.templating.as_ref())?;
    let data = payload("config", wire.data.as_deref())?;
    ConfigSpec::new(annotations(name.clone(), wire.labels), data)
        .map_err(|err| BackendError::invalid(format!("invalid config {name}: {err}")))
}

/// Name + labels of a secret/config spec.
fn annotations(name: String, labels: BTreeMap<String, String>) -> Annotations {
    Annotations { name, labels }
}

/// Whether an opaque Docker member was really filled in (`null` and `{}` both
/// mean "the client's struct was zero", which every Go marshaller emits).
fn is_set(value: Option<&serde_json::Value>) -> bool {
    value.is_some_and(|value| !value.is_null() && value != &serde_json::json!({}))
}

/// Refuses a `Templating` driver: SatL has no template engine, and a config
/// whose `{{ }}` placeholders were never expanded is a broken config file
/// delivered as if it were correct.
fn reject_templating(kind: &str, value: Option<&serde_json::Value>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let driver = ["Name", "name"]
        .iter()
        .find_map(|key| value.get(key))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if driver.is_empty() {
        return Ok(());
    }
    Err(BackendError::invalid(format!(
        "Templating is not supported by SatL: {kind} templating is not supported (driver \
         {driver:?}); render the payload before creating the {kind}"
    )))
}

/// The base64 `Data` member of a secret/config spec, decoded.
///
/// Never echoes the value: a malformed payload is still a payload.
fn payload(kind: &str, data: Option<&str>) -> Result<Vec<u8>> {
    let Some(data) = data.map(str::trim).filter(|data| !data.is_empty()) else {
        return Err(BackendError::invalid(format!(
            "{kind} data is required and must be base64"
        )));
    };
    crate::convert::decode_base64(data).ok_or_else(|| {
        BackendError::invalid(format!(
            "invalid {kind} data: expected a base64-encoded payload"
        ))
    })
}

/// Docker's `ContainerSpec.Secrets` → [`SecretReference`]s.
fn secret_references(wires: Vec<SecretReferenceWire>) -> Result<Vec<SecretReference>> {
    let mut references: Vec<SecretReference> = Vec::with_capacity(wires.len());
    for wire in wires {
        let name = wire.secret_name.trim().to_owned();
        if name.is_empty() {
            return Err(BackendError::invalid(
                "invalid secret reference: SecretName is required",
            ));
        }
        let file = file_target("secret", &name, wire.file, false)?;
        if references.iter().any(|other| other.file.name == file.name) {
            return Err(BackendError::invalid(format!(
                "duplicate secret target {}: two secrets cannot be materialized at the same path",
                file.name
            )));
        }
        references.push(SecretReference {
            secret_id: reference_id("secret", &name, &wire.secret_id)?,
            secret_name: name,
            file,
        });
    }
    Ok(references)
}

/// Docker's `ContainerSpec.Configs` → [`ConfigReference`]s.
fn config_references(wires: Vec<ConfigReferenceWire>) -> Result<Vec<ConfigReference>> {
    let mut references: Vec<ConfigReference> = Vec::with_capacity(wires.len());
    for wire in wires {
        let name = wire.config_name.trim().to_owned();
        if name.is_empty() {
            return Err(BackendError::invalid(
                "invalid config reference: ConfigName is required",
            ));
        }
        let file = file_target("config", &name, wire.file, true)?;
        if references.iter().any(|other| other.file.name == file.name) {
            return Err(BackendError::invalid(format!(
                "duplicate config target {}: two configs cannot be materialized at the same path",
                file.name
            )));
        }
        references.push(ConfigReference {
            config_id: reference_id("config", &name, &wire.config_id)?,
            config_name: name,
            file,
        });
    }
    Ok(references)
}

/// The referenced object's ID, which is required and must be well-formed.
///
/// References are resolved **by ID**, as SwarmKit's are: the client turns a
/// name into an ID first (the Docker CLI lists `/secrets` to do it, and so does
/// `satl`), which is what makes a reference survive a secret being removed and
/// recreated under the same name — the service then names an ID that no longer
/// exists, instead of silently binding to a different payload.
fn reference_id(kind: &str, name: &str, id: &str) -> Result<Id> {
    let id = id.trim();
    if id.is_empty() {
        return Err(BackendError::invalid(format!(
            "{kind} reference {name}: {}ID is required (resolve the name to an ID first, as the \
             docker CLI does)",
            capitalize(kind)
        )));
    }
    id.parse::<Id>()
        .map_err(|err| BackendError::invalid(format!("invalid {kind} reference {name}: {err}")))
}

/// `"secret"` → `"Secret"`, for the Docker field name in a refusal.
fn capitalize(kind: &str) -> String {
    let mut chars = kind.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Docker's `File` → [`FileTarget`], with Docker's own defaults for an omitted
/// one (`root:root`, mode `0444`, file named after the object).
///
/// `allow_absolute` is the one place secrets and configs differ: a secret
/// always lands under [`SECRET_MOUNTPOINT`] (invariant #7), so an absolute
/// target is a request SatL cannot honour rather than one it can reinterpret.
fn file_target(
    kind: &str,
    object: &str,
    wire: Option<FileTargetWire>,
    allow_absolute: bool,
) -> Result<FileTarget> {
    let wire = wire.unwrap_or_default();
    let name = match wire.name.trim() {
        "" => object.to_owned(),
        name => name.to_owned(),
    };
    if name.is_empty() {
        return Err(BackendError::invalid(format!(
            "invalid {kind} target: File.Name is empty"
        )));
    }
    if name.starts_with('/') && !allow_absolute {
        return Err(BackendError::invalid(format!(
            "invalid secret target {name}: secret target must be a relative path; secrets are \
             mounted under {SECRET_MOUNTPOINT}"
        )));
    }
    if name.split('/').any(|component| component == "..") {
        return Err(BackendError::invalid(format!(
            "invalid {kind} target {name}: a target path may not contain \"..\""
        )));
    }
    if wire.mode > MAX_FILE_MODE {
        return Err(BackendError::invalid(format!(
            "invalid {kind} target {name}: mode {} is not a permission bit pattern (at most \
             {MAX_FILE_MODE:#o}, i.e. {MAX_FILE_MODE} in decimal)",
            wire.mode
        )));
    }
    Ok(FileTarget {
        name,
        uid: numeric_owner(&wire.uid),
        gid: numeric_owner(&wire.gid),
        mode: wire.mode,
    })
}

/// A file target's `UID`/`GID`: `root` (`"0"`) when the client sent none.
///
/// The value is *not* checked to be numeric here — a name is refused by the
/// node that materializes the file, where the failure names the task
/// (`docs/api-compat.md`).
fn numeric_owner(value: &str) -> String {
    match value.trim() {
        "" => "0".to_owned(),
        value => value.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn spec(json: serde_json::Value) -> ServiceSpecWire {
        serde_json::from_value(json).expect("test spec must deserialize")
    }

    #[test]
    fn a_spread_preference_converts() {
        let converted = service_spec(spec(serde_json::json!({"Name": "web",
            "TaskTemplate": {
                "ContainerSpec": {"Image": "n"},
                "Placement": {"Preferences": [
                    {"Spread": {"SpreadDescriptor": "node.labels.zone"}}]}}})))
        .expect("a spread preference converts");
        assert_eq!(
            converted.task.placement.preferences,
            [satl_core::PlacementPreference {
                spread: Some(satl_core::SpreadPreference {
                    spread_descriptor: "node.labels.zone".to_owned(),
                }),
            }]
        );
    }

    /// One spec exercising every conversion at once; splitting it would only
    /// hide which field broke.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn full_service_spec_maps_to_core() {
        let converted = service_spec(spec(serde_json::json!({
            "Name": "web",
            "Labels": {"tier": "front"},
            "TaskTemplate": {
                "ContainerSpec": {
                    "Image": "nginx:1.27",
                    "Labels": {"role": "web"},
                    "Command": ["/usr/local/bin/entry"],
                    "Args": ["nginx", "-g", "daemon off;"],
                    "Hostname": "web-1",
                    "Env": ["RUST_LOG=info"],
                    "Dir": "/srv",
                    "User": "www",
                    "Groups": ["www"],
                    "TTY": false,
                    "OpenStdin": false,
                    "ReadOnly": true,
                    "StopSignal": "SIGQUIT",
                    "StopGracePeriod": 15_000_000_000_i64,
                    "Healthcheck": {
                        "Test": ["CMD-SHELL", "curl -f localhost"],
                        "Interval": 5_000_000_000_i64,
                        "Timeout": 2_000_000_000_i64,
                        "Retries": 3,
                        "StartPeriod": 10_000_000_000_i64
                    },
                    "Hosts": ["10.0.0.1 gateway"],
                    "DNSConfig": {"Nameservers": ["10.0.0.53"]},
                    "Mounts": [
                        {"Type": "bind", "Source": "/host", "Target": "/data", "ReadOnly": true},
                        {"Type": "volume", "Source": "assets", "Target": "/srv/assets"},
                        {"Type": "tmpfs", "Target": "/run"}
                    ]
                },
                "Resources": {
                    "Limits": {"NanoCPUs": 1_500_000_000_i64, "MemoryBytes": 536_870_912_i64},
                    "Reservations": {"NanoCPUs": 500_000_000_i64, "MemoryBytes": 134_217_728_i64}
                },
                "RestartPolicy": {
                    "Condition": "on-failure",
                    "Delay": 5_000_000_000_i64,
                    "MaxAttempts": 3,
                    "Window": 60_000_000_000_i64
                },
                "Placement": {
                    "Constraints": ["node.labels.zone == a"],
                    "MaxReplicas": 2,
                    "Platforms": [{"Architecture": "amd64", "OS": "freebsd"}]
                },
                "Networks": [{"Target": "backend", "Aliases": ["app"]}],
                "ForceUpdate": 4,
                "Runtime": "container"
            },
            "Mode": {"Replicated": {"Replicas": 3}},
            "UpdateConfig": {
                "Parallelism": 2,
                "Delay": 10_000_000_000_i64,
                "FailureAction": "rollback",
                "Monitor": 20_000_000_000_i64,
                "MaxFailureRatio": 0.25,
                "Order": "start-first"
            },
            "EndpointSpec": {
                "Mode": "dnsrr",
                "Ports": [{
                    "Name": "http", "Protocol": "tcp", "TargetPort": 80,
                    "PublishedPort": 8080, "PublishMode": "ingress"
                }]
            }
        })))
        .expect("valid spec");

        assert_eq!(converted.annotations.name, "web");
        assert_eq!(converted.annotations.labels["tier"], "front");
        assert_eq!(converted.mode, ServiceMode::Replicated { replicas: 3 });

        let container = &converted.task.container;
        assert_eq!(container.image, "nginx:1.27");
        assert_eq!(container.command, ["/usr/local/bin/entry"]);
        assert_eq!(container.args, ["nginx", "-g", "daemon off;"]);
        assert_eq!(container.hostname.as_deref(), Some("web-1"));
        assert_eq!(container.dir.as_deref(), Some("/srv"));
        assert_eq!(container.user.as_deref(), Some("www"));
        assert!(container.read_only);
        assert_eq!(container.stop_signal.as_deref(), Some("SIGQUIT"));
        assert_eq!(container.stop_grace_period, Some(Duration::from_secs(15)));
        let health = container.healthcheck.as_ref().expect("healthcheck");
        assert_eq!(health.interval, Some(Duration::from_secs(5)));
        assert_eq!(health.retries, 3);
        assert_eq!(
            container.dns_config.as_ref().expect("dns").nameservers,
            ["10.0.0.53"]
        );
        assert_eq!(container.mounts.len(), 3);
        assert_eq!(container.mounts[0].kind, MountType::Bind);
        assert!(container.mounts[0].read_only);
        assert_eq!(container.mounts[1].kind, MountType::Volume);
        assert_eq!(container.mounts[1].source.as_deref(), Some("assets"));
        assert_eq!(container.mounts[2].kind, MountType::Tmpfs);
        assert_eq!(container.mounts[2].source, None);

        let limits = converted.task.resources.limits.expect("limits");
        assert_eq!(limits.nano_cpus, 1_500_000_000);
        assert_eq!(limits.memory_bytes, 536_870_912);
        assert_eq!(
            converted
                .task
                .resources
                .reservations
                .expect("res")
                .nano_cpus,
            500_000_000
        );

        assert_eq!(
            converted.task.restart.condition,
            RestartCondition::OnFailure
        );
        assert_eq!(converted.task.restart.delay, Duration::from_secs(5));
        assert_eq!(converted.task.restart.max_attempts, 3);
        assert_eq!(converted.task.restart.window, Duration::from_mins(1));

        assert_eq!(
            converted.task.placement.constraints,
            ["node.labels.zone == a"]
        );
        assert_eq!(converted.task.placement.max_replicas, 2);
        assert_eq!(converted.task.placement.platforms[0].os, "freebsd");
        assert_eq!(converted.task.networks[0].target, "backend");
        assert_eq!(converted.task.force_update, 4);

        let update = converted.update.expect("update config");
        assert_eq!(update.parallelism, 2);
        assert_eq!(update.delay, Duration::from_secs(10));
        assert_eq!(update.failure_action, FailureAction::Rollback);
        assert_eq!(update.monitor, Duration::from_secs(20));
        assert!((update.max_failure_ratio - 0.25).abs() < f32::EPSILON);
        assert_eq!(update.order, UpdateOrder::StartFirst);

        let endpoint = converted.endpoint.expect("endpoint spec");
        assert_eq!(endpoint.mode, EndpointMode::DnsRR);
        assert_eq!(endpoint.ports[0].target_port, 80);
        assert_eq!(endpoint.ports[0].published_port, 8080);
        assert_eq!(endpoint.ports[0].publish_mode, PublishMode::Ingress);
    }

    #[test]
    fn minimal_service_spec_uses_swarmkit_defaults() {
        let converted = service_spec(spec(serde_json::json!({
            "Name": "web",
            "TaskTemplate": {"ContainerSpec": {"Image": "nginx"}}
        })))
        .expect("valid spec");
        assert_eq!(converted.mode, ServiceMode::Replicated { replicas: 1 });
        assert_eq!(converted.task.restart, RestartPolicy::default());
        assert_eq!(converted.task.placement, Placement::default());
        assert_eq!(converted.update, None);
        assert_eq!(converted.endpoint, None);
        assert!(converted.task.container.platform.is_none());
    }

    /// Audit N1: a policy that names a condition but no `Delay` must still get
    /// SwarmKit's 5 s default — compose and `satl service create
    /// --restart-condition` send exactly this shape, and a 0 there crash-loops
    /// a failing service with no delay at all.
    #[test]
    fn a_policy_without_a_delay_gets_the_default() {
        for json in [
            serde_json::json!({"Condition": "on-failure"}),
            serde_json::json!({"Condition": "on-failure", "MaxAttempts": 3}),
            serde_json::json!({"Condition": "any", "Window": 60_000_000_000_i64}),
        ] {
            let policy: TaskRestartPolicyWire = serde_json::from_value(json.clone()).expect("body");
            let converted = restart_policy(Some(policy)).expect("valid policy");
            assert_eq!(
                converted.delay,
                Duration::from_secs(5),
                "for {json}: an absent Delay is the 5 s default"
            );
        }
        let converted = restart_policy(Some(
            serde_json::from_value(serde_json::json!({"Condition": "on-failure"})).expect("body"),
        ))
        .expect("valid policy");
        assert_eq!(converted.condition, RestartCondition::OnFailure);
        assert_eq!(converted.max_attempts, 0, "absent MaxAttempts is unbounded");
        assert_eq!(
            converted.window,
            Duration::ZERO,
            "absent Window is unbounded"
        );
    }

    /// An explicit `Delay` is honored as sent.
    #[test]
    fn an_explicit_restart_delay_is_honored() {
        let policy: TaskRestartPolicyWire = serde_json::from_value(
            serde_json::json!({"Condition": "on-failure", "Delay": 15_000_000_000_i64}),
        )
        .expect("body");
        let converted = restart_policy(Some(policy)).expect("valid policy");
        assert_eq!(converted.delay, Duration::from_secs(15));
    }

    /// The wire carries `Delay` as a plain i64, so `"Delay": 0` is
    /// indistinguishable from an absent one and gets the 5 s default too
    /// (api-compat 153) — zero-delay restarts are not expressible.
    #[test]
    fn an_explicit_zero_delay_is_read_as_absent() {
        let policy: TaskRestartPolicyWire =
            serde_json::from_value(serde_json::json!({"Condition": "on-failure", "Delay": 0}))
                .expect("body");
        let converted = restart_policy(Some(policy)).expect("valid policy");
        assert_eq!(converted.delay, Duration::from_secs(5));
    }

    #[test]
    fn global_mode_and_replicas_default() {
        let global = service_spec(spec(serde_json::json!({
            "Name": "agent",
            "TaskTemplate": {"ContainerSpec": {"Image": "nginx"}},
            "Mode": {"Global": {}}
        })))
        .expect("valid spec");
        assert_eq!(global.mode, ServiceMode::Global);

        let implicit = service_spec(spec(serde_json::json!({
            "Name": "web",
            "TaskTemplate": {"ContainerSpec": {"Image": "nginx"}},
            "Mode": {"Replicated": {}}
        })))
        .expect("valid spec");
        assert_eq!(implicit.mode, ServiceMode::Replicated { replicas: 1 });
    }

    #[test]
    fn service_level_networks_fold_into_the_task_template() {
        let converted = service_spec(spec(serde_json::json!({
            "Name": "web",
            "TaskTemplate": {"ContainerSpec": {"Image": "nginx"}},
            "Networks": [{"Target": "backend"}]
        })))
        .expect("valid spec");
        assert_eq!(converted.task.networks[0].target, "backend");
    }

    #[test]
    fn unsupported_service_fields_are_rejected_with_docker_messages() {
        let cases: [(serde_json::Value, &str); 15] = [
            (serde_json::json!({"Name": "web"}), "no image specified"),
            (
                serde_json::json!({"Name": "my.service",
                    "TaskTemplate": {"ContainerSpec": {"Image": "n"}}}),
                "invalid service name",
            ),
            (
                serde_json::json!({"Name": "web", "TaskTemplate": {
                    "ContainerSpec": {"Image": "n", "CapabilityAdd": ["NET_ADMIN"]}}}),
                "CapabilityAdd/CapabilityDrop is not supported",
            ),
            (
                serde_json::json!({"Name": "web", "TaskTemplate": {
                    "ContainerSpec": {"Image": "n", "Sysctls": {"a": "b"}}}}),
                "Sysctls is not supported",
            ),
            (
                serde_json::json!({"Name": "web", "TaskTemplate": {
                    "ContainerSpec": {"Image": "n", "Init": true}}}),
                "Init is not supported",
            ),
            (
                serde_json::json!({"Name": "web", "TaskTemplate": {
                    "ContainerSpec": {"Image": "n", "Isolation": "hyperv"}}}),
                "Isolation is not supported",
            ),
            (
                serde_json::json!({"Name": "web", "TaskTemplate": {
                    "ContainerSpec": {"Image": "n", "Privileges": {"SELinuxContext": {}}}}}),
                "Privileges is not supported",
            ),
            (
                serde_json::json!({"Name": "web", "TaskTemplate": {
                    "ContainerSpec": {"Image": "n", "Secrets": [{"SecretID": "x"}]}}}),
                "SecretName is required",
            ),
            (
                serde_json::json!({"Name": "web", "TaskTemplate": {
                    "ContainerSpec": {"Image": "n", "Ulimits": [{"Name": "nofile"}]}}}),
                "Ulimits is not supported",
            ),
            (
                serde_json::json!({"Name": "web", "TaskTemplate": {
                    "ContainerSpec": {"Image": "n"},
                    "Placement": {"Preferences": [{"Spread": {}}]}}}),
                "invalid spread descriptor",
            ),
            (
                serde_json::json!({"Name": "web", "TaskTemplate": {
                    "ContainerSpec": {"Image": "n"},
                    "Placement": {"Constraints": ["node.labels.zone ~~ a"]}}}),
                "invalid constraint",
            ),
            (
                serde_json::json!({"Name": "web", "TaskTemplate": {
                    "ContainerSpec": {"Image": "n"}, "Runtime": "plugin"}}),
                "unknown task runtime",
            ),
            (
                serde_json::json!({"Name": "web", "TaskTemplate": {
                    "ContainerSpec": {"Image": "n"}, "LogDriver": {"Name": "json-file"}}}),
                "LogDriver is not supported",
            ),
            (
                serde_json::json!({"Name": "web",
                    "TaskTemplate": {"ContainerSpec": {"Image": "n"}},
                    "EndpointSpec": {"Mode": "vip"}}),
                "Mode=vip is not supported",
            ),
            (
                serde_json::json!({"Name": "web", "TaskTemplate": {
                    "ContainerSpec": {"Image": "n"},
                    "Resources": {"Limits": {"Pids": 100}}}}),
                "Pids is not supported",
            ),
        ];
        for (json, expected) in cases {
            let err = service_spec(spec(json.clone())).expect_err(&format!("must reject {json}"));
            let BackendError::InvalidParameter(message) = err else {
                panic!("expected InvalidParameter for {json}");
            };
            assert!(
                message.contains(expected),
                "for {json}: message {message:?} must contain {expected:?}"
            );
        }
    }

    #[test]
    fn job_modes_convert() {
        let replicated = service_spec(spec(serde_json::json!({
            "Name": "batch",
            "TaskTemplate": {"ContainerSpec": {"Image": "n"}},
            "Mode": {"ReplicatedJob": {"MaxConcurrent": 2, "TotalCompletions": 5}},
        })))
        .expect("replicated job");
        assert_eq!(
            replicated.mode,
            ServiceMode::ReplicatedJob {
                max_concurrent: Some(2),
                total_completions: Some(5),
            }
        );

        let global = service_spec(spec(serde_json::json!({
            "Name": "sweep",
            "TaskTemplate": {"ContainerSpec": {"Image": "n"}},
            "Mode": {"GlobalJob": {}},
        })))
        .expect("global job");
        assert_eq!(global.mode, ServiceMode::GlobalJob);

        // Both knobs are optional and default to 1 at orchestration time.
        let defaults = service_spec(spec(serde_json::json!({
            "Name": "once",
            "TaskTemplate": {"ContainerSpec": {"Image": "n"}},
            "Mode": {"ReplicatedJob": {}},
        })))
        .expect("defaulted replicated job");
        assert_eq!(
            defaults.mode,
            ServiceMode::ReplicatedJob {
                max_concurrent: None,
                total_completions: None,
            }
        );
    }

    #[test]
    fn job_mode_bad_combinations_are_rejected() {
        let cases: [(serde_json::Value, &str); 3] = [
            // Two modes at once.
            (
                serde_json::json!({"Name": "web",
                    "TaskTemplate": {"ContainerSpec": {"Image": "n"}},
                    "Mode": {"Global": {}, "GlobalJob": {}}}),
                "Mode must set exactly one of",
            ),
            (
                serde_json::json!({"Name": "web",
                    "TaskTemplate": {"ContainerSpec": {"Image": "n"}},
                    "Mode": {"ReplicatedJob": {"TotalCompletions": 0}}}),
                "must be at least 1",
            ),
            // A job retries its failed tasks; "never restart" is a
            // contradiction (on-failure semantics are forced).
            (
                serde_json::json!({"Name": "web",
                    "TaskTemplate": {"ContainerSpec": {"Image": "n"},
                        "RestartPolicy": {"Condition": "none"}},
                    "Mode": {"GlobalJob": {}}}),
                "restart condition \"none\" is not valid for a job",
            ),
        ];
        for (json, expected) in cases {
            let err = service_spec(spec(json.clone())).expect_err(&format!("must reject {json}"));
            assert!(
                err.to_string().contains(expected),
                "for {json}: {err} must contain {expected:?}"
            );
        }
    }

    #[test]
    fn a_job_restart_condition_of_any_becomes_on_failure() {
        let converted = service_spec(spec(serde_json::json!({
            "Name": "batch",
            "TaskTemplate": {"ContainerSpec": {"Image": "n"},
                "RestartPolicy": {"Condition": "any", "MaxAttempts": 3}},
            "Mode": {"ReplicatedJob": {"TotalCompletions": 2}},
        })))
        .expect("valid job");
        assert_eq!(
            converted.task.restart.condition,
            RestartCondition::OnFailure,
            "a clean exit finishes a job, so any == on-failure for one"
        );
        assert_eq!(converted.task.restart.max_attempts, 3);
    }

    #[test]
    fn invalid_enum_values_are_rejected() {
        let cases: [(serde_json::Value, &str); 6] = [
            (
                serde_json::json!({"Condition": "sometimes"}),
                "invalid restart condition",
            ),
            (
                serde_json::json!({"Delay": -1}),
                "is not a positive duration",
            ),
            (serde_json::json!({}), ""),
            (serde_json::json!({"Condition": "any"}), ""),
            (serde_json::json!({"Condition": "none"}), ""),
            (serde_json::json!({"Condition": "on-failure"}), ""),
        ];
        for (json, expected) in cases {
            let policy: TaskRestartPolicyWire = serde_json::from_value(json.clone()).expect("body");
            let result = restart_policy(Some(policy));
            if expected.is_empty() {
                assert!(result.is_ok(), "for {json}");
            } else {
                let err = result.expect_err(&format!("must reject {json}"));
                assert!(err.to_string().contains(expected), "{err}");
            }
        }

        for (json, expected) in [
            (
                serde_json::json!({"FailureAction": "explode"}),
                "invalid failure action",
            ),
            (
                serde_json::json!({"Order": "middle-first"}),
                "invalid update order",
            ),
            (
                serde_json::json!({"MaxFailureRatio": 1.5}),
                "invalid max failure ratio",
            ),
        ] {
            let config: UpdateConfigWire = serde_json::from_value(json.clone()).expect("body");
            let err = update_config(&config).expect_err(&format!("must reject {json}"));
            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    #[test]
    fn ports_and_mounts_reject_bad_values() {
        for (json, expected) in [
            (
                serde_json::json!({"Protocol": "sctp", "TargetPort": 80}),
                "invalid port protocol",
            ),
            (
                serde_json::json!({"PublishMode": "mesh", "TargetPort": 80}),
                "invalid publish mode",
            ),
            (serde_json::json!({"TargetPort": 0}), "port 0"),
            (
                serde_json::json!({"TargetPort": 70000}),
                "is not a port number",
            ),
        ] {
            let port: PortConfigWire = serde_json::from_value(json.clone()).expect("body");
            let err = port_config(port).expect_err(&format!("must reject {json}"));
            assert!(err.to_string().contains(expected), "{err}");
        }

        for (json, expected) in [
            (
                serde_json::json!({"Type": "npipe", "Target": "/x"}),
                "invalid mount type",
            ),
            (
                serde_json::json!({"Type": "bind", "Source": "/a", "Target": "rel"}),
                "absolute path",
            ),
            (
                serde_json::json!({"Type": "bind", "Target": "/x"}),
                "the source is empty",
            ),
            (
                serde_json::json!({"Type": "bind", "Source": "/a", "Target": "/x",
                    "BindOptions": {"Propagation": "rshared"}}),
                "BindOptions/VolumeOptions/TmpfsOptions is not supported",
            ),
        ] {
            let value: MountWire = serde_json::from_value(json.clone()).expect("body");
            let err = mount(value).expect_err(&format!("must reject {json}"));
            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    /// `POST /networks/create` bodies as the wire deserializes them.
    fn create_body(json: serde_json::Value) -> NetworkCreateBody {
        serde_json::from_value(json).expect("test body must deserialize")
    }

    #[test]
    fn encrypted_true_marks_an_overlay_network() {
        let spec = network_spec(create_body(serde_json::json!({
            "Name": "blue",
            "Driver": "overlay",
            "Options": {"encrypted": "true"}
        })))
        .expect("an encrypted overlay converts");
        assert!(spec.encrypted);
    }

    /// Docker's own spelling: `--opt encrypted=false` is accepted and means no
    /// encryption, exactly like passing nothing.
    #[test]
    fn encrypted_false_and_no_options_both_mean_plaintext() {
        let explicit = network_spec(create_body(serde_json::json!({
            "Name": "blue",
            "Driver": "overlay",
            "Options": {"encrypted": "false"}
        })))
        .expect("encrypted=false converts");
        assert!(!explicit.encrypted);

        let absent = network_spec(create_body(serde_json::json!({
            "Name": "blue",
            "Driver": "overlay"
        })))
        .expect("no options converts");
        assert!(!absent.encrypted);
    }

    /// Encryption wraps the VXLAN datagrams between nodes; a bridge network
    /// never leaves its node, so the option is meaningless there.
    #[test]
    fn encryption_is_an_overlay_only_option() {
        for driver in ["bridge", "local"] {
            let err = network_spec(create_body(serde_json::json!({
                "Name": "blue",
                "Driver": driver,
                "Options": {"encrypted": "true"}
            })))
            .expect_err("a bridge network cannot be encrypted");
            assert!(
                matches!(err, BackendError::InvalidParameter(_)),
                "a 400, not a 500: {err:?}"
            );
            assert!(err.to_string().contains("overlay"), "{err}");
        }
    }

    #[test]
    fn unknown_driver_options_are_still_rejected_by_name() {
        let err = network_spec(create_body(serde_json::json!({
            "Name": "blue",
            "Driver": "overlay",
            "Options": {"com.docker.network.driver.mtu": "1450", "encrypted": "true"}
        })))
        .expect_err("an unknown option is a 400 even beside a valid one");
        assert!(
            err.to_string().contains("com.docker.network.driver.mtu"),
            "names the rejected key: {err}"
        );
        assert!(
            err.to_string().contains("encrypted"),
            "says which option SatL does support: {err}"
        );
    }

    #[test]
    fn an_encrypted_value_other_than_true_or_false_is_a_400() {
        let err = network_spec(create_body(serde_json::json!({
            "Name": "blue",
            "Driver": "overlay",
            "Options": {"encrypted": "yes"}
        })))
        .expect_err("only true/false are Docker's spellings");
        assert!(err.to_string().contains("encrypted"), "{err}");
    }

    /// Ingress assignments are broadcast to **every** node, so an encrypted
    /// ingress network would ship its keyring (and a gateway) cluster-wide.
    /// Refused at create; there is no network-update route that could flip
    /// the flag later.
    #[test]
    fn an_encrypted_ingress_network_is_a_400() {
        let err = network_spec(create_body(serde_json::json!({
            "Name": "ingress",
            "Driver": "overlay",
            "Ingress": true,
            "Options": {"encrypted": "true"}
        })))
        .expect_err("the ingress network cannot be encrypted");
        assert!(
            matches!(err, BackendError::InvalidParameter(_)),
            "a 400, not a 500: {err:?}"
        );
        assert!(err.to_string().contains("ingress"), "{err}");
        assert!(err.to_string().contains("encrypted"), "{err}");
    }

    #[test]
    fn an_unencrypted_ingress_network_converts() {
        let spec = network_spec(create_body(serde_json::json!({
            "Name": "ingress",
            "Driver": "overlay",
            "Ingress": true,
            "Options": {"encrypted": "false"}
        })))
        .expect("an unencrypted ingress network converts");
        assert!(spec.ingress);
        assert!(!spec.encrypted);
    }

    #[test]
    fn node_specs_and_roles_convert() {
        let spec: NodeSpecWire = serde_json::from_value(serde_json::json!({
            "Name": "alpha",
            "Labels": {"zone": "a"},
            "Role": "manager",
            "Availability": "drain"
        }))
        .expect("body");
        let update = node_spec_update(spec).expect("valid spec");
        assert_eq!(update.name.as_deref(), Some("alpha"));
        assert_eq!(update.labels["zone"], "a");
        assert_eq!(update.role, NodeRole::Manager);
        assert_eq!(update.availability, Availability::Drain);

        assert_eq!(node_role("worker"), Ok(NodeRole::Worker));
        assert!(node_role("boss").is_err());
        assert_eq!(availability("pause"), Ok(Availability::Pause));
        assert!(availability("asleep").is_err());
    }

    #[test]
    fn versions_parse_and_are_required() {
        assert_eq!(object_version(Some("42")), Ok(Version(42)));
        let err = object_version(None).expect_err("version is required");
        assert!(err.to_string().contains("version is required"), "{err}");
        assert!(object_version(Some("soon")).is_err());
    }

    #[test]
    fn swarm_init_and_join_bodies_validate() {
        let init: crate::types::SwarmInitBody = serde_json::from_value(serde_json::json!({
            "ListenAddr": "0.0.0.0:2377",
            "AdvertiseAddr": "10.2.0.11:2377"
        }))
        .expect("body");
        let options = swarm_init_options(&init).expect("valid init");
        assert_eq!(options.advertise_addr.as_deref(), Some("10.2.0.11:2377"));
        assert_eq!(options.listen_addr.as_deref(), Some("0.0.0.0:2377"));
        assert!(!options.force_new_cluster);

        let locked: crate::types::SwarmInitBody =
            serde_json::from_value(serde_json::json!({"AutoLockManagers": true})).expect("body");
        assert!(
            swarm_init_options(&locked)
                .expect("autolock converts")
                .auto_lock,
            "AutoLockManagers reaches the backend"
        );

        let join: crate::types::SwarmJoinBody = serde_json::from_value(serde_json::json!({
            "RemoteAddrs": ["10.2.0.11:2377"],
            "JoinToken": "SATL-1-worker"
        }))
        .expect("body");
        let options = swarm_join_options(join).expect("valid join");
        assert_eq!(options.remote_addrs, ["10.2.0.11:2377"]);
        assert_eq!(options.join_token, "SATL-1-worker");

        for (json, expected) in [
            (
                serde_json::json!({"JoinToken": "t"}),
                "RemoteAddrs must name at least one",
            ),
            (
                serde_json::json!({"RemoteAddrs": ["a"]}),
                "JoinToken is required",
            ),
        ] {
            let body: crate::types::SwarmJoinBody =
                serde_json::from_value(json.clone()).expect("body");
            let err = swarm_join_options(body).expect_err(&format!("must reject {json}"));
            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    #[test]
    fn task_filters_accept_both_docker_encodings() {
        let map = task_filters(Some(
            r#"{"service":{"web":true},"desired-state":{"running":true}}"#,
        ))
        .expect("valid filters");
        assert_eq!(map.services, ["web"]);
        assert_eq!(map.desired_states, [DesiredState::Running]);

        let list = task_filters(Some(
            r#"{"node":["alpha","beta"],"id":["abc"],"name":["web.1"],"label":["tier=web","x"]}"#,
        ))
        .expect("valid filters");
        assert_eq!(list.nodes, ["alpha", "beta"]);
        assert_eq!(list.ids, ["abc"]);
        assert_eq!(list.names, ["web.1"]);
        assert_eq!(list.labels["tier"], Some("web".to_owned()));
        assert_eq!(list.labels["x"], None);

        assert!(task_filters(None).expect("no filters").is_empty());
        assert!(
            task_filters(Some(r#"{"service":{"web":false}}"#))
                .expect("valid")
                .services
                .is_empty(),
            "a disabled filter value matches nothing"
        );

        for (raw, expected) in [
            ("{oops", "invalid filters"),
            (r#"{"colour":["red"]}"#, "invalid filter"),
            (r#"{"desired-state":["asleep"]}"#, "invalid desired-state"),
            (r#"{"service":5}"#, "expected a list of values"),
        ] {
            let err = task_filters(Some(raw)).expect_err(&format!("must reject {raw}"));
            assert!(err.to_string().contains(expected), "{raw}: {err}");
        }
    }

    /// A well-formed secret create: the payload round-trips out of base64, the
    /// spec keeps its labels, and nothing else is invented.
    #[test]
    fn secret_create_decodes_the_payload_and_keeps_the_annotations() {
        let wire: SecretSpecWire = serde_json::from_value(serde_json::json!({
            "Name": "db_password",
            "Labels": {"env": "prod"},
            // "s3cr3t" in standard base64.
            "Data": "czNjcjN0"
        }))
        .expect("valid wire spec");
        let spec = secret_spec(wire).expect("valid secret");
        assert_eq!(spec.annotations.name, "db_password");
        assert_eq!(spec.annotations.labels["env"], "prod");
        assert_eq!(spec.data(), b"s3cr3t");

        // base64url with no padding, which Docker clients also send.
        let wire: ConfigSpecWire = serde_json::from_value(serde_json::json!({
            "Name": "nginx_conf",
            "Data": "aGVsbG8_d29ybGQ"
        }))
        .expect("valid wire spec");
        let spec = config_spec(wire).expect("valid config");
        assert_eq!(spec.data(), b"hello?world");
    }

    /// Every rejection a payload endpoint can produce — and none of them may
    /// contain the payload.
    #[test]
    fn secret_and_config_creates_reject_bad_input_without_quoting_payloads() {
        let payload = "c3VwZXItc2VjcmV0LXRva2Vu"; // "super-secret-token"
        let cases: Vec<(serde_json::Value, &str)> = vec![
            (
                serde_json::json!({"Name": "-nope-", "Data": payload}),
                "invalid secret name",
            ),
            (serde_json::json!({"Name": "ok"}), "data is required"),
            (
                serde_json::json!({"Name": "ok", "Data": ""}),
                "data is required",
            ),
            (
                serde_json::json!({"Name": "ok", "Data": "not base64!!"}),
                "expected a base64-encoded payload",
            ),
            (
                serde_json::json!({"Name": "ok", "Data": payload,
                    "Driver": {"Name": "vault"}}),
                "secret drivers are not supported",
            ),
            (
                serde_json::json!({"Name": "ok", "Data": payload,
                    "Templating": {"Name": "golang"}}),
                "secret templating is not supported",
            ),
        ];
        for (body, expected) in cases {
            let wire: SecretSpecWire =
                serde_json::from_value(body.clone()).expect("a parsable body");
            let err = secret_spec(wire).expect_err(&format!("must reject {body}"));
            let message = err.to_string();
            assert!(message.contains(expected), "for {body}: {message}");
            assert!(
                !message.contains("super-secret") && !message.contains(payload),
                "a rejection must never quote the payload: {message}"
            );
        }

        // An oversized payload is refused by `satl-core`, and the message says
        // where the limit is.
        let oversized = base64::engine::general_purpose::STANDARD
            .encode(vec![b'x'; satl_core::defaults::MAX_SECRET_SIZE]);
        let wire: SecretSpecWire = serde_json::from_value(serde_json::json!({
            "Name": "big", "Data": oversized
        }))
        .expect("a parsable body");
        let message = secret_spec(wire).expect_err("too large").to_string();
        assert!(message.contains("512000"), "{message}");
        assert!(!message.contains("xxxx"), "{message}");

        // A zero-length payload is a size error, not a silent empty secret.
        let wire: SecretSpecWire = serde_json::from_value(serde_json::json!({
            "Name": "empty", "Data": "="
        }))
        .expect("a parsable body");
        assert!(secret_spec(wire).is_err());

        // Configs: same rules, their own limit and no Driver member at all.
        let wire: ConfigSpecWire = serde_json::from_value(serde_json::json!({
            "Name": "nope", "Data": payload, "Templating": {"Name": "golang"}
        }))
        .expect("a parsable body");
        let message = config_spec(wire).expect_err("templating").to_string();
        assert!(
            message.contains("config templating is not supported"),
            "{message}"
        );
    }

    /// A `Driver`/`Templating` member a Go client marshalled as a zero struct
    /// is not a request for a driver: `null` and `{}` mean "unset".
    #[test]
    fn an_empty_driver_member_is_not_a_driver() {
        for value in [serde_json::json!(null), serde_json::json!({})] {
            let wire: SecretSpecWire = serde_json::from_value(serde_json::json!({
                "Name": "ok", "Data": "eA==", "Driver": value.clone(),
                "Templating": value
            }))
            .expect("a parsable body");
            assert!(secret_spec(wire).is_ok(), "{value:?} must mean unset");
        }
    }

    /// The short `--secret db_password` form: no `File`, so Docker's own
    /// defaults apply — the file is named after the secret, owned by root, mode
    /// 0444.
    #[test]
    fn a_secret_reference_without_a_file_gets_dockers_defaults() {
        let id = Id::generate();
        let converted = service_spec(spec(serde_json::json!({
            "Name": "web",
            "TaskTemplate": {"ContainerSpec": {"Image": "nginx", "Secrets": [
                {"SecretID": id.as_str(), "SecretName": "db_password"}
            ]}}
        })))
        .expect("valid spec");
        let reference = &converted.task.container.secrets[0];
        assert_eq!(reference.secret_id, id);
        assert_eq!(reference.secret_name, "db_password");
        assert_eq!(reference.file.name, "db_password");
        assert_eq!(reference.file.uid, "0");
        assert_eq!(reference.file.gid, "0");
        assert_eq!(reference.file.mode, 0o444);
    }

    /// A config target may be absolute (that is how a config file lands in
    /// `/etc`), and its explicit ownership and mode are kept as sent.
    #[test]
    fn a_config_reference_keeps_an_absolute_target_and_its_mode() {
        let id = Id::generate();
        let converted = service_spec(spec(serde_json::json!({
            "Name": "web",
            "TaskTemplate": {"ContainerSpec": {"Image": "nginx", "Configs": [
                {"ConfigID": id.as_str(), "ConfigName": "nginx_conf",
                 "File": {"Name": "/etc/nginx/nginx.conf", "UID": "80", "GID": "80", "Mode": 384}}
            ]}}
        })))
        .expect("valid spec");
        let reference = &converted.task.container.configs[0];
        assert_eq!(reference.config_id, id);
        assert_eq!(reference.file.name, "/etc/nginx/nginx.conf");
        assert_eq!(reference.file.uid, "80");
        assert_eq!(reference.file.gid, "80");
        assert_eq!(reference.file.mode, 0o600, "384 decimal is 0o600");
    }

    /// Every reference rejection, and the reason each one is a rejection rather
    /// than a normalization.
    #[test]
    fn secret_and_config_references_are_validated() {
        let id = Id::generate();
        let secrets = |value: serde_json::Value| {
            serde_json::json!({"Name": "web", "TaskTemplate": {
                "ContainerSpec": {"Image": "nginx", "Secrets": value}}})
        };
        let configs = |value: serde_json::Value| {
            serde_json::json!({"Name": "web", "TaskTemplate": {
                "ContainerSpec": {"Image": "nginx", "Configs": value}}})
        };
        let cases: Vec<(serde_json::Value, &str)> = vec![
            (
                secrets(serde_json::json!([{"SecretID": id.as_str()}])),
                "SecretName is required",
            ),
            (
                secrets(serde_json::json!([{"SecretName": "db_password"}])),
                "SecretID is required",
            ),
            (
                secrets(serde_json::json!([{"SecretID": "nope", "SecretName": "db_password"}])),
                "invalid secret reference db_password",
            ),
            (
                secrets(
                    serde_json::json!([{"SecretID": id.as_str(), "SecretName": "db",
                    "File": {"Name": "/run/secrets/db"}}]),
                ),
                "secret target must be a relative path",
            ),
            (
                secrets(
                    serde_json::json!([{"SecretID": id.as_str(), "SecretName": "db",
                    "File": {"Name": "../../etc/passwd"}}]),
                ),
                "may not contain \"..\"",
            ),
            (
                secrets(
                    serde_json::json!([{"SecretID": id.as_str(), "SecretName": "db",
                    "File": {"Name": "db", "Mode": 65535}}]),
                ),
                "is not a permission bit pattern",
            ),
            (
                secrets(serde_json::json!([
                    {"SecretID": id.as_str(), "SecretName": "db", "File": {"Name": "creds"}},
                    {"SecretID": id.as_str(), "SecretName": "api", "File": {"Name": "creds"}}
                ])),
                "duplicate secret target creds",
            ),
            (
                configs(
                    serde_json::json!([{"ConfigID": id.as_str(), "ConfigName": "c",
                    "File": {"Name": "/etc/../etc/nginx.conf"}}]),
                ),
                "may not contain \"..\"",
            ),
            (
                configs(serde_json::json!([
                    {"ConfigID": id.as_str(), "ConfigName": "a", "File": {"Name": "/etc/app.conf"}},
                    {"ConfigID": id.as_str(), "ConfigName": "b", "File": {"Name": "/etc/app.conf"}}
                ])),
                "duplicate config target /etc/app.conf",
            ),
        ];
        for (body, expected) in cases {
            let err = service_spec(spec(body.clone())).expect_err(&format!("must reject {body}"));
            assert!(err.to_string().contains(expected), "for {body}: {err}");
            assert!(
                matches!(err, BackendError::InvalidParameter(_)),
                "reference errors are 400s: {err:?}"
            );
        }
    }
}
