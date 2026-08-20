// SPDX-License-Identifier: BSD-2-Clause
//! [`backend::model`](crate::backend::model) types → Docker response
//! documents.
//!
//! The interesting part is the Task → Docker container translation. SatL has
//! no "container state" of its own: a container is a Task (invariant #2), so
//! Docker's `State`/`Status` are *derived* from the task's observed and
//! desired states here, in one place, per the M1 mapping recorded in
//! `docs/api-compat.md`:
//!
//! | Task state | desired | Docker `State` |
//! |---|---|---|
//! | `new`…`ready` | `ready` or anything | `created` |
//! | `starting`, `running` | — | `running` |
//! | `complete` | — | `exited` (0) |
//! | `failed` | — | `exited` (exit code) |
//! | `shutdown` | — | `exited` |
//! | `rejected`, `orphaned` | — | `dead` |

pub mod cluster;

use std::collections::BTreeMap;
use std::time::SystemTime;

use satl_core::{Mount, MountType, Platform, PortProtocol, RestartCondition, TaskState};

use crate::backend::model::{
    ContainerHealth, ContainerInspect, ContainerRuntimeState, ContainerSummary, EventMessage,
    ExecInspect, ExposedPort, ImageDeleted, ImageInspect, ImageSummary, PortMapping,
    PrunedContainers, PrunedImages, PrunedNetworks, PrunedVolumes, PullProgressLine, VolumeInfo,
};
use crate::timefmt;
use crate::types::{
    ContainerHealthResponse, ContainerInspectResponse, ContainerStateResponse,
    ContainerSummaryResponse, ContainersPruneResponse, EventActorResponse, EventResponse,
    ExecInspectResponse, HealthLogEntryResponse, ImageDeleteResponseItem, ImageGraphDriver,
    ImageInspectConfig, ImageInspectResponse, ImageRootFs, ImageSummaryResponse,
    ImagesPruneResponse, InspectConfig, InspectHostConfig, InspectNetworkSettings, JsonErrorDetail,
    JsonMessage, JsonProgressDetail, MountPoint, NetworksPruneResponse, PortBindingBody,
    PortSummary, ProcessConfig, RestartPolicyResponse, SummaryHostConfig, SummaryNetworkSettings,
    VolumeResponse, VolumesPruneResponse,
};

/// Docker's container state names.
mod state_name {
    /// Created but never started.
    pub const CREATED: &str = "created";
    /// Started and still alive.
    pub const RUNNING: &str = "running";
    /// Terminated with an exit code.
    pub const EXITED: &str = "exited";
    /// Unrecoverable — never ran, or lost with its node.
    pub const DEAD: &str = "dead";
    /// Shutting down, on its way to deletion.
    pub const REMOVING: &str = "removing";
}

/// Docker `State` name for a task (see the module table).
#[must_use]
pub fn container_state(state: &ContainerRuntimeState) -> &'static str {
    match state.task_state {
        TaskState::New
        | TaskState::Pending
        | TaskState::Assigned
        | TaskState::Accepted
        | TaskState::Preparing
        | TaskState::Ready => state_name::CREATED,
        TaskState::Starting | TaskState::Running => state_name::RUNNING,
        TaskState::Complete | TaskState::Shutdown | TaskState::Failed => state_name::EXITED,
        TaskState::Rejected | TaskState::Orphaned => state_name::DEAD,
        // `remove` is a desired-state marker and never observed; if the
        // daemon ever reports it, "removing" is the honest rendering.
        TaskState::Remove => state_name::REMOVING,
    }
}

/// Exit code Docker reports for a task: whatever the agent observed, 0 while
/// the task has not exited (`complete` implies 0 by construction).
#[must_use]
pub fn exit_code(state: &ContainerRuntimeState) -> i64 {
    state.exit_code.unwrap_or(0)
}

/// Docker's `State.Health` document.
#[must_use]
pub fn container_health(health: &ContainerHealth) -> ContainerHealthResponse {
    ContainerHealthResponse {
        status: health.status.clone(),
        failing_streak: health.failing_streak,
        log: health
            .log
            .iter()
            .map(|entry| HealthLogEntryResponse {
                start: timefmt::rfc3339_nano(entry.start),
                end: timefmt::rfc3339_nano(entry.end),
                exit_code: entry.exit_code,
                output: entry.output.clone(),
            })
            .collect(),
    }
}

/// The parenthesised health suffix Docker appends to a running container's
/// `Status` — `(healthy)`, `(unhealthy)`, `(health: starting)` (moby's
/// `Health.String()`).
fn health_suffix(health: &ContainerHealth) -> String {
    match health.status.as_str() {
        "starting" => " (health: starting)".to_owned(),
        other => format!(" ({other})"),
    }
}

/// Docker's human-readable `Status` column (`Up 3 minutes`, `Up 3 minutes
/// (healthy)`, `Exited (0) 2 minutes ago`, …), relative to `now`.
#[must_use]
pub fn status_text(state: &ContainerRuntimeState, now: SystemTime) -> String {
    let health = state.health.as_ref().map(health_suffix).unwrap_or_default();
    match container_state(state) {
        state_name::RUNNING => match state.started_at {
            Some(started) => format!(
                "Up {}{health}",
                timefmt::humanize_duration(timefmt::elapsed_since(now, started))
            ),
            None => format!("Up{health}"),
        },
        state_name::EXITED => {
            let code = exit_code(state);
            match state.finished_at {
                Some(finished) => format!(
                    "Exited ({code}) {} ago",
                    timefmt::humanize_duration(timefmt::elapsed_since(now, finished))
                ),
                None => format!("Exited ({code})"),
            }
        }
        state_name::DEAD => "Dead".to_owned(),
        state_name::REMOVING => "Removal In Progress".to_owned(),
        _ => "Created".to_owned(),
    }
}

/// `os/arch`, SatL's `PLATFORM` column value.
#[must_use]
pub fn platform_string(platform: &Platform) -> String {
    format!("{}/{}", platform.os, platform.arch)
}

/// Docker's `<port>/<proto>` key.
#[must_use]
pub fn port_key(port: u16, protocol: PortProtocol) -> String {
    format!("{port}/{}", protocol_name(protocol))
}

/// Docker's protocol spelling.
#[must_use]
pub fn protocol_name(protocol: PortProtocol) -> &'static str {
    match protocol {
        PortProtocol::Tcp => "tcp",
        PortProtocol::Udp => "udp",
    }
}

/// One row of `GET /containers/json`.
#[must_use]
pub fn container_summary(summary: &ContainerSummary, now: SystemTime) -> ContainerSummaryResponse {
    let mut networks = BTreeMap::new();
    networks.insert(
        summary.network_name.clone(),
        crate::types::EndpointSettings {
            ip_address: summary.ip_address.clone().unwrap_or_default(),
            ..crate::types::EndpointSettings::default()
        },
    );
    ContainerSummaryResponse {
        id: summary.id.clone(),
        names: vec![format!("/{}", summary.name)],
        image: summary.image.clone(),
        image_id: summary.image_id.clone(),
        command: summary.command.join(" "),
        created: timefmt::unix_seconds(summary.created),
        ports: summary.ports.iter().map(port_summary).collect(),
        labels: summary.labels.clone(),
        state: container_state(&summary.state).to_owned(),
        status: status_text(&summary.state, now),
        host_config: SummaryHostConfig {
            network_mode: summary.network_name.clone(),
        },
        network_settings: SummaryNetworkSettings { networks },
        mounts: summary.mounts.iter().map(mount_point).collect(),
        platform: summary.platform.as_ref().map(platform_string),
    }
}

/// One `Ports` entry of a container summary.
fn port_summary(port: &PortMapping) -> PortSummary {
    let published = port.host_port != 0;
    PortSummary {
        ip: port
            .host_ip
            .clone()
            .or_else(|| published.then(|| "0.0.0.0".to_owned())),
        private_port: port.container_port,
        public_port: published.then_some(port.host_port),
        kind: protocol_name(port.protocol).to_owned(),
    }
}

/// One `Mounts` entry.
fn mount_point(mount: &Mount) -> MountPoint {
    let (kind, name, source) = match mount.kind {
        MountType::Bind => ("bind", None, mount.source.clone().unwrap_or_default()),
        MountType::Volume => ("volume", mount.source.clone(), String::new()),
        MountType::Tmpfs => ("tmpfs", None, String::new()),
    };
    MountPoint {
        kind: kind.to_owned(),
        name,
        source,
        destination: mount.target.clone(),
        mode: if mount.read_only { "ro" } else { "rw" }.to_owned(),
        rw: !mount.read_only,
        propagation: String::new(),
    }
}

/// Docker's `ExposedPorts` map (`{"80/tcp": {}}`).
fn exposed_ports_map(ports: &[ExposedPort]) -> BTreeMap<String, serde_json::Value> {
    ports
        .iter()
        .map(|port| {
            (
                port_key(port.port, port.protocol),
                serde_json::Value::Object(serde_json::Map::new()),
            )
        })
        .collect()
}

/// Docker's `PortBindings`/`NetworkSettings.Ports` map.
fn port_bindings_map(ports: &[PortMapping]) -> BTreeMap<String, Option<Vec<PortBindingBody>>> {
    let mut map: BTreeMap<String, Option<Vec<PortBindingBody>>> = BTreeMap::new();
    for port in ports {
        let entry = map
            .entry(port_key(port.container_port, port.protocol))
            .or_default();
        if port.host_port == 0 && port.host_ip.is_none() {
            continue;
        }
        entry.get_or_insert_with(Vec::new).push(PortBindingBody {
            host_ip: port.host_ip.clone().unwrap_or_else(|| "0.0.0.0".to_owned()),
            host_port: port.host_port.to_string(),
        });
    }
    map
}

/// Docker's `RestartPolicy` document.
fn restart_policy_response(policy: &satl_core::RestartPolicy) -> RestartPolicyResponse {
    let name = match policy.condition {
        RestartCondition::None => "no",
        RestartCondition::OnFailure => "on-failure",
        RestartCondition::Any => "always",
    };
    RestartPolicyResponse {
        name: name.to_owned(),
        maximum_retry_count: policy.max_attempts,
    }
}

/// `GET /containers/{id}/json`.
#[must_use]
pub fn container_inspect(inspect: &ContainerInspect) -> ContainerInspectResponse {
    let state = &inspect.state;
    let docker_state = container_state(state);
    let mut networks = BTreeMap::new();
    networks.insert(
        inspect.network.network_name.clone(),
        crate::types::EndpointSettings {
            network_id: inspect.network.network_id.clone().unwrap_or_default(),
            ip_address: inspect.network.ip_address.clone().unwrap_or_default(),
            ip_prefix_len: inspect.network.ip_prefix_len,
            gateway: inspect.network.gateway.clone().unwrap_or_default(),
            mac_address: inspect.network.mac_address.clone().unwrap_or_default(),
        },
    );
    let ports = port_bindings_map(&inspect.network.ports);

    ContainerInspectResponse {
        id: inspect.id.clone(),
        created: timefmt::rfc3339_nano(inspect.created),
        path: inspect.path.clone(),
        args: inspect.args.clone(),
        state: ContainerStateResponse {
            status: docker_state.to_owned(),
            running: docker_state == state_name::RUNNING,
            paused: false,
            restarting: false,
            oom_killed: false,
            dead: docker_state == state_name::DEAD,
            pid: state.pid.unwrap_or(0),
            exit_code: exit_code(state),
            error: state.error.clone().unwrap_or_default(),
            started_at: timefmt::rfc3339_nano_or_zero(state.started_at),
            finished_at: timefmt::rfc3339_nano_or_zero(state.finished_at),
            health: state.health.as_ref().map(container_health),
        },
        image: inspect.image_id.clone(),
        name: format!("/{}", inspect.name),
        restart_count: inspect.restart_count,
        driver: "zfs".to_owned(),
        platform: inspect
            .platform
            .as_ref()
            .map(platform_string)
            .unwrap_or_default(),
        jail_id: inspect.jail_id.clone(),
        host_config: InspectHostConfig {
            binds: inspect.host_config.binds.clone(),
            tmpfs: inspect.host_config.tmpfs.clone(),
            port_bindings: port_bindings_map(&inspect.host_config.port_bindings)
                .into_iter()
                .map(|(key, value)| (key, value.unwrap_or_default()))
                .collect(),
            restart_policy: restart_policy_response(&inspect.host_config.restart_policy),
            auto_remove: inspect.host_config.auto_remove,
            network_mode: inspect.host_config.network_mode.clone(),
            memory: inspect.host_config.memory,
            nano_cpus: inspect.host_config.nano_cpus,
        },
        config: InspectConfig {
            hostname: inspect.config.hostname.clone().unwrap_or_default(),
            user: inspect.config.user.clone().unwrap_or_default(),
            open_stdin: inspect.config.open_stdin,
            tty: inspect.config.tty,
            exposed_ports: exposed_ports_map(&inspect.config.exposed_ports),
            env: inspect.config.env.clone(),
            cmd: (!inspect.config.cmd.is_empty()).then(|| inspect.config.cmd.clone()),
            entrypoint: (!inspect.config.entrypoint.is_empty())
                .then(|| inspect.config.entrypoint.clone()),
            image: inspect.config.image.clone(),
            working_dir: inspect.config.working_dir.clone().unwrap_or_default(),
            labels: inspect.config.labels.clone(),
        },
        network_settings: InspectNetworkSettings {
            bridge: String::new(),
            ports: (!ports.is_empty()).then_some(ports),
            ip_address: inspect.network.ip_address.clone().unwrap_or_default(),
            ip_prefix_len: inspect.network.ip_prefix_len,
            gateway: inspect.network.gateway.clone().unwrap_or_default(),
            mac_address: inspect.network.mac_address.clone().unwrap_or_default(),
            networks,
        },
        mounts: inspect.mounts.iter().map(mount_point).collect(),
    }
}

/// One row of `GET /images/json`.
#[must_use]
pub fn image_summary(image: &ImageSummary) -> ImageSummaryResponse {
    ImageSummaryResponse {
        id: image.id.clone(),
        parent_id: image.parent_id.clone(),
        repo_tags: image.repo_tags.clone(),
        repo_digests: image.repo_digests.clone(),
        created: image.created.map_or(0, timefmt::unix_seconds),
        size: image.size,
        shared_size: image.shared_size,
        virtual_size: image.size,
        labels: (!image.labels.is_empty()).then(|| image.labels.clone()),
        containers: image.containers,
        platform: image.platform.as_ref().map(platform_string),
    }
}

/// The `GET /images/{name}/json` document.
#[must_use]
pub fn image_inspect(image: &ImageInspect) -> ImageInspectResponse {
    let (os, architecture) = image
        .platform
        .as_ref()
        .map_or_else(Default::default, |platform| {
            (platform.os.clone(), platform.arch.clone())
        });
    ImageInspectResponse {
        id: image.id.clone(),
        repo_tags: image.repo_tags.clone(),
        repo_digests: image.repo_digests.clone(),
        // Empty rather than absent: Docker clients read these positionally,
        // and an OCI pull gives SatL no source for any of them (#41).
        parent: String::new(),
        comment: String::new(),
        created: timefmt::rfc3339_nano_or_zero(image.created),
        author: String::new(),
        config: ImageInspectConfig {
            user: image.config.user.clone(),
            exposed_ports: (!image.config.exposed_ports.is_empty()).then(|| {
                image
                    .config
                    .exposed_ports
                    .iter()
                    .map(|port| (port.clone(), serde_json::json!({})))
                    .collect()
            }),
            env: (!image.config.env.is_empty()).then(|| image.config.env.clone()),
            cmd: (!image.config.cmd.is_empty()).then(|| image.config.cmd.clone()),
            entrypoint: (!image.config.entrypoint.is_empty())
                .then(|| image.config.entrypoint.clone()),
            working_dir: image.config.working_dir.clone(),
            labels: None,
        },
        architecture,
        os,
        size: image.size,
        virtual_size: image.size,
        graph_driver: ImageGraphDriver::default(),
        root_fs: ImageRootFs {
            kind: "layers".to_owned(),
            layers: image.rootfs_layers.clone(),
        },
        platform: image.platform.as_ref().map(platform_string),
    }
}

/// A volume document.
#[must_use]
pub fn volume(volume: &VolumeInfo) -> VolumeResponse {
    VolumeResponse {
        name: volume.name.clone(),
        driver: volume.driver.clone(),
        mountpoint: volume.mountpoint.clone(),
        created_at: volume
            .created_at
            .map(timefmt::rfc3339_nano)
            .unwrap_or_default(),
        status: BTreeMap::new(),
        labels: volume.labels.clone(),
        scope: "local".to_owned(),
        options: volume.options.clone(),
    }
}

/// A `POST /containers/prune` response.
#[must_use]
pub fn pruned_containers(pruned: &PrunedContainers) -> ContainersPruneResponse {
    ContainersPruneResponse {
        containers_deleted: pruned.deleted.clone(),
        space_reclaimed: pruned.space_reclaimed,
    }
}

/// One `ImagesDeleted` item, in Docker's two shapes.
///
/// Shared by `POST /images/prune` and `DELETE /images/{name}`: Docker's rmi
/// response is a bare array of exactly these, and the prune wraps the same
/// items in an object, so the mapping has one home.
#[must_use]
pub fn image_deleted(item: &ImageDeleted) -> ImageDeleteResponseItem {
    match item {
        ImageDeleted::Untagged(what) => ImageDeleteResponseItem {
            untagged: Some(what.clone()),
            deleted: None,
        },
        ImageDeleted::Deleted(what) => ImageDeleteResponseItem {
            untagged: None,
            deleted: Some(what.clone()),
        },
    }
}

/// A `POST /images/prune` response.
#[must_use]
pub fn pruned_images(pruned: &PrunedImages) -> ImagesPruneResponse {
    ImagesPruneResponse {
        images_deleted: pruned.deleted.iter().map(image_deleted).collect(),
        space_reclaimed: pruned.space_reclaimed,
        deferred: pruned.deferred.clone(),
    }
}

/// A `POST /networks/prune` response.
#[must_use]
pub fn pruned_networks(pruned: &PrunedNetworks) -> NetworksPruneResponse {
    NetworksPruneResponse {
        networks_deleted: pruned.deleted.clone(),
    }
}

/// A `POST /volumes/prune` response.
#[must_use]
pub fn pruned_volumes(pruned: &PrunedVolumes) -> VolumesPruneResponse {
    VolumesPruneResponse {
        volumes_deleted: pruned.deleted.clone(),
        space_reclaimed: pruned.space_reclaimed,
    }
}

/// One `GET /events` message.
#[must_use]
pub fn event(event: &EventMessage) -> EventResponse {
    EventResponse {
        kind: event.kind.clone(),
        action: event.action.clone(),
        actor: EventActorResponse {
            id: event.actor.id.clone(),
            attributes: event.actor.attributes.clone(),
        },
        scope: event.scope.clone(),
        time: timefmt::unix_seconds(event.time),
        time_nano: timefmt::unix_nanos(event.time),
    }
}

/// One line of a pull progress stream.
#[must_use]
pub fn pull_progress(line: &PullProgressLine) -> JsonMessage {
    JsonMessage {
        status: (!line.status.is_empty()).then(|| line.status.clone()),
        id: line.id.clone(),
        progress_detail: line.progress_detail.map(|detail| JsonProgressDetail {
            current: detail.current,
            total: detail.total,
        }),
        progress: line.progress.clone(),
        error: line.error.clone(),
        error_detail: line
            .error
            .clone()
            .map(|message| JsonErrorDetail { message }),
    }
}

/// `GET /exec/{id}/json`.
#[must_use]
pub fn exec_inspect(exec: &ExecInspect) -> ExecInspectResponse {
    let (entrypoint, arguments) = exec.cmd.split_first().map_or_else(
        || (String::new(), Vec::new()),
        |(head, rest)| (head.clone(), rest.to_vec()),
    );
    ExecInspectResponse {
        id: exec.id.clone(),
        container_id: exec.container_id.clone(),
        running: exec.running,
        exit_code: exec.exit_code.unwrap_or(0),
        pid: exec.pid.unwrap_or(0),
        open_stdin: exec.open_stdin,
        open_stdout: exec.open_stdout,
        open_stderr: exec.open_stderr,
        can_remove: true,
        detach_keys: String::new(),
        process_config: ProcessConfig {
            tty: exec.tty,
            entrypoint,
            arguments,
            privileged: false,
            user: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use satl_core::DesiredState;

    use super::*;
    use crate::backend::model::ContainerHealthLog;

    fn state(task_state: TaskState, desired: DesiredState) -> ContainerRuntimeState {
        ContainerRuntimeState {
            task_state,
            desired_state: desired,
            ..ContainerRuntimeState::default()
        }
    }

    #[test]
    fn task_states_map_to_docker_states() {
        let cases = [
            (TaskState::New, DesiredState::Running, "created"),
            (TaskState::Pending, DesiredState::Running, "created"),
            (TaskState::Assigned, DesiredState::Running, "created"),
            (TaskState::Accepted, DesiredState::Running, "created"),
            (TaskState::Preparing, DesiredState::Running, "created"),
            (TaskState::Ready, DesiredState::Ready, "created"),
            (TaskState::Ready, DesiredState::Running, "created"),
            (TaskState::Starting, DesiredState::Running, "running"),
            (TaskState::Running, DesiredState::Running, "running"),
            (TaskState::Complete, DesiredState::Running, "exited"),
            (TaskState::Failed, DesiredState::Running, "exited"),
            (TaskState::Shutdown, DesiredState::Shutdown, "exited"),
            (TaskState::Rejected, DesiredState::Running, "dead"),
            (TaskState::Orphaned, DesiredState::Running, "dead"),
            (TaskState::Remove, DesiredState::Remove, "removing"),
        ];
        for (task_state, desired, expected) in cases {
            assert_eq!(
                container_state(&state(task_state, desired)),
                expected,
                "{task_state} + desired {desired}"
            );
        }
    }

    /// Docker appends the health to a running container's `Status`, and spells
    /// the starting state `health: starting` rather than `starting`
    /// (`Health.String()`). That string is `satl ps`'s STATUS column.
    #[test]
    fn a_running_container_carries_its_health_in_the_status_column() {
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        let with_health = |status: &str, streak: u32| ContainerRuntimeState {
            task_state: TaskState::Running,
            started_at: Some(now - Duration::from_mins(3)),
            health: Some(ContainerHealth {
                status: status.to_owned(),
                failing_streak: streak,
                log: Vec::new(),
            }),
            ..ContainerRuntimeState::default()
        };
        assert_eq!(
            status_text(&with_health("healthy", 0), now),
            "Up 3 minutes (healthy)"
        );
        assert_eq!(
            status_text(&with_health("unhealthy", 3), now),
            "Up 3 minutes (unhealthy)"
        );
        // A task with a healthcheck that has not passed one yet is STARTING,
        // which renders as Docker's `running` state with `health: starting`.
        let starting = ContainerRuntimeState {
            task_state: TaskState::Starting,
            started_at: Some(now - Duration::from_secs(2)),
            health: Some(ContainerHealth {
                status: "starting".to_owned(),
                failing_streak: 0,
                log: Vec::new(),
            }),
            ..ContainerRuntimeState::default()
        };
        assert_eq!(
            status_text(&starting, now),
            "Up 2 seconds (health: starting)"
        );
    }

    /// A task without a healthcheck — or one on another node — renders exactly
    /// as before: no suffix, no `State.Health`.
    #[test]
    fn no_health_means_no_suffix_and_no_health_document() {
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        let running = ContainerRuntimeState {
            task_state: TaskState::Running,
            started_at: Some(now - Duration::from_mins(3)),
            ..ContainerRuntimeState::default()
        };
        assert_eq!(status_text(&running, now), "Up 3 minutes");
        assert!(running.health.is_none());
    }

    #[test]
    fn the_health_document_carries_the_probe_log() {
        let start = UNIX_EPOCH + Duration::from_mins(29_500_000);
        let health = ContainerHealth {
            status: "unhealthy".to_owned(),
            failing_streak: 3,
            log: vec![ContainerHealthLog {
                start,
                end: start + Duration::from_millis(20),
                exit_code: -1,
                output: "Health check exceeded timeout (2s)".to_owned(),
            }],
        };
        let rendered = container_health(&health);
        assert_eq!(rendered.status, "unhealthy");
        assert_eq!(rendered.failing_streak, 3);
        assert_eq!(rendered.log.len(), 1);
        assert_eq!(rendered.log[0].exit_code, -1);
        assert_eq!(rendered.log[0].start, "2026-02-02T02:40:00Z");
        assert_eq!(rendered.log[0].output, "Health check exceeded timeout (2s)");
    }

    #[test]
    fn status_text_matches_docker_wording() {
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        let running = ContainerRuntimeState {
            task_state: TaskState::Running,
            started_at: Some(now - Duration::from_mins(3)),
            ..ContainerRuntimeState::default()
        };
        assert_eq!(status_text(&running, now), "Up 3 minutes");

        let exited = ContainerRuntimeState {
            task_state: TaskState::Complete,
            exit_code: Some(0),
            finished_at: Some(now - Duration::from_mins(2)),
            ..ContainerRuntimeState::default()
        };
        assert_eq!(status_text(&exited, now), "Exited (0) 2 minutes ago");

        let failed = ContainerRuntimeState {
            task_state: TaskState::Failed,
            exit_code: Some(137),
            finished_at: Some(now - Duration::from_secs(3)),
            ..ContainerRuntimeState::default()
        };
        assert_eq!(status_text(&failed, now), "Exited (137) 3 seconds ago");

        assert_eq!(
            status_text(&state(TaskState::New, DesiredState::Ready), now),
            "Created"
        );
        assert_eq!(
            status_text(&state(TaskState::Rejected, DesiredState::Running), now),
            "Dead"
        );
        // Missing timestamps never panic and never lie about a duration.
        assert_eq!(
            status_text(&state(TaskState::Running, DesiredState::Running), now),
            "Up"
        );
        assert_eq!(
            status_text(&state(TaskState::Failed, DesiredState::Running), now),
            "Exited (0)"
        );
    }

    #[test]
    fn ports_render_in_both_docker_shapes() {
        let published = PortMapping {
            host_ip: None,
            host_port: 8080,
            container_port: 80,
            protocol: PortProtocol::Tcp,
        };
        let unpublished = PortMapping {
            host_ip: None,
            host_port: 0,
            container_port: 53,
            protocol: PortProtocol::Udp,
        };

        let summary = port_summary(&published);
        assert_eq!(summary.ip.as_deref(), Some("0.0.0.0"));
        assert_eq!(summary.private_port, 80);
        assert_eq!(summary.public_port, Some(8080));
        assert_eq!(summary.kind, "tcp");

        let summary = port_summary(&unpublished);
        assert_eq!(summary.ip, None);
        assert_eq!(summary.public_port, None);

        let map = port_bindings_map(&[published, unpublished]);
        assert_eq!(
            map["80/tcp"].as_ref().expect("published")[0].host_port,
            "8080"
        );
        assert_eq!(
            map["80/tcp"].as_ref().expect("published")[0].host_ip,
            "0.0.0.0"
        );
        assert!(map["53/udp"].is_none(), "unpublished ports map to null");
    }

    #[test]
    fn mounts_render_with_docker_kinds() {
        let bind = mount_point(&Mount {
            kind: MountType::Bind,
            source: Some("/host".to_owned()),
            target: "/data".to_owned(),
            read_only: true,
        });
        assert_eq!(bind.kind, "bind");
        assert_eq!(bind.source, "/host");
        assert_eq!(bind.destination, "/data");
        assert_eq!(bind.mode, "ro");
        assert!(!bind.rw);

        let volume = mount_point(&Mount {
            kind: MountType::Volume,
            source: Some("assets".to_owned()),
            target: "/srv".to_owned(),
            read_only: false,
        });
        assert_eq!(volume.kind, "volume");
        assert_eq!(volume.name.as_deref(), Some("assets"));
        assert!(volume.rw);

        let tmpfs = mount_point(&Mount {
            kind: MountType::Tmpfs,
            source: None,
            target: "/run".to_owned(),
            read_only: false,
        });
        assert_eq!(tmpfs.kind, "tmpfs");
        assert_eq!(tmpfs.name, None);
    }

    #[test]
    fn restart_policies_render_back_to_docker_names() {
        let cases = [
            (RestartCondition::None, "no"),
            (RestartCondition::OnFailure, "on-failure"),
            (RestartCondition::Any, "always"),
        ];
        for (condition, expected) in cases {
            let rendered = restart_policy_response(&satl_core::RestartPolicy {
                condition,
                max_attempts: 4,
                ..satl_core::RestartPolicy::default()
            });
            assert_eq!(rendered.name, expected);
            assert_eq!(rendered.maximum_retry_count, 4);
        }
    }

    #[test]
    fn platform_and_port_keys() {
        assert_eq!(
            platform_string(&Platform {
                os: "freebsd".to_owned(),
                arch: "amd64".to_owned()
            }),
            "freebsd/amd64"
        );
        assert_eq!(port_key(80, PortProtocol::Tcp), "80/tcp");
        assert_eq!(port_key(53, PortProtocol::Udp), "53/udp");
    }
}
