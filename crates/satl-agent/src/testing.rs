// SPDX-License-Identifier: BSD-2-Clause
//! Fixture builders shared by this crate's unit tests: minimal but *valid*
//! [`Task`]/[`ContainerSpec`]/[`ImageConfig`] values so each test only states
//! the field it cares about.

use std::collections::BTreeMap;

use satl_core::{
    Annotations, ContainerSpec, DesiredState, Id, Meta, Placement, ResourceRequirements,
    RestartPolicy, Task, TaskSpec, TaskState, TaskStatus,
};
use satl_image::{Digest, ImageConfig, Platform, PulledImage};

/// A fixed 25-char base36 task ID (the shape [`Id::generate`] produces), so
/// hostname-prefix assertions can be written literally.
pub(crate) const TASK_ID: &str = "1hvy0lj3x0b883f8e30fyp217";

/// The most boring valid container spec: an image reference and nothing else.
pub(crate) fn container_spec() -> ContainerSpec {
    ContainerSpec {
        image: "127.0.0.1:5000/satl-test/freebsd-nginx:latest".to_owned(),
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

/// An image config with the given entrypoint and cmd, nothing else set.
pub(crate) fn image_config(entrypoint: &[&str], cmd: &[&str]) -> ImageConfig {
    ImageConfig {
        env: Vec::new(),
        entrypoint: entrypoint.iter().map(|s| (*s).to_owned()).collect(),
        cmd: cmd.iter().map(|s| (*s).to_owned()).collect(),
        working_dir: None,
        user: None,
        exposed_ports: Vec::new(),
        os: "freebsd".to_owned(),
        architecture: "amd64".to_owned(),
    }
}

/// A [`PulledImage`] wrapping `config`, with no layers (planning never looks
/// at them).
pub(crate) fn pulled_image(config: ImageConfig, platform: Platform) -> PulledImage {
    PulledImage {
        reference: "127.0.0.1:5000/satl-test/freebsd-nginx:latest".to_owned(),
        manifest_digest: Digest::sha256_of(b"manifest"),
        config,
        platform,
        layers: Vec::new(),
        created: None,
    }
}

/// A task at [`TaskState::Assigned`] with desired [`DesiredState::Running`],
/// customized by `edit`.
pub(crate) fn task_with(edit: impl FnOnce(&mut TaskSpec)) -> Task {
    let mut spec = TaskSpec {
        container: container_spec(),
        resources: ResourceRequirements::default(),
        restart: RestartPolicy::default(),
        placement: Placement::default(),
        networks: Vec::new(),
        force_update: 0,
    };
    edit(&mut spec);
    Task {
        // Infallible: TASK_ID is a well-formed 25-char base36 ID.
        id: TASK_ID.parse::<Id>().expect("valid fixture task id"),
        meta: Meta::new(),
        spec,
        spec_version: None,
        service_id: None,
        slot: 1,
        node_id: None,
        annotations: Annotations {
            name: "web.1.1hvy0lj3x0b883f8e30fyp217".to_owned(),
            labels: BTreeMap::new(),
        },
        service_annotations: Annotations {
            name: "web".to_owned(),
            labels: BTreeMap::new(),
        },
        status: TaskStatus::new(TaskState::Assigned, "assigned"),
        desired_state: DesiredState::Running,
        networks: Vec::new(),
        endpoint: None,
        job_iteration: None,
    }
}

/// [`task_with`] with no customization.
pub(crate) fn task() -> Task {
    task_with(|_| {})
}
