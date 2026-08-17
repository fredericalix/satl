// SPDX-License-Identifier: BSD-2-Clause
#![allow(dead_code)]

//! A recording [`Backend`] double for the router tests.
//!
//! Every call is appended to a shared log the test can assert on, and every
//! answer is a canned value the test sets up front. Errors are injected with
//! [`MockBackend::failing`], which makes every method fail with the same
//! [`BackendError`] — enough to pin the whole error → status-code mapping.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use futures_util::stream::{self, BoxStream, StreamExt as _};
use satl_api::model::{
    BackendError, ChangeOutcome, ConfigCreated, ContainerInspect, ContainerSummary, Counts,
    CreateContainerOptions, CreateNetworkOptions, CreateVolumeOptions, CreatedContainer,
    EventMessage, ExecConfig, ExecId, ExecInspect, ExecStream, ImageSummary, LogFrame, LogOptions,
    NetworkConnectOptions, NetworkCreated, NetworkDetail, NetworkDisconnectOptions, NetworkSummary,
    NodeDetail, NodeSpecUpdate, NodeSummary, PrunedContainers, PrunedImages, PrunedNetworks,
    PrunedVolumes, PullProgressLine, RegistryAuth, Result, SecretCreated, ServiceCreateOptions,
    ServiceCreated, ServiceDetail, ServiceSummary, ServiceUpdateOptions, SwarmDetail,
    SwarmInitOptions, SwarmInitResult, SwarmJoinOptions, SwarmStatus, TaskDetail, TaskFilters,
    TaskSummary, TokenRole, VolumeInfo, WaitCondition, WaitResult,
};
use satl_api::{ApiState, Backend, SwarmInfo, SystemInfo, VersionInfo};
use satl_core::{Config, ConfigSpec, Platform, Secret, SecretSpec, Version};

/// One recorded backend call, with the arguments the router passed.
#[derive(Debug, Clone, PartialEq)]
pub enum Call {
    CreateContainer(Box<CreateContainerOptions>),
    StartContainer(String),
    StopContainer(String, Option<Duration>),
    KillContainer(String, String),
    RemoveContainer(String, bool, bool),
    ListContainers(bool),
    InspectContainer(String),
    WaitContainer(String, WaitCondition),
    ContainerLogs(String, LogOptions),
    PullImage(String, Option<RegistryAuth>, Option<Platform>),
    ListImages,
    /// `POST /images/{name}/tag`, carrying the source name and the joined
    /// target reference.
    TagImage(String, String),
    /// `POST /containers/prune`.
    PruneContainers,
    /// `POST /images/prune`, carrying whether `-a` reached the backend.
    PruneImages(bool),
    /// `POST /networks/prune`.
    PruneNetworks,
    /// `POST /volumes/prune`.
    PruneVolumes,
    CreateExec(String, ExecConfig),
    StartExec(String),
    InspectExec(String),
    CreateVolume(CreateVolumeOptions),
    ListVolumes,
    RemoveVolume(String, bool),
    ListNetworks,
    InspectNetwork(String),
    CreateNetwork(Box<CreateNetworkOptions>),
    RemoveNetwork(String),
    ConnectNetwork(String, NetworkConnectOptions),
    DisconnectNetwork(String, NetworkDisconnectOptions),
    Events(Option<SystemTime>),
    SystemCounts,
    SwarmInit(SwarmInitOptions),
    SwarmJoin(SwarmJoinOptions),
    SwarmLeave(bool),
    SwarmInspect,
    SwarmRotateToken(TokenRole),
    SwarmRotateCa(u64),
    SwarmSetAutolock(bool),
    SwarmUnlockKey,
    SwarmRotateUnlockKey,
    SwarmStatus,
    ListNodes,
    InspectNode(String),
    UpdateNode(String, Version, NodeSpecUpdate),
    RemoveNode(String, bool),
    CreateService(Box<ServiceCreateOptions>),
    ListServices,
    InspectService(String),
    UpdateService(String, Version, Box<ServiceUpdateOptions>),
    RemoveService(String),
    ListTasks(TaskFilters),
    InspectTask(String),
    CreateSecret(SecretSpec),
    ListSecrets,
    InspectSecret(String),
    RemoveSecret(String),
    CreateConfig(ConfigSpec),
    ListConfigs,
    InspectConfig(String),
    RemoveConfig(String),
}

/// Canned answers; anything not set falls back to an empty/default value.
#[derive(Debug, Default, Clone)]
pub struct Answers {
    pub error: Option<BackendError>,
    pub created: CreatedContainer,
    pub start: Option<ChangeOutcome>,
    pub stop: Option<ChangeOutcome>,
    pub containers: Vec<ContainerSummary>,
    pub inspect: Option<ContainerInspect>,
    pub wait: WaitResult,
    pub log_frames: Vec<LogFrame>,
    pub pull_lines: Vec<PullProgressLine>,
    pub images: Vec<ImageSummary>,
    pub exec_id: String,
    pub exec_frames: Vec<LogFrame>,
    pub exec_exit_code: i64,
    pub exec_inspect: Option<ExecInspect>,
    pub volumes: Vec<VolumeInfo>,
    pub networks: Vec<NetworkSummary>,
    pub network: Option<NetworkDetail>,
    pub network_created: NetworkCreated,
    pub events: Vec<EventMessage>,
    pub counts: Counts,
    pub swarm_node_id: String,
    pub swarm: Option<SwarmDetail>,
    pub swarm_status: Option<SwarmStatus>,
    pub unlock_key: String,
    pub nodes: Vec<NodeSummary>,
    pub node: Option<NodeDetail>,
    pub service_created: ServiceCreated,
    pub services: Vec<ServiceSummary>,
    pub service: Option<ServiceDetail>,
    pub service_warnings: Vec<String>,
    pub tasks: Vec<TaskSummary>,
    pub task: Option<TaskDetail>,
    pub secret_created: SecretCreated,
    pub secrets: Vec<Secret>,
    pub secret: Option<Secret>,
    pub config_created: ConfigCreated,
    pub configs: Vec<Config>,
    pub config: Option<Config>,
}

/// The recording backend itself.
#[derive(Debug, Clone)]
pub struct MockBackend {
    calls: Arc<Mutex<Vec<Call>>>,
    answers: Answers,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
    /// A backend that records calls and answers with defaults.
    pub fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            answers: Answers::default(),
        }
    }

    /// A backend whose every method fails with `error`.
    pub fn failing(error: BackendError) -> Self {
        let mut mock = Self::new();
        mock.answers.error = Some(error);
        mock
    }

    /// Edits the canned answers.
    pub fn answer(mut self, edit: impl FnOnce(&mut Answers)) -> Self {
        edit(&mut self.answers);
        self
    }

    /// Handle on the recorded calls, valid after the backend is moved into an
    /// [`ApiState`].
    pub fn recorder(&self) -> Recorder {
        Recorder {
            calls: Arc::clone(&self.calls),
        }
    }

    /// Builds an [`ApiState`] backed by this mock, plus its recorder.
    pub fn into_state(self) -> (ApiState, Recorder) {
        let recorder = self.recorder();
        (test_state().with_backend(Arc::new(self)), recorder)
    }

    fn record(&self, call: Call) {
        self.calls
            .lock()
            .expect("the call log is never poisoned in tests")
            .push(call);
    }

    /// Returns the injected error, if the test asked for one.
    fn injected<T>(&self) -> Option<Result<T>> {
        self.answers.error.clone().map(Err)
    }

    /// The canned cluster object, or Docker's worker refusal (`errNoManager`,
    /// moby `daemon/cluster/cluster.go`: a `notAvailableError`, i.e. 503).
    fn swarm_detail(&self) -> Result<SwarmDetail> {
        self.answers
            .swarm
            .clone()
            .ok_or_else(BackendError::not_a_swarm_manager)
    }
}

/// Read side of a [`MockBackend`]'s call log.
#[derive(Debug, Clone)]
pub struct Recorder {
    calls: Arc<Mutex<Vec<Call>>>,
}

impl Recorder {
    /// Every call recorded so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.calls
            .lock()
            .expect("the call log is never poisoned in tests")
            .clone()
    }

    /// The single call the test expects to have been recorded.
    pub fn only_call(&self) -> Call {
        let calls = self.calls();
        assert_eq!(
            calls.len(),
            1,
            "expected exactly one backend call: {calls:?}"
        );
        calls.into_iter().next().expect("length checked above")
    }
}

/// The daemon facts shared by every router test.
pub fn test_state() -> ApiState {
    ApiState::new(
        VersionInfo {
            version: "0.1.0".to_owned(),
            api_version: "1.43".to_owned(),
            min_api_version: "1.24".to_owned(),
            git_commit: "deadbeef".to_owned(),
            os: "freebsd".to_owned(),
            arch: "amd64".to_owned(),
            kernel_version: "15.1-RELEASE".to_owned(),
            build_time: "2026-08-09T00:00:00Z".to_owned(),
        },
        SystemInfo {
            id: "TEST:NODE:0001".to_owned(),
            name: "alpha".to_owned(),
            ncpu: 8,
            mem_total: 34_359_738_368,
            operating_system: "FreeBSD".to_owned(),
            os_version: "15.1-RELEASE".to_owned(),
            server_version: "0.1.0".to_owned(),
        },
        SwarmInfo {
            node_id: "1hvy0lj3x0b883f8e30fyp217".to_owned(),
            node_addr: String::new(),
            local_node_state: "active".to_owned(),
            control_available: true,
            error: String::new(),
            remote_managers: None,
        },
    )
}

#[async_trait]
impl Backend for MockBackend {
    async fn create_container(&self, options: CreateContainerOptions) -> Result<CreatedContainer> {
        self.record(Call::CreateContainer(Box::new(options)));
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.created.clone()))
    }

    async fn start_container(&self, id: &str) -> Result<ChangeOutcome> {
        self.record(Call::StartContainer(id.to_owned()));
        self.injected()
            .unwrap_or(Ok(self.answers.start.unwrap_or(ChangeOutcome::Changed)))
    }

    async fn stop_container(&self, id: &str, timeout: Option<Duration>) -> Result<ChangeOutcome> {
        self.record(Call::StopContainer(id.to_owned(), timeout));
        self.injected()
            .unwrap_or(Ok(self.answers.stop.unwrap_or(ChangeOutcome::Changed)))
    }

    async fn kill_container(&self, id: &str, signal: &str) -> Result<()> {
        self.record(Call::KillContainer(id.to_owned(), signal.to_owned()));
        self.injected().unwrap_or(Ok(()))
    }

    async fn remove_container(&self, id: &str, force: bool, remove_volumes: bool) -> Result<()> {
        self.record(Call::RemoveContainer(id.to_owned(), force, remove_volumes));
        self.injected().unwrap_or(Ok(()))
    }

    async fn list_containers(&self, all: bool) -> Result<Vec<ContainerSummary>> {
        self.record(Call::ListContainers(all));
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.containers.clone()))
    }

    async fn inspect_container(&self, id: &str) -> Result<ContainerInspect> {
        self.record(Call::InspectContainer(id.to_owned()));
        self.injected().unwrap_or_else(|| {
            self.answers
                .inspect
                .clone()
                .ok_or_else(|| BackendError::not_found(format!("no such container: {id}")))
        })
    }

    async fn wait_container(&self, id: &str, condition: WaitCondition) -> Result<WaitResult> {
        self.record(Call::WaitContainer(id.to_owned(), condition));
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.wait.clone()))
    }

    async fn container_logs(
        &self,
        id: &str,
        options: LogOptions,
    ) -> Result<BoxStream<'static, LogFrame>> {
        self.record(Call::ContainerLogs(id.to_owned(), options));
        self.injected()
            .unwrap_or_else(|| Ok(stream::iter(self.answers.log_frames.clone()).boxed()))
    }

    async fn pull_image(
        &self,
        reference: &str,
        auth: Option<RegistryAuth>,
        platform: Option<Platform>,
    ) -> Result<BoxStream<'static, PullProgressLine>> {
        self.record(Call::PullImage(reference.to_owned(), auth, platform));
        self.injected()
            .unwrap_or_else(|| Ok(stream::iter(self.answers.pull_lines.clone()).boxed()))
    }

    async fn list_images(&self) -> Result<Vec<ImageSummary>> {
        self.record(Call::ListImages);
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.images.clone()))
    }

    async fn tag_image(&self, source: &str, target: &str) -> Result<()> {
        self.record(Call::TagImage(source.to_owned(), target.to_owned()));
        self.injected().unwrap_or(Ok(()))
    }

    async fn prune_containers(&self) -> Result<PrunedContainers> {
        self.record(Call::PruneContainers);
        self.injected()
            .unwrap_or_else(|| Ok(PrunedContainers::default()))
    }

    async fn prune_images(&self, all: bool) -> Result<PrunedImages> {
        self.record(Call::PruneImages(all));
        self.injected()
            .unwrap_or_else(|| Ok(PrunedImages::default()))
    }

    async fn prune_networks(&self) -> Result<PrunedNetworks> {
        self.record(Call::PruneNetworks);
        self.injected()
            .unwrap_or_else(|| Ok(PrunedNetworks::default()))
    }

    async fn prune_volumes(&self) -> Result<PrunedVolumes> {
        self.record(Call::PruneVolumes);
        self.injected()
            .unwrap_or_else(|| Ok(PrunedVolumes::default()))
    }

    async fn create_exec(&self, container: &str, config: ExecConfig) -> Result<ExecId> {
        self.record(Call::CreateExec(container.to_owned(), config));
        self.injected()
            .unwrap_or_else(|| Ok(ExecId::new(self.answers.exec_id.clone())))
    }

    async fn start_exec(&self, exec_id: &str) -> Result<ExecStream> {
        self.record(Call::StartExec(exec_id.to_owned()));
        if let Some(injected) = self.injected() {
            return injected;
        }
        let (sender, exit) = tokio::sync::oneshot::channel();
        let _ = sender.send(self.answers.exec_exit_code);
        Ok(ExecStream {
            frames: stream::iter(self.answers.exec_frames.clone()).boxed(),
            exit,
        })
    }

    async fn inspect_exec(&self, exec_id: &str) -> Result<ExecInspect> {
        self.record(Call::InspectExec(exec_id.to_owned()));
        self.injected().unwrap_or_else(|| {
            self.answers
                .exec_inspect
                .clone()
                .ok_or_else(|| BackendError::not_found(format!("no such exec instance: {exec_id}")))
        })
    }

    async fn create_volume(&self, options: CreateVolumeOptions) -> Result<VolumeInfo> {
        self.record(Call::CreateVolume(options.clone()));
        self.injected().unwrap_or_else(|| {
            Ok(self.answers.volumes.first().cloned().unwrap_or(VolumeInfo {
                name: options.name,
                driver: options.driver,
                ..VolumeInfo::default()
            }))
        })
    }

    async fn list_volumes(&self) -> Result<Vec<VolumeInfo>> {
        self.record(Call::ListVolumes);
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.volumes.clone()))
    }

    async fn remove_volume(&self, name: &str, force: bool) -> Result<()> {
        self.record(Call::RemoveVolume(name.to_owned(), force));
        self.injected().unwrap_or(Ok(()))
    }

    async fn list_networks(&self) -> Result<Vec<NetworkSummary>> {
        self.record(Call::ListNetworks);
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.networks.clone()))
    }

    async fn inspect_network(&self, id_or_name: &str) -> Result<NetworkDetail> {
        self.record(Call::InspectNetwork(id_or_name.to_owned()));
        self.injected().unwrap_or_else(|| {
            self.answers
                .network
                .clone()
                .ok_or_else(|| BackendError::not_found(format!("network {id_or_name} not found")))
        })
    }

    async fn create_network(&self, options: CreateNetworkOptions) -> Result<NetworkCreated> {
        self.record(Call::CreateNetwork(Box::new(options)));
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.network_created.clone()))
    }

    async fn remove_network(&self, id_or_name: &str) -> Result<()> {
        self.record(Call::RemoveNetwork(id_or_name.to_owned()));
        self.injected().unwrap_or(Ok(()))
    }

    async fn connect_network(
        &self,
        id_or_name: &str,
        options: NetworkConnectOptions,
    ) -> Result<()> {
        self.record(Call::ConnectNetwork(id_or_name.to_owned(), options));
        self.injected().unwrap_or(Ok(()))
    }

    async fn disconnect_network(
        &self,
        id_or_name: &str,
        options: NetworkDisconnectOptions,
    ) -> Result<()> {
        self.record(Call::DisconnectNetwork(id_or_name.to_owned(), options));
        self.injected().unwrap_or(Ok(()))
    }

    async fn events(&self, since: Option<SystemTime>) -> Result<BoxStream<'static, EventMessage>> {
        self.record(Call::Events(since));
        self.injected()
            .unwrap_or_else(|| Ok(stream::iter(self.answers.events.clone()).boxed()))
    }

    async fn system_counts(&self) -> Result<Counts> {
        self.record(Call::SystemCounts);
        self.injected().unwrap_or(Ok(self.answers.counts))
    }

    async fn swarm_init(&self, options: SwarmInitOptions) -> Result<SwarmInitResult> {
        self.record(Call::SwarmInit(options));
        self.injected().unwrap_or_else(|| {
            Ok(SwarmInitResult {
                node_id: self.answers.swarm_node_id.clone(),
            })
        })
    }

    async fn swarm_join(&self, options: SwarmJoinOptions) -> Result<()> {
        self.record(Call::SwarmJoin(options));
        self.injected().unwrap_or(Ok(()))
    }

    async fn swarm_leave(&self, force: bool) -> Result<()> {
        self.record(Call::SwarmLeave(force));
        self.injected().unwrap_or(Ok(()))
    }

    async fn swarm_inspect(&self) -> Result<SwarmDetail> {
        self.record(Call::SwarmInspect);
        self.injected().unwrap_or_else(|| self.swarm_detail())
    }

    async fn swarm_rotate_token(&self, role: TokenRole) -> Result<SwarmDetail> {
        self.record(Call::SwarmRotateToken(role));
        self.injected().unwrap_or_else(|| self.swarm_detail())
    }

    async fn swarm_rotate_ca(&self, force_rotate: u64) -> Result<SwarmDetail> {
        self.record(Call::SwarmRotateCa(force_rotate));
        self.injected().unwrap_or_else(|| self.swarm_detail())
    }

    async fn swarm_set_autolock(&self, enabled: bool) -> Result<SwarmDetail> {
        self.record(Call::SwarmSetAutolock(enabled));
        self.injected().unwrap_or_else(|| self.swarm_detail())
    }

    async fn swarm_unlock_key(&self) -> Result<String> {
        self.record(Call::SwarmUnlockKey);
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.unlock_key.clone()))
    }

    async fn swarm_rotate_unlock_key(&self) -> Result<SwarmDetail> {
        self.record(Call::SwarmRotateUnlockKey);
        self.injected().unwrap_or_else(|| self.swarm_detail())
    }

    async fn swarm_status(&self) -> Result<SwarmStatus> {
        self.record(Call::SwarmStatus);
        self.injected().unwrap_or_else(|| {
            self.answers
                .swarm_status
                .clone()
                .ok_or_else(|| BackendError::not_implemented("no swarm status in this test"))
        })
    }

    async fn list_nodes(&self) -> Result<Vec<NodeSummary>> {
        self.record(Call::ListNodes);
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.nodes.clone()))
    }

    async fn inspect_node(&self, id_or_name: &str) -> Result<NodeDetail> {
        self.record(Call::InspectNode(id_or_name.to_owned()));
        self.injected().unwrap_or_else(|| {
            self.answers
                .node
                .clone()
                .ok_or_else(|| BackendError::not_found(format!("node {id_or_name} not found")))
        })
    }

    async fn update_node(&self, id: &str, version: Version, spec: NodeSpecUpdate) -> Result<()> {
        self.record(Call::UpdateNode(id.to_owned(), version, spec));
        self.injected().unwrap_or(Ok(()))
    }

    async fn remove_node(&self, id: &str, force: bool) -> Result<()> {
        self.record(Call::RemoveNode(id.to_owned(), force));
        self.injected().unwrap_or(Ok(()))
    }

    async fn create_service(&self, options: ServiceCreateOptions) -> Result<ServiceCreated> {
        self.record(Call::CreateService(Box::new(options)));
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.service_created.clone()))
    }

    async fn list_services(&self) -> Result<Vec<ServiceSummary>> {
        self.record(Call::ListServices);
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.services.clone()))
    }

    async fn inspect_service(&self, id_or_name: &str) -> Result<ServiceDetail> {
        self.record(Call::InspectService(id_or_name.to_owned()));
        self.injected().unwrap_or_else(|| {
            self.answers
                .service
                .clone()
                .ok_or_else(|| BackendError::not_found(format!("service {id_or_name} not found")))
        })
    }

    async fn update_service(
        &self,
        id: &str,
        version: Version,
        options: ServiceUpdateOptions,
    ) -> Result<Vec<String>> {
        self.record(Call::UpdateService(
            id.to_owned(),
            version,
            Box::new(options),
        ));
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.service_warnings.clone()))
    }

    async fn remove_service(&self, id_or_name: &str) -> Result<()> {
        self.record(Call::RemoveService(id_or_name.to_owned()));
        self.injected().unwrap_or(Ok(()))
    }

    async fn list_tasks(&self, filters: TaskFilters) -> Result<Vec<TaskSummary>> {
        self.record(Call::ListTasks(filters));
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.tasks.clone()))
    }

    async fn inspect_task(&self, id: &str) -> Result<TaskDetail> {
        self.record(Call::InspectTask(id.to_owned()));
        self.injected().unwrap_or_else(|| {
            self.answers
                .task
                .clone()
                .ok_or_else(|| BackendError::not_found(format!("task {id} not found")))
        })
    }

    async fn create_secret(&self, spec: SecretSpec) -> Result<SecretCreated> {
        self.record(Call::CreateSecret(spec));
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.secret_created.clone()))
    }

    async fn list_secrets(&self) -> Result<Vec<Secret>> {
        self.record(Call::ListSecrets);
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.secrets.clone()))
    }

    async fn inspect_secret(&self, id_or_name: &str) -> Result<Secret> {
        self.record(Call::InspectSecret(id_or_name.to_owned()));
        self.injected().unwrap_or_else(|| {
            self.answers
                .secret
                .clone()
                .ok_or_else(|| BackendError::not_found(format!("no such secret: {id_or_name}")))
        })
    }

    async fn remove_secret(&self, id_or_name: &str) -> Result<()> {
        self.record(Call::RemoveSecret(id_or_name.to_owned()));
        self.injected().unwrap_or(Ok(()))
    }

    async fn create_config(&self, spec: ConfigSpec) -> Result<ConfigCreated> {
        self.record(Call::CreateConfig(spec));
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.config_created.clone()))
    }

    async fn list_configs(&self) -> Result<Vec<Config>> {
        self.record(Call::ListConfigs);
        self.injected()
            .unwrap_or_else(|| Ok(self.answers.configs.clone()))
    }

    async fn inspect_config(&self, id_or_name: &str) -> Result<Config> {
        self.record(Call::InspectConfig(id_or_name.to_owned()));
        self.injected().unwrap_or_else(|| {
            self.answers
                .config
                .clone()
                .ok_or_else(|| BackendError::not_found(format!("no such config: {id_or_name}")))
        })
    }

    async fn remove_config(&self, id_or_name: &str) -> Result<()> {
        self.record(Call::RemoveConfig(id_or_name.to_owned()));
        self.injected().unwrap_or(Ok(()))
    }
}
