// SPDX-License-Identifier: BSD-2-Clause
//! `satl service create|ls|ps|inspect|scale|rm|update`.
//!
//! `create` builds a whole Docker `ServiceSpec` from the flags; `update` and
//! `scale` read the current spec, change one thing and send it back against
//! the version they read, exactly as `docker service update` does.

use std::collections::BTreeMap;

use crate::api::cluster::{
    Config, ConfigReference, ContainerSpec, EndpointSpec, FileTarget, Node, Placement, PortConfig,
    ResourceRequirements, Resources, Secret, SecretReference, Service, ServiceCreateResponse,
    ServiceMode, ServiceSpec, ServiceUpdateResponse, Task, TaskRestartPolicy, TaskTemplate,
    UpdateConfig,
};
use crate::client::{self, Host};
use crate::cmd::FAILURE;
use crate::format::{self, Table};
use crate::output::Streams;
use crate::parse;

/// Subcommands of `satl service`.
// `create` carries far more flags than the other verbs; the enum is built
// once per process, so the size difference costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, clap::Subcommand)]
pub enum ServiceCommand {
    /// Create a new service.
    Create(CreateArgs),
    /// List services.
    Ls(LsArgs),
    /// List the tasks of a service.
    Ps(PsArgs),
    /// Display detailed information on one or more services.
    Inspect(InspectArgs),
    /// Scale one or multiple replicated services.
    Scale(ScaleArgs),
    /// Remove one or more services.
    Rm(RmArgs),
    /// Update a service.
    Update(UpdateArgs),
}

/// Flags of `satl service create`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct CreateArgs {
    /// Service name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Number of tasks (replicated services only; on a replicated job it sets
    /// both `MaxConcurrent` and `TotalCompletions`, as Docker's CLI does).
    #[arg(long, value_name = "N")]
    pub replicas: Option<u64>,

    /// Service mode.
    #[arg(
        long,
        value_name = "MODE",
        value_parser = ["replicated", "global", "replicated-job", "global-job"]
    )]
    pub mode: Option<String>,

    /// Maximum number of job tasks live at once (replicated-job only).
    #[arg(long, value_name = "N")]
    pub max_concurrent: Option<u64>,

    /// Total completions that finish a replicated job (replicated-job only).
    #[arg(long, value_name = "N")]
    pub total_completions: Option<u64>,

    /// Publish a port as a node port (`[published:]target[/protocol]`).
    #[arg(short, long, value_name = "PORT")]
    pub publish: Vec<String>,

    /// Set environment variables.
    #[arg(short, long, value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Service labels.
    #[arg(short, long, value_name = "KEY=VALUE")]
    pub label: Vec<String>,

    /// Placement constraints.
    #[arg(long, value_name = "EXPR")]
    pub constraint: Vec<String>,

    /// Soft placement preference (`spread=node.labels.zone`); repeatable,
    /// applied in order.
    #[arg(long = "placement-pref", value_name = "PREF")]
    pub placement_pref: Vec<String>,

    /// Limit CPUs.
    #[arg(long = "limit-cpu", value_name = "VALUE")]
    pub limit_cpu: Option<String>,

    /// Limit memory.
    #[arg(long = "limit-memory", value_name = "BYTES")]
    pub limit_memory: Option<String>,

    /// Reserve CPUs.
    #[arg(long = "reserve-cpu", value_name = "VALUE")]
    pub reserve_cpu: Option<String>,

    /// Reserve memory.
    #[arg(long = "reserve-memory", value_name = "BYTES")]
    pub reserve_memory: Option<String>,

    /// Restart when a condition is met.
    #[arg(
        long = "restart-condition",
        value_name = "CONDITION",
        value_parser = ["none", "on-failure", "any"]
    )]
    pub restart_condition: Option<String>,

    /// Network attachments.
    #[arg(long, value_name = "NETWORK")]
    pub network: Vec<String>,

    /// Give the tasks a secret, delivered as one file: NAME, or
    /// source=NAME[,target=FILE][,uid=UID][,gid=GID][,mode=0444].
    #[arg(long, value_name = "SECRET")]
    pub secret: Vec<String>,

    /// Give the tasks a config file, in the same forms as --secret.
    #[arg(long, value_name = "CONFIG")]
    pub config: Vec<String>,

    /// Rolling-update and rollback policy.
    #[command(flatten)]
    pub policy: PolicyArgs,

    /// Image to run.
    #[arg(value_name = "IMAGE")]
    pub image: String,

    /// Command and arguments to run inside the container.
    #[arg(
        value_name = "COMMAND",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub command: Vec<String>,
}

/// The `--update-*` and `--rollback-*` flags, flattened into both
/// `satl service create` and `satl service update`.
///
/// One struct rather than two copies, because Docker spells the flags
/// identically on both verbs and because the contract of the group is that an
/// **unset flag changes nothing**: twelve `Option`s written out twice is two
/// places to get that wrong. Names, value spellings and defaults are Docker's,
/// read from `docker service create --help` / `docker service update --help`
/// (docker 29.4.2) rather than remembered.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct PolicyArgs {
    /// Maximum number of tasks updated simultaneously (0 to update all at once).
    #[arg(long = "update-parallelism", value_name = "N")]
    pub update_parallelism: Option<u64>,

    /// Delay between updates (`1m30s`, `10s`).
    #[arg(long = "update-delay", value_name = "DURATION")]
    pub update_delay: Option<String>,

    /// Action on update failure.
    #[arg(
        long = "update-failure-action",
        value_name = "ACTION",
        value_parser = ["pause", "continue", "rollback"]
    )]
    pub update_failure_action: Option<String>,

    /// Duration after each task update to monitor for failure.
    #[arg(long = "update-monitor", value_name = "DURATION")]
    pub update_monitor: Option<String>,

    /// Failure rate to tolerate during an update (0 to 1).
    #[arg(long = "update-max-failure-ratio", value_name = "RATIO")]
    pub update_max_failure_ratio: Option<f32>,

    /// Update order.
    #[arg(
        long = "update-order",
        value_name = "ORDER",
        value_parser = ["start-first", "stop-first"]
    )]
    pub update_order: Option<String>,

    /// Maximum number of tasks rolled back simultaneously (0 to roll back all
    /// at once).
    #[arg(long = "rollback-parallelism", value_name = "N")]
    pub rollback_parallelism: Option<u64>,

    /// Delay between task rollbacks (`1m30s`, `10s`).
    #[arg(long = "rollback-delay", value_name = "DURATION")]
    pub rollback_delay: Option<String>,

    /// Action on rollback failure. A rollback never rolls back: `rollback` is
    /// not a value here, exactly as in docker.
    #[arg(
        long = "rollback-failure-action",
        value_name = "ACTION",
        value_parser = ["pause", "continue"]
    )]
    pub rollback_failure_action: Option<String>,

    /// Duration after each task rollback to monitor for failure.
    #[arg(long = "rollback-monitor", value_name = "DURATION")]
    pub rollback_monitor: Option<String>,

    /// Failure rate to tolerate during a rollback (0 to 1).
    #[arg(long = "rollback-max-failure-ratio", value_name = "RATIO")]
    pub rollback_max_failure_ratio: Option<f32>,

    /// Rollback order.
    #[arg(
        long = "rollback-order",
        value_name = "ORDER",
        value_parser = ["start-first", "stop-first"]
    )]
    pub rollback_order: Option<String>,
}

/// One half of a [`PolicyArgs`] — the six `--update-*` flags or the six
/// `--rollback-*` ones — so both halves share one applier.
struct PolicyFlags<'a> {
    /// `update` or `rollback`, for error messages.
    what: &'a str,
    parallelism: Option<u64>,
    delay: Option<&'a str>,
    failure_action: Option<&'a str>,
    monitor: Option<&'a str>,
    max_failure_ratio: Option<f32>,
    order: Option<&'a str>,
}

impl PolicyArgs {
    /// The `--update-*` half.
    fn update(&self) -> PolicyFlags<'_> {
        PolicyFlags {
            what: "update",
            parallelism: self.update_parallelism,
            delay: self.update_delay.as_deref(),
            failure_action: self.update_failure_action.as_deref(),
            monitor: self.update_monitor.as_deref(),
            max_failure_ratio: self.update_max_failure_ratio,
            order: self.update_order.as_deref(),
        }
    }

    /// The `--rollback-*` half.
    fn rollback(&self) -> PolicyFlags<'_> {
        PolicyFlags {
            what: "rollback",
            parallelism: self.rollback_parallelism,
            delay: self.rollback_delay.as_deref(),
            failure_action: self.rollback_failure_action.as_deref(),
            monitor: self.rollback_monitor.as_deref(),
            max_failure_ratio: self.rollback_max_failure_ratio,
            order: self.rollback_order.as_deref(),
        }
    }
}

impl PolicyFlags<'_> {
    /// Whether the operator named any flag of this half.
    fn given(&self) -> bool {
        self.parallelism.is_some()
            || self.delay.is_some()
            || self.failure_action.is_some()
            || self.monitor.is_some()
            || self.max_failure_ratio.is_some()
            || self.order.is_some()
    }

    /// Writes the flags that were given into `config`, and **only** those.
    ///
    /// This is the whole point of the group. `satl service update` reads the
    /// stored spec, edits it and posts it back, so a field this does not touch
    /// keeps the value the service already had; a field written from a default
    /// would overwrite the operator's own policy with the daemon's. `config` is
    /// created only when there was none and at least one flag asks for one.
    fn apply(&self, config: &mut Option<UpdateConfig>) -> anyhow::Result<()> {
        if !self.given() {
            return Ok(());
        }
        let config = config.get_or_insert_with(UpdateConfig::docker_defaults);
        if let Some(parallelism) = self.parallelism {
            config.parallelism = parallelism;
        }
        if let Some(delay) = self.delay {
            config.delay = parse_duration(delay)?;
        }
        if let Some(action) = self.failure_action {
            action.clone_into(&mut config.failure_action);
        }
        if let Some(monitor) = self.monitor {
            config.monitor = parse_duration(monitor)?;
        }
        if let Some(ratio) = self.max_failure_ratio {
            if !(0.0..=1.0).contains(&ratio) {
                anyhow::bail!(
                    "invalid --{}-max-failure-ratio {ratio}: expected a fraction between 0 and 1",
                    self.what
                );
            }
            config.max_failure_ratio = ratio;
        }
        if let Some(order) = self.order {
            order.clone_into(&mut config.order);
        }
        Ok(())
    }
}

/// Flags of `satl service ls`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct LsArgs {
    /// Only display IDs.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Flags of `satl service ps`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct PsArgs {
    /// Don't truncate output.
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,

    /// Only display task IDs.
    #[arg(short, long)]
    pub quiet: bool,

    /// Services whose tasks to list.
    #[arg(required = true, value_name = "SERVICE")]
    pub services: Vec<String>,
}

/// Flags of `satl service inspect`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct InspectArgs {
    /// Print the information in a human friendly format.
    #[arg(long)]
    pub pretty: bool,

    /// Services to inspect.
    #[arg(required = true, value_name = "SERVICE")]
    pub services: Vec<String>,
}

/// Flags of `satl service scale`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct ScaleArgs {
    /// `SERVICE=REPLICAS` pairs.
    #[arg(required = true, value_name = "SERVICE=REPLICAS")]
    pub scales: Vec<String>,
}

/// Flags of `satl service rm`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RmArgs {
    /// Services to remove.
    #[arg(required = true, value_name = "SERVICE")]
    pub services: Vec<String>,
}

/// Flags of `satl service update`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct UpdateArgs {
    /// Service image tag.
    #[arg(long, value_name = "IMAGE")]
    pub image: Option<String>,

    /// Number of tasks.
    #[arg(long, value_name = "N")]
    pub replicas: Option<u64>,

    /// Add or update a placement constraint.
    #[arg(long = "constraint-add", value_name = "EXPR")]
    pub constraint_add: Vec<String>,

    /// Remove a placement constraint.
    #[arg(long = "constraint-rm", value_name = "EXPR")]
    pub constraint_rm: Vec<String>,

    /// Add a placement preference (`spread=node.labels.zone`).
    #[arg(long = "placement-pref-add", value_name = "PREF")]
    pub placement_pref_add: Vec<String>,

    /// Remove a placement preference by descriptor (`node.labels.zone`).
    #[arg(long = "placement-pref-rm", value_name = "DESCRIPTOR")]
    pub placement_pref_rm: Vec<String>,

    /// Add or update a service label.
    #[arg(long = "label-add", value_name = "KEY=VALUE")]
    pub label_add: Vec<String>,

    /// Remove a service label.
    #[arg(long = "label-rm", value_name = "KEY")]
    pub label_rm: Vec<String>,

    /// Limit CPUs. `0` clears the limit. A resources-only update is a
    /// hot resize — the live tasks are not replaced.
    #[arg(long = "limit-cpu", value_name = "VALUE")]
    pub limit_cpu: Option<String>,

    /// Limit memory. `0` clears the limit.
    #[arg(long = "limit-memory", value_name = "BYTES")]
    pub limit_memory: Option<String>,

    /// Reserve CPUs. `0` clears the reservation.
    #[arg(long = "reserve-cpu", value_name = "VALUE")]
    pub reserve_cpu: Option<String>,

    /// Reserve memory. `0` clears the reservation.
    #[arg(long = "reserve-memory", value_name = "BYTES")]
    pub reserve_memory: Option<String>,

    /// Rolling-update and rollback policy. A flag left out keeps whatever the
    /// service already has.
    #[command(flatten)]
    pub policy: PolicyArgs,

    /// The service to update.
    #[arg(value_name = "SERVICE")]
    pub service: String,
}

/// Dispatch a `satl service` subcommand.
pub async fn execute(
    host: &Host,
    command: &ServiceCommand,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    match command {
        ServiceCommand::Create(args) => create(host, args, streams).await,
        ServiceCommand::Ls(args) => {
            let services: Vec<Service> = client::get_json(host, "/services?status=true").await?;
            streams.out(render_ls(&services, args).as_bytes()).await;
            Ok(0)
        }
        ServiceCommand::Ps(args) => ps(host, args, streams).await,
        ServiceCommand::Inspect(args) => inspect(host, args, streams).await,
        ServiceCommand::Scale(args) => scale(host, args, streams).await,
        ServiceCommand::Rm(args) => remove(host, args, streams).await,
        ServiceCommand::Update(args) => {
            let warnings = update(host, &args.service, |spec| apply(spec, args)).await?;
            for warning in &warnings {
                streams.warn(warning).await;
            }
            streams.outln(&args.service).await;
            Ok(0)
        }
    }
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

/// `satl service create`: resolve the secret/config names to store IDs, then
/// post the spec.
///
/// The resolution is the impure half — one list request per kind — kept out of
/// [`create_spec`] the way `satl run` keeps `--env-file` reading out of its body
/// builder. Docker's own client resolves names client-side too, so the stored
/// spec carries both the ID the daemon dereferences and the name the operator
/// typed.
async fn create(host: &Host, args: &CreateArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let secrets = parse_refs(&args.secret, parse::parse_secret_ref)?;
    let configs = parse_refs(&args.config, parse::parse_config_ref)?;
    let secret_ids = resolve_ids::<Secret, _>(host, "/secrets", "secret", &secrets, |secret| {
        (secret.id.as_str(), secret.spec.name.as_str())
    })
    .await?;
    let config_ids = resolve_ids::<Config, _>(host, "/configs", "config", &configs, |config| {
        (config.id.as_str(), config.spec.name.as_str())
    })
    .await?;

    let spec = create_spec(args, &secret_ids, &config_ids)?;
    let created: ServiceCreateResponse =
        client::post_json(host, "/services/create", Some(&spec)).await?;
    for warning in &created.warnings {
        streams.warn(warning).await;
    }
    streams.outln(&created.id).await;
    Ok(0)
}

/// Parse every `--secret`/`--config` value, failing on the first bad one.
fn parse_refs<F>(values: &[String], parse_one: F) -> anyhow::Result<Vec<parse::FileRef>>
where
    F: Fn(&str) -> anyhow::Result<parse::FileRef>,
{
    values.iter().map(|value| parse_one(value)).collect()
}

/// Map each named source to its store ID with one list request; a name with no
/// object behind it fails before anything is created.
async fn resolve_ids<T, F>(
    host: &Host,
    path: &str,
    kind: &str,
    refs: &[parse::FileRef],
    entry: F,
) -> anyhow::Result<BTreeMap<String, String>>
where
    T: serde::de::DeserializeOwned,
    F: Fn(&T) -> (&str, &str),
{
    if refs.is_empty() {
        return Ok(BTreeMap::new());
    }
    let stored: Vec<T> = client::get_json(host, path).await?;
    let mut ids = BTreeMap::new();
    for reference in refs {
        let id = stored
            .iter()
            .map(&entry)
            .find_map(|(id, name)| (name == reference.source).then(|| id.to_owned()))
            .ok_or_else(|| anyhow::anyhow!("{kind} not found: {}", reference.source))?;
        ids.insert(reference.source.clone(), id);
    }
    Ok(ids)
}

/// The `Mode` `satl service create` asks for: the two keep-alive modes and
/// the two run-to-completion ones. On a replicated job, `--replicas N` maps
/// onto both of Docker's knobs (N completions, up to N live at once), which
/// is what Docker's own CLI does; `--max-concurrent`/`--total-completions`
/// set the knobs individually.
fn create_mode(args: &CreateArgs) -> anyhow::Result<ServiceMode> {
    if args.replicas.is_some() && matches!(args.mode.as_deref(), Some("global" | "global-job")) {
        anyhow::bail!(
            "--replicas can only be used with the replicated or replicated-job service mode"
        );
    }
    if (args.max_concurrent.is_some() || args.total_completions.is_some())
        && args.mode.as_deref() != Some("replicated-job")
    {
        anyhow::bail!("--max-concurrent and --total-completions require --mode replicated-job");
    }
    if args.replicas.is_some()
        && (args.max_concurrent.is_some() || args.total_completions.is_some())
    {
        anyhow::bail!("--replicas cannot be combined with --max-concurrent/--total-completions");
    }
    Ok(match args.mode.as_deref() {
        Some("global") => ServiceMode::global(),
        Some("replicated-job") => ServiceMode::replicated_job(
            args.max_concurrent.or(args.replicas),
            args.total_completions.or(args.replicas),
        ),
        Some("global-job") => ServiceMode::global_job(),
        _ => ServiceMode::replicated(args.replicas.unwrap_or(1)),
    })
}

/// The reservations `--reserve-cpu`/`--reserve-memory` describe, parsed the way
/// update's `Dimension::Reservations` is: `0` on both means no reservation at
/// all, not an empty object.
fn create_reservations(args: &CreateArgs) -> anyhow::Result<Option<Resources>> {
    match (&args.reserve_cpu, &args.reserve_memory) {
        (None, None) => Ok(None),
        (cpu, memory) => {
            let nano_cpus = match cpu.as_deref() {
                Some("0") | None => 0,
                Some(value) => parse::parse_nano_cpus(value)?,
            };
            let memory_bytes = match memory.as_deref() {
                Some("0") | None => 0,
                Some(value) => parse::parse_memory(value)?,
            };
            Ok((nano_cpus > 0 || memory_bytes > 0).then_some(Resources {
                nano_cpus,
                memory_bytes,
            }))
        }
    }
}

/// Build the `ServiceSpec` `satl service create` posts (pure, for goldens).
///
/// `secret_ids`/`config_ids` map a source name to the store ID [`create`]
/// resolved; a name that is missing from them yields an empty ID, which is what
/// the flag-matrix tests exercise.
pub fn create_spec(
    args: &CreateArgs,
    secret_ids: &BTreeMap<String, String>,
    config_ids: &BTreeMap<String, String>,
) -> anyhow::Result<ServiceSpec> {
    let mode = create_mode(args)?;

    let mut labels = BTreeMap::new();
    for label in &args.label {
        let (key, value) = parse::parse_label(label)?;
        labels.insert(key, value);
    }

    let mut ports = Vec::new();
    for publish in &args.publish {
        let spec = parse::parse_publish(publish)?;
        ports.push(PortConfig {
            protocol: spec.protocol.clone(),
            target_port: u32::from(spec.container_port),
            published_port: u32::from(spec.host_port.unwrap_or(0)),
            publish_mode: "ingress".to_owned(),
            rest: serde_json::Map::new(),
        });
    }

    let limits = match (&args.limit_cpu, &args.limit_memory) {
        (None, None) => None,
        (cpu, memory) => Some(Resources {
            nano_cpus: cpu
                .as_deref()
                .map(parse::parse_nano_cpus)
                .transpose()?
                .unwrap_or(0),
            memory_bytes: memory
                .as_deref()
                .map(parse::parse_memory)
                .transpose()?
                .unwrap_or(0),
        }),
    };
    // Same shape as limits, except a `0` on both means no reservation at all,
    // not an empty object — there is nothing stored to clear at create time.
    let reservations = create_reservations(args)?;

    let secrets = secret_refs(&args.secret, secret_ids)?;
    let configs = config_refs(&args.config, config_ids)?;
    let preferences = args
        .placement_pref
        .iter()
        .map(|pref| parse_placement_pref(pref))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // No flag means no policy in the spec at all, so the daemon's defaults
    // apply and are visible as such in `service inspect` — rather than a spec
    // that spells out values the operator never chose.
    let mut update_config = None;
    let mut rollback_config = None;
    args.policy.update().apply(&mut update_config)?;
    args.policy.rollback().apply(&mut rollback_config)?;

    Ok(ServiceSpec {
        name: args.name.clone().unwrap_or_default(),
        labels,
        task_template: TaskTemplate {
            container_spec: ContainerSpec {
                image: args.image.clone(),
                args: args.command.clone(),
                env: args.env.clone(),
                secrets,
                configs,
                ..ContainerSpec::default()
            },
            resources: (limits.is_some() || reservations.is_some()).then_some(
                ResourceRequirements {
                    limits,
                    reservations,
                },
            ),
            restart_policy: args
                .restart_condition
                .as_ref()
                .map(|condition| TaskRestartPolicy {
                    condition: condition.clone(),
                    ..TaskRestartPolicy::default()
                }),
            placement: (!args.constraint.is_empty() || !preferences.is_empty()).then(|| {
                Placement {
                    constraints: args.constraint.clone(),
                    max_replicas: 0,
                    preferences,
                    rest: serde_json::Map::new(),
                }
            }),
            networks: args
                .network
                .iter()
                .map(|target| crate::api::cluster::NetworkAttachmentConfig {
                    target: target.clone(),
                    // `--network` takes no alias: a service is reachable by its
                    // own name (api-compat 73). `satl compose` is the caller
                    // that fills these in.
                    aliases: Vec::new(),
                })
                .collect(),
            rest: serde_json::Map::new(),
        },
        mode,
        update_config,
        rollback_config,
        endpoint_spec: (!ports.is_empty()).then_some(EndpointSpec {
            ports,
            rest: serde_json::Map::new(),
        }),
    })
}

/// The `Secrets` list of a container spec, from the `--secret` values.
/// One `--placement-pref` value: `spread=<descriptor>` — the only strategy
/// Docker has, and the only one SatL implements (M7d).
fn parse_placement_pref(value: &str) -> anyhow::Result<crate::api::cluster::PlacementPreference> {
    let Some(descriptor) = value.strip_prefix("spread=") else {
        anyhow::bail!("invalid placement preference {value:?}: only spread=<descriptor> exists");
    };
    Ok(crate::api::cluster::PlacementPreference {
        spread: Some(crate::api::cluster::SpreadPreference {
            spread_descriptor: descriptor.to_owned(),
        }),
    })
}

fn secret_refs(
    values: &[String],
    ids: &BTreeMap<String, String>,
) -> anyhow::Result<Vec<SecretReference>> {
    let mut refs = Vec::new();
    for value in values {
        let reference = parse::parse_secret_ref(value)?;
        refs.push(SecretReference {
            file: file_target(&reference),
            secret_id: ids.get(&reference.source).cloned().unwrap_or_default(),
            secret_name: reference.source,
        });
    }
    Ok(refs)
}

/// The `Configs` list of a container spec, from the `--config` values.
fn config_refs(
    values: &[String],
    ids: &BTreeMap<String, String>,
) -> anyhow::Result<Vec<ConfigReference>> {
    let mut refs = Vec::new();
    for value in values {
        let reference = parse::parse_config_ref(value)?;
        refs.push(ConfigReference {
            file: file_target(&reference),
            config_id: ids.get(&reference.source).cloned().unwrap_or_default(),
            config_name: reference.source,
        });
    }
    Ok(refs)
}

/// The `File` half of a secret/config reference: where the payload lands and
/// who owns it.
fn file_target(reference: &parse::FileRef) -> FileTarget {
    FileTarget {
        name: reference.target.clone(),
        uid: reference.uid.clone(),
        gid: reference.gid.clone(),
        mode: reference.mode,
    }
}

/// Parse docker's Go duration strings (`10s`, `1m30s`, `500ms`) into the
/// nanoseconds the service spec carries.
pub fn parse_duration(value: &str) -> anyhow::Result<i64> {
    let invalid = || anyhow::anyhow!("invalid duration {value:?}: expected e.g. 10s, 1m30s, 500ms");
    let raw = value.trim();
    if raw.is_empty() {
        return Err(invalid());
    }
    let mut total: i64 = 0;
    let mut digits = String::new();
    let mut unit = String::new();
    let mut saw_unit = false;
    for ch in raw.chars() {
        if ch.is_ascii_digit() && unit.is_empty() {
            digits.push(ch);
        } else if ch.is_ascii_digit() {
            total += duration_part(&digits, &unit).ok_or_else(invalid)?;
            digits.clear();
            digits.push(ch);
            unit.clear();
        } else {
            saw_unit = true;
            unit.push(ch);
        }
    }
    if digits.is_empty() || !saw_unit {
        return Err(invalid());
    }
    total += duration_part(&digits, &unit).ok_or_else(invalid)?;
    Ok(total)
}

/// One `<number><unit>` pair of a Go duration, in nanoseconds.
fn duration_part(digits: &str, unit: &str) -> Option<i64> {
    let value: i64 = digits.parse().ok()?;
    let multiplier = match unit {
        "ns" => 1,
        "us" | "µs" => 1_000,
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        "m" => 60 * 1_000_000_000,
        "h" => 3_600 * 1_000_000_000,
        _ => return None,
    };
    value.checked_mul(multiplier)
}

// ---------------------------------------------------------------------------
// ls / ps / inspect
// ---------------------------------------------------------------------------

/// Render `service ls` (pure, for goldens).
pub fn render_ls(services: &[Service], args: &LsArgs) -> String {
    if args.quiet {
        let mut out = String::new();
        for service in services {
            out.push_str(&format::truncate_id(&service.id));
            out.push('\n');
        }
        return out;
    }

    let mut table = Table::new(&["ID", "NAME", "MODE", "REPLICAS", "IMAGE", "PORTS"]);
    for service in services {
        table.push(vec![
            format::truncate_id(&service.id),
            service.spec.name.clone(),
            service.spec.mode.name().to_owned(),
            replicas_cell(service),
            service.spec.task_template.container_spec.image.clone(),
            service_ports(&service.endpoint.ports),
        ]);
    }
    table.render()
}

/// The `REPLICAS` cell: `running/desired`, from `ServiceStatus` when the
/// daemon sent it, from the spec otherwise.
fn replicas_cell(service: &Service) -> String {
    match service.service_status {
        Some(status) => format!("{}/{}", status.running_tasks, status.desired_tasks),
        None => match service.spec.mode.replicas() {
            Some(desired) => format!("0/{desired}"),
            None => "0/0".to_owned(),
        },
    }
}

/// The `PORTS` cell of `service ls`: docker's `*:published->target/proto`.
fn service_ports(ports: &[PortConfig]) -> String {
    ports
        .iter()
        .filter(|port| port.published_port != 0)
        .map(|port| {
            let proto = if port.protocol.is_empty() {
                "tcp"
            } else {
                &port.protocol
            };
            format!("*:{}->{}/{proto}", port.published_port, port.target_port)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

async fn ps(host: &Host, args: &PsArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut tasks: Vec<Task> = Vec::new();
    let mut failed = false;
    for service in &args.services {
        let filters = serde_json::json!({"service": {service: true}}).to_string();
        let path = format!("/tasks{}", client::query(&[("filters", filters.as_str())]));
        match client::get_json::<Vec<Task>>(host, &path).await {
            Ok(found) => tasks.extend(found),
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    // Docker shows hostnames in the NODE column; the node list is the only
    // place that maps a node ID to one.
    let nodes: Vec<Node> = client::get_json(host, "/nodes").await.unwrap_or_default();
    let hostnames: BTreeMap<String, String> = nodes
        .iter()
        .map(|node| (node.id.clone(), node.display_name().to_owned()))
        .collect();
    streams
        .out(render_ps(&tasks, &hostnames, args, format::now_unix()).as_bytes())
        .await;
    Ok(if failed { FAILURE } else { 0 })
}

/// Render `service ps` (pure: the clock is injected so goldens are stable).
pub fn render_ps(
    tasks: &[Task],
    hostnames: &BTreeMap<String, String>,
    args: &PsArgs,
    now_unix: i64,
) -> String {
    if args.quiet {
        let mut out = String::new();
        for task in tasks {
            out.push_str(&id_cell(&task.id, args.no_trunc));
            out.push('\n');
        }
        return out;
    }

    let mut table = Table::new(&[
        "ID",
        "NAME",
        "IMAGE",
        "NODE",
        "DESIRED STATE",
        "CURRENT STATE",
        "ERROR",
        "PORTS",
    ]);
    for task in tasks {
        table.push(vec![
            id_cell(&task.id, args.no_trunc),
            task_name(task),
            task.spec.container_spec.image.clone(),
            hostnames
                .get(&task.node_id)
                .cloned()
                .unwrap_or_else(|| task.node_id.clone()),
            format::capitalize(&task.desired_state),
            current_state(task, now_unix),
            task.status.err.clone(),
            service_ports(&task.status.port_status.ports),
        ]);
    }
    table.render()
}

fn id_cell(id: &str, no_trunc: bool) -> String {
    if no_trunc {
        id.to_owned()
    } else {
        format::truncate_id(id)
    }
}

/// The `NAME` cell: docker prints `<service>.<slot>` for the task name it got
/// from the daemon, dropping the task-ID suffix.
fn task_name(task: &Task) -> String {
    match task.name.rsplit_once('.') {
        Some((prefix, _)) if !prefix.is_empty() => prefix.to_owned(),
        _ => task.name.clone(),
    }
}

/// The `CURRENT STATE` cell: `Running 3 minutes ago`.
fn current_state(task: &Task, now_unix: i64) -> String {
    let state = format::capitalize(&task.status.state);
    match format::parse_rfc3339_seconds(&task.status.timestamp) {
        Some(seconds) => format!("{state} {}", format::created_ago(seconds, now_unix)),
        None => state,
    }
}

async fn inspect(host: &Host, args: &InspectArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut failed = false;
    let mut raw: Vec<serde_json::Value> = Vec::new();
    let mut pretty_out = String::new();
    for reference in &args.services {
        let path = format!("/services/{reference}");
        match client::get_json::<serde_json::Value>(host, &path).await {
            Ok(value) => {
                if args.pretty {
                    match serde_json::from_value::<Service>(value) {
                        Ok(service) => pretty_out.push_str(&pretty(&service)),
                        Err(err) => {
                            streams.error(&format!("{err:#}")).await;
                            failed = true;
                        }
                    }
                } else {
                    raw.push(value);
                }
            }
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    if args.pretty {
        streams.out(pretty_out.as_bytes()).await;
    } else {
        streams.outln(&crate::cmd::inspect::render(&raw)).await;
    }
    Ok(if failed { FAILURE } else { 0 })
}

/// `satl service inspect --pretty` (pure, for goldens).
// Writing into a `String` is infallible; the `let _` discards a `fmt::Result`
// that cannot be an error.
pub fn pretty(service: &Service) -> String {
    use std::fmt::Write as _;

    let spec = &service.spec;
    let mut out = String::new();
    let _ = writeln!(out, "ID:\t\t{}", service.id);
    let _ = writeln!(out, "Name:\t\t{}", spec.name);
    if !spec.labels.is_empty() {
        out.push_str("Labels:\n");
        for (key, value) in &spec.labels {
            let _ = writeln!(out, " {key}={value}");
        }
    }
    let _ = writeln!(out, "Service Mode:\t{}", spec.mode.name());
    if let Some(replicas) = spec.mode.replicas() {
        let _ = writeln!(out, " Replicas:\t{replicas}");
    }
    out.push_str("ContainerSpec:\n");
    let _ = writeln!(
        out,
        " Image:\t\t{}",
        spec.task_template.container_spec.image
    );
    if !spec.task_template.container_spec.args.is_empty() {
        let _ = writeln!(
            out,
            " Args:\t\t{}",
            spec.task_template.container_spec.args.join(" ")
        );
    }
    if let Some(placement) = &spec.task_template.placement
        && !placement.constraints.is_empty()
    {
        out.push_str("Placement:\n");
        let _ = writeln!(out, " Constraints:\t{}", placement.constraints.join(", "));
    }
    if let Some(resources) = spec.task_template.resources.and_then(|r| r.limits) {
        out.push_str("Resources:\n");
        if resources.nano_cpus != 0 {
            // Display only: CPU limits never approach f64's mantissa.
            #[allow(clippy::cast_precision_loss)]
            let cpus = resources.nano_cpus as f64 / 1e9;
            let _ = writeln!(out, " Limits:\n  CPU:\t\t{cpus}");
        }
        if resources.memory_bytes != 0 {
            let _ = writeln!(
                out,
                "  Memory:\t{}",
                format::human_size(resources.memory_bytes)
            );
        }
    }
    let ports = service_ports(&service.endpoint.ports);
    if !ports.is_empty() {
        let _ = writeln!(out, "Ports:\n {ports}");
    }
    out
}

// ---------------------------------------------------------------------------
// scale / rm / update
// ---------------------------------------------------------------------------

async fn scale(host: &Host, args: &ScaleArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut failed = false;
    for pair in &args.scales {
        let (reference, replicas) = match parse_scale(pair) {
            Ok(parsed) => parsed,
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
                continue;
            }
        };
        let outcome = update(host, &reference, |spec| {
            if spec.mode.replicated.is_none() {
                anyhow::bail!("{reference}: scale can only be used with replicated mode");
            }
            spec.mode = ServiceMode::replicated(replicas);
            Ok(())
        })
        .await;
        match outcome {
            Ok(warnings) => {
                for warning in &warnings {
                    streams.warn(warning).await;
                }
                streams
                    .outln(&format!("{reference} scaled to {replicas}"))
                    .await;
            }
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    Ok(if failed { FAILURE } else { 0 })
}

/// Parse one `SERVICE=REPLICAS` argument of `satl service scale`.
pub fn parse_scale(value: &str) -> anyhow::Result<(String, u64)> {
    let (name, replicas) = value.split_once('=').ok_or_else(|| {
        anyhow::anyhow!("invalid scale specifier {value:?}: expected SERVICE=REPLICAS")
    })?;
    if name.is_empty() {
        anyhow::bail!("invalid scale specifier {value:?}: empty service name");
    }
    let replicas: u64 = replicas.parse().map_err(|_| {
        anyhow::anyhow!("invalid scale specifier {value:?}: {replicas:?} is not a replica count")
    })?;
    Ok((name.to_owned(), replicas))
}

async fn remove(host: &Host, args: &RmArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut failed = false;
    for reference in &args.services {
        let path = format!("/services/{reference}");
        match client::delete_ok(host, &path).await {
            Ok(()) => streams.outln(reference).await,
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    Ok(if failed { FAILURE } else { 0 })
}

/// Reads the service, applies `edit` to its spec and writes it back against
/// the version that was read; returns the daemon's warnings.
async fn update<F>(host: &Host, reference: &str, edit: F) -> anyhow::Result<Vec<String>>
where
    F: FnOnce(&mut ServiceSpec) -> anyhow::Result<()>,
{
    let service: Service = client::get_json(host, &format!("/services/{reference}")).await?;
    let mut spec = service.spec.clone();
    edit(&mut spec)?;
    let version = service.version.index.to_string();
    let path = format!(
        "/services/{}/update{}",
        service.id,
        client::query(&[("version", version.as_str())])
    );
    let response: ServiceUpdateResponse = client::post_json(host, &path, Some(&spec)).await?;
    Ok(response.warnings)
}

/// Applies `satl service update`'s flags to a spec.
/// Which half of `ResourceRequirements` an update flag edits.
#[derive(Debug, Clone, Copy)]
enum Dimension {
    Limits,
    Reservations,
}

fn apply(spec: &mut ServiceSpec, args: &UpdateArgs) -> anyhow::Result<()> {
    if let Some(image) = &args.image {
        spec.task_template.container_spec.image.clone_from(image);
    }
    if let Some(replicas) = args.replicas {
        if spec.mode.replicated.is_none() {
            anyhow::bail!("--replicas can only be used with the replicated service mode");
        }
        spec.mode = ServiceMode::replicated(replicas);
    }
    if !args.constraint_add.is_empty() || !args.constraint_rm.is_empty() {
        let placement = spec
            .task_template
            .placement
            .get_or_insert_with(Placement::default);
        placement
            .constraints
            .retain(|constraint| !args.constraint_rm.contains(constraint));
        for constraint in &args.constraint_add {
            if !placement.constraints.contains(constraint) {
                placement.constraints.push(constraint.clone());
            }
        }
    }
    if !args.placement_pref_add.is_empty() || !args.placement_pref_rm.is_empty() {
        let placement = spec
            .task_template
            .placement
            .get_or_insert_with(Placement::default);
        placement.preferences.retain(|preference| {
            let descriptor = preference
                .spread
                .as_ref()
                .map_or("", |spread| spread.spread_descriptor.as_str());
            !args
                .placement_pref_rm
                .iter()
                .any(|remove| remove == descriptor)
        });
        for pref in &args.placement_pref_add {
            placement.preferences.push(parse_placement_pref(pref)?);
        }
    }
    for label in &args.label_add {
        let (key, value) = parse::parse_label(label)?;
        spec.labels.insert(key, value);
    }
    for key in &args.label_rm {
        spec.labels.remove(key);
    }
    // A resources-only edit is a hot resize (M6g): the daemon pushes the new
    // values into the live tasks instead of rolling them. A flag left out
    // keeps the stored dimension; `0` clears it.
    for (cpu, memory, which) in [
        (&args.limit_cpu, &args.limit_memory, Dimension::Limits),
        (
            &args.reserve_cpu,
            &args.reserve_memory,
            Dimension::Reservations,
        ),
    ] {
        if cpu.is_none() && memory.is_none() {
            continue;
        }
        let current = spec
            .task_template
            .resources
            .and_then(|r| match which {
                Dimension::Limits => r.limits,
                Dimension::Reservations => r.reservations,
            })
            .unwrap_or_default();
        let nano_cpus = match cpu.as_deref() {
            Some("0") => 0,
            Some(value) => parse::parse_nano_cpus(value)?,
            None => current.nano_cpus,
        };
        let memory_bytes = match memory.as_deref() {
            Some("0") => 0,
            Some(value) => parse::parse_memory(value)?,
            None => current.memory_bytes,
        };
        let value = (nano_cpus > 0 || memory_bytes > 0).then_some(Resources {
            nano_cpus,
            memory_bytes,
        });
        // Do not materialize an empty `Resources` object for a service that
        // never had one.
        if value.is_some() || spec.task_template.resources.is_some() {
            let resources = spec
                .task_template
                .resources
                .get_or_insert_with(Default::default);
            match which {
                Dimension::Limits => resources.limits = value,
                Dimension::Reservations => resources.reservations = value,
            }
        }
    }
    // The spec here is the *stored* one, read back a moment ago, so both halves
    // start from the service's own policy and only the named flags move.
    args.policy.update().apply(&mut spec.update_config)?;
    args.policy.rollback().apply(&mut spec.rollback_config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;
    use crate::stub::{Reply, Stub};

    const NOW: i64 = 1_770_000_600;
    const SERVICE_ID: &str = "2hvy0lj3x0b883f8e30fyp218";
    const SECRET_ID: &str = "5hvy0lj3x0b883f8e30fyp221";
    const CONFIG_ID: &str = "6hvy0lj3x0b883f8e30fyp222";
    const TASK_ID: &str = "3hvy0lj3x0b883f8e30fyp219";
    const NODE_ID: &str = "1hvy0lj3x0b883f8e30fyp217";

    fn service_json() -> String {
        format!(
            r#"{{"ID":"{SERVICE_ID}","Version":{{"Index":7}},
              "Spec":{{"Name":"web","Labels":{{"tier":"front"}},
                "TaskTemplate":{{"ContainerSpec":{{"Image":"nginx:1.27"}},
                  "Placement":{{"Constraints":["node.labels.zone == a"]}}}},
                "Mode":{{"Replicated":{{"Replicas":3}}}}}},
              "Endpoint":{{"Ports":[
                {{"Protocol":"tcp","TargetPort":80,"PublishedPort":8080,"PublishMode":"ingress"}}]}},
              "ServiceStatus":{{"RunningTasks":2,"DesiredTasks":3}}}}"#
        )
    }

    fn sample_services() -> Vec<Service> {
        vec![serde_json::from_str(&service_json()).expect("fixture parses")]
    }

    fn tasks_json() -> String {
        format!(
            r#"[{{"ID":"{TASK_ID}","Name":"web.1.{TASK_ID}",
                 "Spec":{{"ContainerSpec":{{"Image":"nginx:1.27"}}}},
                 "ServiceID":"{SERVICE_ID}","Slot":1,"NodeID":"{NODE_ID}",
                 "Status":{{"Timestamp":"2026-02-02T02:45:00Z","State":"running",
                   "Message":"started","PortStatus":{{"Ports":[]}}}},
                 "DesiredState":"running"}},
                {{"ID":"4hvy0lj3x0b883f8e30fyp220","Name":"web.2.4hvy0lj3x0b883f8e30fyp220",
                 "Spec":{{"ContainerSpec":{{"Image":"nginx:1.27"}}}},
                 "ServiceID":"{SERVICE_ID}","Slot":2,"NodeID":"{NODE_ID}",
                 "Status":{{"Timestamp":"2026-02-02T02:40:00Z","State":"failed",
                   "Err":"task: non-zero exit (1)"}},
                 "DesiredState":"shutdown"}}]"#
        )
    }

    fn sample_tasks() -> Vec<Task> {
        serde_json::from_str(&tasks_json()).expect("fixture parses")
    }

    fn hostnames() -> BTreeMap<String, String> {
        BTreeMap::from([(NODE_ID.to_owned(), "alpha".to_owned())])
    }

    /// `create_spec` without resolved secret/config IDs — every test that does
    /// not exercise name resolution.
    fn spec_of(args: &CreateArgs) -> anyhow::Result<ServiceSpec> {
        create_spec(args, &BTreeMap::new(), &BTreeMap::new())
    }

    /// `--restart-condition` alone sends a policy with no `Delay` key, so the
    /// daemon's admission default applies (5 s, api-compat 153) — audit N1
    /// measured a 0 there restarting a crash-looping service with no delay.
    #[test]
    fn a_restart_condition_without_a_delay_sends_none() {
        let args = CreateArgs {
            image: "nginx".to_owned(),
            restart_condition: Some("on-failure".to_owned()),
            ..CreateArgs::default()
        };
        let spec = spec_of(&args).expect("valid flags");
        let policy = spec.task_template.restart_policy.expect("a restart policy");
        assert_eq!(policy.condition, "on-failure");
        let json = serde_json::to_value(&policy).expect("serializable");
        assert!(
            json.get("Delay").is_none(),
            "no Delay on the wire, so admission defaults it: {json}"
        );
    }

    #[test]
    fn create_spec_maps_every_flag() {
        let args = CreateArgs {
            name: Some("web".to_owned()),
            replicas: Some(3),
            mode: Some("replicated".to_owned()),
            max_concurrent: None,
            total_completions: None,
            publish: vec!["8080:80".to_owned(), "53:53/udp".to_owned()],
            env: vec!["A=1".to_owned()],
            label: vec!["tier=front".to_owned()],
            constraint: vec!["node.labels.zone == a".to_owned()],
            placement_pref: vec!["spread=node.labels.zone".to_owned()],
            limit_cpu: Some("1.5".to_owned()),
            limit_memory: Some("512m".to_owned()),
            reserve_cpu: Some("0.5".to_owned()),
            reserve_memory: Some("128m".to_owned()),
            restart_condition: Some("on-failure".to_owned()),
            network: vec!["backend".to_owned()],
            secret: Vec::new(),
            config: Vec::new(),
            policy: PolicyArgs {
                update_parallelism: Some(2),
                update_delay: Some("10s".to_owned()),
                update_failure_action: Some("rollback".to_owned()),
                update_monitor: Some("8s".to_owned()),
                update_max_failure_ratio: Some(0.25),
                update_order: Some("start-first".to_owned()),
                rollback_parallelism: Some(3),
                rollback_delay: Some("1s".to_owned()),
                rollback_failure_action: Some("continue".to_owned()),
                rollback_monitor: Some("4s".to_owned()),
                rollback_max_failure_ratio: Some(0.5),
                rollback_order: Some("stop-first".to_owned()),
            },
            image: "nginx:1.27".to_owned(),
            command: vec![
                "nginx".to_owned(),
                "-g".to_owned(),
                "daemon off;".to_owned(),
            ],
        };
        let spec = spec_of(&args).expect("valid flags");
        assert_eq!(
            serde_json::to_string(&spec).expect("serializable"),
            concat!(
                r#"{"Name":"web","Labels":{"tier":"front"},"#,
                r#""TaskTemplate":{"ContainerSpec":{"Image":"nginx:1.27","#,
                r#""Args":["nginx","-g","daemon off;"],"Env":["A=1"]},"#,
                r#""Resources":{"Limits":{"NanoCPUs":1500000000,"MemoryBytes":536870912},"#,
                r#""Reservations":{"NanoCPUs":500000000,"MemoryBytes":134217728}},"#,
                r#""RestartPolicy":{"Condition":"on-failure","MaxAttempts":0},"#,
                r#""Placement":{"Constraints":["node.labels.zone == a"],"#,
                r#""Preferences":[{"Spread":{"SpreadDescriptor":"node.labels.zone"}}]},"#,
                r#""Networks":[{"Target":"backend"}]},"#,
                r#""Mode":{"Replicated":{"Replicas":3}},"#,
                r#""UpdateConfig":{"Parallelism":2,"Delay":10000000000,"#,
                r#""FailureAction":"rollback","Monitor":8000000000,"#,
                r#""MaxFailureRatio":0.25,"Order":"start-first"},"#,
                r#""RollbackConfig":{"Parallelism":3,"Delay":1000000000,"#,
                r#""FailureAction":"continue","Monitor":4000000000,"#,
                r#""MaxFailureRatio":0.5,"Order":"stop-first"},"#,
                r#""EndpointSpec":{"Ports":["#,
                r#"{"Protocol":"tcp","TargetPort":80,"PublishedPort":8080,"PublishMode":"ingress"},"#,
                r#"{"Protocol":"udp","TargetPort":53,"PublishedPort":53,"PublishMode":"ingress"}"#,
                r#"]}}"#,
            )
        );
    }

    /// One flag of a half fills in Docker's documented defaults for the rest of
    /// that half — and touches the other half not at all. Parallelism is the
    /// one that has to be spelled out: 0 means "every slot at once" to the
    /// daemon, so a lone `--update-monitor` must not turn into a restart.
    #[test]
    fn one_policy_flag_names_a_whole_policy_and_only_that_half() {
        let args = CreateArgs {
            image: "nginx".to_owned(),
            policy: PolicyArgs {
                update_monitor: Some("30s".to_owned()),
                ..PolicyArgs::default()
            },
            ..CreateArgs::default()
        };
        let spec = spec_of(&args).expect("valid flags");
        let config = spec.update_config.expect("an update policy");
        assert_eq!(config.parallelism, 1);
        assert_eq!(config.monitor, 30_000_000_000);
        assert_eq!(config.failure_action, "pause");
        assert_eq!(config.order, "stop-first");
        assert!(
            spec.rollback_config.is_none(),
            "an --update-* flag must not invent a rollback policy"
        );
    }

    /// One `--secret` and one `--config`, with the mode written the way an
    /// operator writes it (octal) and sent the way docker sends it (decimal:
    /// `0o444` is 292, `0o400` is 256).
    #[test]
    fn create_spec_carries_the_resolved_secret_and_config_references() {
        let args = CreateArgs {
            secret: vec!["site-cert".to_owned()],
            config: vec![
                "source=nginx-conf,target=/etc/nginx/nginx.conf,uid=80,gid=80,mode=0400".to_owned(),
            ],
            image: "nginx:1.27".to_owned(),
            ..CreateArgs::default()
        };
        let secret_ids = BTreeMap::from([("site-cert".to_owned(), SECRET_ID.to_owned())]);
        let config_ids = BTreeMap::from([("nginx-conf".to_owned(), CONFIG_ID.to_owned())]);
        let spec = create_spec(&args, &secret_ids, &config_ids).expect("valid flags");
        let expected = concat!(
            r#"{"Name":"","TaskTemplate":{"ContainerSpec":{"Image":"nginx:1.27","#,
            r#""Secrets":[{"File":{"Name":"site-cert","UID":"0","GID":"0","Mode":292},"#,
            r#""SecretID":"SECRET","SecretName":"site-cert"}],"#,
            r#""Configs":[{"File":{"Name":"/etc/nginx/nginx.conf","UID":"80","GID":"80","#,
            r#""Mode":256},"ConfigID":"CONFIG","ConfigName":"nginx-conf"}]}},"#,
            r#""Mode":{"Replicated":{"Replicas":1}}}"#,
        )
        .replace("SECRET", SECRET_ID)
        .replace("CONFIG", CONFIG_ID);
        assert_eq!(
            serde_json::to_string(&spec).expect("serializable"),
            expected
        );
    }

    #[test]
    fn create_spec_leaves_the_id_empty_when_the_name_was_not_resolved() {
        let args = CreateArgs {
            secret: vec!["site-cert".to_owned()],
            image: "nginx".to_owned(),
            ..CreateArgs::default()
        };
        let spec = spec_of(&args).expect("valid flags");
        let reference = &spec.task_template.container_spec.secrets[0];
        assert_eq!(reference.secret_name, "site-cert");
        assert!(reference.secret_id.is_empty());
    }

    #[test]
    fn create_spec_rejects_a_bad_secret_or_config_reference() {
        let args = CreateArgs {
            secret: vec!["source=site-cert,owner=root".to_owned()],
            image: "nginx".to_owned(),
            ..CreateArgs::default()
        };
        let err = spec_of(&args).expect_err("unknown option");
        assert!(err.to_string().contains("unknown option"), "{err}");

        let args = CreateArgs {
            config: vec!["source=nginx-conf,mode=0999".to_owned()],
            image: "nginx".to_owned(),
            ..CreateArgs::default()
        };
        let err = spec_of(&args).expect_err("bad mode");
        assert!(err.to_string().contains("octal file mode"), "{err}");
    }

    #[test]
    fn create_spec_minimal_is_one_replica() {
        let args = CreateArgs {
            image: "nginx".to_owned(),
            ..CreateArgs::default()
        };
        let spec = spec_of(&args).expect("valid flags");
        assert_eq!(
            serde_json::to_string(&spec).expect("serializable"),
            r#"{"Name":"","TaskTemplate":{"ContainerSpec":{"Image":"nginx"}},"Mode":{"Replicated":{"Replicas":1}}}"#
        );
    }

    #[test]
    fn create_spec_global_mode_and_its_conflict() {
        let args = CreateArgs {
            mode: Some("global".to_owned()),
            image: "nginx".to_owned(),
            ..CreateArgs::default()
        };
        let spec = spec_of(&args).expect("valid flags");
        assert_eq!(spec.mode, ServiceMode::global());

        let conflicting = CreateArgs {
            replicas: Some(3),
            ..args
        };
        let err = spec_of(&conflicting).expect_err("global has no replicas");
        assert!(err.to_string().contains("--replicas"), "{err}");
    }

    #[test]
    fn create_spec_job_modes() {
        // Bare: both knobs default at the daemon.
        let args = CreateArgs {
            mode: Some("replicated-job".to_owned()),
            image: "nginx".to_owned(),
            ..CreateArgs::default()
        };
        let spec = spec_of(&args).expect("valid flags");
        assert_eq!(spec.mode, ServiceMode::replicated_job(None, None));
        assert_eq!(spec.mode.name(), "replicated-job");

        // `--replicas N` maps onto both knobs, as Docker's CLI does.
        let args = CreateArgs {
            replicas: Some(3),
            ..args
        };
        let spec = spec_of(&args).expect("valid flags");
        assert_eq!(spec.mode, ServiceMode::replicated_job(Some(3), Some(3)));

        // The knobs set individually.
        let args = CreateArgs {
            mode: Some("replicated-job".to_owned()),
            max_concurrent: Some(2),
            total_completions: Some(5),
            image: "nginx".to_owned(),
            ..CreateArgs::default()
        };
        let spec = spec_of(&args).expect("valid flags");
        assert_eq!(spec.mode, ServiceMode::replicated_job(Some(2), Some(5)));

        // ... but not on another mode, and not mixed with --replicas.
        let err = spec_of(&CreateArgs {
            mode: Some("replicated".to_owned()),
            max_concurrent: Some(2),
            image: "nginx".to_owned(),
            ..CreateArgs::default()
        })
        .expect_err("the job knobs are job-only");
        assert!(err.to_string().contains("--mode replicated-job"), "{err}");
        let err = spec_of(&CreateArgs {
            mode: Some("replicated-job".to_owned()),
            replicas: Some(2),
            total_completions: Some(5),
            image: "nginx".to_owned(),
            ..CreateArgs::default()
        })
        .expect_err("--replicas already sets both knobs");
        assert!(err.to_string().contains("--replicas"), "{err}");

        let args = CreateArgs {
            mode: Some("global-job".to_owned()),
            image: "nginx".to_owned(),
            ..CreateArgs::default()
        };
        let spec = spec_of(&args).expect("valid flags");
        assert_eq!(spec.mode, ServiceMode::global_job());
        assert_eq!(spec.mode.name(), "global-job");

        let conflicting = CreateArgs {
            replicas: Some(3),
            ..args
        };
        let err = spec_of(&conflicting).expect_err("a global job has no replica count");
        assert!(err.to_string().contains("--replicas"), "{err}");
    }

    #[test]
    fn create_spec_rejects_bad_flag_values() {
        for (args, needle) in [
            (
                CreateArgs {
                    publish: vec!["8080:80/sctp".to_owned()],
                    image: "n".to_owned(),
                    ..CreateArgs::default()
                },
                "tcp or udp",
            ),
            (
                CreateArgs {
                    limit_memory: Some("512x".to_owned()),
                    image: "n".to_owned(),
                    ..CreateArgs::default()
                },
                "invalid memory value",
            ),
            (
                CreateArgs {
                    limit_cpu: Some("many".to_owned()),
                    image: "n".to_owned(),
                    ..CreateArgs::default()
                },
                "invalid cpu value",
            ),
            (
                CreateArgs {
                    policy: PolicyArgs {
                        update_delay: Some("soon".to_owned()),
                        ..PolicyArgs::default()
                    },
                    image: "n".to_owned(),
                    ..CreateArgs::default()
                },
                "invalid duration",
            ),
            (
                CreateArgs {
                    policy: PolicyArgs {
                        rollback_monitor: Some("later".to_owned()),
                        ..PolicyArgs::default()
                    },
                    image: "n".to_owned(),
                    ..CreateArgs::default()
                },
                "invalid duration",
            ),
            (
                CreateArgs {
                    policy: PolicyArgs {
                        update_max_failure_ratio: Some(1.5),
                        ..PolicyArgs::default()
                    },
                    image: "n".to_owned(),
                    ..CreateArgs::default()
                },
                "invalid --update-max-failure-ratio",
            ),
        ] {
            let err = spec_of(&args).expect_err("must be rejected");
            assert!(err.to_string().contains(needle), "{err}");
        }
    }

    #[test]
    fn go_durations_parse() {
        assert_eq!(parse_duration("10s").expect("valid"), 10_000_000_000);
        assert_eq!(parse_duration("1m30s").expect("valid"), 90_000_000_000);
        assert_eq!(parse_duration("500ms").expect("valid"), 500_000_000);
        assert_eq!(parse_duration("2h").expect("valid"), 7_200_000_000_000);
        for bad in ["", "10", "soon", "10x", "s"] {
            assert!(parse_duration(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn ls_column_golden() {
        let expected = format!(
            "\
ID             NAME   MODE         REPLICAS   IMAGE        PORTS
{}   web    replicated   2/3        nginx:1.27   *:8080->80/tcp
",
            format::truncate_id(SERVICE_ID)
        );
        assert_eq!(render_ls(&sample_services(), &LsArgs::default()), expected);
    }

    #[test]
    fn ls_without_service_status_falls_back_to_the_spec() {
        let mut services = sample_services();
        services[0].service_status = None;
        assert!(render_ls(&services, &LsArgs::default()).contains("0/3"));
    }

    #[test]
    fn ls_quiet_and_empty() {
        let args = LsArgs { quiet: true };
        assert_eq!(
            render_ls(&sample_services(), &args),
            format!("{}\n", format::truncate_id(SERVICE_ID))
        );
        let empty = render_ls(&[], &LsArgs::default());
        assert_eq!(empty.lines().count(), 1);
        assert!(empty.starts_with("ID "));
    }

    /// Docker's tabwriter pads every cell but the last, so a row whose last
    /// columns are empty ends in the padding of the columns before it; the
    /// `{:N}` fills below spell that out rather than hiding it in a literal.
    #[test]
    fn ps_column_golden() {
        let expected = format!(
            "\
ID             NAME    IMAGE        NODE    DESIRED STATE   CURRENT STATE           ERROR                     PORTS\n\
{id1}   web.1   nginx:1.27   alpha   Running         Running 5 minutes ago{blank:29}\n\
{id2}   web.2   nginx:1.27   alpha   Shutdown        Failed 10 minutes ago   task: non-zero exit (1){blank:3}\n",
            id1 = format::truncate_id(TASK_ID),
            id2 = format::truncate_id("4hvy0lj3x0b883f8e30fyp220"),
            blank = "",
        );
        assert_eq!(
            render_ps(&sample_tasks(), &hostnames(), &PsArgs::default(), NOW),
            expected
        );
    }

    #[test]
    fn ps_falls_back_to_the_node_id_when_the_hostname_is_unknown() {
        let rendered = render_ps(&sample_tasks(), &BTreeMap::new(), &PsArgs::default(), NOW);
        assert!(rendered.contains(NODE_ID), "{rendered}");
    }

    #[test]
    fn ps_quiet_and_no_trunc() {
        let quiet = PsArgs {
            quiet: true,
            ..PsArgs::default()
        };
        assert!(
            render_ps(&sample_tasks(), &hostnames(), &quiet, NOW)
                .starts_with(&format::truncate_id(TASK_ID))
        );
        let full = PsArgs {
            no_trunc: true,
            ..PsArgs::default()
        };
        assert!(render_ps(&sample_tasks(), &hostnames(), &full, NOW).contains(TASK_ID));
    }

    #[test]
    fn pretty_golden() {
        let expected = format!(
            "\
ID:\t\t{SERVICE_ID}
Name:\t\tweb
Labels:
 tier=front
Service Mode:\treplicated
 Replicas:\t3
ContainerSpec:
 Image:\t\tnginx:1.27
Placement:
 Constraints:\tnode.labels.zone == a
Ports:
 *:8080->80/tcp
"
        );
        assert_eq!(pretty(&sample_services()[0]), expected);
    }

    #[test]
    fn scale_specifiers_parse() {
        assert_eq!(parse_scale("web=3").expect("valid"), ("web".to_owned(), 3));
        for bad in ["web", "=3", "web=many", "web="] {
            assert!(parse_scale(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[tokio::test]
    async fn create_posts_the_spec_and_prints_the_id() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/services/create",
            Reply::json(
                201,
                &format!(r#"{{"ID":"{SERVICE_ID}","Warnings":["rctl is disabled"]}}"#),
            ),
        );
        let (mut streams, out, err) = testing::streams();
        let args = CreateArgs {
            name: Some("web".to_owned()),
            replicas: Some(3),
            image: "nginx:1.27".to_owned(),
            ..CreateArgs::default()
        };
        execute(&stub.host(), &ServiceCommand::Create(args), &mut streams)
            .await
            .expect("create succeeds");

        assert_eq!(out.contents(), format!("{SERVICE_ID}\n"));
        assert_eq!(err.contents(), "WARNING: rctl is disabled\n");
        let call = stub.first_call("POST /services/create").expect("create");
        assert!(call.body.contains(r#""Name":"web""#), "{}", call.body);
        assert!(
            call.body
                .contains(r#""Mode":{"Replicated":{"Replicas":3}}"#),
            "{}",
            call.body
        );
    }

    /// Mirror of `update_resizes_limits_and_clears_them_on_zero`: create takes
    /// the same reserve flags, and `0` means no reservation reaches the wire.
    #[tokio::test]
    async fn create_sends_the_reservations_and_zero_omits_them() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/services/create",
            Reply::json(201, &format!(r#"{{"ID":"{SERVICE_ID}","Warnings":null}}"#)),
        );

        let (mut streams, _, _) = testing::streams();
        let args = CreateArgs {
            image: "nginx:1.27".to_owned(),
            reserve_cpu: Some("0.5".to_owned()),
            reserve_memory: Some("128m".to_owned()),
            ..CreateArgs::default()
        };
        execute(&stub.host(), &ServiceCommand::Create(args), &mut streams)
            .await
            .expect("create succeeds");
        let call = stub.first_call("POST /services/create").expect("create");
        assert!(
            call.body
                .contains(r#""Reservations":{"NanoCPUs":500000000,"MemoryBytes":134217728}"#),
            "{}",
            call.body
        );

        let (mut streams, _, _) = testing::streams();
        let args = CreateArgs {
            image: "nginx:1.27".to_owned(),
            reserve_cpu: Some("0".to_owned()),
            reserve_memory: Some("0".to_owned()),
            ..CreateArgs::default()
        };
        execute(&stub.host(), &ServiceCommand::Create(args), &mut streams)
            .await
            .expect("create succeeds");
        let call = stub
            .calls()
            .into_iter()
            .rfind(|call| call.route() == "POST /services/create")
            .expect("create");
        assert!(!call.body.contains(r#""Resources""#), "{}", call.body);
    }

    /// The name→ID resolution docker's client does: list the secrets, match the
    /// source by name, and embed both the ID and the name in the spec.
    #[tokio::test]
    async fn create_with_a_secret_resolves_the_name_before_posting_the_spec() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/secrets",
            Reply::json(
                200,
                &format!(
                    r#"[{{"ID":"{SECRET_ID}","Spec":{{"Name":"site-cert"}}}},
                        {{"ID":"9zzz","Spec":{{"Name":"other"}}}}]"#
                ),
            ),
        )
        .on(
            "POST",
            "/services/create",
            Reply::json(201, &format!(r#"{{"ID":"{SERVICE_ID}","Warnings":[]}}"#)),
        );

        let (mut streams, out, _err) = testing::streams();
        let args = CreateArgs {
            name: Some("web".to_owned()),
            secret: vec!["source=site-cert,target=site.pem,mode=0400".to_owned()],
            image: "nginx:1.27".to_owned(),
            ..CreateArgs::default()
        };
        execute(&stub.host(), &ServiceCommand::Create(args), &mut streams)
            .await
            .expect("create succeeds");

        assert_eq!(out.contents(), format!("{SERVICE_ID}\n"));
        assert_eq!(
            stub.routes(),
            vec!["GET /secrets", "POST /services/create"],
            "the lookup comes first, and no /configs call is made"
        );
        let call = stub.first_call("POST /services/create").expect("create");
        assert!(
            call.body.contains(&format!(
                r#""Secrets":[{{"File":{{"Name":"site.pem","UID":"0","GID":"0","Mode":256}},"SecretID":"{SECRET_ID}","SecretName":"site-cert"}}]"#
            )),
            "{}",
            call.body
        );
    }

    #[tokio::test]
    async fn create_with_an_unknown_secret_never_reaches_services_create() {
        let stub = Stub::start().await;
        stub.on("GET", "/secrets", Reply::json(200, "[]"));
        let (mut streams, out, _err) = testing::streams();
        let args = CreateArgs {
            secret: vec!["ghost".to_owned()],
            image: "nginx".to_owned(),
            ..CreateArgs::default()
        };
        let err = execute(&stub.host(), &ServiceCommand::Create(args), &mut streams)
            .await
            .expect_err("no such secret");
        assert_eq!(err.to_string(), "secret not found: ghost");
        assert!(out.contents().is_empty());
        assert_eq!(stub.routes(), vec!["GET /secrets"]);
    }

    #[tokio::test]
    async fn create_failure_exits_with_an_error() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/services/create",
            Reply::json(
                409,
                r#"{"message":"name conflicts with an existing object"}"#,
            ),
        );
        let (mut streams, out, _err) = testing::streams();
        let args = CreateArgs {
            image: "nginx".to_owned(),
            ..CreateArgs::default()
        };
        let err = execute(&stub.host(), &ServiceCommand::Create(args), &mut streams)
            .await
            .expect_err("a conflict is an error");
        assert!(err.to_string().contains("name conflicts"), "{err}");
        assert!(out.contents().is_empty());
    }

    #[tokio::test]
    async fn ls_asks_for_the_replica_counts() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/services",
            Reply::json(200, &format!("[{}]", service_json())),
        );
        let (mut streams, out, _err) = testing::streams();
        execute(
            &stub.host(),
            &ServiceCommand::Ls(LsArgs::default()),
            &mut streams,
        )
        .await
        .expect("ls succeeds");
        assert!(out.contents().contains("2/3"), "{}", out.contents());
        assert_eq!(
            stub.first_call("GET /services").expect("list").query,
            "status=true"
        );
    }

    #[tokio::test]
    async fn ps_filters_by_service_and_resolves_hostnames() {
        let stub = Stub::start().await;
        stub.on("GET", "/tasks", Reply::json(200, &tasks_json()))
            .on(
                "GET",
                "/nodes",
                Reply::json(
                    200,
                    &format!(r#"[{{"ID":"{NODE_ID}","Description":{{"Hostname":"alpha"}}}}]"#),
                ),
            );
        let (mut streams, out, _err) = testing::streams();
        let args = PsArgs {
            services: vec!["web".to_owned()],
            ..PsArgs::default()
        };
        execute(&stub.host(), &ServiceCommand::Ps(args), &mut streams)
            .await
            .expect("ps succeeds");

        let call = stub.first_call("GET /tasks").expect("tasks call");
        assert_eq!(
            call.query,
            "filters=%7B%22service%22%3A%7B%22web%22%3Atrue%7D%7D"
        );
        let printed = out.contents();
        assert!(printed.contains("web.1"), "{printed}");
        assert!(printed.contains("alpha"), "{printed}");
        assert!(printed.contains("task: non-zero exit (1)"), "{printed}");
    }

    #[tokio::test]
    async fn ps_reports_a_missing_service_and_exits_1() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/tasks",
            Reply::json(404, r#"{"message":"no such service: ghost"}"#),
        );
        let (mut streams, _out, err) = testing::streams();
        let args = PsArgs {
            services: vec!["ghost".to_owned()],
            ..PsArgs::default()
        };
        let code = execute(&stub.host(), &ServiceCommand::Ps(args), &mut streams)
            .await
            .expect("ps returns an exit code");
        assert_eq!(code, FAILURE);
        assert_eq!(
            err.contents(),
            "Error response from daemon: no such service: ghost\n"
        );
    }

    #[tokio::test]
    async fn scale_sends_an_update_with_the_current_version() {
        let stub = Stub::start().await;
        stub.on("GET", "/services/web", Reply::json(200, &service_json()))
            .on(
                "POST",
                &format!("/services/{SERVICE_ID}/update"),
                Reply::json(200, r#"{"Warnings":null}"#),
            );

        let (mut streams, out, _err) = testing::streams();
        let args = ScaleArgs {
            scales: vec!["web=5".to_owned()],
        };
        execute(&stub.host(), &ServiceCommand::Scale(args), &mut streams)
            .await
            .expect("scale succeeds");

        assert_eq!(out.contents(), "web scaled to 5\n");
        let call = stub
            .first_call(&format!("POST /services/{SERVICE_ID}/update"))
            .expect("update call");
        assert_eq!(call.query, "version=7");
        assert!(
            call.body
                .contains(r#""Mode":{"Replicated":{"Replicas":5}}"#),
            "{}",
            call.body
        );
        // The rest of the spec is sent back unchanged.
        assert!(
            call.body.contains(r#""Image":"nginx:1.27""#),
            "{}",
            call.body
        );
        assert!(
            call.body
                .contains(r#""Constraints":["node.labels.zone == a"]"#),
            "{}",
            call.body
        );
    }

    #[tokio::test]
    async fn scale_of_a_global_service_is_refused() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/services/agent",
            Reply::json(
                200,
                r#"{"ID":"s","Version":{"Index":1},"Spec":{"Name":"agent","Mode":{"Global":{}}}}"#,
            ),
        );
        let (mut streams, out, err) = testing::streams();
        let args = ScaleArgs {
            scales: vec!["agent=3".to_owned()],
        };
        let code = execute(&stub.host(), &ServiceCommand::Scale(args), &mut streams)
            .await
            .expect("scale returns an exit code");
        assert_eq!(code, FAILURE);
        assert!(out.contents().is_empty());
        assert!(
            err.contents().contains("replicated mode"),
            "{}",
            err.contents()
        );
    }

    #[tokio::test]
    async fn update_changes_the_image_constraints_and_labels() {
        let stub = Stub::start().await;
        stub.on("GET", "/services/web", Reply::json(200, &service_json()))
            .on(
                "POST",
                &format!("/services/{SERVICE_ID}/update"),
                Reply::json(200, r#"{"Warnings":["pinned to a digest"]}"#),
            );

        let (mut streams, out, err) = testing::streams();
        let args = UpdateArgs {
            image: Some("nginx:1.28".to_owned()),
            replicas: Some(4),
            constraint_add: vec!["node.role == worker".to_owned()],
            constraint_rm: vec!["node.labels.zone == a".to_owned()],
            placement_pref_add: Vec::new(),
            placement_pref_rm: Vec::new(),
            label_add: vec!["owner=sre".to_owned()],
            label_rm: vec!["tier".to_owned()],
            limit_cpu: None,
            limit_memory: None,
            reserve_cpu: None,
            reserve_memory: None,
            policy: PolicyArgs::default(),
            service: "web".to_owned(),
        };
        execute(&stub.host(), &ServiceCommand::Update(args), &mut streams)
            .await
            .expect("update succeeds");

        assert_eq!(out.contents(), "web\n");
        assert_eq!(err.contents(), "WARNING: pinned to a digest\n");
        let call = stub
            .first_call(&format!("POST /services/{SERVICE_ID}/update"))
            .expect("update call");
        assert_eq!(call.query, "version=7");
        assert!(
            call.body.contains(r#""Image":"nginx:1.28""#),
            "{}",
            call.body
        );
        assert!(
            call.body
                .contains(r#""Constraints":["node.role == worker"]"#),
            "{}",
            call.body
        );
        assert!(
            call.body.contains(r#""Labels":{"owner":"sre"}"#),
            "{}",
            call.body
        );
        assert!(
            call.body
                .contains(r#""Mode":{"Replicated":{"Replicas":4}}"#),
            "{}",
            call.body
        );
    }

    #[tokio::test]
    async fn update_resizes_limits_and_clears_them_on_zero() {
        let stub = Stub::start().await;
        stub.on("GET", "/services/web", Reply::json(200, &service_json()))
            .on(
                "POST",
                &format!("/services/{SERVICE_ID}/update"),
                Reply::json(200, r#"{"Warnings":null}"#),
            );

        let (mut streams, _, _) = testing::streams();
        let args = UpdateArgs {
            limit_memory: Some("256m".to_owned()),
            limit_cpu: Some("1.5".to_owned()),
            reserve_memory: Some("128m".to_owned()),
            service: "web".to_owned(),
            ..UpdateArgs::default()
        };
        execute(&stub.host(), &ServiceCommand::Update(args), &mut streams)
            .await
            .expect("update succeeds");

        let call = stub
            .first_call(&format!("POST /services/{SERVICE_ID}/update"))
            .expect("update call");
        assert!(
            call.body
                .contains(r#""Limits":{"NanoCPUs":1500000000,"MemoryBytes":268435456}"#),
            "{}",
            call.body
        );
        assert!(
            call.body
                .contains(r#""Reservations":{"MemoryBytes":134217728}"#),
            "{}",
            call.body
        );

        // `0` clears: no Resources reach the wire at all.
        let (mut streams, _, _) = testing::streams();
        let args = UpdateArgs {
            limit_memory: Some("0".to_owned()),
            reserve_memory: Some("0".to_owned()),
            service: "web".to_owned(),
            ..UpdateArgs::default()
        };
        execute(&stub.host(), &ServiceCommand::Update(args), &mut streams)
            .await
            .expect("update succeeds");
        let call = stub
            .calls()
            .into_iter()
            .rfind(|call| call.route() == format!("POST /services/{SERVICE_ID}/update"))
            .expect("update call");
        assert!(!call.body.contains(r#""Resources""#), "{}", call.body);
    }

    /// A service the daemon describes in full: a rollback-on-failure policy, a
    /// separate rollback policy, a healthcheck, a named port and a restart
    /// window. Everything here is a field the CLI has no flag for, and an update
    /// is a read-edit-write of this document — so everything here is something an
    /// update can silently delete.
    fn rich_service_json() -> String {
        format!(
            r#"{{"ID":"{SERVICE_ID}","Version":{{"Index":9}},
              "Spec":{{"Name":"web",
                "TaskTemplate":{{
                  "ContainerSpec":{{"Image":"nginx:1.27",
                    "Healthcheck":{{"Test":["CMD-SHELL","curl -f localhost"],"Retries":3}},
                    "StopSignal":"SIGQUIT","StopGracePeriod":20000000000}},
                  "RestartPolicy":{{"Condition":"any","Delay":15000000000,"MaxAttempts":2,"Window":60000000000}},
                  "ForceUpdate":3}},
                "Mode":{{"Replicated":{{"Replicas":6}}}},
                "UpdateConfig":{{"Parallelism":1,"Delay":0,"FailureAction":"rollback",
                  "Monitor":8000000000,"MaxFailureRatio":0.0,"Order":"stop-first"}},
                "RollbackConfig":{{"Parallelism":2,"Delay":0,"FailureAction":"pause",
                  "Monitor":5000000000,"MaxFailureRatio":0.5,"Order":"start-first"}},
                "EndpointSpec":{{"Mode":"dnsrr","Ports":[
                  {{"Name":"http","Protocol":"tcp","TargetPort":80,
                    "PublishedPort":18082,"PublishMode":"ingress"}}]}}}}}}"#
        )
    }

    /// The defect: `satl service update --image` used to post an `UpdateConfig`
    /// carrying `Parallelism` and `Delay` alone, so the daemon filled the rest
    /// with defaults and the service lost `failure_action: rollback` — automatic
    /// rollback switched off by an operator changing an image tag. Every field
    /// below must come back out unchanged.
    #[tokio::test]
    async fn an_update_naming_only_the_image_keeps_the_whole_policy() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/services/web",
            Reply::json(200, &rich_service_json()),
        )
        .on(
            "POST",
            &format!("/services/{SERVICE_ID}/update"),
            Reply::json(200, r#"{"Warnings":[]}"#),
        );
        let (mut streams, _out, _err) = testing::streams();
        let args = UpdateArgs {
            image: Some("nginx:1.28".to_owned()),
            service: "web".to_owned(),
            ..UpdateArgs::default()
        };
        execute(&stub.host(), &ServiceCommand::Update(args), &mut streams)
            .await
            .expect("update succeeds");
        let call = stub
            .first_call(&format!("POST /services/{SERVICE_ID}/update"))
            .expect("update call");
        for kept in [
            r#""Image":"nginx:1.28""#,
            r#""FailureAction":"rollback""#,
            r#""Monitor":8000000000"#,
            r#""Order":"stop-first""#,
            r#""RollbackConfig""#,
            r#""FailureAction":"pause""#,
            r#""MaxFailureRatio":0.5"#,
            // Not the update policy, but the same read-edit-write and the same
            // consequence: a healthcheck deleted by an image change takes the
            // health gate a rolling update depends on with it (api-compat 87).
            r#""Healthcheck""#,
            r#""CMD-SHELL""#,
            r#""StopSignal":"SIGQUIT""#,
            // The restart policy an update does not name is carried through
            // whole — a stored 15 s Delay must not come back as the default.
            r#""Delay":15000000000"#,
            r#""Window":60000000000"#,
            r#""ForceUpdate":3"#,
            r#""Name":"http""#,
            r#""Mode":"dnsrr""#,
        ] {
            assert!(
                call.body.contains(kept),
                "the update dropped {kept} from the stored spec:\n{}",
                call.body
            );
        }
    }

    /// The flags an operator does name overwrite exactly those fields, and
    /// nothing else — including in the other half of the policy.
    #[tokio::test]
    async fn a_named_policy_flag_changes_that_field_only() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/services/web",
            Reply::json(200, &rich_service_json()),
        )
        .on(
            "POST",
            &format!("/services/{SERVICE_ID}/update"),
            Reply::json(200, r#"{"Warnings":[]}"#),
        );
        let (mut streams, _out, _err) = testing::streams();
        let args = UpdateArgs {
            policy: PolicyArgs {
                update_parallelism: Some(3),
                rollback_order: Some("stop-first".to_owned()),
                ..PolicyArgs::default()
            },
            service: "web".to_owned(),
            ..UpdateArgs::default()
        };
        execute(&stub.host(), &ServiceCommand::Update(args), &mut streams)
            .await
            .expect("update succeeds");
        let call = stub
            .first_call(&format!("POST /services/{SERVICE_ID}/update"))
            .expect("update call");
        let spec: ServiceSpec = serde_json::from_str(&call.body).expect("a spec went out");
        let update = spec.update_config.expect("the update policy");
        assert_eq!(update.parallelism, 3, "the named flag applies");
        assert_eq!(
            update.failure_action, "rollback",
            "an unnamed field keeps the stored value"
        );
        assert_eq!(update.monitor, 8_000_000_000);
        let rollback = spec.rollback_config.expect("the rollback policy");
        assert_eq!(rollback.order, "stop-first", "the named flag applies");
        assert_eq!(
            rollback.parallelism, 2,
            "the rollback half keeps its own stored values"
        );
        assert!(
            (rollback.max_failure_ratio - 0.5).abs() < f32::EPSILON,
            "{rollback:?}"
        );
    }

    #[tokio::test]
    async fn rm_reports_each_service_and_its_failures() {
        let stub = Stub::start().await;
        stub.on("DELETE", "/services/web", Reply::empty(200)).on(
            "DELETE",
            "/services/ghost",
            Reply::json(404, r#"{"message":"service ghost not found"}"#),
        );
        let (mut streams, out, err) = testing::streams();
        let args = RmArgs {
            services: vec!["web".to_owned(), "ghost".to_owned()],
        };
        let code = execute(&stub.host(), &ServiceCommand::Rm(args), &mut streams)
            .await
            .expect("rm returns an exit code");
        assert_eq!(code, FAILURE);
        assert_eq!(out.contents(), "web\n");
        assert_eq!(
            err.contents(),
            "Error response from daemon: service ghost not found\n"
        );
    }

    #[tokio::test]
    async fn inspect_pretty_and_raw() {
        let stub = Stub::start().await;
        stub.on("GET", "/services/web", Reply::json(200, &service_json()));

        let (mut streams, out, _err) = testing::streams();
        let args = InspectArgs {
            pretty: true,
            services: vec!["web".to_owned()],
        };
        execute(&stub.host(), &ServiceCommand::Inspect(args), &mut streams)
            .await
            .expect("inspect succeeds");
        assert_eq!(out.contents(), pretty(&sample_services()[0]));

        let (mut streams, out, _err) = testing::streams();
        let args = InspectArgs {
            pretty: false,
            services: vec!["web".to_owned()],
        };
        execute(&stub.host(), &ServiceCommand::Inspect(args), &mut streams)
            .await
            .expect("inspect succeeds");
        assert!(
            out.contents().starts_with("[\n    {\n"),
            "{}",
            out.contents()
        );
        assert!(
            out.contents()
                .contains(&format!("\"ID\": \"{SERVICE_ID}\""))
        );
    }
}
