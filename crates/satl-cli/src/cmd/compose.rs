// SPDX-License-Identifier: BSD-2-Clause
//! `satl compose up|down|ps|config`, and the machinery `satl stack` runs on.
//!
//! Docker has two worlds and SatL has both of them. `satl compose` is the
//! node-local one: the file runs on the node the CLI is talking to, pinned
//! there, publishing on that node. `satl stack` is the cluster one: the same
//! file spread over the cluster by the scheduler, on an overlay, published
//! through the ingress mesh. One planner serves both, told which world it is
//! in by [`plan::Scope`] (api-compat 110, 169–174).
//!
//! What is *not* a difference between them: every container is a task of a
//! service in either world — there is no standalone container (invariant 2),
//! so `up` creates one service per compose service and `deploy:` is honoured
//! rather than ignored. The split is scope, not execution model.
//!
//! The parsing and the mapping live in [`plan`], as a pure function of the
//! file's text and its scope; this module is the I/O half: finding the file,
//! deriving the project name, looking the node id up, and turning a
//! [`plan::Plan`] into REST calls.

pub mod logs;
pub mod model;
pub mod plan;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::api::cluster::{
    Config, Secret, Service, ServiceCreateResponse, ServiceUpdateResponse, Task,
};
use crate::client::{self, Host};
use crate::cmd::FAILURE;
use crate::format;
use crate::output::Streams;

/// The names a compose file is looked for under, in docker's own order of
/// preference (compose-go's `DefaultFileNames` — note `.yml` before `.yaml` for
/// the `docker-compose` spelling, which is not the order it has for `compose`).
const DEFAULT_FILE_NAMES: &[&str] = &[
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
];

/// Flags of `satl compose`, shared by every subcommand.
///
/// The long help an operator reads before their first `up` is the doc comment
/// on `cli::Command::Compose`: a subcommand's own doc comment wins over a
/// `long_about` set here (measured -- this struct's `long_about` never
/// appeared), so there is exactly one place to write it.
#[derive(Debug, Clone, clap::Args)]
pub struct ComposeArgs {
    /// Compose file to read; found by walking up from the working directory
    /// when not given.
    #[arg(short, long, global = true, value_name = "FILE")]
    pub file: Vec<PathBuf>,

    /// Project name (default: the project directory's name, normalized).
    #[arg(short = 'p', long = "project-name", global = true, value_name = "NAME")]
    pub project_name: Option<String>,

    /// Directory `env_file` paths and the default project name come from.
    #[arg(long = "project-directory", global = true, value_name = "DIR")]
    pub project_directory: Option<PathBuf>,

    /// The compose subcommand.
    #[command(subcommand)]
    pub command: ComposeCommand,
}

/// Subcommands of `satl compose`.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum ComposeCommand {
    /// Create or update the project's networks and services.
    Up(UpArgs),
    /// Remove the services and networks this project created.
    Down(DownArgs),
    /// List the tasks of the project's services.
    Ps(PsArgs),
    /// Print what `up` would create, without creating it.
    Config(ConfigArgs),
    /// Scale every service of the project to zero, keeping the services.
    Stop(StopArgs),
    /// Scale the project's services back to what the file says.
    Start(StartArgs),
    /// Replace the project's running tasks, under each service's own policy.
    Restart(RestartArgs),
    /// Show the output of the project's tasks.
    Logs(LogsArgs),
    /// Build the images of services that declare `build:`.
    Build(BuildArgs),
}

/// Flags of `satl compose build`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct BuildArgs {
    /// Re-execute every build step instead of reusing the cache.
    #[arg(long = "no-cache")]
    pub no_cache: bool,

    /// Only these compose services (default: every service with a `build:`).
    #[arg(value_name = "SERVICE")]
    pub services: Vec<String>,
}

/// Flags of `satl compose logs`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct LogsArgs {
    /// Follow log output.
    ///
    /// Long-only, deliberately: `-f` is already `--file` at the `satl compose`
    /// level, where it is global so that every subcommand takes the same
    /// compose file, and one letter cannot mean two things. `satl logs -f` on
    /// a single container is unaffected (api-compat 179).
    #[arg(long)]
    pub follow: bool,

    /// Number of lines to show from the end of each task's logs.
    #[arg(long, default_value = "all", value_name = "N")]
    pub tail: String,

    /// Show the daemon's timestamps.
    #[arg(short = 't', long)]
    pub timestamps: bool,

    /// Only these compose services (default: all of them).
    #[arg(value_name = "SERVICE")]
    pub services: Vec<String>,
}

/// Flags of `satl compose up`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct UpArgs {
    /// Create everything and return, instead of attaching to the output.
    #[arg(short, long)]
    pub detach: bool,

    /// Remove services of this project that the file no longer declares.
    #[arg(long = "remove-orphans")]
    pub remove_orphans: bool,

    /// Override a service's replica count: `--scale web=3`, repeatable.
    #[arg(long = "scale", value_name = "SERVICE=N")]
    pub scale: Vec<String>,

    /// Build the images of services that declare `build:` first.
    #[arg(long)]
    pub build: bool,
}

/// Flags of `satl compose stop`.
///
/// No `-t/--timeout`: the grace period a task gets is its service's own
/// `stop_grace_period:`, and accepting a flag that changed nothing would be
/// the silent no-op this project refuses.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct StopArgs {}

/// Flags of `satl compose start`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct StartArgs {}

/// Flags of `satl compose restart`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RestartArgs {}

/// Flags of `satl compose down`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct DownArgs {
    /// Refused: see the message it prints.
    #[arg(short, long)]
    pub volumes: bool,

    /// Accepted for compatibility: `down` removes everything labelled with the
    /// project, so an orphan is removed either way.
    #[arg(long = "remove-orphans")]
    pub remove_orphans: bool,
}

/// Flags of `satl compose ps`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct PsArgs {
    /// Don't truncate output.
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,

    /// Only display task IDs.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Flags of `satl compose config`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct ConfigArgs {
    /// Only validate the file; print nothing.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Where the compose file is and what the project is called.
#[derive(Debug, Clone)]
pub struct Located {
    /// The compose file, when one was given or found.
    pub file: Option<PathBuf>,
    /// Directory relative paths resolve against.
    pub dir: PathBuf,
    /// The resolved, normalized project name.
    pub project: String,
}

/// Which of Docker's two worlds the caller is.
///
/// `satl compose` is [`World::Local`], `satl stack` is [`World::Cluster`]. The
/// planner takes the resolved [`plan::Scope`]; this is what the *verb* asks
/// for, before the node id behind `Scope::Local` has been looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum World {
    /// Everything on the node the CLI is talking to (`satl compose`).
    Local,
    /// Placed across the cluster by the scheduler (`satl stack`).
    Cluster,
}

/// What `config` renders in place of a node id when no daemon answered.
///
/// `satl compose config` reaches no daemon by design, so it stays useful in a
/// checkout with nothing running; the pin is the one thing it cannot know.
const OFFLINE_NODE: &str = "<this node>";

/// Dispatch a `satl compose` subcommand.
pub async fn execute(
    host: &Host,
    args: &ComposeArgs,
    world: World,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    let located = locate(args, streams).await?;
    match &args.command {
        ComposeCommand::Up(up) => self::up(host, &located, up, world, streams).await,
        ComposeCommand::Down(down) => self::down(host, &located, down, world, streams).await,
        ComposeCommand::Ps(ps) => self::ps(host, &located, ps, streams).await,
        ComposeCommand::Config(config) => {
            self::config(host, &located, config, world, streams).await
        }
        ComposeCommand::Stop(_) => self::stop(host, &located, streams).await,
        ComposeCommand::Start(_) => self::start(host, &located, world, streams).await,
        ComposeCommand::Restart(_) => self::restart(host, &located, streams).await,
        ComposeCommand::Logs(logs) => self::logs(host, &located, logs, streams).await,
        ComposeCommand::Build(build) => self::build(host, &located, build, world, streams).await,
    }
}

/// The image store `satl compose build` registers into.
///
/// The daemon's own, because the point of building here is that the node that
/// will run the task can already see the image without a registry: the agent
/// resolves a locally present image before it considers a pull. Same default as
/// `satl build`, and the same consequence -- opening it needs root.
const IMAGE_STORE: &str = "/var/db/satl/images";

/// Build the plan's images, in service order.
///
/// Returns the number built. A service with no `build:` is not an error and not
/// a build; asking for one by name that has none is a warning, because the
/// likely cause is a typo and silently doing nothing would hide it.
async fn build_images(
    plan: &plan::Plan,
    only: &[String],
    no_cache: bool,
    streams: &mut Streams,
) -> anyhow::Result<BTreeMap<String, String>> {
    let wanted: Vec<&plan::PlannedBuild> = plan
        .services
        .iter()
        .filter_map(|service| service.build.as_ref())
        .filter(|build| only.is_empty() || only.contains(&build.key))
        .collect();
    for name in only {
        if !plan
            .services
            .iter()
            .any(|service| service.key == *name && service.build.is_some())
        {
            streams
                .warn(&format!(
                    "service {name:?} declares no `build:`; nothing to build for it"
                ))
                .await;
        }
    }
    let mut built: BTreeMap<String, String> = BTreeMap::new();
    if wanted.is_empty() {
        return Ok(built);
    }
    let store = satl_image::ImageStore::open(IMAGE_STORE).map_err(|error| {
        anyhow::anyhow!(
            "cannot open the image store at {IMAGE_STORE}: {error} (a build writes to it, so \
             `satl compose build` needs root -- re-run with sudo)"
        )
    })?;
    for build in &wanted {
        let text = std::fs::read_to_string(&build.file).map_err(|error| {
            anyhow::anyhow!(
                "services.{}.build: cannot read {}: {error}. SatL builds from a `Satlfile`, \
                 not a Dockerfile (docs/image-sources.md); `dockerfile:` names which file to \
                 read, and its contents must be Satlfile syntax",
                build.key,
                build.file.display()
            )
        })?;
        let spec = satl_build::Satlfile::parse(&text).map_err(|error| {
            anyhow::anyhow!(
                "services.{}.build: {}: {error}",
                build.key,
                build.file.display()
            )
        })?;
        let tag = satl_image::ImageReference::parse(&build.tag)
            .map_err(|error| anyhow::anyhow!("services.{}: {error}", build.key))?;
        streams
            .outln(&format!(
                "building {} from {}",
                build.tag,
                build.file.display()
            ))
            .await;
        let cache = (!no_cache).then(|| {
            satl_build::BuildCache::new(std::path::PathBuf::from(satl_build::DEFAULT_CACHE_DIR))
        });
        let outcome = satl_build::build(
            &store,
            &spec,
            &tag,
            satl_build::DEFAULT_PKG_ABI,
            &build.context,
            cache.as_ref(),
        )
        .await
        .map_err(|error| anyhow::anyhow!("services.{}.build: {error}", build.key))?;
        streams
            .outln(&format!(
                "built {} (manifest {})",
                outcome.reference, outcome.image.manifest_digest
            ))
            .await;
        built.insert(build.key.clone(), outcome.image.manifest_digest.to_string());
    }
    Ok(built)
}

/// Make the services whose image was just rebuilt dirty, so their tasks are
/// replaced with it.
///
/// Rebuilding under the same tag changes nothing the orchestrator can see: the
/// service spec is byte-identical, so no task is dirty and `up --build` would
/// rebuild the image and leave the old one running -- measured, before this
/// existed. `ForceUpdate` is the counter the dirty comparison already watches
/// (the same one `satl compose restart` bumps), so setting it is enough.
///
/// It is set to a value **derived from the manifest digest** rather than
/// incremented, so that the stamp follows the image rather than the number of
/// times the verb was typed.
///
/// Measured caveat, so nobody reads more into that than is there: SatL's
/// builder does **not** produce a reproducible manifest digest. Two builds of
/// an unchanged tree give different digests (the image config carries a
/// `created` timestamp), so in practice every `up --build` does replace the
/// tasks. That is defensible — the operator asked to rebuild and deploy — but
/// it is not the idempotence the digest would otherwise buy, and it becomes
/// idempotent for free if the builder ever gains reproducible output
/// (api-compat 182).
fn mark_rebuilt(plan: &mut plan::Plan, built: &BTreeMap<String, String>) {
    for service in &mut plan.services {
        let Some(digest) = built.get(&service.key) else {
            continue;
        };
        service.spec.task_template.rest.insert(
            FORCE_UPDATE.to_owned(),
            serde_json::json!(digest_stamp(digest)),
        );
    }
}

/// A manifest digest as the `u64` `ForceUpdate` carries.
///
/// The first 16 hex characters of the digest body. Not a hash of a hash: the
/// digest is already content-addressed, and any 64 bits of it distinguish two
/// builds as well as any other for this purpose -- the value is compared for
/// equality and never ordered.
fn digest_stamp(digest: &str) -> u64 {
    let body = digest.rsplit(':').next().unwrap_or(digest);
    let hex: String = body
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(16)
        .collect();
    u64::from_str_radix(&hex, 16).unwrap_or(1)
}

/// `satl compose build`: build the project's images and stop there.
async fn build(
    host: &Host,
    located: &Located,
    args: &BuildArgs,
    world: World,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    let scope = self::scope(host, world, true, streams).await?;
    let plan = planned(located, scope)?;
    for warning in &plan.warnings {
        streams.warn(warning).await;
    }
    if build_images(&plan, &args.services, args.no_cache, streams)
        .await?
        .is_empty()
    {
        streams
            .warn("no service in this file declares `build:`; nothing to build")
            .await;
    }
    Ok(0)
}

/// The tasks whose output belongs to this project, as log sources.
///
/// The prefix is docker's `<service>-<slot>`, built from the compose service
/// key the label carries rather than from the namespaced service name: the
/// reader already knows the project, and `shop-web-1` would be noise on every
/// line. Terminal tasks are skipped -- a replaced task has nothing more to say,
/// and after a `restart` there is one of those per slot (api-compat 177).
///
/// Sorted by label so the colours a follow assigns are stable between runs.
async fn project_sources(
    host: &Host,
    project: &str,
    only: &[String],
    streams: &mut Streams,
) -> anyhow::Result<Vec<logs::Source>> {
    let services = project_services(host, project).await?;
    let mut sources = Vec::new();
    let mut known: Vec<String> = Vec::new();
    for service in &services {
        let key = service
            .spec
            .labels
            .get(plan::SERVICE_LABEL)
            .cloned()
            .unwrap_or_else(|| service.spec.name.clone());
        known.push(key.clone());
        if !only.is_empty() && !only.contains(&key) {
            continue;
        }
        let filters = serde_json::json!({"service": {service.spec.name.clone(): true}}).to_string();
        let path = format!("/tasks{}", client::query(&[("filters", filters.as_str())]));
        let tasks: Vec<Task> = client::get_json(host, &path).await?;
        for task in tasks {
            if is_terminal(&task.status.state) {
                continue;
            }
            sources.push(logs::Source {
                label: format!("{key}-{}", task.slot),
                container: task.id,
            });
        }
    }
    for wanted in only {
        if !known.contains(wanted) {
            streams
                .warn(&format!(
                    "no service {wanted:?} in project {project}; it has: {}",
                    known.join(", ")
                ))
                .await;
        }
    }
    sources.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(sources)
}

/// Whether a task will produce no more output.
///
/// Docker's task states, lowercased on the wire. Kept as a list rather than a
/// parse because the CLI carries the state as the string the daemon sent.
fn is_terminal(state: &str) -> bool {
    matches!(
        state,
        "complete" | "failed" | "shutdown" | "rejected" | "orphaned" | "remove"
    )
}

/// `satl compose logs`: the project's output, one prefixed stream.
async fn logs(
    host: &Host,
    located: &Located,
    args: &LogsArgs,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    let sources = project_sources(host, &located.project, &args.services, streams).await?;
    if sources.is_empty() {
        streams
            .warn(&format!(
                "no running task in project {}: there is nothing to read",
                located.project
            ))
            .await;
        return Ok(0);
    }
    let options = logs::Options {
        follow: args.follow,
        tail: args.tail.clone(),
        timestamps: args.timestamps,
    };
    logs::stream(host, &sources, &options, streams).await?;
    Ok(0)
}

/// The project's services, as the daemon holds them, in name order.
///
/// Scoped by the label `up` stamped, never by name, for the same reason `down`
/// is: an object that merely shares the prefix belongs to somebody else.
async fn project_services(host: &Host, project: &str) -> anyhow::Result<Vec<Service>> {
    let services: Vec<Service> = client::get_json(host, "/services").await?;
    let mut mine: Vec<Service> = services
        .into_iter()
        .filter(|service| {
            service
                .spec
                .labels
                .get(plan::PROJECT_LABEL)
                .map(String::as_str)
                == Some(project)
        })
        .collect();
    mine.sort_by(|a, b| a.spec.name.cmp(&b.spec.name));
    Ok(mine)
}

/// Repost one service's spec against the version it was read at.
async fn repost(
    host: &Host,
    service: &Service,
    spec: &crate::api::cluster::ServiceSpec,
    streams: &mut Streams,
) -> anyhow::Result<()> {
    let version = service.version.index.to_string();
    let path = format!(
        "/services/{}/update{}",
        service.id,
        client::query(&[("version", version.as_str())])
    );
    let response: ServiceUpdateResponse = client::post_json(host, &path, Some(spec)).await?;
    for warning in &response.warnings {
        streams.warn(warning).await;
    }
    Ok(())
}

/// `satl compose stop`: scale every service of the project to zero.
///
/// **Not docker's `stop`, and it cannot be.** A task is one-shot and immutable
/// (invariant 2): it is never paused and never resumed, and `start` on one that
/// has run is a 409 (api-compat 30). What can be stopped is the *service's*
/// desire for tasks, so this sets every replica count to zero and leaves the
/// services, their networks and their volumes in place. `start` puts the counts
/// back from the file (api-compat 176).
async fn stop(host: &Host, located: &Located, streams: &mut Streams) -> anyhow::Result<u8> {
    let services = project_services(host, &located.project).await?;
    if services.is_empty() {
        streams
            .warn(&format!(
                "no service of project {} is running",
                located.project
            ))
            .await;
        return Ok(0);
    }
    let mut failed = false;
    for service in &services {
        let mut spec = service.spec.clone();
        if spec.mode.replicated.is_none() {
            streams
                .warn(&format!(
                    "service {} is global, so it has no replica count to zero; it keeps one \
                     task per eligible node",
                    spec.name
                ))
                .await;
            continue;
        }
        spec.mode = crate::api::cluster::ServiceMode::replicated(0);
        match repost(host, service, &spec, streams).await {
            Ok(()) => {
                streams
                    .outln(&format!("service {} stopped", spec.name))
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

/// `satl compose start`: put the replica counts back to what the file says.
///
/// The counterpart of [`stop`], and the reason it needs the compose file where
/// `stop` does not: nothing was stashed anywhere. Squirrelling the old count
/// away in a label would make `start` depend on state only `stop` could have
/// written, so a `start` after a daemon restart, or from another checkout,
/// would restore a number nobody could see. The file is the desired state; this
/// re-asserts it.
///
/// It never *creates*: a service the file declares but the daemon does not hold
/// is named and skipped, because creating one here would make `start` a quiet
/// `up`.
async fn start(
    host: &Host,
    located: &Located,
    world: World,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    let scope = self::scope(host, world, false, streams).await?;
    let plan = planned(located, scope)?;
    let services = project_services(host, &located.project).await?;
    let mut failed = false;
    let mut touched = 0_usize;
    for wanted in &plan.services {
        let Some(service) = services
            .iter()
            .find(|service| service.spec.name == wanted.name)
        else {
            streams
                .warn(&format!(
                    "service {} is not running: `satl compose start` restores replica counts \
                     and never creates. Use `satl compose up`",
                    wanted.name
                ))
                .await;
            continue;
        };
        let mut spec = service.spec.clone();
        spec.mode = wanted.spec.mode;
        match repost(host, service, &spec, streams).await {
            Ok(()) => {
                touched += 1;
                streams
                    .outln(&format!("service {} started", wanted.name))
                    .await;
            }
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    if touched == 0 && !failed {
        streams
            .warn(&format!(
                "no service of project {} was started",
                located.project
            ))
            .await;
    }
    Ok(if failed { FAILURE } else { 0 })
}

/// `satl compose restart`: replace the project's running tasks.
///
/// A task is never restarted in place — "restart" always means a replacement
/// task in the slot (invariant 2) — so this bumps `ForceUpdate` on each
/// service's task template and lets the rolling updater do the replacement
/// under that service's own `update_config`. The tasks that come back are new
/// tasks with new ids, which is what `satl compose ps` will show
/// (api-compat 177).
///
/// `ForceUpdate` is not a field this CLI models: it rides in the task
/// template's passthrough map, which is exactly what that map is for.
async fn restart(host: &Host, located: &Located, streams: &mut Streams) -> anyhow::Result<u8> {
    let services = project_services(host, &located.project).await?;
    if services.is_empty() {
        streams
            .warn(&format!(
                "no service of project {} is running",
                located.project
            ))
            .await;
        return Ok(0);
    }
    let mut failed = false;
    for service in &services {
        let mut spec = service.spec.clone();
        let bumped = spec
            .task_template
            .rest
            .get(FORCE_UPDATE)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            .saturating_add(1);
        spec.task_template
            .rest
            .insert(FORCE_UPDATE.to_owned(), serde_json::json!(bumped));
        match repost(host, service, &spec, streams).await {
            Ok(()) => {
                streams
                    .outln(&format!("service {} restarting", spec.name))
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

/// The task template counter whose change makes every task of a service dirty.
///
/// Docker's own spelling, and the daemon's: `satl_core::TaskSpec::force_update`
/// takes part in the orchestrator's deep comparison, so bumping it is what
/// turns "nothing about this spec changed" into a rolling replacement.
const FORCE_UPDATE: &str = "ForceUpdate";

/// The scope to plan with, looking the node id up when the world is local.
///
/// The lookup goes to the local socket, so a follower names itself and never
/// the leader -- the property `satl run`'s own pin relies on (api-compat 168).
/// When `offline_ok`, a daemon that does not answer is a warning and a
/// placeholder rather than a failure.
async fn scope(
    host: &Host,
    world: World,
    offline_ok: bool,
    streams: &mut Streams,
) -> anyhow::Result<plan::Scope> {
    if world == World::Cluster {
        return Ok(plan::Scope::Cluster);
    }
    let info: anyhow::Result<crate::api::cluster::SystemInfo> =
        client::get_json(host, "/info").await;
    match info {
        Ok(info) if !info.swarm.node_id.is_empty() => Ok(plan::Scope::Local {
            node_id: info.swarm.node_id,
        }),
        Ok(_) if offline_ok => {
            streams
                .warn(&format!(
                    "the daemon reports no node id, so the placement constraint is rendered as \
                     `node.id=={OFFLINE_NODE}`"
                ))
                .await;
            Ok(plan::Scope::Local {
                node_id: OFFLINE_NODE.to_owned(),
            })
        }
        Ok(_) => anyhow::bail!(
            "the daemon reports no node id, so there is no node to pin this project to: \
             `satl compose` runs every task on the node you are talking to"
        ),
        Err(err) if offline_ok => {
            streams
                .warn(&format!(
                    "no daemon answered ({err}), so the placement constraint is rendered as \
                     `node.id=={OFFLINE_NODE}`"
                ))
                .await;
            Ok(plan::Scope::Local {
                node_id: OFFLINE_NODE.to_owned(),
            })
        }
        Err(err) => Err(err),
    }
}

// ---------------------------------------------------------------------------
// Finding the file and naming the project
// ---------------------------------------------------------------------------

/// Resolve the compose file and the project name.
///
/// Precedence is docker's, read from compose-go's `withNamePrecedenceLoad`
/// rather than remembered: `-p`, then `COMPOSE_PROJECT_NAME`, then the file's
/// own `name:`, then the project directory's base name normalized.
async fn locate(args: &ComposeArgs, streams: &mut Streams) -> anyhow::Result<Located> {
    if args.file.len() > 1 {
        anyhow::bail!(
            "only one -f/--file is accepted: satl compose does not merge compose files, and a \
             silent half-merge is worse than no merge at all"
        );
    }
    let cwd = std::env::current_dir()?;
    let search_dir = args
        .project_directory
        .clone()
        .unwrap_or_else(|| cwd.clone());
    let file = match args.file.first() {
        Some(path) => {
            if !path.is_file() {
                anyhow::bail!("no such compose file: {}", path.display());
            }
            Some(path.clone())
        }
        None => discover(&search_dir, streams).await,
    };
    let dir = match (&args.project_directory, &file) {
        (Some(dir), _) => dir.clone(),
        (None, Some(file)) => file
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map_or_else(|| cwd.clone(), Path::to_path_buf),
        (None, None) => cwd.clone(),
    };

    let project = if let Some(name) = &args.project_name {
        plan::validate_project_name(name)?;
        name.clone()
    } else if let Some(name) = std::env::var("COMPOSE_PROJECT_NAME")
        .ok()
        .filter(|name| !name.is_empty())
    {
        plan::validate_project_name(&name)?;
        name
    } else if let Some(name) = declared_name(file.as_deref())? {
        plan::normalize_project_name(&name)
    } else {
        let base = dir
            .canonicalize()
            .unwrap_or_else(|_| dir.clone())
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let project = plan::normalize_project_name(&base);
        if project.is_empty() {
            anyhow::bail!(
                "cannot derive a project name from {}: name it with -p",
                dir.display()
            );
        }
        project
    };

    Ok(Located { file, dir, project })
}

/// Walk up from `start` looking for a default compose file name.
///
/// The walk stops at the first directory that holds any candidate; several
/// candidates in one directory is a warning and the most preferred one wins,
/// which is what docker does.
async fn discover(start: &Path, streams: &mut Streams) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let found: Vec<PathBuf> = DEFAULT_FILE_NAMES
            .iter()
            .map(|name| dir.join(name))
            .filter(|path| path.is_file())
            .collect();
        if let Some(winner) = found.first() {
            if found.len() > 1 {
                let names: Vec<String> = found
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect();
                streams
                    .warn(&format!(
                        "found multiple config files with supported names: {}; using {}",
                        names.join(", "),
                        winner.display()
                    ))
                    .await;
            }
            return Some(winner.clone());
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// The `name:` a compose file declares, if any.
fn declared_name(file: Option<&Path>) -> anyhow::Result<Option<String>> {
    let Some(file) = file else { return Ok(None) };
    let text = std::fs::read_to_string(file)
        .map_err(|err| anyhow::anyhow!("cannot read {}: {err}", file.display()))?;
    Ok(plan::parse(&text, file)?
        .name
        .filter(|name| !name.is_empty()))
}

/// Build the plan for a located file, or say that there is no file.
fn planned(located: &Located, scope: plan::Scope) -> anyhow::Result<plan::Plan> {
    let Some(file) = &located.file else {
        anyhow::bail!(
            "no compose file found in {} or its parents: name one with -f",
            located.dir.display()
        );
    };
    let text = std::fs::read_to_string(file)
        .map_err(|err| anyhow::anyhow!("cannot read {}: {err}", file.display()))?;
    let env = |name: &str| std::env::var(name).ok();
    let read = |path: &Path| -> anyhow::Result<String> {
        std::fs::read_to_string(path).map_err(|err| anyhow::anyhow!("{err}"))
    };
    let ctx = plan::Context {
        scope,
        path: file,
        project_dir: &located.dir,
        project: &located.project,
        env: &env,
        read: &read,
    };
    plan::build(&text, &ctx)
}

// ---------------------------------------------------------------------------
// up
// ---------------------------------------------------------------------------

/// `satl compose up`: create the networks, then create or update the services.
async fn up(
    host: &Host,
    located: &Located,
    args: &UpArgs,
    world: World,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    let scope = self::scope(host, world, false, streams).await?;
    let mut plan = planned(located, scope.clone())?;
    apply_scale(&mut plan, &args.scale, &scope)?;
    // Before the networks and the services: a build that fails must leave the
    // project exactly as it was, not half-deployed against a stale image.
    if args.build {
        let built = build_images(&plan, &[], false, streams).await?;
        mark_rebuilt(&mut plan, &built);
    }
    for warning in &plan.warnings {
        streams.warn(warning).await;
    }

    up_networks(host, &plan, streams).await?;

    // Names to store IDs, before anything is posted: a reference naming an
    // object that no longer exists must fail here rather than reject every task.
    let secret_ids = resolve_dependencies::<Secret, _>(
        host,
        "/secrets",
        "secret",
        &plan.secret_names(),
        |secret| (secret.id.clone(), secret.spec.name.clone()),
    )
    .await?;
    let config_ids = resolve_dependencies::<Config, _>(
        host,
        "/configs",
        "config",
        &plan.config_names(),
        |config| (config.id.clone(), config.spec.name.clone()),
    )
    .await?;
    plan.resolve(&secret_ids, &config_ids);
    let code = up_services(host, &plan, located, args, streams).await?;
    if args.detach || code != 0 {
        return Ok(code);
    }
    attach(host, located, streams).await
}

/// How long `up` waits for the orchestrator to produce the tasks to attach to.
///
/// A create returns as soon as the service is in the store; the tasks follow
/// from the reconciliation loop, so there is always a gap. Bounded because a
/// service that never schedules -- an image no node can pull, a constraint
/// nothing matches -- must not leave `up` hanging with nothing said.
const ATTACH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Attach to the project's output until Ctrl-C.
///
/// Only reachable under `satl compose`, where every task is on the node this
/// CLI is talking to (api-compat 169) and its logs are therefore readable from
/// here; that is what makes attaching possible at all, and why `satl stack
/// deploy` has no equivalent (api-compat 81, 124).
async fn attach(host: &Host, located: &Located, streams: &mut Streams) -> anyhow::Result<u8> {
    let deadline = std::time::Instant::now() + ATTACH_TIMEOUT;
    let sources = loop {
        let sources = project_sources(host, &located.project, &[], streams).await?;
        if !sources.is_empty() {
            break sources;
        }
        if std::time::Instant::now() >= deadline {
            streams
                .warn(
                    "no task started within 30s, so there is nothing to attach to. The project \
                     is deployed; `satl compose ps` says what its tasks are doing",
                )
                .await;
            return Ok(0);
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    };
    streams
        .errln(&format!(
            "Attached to {}. Ctrl-C detaches; the project keeps running (`satl compose stop` \
             stops it).",
            sources
                .iter()
                .map(|source| source.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .await;
    let options = logs::Options {
        follow: true,
        tail: "all".to_owned(),
        timestamps: false,
    };
    if logs::stream(host, &sources, &options, streams).await? == logs::Ending::Interrupted {
        streams
            .errln("detached; the project is still running")
            .await;
    }
    Ok(0)
}

/// Create the plan's networks, reusing the ones this project already owns.
async fn up_networks(host: &Host, plan: &plan::Plan, streams: &mut Streams) -> anyhow::Result<()> {
    let existing: Vec<crate::api::Network> = client::get_json(host, "/networks").await?;
    for network in &plan.networks {
        match existing.iter().find(|found| found.name == network.name) {
            Some(found) => {
                if !network.external
                    && found.labels.get(plan::PROJECT_LABEL).map(String::as_str)
                        != Some(plan.project.as_str())
                {
                    anyhow::bail!(
                        "network {} already exists and does not belong to project {}: satl \
                         compose only touches what it created (label {}). Give the network \
                         another name in the file, or mark it `external: true` to use it as it is",
                        network.name,
                        plan.project,
                        plan::PROJECT_LABEL
                    );
                }
                streams
                    .outln(&format!("network {} exists", network.name))
                    .await;
            }
            None if network.external => {
                anyhow::bail!(
                    "network {} is declared external but does not exist: create it with \
                     `satl network create -d overlay {}`",
                    network.name,
                    network.name
                );
            }
            None => {
                let created: crate::api::CreateNetworkResponse =
                    client::post_json(host, "/networks/create", network.body.as_ref()).await?;
                if !created.warning.is_empty() {
                    streams.warn(&created.warning).await;
                }
                streams
                    .outln(&format!("network {} created", network.name))
                    .await;
            }
        }
    }

    Ok(())
}

/// Apply `--scale SERVICE=N` to a built plan.
///
/// After the plan rather than inside it, because the file is what `config`
/// prints and what a second `up` compares against; a flag is an override of
/// that, not part of it. The consequence is that the checks the planner ran on
/// the file have to be re-run on the result -- a `--scale web=3` on a service
/// publishing a fixed host port is exactly the conflict the planner refuses
/// (api-compat 174), and it must not slip in through the flag.
fn apply_scale(plan: &mut plan::Plan, scale: &[String], scope: &plan::Scope) -> anyhow::Result<()> {
    for entry in scale {
        let (key, count) = entry.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("--scale {entry:?} is not SERVICE=N: it needs an `=` and a count")
        })?;
        let replicas: u64 = count
            .parse()
            .map_err(|_| anyhow::anyhow!("--scale {entry:?}: {count:?} is not a replica count"))?;
        // Collected before the mutable borrow: the message names what the file
        // does declare, which is the whole value of the refusal.
        let declared = plan
            .services
            .iter()
            .map(|service| service.key.clone())
            .collect::<Vec<_>>()
            .join(", ");
        let service = plan
            .services
            .iter_mut()
            .find(|service| service.key == key)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--scale {entry:?}: this file declares no service {key:?}. It declares: \
                     {declared}"
                )
            })?;
        if service.spec.mode.replicated.is_none() {
            anyhow::bail!(
                "--scale {entry:?}: {key:?} is a global service, which runs one task per \
                 eligible node and has no replica count"
            );
        }
        service.spec.mode = crate::api::cluster::ServiceMode::replicated(replicas);
        plan::refuse_scaled_host_port(scope, service, replicas)?;
    }
    Ok(())
}

/// Create or update the plan's services, then deal with the orphans.
async fn up_services(
    host: &Host,
    plan: &plan::Plan,
    located: &Located,
    args: &UpArgs,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    let services: Vec<Service> = client::get_json(host, "/services").await?;
    for planned in &plan.services {
        if let Some(found) = services
            .iter()
            .find(|found| found.spec.name == planned.name)
        {
            let owner = found
                .spec
                .labels
                .get(plan::PROJECT_LABEL)
                .map(String::as_str);
            if owner != Some(plan.project.as_str()) {
                anyhow::bail!(
                    "service {} already exists and does not belong to project {}: satl \
                     compose only touches what it created (label {})",
                    planned.name,
                    plan.project,
                    plan::PROJECT_LABEL
                );
            }
            let version = found.version.index.to_string();
            let path = format!(
                "/services/{}/update{}",
                found.id,
                client::query(&[("version", version.as_str())])
            );
            let response: ServiceUpdateResponse =
                client::post_json(host, &path, Some(&planned.spec)).await?;
            for warning in &response.warnings {
                streams.warn(warning).await;
            }
            streams
                .outln(&format!("service {} updated", planned.name))
                .await;
        } else {
            let created: ServiceCreateResponse =
                client::post_json(host, "/services/create", Some(&planned.spec)).await?;
            for warning in &created.warnings {
                streams.warn(warning).await;
            }
            streams
                .outln(&format!("service {} created", planned.name))
                .await;
        }
    }

    // Anything left carrying this project's label that the file no longer
    // declares. Docker warns and removes only with --remove-orphans; so do we,
    // because a service the operator moved out of the file by hand is not
    // obviously garbage.
    let declared: BTreeSet<&str> = plan
        .services
        .iter()
        .map(|service| service.name.as_str())
        .collect();
    let mut failed = false;
    for service in &services {
        let ours = service
            .spec
            .labels
            .get(plan::PROJECT_LABEL)
            .map(String::as_str)
            == Some(plan.project.as_str());
        if !ours || declared.contains(service.spec.name.as_str()) {
            continue;
        }
        if args.remove_orphans {
            match client::delete_ok(host, &format!("/services/{}", service.id)).await {
                Ok(()) => {
                    streams
                        .outln(&format!("service {} removed (orphan)", service.spec.name))
                        .await;
                }
                Err(err) => {
                    streams.error(&format!("{err:#}")).await;
                    failed = true;
                }
            }
        } else {
            streams
                .warn(&format!(
                    "service {} belongs to project {} but is not in {}: run with \
                     --remove-orphans to remove it",
                    service.spec.name,
                    plan.project,
                    located
                        .file
                        .as_deref()
                        .unwrap_or_else(|| Path::new("the compose file"))
                        .display()
                ))
                .await;
        }
    }
    Ok(if failed { FAILURE } else { 0 })
}

/// Map each referenced secret/config name to its store ID.
async fn resolve_dependencies<T, F>(
    host: &Host,
    path: &str,
    kind: &str,
    names: &BTreeSet<String>,
    entry: F,
) -> anyhow::Result<BTreeMap<String, String>>
where
    T: serde::de::DeserializeOwned,
    F: Fn(&T) -> (String, String),
{
    if names.is_empty() {
        return Ok(BTreeMap::new());
    }
    let stored: Vec<T> = client::get_json(host, path).await?;
    let by_name: BTreeMap<String, String> = stored
        .iter()
        .map(&entry)
        .map(|(id, name)| (name, id))
        .collect();
    let mut ids = BTreeMap::new();
    for name in names {
        let id = by_name.get(name).cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "{kind} not found: {name}. Create it with `satl {kind} create {name} <file>`; \
                 satl compose never creates one from a file (a {kind} is immutable)"
            )
        })?;
        ids.insert(name.clone(), id);
    }
    Ok(ids)
}

// ---------------------------------------------------------------------------
// down
// ---------------------------------------------------------------------------

/// `satl compose down`: remove exactly what `up` created, and nothing else.
///
/// Scoping is by label, never by name: every service and network `up` makes
/// carries `com.docker.compose.project=<project>`, and this reads that label
/// back. A stack removed this way therefore needs no compose file at all —
/// `satl compose down -p <project>` is enough, which is also how docker's own
/// `Down()` works (it takes a project *name*; the model may be nil).
async fn down(
    host: &Host,
    located: &Located,
    args: &DownArgs,
    world: World,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    // `-v` needs to know *which* volumes, and volume labels are not persisted
    // (api-compat 39), so unlike the rest of `down` — which works from the
    // project label and needs no file at all — this reads the file. Resolved
    // before anything is deleted, so a missing file is not a half-done `down`.
    let volumes = if args.volumes {
        Some(removable_volumes(host, located, world, streams).await?)
    } else {
        None
    };
    let mut failed = false;
    let mut removed = 0_usize;

    let services: Vec<Service> = client::get_json(host, "/services").await?;
    let mine: Vec<&Service> = services
        .iter()
        .filter(|service| {
            service
                .spec
                .labels
                .get(plan::PROJECT_LABEL)
                .map(String::as_str)
                == Some(located.project.as_str())
        })
        .collect();
    for service in &mine {
        match client::delete_ok(host, &format!("/services/{}", service.id)).await {
            Ok(()) => {
                removed += 1;
                streams
                    .outln(&format!("service {} removed", service.spec.name))
                    .await;
            }
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }

    let networks: Vec<crate::api::Network> = client::get_json(host, "/networks").await?;
    let mine: Vec<&crate::api::Network> = networks
        .iter()
        .filter(|network| {
            network.labels.get(plan::PROJECT_LABEL).map(String::as_str)
                == Some(located.project.as_str())
        })
        .collect();
    for network in &mine {
        match remove_network(host, network, streams).await {
            Ok(()) => {
                removed += 1;
                streams
                    .outln(&format!("network {} removed", network.name))
                    .await;
            }
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }

    // Last, and after the network wait above: a volume a task still holds is a
    // 409, and the tasks of the services removed a moment ago take their stop
    // grace period to become terminal.
    if let Some(volumes) = volumes {
        for name in &volumes {
            match remove_volume(host, name, streams).await {
                Ok(true) => {
                    removed += 1;
                    streams.outln(&format!("volume {name} removed")).await;
                }
                Ok(false) => {
                    streams
                        .warn(&format!(
                            "volume {name} does not exist on this node; nothing to remove"
                        ))
                        .await;
                }
                Err(err) => {
                    streams.error(&format!("{err:#}")).await;
                    failed = true;
                }
            }
        }
    }

    if removed == 0 && !failed {
        streams
            .warn(&format!(
                "no resource found to remove for project {}",
                located.project
            ))
            .await;
    }
    Ok(if failed { FAILURE } else { 0 })
}

/// The volume names `down -v` may remove, or the reason it may not.
///
/// Only in the node-local world. Under `satl stack` the project's tasks ran on
/// whichever nodes the scheduler chose, each with a dataset of its own, and the
/// CLI speaks one node's unix socket — so there is no single node to remove
/// from and no label to find them by (api-compat 39, 118).
///
/// `external: true` volumes are excluded: they are somebody else's, exactly as
/// an external network is.
async fn removable_volumes(
    host: &Host,
    located: &Located,
    world: World,
    streams: &mut Streams,
) -> anyhow::Result<Vec<String>> {
    if world != World::Local {
        anyhow::bail!(
            "-v/--volumes is refused for a stack: a volume is a node-local ZFS dataset, one per \
             node that ran a task, and volume labels are not persisted (api-compat 39), so \
             there is no single node to remove from. `satl compose down -v` does remove them, \
             on the node it runs on; for a stack, `satl stack config` prints the names and \
             `satl volume rm <name>` removes one where its daemon is"
        );
    }
    let scope = self::scope(host, world, false, streams).await?;
    let plan = planned(located, scope)?;
    Ok(plan
        .volumes
        .iter()
        .filter(|volume| !volume.external)
        .map(|volume| volume.name.clone())
        .collect())
}

/// Remove one volume, waiting out the tasks that still hold it.
///
/// `Ok(false)` when there is nothing there: a project whose tasks all ran on
/// another node leaves no dataset here, and that is not a failure.
async fn remove_volume(host: &Host, name: &str, streams: &mut Streams) -> anyhow::Result<bool> {
    let path = format!("/volumes/{name}");
    let deadline = std::time::Instant::now() + NETWORK_REMOVAL_TIMEOUT;
    let mut said = false;
    loop {
        let response = client::request(host, &hyper::Method::DELETE, &path, None).await?;
        if response.status.is_success() {
            return Ok(true);
        }
        if response.status == hyper::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if response.status != hyper::StatusCode::CONFLICT || std::time::Instant::now() >= deadline {
            return Err(client::daemon_error(response.status, &response.body));
        }
        if !said {
            said = true;
            streams
                .warn(&format!(
                    "volume {name} is still in use by a task; waiting for it to stop"
                ))
                .await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// How long `down` waits for a network's last task to reach a terminal state.
const NETWORK_REMOVAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// Remove a network, waiting out the tasks that still hold it.
///
/// Deleting a network under a live task is a 409 (api-compat 70), and the tasks
/// of the services removed a moment ago take their stop grace period to get
/// there — so a `down` that deleted services and then immediately failed on the
/// network would be a `down` that never worked. The wait is on the daemon's own
/// answer, not on a timer: as soon as the last task is terminal the delete
/// succeeds.
async fn remove_network(
    host: &Host,
    network: &crate::api::Network,
    streams: &mut Streams,
) -> anyhow::Result<()> {
    let path = format!("/networks/{}", network.id);
    let deadline = std::time::Instant::now() + NETWORK_REMOVAL_TIMEOUT;
    let mut said = false;
    loop {
        let response = client::request(host, &hyper::Method::DELETE, &path, None).await?;
        if response.status.is_success() {
            return Ok(());
        }
        if response.status != hyper::StatusCode::CONFLICT || std::time::Instant::now() >= deadline {
            return Err(client::daemon_error(response.status, &response.body));
        }
        if !said {
            said = true;
            streams
                .warn(&format!(
                    "network {} still has tasks attached; waiting for them to stop",
                    network.name
                ))
                .await;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

// ---------------------------------------------------------------------------
// ps / config
// ---------------------------------------------------------------------------

/// `satl compose ps`: the tasks of this project's services.
///
/// It earns its place by being the only view scoped to the project: `satl
/// service ps` takes service names, and the names here are namespaced, so
/// without this an operator has to reconstruct `<project>_<service>` by hand for
/// every service in the file.
async fn ps(
    host: &Host,
    located: &Located,
    args: &PsArgs,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    let services: Vec<Service> = client::get_json(host, "/services").await?;
    let mine: Vec<&Service> = services
        .iter()
        .filter(|service| {
            service
                .spec
                .labels
                .get(plan::PROJECT_LABEL)
                .map(String::as_str)
                == Some(located.project.as_str())
        })
        .collect();
    let mut tasks: Vec<Task> = Vec::new();
    let mut failed = false;
    for service in &mine {
        let filters = serde_json::json!({"service": {service.spec.name.clone(): true}}).to_string();
        let path = format!("/tasks{}", client::query(&[("filters", filters.as_str())]));
        match client::get_json::<Vec<Task>>(host, &path).await {
            Ok(found) => tasks.extend(found),
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    let nodes: Vec<crate::api::cluster::Node> =
        client::get_json(host, "/nodes").await.unwrap_or_default();
    let hostnames: BTreeMap<String, String> = nodes
        .iter()
        .map(|node| (node.id.clone(), node.display_name().to_owned()))
        .collect();
    let render_args = crate::cmd::service::PsArgs {
        no_trunc: args.no_trunc,
        quiet: args.quiet,
        services: Vec::new(),
    };
    streams
        .out(
            crate::cmd::service::render_ps(&tasks, &hostnames, &render_args, format::now_unix())
                .as_bytes(),
        )
        .await;
    Ok(if failed { FAILURE } else { 0 })
}

/// `satl compose config`: what `up` would create.
///
/// Docker prints the merged compose file; this prints the **specs**, because
/// that is where the surprises live — the namespaced names, the DNS aliases, the
/// project labels, the ingress ports, the nanosecond durations. Reading it back
/// is how an operator checks a refusal they disagree with, and it is what the
/// unit tests assert.
async fn config(
    host: &Host,
    located: &Located,
    args: &ConfigArgs,
    world: World,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    let scope = self::scope(host, world, true, streams).await?;
    let plan = planned(located, scope)?;
    for warning in &plan.warnings {
        streams.warn(warning).await;
    }
    if args.quiet {
        return Ok(0);
    }
    streams.outln(&render_config(&plan)?).await;
    Ok(0)
}

/// Render a plan as JSON (pure, for goldens).
pub fn render_config(plan: &plan::Plan) -> anyhow::Result<String> {
    let document = serde_json::json!({
        "Project": plan.project,
        "Networks": plan
            .networks
            .iter()
            .map(|network| serde_json::json!({
                "Key": network.key,
                "Name": network.name,
                "External": network.external,
                "Create": network.body,
            }))
            .collect::<Vec<_>>(),
        "Volumes": plan
            .volumes
            .iter()
            .map(|volume| serde_json::json!({
                "Key": volume.key,
                "Name": volume.name,
                "External": volume.external,
            }))
            .collect::<Vec<_>>(),
        "Services": plan
            .services
            .iter()
            .map(|service| serde_json::json!({
                "Key": service.key,
                "Name": service.name,
                "Spec": service.spec,
            }))
            .collect::<Vec<_>>(),
    });
    Ok(serde_json::to_string_pretty(&document)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;
    use crate::stub::{Reply, Stub};

    const SERVICE_ID: &str = "2hvy0lj3x0b883f8e30fyp218";
    const NETWORK_ID: &str = "3hvy0lj3x0b883f8e30fyp219";
    const SECRET_ID: &str = "4hvy0lj3x0b883f8e30fyp220";

    /// Two services, one network, no dependencies: the shape most flow tests
    /// need.
    const SMALL: &str = "\
services:
  web:
    image: nginx
    ports: ['18088:80']
  redis:
    image: redis
";

    /// One service and one named volume, for the `down -v` half.
    const WITH_VOLUME: &str = "\
services:
  web:
    image: nginx
    volumes:
      - 'data:/var/lib/data'
volumes:
  data:
";

    /// The node id every `World::Local` test plans against.
    const TEST_NODE: &str = "1oihjf6ers1k3v6ow4lxiy5bd";

    /// A `GET /info` document carrying this node's id, which is what the
    /// node-local world pins to.
    fn info_body() -> String {
        format!(r#"{{"Swarm":{{"NodeID":"{TEST_NODE}"}}}}"#)
    }

    fn located(dir: &tempfile::TempDir, text: &str) -> Located {
        let file = dir.path().join("compose.yaml");
        std::fs::write(&file, text).expect("the fixture is written");
        Located {
            file: Some(file),
            dir: dir.path().to_path_buf(),
            project: "demo".to_owned(),
        }
    }

    /// A `GET /services` document for a service this project owns.
    fn owned_service(name: &str, version: u64) -> String {
        format!(
            r#"{{"ID":"{SERVICE_ID}","Version":{{"Index":{version}}},
               "Spec":{{"Name":"{name}",
                 "Labels":{{"com.docker.compose.project":"demo",
                            "com.docker.compose.service":"{}"}},
                 "TaskTemplate":{{"ContainerSpec":{{"Image":"nginx"}}}},
                 "Mode":{{"Replicated":{{"Replicas":1}}}}}}}}"#,
            name.strip_prefix("demo_").unwrap_or(name)
        )
    }

    #[tokio::test]
    async fn up_creates_the_network_then_the_services() {
        let stub = Stub::start().await;
        stub.on("GET", "/networks", Reply::json(200, "[]"))
            .on(
                "POST",
                "/networks/create",
                Reply::json(201, &format!(r#"{{"Id":"{NETWORK_ID}","Warning":""}}"#)),
            )
            .on("GET", "/services", Reply::json(200, "[]"))
            .on(
                "POST",
                "/services/create",
                Reply::json(201, &format!(r#"{{"ID":"{SERVICE_ID}","Warnings":[]}}"#)),
            );

        let dir = tempfile::tempdir().expect("tempdir");
        let (mut streams, out, err) = testing::streams();
        let code = up(
            &stub.host(),
            &located(&dir, SMALL),
            &UpArgs {
                detach: true,
                ..UpArgs::default()
            },
            World::Cluster,
            &mut streams,
        )
        .await
        .expect("up succeeds");

        assert_eq!(code, 0);
        assert_eq!(
            out.contents(),
            "network demo_default created\nservice demo_redis created\nservice demo_web created\n"
        );
        assert_eq!(err.contents(), "");
        assert_eq!(
            stub.routes(),
            vec![
                "GET /networks",
                "POST /networks/create",
                "GET /services",
                "POST /services/create",
                "POST /services/create",
            ],
            "the network exists before a service can attach to it"
        );
        let call = stub.first_call("POST /networks/create").expect("create");
        assert!(call.body.contains(r#""Driver":"overlay""#), "{}", call.body);
        assert!(
            call.body.contains(r#""com.docker.compose.project":"demo""#),
            "the label `down` scopes by must be set at creation: {}",
            call.body
        );
    }

    #[tokio::test]
    async fn up_updates_a_service_it_already_owns_against_its_version() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/networks",
            Reply::json(
                200,
                &format!(
                    r#"[{{"Id":"{NETWORK_ID}","Name":"demo_default","Driver":"overlay",
                        "Scope":"swarm",
                        "Labels":{{"com.docker.compose.project":"demo",
                                   "com.docker.compose.network":"default"}}}}]"#
                ),
            ),
        )
        .on(
            "GET",
            "/services",
            Reply::json(200, &format!("[{}]", owned_service("demo_web", 7))),
        )
        .on(
            "POST",
            &format!("/services/{SERVICE_ID}/update"),
            Reply::json(200, r#"{"Warnings":[]}"#),
        )
        .on(
            "POST",
            "/services/create",
            Reply::json(201, r#"{"ID":"9zzz","Warnings":[]}"#),
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let (mut streams, out, _err) = testing::streams();
        up(
            &stub.host(),
            &located(&dir, SMALL),
            &UpArgs {
                detach: true,
                ..UpArgs::default()
            },
            World::Cluster,
            &mut streams,
        )
        .await
        .expect("up succeeds");

        assert_eq!(
            out.contents(),
            "network demo_default exists\nservice demo_redis created\nservice demo_web updated\n"
        );
        let call = stub
            .first_call(&format!("POST /services/{SERVICE_ID}/update"))
            .expect("the update call");
        assert_eq!(call.query, "version=7");
        assert!(call.body.contains(r#""Name":"demo_web""#), "{}", call.body);
    }

    /// The rule that makes `up` safe to run in a shared cluster: an object with
    /// the name this project would use, but without its label, is somebody
    /// else's and is never touched.
    #[tokio::test]
    async fn up_refuses_to_adopt_an_object_it_does_not_own() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/networks",
            Reply::json(
                200,
                &format!(
                    r#"[{{"Id":"{NETWORK_ID}","Name":"demo_default","Driver":"overlay",
                        "Scope":"swarm","Labels":{{}}}}]"#
                ),
            ),
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut streams, out, _err) = testing::streams();
        let err = up(
            &stub.host(),
            &located(&dir, SMALL),
            &UpArgs {
                detach: true,
                ..UpArgs::default()
            },
            World::Cluster,
            &mut streams,
        )
        .await
        .expect_err("the network is not ours");
        assert!(
            format!("{err:#}").contains("does not belong to project demo"),
            "{err:#}"
        );
        assert!(out.contents().is_empty());
        assert_eq!(stub.routes(), vec!["GET /networks"], "nothing was created");
    }

    #[tokio::test]
    async fn up_resolves_a_secret_name_to_an_id_and_refuses_a_missing_one() {
        let text = "\
services:
  web:
    image: nginx
    secrets: [db]
secrets:
  db:
    external: true
";
        let stub = Stub::start().await;
        stub.on("GET", "/networks", Reply::json(200, "[]"))
            .on(
                "POST",
                "/networks/create",
                Reply::json(201, r#"{"Id":"n","Warning":""}"#),
            )
            .on(
                "GET",
                "/secrets",
                Reply::json(
                    200,
                    &format!(r#"[{{"ID":"{SECRET_ID}","Spec":{{"Name":"db"}}}}]"#),
                ),
            )
            .on("GET", "/services", Reply::json(200, "[]"))
            .on(
                "POST",
                "/services/create",
                Reply::json(201, &format!(r#"{{"ID":"{SERVICE_ID}","Warnings":[]}}"#)),
            );
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut streams, _out, _err) = testing::streams();
        up(
            &stub.host(),
            &located(&dir, text),
            &UpArgs {
                detach: true,
                ..UpArgs::default()
            },
            World::Cluster,
            &mut streams,
        )
        .await
        .expect("up succeeds");
        let call = stub.first_call("POST /services/create").expect("create");
        assert!(
            call.body.contains(&format!(r#""SecretID":"{SECRET_ID}""#)),
            "{}",
            call.body
        );

        // The same file against a cluster that has no such secret.
        let stub = Stub::start().await;
        stub.on("GET", "/networks", Reply::json(200, "[]"))
            .on(
                "POST",
                "/networks/create",
                Reply::json(201, r#"{"Id":"n","Warning":""}"#),
            )
            .on("GET", "/secrets", Reply::json(200, "[]"));
        let (mut streams, _out, _err) = testing::streams();
        let err = up(
            &stub.host(),
            &located(&dir, text),
            &UpArgs {
                detach: true,
                ..UpArgs::default()
            },
            World::Cluster,
            &mut streams,
        )
        .await
        .expect_err("no such secret");
        assert!(
            format!("{err:#}").contains("secret not found: db"),
            "{err:#}"
        );
        assert!(
            !stub.routes().contains(&"POST /services/create".to_owned()),
            "no service is created once a reference cannot be resolved"
        );
    }

    #[tokio::test]
    async fn up_warns_about_an_orphan_and_removes_it_only_when_asked() {
        let orphan = r#"{"ID":"7zzz","Version":{"Index":3},
               "Spec":{"Name":"demo_gone",
                 "Labels":{"com.docker.compose.project":"demo",
                            "com.docker.compose.service":"gone"},
                 "TaskTemplate":{"ContainerSpec":{"Image":"nginx"}},
                 "Mode":{"Replicated":{"Replicas":1}}}}"#;
        for (args, expect_removal) in [
            (
                UpArgs {
                    detach: true,
                    ..UpArgs::default()
                },
                false,
            ),
            (
                UpArgs {
                    detach: true,
                    remove_orphans: true,
                    ..UpArgs::default()
                },
                true,
            ),
        ] {
            let stub = Stub::start().await;
            stub.on("GET", "/networks", Reply::json(200, "[]"))
                .on(
                    "POST",
                    "/networks/create",
                    Reply::json(201, r#"{"Id":"n","Warning":""}"#),
                )
                .on("GET", "/services", Reply::json(200, &format!("[{orphan}]")))
                .on(
                    "POST",
                    "/services/create",
                    Reply::json(201, &format!(r#"{{"ID":"{SERVICE_ID}","Warnings":[]}}"#)),
                )
                .on("DELETE", "/services/7zzz", Reply::empty(200));
            let dir = tempfile::tempdir().expect("tempdir");
            let (mut streams, out, err) = testing::streams();
            up(
                &stub.host(),
                &located(&dir, SMALL),
                &args,
                World::Cluster,
                &mut streams,
            )
            .await
            .expect("up succeeds");
            if expect_removal {
                assert!(
                    out.contents()
                        .contains("service demo_gone removed (orphan)"),
                    "{}",
                    out.contents()
                );
            } else {
                assert!(
                    err.contents().contains("run with --remove-orphans"),
                    "{}",
                    err.contents()
                );
                assert!(
                    !stub.routes().contains(&"DELETE /services/7zzz".to_owned()),
                    "an orphan is never removed without being asked for"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // down
    // -----------------------------------------------------------------------

    /// The whole point of the label: `down` removes what `up` created and
    /// nothing that merely looks like it.
    #[tokio::test]
    async fn down_removes_only_what_carries_the_project_label() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/services",
            Reply::json(
                200,
                &format!(
                    "[{},{},{}]",
                    owned_service("demo_web", 7),
                    // Same project, another service.
                    owned_service("demo_redis", 2).replace(SERVICE_ID, "5zzz"),
                    // Another project's service, and a hand-made one with no
                    // labels at all. Neither may be touched.
                    r#"{"ID":"6zzz","Version":{"Index":1},
                        "Spec":{"Name":"other_web",
                          "Labels":{"com.docker.compose.project":"other"},
                          "TaskTemplate":{"ContainerSpec":{"Image":"nginx"}},
                          "Mode":{"Replicated":{"Replicas":1}}}}"#
                ),
            ),
        )
        .on(
            "DELETE",
            &format!("/services/{SERVICE_ID}"),
            Reply::empty(200),
        )
        .on("DELETE", "/services/5zzz", Reply::empty(200))
        .on(
            "GET",
            "/networks",
            Reply::json(
                200,
                &format!(
                    r#"[{{"Id":"{NETWORK_ID}","Name":"demo_default","Driver":"overlay",
                        "Scope":"swarm",
                        "Labels":{{"com.docker.compose.project":"demo",
                                   "com.docker.compose.network":"default"}}}},
                       {{"Id":"8zzz","Name":"satl0","Driver":"bridge","Scope":"local",
                        "Labels":{{}}}}]"#
                ),
            ),
        )
        .on(
            "DELETE",
            &format!("/networks/{NETWORK_ID}"),
            Reply::empty(200),
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let (mut streams, out, err) = testing::streams();
        let code = down(
            &stub.host(),
            &located(&dir, SMALL),
            &DownArgs::default(),
            World::Cluster,
            &mut streams,
        )
        .await
        .expect("down succeeds");

        assert_eq!(code, 0);
        assert_eq!(
            out.contents(),
            "service demo_web removed\nservice demo_redis removed\nnetwork demo_default removed\n"
        );
        assert_eq!(err.contents(), "");
        assert_eq!(
            stub.routes(),
            vec![
                "GET /services",
                &format!("DELETE /services/{SERVICE_ID}"),
                "DELETE /services/5zzz",
                "GET /networks",
                &format!("DELETE /networks/{NETWORK_ID}"),
            ],
            "no other project's object is even asked about"
        );
    }

    /// A network cannot be removed while a task still holds it (api-compat 70),
    /// and the tasks of the services `down` just removed take their grace period
    /// to get there. Time is paused, so the retry costs the test nothing.
    #[tokio::test(start_paused = true)]
    async fn down_waits_for_the_tasks_to_stop_before_removing_the_network() {
        let stub = Stub::start().await;
        stub.on("GET", "/services", Reply::json(200, "[]"))
            .on(
                "GET",
                "/networks",
                Reply::json(
                    200,
                    &format!(
                        r#"[{{"Id":"{NETWORK_ID}","Name":"demo_default","Driver":"overlay",
                            "Scope":"swarm",
                            "Labels":{{"com.docker.compose.project":"demo"}}}}]"#
                    ),
                ),
            )
            .on(
                "DELETE",
                &format!("/networks/{NETWORK_ID}"),
                Reply::json(
                    409,
                    r#"{"message":"network demo_default has active endpoints"}"#,
                ),
            )
            .on(
                "DELETE",
                &format!("/networks/{NETWORK_ID}"),
                Reply::empty(200),
            );
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut streams, out, err) = testing::streams();
        down(
            &stub.host(),
            &located(&dir, SMALL),
            &DownArgs::default(),
            World::Cluster,
            &mut streams,
        )
        .await
        .expect("down succeeds once the conflict clears");
        assert_eq!(out.contents(), "network demo_default removed\n");
        assert!(
            err.contents().contains("waiting for them to stop"),
            "{}",
            err.contents()
        );
    }

    #[tokio::test]
    async fn down_with_nothing_of_ours_says_so_and_succeeds() {
        let stub = Stub::start().await;
        stub.on("GET", "/services", Reply::json(200, "[]")).on(
            "GET",
            "/networks",
            Reply::json(200, "[]"),
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut streams, out, err) = testing::streams();
        let code = down(
            &stub.host(),
            &located(&dir, SMALL),
            &DownArgs::default(),
            World::Cluster,
            &mut streams,
        )
        .await
        .expect("down succeeds");
        assert_eq!(code, 0);
        assert!(out.contents().is_empty());
        assert_eq!(
            err.contents(),
            "WARNING: no resource found to remove for project demo\n"
        );
    }

    /// `-v` is refused for a stack and honoured for a compose project: the two
    /// halves of the same rule, that a volume can only be removed where it is.
    #[tokio::test]
    async fn down_removes_volumes_locally_and_refuses_them_for_a_stack() {
        let dir = tempfile::tempdir().expect("tempdir");
        let args = DownArgs {
            volumes: true,
            ..DownArgs::default()
        };

        // A stack's tasks ran on nodes this CLI cannot reach.
        let stub = Stub::start().await;
        let (mut streams, _out, _err) = testing::streams();
        let err = down(
            &stub.host(),
            &located(&dir, SMALL),
            &args,
            World::Cluster,
            &mut streams,
        )
        .await
        .expect_err("a stack's volumes are on nodes this CLI cannot reach");
        let message = format!("{err:#}");
        assert!(
            message.contains("a volume is a node-local ZFS dataset"),
            "{message}"
        );
        assert!(message.contains("satl compose down -v"), "{message}");
        assert!(
            stub.routes().is_empty(),
            "the refusal happens before anything is deleted"
        );

        // The node-local world removes the volumes the file declares, by name
        // (there is no label to find them by), and only after the services.
        let dir = tempfile::tempdir().expect("tempdir");
        let info = info_body();
        let stub = Stub::start().await;
        let stub = stub
            .on("GET", "/info", Reply::json(200, &info))
            .on("GET", "/services", Reply::json(200, "[]"))
            .on("GET", "/networks", Reply::json(200, "[]"))
            .on("DELETE", "/volumes/demo-data", Reply::empty(204));
        let (mut streams, out, _err) = testing::streams();
        let code = down(
            &stub.host(),
            &located(&dir, WITH_VOLUME),
            &args,
            World::Local,
            &mut streams,
        )
        .await
        .expect("down succeeds");
        assert_eq!(code, 0);
        assert!(
            out.contents().contains("volume demo-data removed"),
            "{}",
            out.contents()
        );
    }

    // -----------------------------------------------------------------------
    // stop / start / restart / --scale  (M11c)
    // -----------------------------------------------------------------------

    /// `stop` then `start` is a round trip through the *file*, not through
    /// hidden state: nothing stashes the old replica count anywhere, so a
    /// `start` from another checkout or after a daemon restart restores the
    /// same number, and that number is one an operator can read.
    #[tokio::test]
    async fn stop_zeroes_the_replica_counts_and_start_restores_them_from_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let running = format!("[{}]", owned_service("demo-web", 7));

        let stub = Stub::start().await;
        stub.on("GET", "/services", Reply::json(200, &running)).on(
            "POST",
            &format!("/services/{SERVICE_ID}/update"),
            Reply::json(200, r#"{"Warnings":[]}"#),
        );
        let (mut streams, out, _err) = testing::streams();
        let code = stop(&stub.host(), &located(&dir, SMALL), &mut streams)
            .await
            .expect("stop succeeds");
        assert_eq!(code, 0);
        assert!(out.contents().contains("service demo-web stopped"));
        let posted = stub
            .first_call(&format!("POST /services/{SERVICE_ID}/update"))
            .expect("the spec was reposted");
        assert!(
            posted.query.contains("version=7"),
            "the repost must carry the version it read: {}",
            posted.query
        );
        assert!(
            posted.body.contains(r#""Replicas":0"#),
            "stop scales to zero, it does not remove: {}",
            posted.body
        );

        // `start` puts back what the file asks for, and never creates.
        let info = info_body();
        let stub = Stub::start().await;
        stub.on("GET", "/info", Reply::json(200, &info))
            .on("GET", "/services", Reply::json(200, &running))
            .on(
                "POST",
                &format!("/services/{SERVICE_ID}/update"),
                Reply::json(200, r#"{"Warnings":[]}"#),
            );
        let (mut streams, out, err) = testing::streams();
        let code = start(
            &stub.host(),
            &located(&dir, SMALL),
            World::Local,
            &mut streams,
        )
        .await
        .expect("start succeeds");
        assert_eq!(code, 0);
        assert!(out.contents().contains("service demo-web started"));
        let posted = stub
            .first_call(&format!("POST /services/{SERVICE_ID}/update"))
            .expect("the spec was reposted");
        assert!(
            posted.body.contains(r#""Replicas":1"#),
            "start restores the file's count: {}",
            posted.body
        );
        // The file's other service is not running, and start says so rather
        // than quietly becoming an `up`.
        assert!(
            err.contents().contains("demo-redis is not running"),
            "{}",
            err.contents()
        );
        assert!(
            !stub.routes().contains(&"POST /services/create".to_owned()),
            "start must never create"
        );
    }

    /// `restart` is a replacement, because a task is one-shot: it bumps the
    /// counter the orchestrator's dirty comparison watches and lets the rolling
    /// updater do the work under the service's own policy.
    #[tokio::test]
    async fn restart_bumps_force_update_rather_than_touching_the_tasks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/services",
            Reply::json(200, &format!("[{}]", owned_service("demo-web", 9))),
        )
        .on(
            "POST",
            &format!("/services/{SERVICE_ID}/update"),
            Reply::json(200, r#"{"Warnings":[]}"#),
        );
        let (mut streams, out, _err) = testing::streams();
        let code = restart(&stub.host(), &located(&dir, SMALL), &mut streams)
            .await
            .expect("restart succeeds");
        assert_eq!(code, 0);
        assert!(out.contents().contains("service demo-web restarting"));
        let posted = stub
            .first_call(&format!("POST /services/{SERVICE_ID}/update"))
            .expect("the spec was reposted");
        assert!(
            posted.body.contains(r#""ForceUpdate":1"#),
            "restart bumps ForceUpdate: {}",
            posted.body
        );
        assert!(
            !stub.routes().iter().any(|route| route.contains("/tasks")),
            "restart goes through the service, never at a task"
        );
    }

    /// `--scale` overrides the file, and is held to the same rule the file is:
    /// a fixed host port cannot be taken twice on one node.
    #[test]
    fn scale_overrides_the_file_and_cannot_smuggle_a_host_port_conflict() {
        let scope = plan::Scope::Local {
            node_id: TEST_NODE.to_owned(),
        };
        let build = |text: &str| {
            let env = |_: &str| None;
            let read = |_: &std::path::Path| -> anyhow::Result<String> {
                Err(anyhow::anyhow!("no env_file in this fixture"))
            };
            let ctx = plan::Context {
                scope: scope.clone(),
                path: std::path::Path::new("./compose.yaml"),
                project_dir: std::path::Path::new("/srv/demo"),
                project: "demo",
                env: &env,
                read: &read,
            };
            plan::build(text, &ctx).expect("the fixture plans")
        };

        // A service with no published port scales freely.
        let mut plan = build("services:\n  web:\n    image: nginx\n");
        apply_scale(&mut plan, &["web=3".to_owned()], &scope).expect("nothing to contend over");
        assert_eq!(
            plan.services[0]
                .spec
                .mode
                .replicated
                .as_ref()
                .unwrap()
                .replicas,
            Some(3)
        );

        // The same flag on a service publishing 18088 is the conflict the
        // planner refuses when the *file* says it (api-compat 174).
        let mut plan = build(SMALL);
        let err = apply_scale(&mut plan, &["web=2".to_owned()], &scope)
            .expect_err("a host port is taken once on a node");
        let message = format!("{err:#}");
        assert!(message.contains("--scale web=2"), "{message}");
        assert!(message.contains("satl stack deploy"), "{message}");

        // And an unknown service names the ones the file does declare.
        let mut plan = build(SMALL);
        let err =
            apply_scale(&mut plan, &["nope=2".to_owned()], &scope).expect_err("no such service");
        let message = format!("{err:#}");
        assert!(message.contains("It declares: redis, web"), "{message}");
    }

    // -----------------------------------------------------------------------
    // logs  (M11d)
    // -----------------------------------------------------------------------

    /// A docker log frame: stream byte, three pad bytes, big-endian length.
    fn frame(stream: u8, payload: &str) -> Vec<u8> {
        let mut out = vec![stream, 0, 0, 0];
        let len = u32::try_from(payload.len()).expect("short payload");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload.as_bytes());
        out
    }

    /// A `GET /tasks` document for one running task of a service.
    fn running_task(id: &str, slot: u64) -> String {
        format!(
            r#"{{"ID":"{id}","Slot":{slot},"Status":{{"State":"running"}},
               "DesiredState":"running"}}"#
        )
    }

    /// `logs` reads every task of the project, prefixes each line with
    /// `<service>-<slot>`, and keeps stdout and stderr apart.
    #[tokio::test]
    async fn logs_prefixes_each_task_and_keeps_the_two_streams_apart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/services",
            Reply::json(200, &format!("[{}]", owned_service("demo-web", 3))),
        )
        .on(
            "GET",
            "/tasks",
            Reply::json(200, &format!("[{}]", running_task("t0", 1))),
        )
        .on(
            "GET",
            "/containers/t0/logs",
            Reply::raw(200, {
                let mut bytes = frame(1, "hello\n");
                bytes.extend(frame(2, "trouble\n"));
                bytes
            }),
        );
        let (mut streams, out, err) = testing::streams();
        let code = logs(
            &stub.host(),
            &located(&dir, SMALL),
            &LogsArgs::default(),
            &mut streams,
        )
        .await
        .expect("logs succeeds");
        assert_eq!(code, 0);
        // `owned_service` derives the compose key from the name, so the label
        // is `demo-web` here; what matters is the `<key>-<slot>` shape and that
        // the prefix is not the namespaced service name repeated on every line.
        assert!(
            out.contents().ends_with("| hello\n"),
            "stdout: {:?}",
            out.contents()
        );
        assert!(
            err.contents().ends_with("| trouble\n"),
            "stderr: {:?}",
            err.contents()
        );
    }

    /// A project with no live task says so instead of hanging on an empty
    /// stream, and a service name that is not in the file is named.
    #[tokio::test]
    async fn logs_says_when_there_is_nothing_to_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/services",
            Reply::json(200, &format!("[{}]", owned_service("demo-web", 3))),
        )
        .on("GET", "/tasks", Reply::json(200, "[]"));
        let (mut streams, out, err) = testing::streams();
        let args = LogsArgs {
            services: vec!["nope".to_owned()],
            ..LogsArgs::default()
        };
        let code = logs(&stub.host(), &located(&dir, SMALL), &args, &mut streams)
            .await
            .expect("logs succeeds");
        assert_eq!(code, 0);
        assert!(out.contents().is_empty(), "{}", out.contents());
        assert!(
            err.contents().contains("no service \"nope\""),
            "{}",
            err.contents()
        );
        assert!(
            err.contents().contains("nothing to read"),
            "{}",
            err.contents()
        );
    }

    /// A task that has finished is not a source: after a `restart` there is one
    /// of those in every slot, and following them would replay dead output.
    #[test]
    fn terminal_states_are_not_followed() {
        for state in ["complete", "failed", "shutdown", "rejected", "orphaned"] {
            assert!(is_terminal(state), "{state} should be terminal");
        }
        for state in ["running", "starting", "preparing", "ready", "accepted"] {
            assert!(!is_terminal(state), "{state} should not be terminal");
        }
    }

    // -----------------------------------------------------------------------
    // ps / config
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ps_lists_the_tasks_of_this_projects_services_only() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/services",
            Reply::json(
                200,
                &format!(
                    "[{},{}]",
                    owned_service("demo_web", 7),
                    r#"{"ID":"6zzz","Version":{"Index":1},
                        "Spec":{"Name":"other_web","Labels":{},
                          "TaskTemplate":{"ContainerSpec":{"Image":"nginx"}},
                          "Mode":{"Replicated":{"Replicas":1}}}}"#
                ),
            ),
        )
        .on(
            "GET",
            "/tasks",
            Reply::json(
                200,
                r#"[{"ID":"1hvy0lj3x0b883f8e30fyp217","Name":"demo_web.1.1hvy0lj3x0b883f8e30fyp217",
                     "Spec":{"ContainerSpec":{"Image":"nginx"}},
                     "ServiceID":"s","Slot":1,"NodeID":"n1",
                     "Status":{"Timestamp":"2026-02-02T02:45:00Z","State":"running"},
                     "DesiredState":"running"}]"#,
            ),
        )
        .on(
            "GET",
            "/nodes",
            Reply::json(200, r#"[{"ID":"n1","Description":{"Hostname":"node1"}}]"#),
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut streams, out, _err) = testing::streams();
        ps(
            &stub.host(),
            &located(&dir, SMALL),
            &PsArgs::default(),
            &mut streams,
        )
        .await
        .expect("ps succeeds");
        let printed = out.contents();
        assert!(printed.contains("demo_web.1"), "{printed}");
        assert!(printed.contains("node1"), "{printed}");
        // One /tasks call: the other project's service is not asked about.
        assert_eq!(
            stub.routes()
                .iter()
                .filter(|route| *route == "GET /tasks")
                .count(),
            1
        );
        let call = stub.first_call("GET /tasks").expect("a filtered list");
        assert_eq!(
            call.query,
            "filters=%7B%22service%22%3A%7B%22demo_web%22%3Atrue%7D%7D"
        );
    }

    /// `config` is the pure half of `up`, so it talks to no daemon at all.
    #[tokio::test]
    async fn config_prints_the_specs_and_reaches_no_daemon() {
        let stub = Stub::start().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut streams, out, _err) = testing::streams();
        config(
            &stub.host(),
            &located(&dir, SMALL),
            &ConfigArgs::default(),
            World::Cluster,
            &mut streams,
        )
        .await
        .expect("config succeeds");
        assert!(stub.routes().is_empty());
        let printed = out.contents();
        let document: serde_json::Value = serde_json::from_str(&printed).expect("valid JSON");
        assert_eq!(document["Project"], "demo");
        assert_eq!(document["Networks"][0]["Name"], "demo_default");
        assert_eq!(document["Networks"][0]["Create"]["Driver"], "overlay");
        assert_eq!(document["Services"][0]["Name"], "demo_redis");
        assert_eq!(
            document["Services"][1]["Spec"]["TaskTemplate"]["Networks"][0]["Aliases"][0],
            "web"
        );

        // --quiet validates and prints nothing.
        let (mut streams, out, _err) = testing::streams();
        let args = ConfigArgs { quiet: true };
        config(
            &stub.host(),
            &located(&dir, SMALL),
            &args,
            World::Cluster,
            &mut streams,
        )
        .await
        .expect("config succeeds");
        assert!(out.contents().is_empty());
    }

    #[tokio::test]
    async fn a_missing_compose_file_is_named_as_such() {
        let dir = tempfile::tempdir().expect("tempdir");
        let located = Located {
            file: None,
            dir: dir.path().to_path_buf(),
            project: "demo".to_owned(),
        };
        let (mut streams, _out, _err) = testing::streams();
        // World::Cluster needs no node id, so no daemon is dialled and the
        // socket path is never opened.
        let host = Host::parse("unix:///nonexistent/satl.sock").expect("host");
        let err = config(
            &host,
            &located,
            &ConfigArgs::default(),
            World::Cluster,
            &mut streams,
        )
        .await
        .expect_err("there is no file");
        assert!(
            format!("{err:#}").contains("no compose file found in"),
            "{err:#}"
        );
    }

    /// Discovery is docker's: the four names in that order of preference,
    /// walking up from the working directory, stopping at the first directory
    /// that holds any of them.
    #[tokio::test]
    async fn discovery_walks_up_and_prefers_composes_own_order() {
        let root = tempfile::tempdir().expect("tempdir");
        let deep = root.path().join("a").join("b");
        std::fs::create_dir_all(&deep).expect("mkdir");
        let (mut streams, _out, err) = testing::streams();

        // Nothing anywhere: no file, and no error either -- `down -p` needs none.
        assert!(discover(&deep, &mut streams).await.is_none());

        // A file two directories up is found from below.
        let up = root.path().join("a").join("docker-compose.yml");
        std::fs::write(&up, SMALL).expect("write");
        assert_eq!(
            discover(&deep, &mut streams).await.as_deref(),
            Some(up.as_path())
        );

        // In one directory, `compose.yaml` wins over `docker-compose.yml`, and
        // the operator is told which one was used.
        let preferred = root.path().join("a").join("compose.yaml");
        std::fs::write(&preferred, SMALL).expect("write");
        assert_eq!(
            discover(&deep, &mut streams).await.as_deref(),
            Some(preferred.as_path())
        );
        assert!(
            err.contents().contains("found multiple config files"),
            "{}",
            err.contents()
        );

        // A file in the working directory itself beats one further up.
        let nearest = deep.join("compose.yml");
        std::fs::write(&nearest, SMALL).expect("write");
        assert_eq!(
            discover(&deep, &mut streams).await.as_deref(),
            Some(nearest.as_path())
        );
    }

    /// The project name a compose file declares, which `locate` prefers over the
    /// directory's own (and normalizes).
    #[test]
    fn a_files_own_name_key_is_read_and_normalized() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("compose.yaml");
        std::fs::write(&file, format!("name: My.Shop\n{SMALL}")).expect("write");
        assert_eq!(
            declared_name(Some(&file)).expect("valid").as_deref(),
            Some("My.Shop")
        );
        assert_eq!(plan::normalize_project_name("My.Shop"), "myshop");

        std::fs::write(&file, SMALL).expect("write");
        assert!(declared_name(Some(&file)).expect("valid").is_none());

        // A broken file is an error rather than a silently defaulted project:
        // `down` acting on the wrong project name is worse than a refusal.
        std::fs::write(&file, "services:\n  web:\n    image: nginx\n    build: .\n")
            .expect("write");
        assert!(
            declared_name(Some(&file)).is_ok(),
            "only `name:` is read here"
        );
        std::fs::write(&file, "services: [oops\n").expect("write");
        assert!(declared_name(Some(&file)).is_err());
    }
}
