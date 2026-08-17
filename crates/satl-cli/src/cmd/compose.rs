// SPDX-License-Identifier: BSD-2-Clause
//! `satl compose up|down|ps|config`.
//!
//! **This is not `docker compose`.** SatL has no standalone containers: every
//! container is a task of a service and the cluster is always on (invariant 2,
//! api-compat 1), so a compose file here deploys *services* on a shared overlay,
//! scheduled across the cluster — what `docker stack deploy` does, under the
//! command name people type. The deviation is recorded as api-compat 110 and
//! stated in this command's own `--help`, because a familiar command that does
//! something else owes the operator a warning.
//!
//! The parsing and the mapping live in [`plan`], as a pure function of the
//! file's text; this module is the I/O half: finding the file, deriving the
//! project name, and turning a [`plan::Plan`] into REST calls.

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
    /// Create or update the stack's networks and services.
    Up(UpArgs),
    /// Remove the services and networks this project created.
    Down(DownArgs),
    /// List the tasks of the project's services.
    Ps(PsArgs),
    /// Print what `up` would create, without creating it.
    Config(ConfigArgs),
}

/// Flags of `satl compose up`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct UpArgs {
    /// Accepted for compatibility: `up` never attaches, so it is always
    /// detached (there is no cluster-wide log stream yet).
    #[arg(short, long)]
    pub detach: bool,

    /// Remove services of this project that the file no longer declares.
    #[arg(long = "remove-orphans")]
    pub remove_orphans: bool,
}

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

/// Dispatch a `satl compose` subcommand.
pub async fn execute(host: &Host, args: &ComposeArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let located = locate(args, streams).await?;
    match &args.command {
        ComposeCommand::Up(up) => self::up(host, &located, up, streams).await,
        ComposeCommand::Down(down) => self::down(host, &located, down, streams).await,
        ComposeCommand::Ps(ps) => self::ps(host, &located, ps, streams).await,
        ComposeCommand::Config(config) => self::config(&located, config, streams).await,
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
fn planned(located: &Located) -> anyhow::Result<plan::Plan> {
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
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    let mut plan = planned(located)?;
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
    up_services(host, &plan, located, args, streams).await
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
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    if args.volumes {
        anyhow::bail!(
            "-v/--volumes is refused: a volume is a node-local ZFS dataset, one per node that \
             ran a task, and volume labels are not persisted (api-compat 39), so there is no \
             label to scope a removal by. Remove them on each node that ran a task, where the \
             daemon's socket is (`satl volume ls`, then `satl volume rm <name>`); `satl compose \
             config` prints the names this project uses"
        );
    }
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
async fn config(located: &Located, args: &ConfigArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let plan = planned(located)?;
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
            &UpArgs::default(),
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
            &UpArgs::default(),
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
            &UpArgs::default(),
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
            &UpArgs::default(),
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
            &UpArgs::default(),
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
            (UpArgs::default(), false),
            (
                UpArgs {
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
            up(&stub.host(), &located(&dir, SMALL), &args, &mut streams)
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

    #[tokio::test]
    async fn down_refuses_to_remove_volumes_and_says_where_they_are() {
        let stub = Stub::start().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut streams, _out, _err) = testing::streams();
        let args = DownArgs {
            volumes: true,
            ..DownArgs::default()
        };
        let err = down(&stub.host(), &located(&dir, SMALL), &args, &mut streams)
            .await
            .expect_err("volumes are node-local");
        let message = format!("{err:#}");
        assert!(
            message.contains("a volume is a node-local ZFS dataset"),
            "{message}"
        );
        assert!(message.contains("satl volume rm <name>"), "{message}");
        assert!(stub.routes().is_empty(), "nothing is removed");
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
        config(&located(&dir, SMALL), &ConfigArgs::default(), &mut streams)
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
        config(&located(&dir, SMALL), &args, &mut streams)
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
        let err = config(&located, &ConfigArgs::default(), &mut streams)
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
