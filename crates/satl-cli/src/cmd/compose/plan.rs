// SPDX-License-Identifier: BSD-2-Clause
//! From a compose file to exactly what SatL would create.
//!
//! Pure: the file's text, the project name and the two injected accessors
//! (`env_file` reading, environment lookup) in, a [`Plan`] out. No socket, no
//! clock, no `std::env` — which is what lets the whole accepted subset and
//! every refusal be a unit test.
//!
//! The shape of the result is Docker's *stack* model, not compose's: one
//! service per compose service, on a shared overlay, scheduled across the
//! cluster (api-compat 110). Names follow `docker stack deploy`'s convention,
//! read from docker/cli's own `Namespace.Scope` rather than remembered:
//! `<project>_<service>` for services and `<project>_<key>` for networks, with
//! the bare service name added as a **network alias** so that the hostnames
//! inside the compose file keep working.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::api::cluster::{
    ConfigReference, ContainerSpec, EndpointSpec, FileTarget, NetworkAttachmentConfig, Placement,
    PortConfig, ResourceRequirements, Resources, SecretReference, ServiceMode, ServiceSpec,
    TaskRestartPolicy, TaskTemplate, UpdateConfig,
};
use crate::api::{CreateNetworkBody, Ipam, IpamConfig};
use crate::cmd::service::parse_duration;
use crate::parse;

use super::model::{
    ComposeFile, Dependency, Deploy, FileRef, FileRefLong, Healthcheck, KeyValues, Network, Port,
    Rest, Scalar, ScalarList, Service, VolumeMount, VolumeMountLong,
};

/// The label every object this project creates carries, and the only thing
/// `satl compose down` will act on.
pub const PROJECT_LABEL: &str = "com.docker.compose.project";
/// The compose service a SatL service came from.
pub const SERVICE_LABEL: &str = "com.docker.compose.service";
/// The compose key a network came from (docker labels the key, not the name).
pub const NETWORK_LABEL: &str = "com.docker.compose.network";

/// Which of the two worlds a file is being planned for.
///
/// Docker has two: `docker compose` runs containers on one host, `docker stack
/// deploy` runs services on a swarm. SatL has both, and the difference is
/// *scope*, not execution model -- every container is a Task of a Service in
/// either one (invariant 2). What moves is where the tasks land, how a port is
/// published, what a name looks like, and which half of the Compose Spec the
/// file may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// `satl compose`: every task on the node the CLI is talking to, pinned
    /// with a `node.id==` constraint. The client's filesystem is that node's
    /// filesystem (the CLI speaks `unix://` only), so a relative bind means
    /// what the file says it means (api-compat 169).
    Local {
        /// What the receiving daemon reported as its own node
        /// (`GET /info`, `Swarm.NodeID`).
        node_id: String,
    },
    /// `satl stack`: placed across the cluster by the scheduler, on an overlay,
    /// published through the ingress mesh.
    Cluster,
}

impl Scope {
    /// Whether this is the node-local world.
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local { .. })
    }

    /// The separator between the project and the key in an object's name.
    ///
    /// Docker's own split, and the reason it is a split: compose v2 names
    /// *containers* `<project>-<service>`, docker stack names *services*
    /// `<project>_<service>` (`Namespace.Scope` in docker/cli).
    fn separator(self: &Scope) -> char {
        match self {
            Self::Local { .. } => '-',
            Self::Cluster => '_',
        }
    }
}

/// What the caller must supply besides the file's text.
pub struct Context<'a> {
    /// Which world this file is planned for: `satl compose` is node-local,
    /// `satl stack` spans the cluster.
    pub scope: Scope,
    /// Path of the compose file, for error messages.
    pub path: &'a Path,
    /// Directory `env_file` paths are resolved against.
    pub project_dir: &'a Path,
    /// The project name, already resolved and normalized.
    pub project: &'a str,
    /// `satl`'s own environment, for `environment: [KEY]` and `KEY:` with no
    /// value — docker's "inherit" spelling.
    pub env: &'a dyn Fn(&str) -> Option<String>,
    /// Reads an `env_file`. Injected so the parser stays pure in tests.
    pub read: &'a dyn Fn(&Path) -> anyhow::Result<String>,
}

impl Context<'_> {
    /// The name an object created for compose key `key` carries.
    ///
    /// One place, because the separator is scope-dependent and a name that
    /// disagreed with the label would leave `down` unable to find its own work.
    fn name(&self, key: &str) -> String {
        format!("{}{}{key}", self.project, self.scope.separator())
    }
}

/// Everything `satl compose up` would create, in the order it creates it.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// Project name.
    pub project: String,
    /// Networks, created before the services that attach to them.
    pub networks: Vec<PlannedNetwork>,
    /// Named volumes the file declares; nothing is created for them (a volume
    /// is a node-local dataset the agent makes on first use).
    pub volumes: Vec<PlannedVolume>,
    /// One service per compose service, in name order.
    pub services: Vec<PlannedService>,
    /// Things honoured only in part, said out loud.
    pub warnings: Vec<String>,
}

/// One network of the plan.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedNetwork {
    /// Key in the compose file.
    pub key: String,
    /// Name of the network object.
    pub name: String,
    /// Declared `external: true`: use it, never create or remove it.
    pub external: bool,
    /// The create body, absent for an external network.
    pub body: Option<CreateNetworkBody>,
}

/// One named volume of the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedVolume {
    /// Key in the compose file.
    pub key: String,
    /// Name of the volume on each node.
    pub name: String,
    /// Declared `external: true`.
    pub external: bool,
}

/// One image `satl compose build` (or `up --build`) produces before deploying.
///
/// Node-local only. The image lands in *this* node's store and nowhere else,
/// which is exactly right here — the task that uses it is pinned to this node
/// (api-compat 169) and the agent resolves a locally present image before
/// considering a pull — and exactly wrong for a stack, where any node might be
/// asked to run it (api-compat 144, 181).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedBuild {
    /// Compose service key, for messages and for `--build <service>`.
    pub key: String,
    /// Directory the build reads, absolute, resolved against the project.
    pub context: PathBuf,
    /// The `Satlfile` to read, absolute.
    pub file: PathBuf,
    /// The reference the built image is registered under, which is also what
    /// the service spec's `image:` says.
    pub tag: String,
}

/// One service of the plan.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedService {
    /// The image to build before deploying this service, if it declares one.
    pub build: Option<PlannedBuild>,
    /// Key in the compose file (the DNS name inside the stack).
    pub key: String,
    /// Name of the service object: `<project>_<key>`.
    pub name: String,
    /// The spec `up` posts, with secret/config IDs still empty.
    pub spec: ServiceSpec,
}

impl Plan {
    /// The secret names the plan's specs refer to.
    pub fn secret_names(&self) -> BTreeSet<String> {
        self.services
            .iter()
            .flat_map(|service| &service.spec.task_template.container_spec.secrets)
            .map(|reference| reference.secret_name.clone())
            .collect()
    }

    /// The config names the plan's specs refer to.
    pub fn config_names(&self) -> BTreeSet<String> {
        self.services
            .iter()
            .flat_map(|service| &service.spec.task_template.container_spec.configs)
            .map(|reference| reference.config_name.clone())
            .collect()
    }

    /// Fill in the store IDs the daemon resolves references by (api-compat,
    /// "Secrets and configs": references are resolved by ID, and a name with no
    /// object behind it must fail before anything is created).
    pub fn resolve(
        &mut self,
        secret_ids: &BTreeMap<String, String>,
        config_ids: &BTreeMap<String, String>,
    ) {
        for service in &mut self.services {
            let container = &mut service.spec.task_template.container_spec;
            for reference in &mut container.secrets {
                if let Some(id) = secret_ids.get(&reference.secret_name) {
                    reference.secret_id.clone_from(id);
                }
            }
            for reference in &mut container.configs {
                if let Some(id) = config_ids.get(&reference.config_name) {
                    reference.config_id.clone_from(id);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Project name
// ---------------------------------------------------------------------------

/// Normalize a project name exactly as compose-go's `NormalizeProjectName`
/// does: lowercase, **delete** every character outside `[a-z0-9_-]`, then trim
/// leading `_`/`-`.
///
/// Deleting rather than replacing is the part worth pinning: a directory called
/// `my.app` is project `myapp`, not `my-app`, so `down` in that directory finds
/// what `up` created there.
pub fn normalize_project_name(value: &str) -> String {
    let kept: String = value
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_' || *c == '-')
        .collect();
    kept.trim_start_matches(['_', '-']).to_owned()
}

/// Validate a project name the operator named explicitly.
///
/// Compose defines validity as idempotence under normalization and refuses
/// anything else with the message quoted here from `loader.InvalidProjectNameErr`.
pub fn validate_project_name(value: &str) -> anyhow::Result<()> {
    if value.is_empty() || normalize_project_name(value) != value {
        anyhow::bail!(
            "invalid project name {value:?}: must consist only of lowercase alphanumeric \
             characters, hyphens, and underscores as well as start with a letter or number"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Keys of a service SatL refuses, each with the reason it cannot honour it.
///
/// A key absent from this table is still refused — [`refuse_rest`] falls back to
/// naming the supported keys — but these are the ones whose reason an operator
/// needs, because they are the ones real compose files carry.
const SERVICE_REFUSALS: &[(&str, &str)] = &[
    (
        "privileged",
        "a task never runs privileged: securelevel and the devfs ruleset are the \
         jail's isolation and SatL will not weaken them (api-compat 4)",
    ),
    (
        "cap_add",
        "FreeBSD jails have no capability model, so a capability cannot be granted \
         (api-compat 4)",
    ),
    (
        "cap_drop",
        "FreeBSD jails have no capability model, so a capability cannot be dropped \
         (api-compat 4)",
    ),
    (
        "devices",
        "device passthrough is not implemented: a jail's /dev comes from SatL's own \
         devfs ruleset (api-compat 4)",
    ),
    (
        "device_cgroup_rules",
        "there are no cgroups on FreeBSD (docs/linuxulator.md)",
    ),
    (
        "cgroup",
        "there are no cgroups on FreeBSD (docs/linuxulator.md)",
    ),
    (
        "cgroup_parent",
        "there are no cgroups on FreeBSD (docs/linuxulator.md)",
    ),
    (
        "network_mode",
        "every task is attached to SatL networks; host, none and container network \
         modes do not exist (api-compat 68). Use `networks:`",
    ),
    (
        "profiles",
        "profiles are not implemented: every service in the file would be deployed, \
         which is not what a profile means",
    ),
    (
        "extends",
        "extends is not implemented: no file is merged into another. Write the keys out",
    ),
    (
        "container_name",
        "a container is a task of a service and its name is derived from the service \
         (api-compat 1)",
    ),
    ("scale", "use `deploy.replicas:`"),
    ("cpus", "use `deploy.resources.limits.cpus:`"),
    ("cpu_shares", "relative CPU shares have no rctl equivalent"),
    ("cpu_quota", "use `deploy.resources.limits.cpus:`"),
    ("cpuset", "CPU pinning is not implemented"),
    ("mem_limit", "use `deploy.resources.limits.memory:`"),
    (
        "mem_reservation",
        "use `deploy.resources.reservations.memory:`",
    ),
    (
        "memswap_limit",
        "there is no swap accounting in rctl for a jail",
    ),
    (
        "pids_limit",
        "a process cap has no rctl mapping yet (api-compat 50)",
    ),
    (
        "sysctls",
        "per-jail sysctls are not implemented (api-compat 4)",
    ),
    (
        "ulimits",
        "per-task ulimits are not implemented (api-compat 4)",
    ),
    (
        "init",
        "there is no init shim: the entrypoint is the jail's own process (api-compat 50)",
    ),
    (
        "pid",
        "a jail has no PID namespace to share (docs/linuxulator.md)",
    ),
    ("ipc", "SysV IPC sharing is not implemented (api-compat 4)"),
    ("uts", "a jail's hostname is its own; use `hostname:`"),
    (
        "userns_mode",
        "there is no user-namespace remapping (api-compat 4)",
    ),
    (
        "security_opt",
        "there is no seccomp, AppArmor or SELinux (api-compat 4)",
    ),
    (
        "shm_size",
        "the /dev/shm tmpfs size is not configurable yet (api-compat 4)",
    ),
    (
        "tmpfs",
        "a tmpfs mount is not exposed through compose; secrets already arrive on one \
         (invariant 7)",
    ),
    (
        "links",
        "container links do not exist (api-compat 11); use `networks:`",
    ),
    (
        "external_links",
        "container links do not exist (api-compat 11)",
    ),
    (
        "volumes_from",
        "there is no volume inheritance between containers",
    ),
    (
        "expose",
        "`expose:` has no effect anywhere (docker dropped it with the linking model): \
         publish the port with `ports:` or remove the key",
    ),
    (
        "dns",
        "a task's resolver is its node's DNS responder (api-compat 73)",
    ),
    (
        "dns_search",
        "a task's resolver is its node's DNS responder (api-compat 73)",
    ),
    (
        "extra_hosts",
        "extra /etc/hosts entries are not exposed through compose yet",
    ),
    (
        "logging",
        "the log driver is not configurable (api-compat 50)",
    ),
    (
        "platform",
        "the platform is chosen from the image's manifest (api-compat 9)",
    ),
    (
        "read_only",
        "a read-only root filesystem is not implemented",
    ),
    ("tty", "SatL never allocates a TTY (api-compat 23)"),
    (
        "stdin_open",
        "stdin is not attached to a task (api-compat 27)",
    ),
    (
        "stop_timeout",
        "use `stop_grace_period:`, which is what swarm carries",
    ),
    ("develop", "there is no file-watch/sync mode"),
    (
        "pull_policy",
        "an image is pulled when a node does not have it",
    ),
    ("runtime", "the runtime is always ocijail (invariant 6)"),
];

/// Keys of a compose file's top level SatL refuses.
const TOP_REFUSALS: &[(&str, &str)] = &[(
    "include",
    "include is not implemented: no file is merged into another. Write the keys out",
)];

/// The service keys `satl compose` does read, for the fallback message.
const SERVICE_KEYS: &str = "build, command, configs, depends_on, deploy, entrypoint, env_file, \
     environment, healthcheck, hostname, image, labels, networks, ports, restart, secrets, \
     stop_grace_period, stop_signal, user, volumes, working_dir";

/// The image a service's tasks run.
///
/// `image:` when it is given; otherwise the reference `build:` will register,
/// which is docker compose's rule too -- a service that builds its image does
/// not have to name it twice.
fn service_image(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    service: &Service,
    at: &str,
) -> anyhow::Result<String> {
    match (&service.image, &service.build) {
        (Some(image), _) => Ok(image.clone()),
        (None, Some(_)) => Ok(built_image_tag(ctx, service_ctx.key)),
        (None, None) => Err(refuse(
            ctx,
            at,
            if ctx.scope.is_local() {
                "no `image:` and no `build:`: a service needs one or the other -- an image \
                 this node can pull, or a Satlfile to build one from"
            } else {
                "no `image:` given: a stack's tasks are placed on any node, so every service \
                 names an image every node can pull. `satl compose` can build one from a \
                 Satlfile instead"
            },
        )),
    }
}

/// The reference a service's built image is registered under.
///
/// `<project>-<service>` with the scope's separator, so it matches everything
/// else the project names and cannot collide with another project's. No
/// registry prefix: the image never leaves this node, and prefixing it with one
/// would suggest it could be pulled from there.
fn built_image_tag(ctx: &Context<'_>, key: &str) -> String {
    format!("{}:latest", ctx.name(key))
}

/// The build a service declares, resolved against the project directory.
///
/// Refused outright under [`Scope::Cluster`]: `satl build` registers into the
/// image store of the node it runs on, and a stack's tasks are placed on any
/// node, so a stack that built its own images would deploy an image most of the
/// cluster cannot pull (api-compat 144). The node-local world is the one where
/// "built here" and "runs here" are the same node.
fn planned_build(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    service: &Service,
) -> anyhow::Result<Option<PlannedBuild>> {
    let Some(build) = &service.build else {
        return Ok(None);
    };
    let at = format!("services.{}.build", service_ctx.key);
    if !ctx.scope.is_local() {
        return Err(refuse(
            ctx,
            &at,
            "a stack's tasks are placed on any node, and a build registers the image in the \
             store of the node that ran it, so most of the cluster could not pull the result. \
             Build it once with `satl build -t <ref>`, `--push` it to a registry and name it \
             with `image:`; or run this file on one node with `satl compose up --build`",
        ));
    }
    let (context, file) = match build {
        super::model::Build::Short(context) => (context.clone(), None),
        super::model::Build::Long(long) => {
            refuse_rest(ctx, &at, &long.rest, BUILD_REFUSALS, "context, dockerfile")?;
            let context = long.context.clone().ok_or_else(|| {
                refuse(
                    ctx,
                    &at,
                    "no `context:`: the directory the build reads is required",
                )
            })?;
            (context, long.dockerfile.clone())
        }
    };
    let context = local_bind_source(ctx, &at, &context)?;
    let file = match file {
        Some(name) if name.starts_with('/') => name,
        Some(name) => format!("{context}/{name}"),
        None => format!("{context}/Satlfile"),
    };
    Ok(Some(PlannedBuild {
        key: service_ctx.key.to_owned(),
        context: PathBuf::from(context),
        file: PathBuf::from(file),
        tag: service
            .image
            .clone()
            .unwrap_or_else(|| built_image_tag(ctx, service_ctx.key)),
    }))
}

/// Keys of a service's `build:` mapping SatL refuses, each with its reason.
///
/// SatL's builder reads a `Satlfile`, not a Dockerfile (`docs/image-sources.md`),
/// and the difference is not cosmetic: there is no `ARG`, and a multi-stage
/// build always packs its *last* stage. So the compose keys that describe those
/// two features cannot be half-honoured, and are named rather than dropped.
const BUILD_REFUSALS: &[(&str, &str)] = &[
    (
        "args",
        "a Satlfile has no `ARG`: build arguments are not substituted anywhere, so a value \
         here would be silently ignored. Bake the value into the Satlfile, or generate it",
    ),
    (
        "target",
        "a Satlfile may hold several stages but always packs the last one, so a stage cannot \
         be selected. Split the file, or make the wanted stage the last",
    ),
    (
        "cache_from",
        "the build cache is local and content-addressed (`--cache-dir`), not pulled from a \
         registry",
    ),
    (
        "ssh",
        "there are no build secrets or ssh forwarding in a Satlfile build",
    ),
    (
        "secrets",
        "there are no build secrets in a Satlfile build; a runtime secret is the service's \
         `secrets:` key",
    ),
    (
        "platform",
        "a Satlfile build produces an image for the node it runs on (api-compat 144)",
    ),
    (
        "network",
        "a build step's network is the host's; there is no build-time network mode",
    ),
    (
        "tags",
        "the image is tagged from `image:`, or `<project>-<service>` when that is absent; one \
         tag, so that what `up` deploys is what was just built",
    ),
];

/// An error naming the file, the place in it, and why.
fn refuse(ctx: &Context<'_>, at: &str, reason: &str) -> anyhow::Error {
    anyhow::anyhow!("{}: {at}: {reason}", ctx.path.display())
}

/// Refuse every key of a `rest` catch-all, `x-` extensions excepted.
///
/// The Compose Spec reserves `x-` prefixed keys for extensions, and anchors are
/// usually parked in one (`x-common: &common`), so ignoring those is the spec's
/// own rule rather than a silent drop. Everything else is refused with its
/// reason from `table`, or with the list of keys that *are* read.
fn refuse_rest(
    ctx: &Context<'_>,
    at: &str,
    rest: &Rest,
    table: &[(&str, &str)],
    supported: &str,
) -> anyhow::Result<()> {
    for key in rest.keys() {
        if key.starts_with("x-") {
            continue;
        }
        let reason = table
            .iter()
            .find_map(|(name, reason)| (name == key).then_some((*reason).to_owned()))
            .unwrap_or_else(|| {
                format!("not supported by satl compose; supported keys are {supported}")
            });
        return Err(refuse(ctx, &format!("{at}.{key}"), &reason));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Read a compose file's text into the model, or say where it is wrong.
///
/// Two YAML behaviours here are deliberate and pinned by tests: `strict_booleans`
/// keeps the Norway problem out of a compose file (`restart: no` is the string
/// `no`, not `false`), and the crate's own duplicate-key error is left to fire —
/// two `web:` entries under `services:` must not silently collapse into the
/// second one.
pub fn parse(text: &str, path: &Path) -> anyhow::Result<ComposeFile> {
    let text = unescape_dollars(text, path)?;
    let options = serde_saphyr::options! { strict_booleans: true };
    serde_saphyr::from_str_with_options::<ComposeFile>(&text, options).map_err(|err| {
        // The crate renders a rustc-style snippet but names the input
        // `<input>`; the operator needs their own path in it.
        let mut err = err;
        if let serde_saphyr::Error::WithSnippet { regions, .. } = &mut err {
            for region in &mut *regions {
                region.source_name = path.display().to_string();
            }
        }
        anyhow::anyhow!("{err}")
    })
}

/// Refuse compose's variable interpolation, and apply its escape.
///
/// `satl compose` does not interpolate: it has no `.env` loading, no
/// `${VAR:-default}` grammar and no `--env-file` for the file itself. Passing
/// `image: nginx:${TAG}` through *literally* would deploy a service asking for
/// the tag `${TAG}`, so the sigil is refused where it appears. `$$` is compose's
/// escape for a literal `$` and is applied here, in one text-level pass, so that
/// a command written for compose (`sh -c 'echo $$HOME'`) means the same thing
/// here as it does there.
fn unescape_dollars(text: &str, path: &Path) -> anyhow::Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.char_indices().peekable();
    let mut line = 1_usize;
    let mut column = 1_usize;
    while let Some((_, ch)) = chars.next() {
        if ch == '\n' {
            line += 1;
            column = 1;
            out.push(ch);
            continue;
        }
        column += 1;
        if ch != '$' {
            out.push(ch);
            continue;
        }
        match chars.peek().map(|(_, next)| *next) {
            Some('$') => {
                chars.next();
                column += 1;
                out.push('$');
            }
            Some(next) if next == '{' || next.is_ascii_alphabetic() || next == '_' => {
                anyhow::bail!(
                    "{}: line {line} column {}: variable interpolation is not implemented: \
                     substitute the value before deploying, or write `$$` for a literal dollar",
                    path.display(),
                    column - 1
                );
            }
            _ => out.push(ch),
        }
    }
    Ok(out)
}

/// The whole pipeline: text in, plan out.
pub fn build(text: &str, ctx: &Context<'_>) -> anyhow::Result<Plan> {
    let file = parse(text, ctx.path)?;
    plan(&file, ctx)
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/// Turn a parsed file into the objects `up` would create.
pub fn plan(file: &ComposeFile, ctx: &Context<'_>) -> anyhow::Result<Plan> {
    let mut warnings = Vec::new();
    if file.version.is_some() {
        warnings.push(
            "the `version:` top-level key is obsolete and is ignored, as it is by docker \
             compose itself"
                .to_owned(),
        );
    }
    refuse_rest(
        ctx,
        "",
        &file.rest,
        TOP_REFUSALS,
        "name, services, networks, volumes, secrets, configs",
    )?;
    if file.services.is_empty() {
        anyhow::bail!("{}: services: no service declared", ctx.path.display());
    }

    // Which networks are actually used decides which are created: an unused
    // declaration is not an object, and a service naming no network joins
    // `default`, exactly as docker compose and docker stack deploy do.
    let mut used: BTreeSet<String> = BTreeSet::new();
    for (key, service) in &file.services {
        let attachments = service
            .networks
            .as_ref()
            .map(super::model::Attachments::entries)
            .unwrap_or_default();
        if attachments.is_empty() {
            used.insert("default".to_owned());
            continue;
        }
        for (network, _) in attachments {
            if !file.networks.contains_key(&network) {
                anyhow::bail!(
                    "{}: services.{key}.networks: undefined network {network:?}: declare it \
                     under the top-level `networks:` key, or mark it `external: true`",
                    ctx.path.display()
                );
            }
            used.insert(network);
        }
    }

    let mut networks = Vec::new();
    for key in &used {
        let declared = file.networks.get(key).and_then(Option::as_ref);
        networks.push(planned_network(ctx, key, declared, &mut warnings)?);
    }
    for key in file.networks.keys() {
        if !used.contains(key) {
            warnings.push(format!(
                "network {key:?} is declared but no service attaches to it: nothing is created \
                 for it"
            ));
        }
    }
    let network_names: BTreeMap<String, String> = networks
        .iter()
        .map(|network| (network.key.clone(), network.name.clone()))
        .collect();

    let mut volumes = Vec::new();
    for (key, declared) in &file.volumes {
        volumes.push(planned_volume(ctx, key, declared.as_ref())?);
    }
    let volume_names: BTreeMap<String, String> = volumes
        .iter()
        .map(|volume| (volume.key.clone(), volume.name.clone()))
        .collect();

    let secrets = dependency_names(ctx, &file.secrets, "secrets")?;
    let configs = dependency_names(ctx, &file.configs, "configs")?;

    let mut services = Vec::new();
    for (key, service) in &file.services {
        let context = ServiceContext {
            key,
            networks: &network_names,
            volumes: &volume_names,
            secrets: &secrets,
            configs: &configs,
            declared_services: &file.services.keys().cloned().collect(),
        };
        let spec = service_spec(ctx, &context, service, &mut warnings)?;
        services.push(PlannedService {
            build: planned_build(ctx, &context, service)?,
            key: key.clone(),
            name: ctx.name(key),
            spec,
        });
    }

    Ok(Plan {
        project: ctx.project.to_owned(),
        networks,
        volumes,
        services,
        warnings,
    })
}

/// Keys of a `networks:` entry SatL refuses.
const NETWORK_REFUSALS: &[(&str, &str)] = &[
    (
        "attachable",
        "every container is a task of a service, so there is nothing to attach by hand \
         (api-compat 63)",
    ),
    (
        "internal",
        "every SatL network has egress through the node's pf NAT anchor (api-compat 63)",
    ),
    (
        "enable_ipv6",
        "v1's IPAM and data plane are IPv4-only (api-compat 63)",
    ),
    (
        "driver_opts",
        "encrypted is the only driver option SatL reads, and compose has no spelling for it \
         yet: create the network with satl network create --opt encrypted and reference it as \
         external (api-compat 63)",
    ),
];

/// Keys of a `volumes:` entry SatL refuses.
const VOLUME_REFUSALS: &[(&str, &str)] = &[(
    "driver_opts",
    "a volume is a ZFS dataset with no tunables of its own (api-compat 39)",
)];

/// Keys of a top-level `secrets:`/`configs:` entry SatL refuses.
const DEPENDENCY_REFUSALS: &[(&str, &str)] = &[
    (
        "environment",
        "a payload from the environment is not accepted: it would put the value in \
         `satl`'s own process environment on the way in",
    ),
    (
        "template_driver",
        "there is no template engine, so `{{ }}` placeholders would arrive unexpanded \
         (api-compat 103)",
    ),
    (
        "driver",
        "secret drivers are not supported (api-compat 103)",
    ),
];

/// One network of the plan, with its create body.
fn planned_network(
    ctx: &Context<'_>,
    key: &str,
    declared: Option<&Network>,
    warnings: &mut Vec<String>,
) -> anyhow::Result<PlannedNetwork> {
    let at = format!("networks.{key}");
    let Some(declared) = declared else {
        // An implicit or empty declaration: the project's own network, on
        // whichever driver its world uses.
        return Ok(PlannedNetwork {
            key: key.to_owned(),
            name: ctx.name(key),
            external: false,
            body: Some(CreateNetworkBody {
                name: ctx.name(key),
                driver: default_network_driver(ctx).to_owned(),
                ipam: None,
                options: BTreeMap::new(),
                labels: network_labels(ctx, key),
            }),
        });
    };
    refuse_rest(
        ctx,
        &at,
        &declared.rest,
        NETWORK_REFUSALS,
        "driver, name, external, labels, ipam",
    )?;

    let external = declared
        .external
        .as_ref()
        .is_some_and(super::model::External::is_external);
    let name = match (&declared.name, external_name(declared.external.as_ref())) {
        (Some(name), _) => name.clone(),
        (None, Some(name)) => name,
        // An external network keeps its own name, as compose-go's
        // `setNameFromKey` does; a created one is namespaced.
        (None, None) if external => key.to_owned(),
        (None, None) => ctx.name(key),
    };
    if external {
        if declared.driver.is_some() || declared.ipam.is_some() {
            return Err(refuse(
                ctx,
                &at,
                "an external network is used as it is: `driver:` and `ipam:` would be ignored",
            ));
        }
        return Ok(PlannedNetwork {
            key: key.to_owned(),
            name,
            external: true,
            body: None,
        });
    }

    let default_driver = default_network_driver(ctx);
    let driver = declared
        .driver
        .clone()
        .unwrap_or_else(|| default_driver.to_owned());
    if driver != default_driver {
        return Err(refuse(
            ctx,
            &format!("{at}.driver"),
            &driver_refusal(ctx, &driver),
        ));
    }

    let mut labels = BTreeMap::new();
    if let Some(declared_labels) = &declared.labels {
        for (key, value) in key_values(ctx, &at, declared_labels)? {
            labels.insert(key, value);
        }
    }
    let ipam = network_ipam(ctx, &at, declared, warnings)?;

    Ok(PlannedNetwork {
        key: key.to_owned(),
        name: name.clone(),
        external: false,
        body: Some(CreateNetworkBody {
            name,
            driver,
            ipam,
            options: BTreeMap::new(),
            labels: {
                let mut all = network_labels(ctx, key);
                all.extend(labels);
                all
            },
        }),
    })
}

/// The labels a created network carries: the project's, plus the compose key
/// (docker labels the key, not the derived name, so `down` can map back).
fn network_labels(ctx: &Context<'_>, key: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (PROJECT_LABEL.to_owned(), ctx.project.to_owned()),
        (NETWORK_LABEL.to_owned(), key.to_owned()),
    ])
}

/// The name inside a legacy `external: { name: … }`.
fn external_name(external: Option<&super::model::External>) -> Option<String> {
    match external {
        Some(super::model::External::Named(rest)) => rest
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        _ => None,
    }
}

/// One declared named volume. Nothing is created: a volume is a node-local
/// dataset the agent makes on first use, on whichever node the task lands.
fn planned_volume(
    ctx: &Context<'_>,
    key: &str,
    declared: Option<&super::model::Volume>,
) -> anyhow::Result<PlannedVolume> {
    let at = format!("volumes.{key}");
    let Some(declared) = declared else {
        return Ok(PlannedVolume {
            key: key.to_owned(),
            name: ctx.name(key),
            external: false,
        });
    };
    refuse_rest(
        ctx,
        &at,
        &declared.rest,
        VOLUME_REFUSALS,
        "driver, name, external, labels",
    )?;
    if let Some(driver) = &declared.driver
        && driver != "local"
    {
        return Err(refuse(
            ctx,
            &format!("{at}.driver"),
            "only the `local` driver exists: a volume is a ZFS dataset on the node that runs \
             the task (api-compat 20)",
        ));
    }
    let external = declared
        .external
        .as_ref()
        .is_some_and(super::model::External::is_external);
    let name = match (&declared.name, external_name(declared.external.as_ref())) {
        (Some(name), _) => name.clone(),
        (None, Some(name)) => name,
        (None, None) if external => key.to_owned(),
        (None, None) => ctx.name(key),
    };
    Ok(PlannedVolume {
        key: key.to_owned(),
        name,
        external,
    })
}

/// Map each declared secret/config key to the name of the stored object.
///
/// Only `external: true` (optionally with a `name:`) is accepted. A `file:`
/// declaration is refused rather than uploaded: a secret is immutable
/// (api-compat 97), so a second `up` after editing the file would silently keep
/// the old payload, and a `down` would then have to decide whether to delete
/// cluster secret material it did not know it owned.
fn dependency_names(
    ctx: &Context<'_>,
    declared: &BTreeMap<String, Option<Dependency>>,
    kind: &str,
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut names = BTreeMap::new();
    for (key, entry) in declared {
        let at = format!("{kind}.{key}");
        let Some(entry) = entry else {
            return Err(refuse(
                ctx,
                &at,
                &format!(
                    "an empty declaration says nothing: mark it `external: true` if the \
                     {} already exists in the cluster",
                    singular(kind)
                ),
            ));
        };
        refuse_rest(ctx, &at, &entry.rest, DEPENDENCY_REFUSALS, "external, name")?;
        if let Some(file) = &entry.file {
            return Err(refuse(
                ctx,
                &format!("{at}.file"),
                &format!(
                    "satl compose never creates a {kind_singular} from a file: a {kind_singular} \
                     is immutable, so a later `up` could not update it and a `down` must not \
                     delete it. Create it once with `satl {kind_singular} create {key} {file}` \
                     and mark it `external: true` here",
                    kind_singular = singular(kind)
                ),
            ));
        }
        if entry.environment.is_some() {
            // Covered by DEPENDENCY_REFUSALS, but the model names the field.
            return Err(refuse(
                ctx,
                &format!("{at}.environment"),
                "a payload from the environment is not accepted",
            ));
        }
        let external = entry
            .external
            .as_ref()
            .is_some_and(super::model::External::is_external);
        if !external {
            return Err(refuse(
                ctx,
                &at,
                &format!(
                    "only `external: true` is supported: satl compose refers to a \
                     {} that already exists in the cluster store",
                    singular(kind)
                ),
            ));
        }
        let name = entry
            .name
            .clone()
            .or_else(|| external_name(entry.external.as_ref()))
            .unwrap_or_else(|| key.clone());
        names.insert(key.clone(), name);
    }
    Ok(names)
}

/// `secrets` -> `secret`, `configs` -> `config`.
fn singular(kind: &str) -> &str {
    kind.strip_suffix('s').unwrap_or(kind)
}

// ---------------------------------------------------------------------------
// One service
// ---------------------------------------------------------------------------

/// What the surrounding file tells one service.
struct ServiceContext<'a> {
    /// The compose key of the service being planned.
    key: &'a str,
    /// Compose network key -> network object name.
    networks: &'a BTreeMap<String, String>,
    /// Compose volume key -> volume name on the node.
    volumes: &'a BTreeMap<String, String>,
    /// Compose secret key -> name in the cluster store.
    secrets: &'a BTreeMap<String, String>,
    /// Compose config key -> name in the cluster store.
    configs: &'a BTreeMap<String, String>,
    /// Every service the file declares, for `depends_on` validation.
    declared_services: &'a BTreeSet<String>,
}

/// Build the `ServiceSpec` one compose service becomes.
fn service_spec(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    service: &Service,
    warnings: &mut Vec<String>,
) -> anyhow::Result<ServiceSpec> {
    let key = service_ctx.key;
    let at = format!("services.{key}");
    refuse_rest(ctx, &at, &service.rest, SERVICE_REFUSALS, SERVICE_KEYS)?;
    let container = container_spec(ctx, service_ctx, service, warnings)?;
    if let Some(depends_on) = &service.depends_on {
        check_depends_on(ctx, service_ctx, depends_on, warnings)?;
    }
    service_rest(ctx, service_ctx, service, container, warnings)
}
/// The `ContainerSpec` of one compose service.
fn container_spec(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    service: &Service,
    warnings: &mut Vec<String>,
) -> anyhow::Result<ContainerSpec> {
    let at = format!("services.{}", service_ctx.key);
    let image = service_image(ctx, service_ctx, service, &at)?;

    // Env files first, then `environment:` on top — docker's precedence. A name
    // set twice keeps its place and takes the later value, because compose
    // merges into a map and a duplicate on the wire would leave the winner up
    // to whoever reads the list.
    let mut env: Vec<(String, String)> = Vec::new();
    let mut set =
        |name: &str, value: &str| match env.iter_mut().find(|(existing, _)| existing == name) {
            Some((_, existing)) => value.clone_into(existing),
            None => env.push((name.to_owned(), value.to_owned())),
        };
    if let Some(files) = &service.env_file {
        for file in &files.0 {
            let path = ctx.project_dir.join(file.as_str());
            let contents = (ctx.read)(&path).map_err(|err| {
                refuse(
                    ctx,
                    &format!("{at}.env_file"),
                    &format!("cannot read {}: {err}", path.display()),
                )
            })?;
            let entries = parse::parse_env_file(&contents, &ctx.env)
                .map_err(|err| refuse(ctx, &format!("{at}.env_file"), &format!("{err}")))?;
            for entry in entries {
                let (name, value) = entry.split_once('=').unwrap_or((entry.as_str(), ""));
                set(name, value);
            }
        }
    }
    if let Some(environment) = &service.environment {
        for (name, value) in &environment.0 {
            match value {
                Some(value) => set(name, value),
                // Docker's "inherit": a name with no value takes it from the
                // client's own environment, and is dropped when unset.
                None => {
                    if let Some(resolved) = (ctx.env)(name) {
                        set(name, &resolved);
                    }
                }
            }
        }
    }
    let env: Vec<String> = env
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();

    let mut container_labels = BTreeMap::new();
    if let Some(labels) = &service.labels {
        for (name, value) in key_values(ctx, &format!("{at}.labels"), labels)? {
            container_labels.insert(name, value);
        }
    }

    let mut container = ContainerSpec {
        image,
        labels: container_labels,
        command: service
            .entrypoint
            .as_ref()
            .map(|entrypoint| words(ctx, &format!("{at}.entrypoint"), entrypoint))
            .transpose()?
            .unwrap_or_default(),
        args: service
            .command
            .as_ref()
            .map(|command| words(ctx, &format!("{at}.command"), command))
            .transpose()?
            .unwrap_or_default(),
        env,
        dir: service.working_dir.clone().unwrap_or_default(),
        user: service.user.as_ref().map_or("", Scalar::as_str).to_owned(),
        hostname: service.hostname.clone().unwrap_or_default(),
        mounts: mounts(ctx, service_ctx, service, warnings)?,
        secrets: secret_refs(ctx, service_ctx, service)?,
        configs: config_refs(ctx, service_ctx, service)?,
        rest: serde_json::Map::new(),
    };

    // Healthcheck, StopSignal and StopGracePeriod have no named field on the
    // CLI's copy of the container spec: it carries every other key the daemon
    // accepts in one catch-all, which is what keeps `service update` from
    // deleting them (see `ContainerSpec::rest`). Inserted in key order, because
    // that is the order they go out in.
    if let Some(healthcheck) = &service.healthcheck
        && let Some(value) = healthcheck_json(ctx, &at, healthcheck)?
    {
        container.rest.insert("Healthcheck".to_owned(), value);
    }
    if let Some(grace) = &service.stop_grace_period {
        let nanos = duration(ctx, &format!("{at}.stop_grace_period"), grace)?;
        container
            .rest
            .insert("StopGracePeriod".to_owned(), serde_json::json!(nanos));
    }
    if let Some(signal) = &service.stop_signal {
        container
            .rest
            .insert("StopSignal".to_owned(), serde_json::json!(signal));
    }
    Ok(container)
}

/// The rest of the spec: mode, policies, placement, attachments, ports.
fn service_rest(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    service: &Service,
    container: ContainerSpec,
    warnings: &mut Vec<String>,
) -> anyhow::Result<ServiceSpec> {
    let key = service_ctx.key;
    let at = format!("services.{key}");
    let deploy = service.deploy.clone().unwrap_or_default();
    let deploy_at = format!("{at}.deploy");
    refuse_rest(
        ctx,
        &deploy_at,
        &deploy.rest,
        DEPLOY_REFUSALS,
        "mode, replicas, labels, resources, placement, restart_policy, endpoint_mode, \
         update_config, rollback_config",
    )?;

    let mode = match deploy.mode.as_deref() {
        None | Some("replicated") => ServiceMode::replicated(deploy.replicas.unwrap_or(1)),
        Some("global") => {
            if deploy.replicas.is_some() {
                return Err(refuse(
                    ctx,
                    &format!("{deploy_at}.replicas"),
                    "a global service runs one task per eligible node and has no replica count",
                ));
            }
            ServiceMode::global()
        }
        Some(other) => {
            return Err(refuse(
                ctx,
                &format!("{deploy_at}.mode"),
                &format!(
                    "{other:?} is not a service mode here: `replicated` and `global` are the \
                     two compose supports (Docker compose has no jobs; use satl service create \
                     --mode replicated-job)"
                ),
            ));
        }
    };
    if let Some(endpoint_mode) = &deploy.endpoint_mode
        && endpoint_mode != "dnsrr"
    {
        return Err(refuse(
            ctx,
            &format!("{deploy_at}.endpoint_mode"),
            &format!(
                "{endpoint_mode:?} is not supported: a service name resolves to its running \
                 tasks and there is no virtual IP (api-compat 50, 52)"
            ),
        ));
    }

    let mut labels = BTreeMap::from([
        (PROJECT_LABEL.to_owned(), ctx.project.to_owned()),
        (SERVICE_LABEL.to_owned(), key.to_owned()),
    ]);
    if let Some(deploy_labels) = &deploy.labels {
        for (name, value) in key_values(ctx, &format!("{deploy_at}.labels"), deploy_labels)? {
            labels.insert(name, value);
        }
    }

    let ports = ports(ctx, &at, service, warnings)?;
    refuse_host_port_conflict(ctx, &at, &deploy, &ports)?;
    Ok(ServiceSpec {
        name: ctx.name(key),
        labels,
        task_template: TaskTemplate {
            container_spec: container,
            resources: resources(ctx, &deploy_at, &deploy)?,
            restart_policy: restart_policy(ctx, &at, service, &deploy, warnings)?,
            placement: placement(ctx, &deploy_at, &deploy)?,
            networks: attachments(ctx, service_ctx, service)?,
            rest: serde_json::Map::new(),
        },
        mode,
        update_config: update_policy(
            ctx,
            &deploy_at,
            "update_config",
            deploy.update_config.as_ref(),
        )?,
        rollback_config: update_policy(
            ctx,
            &deploy_at,
            "rollback_config",
            deploy.rollback_config.as_ref(),
        )?,
        endpoint_spec: (!ports.is_empty()).then_some(EndpointSpec {
            ports,
            rest: serde_json::Map::new(),
        }),
    })
}

/// Refuse replicas that would fight over one host port.
///
/// Host-mode publishing takes a host port exactly once on a node, and the
/// node-local world has exactly one node: two replicas asking for the same
/// fixed port would sit in `PENDING` for ever. This turns that into a sentence
/// before anything is created (api-compat 174). An ephemeral published port
/// (`0`, or a short `"80"`) has nothing to collide over, and `mode: global` is
/// one task here because the pin leaves one eligible node.
fn refuse_host_port_conflict(
    ctx: &Context<'_>,
    at: &str,
    deploy: &Deploy,
    ports: &[PortConfig],
) -> anyhow::Result<()> {
    let replicas = deploy.replicas.unwrap_or(1);
    let Some(taken) = contended_host_port(&ctx.scope, replicas, ports) else {
        return Ok(());
    };
    Err(refuse(ctx, at, &host_port_conflict(replicas, taken)))
}

/// The port two replicas would fight over, if there is one.
///
/// Only under [`Scope::Local`]: a host-mode port in the cluster world is taken
/// once *per node*, and the scheduler spreads the replicas over nodes. Only a
/// *fixed* published port conflicts -- an omitted or `0` one is ephemeral --
/// and only a replicated service has a count to raise at all.
fn contended_host_port<'a>(
    scope: &Scope,
    replicas: u64,
    ports: &'a [PortConfig],
) -> Option<&'a PortConfig> {
    if !scope.is_local() || replicas < 2 {
        return None;
    }
    ports.iter().find(|port| port.published_port != 0)
}

/// The sentence both the file-time and the `--scale` refusals print.
fn host_port_conflict(replicas: u64, taken: &PortConfig) -> String {
    format!(
        "{replicas} replicas with host port {} published: a host port can only be taken once \
         on a node, and `satl compose` runs every task on this one. Drop the fixed host port \
         (`\"{}\"` alone publishes on an ephemeral one), ask for one replica, or spread the \
         service over the cluster with `satl stack deploy`",
        taken.published_port, taken.target_port
    )
}

/// The same check, re-run after `--scale` overrode a service's replica count.
///
/// `up --scale web=3` must not get past what the planner would have refused had
/// the file said `deploy.replicas: 3` (api-compat 174). The plan is already
/// built here, so the message names the flag rather than a line in the file.
///
/// # Errors
///
/// When `replicas` above one would contend for a fixed host port.
pub fn refuse_scaled_host_port(
    scope: &Scope,
    service: &PlannedService,
    replicas: u64,
) -> anyhow::Result<()> {
    let ports = service
        .spec
        .endpoint_spec
        .as_ref()
        .map_or(&[][..], |endpoint| endpoint.ports.as_slice());
    let Some(taken) = contended_host_port(scope, replicas, ports) else {
        return Ok(());
    };
    anyhow::bail!(
        "--scale {}={replicas}: {}",
        service.key,
        host_port_conflict(replicas, taken)
    )
}

/// Keys of `deploy:` SatL refuses.
const DEPLOY_REFUSALS: &[(&str, &str)] = &[
    (
        "preferences",
        "placement preferences are deferred (SWK 8.5, api-compat 50); use \
         `placement.constraints:`",
    ),
    (
        "resources.reservations.generic_resources",
        "generic resources are not modelled (api-compat 53)",
    ),
];

// ---------------------------------------------------------------------------
// Service members
// ---------------------------------------------------------------------------

/// `labels:`-shaped pairs, with a value-less key meaning an empty value (the
/// rule `--label key` follows).
fn key_values(
    ctx: &Context<'_>,
    at: &str,
    values: &KeyValues,
) -> anyhow::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (key, value) in &values.0 {
        if key.is_empty() {
            return Err(refuse(ctx, at, "empty key"));
        }
        out.push((key.clone(), value.clone().unwrap_or_default()));
    }
    Ok(out)
}

/// `command:`/`entrypoint:` as an argv.
///
/// A list is the argv. A single string is split the way a shell would, because
/// that is what compose does with it — and an unterminated quote is an error
/// rather than one long argument.
fn words(ctx: &Context<'_>, at: &str, value: &ScalarList) -> anyhow::Result<Vec<String>> {
    if value.0.len() == 1 && value.0[0].as_str().contains(char::is_whitespace) {
        return shell_words(value.0[0].as_str()).map_err(|reason| refuse(ctx, at, &reason));
    }
    Ok(value.0.iter().map(|word| word.0.clone()).collect())
}

/// Split a command string into words, honouring single and double quotes and
/// backslash escapes — the subset of shell quoting compose files use.
fn shell_words(value: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        match ch {
            ' ' | '\t' | '\n' => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            '\'' => {
                started = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(inner) => word.push(inner),
                        None => return Err("unterminated single quote".to_owned()),
                    }
                }
            }
            '"' => {
                started = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(escaped) => word.push(escaped),
                            None => return Err("unterminated double quote".to_owned()),
                        },
                        Some(inner) => word.push(inner),
                        None => return Err("unterminated double quote".to_owned()),
                    }
                }
            }
            '\\' => {
                started = true;
                match chars.next() {
                    Some(escaped) => word.push(escaped),
                    None => return Err("trailing backslash".to_owned()),
                }
            }
            other => {
                started = true;
                word.push(other);
            }
        }
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

/// A Go duration string in nanoseconds, with the file and key on the error.
fn duration(ctx: &Context<'_>, at: &str, value: &Scalar) -> anyhow::Result<i64> {
    parse_duration(value.as_str()).map_err(|err| refuse(ctx, at, &format!("{err}")))
}

/// `ports:` as the endpoint spec's port list.
fn ports(
    ctx: &Context<'_>,
    at: &str,
    service: &Service,
    warnings: &mut Vec<String>,
) -> anyhow::Result<Vec<PortConfig>> {
    let mut out = Vec::new();
    for (index, port) in service.ports.iter().flatten().enumerate() {
        let at = format!("{at}.ports[{index}]");
        let config = match port {
            Port::Short(value) => {
                let spec = parse::parse_publish(value.as_str())
                    .map_err(|err| refuse(ctx, &at, &format!("{err}")))?;
                if spec.ignored_ip.is_some() {
                    warnings.push(format!(
                        "{at}: the host address is ignored and the port is published on every \
                         address (api-compat 25)"
                    ));
                }
                PortConfig {
                    protocol: spec.protocol,
                    target_port: u32::from(spec.container_port),
                    published_port: u32::from(spec.host_port.unwrap_or(0)),
                    publish_mode: default_publish_mode(ctx).to_owned(),
                    rest: serde_json::Map::new(),
                }
            }
            Port::Long(long) => {
                refuse_rest(
                    ctx,
                    &at,
                    &long.rest,
                    &[
                        (
                            "host_ip",
                            "a published port is published on every address (api-compat 25)",
                        ),
                        ("name", "a port name is not carried by satl compose"),
                        ("app_protocol", "the application protocol is not modelled"),
                    ],
                    "target, published, protocol, mode",
                )?;
                let target = long.target.as_ref().ok_or_else(|| {
                    refuse(
                        ctx,
                        &at,
                        "no `target:`: the container-side port is required",
                    )
                })?;
                let protocol = long.protocol.clone().unwrap_or_else(|| "tcp".to_owned());
                if protocol != "tcp" && protocol != "udp" {
                    return Err(refuse(
                        ctx,
                        &format!("{at}.protocol"),
                        &format!("{protocol:?} is not a protocol: tcp or udp"),
                    ));
                }
                let mode = long
                    .mode
                    .clone()
                    .unwrap_or_else(|| default_publish_mode(ctx).to_owned());
                if mode != "ingress" && mode != "host" {
                    return Err(refuse(
                        ctx,
                        &format!("{at}.mode"),
                        &format!("{mode:?} is not a publish mode: ingress or host"),
                    ));
                }
                if mode == "ingress" && ctx.scope.is_local() {
                    return Err(refuse(
                        ctx,
                        &format!("{at}.mode"),
                        "the ingress routing mesh spans the cluster, and `satl compose` \
                         publishes on the one node it runs on: use `mode: host` (the default \
                         here), or deploy across the cluster with `satl stack deploy`",
                    ));
                }
                PortConfig {
                    protocol,
                    target_port: u32::from(port_number(ctx, &format!("{at}.target"), target)?),
                    published_port: match &long.published {
                        Some(published) => {
                            u32::from(port_number(ctx, &format!("{at}.published"), published)?)
                        }
                        None => 0,
                    },
                    publish_mode: mode,
                    rest: serde_json::Map::new(),
                }
            }
        };
        out.push(config);
    }
    Ok(out)
}

/// The driver a project network is created with.
///
/// Docker's own split: `docker compose` makes a bridge network per project,
/// `docker stack deploy` makes an overlay. SatL's bridge is node-local and its
/// overlay spans the cluster, so the drivers line up with the scopes exactly
/// (api-compat 170).
fn default_network_driver(ctx: &Context<'_>) -> &'static str {
    if ctx.scope.is_local() {
        "bridge"
    } else {
        "overlay"
    }
}

/// Why a declared driver is not the one this world uses.
///
/// Each arm names the other verb, because "wrong driver" here almost always
/// means the file was written for the other scope.
fn driver_refusal(ctx: &Context<'_>, driver: &str) -> String {
    if ctx.scope.is_local() {
        format!(
            "{driver:?} is not a driver `satl compose` can use: it runs the project on this \
             node alone, so its networks are bridge networks (the default -- drop the key). \
             An overlay spans the cluster: deploy with `satl stack deploy` to use one, or \
             reference an existing overlay with `external: true`"
        )
    } else {
        format!(
            "{driver:?} cannot carry a stack: a compose stack spans the cluster, and only the \
             overlay driver does (api-compat 60). Drop the key, or run the project on one node \
             with `satl compose up`, whose networks are bridge networks"
        )
    }
}

/// How a port with no `mode:` of its own is published.
///
/// `docker compose` binds the port on the host it runs on; `docker stack
/// deploy` puts it on the routing mesh. Same split here (api-compat 172).
fn default_publish_mode(ctx: &Context<'_>) -> &'static str {
    if ctx.scope.is_local() {
        "host"
    } else {
        "ingress"
    }
}

/// A relative bind source, resolved against the project directory.
///
/// Only reachable under [`Scope::Local`], where the project directory is a path
/// on the very node that will run the task. `~` is expanded from the injected
/// environment rather than read from the process, so the planner stays pure.
/// The path is normalized textually (no symlink resolution, no `stat`): the
/// planner never touches the filesystem, and a source that does not exist is
/// the daemon's error to report, with the node's own view of it.
fn local_bind_source(ctx: &Context<'_>, at: &str, path: &str) -> anyhow::Result<String> {
    let expanded = if path == "~" || path.starts_with("~/") {
        let home = (ctx.env)("HOME").ok_or_else(|| {
            refuse(
                ctx,
                at,
                &format!("the bind source {path:?} starts with `~` and HOME is not set"),
            )
        })?;
        format!("{}{}", home.trim_end_matches('/'), &path[1..])
    } else if path.starts_with('~') {
        return Err(refuse(
            ctx,
            at,
            &format!(
                "the bind source {path:?} names another user's home directory, which is not \
                 expanded: write the path out"
            ),
        ));
    } else {
        format!("{}/{path}", ctx.project_dir.display())
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in expanded.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(refuse(
                        ctx,
                        at,
                        &format!("the bind source {path:?} climbs above the filesystem root"),
                    ));
                }
            }
            other => parts.push(other),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

/// One port number of the long form.
fn port_number(ctx: &Context<'_>, at: &str, value: &Scalar) -> anyhow::Result<u16> {
    value.as_str().parse().map_err(|_| {
        refuse(
            ctx,
            at,
            &format!(
                "{:?} is not a port (ranges are not supported, api-compat 7)",
                value.as_str()
            ),
        )
    })
}

/// `networks:` as the task template's attachments.
///
/// Every attachment carries the bare compose service name as a **DNS alias**,
/// which is what makes `redis:6379` inside a compose file resolve to the
/// service SatL actually created (`<project>_redis`). This is what
/// `docker stack deploy` does — `convertServiceNetworks` appends
/// `service.Name` to the aliases of every user-defined network.
fn attachments(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    service: &Service,
) -> anyhow::Result<Vec<NetworkAttachmentConfig>> {
    let declared = service
        .networks
        .as_ref()
        .map(super::model::Attachments::entries)
        .unwrap_or_default();
    let declared = if declared.is_empty() {
        vec![("default".to_owned(), None)]
    } else {
        declared
    };
    let at = format!("services.{}.networks", service_ctx.key);
    let mut out = Vec::new();
    for (network, options) in declared {
        let target = service_ctx
            .networks
            .get(&network)
            .cloned()
            .ok_or_else(|| refuse(ctx, &at, &format!("undefined network {network:?}")))?;
        let mut aliases = vec![service_ctx.key.to_owned()];
        if let Some(options) = options {
            refuse_rest(
                ctx,
                &format!("{at}.{network}"),
                &options.rest,
                &[
                    (
                        "ipv4_address",
                        "the cluster allocator owns addresses (api-compat 69)",
                    ),
                    ("ipv6_address", "v1 is IPv4-only (api-compat 63)"),
                    (
                        "priority",
                        "attachment order is the order this file declares (api-compat 73)",
                    ),
                ],
                "aliases",
            )?;
            for alias in &options.aliases {
                if !aliases.contains(alias) {
                    aliases.push(alias.clone());
                }
            }
        }
        out.push(NetworkAttachmentConfig { target, aliases });
    }
    Ok(out)
}

/// `volumes:` of a service as the container spec's `Mounts`.
fn mounts(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    service: &Service,
    warnings: &mut Vec<String>,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    for (index, mount) in service.volumes.iter().flatten().enumerate() {
        let at = format!("services.{}.volumes[{index}]", service_ctx.key);
        out.push(one_mount(ctx, service_ctx, &at, mount, warnings)?);
    }
    Ok(out)
}

/// One entry of a service's `volumes:` as a `Mounts` document.
fn one_mount(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    at: &str,
    mount: &VolumeMount,
    warnings: &mut Vec<String>,
) -> anyhow::Result<serde_json::Value> {
    {
        let long = mount_long(ctx, at, mount)?;

        let target = long
            .target
            .clone()
            .filter(|target| !target.is_empty())
            .ok_or_else(|| {
                refuse(
                    ctx,
                    at,
                    "no `target:`: the mount point inside the jail is required",
                )
            })?;
        if !target.starts_with('/') {
            return Err(refuse(
                ctx,
                at,
                &format!("the mount point {target:?} must be an absolute path"),
            ));
        }
        let source = long.source.clone().filter(|source| !source.is_empty());
        let kind = match (long.kind.as_deref(), &source) {
            (Some(kind), _) => kind.to_owned(),
            // Compose's own rule: a source that looks like a path is a bind
            // mount, anything else names a volume. `./conf` has to reach the
            // bind arm to be refused for what it is (a path on this client's
            // filesystem) rather than as a volume nobody declared.
            (None, Some(source))
                if source.contains('/') || source.starts_with('.') || source.starts_with('~') =>
            {
                "bind".to_owned()
            }
            (None, Some(_)) => "volume".to_owned(),
            (None, None) => {
                return Err(refuse(
                    ctx,
                    at,
                    "an anonymous volume has no name to reattach to on the next task: declare \
                     a named volume under the top-level `volumes:` key",
                ));
            }
        };

        let source = mount_source(ctx, service_ctx, at, &kind, source, warnings)?;

        let mut wire = serde_json::Map::new();
        wire.insert("Type".to_owned(), serde_json::json!(kind));
        if let Some(source) = source {
            wire.insert("Source".to_owned(), serde_json::json!(source));
        }
        wire.insert("Target".to_owned(), serde_json::json!(target));
        if long.read_only == Some(true) {
            wire.insert("ReadOnly".to_owned(), serde_json::json!(true));
        }
        Ok(serde_json::Value::Object(wire))
    }
}

/// `secrets:` of a service, resolved against the file's declarations.
fn secret_refs(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    service: &Service,
) -> anyhow::Result<Vec<SecretReference>> {
    let mut out = Vec::new();
    for (index, reference) in service.secrets.iter().flatten().enumerate() {
        let (key, long) = file_ref(
            ctx,
            &format!("services.{}.secrets[{index}]", service_ctx.key),
            reference,
        )?;
        let name = declared_dependency(ctx, service_ctx, &key, "secret", service_ctx.secrets)?;
        out.push(SecretReference {
            file: file_target(ctx, &key, &long)?,
            secret_id: String::new(),
            secret_name: name,
        });
    }
    Ok(out)
}

/// `configs:` of a service, resolved against the file's declarations.
fn config_refs(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    service: &Service,
) -> anyhow::Result<Vec<ConfigReference>> {
    let mut out = Vec::new();
    for (index, reference) in service.configs.iter().flatten().enumerate() {
        let (key, long) = file_ref(
            ctx,
            &format!("services.{}.configs[{index}]", service_ctx.key),
            reference,
        )?;
        let name = declared_dependency(ctx, service_ctx, &key, "config", service_ctx.configs)?;
        out.push(ConfigReference {
            file: file_target(ctx, &key, &long)?,
            config_id: String::new(),
            config_name: name,
        });
    }
    Ok(out)
}

/// Normalize one secret/config reference into `(compose key, long form)`.
fn file_ref(
    ctx: &Context<'_>,
    at: &str,
    reference: &FileRef,
) -> anyhow::Result<(String, FileRefLong)> {
    match reference {
        FileRef::Short(source) => Ok((
            source.clone(),
            FileRefLong {
                source: Some(source.clone()),
                ..FileRefLong::default()
            },
        )),
        FileRef::Long(long) => {
            refuse_rest(ctx, at, &long.rest, &[], "source, target, uid, gid, mode")?;
            let source = long
                .source
                .clone()
                .ok_or_else(|| refuse(ctx, at, "no `source:` naming the object"))?;
            Ok((source, long.clone()))
        }
    }
}

/// The store name behind a compose secret/config key.
fn declared_dependency(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    key: &str,
    kind: &str,
    declared: &BTreeMap<String, String>,
) -> anyhow::Result<String> {
    declared.get(key).cloned().ok_or_else(|| {
        refuse(
            ctx,
            &format!("services.{}.{kind}s", service_ctx.key),
            &format!(
                "undefined {kind} {key:?}: declare it under the top-level `{kind}s:` key with \
                 `external: true`"
            ),
        )
    })
}

/// Where a secret/config payload lands inside the task, and who owns it.
fn file_target(ctx: &Context<'_>, key: &str, long: &FileRefLong) -> anyhow::Result<FileTarget> {
    let mode = match &long.mode {
        None => parse::DEFAULT_FILE_MODE,
        Some(mode) => octal_mode(ctx, key, mode)?,
    };
    Ok(FileTarget {
        // Docker's default: the file is named after the source.
        name: long.target.clone().unwrap_or_else(|| key.to_owned()),
        uid: long.uid.as_ref().map_or("0", Scalar::as_str).to_owned(),
        gid: long.gid.as_ref().map_or("0", Scalar::as_str).to_owned(),
        mode,
    })
}

/// A compose file mode, read as octal digits.
///
/// Measured, because it is a place where two YAML versions disagree and the
/// disagreement is silent: an unquoted `0440` reaches this function as the
/// digits `440` (YAML 1.2 has no octal-by-leading-zero, and the parser drops
/// the zero), while `"0440"` arrives whole. Both are read as **octal**, so both
/// mean `0o440` — the mode the operator wrote, and the one docker's go-yaml
/// would have produced. The cost is that a bare `mode: 700` is 0o700 here and
/// decimal 700 in docker; the benefit is that nobody gets a wider mode than
/// they typed.
fn octal_mode(ctx: &Context<'_>, key: &str, value: &Scalar) -> anyhow::Result<u32> {
    let text = value.as_str();
    let digits = text.strip_prefix("0o").unwrap_or(text);
    let mode = u32::from_str_radix(digits, 8).map_err(|_| {
        anyhow::anyhow!(
            "{}: secret/config {key}: invalid mode {text:?}: expected an octal file mode such \
             as 0440",
            ctx.path.display()
        )
    })?;
    if mode > 0o7777 {
        anyhow::bail!(
            "{}: secret/config {key}: invalid mode {text:?}: at most 7777 (octal)",
            ctx.path.display()
        );
    }
    Ok(mode)
}

/// `healthcheck:` as the container spec's `Healthcheck` document.
fn healthcheck_json(
    ctx: &Context<'_>,
    at: &str,
    healthcheck: &Healthcheck,
) -> anyhow::Result<Option<serde_json::Value>> {
    let at = format!("{at}.healthcheck");
    refuse_rest(
        ctx,
        &at,
        &healthcheck.rest,
        &[(
            "start_interval",
            "the service spec has no start interval; SatL probes every min(interval, 5s) while \
             a container has never been healthy (api-compat 90)",
        )],
        "test, interval, timeout, retries, start_period, disable",
    )?;

    let test = if healthcheck.disable == Some(true) {
        vec!["NONE".to_owned()]
    } else {
        match &healthcheck.test {
            None => return Ok(None),
            Some(test) if test.0.is_empty() => return Ok(None),
            Some(test) if test.0.len() == 1 => {
                // A bare string is a shell command, as in docker.
                let single = test.0[0].as_str();
                match single {
                    "NONE" => vec!["NONE".to_owned()],
                    "CMD" | "CMD-SHELL" => {
                        return Err(refuse(
                            ctx,
                            &format!("{at}.test"),
                            "a `CMD`/`CMD-SHELL` marker with no command",
                        ));
                    }
                    other => vec!["CMD-SHELL".to_owned(), other.to_owned()],
                }
            }
            Some(test) => {
                let words: Vec<String> = test.0.iter().map(|word| word.0.clone()).collect();
                match words[0].as_str() {
                    "CMD" | "CMD-SHELL" | "NONE" => words,
                    other => {
                        return Err(refuse(
                            ctx,
                            &format!("{at}.test"),
                            &format!(
                                "a list must start with CMD, CMD-SHELL or NONE, not {other:?}: \
                                 the daemon would run no probe at all and the tasks would reach \
                                 RUNNING unchecked (api-compat 91)"
                            ),
                        ));
                    }
                }
            }
        }
    };

    let mut document = serde_json::Map::new();
    document.insert("Test".to_owned(), serde_json::json!(test));
    if let Some(interval) = &healthcheck.interval {
        let nanos = duration(ctx, &format!("{at}.interval"), interval)?;
        document.insert("Interval".to_owned(), serde_json::json!(nanos));
    }
    if let Some(retries) = healthcheck.retries {
        document.insert("Retries".to_owned(), serde_json::json!(retries));
    }
    if let Some(start_period) = &healthcheck.start_period {
        let nanos = duration(ctx, &format!("{at}.start_period"), start_period)?;
        document.insert("StartPeriod".to_owned(), serde_json::json!(nanos));
    }
    if let Some(timeout) = &healthcheck.timeout {
        let nanos = duration(ctx, &format!("{at}.timeout"), timeout)?;
        document.insert("Timeout".to_owned(), serde_json::json!(nanos));
    }
    Ok(Some(serde_json::Value::Object(document)))
}

/// `deploy.resources:` as the task template's resource requirements.
fn resources(
    ctx: &Context<'_>,
    at: &str,
    deploy: &Deploy,
) -> anyhow::Result<Option<ResourceRequirements>> {
    let Some(resources) = &deploy.resources else {
        return Ok(None);
    };
    let at = format!("{at}.resources");
    refuse_rest(ctx, &at, &resources.rest, &[], "limits, reservations")?;
    let mut limits = None;
    let mut reservations = None;
    for (which, quantities) in [
        ("limits", &resources.limits),
        ("reservations", &resources.reservations),
    ] {
        let Some(quantities) = quantities else {
            continue;
        };
        let at = format!("{at}.{which}");
        refuse_rest(
            ctx,
            &at,
            &quantities.rest,
            &[
                (
                    "pids",
                    "a process cap has no rctl mapping yet (api-compat 50)",
                ),
                (
                    "devices",
                    "device reservations are not modelled (api-compat 53)",
                ),
                (
                    "generic_resources",
                    "generic resources are not modelled (api-compat 53)",
                ),
            ],
            "cpus, memory",
        )?;
        let parsed = Resources {
            nano_cpus: match &quantities.cpus {
                Some(cpus) => parse::parse_nano_cpus(cpus.as_str())
                    .map_err(|err| refuse(ctx, &format!("{at}.cpus"), &format!("{err}")))?,
                None => 0,
            },
            memory_bytes: match &quantities.memory {
                Some(memory) => parse::parse_memory(memory.as_str())
                    .map_err(|err| refuse(ctx, &format!("{at}.memory"), &format!("{err}")))?,
                None => 0,
            },
        };
        if which == "limits" {
            limits = Some(parsed);
        } else {
            reservations = Some(parsed);
        }
    }
    if limits.is_none() && reservations.is_none() {
        return Ok(None);
    }
    Ok(Some(ResourceRequirements {
        limits,
        reservations,
    }))
}

/// `deploy.placement:` as the task template's placement.
fn placement(ctx: &Context<'_>, at: &str, deploy: &Deploy) -> anyhow::Result<Option<Placement>> {
    // The node-local world places nothing: every task runs on the node the CLI
    // spoke to, pinned the way `satl run` pins its anonymous service
    // (api-compat 168). A `placement:` block would be asking the scheduler for
    // something the pin has already decided, so it is refused rather than
    // silently ANDed into unschedulability (api-compat 171).
    if let Scope::Local { node_id } = &ctx.scope {
        if deploy.placement.is_some() {
            return Err(refuse(
                ctx,
                &format!("{at}.placement"),
                "`satl compose` runs every task on the node you are talking to, so there is \
                 nothing left to place: a constraint or a preference here could only make the \
                 service unschedulable. Deploy across the cluster with `satl stack deploy` to \
                 use it",
            ));
        }
        return Ok(Some(Placement {
            constraints: vec![format!("node.id=={node_id}")],
            max_replicas: 0,
            preferences: Vec::new(),
            rest: serde_json::Map::new(),
        }));
    }
    let Some(placement) = &deploy.placement else {
        return Ok(None);
    };
    let at = format!("{at}.placement");
    refuse_rest(
        ctx,
        &at,
        &placement.rest,
        DEPLOY_REFUSALS,
        "constraints, max_replicas_per_node",
    )?;
    if placement.constraints.is_empty()
        && placement.max_replicas_per_node.is_none()
        && placement.preferences.is_empty()
    {
        return Ok(None);
    }
    let mut preferences = Vec::with_capacity(placement.preferences.len());
    for (index, preference) in placement.preferences.iter().enumerate() {
        refuse_rest(
            ctx,
            &format!("{at}.preferences[{index}]"),
            &preference.rest,
            &[],
            "spread",
        )?;
        let descriptor = preference.spread.clone().ok_or_else(|| {
            refuse(
                ctx,
                &format!("{at}.preferences[{index}]"),
                "only `spread: <descriptor>` is a supported placement preference",
            )
        })?;
        preferences.push(crate::api::cluster::PlacementPreference {
            spread: Some(crate::api::cluster::SpreadPreference {
                spread_descriptor: descriptor,
            }),
        });
    }
    Ok(Some(Placement {
        constraints: placement.constraints.clone(),
        max_replicas: placement.max_replicas_per_node.unwrap_or(0),
        preferences,
        rest: serde_json::Map::new(),
    }))
}

/// `restart:` / `deploy.restart_policy:` as the task template's restart policy.
///
/// Both spellings are honoured, `deploy.restart_policy` winning and saying so —
/// docker stack deploy silently drops `restart:` (it is in its own
/// `UnsupportedProperties` list), which is the behaviour this project refuses.
fn restart_policy(
    ctx: &Context<'_>,
    at: &str,
    service: &Service,
    deploy: &Deploy,
    warnings: &mut Vec<String>,
) -> anyhow::Result<Option<TaskRestartPolicy>> {
    let from_short = match &service.restart {
        None => None,
        Some(value) => {
            let policy = parse::parse_restart(value.as_str())
                .map_err(|err| refuse(ctx, &format!("{at}.restart"), &format!("{err}")))?;
            let condition = match policy.name.as_str() {
                "no" => "none",
                "always" => "any",
                other => other,
            };
            Some(TaskRestartPolicy {
                condition: condition.to_owned(),
                delay: 0,
                max_attempts: u64::from(policy.maximum_retry_count),
                rest: serde_json::Map::new(),
            })
        }
    };

    let Some(declared) = &deploy.restart_policy else {
        return Ok(from_short);
    };
    let policy_at = format!("{at}.deploy.restart_policy");
    refuse_rest(
        ctx,
        &policy_at,
        &declared.rest,
        &[],
        "condition, delay, max_attempts, window",
    )?;
    if from_short.is_some() {
        warnings.push(format!(
            "{at}: both `restart:` and `deploy.restart_policy:` are set; the deploy policy is \
             the one that applies"
        ));
    }
    let condition = declared
        .condition
        .clone()
        .unwrap_or_else(|| "any".to_owned());
    if !["none", "on-failure", "any"].contains(&condition.as_str()) {
        return Err(refuse(
            ctx,
            &format!("{policy_at}.condition"),
            &format!("{condition:?} is not a restart condition: none, on-failure or any"),
        ));
    }
    let mut rest = serde_json::Map::new();
    if let Some(window) = &declared.window {
        let nanos = duration(ctx, &format!("{policy_at}.window"), window)?;
        rest.insert("Window".to_owned(), serde_json::json!(nanos));
    }
    Ok(Some(TaskRestartPolicy {
        condition,
        delay: match &declared.delay {
            Some(delay) => duration(ctx, &format!("{policy_at}.delay"), delay)?,
            None => 0,
        },
        max_attempts: declared.max_attempts.unwrap_or(0),
        rest,
    }))
}

/// `deploy.update_config:` / `deploy.rollback_config:` as an `UpdateConfig`.
///
/// A named policy is filled in from docker's own defaults first, exactly as
/// `satl service create --update-*` does (api-compat 96): `Parallelism: 0` means
/// "every slot at once" to the daemon and must never be arrived at by omission.
fn update_policy(
    ctx: &Context<'_>,
    at: &str,
    which: &str,
    declared: Option<&super::model::UpdatePolicy>,
) -> anyhow::Result<Option<UpdateConfig>> {
    let Some(declared) = declared else {
        return Ok(None);
    };
    let at = format!("{at}.{which}");
    refuse_rest(
        ctx,
        &at,
        &declared.rest,
        &[],
        "parallelism, delay, failure_action, monitor, max_failure_ratio, order",
    )?;
    let mut config = UpdateConfig::docker_defaults();
    if let Some(parallelism) = declared.parallelism {
        config.parallelism = parallelism;
    }
    if let Some(delay) = &declared.delay {
        config.delay = duration(ctx, &format!("{at}.delay"), delay)?;
    }
    if let Some(action) = &declared.failure_action {
        let allowed: &[&str] = if which == "rollback_config" {
            &["pause", "continue"]
        } else {
            &["pause", "continue", "rollback"]
        };
        if !allowed.contains(&action.as_str()) {
            return Err(refuse(
                ctx,
                &format!("{at}.failure_action"),
                &format!("{action:?} is not one of {}", allowed.join(", ")),
            ));
        }
        action.clone_into(&mut config.failure_action);
    }
    if let Some(monitor) = &declared.monitor {
        config.monitor = duration(ctx, &format!("{at}.monitor"), monitor)?;
    }
    if let Some(ratio) = declared.max_failure_ratio {
        if !(0.0..=1.0).contains(&ratio) {
            return Err(refuse(
                ctx,
                &format!("{at}.max_failure_ratio"),
                &format!("{ratio} is not a fraction between 0 and 1"),
            ));
        }
        config.max_failure_ratio = ratio;
    }
    if let Some(order) = &declared.order {
        if !["start-first", "stop-first"].contains(&order.as_str()) {
            return Err(refuse(
                ctx,
                &format!("{at}.order"),
                &format!("{order:?} is not an update order: start-first or stop-first"),
            ));
        }
        order.clone_into(&mut config.order);
    }
    Ok(Some(config))
}

/// `depends_on:` — validated, warned about, and refused where a condition
/// promises something SatL cannot deliver.
///
/// There is no startup ordering in a cluster scheduler: the orchestrator places
/// every task as soon as it can, and a dependency's task may land on another
/// node a second later. Docker's own swarm mode drops `depends_on` **silently**
/// (it is in neither its unsupported nor its deprecated list, so `docker stack
/// deploy` prints nothing at all); the short form is honoured here as a warning
/// instead, and a `service_healthy`-style condition — which an application
/// genuinely relies on — is refused rather than ignored.
fn check_depends_on(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    depends_on: &super::model::DependsOn,
    warnings: &mut Vec<String>,
) -> anyhow::Result<()> {
    let at = format!("services.{}.depends_on", service_ctx.key);
    let entries = depends_on.entries();
    if entries.is_empty() {
        return Ok(());
    }
    for (name, options) in &entries {
        if !service_ctx.declared_services.contains(name) {
            return Err(refuse(ctx, &at, &format!("undefined service {name:?}")));
        }
        let Some(options) = options else { continue };
        refuse_rest(
            ctx,
            &format!("{at}.{name}"),
            &options.rest,
            &[(
                "restart",
                "a task is not restarted because a dependency was replaced",
            )],
            "condition, required",
        )?;
        match options.condition.as_deref() {
            None | Some("service_started") => {}
            Some(condition) => {
                return Err(refuse(
                    ctx,
                    &format!("{at}.{name}.condition"),
                    &format!(
                        "{condition:?} cannot be honoured: the orchestrator starts every task as \
                         soon as it can place it, so a task that waits for another service to be \
                         healthy would be started anyway. Retry the dependency inside the \
                         container, and give it a `healthcheck:` so nothing reaches RUNNING \
                         before it answers (api-compat 87)"
                    ),
                ));
            }
        }
    }
    let names: Vec<String> = entries.iter().map(|(name, _)| name.clone()).collect();
    warnings.push(format!(
        "{at}: {} is not a startup order here: every task is started as soon as it is placed. \
         Retry the connection in the container",
        names.join(", ")
    ));
    Ok(())
}

/// `networks.<key>.ipam:` as a create body's `IPAM`.
fn network_ipam(
    ctx: &Context<'_>,
    at: &str,
    declared: &Network,
    warnings: &mut Vec<String>,
) -> anyhow::Result<Option<Ipam>> {
    let Some(ipam) = &declared.ipam else {
        return Ok(None);
    };
    let at = format!("{at}.ipam");
    refuse_rest(ctx, &at, &ipam.rest, &[], "driver, config")?;
    if let Some(driver) = &ipam.driver
        && driver != "default"
    {
        return Err(refuse(
            ctx,
            &format!("{at}.driver"),
            "only the `default` IPAM driver exists (api-compat 63)",
        ));
    }
    if ipam.config.len() > 1 {
        return Err(refuse(
            ctx,
            &format!("{at}.config"),
            "a SatL network has exactly one subnet (api-compat 63)",
        ));
    }
    let Some(config) = ipam.config.first() else {
        return Ok(None);
    };
    refuse_rest(
        ctx,
        &format!("{at}.config[0]"),
        &config.rest,
        &[(
            "ip_range",
            "a sub-range of the subnet is not implemented (api-compat 63)",
        )],
        "subnet, gateway",
    )?;
    if config.gateway.is_some() {
        warnings.push(format!(
            "{at}: the requested gateway is reserved and handed to nobody: an overlay's \
             gateway is per node (api-compat 61, 71)"
        ));
    }
    Ok(Some(Ipam {
        config: vec![IpamConfig {
            subnet: config.subnet.clone().unwrap_or_default(),
            gateway: config.gateway.clone().unwrap_or_default(),
        }],
    }))
}

/// Normalize one `volumes:` entry into its long form.
fn mount_long(ctx: &Context<'_>, at: &str, mount: &VolumeMount) -> anyhow::Result<VolumeMountLong> {
    match mount {
        VolumeMount::Short(value) => {
            let spec =
                parse::parse_volume(value).map_err(|err| refuse(ctx, at, &format!("{err}")))?;
            Ok(VolumeMountLong {
                kind: None,
                source: spec.source,
                target: Some(spec.target),
                read_only: Some(spec.read_only),
                rest: Rest::new(),
            })
        }
        VolumeMount::Long(long) => {
            refuse_rest(
                ctx,
                at,
                &long.rest,
                &[
                    (
                        "bind",
                        "propagation and SELinux relabelling have no FreeBSD equivalent \
                         (api-compat 6, 50)",
                    ),
                    (
                        "volume",
                        "a volume has no options of its own (api-compat 39, 50)",
                    ),
                    (
                        "tmpfs",
                        "a tmpfs size cannot be set through the service spec (api-compat 50)",
                    ),
                    (
                        "consistency",
                        "mount consistency has no FreeBSD equivalent (api-compat 50)",
                    ),
                ],
                "type, source, target, read_only",
            )?;
            Ok(long.clone())
        }
    }
}

/// Resolve a mount's source against the file's declarations, warning about the
/// two things a cluster makes different: a named volume is per node, and a bind
/// source has to exist on every node the scheduler may choose.
fn mount_source(
    ctx: &Context<'_>,
    service_ctx: &ServiceContext<'_>,
    at: &str,
    kind: &str,
    source: Option<String>,
    warnings: &mut Vec<String>,
) -> anyhow::Result<Option<String>> {
    match kind {
        "volume" => {
            let name = source.ok_or_else(|| {
                refuse(
                    ctx,
                    at,
                    "a volume mount needs a `source:` naming the volume",
                )
            })?;
            let resolved = service_ctx.volumes.get(&name).cloned().ok_or_else(|| {
                refuse(
                    ctx,
                    at,
                    &format!(
                        "undefined volume {name:?}: declare it under the top-level `volumes:` key"
                    ),
                )
            })?;
            warnings.push(format!(
                "{at}: volume {resolved:?} is node-local: each node that runs a task of this \
                 service gets its own dataset, and the data does not follow a rescheduled task"
            ));
            Ok(Some(resolved))
        }
        "bind" => {
            let path = source.ok_or_else(|| {
                refuse(ctx, at, "a bind mount needs a `source:` naming a host path")
            })?;
            if !path.starts_with('/') {
                // In the node-local world the task runs on the node the CLI is
                // talking to, and the CLI only speaks `unix://` -- so the
                // project directory *is* a path on that node and a relative
                // bind means what the file says it means (api-compat 173).
                if ctx.scope.is_local() {
                    return Ok(Some(local_bind_source(ctx, at, &path)?));
                }
                return Err(refuse(
                    ctx,
                    at,
                    &format!(
                        "the bind source {path:?} is relative to the project directory, which is \
                         this client's filesystem and not the nodes': give an absolute path that \
                         exists on every node, or deliver the file as a config (`configs:`). \
                         `satl compose` runs on one node and does honour a relative bind"
                    ),
                ));
            }
            warnings.push(format!(
                "{at}: {path} must exist on every node the scheduler may place this service on; \
                 a task whose bind source is missing is rejected"
            ));
            Ok(Some(path))
        }
        "tmpfs" => {
            if source.is_some() {
                return Err(refuse(ctx, at, "a tmpfs mount has no source"));
            }
            Ok(None)
        }
        other => Err(refuse(
            ctx,
            &format!("{at}.type"),
            &format!("{other:?} is not a mount type: volume, bind or tmpfs (api-compat 50)"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compose file every "accepted subset" test reads: the M5 stack shape,
    /// with every supported key used at least once.
    const STACK: &str = include_str!("../../../tests/fixtures/compose/stack.yaml");

    /// The node id every `Scope::Local` test plans against.
    const TEST_NODE: &str = "n0d31d";

    /// `env_file` and `${...}`-free environment inheritance, injected.
    ///
    /// Defaults to [`Scope::Cluster`], so every test written before the two
    /// worlds were split still asserts what `satl stack` produces -- which is
    /// exactly the regression guard that says `satl stack` did not move.
    fn build_project(text: &str, project: &str) -> anyhow::Result<Plan> {
        build_scoped(text, project, Scope::Cluster)
    }

    /// The same, planned for the node-local world (`satl compose`).
    fn local_of(text: &str) -> anyhow::Result<Plan> {
        build_scoped(
            text,
            "demo",
            Scope::Local {
                node_id: TEST_NODE.to_owned(),
            },
        )
    }

    fn build_scoped(text: &str, project: &str, scope: Scope) -> anyhow::Result<Plan> {
        let path = Path::new("./compose.yaml");
        let env = |name: &str| match name {
            "FROM_ENV" => Some("from-the-client".to_owned()),
            _ => None,
        };
        let read = |path: &Path| -> anyhow::Result<String> {
            if path.ends_with("web.env") {
                Ok("# a comment\nWEB_ROOT=/usr/local/www\nFROM_ENV\nMISSING\n".to_owned())
            } else {
                Err(anyhow::anyhow!("No such file or directory (os error 2)"))
            }
        };
        let ctx = Context {
            scope,
            path,
            project_dir: Path::new("/srv/demo"),
            project,
            env: &env,
            read: &read,
        };
        build(text, &ctx)
    }

    fn plan_of(text: &str) -> anyhow::Result<Plan> {
        build_project(text, "demo")
    }

    fn service<'a>(plan: &'a Plan, key: &str) -> &'a PlannedService {
        plan.services
            .iter()
            .find(|service| service.key == key)
            .expect("the service is in the plan")
    }

    /// A file with one service and nothing else, for the refusal tests to hang
    /// keys off.
    fn one_service(body: &str) -> String {
        format!("services:\n  web:\n    image: nginx\n{body}")
    }

    // -----------------------------------------------------------------------
    // The accepted subset
    // -----------------------------------------------------------------------

    #[test]
    fn the_stack_fixture_becomes_three_services_two_networks_and_a_volume() {
        let plan = build_project(STACK, "shop").expect("the fixture is the supported subset");
        assert_eq!(plan.project, "shop");
        assert_eq!(
            plan.services
                .iter()
                .map(|service| service.name.as_str())
                .collect::<Vec<_>>(),
            ["shop_redis", "shop_web", "shop_worker"]
        );
        assert_eq!(
            plan.networks
                .iter()
                .map(|network| network.name.as_str())
                .collect::<Vec<_>>(),
            ["shop_default", "shop_internal"]
        );
        assert_eq!(plan.volumes[0].name, "shop_redis-data");
    }

    /// The spec of the whole fixture, field for field. This is the golden that
    /// makes every mapping decision visible in a diff.
    #[test]
    fn the_stack_fixture_maps_field_for_field() {
        let plan = build_project(STACK, "shop").expect("valid");
        let web = serde_json::to_string(&service(&plan, "web").spec).expect("serializable");
        assert_eq!(
            web,
            concat!(
                r#"{"Name":"shop_web","Labels":{"com.docker.compose.project":"shop","#,
                r#""com.docker.compose.service":"web","owner":"sre"},"#,
                r#""TaskTemplate":{"ContainerSpec":{"#,
                r#""Image":"127.0.0.1:5000/satl-test/freebsd-nginx:latest","#,
                r#""Labels":{"tier":"front"},"#,
                r#""Env":["WEB_ROOT=/usr/local/www","FROM_ENV=from-the-client","#,
                r#""REDIS_HOST=redis","REPLICAS=3"],"#,
                r#""Healthcheck":{"Interval":10000000000,"Retries":3,"StartPeriod":20000000000,"#,
                r#""Test":["CMD","/rescue/test","-f","/usr/local/www/satl-test/index.html"],"#,
                r#""Timeout":3000000000},"StopGracePeriod":15000000000},"#,
                r#""Resources":{"Limits":{"NanoCPUs":500000000,"MemoryBytes":268435456},"#,
                r#""Reservations":{"MemoryBytes":67108864}},"#,
                r#""RestartPolicy":{"Condition":"any","MaxAttempts":0},"#,
                r#""Placement":{"Constraints":["node.role == worker"],"MaxReplicas":2},"#,
                r#""Networks":[{"Target":"shop_default","Aliases":["web"]},"#,
                r#"{"Target":"shop_internal","Aliases":["web"]}]},"#,
                r#""Mode":{"Replicated":{"Replicas":3}},"#,
                // A zero `Delay`, `Monitor` or `MaxFailureRatio` is left off the
                // wire: the daemon reads a missing `Monitor` as "the SwarmKit
                // default" (api-compat 51), which is what an unset key means.
                r#""UpdateConfig":{"Parallelism":1,"FailureAction":"rollback","#,
                r#""Monitor":8000000000,"Order":"stop-first"},"#,
                r#""RollbackConfig":{"Parallelism":2,"FailureAction":"pause","#,
                r#""Order":"stop-first"},"#,
                r#""EndpointSpec":{"Ports":["#,
                r#"{"Protocol":"tcp","TargetPort":80,"PublishedPort":18088,"PublishMode":"ingress"},"#,
                r#"{"Protocol":"tcp","TargetPort":8443,"PublishedPort":18443,"PublishMode":"host"}"#,
                r#"]}}"#,
            )
        );
    }

    /// The two things that make a namespaced stack work at all: the service is
    /// `<project>_<service>`, and the compose service name is a DNS alias on
    /// every network it joins.
    #[test]
    fn every_attachment_carries_the_compose_service_name_as_an_alias() {
        let plan = build_project(STACK, "shop").expect("valid");
        let redis = &service(&plan, "redis").spec.task_template.networks;
        assert_eq!(redis.len(), 1);
        assert_eq!(redis[0].target, "shop_internal");
        assert_eq!(redis[0].aliases, ["redis", "cache"]);
    }

    #[test]
    fn a_service_naming_no_network_joins_the_projects_default_overlay() {
        let plan = plan_of("services:\n  web:\n    image: nginx\n").expect("valid");
        assert_eq!(plan.networks.len(), 1);
        let network = &plan.networks[0];
        assert_eq!(network.name, "demo_default");
        assert!(!network.external);
        let body = network.body.as_ref().expect("a create body");
        assert_eq!(body.driver, "overlay");
        assert_eq!(
            body.labels,
            BTreeMap::from([
                (
                    "com.docker.compose.network".to_owned(),
                    "default".to_owned()
                ),
                ("com.docker.compose.project".to_owned(), "demo".to_owned()),
            ])
        );
        assert_eq!(
            service(&plan, "web").spec.task_template.networks[0].target,
            "demo_default"
        );
    }

    #[test]
    fn an_external_network_keeps_its_own_name_and_is_not_created() {
        let plan = plan_of(
            "services:\n  web:\n    image: nginx\n    networks: [shared]\n\
             networks:\n  shared:\n    external: true\n",
        )
        .expect("valid");
        assert_eq!(plan.networks[0].name, "shared");
        assert!(plan.networks[0].external);
        assert!(plan.networks[0].body.is_none());
    }

    #[test]
    fn entrypoint_becomes_command_and_command_becomes_args() {
        let plan = plan_of(&one_service(
            "    entrypoint: /bin/tini\n    command: nginx -g 'daemon off;'\n",
        ))
        .expect("valid");
        let container = &service(&plan, "web").spec.task_template.container_spec;
        assert_eq!(container.command, ["/bin/tini"]);
        assert_eq!(container.args, ["nginx", "-g", "daemon off;"]);
    }

    #[test]
    fn a_secret_lands_under_run_secrets_with_the_mode_that_was_written() {
        let plan = build_project(STACK, "shop").expect("valid");
        let secrets = &service(&plan, "redis")
            .spec
            .task_template
            .container_spec
            .secrets;
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_name, "redis_auth");
        assert!(
            secrets[0].secret_id.is_empty(),
            "resolved against the daemon"
        );
        assert_eq!(secrets[0].file.name, "redis.conf");
        // 0400 unquoted reaches the parser as the digits 440-style decimal; both
        // spellings mean the octal mode the operator wrote.
        assert_eq!(secrets[0].file.mode, 0o400);
    }

    #[test]
    fn a_config_can_name_a_store_object_that_is_not_its_key() {
        let plan = build_project(STACK, "shop").expect("valid");
        let configs = &service(&plan, "worker")
            .spec
            .task_template
            .container_spec
            .configs;
        assert_eq!(configs[0].config_name, "shop_worker_conf_v2");
        assert_eq!(configs[0].file.name, "/usr/local/etc/worker.conf");
    }

    #[test]
    fn a_named_volume_is_namespaced_and_a_bind_is_left_alone() {
        let plan = plan_of(&one_service(
            "    volumes:\n      - data:/var/db\n      - /etc/ssl/certs:/etc/ssl/certs:ro\n\
             volumes:\n  data: {}\n",
        ))
        .expect("valid");
        let mounts = &service(&plan, "web")
            .spec
            .task_template
            .container_spec
            .mounts;
        // `serde_json::Map` is a `BTreeMap`, so a mount document goes out with
        // its keys in alphabetical order.
        assert_eq!(
            serde_json::to_string(mounts).expect("serializable"),
            concat!(
                r#"[{"Source":"demo_data","Target":"/var/db","Type":"volume"},"#,
                r#"{"ReadOnly":true,"Source":"/etc/ssl/certs","Target":"/etc/ssl/certs","#,
                r#""Type":"bind"}]"#,
            )
        );
    }

    #[test]
    fn global_mode_and_a_restart_policy_reach_the_spec() {
        let plan = build_project(STACK, "shop").expect("valid");
        assert_eq!(service(&plan, "worker").spec.mode, ServiceMode::global());
        let policy = service(&plan, "redis")
            .spec
            .task_template
            .restart_policy
            .clone()
            .expect("a restart policy");
        assert_eq!(policy.condition, "any");
        assert_eq!(policy.delay, 5_000_000_000);
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(
            policy
                .rest
                .get("Window")
                .and_then(serde_json::Value::as_i64),
            Some(60_000_000_000)
        );
    }

    /// `restart:` alone, in docker run's spelling, mapped onto the swarm
    /// conditions.
    #[test]
    fn the_short_restart_key_maps_onto_a_condition() {
        for (written, condition) in [
            ("no", "none"),
            ("always", "any"),
            ("on-failure", "on-failure"),
        ] {
            let plan = plan_of(&one_service(&format!("    restart: {written}\n")))
                .unwrap_or_else(|err| panic!("restart: {written} must be accepted: {err}"));
            let policy = service(&plan, "web")
                .spec
                .task_template
                .restart_policy
                .clone()
                .expect("a restart policy");
            assert_eq!(policy.condition, condition);
        }
        let plan = plan_of(&one_service("    restart: on-failure:3\n")).expect("valid");
        assert_eq!(
            service(&plan, "web")
                .spec
                .task_template
                .restart_policy
                .clone()
                .expect("a policy")
                .max_attempts,
            3
        );
    }

    /// A `restart_policy:` with a condition and no `delay:` sends no `Delay`
    /// at all, so the daemon's admission default applies (5 s, api-compat
    /// 153) — audit N1 measured this exact shape crash-looping with no delay.
    #[test]
    fn a_restart_policy_without_a_delay_sends_none() {
        for body in [
            "    deploy:\n      restart_policy:\n        condition: on-failure\n",
            "    restart: on-failure\n",
        ] {
            let plan = plan_of(&one_service(body))
                .unwrap_or_else(|err| panic!("{body:?} must be accepted: {err}"));
            let policy = service(&plan, "web")
                .spec
                .task_template
                .restart_policy
                .clone()
                .expect("a restart policy");
            assert_eq!(policy.condition, "on-failure");
            let json = serde_json::to_value(&policy).expect("serializable");
            assert!(
                json.get("Delay").is_none(),
                "for {body:?}: no Delay on the wire, so admission defaults it: {json}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Refusals
    // -----------------------------------------------------------------------

    /// Everything SatL cannot honour, with the reason it gives. The table is
    /// the feature: a compose file that half-deployed would be worse than one
    /// refused, so every one of these must fail *before* anything is created.
    // One table, deliberately: the refusals are the feature, and splitting them
    // across functions to satisfy a line count would hide that they are one
    // list with one contract.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn every_refusal_names_the_file_the_place_and_the_reason() {
        for (body, needle) in [
            (
                "    build: .\n",
                "services.web.build: a stack's tasks are placed on any node",
            ),
            (
                "    privileged: true\n",
                "services.web.privileged: a task never runs privileged",
            ),
            (
                "    cap_add: [NET_ADMIN]\n",
                "services.web.cap_add: FreeBSD jails have no capability model",
            ),
            (
                "    cap_drop: [ALL]\n",
                "services.web.cap_drop: FreeBSD jails have no capability model",
            ),
            (
                "    devices: ['/dev/dri:/dev/dri']\n",
                "services.web.devices: device passthrough is not implemented",
            ),
            (
                "    network_mode: host\n",
                "services.web.network_mode: every task is attached to SatL networks",
            ),
            (
                "    profiles: [debug]\n",
                "services.web.profiles: profiles are not implemented",
            ),
            (
                "    extends:\n      service: base\n",
                "services.web.extends: extends is not implemented",
            ),
            (
                "    container_name: web1\n",
                "services.web.container_name: a container is a task of a service",
            ),
            (
                "    mem_limit: 512m\n",
                "services.web.mem_limit: use `deploy.resources.limits.memory:`",
            ),
            (
                "    sysctls:\n      a: b\n",
                "services.web.sysctls: per-jail sysctls",
            ),
            (
                "    expose: ['80']\n",
                "services.web.expose: `expose:` has no effect anywhere",
            ),
            (
                "    tty: true\n",
                "services.web.tty: SatL never allocates a TTY",
            ),
            (
                "    runtime: runc\n",
                "services.web.runtime: the runtime is always ocijail",
            ),
            // A key nobody has a bespoke reason for still gets refused, with the
            // list of keys that are read.
            (
                "    annotations:\n      a: b\n",
                "services.web.annotations: not supported by satl compose; supported keys are \
                 build, command, configs",
            ),
            (
                "    deploy:\n      preferences:\n        - spread: node.labels.zone\n",
                "services.web.deploy.preferences: placement preferences are deferred",
            ),
            (
                "    deploy:\n      endpoint_mode: vip\n",
                "services.web.deploy.endpoint_mode: \"vip\" is not supported",
            ),
            (
                "    deploy:\n      mode: replicated-job\n",
                "services.web.deploy.mode: \"replicated-job\" is not a service mode here",
            ),
            (
                "    deploy:\n      mode: global\n      replicas: 3\n",
                "services.web.deploy.replicas: a global service runs one task per eligible node",
            ),
            (
                "    deploy:\n      resources:\n        limits:\n          pids: 100\n",
                "services.web.deploy.resources.limits.pids: a process cap has no rctl mapping",
            ),
            (
                "    deploy:\n      update_config:\n        order: fastest\n",
                "update_config.order: \"fastest\" is not an update order",
            ),
            (
                "    deploy:\n      rollback_config:\n        failure_action: rollback\n",
                "rollback_config.failure_action: \"rollback\" is not one of pause, continue",
            ),
            (
                "    restart: unless-stopped\n",
                "unless-stopped has no equivalent in SatL's restart supervisor",
            ),
            (
                "    healthcheck:\n      test: [curl, -f, localhost]\n",
                "must start with CMD, CMD-SHELL or NONE, not \"curl\"",
            ),
            (
                "    healthcheck:\n      test: [CMD, true]\n      start_interval: 1s\n",
                "healthcheck.start_interval: the service spec has no start interval",
            ),
            (
                "    ports: ['8000-8010:80']\n",
                "port ranges are not supported yet",
            ),
            (
                "    ports:\n      - target: 80\n        host_ip: 127.0.0.1\n",
                "ports[0].host_ip: a published port is published on every address",
            ),
            (
                "    volumes: ['./conf:/etc/nginx']\n",
                "is relative to the project directory, which is this client's filesystem",
            ),
            (
                "    volumes: ['/var/db']\n",
                "an anonymous volume has no name to reattach to",
            ),
            (
                "    volumes: ['nowhere:/var/db']\n",
                "undefined volume \"nowhere\": declare it under the top-level `volumes:` key",
            ),
            (
                "    volumes:\n      - type: npipe\n        source: x\n        target: /x\n",
                "volumes[0].type: \"npipe\" is not a mount type",
            ),
            (
                "    networks: [nowhere]\n",
                "services.web.networks: undefined network \"nowhere\"",
            ),
            (
                "    secrets: [nowhere]\n",
                "undefined secret \"nowhere\": declare it under the top-level `secrets:` key",
            ),
            (
                "    depends_on:\n      db:\n        condition: service_healthy\n",
                "depends_on: undefined service \"db\"",
            ),
        ] {
            let err = plan_of(&one_service(body)).expect_err(&format!("must refuse: {body}"));
            let message = format!("{err:#}");
            assert!(
                message.contains(needle),
                "the refusal for {body:?} reads {message:?}, which does not contain {needle:?}"
            );
            assert!(
                message.starts_with("./compose.yaml:"),
                "a refusal must name the file: {message}"
            );
        }
    }

    /// The refusals that need more than one service or a top-level key.
    #[test]
    fn top_level_refusals() {
        for (text, needle) in [
            (
                "services:\n  web:\n    image: nginx\ninclude:\n  - other.yaml\n",
                "include: include is not implemented",
            ),
            ("services: {}\n", "services: no service declared"),
            ("services:\n  web: {}\n", "services.web: no `image:` given"),
            (
                "services:\n  web:\n    image: nginx\n    networks: [blue]\nnetworks:\n  blue:\n    driver: bridge\n",
                "networks.blue.driver: \"bridge\" cannot carry a stack",
            ),
            (
                "services:\n  web:\n    image: nginx\n    networks: [blue]\nnetworks:\n  blue:\n    attachable: true\n",
                "networks.blue.attachable: every container is a task of a service",
            ),
            (
                "services:\n  web:\n    image: nginx\n    networks: [blue]\nnetworks:\n  blue:\n    external: true\n    driver: overlay\n",
                "networks.blue: an external network is used as it is",
            ),
            (
                "services:\n  web:\n    image: nginx\n    networks: [blue]\nnetworks:\n  blue:\n    ipam:\n      config:\n        - subnet: 10.1.0.0/24\n        - subnet: 10.2.0.0/24\n",
                "networks.blue.ipam.config: a SatL network has exactly one subnet",
            ),
            (
                "services:\n  web:\n    image: nginx\n    secrets: [db]\nsecrets:\n  db:\n    file: ./db.txt\n",
                "secrets.db.file: satl compose never creates a secret from a file",
            ),
            (
                "services:\n  web:\n    image: nginx\n    secrets: [db]\nsecrets:\n  db:\n    environment: DB_PASSWORD\n",
                "secrets.db.environment: a payload from the environment is not accepted",
            ),
            (
                "services:\n  web:\n    image: nginx\n    secrets: [db]\nsecrets:\n  db: {}\n",
                "secrets.db: only `external: true` is supported",
            ),
            (
                "services:\n  web:\n    image: nginx\n    volumes: ['d:/d']\nvolumes:\n  d:\n    driver: nfs\n",
                "volumes.d.driver: only the `local` driver exists",
            ),
        ] {
            let err = plan_of(text).expect_err(&format!("must refuse: {text}"));
            let message = format!("{err:#}");
            assert!(
                message.contains(needle),
                "the refusal reads {message:?}, which does not contain {needle:?}"
            );
        }
    }

    /// The `x-` keys the Compose Spec reserves for extensions are the one thing
    /// an unknown key may be: ignored, at every level, because that is where
    /// YAML anchors are usually parked.
    #[test]
    fn extension_keys_are_the_only_unknown_keys_accepted() {
        let plan = plan_of(
            "x-anchors:\n  common: &common\n    image: nginx\nservices:\n  web:\n    <<: *common\n\
                 x-note: whatever\n",
        )
        .expect("x- keys are extensions");
        assert_eq!(
            service(&plan, "web")
                .spec
                .task_template
                .container_spec
                .image,
            "nginx"
        );
    }

    #[test]
    fn interpolation_is_refused_rather_than_passed_through() {
        let err = plan_of("services:\n  web:\n    image: nginx:${TAG}\n")
            .expect_err("a literal ${TAG} would be deployed");
        let message = format!("{err:#}");
        assert!(
            message.contains("line 3 column 18: variable interpolation is not implemented"),
            "{message}"
        );
        // `$$` is compose's escape and is applied, so a command written for
        // compose means the same thing here.
        let plan = plan_of(&one_service("    command: sh -c 'echo $$HOME'\n")).expect("valid");
        assert_eq!(
            service(&plan, "web").spec.task_template.container_spec.args,
            ["sh", "-c", "echo $HOME"]
        );
    }

    // -----------------------------------------------------------------------
    // YAML behaviour this parser depends on (measured, not assumed)
    // -----------------------------------------------------------------------

    /// The Norway problem, in the one place it bites a compose file: `restart:
    /// no` must stay the string `no`. YAML 1.1 resolves it to `false`, and the
    /// parser is configured with `strict_booleans` for exactly this reason -- a
    /// service silently switched to "restart: false" would restart forever.
    #[test]
    fn restart_no_is_the_string_no_and_not_a_boolean() {
        let plan = plan_of(&one_service("    restart: no\n")).expect("valid");
        assert_eq!(
            service(&plan, "web")
                .spec
                .task_template
                .restart_policy
                .clone()
                .expect("a policy")
                .condition,
            "none"
        );
        // And a real boolean still reads as one where compose expects it.
        let plan = plan_of(&one_service(
            "    healthcheck:\n      test: [CMD, true]\n      disable: true\n",
        ))
        .expect("valid");
        let health = service(&plan, "web")
            .spec
            .task_template
            .container_spec
            .rest
            .get("Healthcheck")
            .expect("a healthcheck")
            .clone();
        assert_eq!(health["Test"], serde_json::json!(["NONE"]));
    }

    /// `ports: ["8080:80"]` must not become a sexagesimal integer (YAML 1.1's
    /// `8080:80` is 484880), and a bare `80` must still be a port.
    #[test]
    fn a_port_pair_is_not_a_number() {
        let plan =
            plan_of(&one_service("    ports:\n      - 8080:80\n      - 80\n")).expect("valid");
        let ports = &service(&plan, "web")
            .spec
            .endpoint_spec
            .clone()
            .expect("ports")
            .ports;
        assert_eq!((ports[0].published_port, ports[0].target_port), (8080, 80));
        assert_eq!((ports[1].published_port, ports[1].target_port), (0, 80));
    }

    /// Two services with the same key must not silently collapse into the
    /// second one. The YAML crate refuses the document; this test is what pins
    /// that choice of crate.
    #[test]
    fn a_duplicate_service_key_is_an_error() {
        let err = plan_of("services:\n  web:\n    image: a\n  web:\n    image: b\n")
            .expect_err("a duplicate key must not be a silent overwrite");
        let message = format!("{err:#}");
        assert!(message.contains("duplicate mapping key: web"), "{message}");
        assert!(
            message.contains("./compose.yaml:4:3"),
            "the snippet must name the operator's own file: {message}"
        );
    }

    /// A merge key is resolved rather than dropped: a compose file whose
    /// services inherit from `x-defaults: &defaults` must deploy what it says.
    #[test]
    fn merge_keys_are_applied() {
        let plan = build_project(STACK, "shop").expect("valid");
        let web = &service(&plan, "web").spec.task_template;
        // `restart: always` and `stop_grace_period: 15s` come from the anchor.
        assert_eq!(
            web.restart_policy.clone().expect("a policy").condition,
            "any"
        );
        assert_eq!(
            web.container_spec
                .rest
                .get("StopGracePeriod")
                .and_then(serde_json::Value::as_i64),
            Some(15_000_000_000)
        );
    }

    /// A file mode is read as octal whichever way it is written, because the two
    /// spellings reach this parser differently: `0400` arrives as the digits
    /// `400` (the leading zero is gone), `"0400"` arrives whole.
    #[test]
    fn a_file_mode_is_octal_written_either_way() {
        for written in ["0400", "\"0400\"", "400"] {
            let text = format!(
                "services:\n  web:\n    image: nginx\n    secrets:\n      - source: db\n\
                     \x20       mode: {written}\nsecrets:\n  db:\n    external: true\n"
            );
            let plan = plan_of(&text).unwrap_or_else(|err| panic!("mode: {written}: {err}"));
            assert_eq!(
                service(&plan, "web")
                    .spec
                    .task_template
                    .container_spec
                    .secrets[0]
                    .file
                    .mode,
                0o400,
                "mode: {written}"
            );
        }
        let text = "services:\n  web:\n    image: nginx\n    secrets:\n      - source: db\n\
                    \x20       mode: 999\nsecrets:\n  db:\n    external: true\n";
        let err = plan_of(text).expect_err("999 is not octal");
        assert!(
            format!("{err:#}").contains("expected an octal file mode"),
            "{err:#}"
        );
    }

    // -----------------------------------------------------------------------
    // Project naming
    // -----------------------------------------------------------------------

    /// compose-go's `NormalizeProjectName`: lowercase, *delete* what is not
    /// allowed (never replace it), trim leading `_`/`-` only.
    #[test]
    fn project_names_are_normalized_like_composes() {
        for (input, expected) in [
            ("Shop", "shop"),
            ("my.app", "myapp"),
            ("My App!", "myapp"),
            ("_leading", "leading"),
            ("-leading", "leading"),
            ("trailing_", "trailing_"),
            ("keep-both_", "keep-both_"),
            ("2fast", "2fast"),
            ("...", ""),
        ] {
            assert_eq!(normalize_project_name(input), expected, "{input}");
        }
    }

    #[test]
    fn an_explicit_project_name_must_already_be_normalized() {
        assert!(validate_project_name("shop").is_ok());
        assert!(validate_project_name("shop_2-a").is_ok());
        for bad in ["Shop", "my.app", "_leading", ""] {
            let err = validate_project_name(bad).expect_err(&format!("{bad} must be refused"));
            assert!(
                format!("{err}").contains("must consist only of lowercase alphanumeric"),
                "{err}"
            );
        }
    }

    /// The project name namespaces every object, which is what makes `down`
    /// removable-by-label and two stacks of the same file coexist.
    #[test]
    fn the_project_name_namespaces_every_object() {
        let plan = build_project(STACK, "other").expect("valid");
        assert_eq!(service(&plan, "web").name, "other_web");
        assert_eq!(plan.networks[0].name, "other_default");
        assert_eq!(plan.volumes[0].name, "other_redis-data");
        assert_eq!(service(&plan, "web").spec.labels[PROJECT_LABEL], "other");
        assert_eq!(service(&plan, "web").spec.labels[SERVICE_LABEL], "web");
    }

    // -----------------------------------------------------------------------
    // Warnings: honoured in part, said out loud
    // -----------------------------------------------------------------------

    #[test]
    fn what_is_honoured_only_in_part_is_warned_about() {
        let plan = build_project(STACK, "shop").expect("valid");
        let warnings = plan.warnings.join("\n");
        for needle in [
            "depends_on: redis is not a startup order here",
            "volume \"shop_redis-data\" is node-local",
        ] {
            assert!(
                warnings.contains(needle),
                "missing warning {needle:?} in:\n{warnings}"
            );
        }
    }

    #[test]
    fn an_obsolete_version_key_is_a_warning_not_a_refusal() {
        let plan = plan_of("version: '3.9'\nservices:\n  web:\n    image: nginx\n")
            .expect("version is accepted");
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("`version:` top-level key is obsolete")),
            "{:?}",
            plan.warnings
        );
    }

    #[test]
    fn a_declared_network_nobody_uses_is_not_created() {
        let plan = plan_of(
            "services:\n  web:\n    image: nginx\nnetworks:\n  unused:\n    driver: overlay\n",
        )
        .expect("valid");
        assert_eq!(
            plan.networks
                .iter()
                .map(|network| network.key.as_str())
                .collect::<Vec<_>>(),
            ["default"]
        );
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("network \"unused\" is declared but no service")),
            "{:?}",
            plan.warnings
        );
    }

    #[test]
    fn a_bind_mount_warns_that_the_path_must_exist_on_every_node() {
        let plan = plan_of(&one_service("    volumes: ['/etc/ssl:/etc/ssl:ro']\n")).expect("valid");
        assert!(
            plan.warnings.iter().any(|warning| warning
                .contains("/etc/ssl must exist on every node the scheduler may place")),
            "{:?}",
            plan.warnings
        );
    }

    #[test]
    fn an_ipam_gateway_is_reserved_and_handed_to_nobody() {
        let plan = plan_of(
            "services:\n  web:\n    image: nginx\n    networks: [blue]\nnetworks:\n  blue:\n\
             \x20   ipam:\n      config:\n        - subnet: 10.9.0.0/24\n          gateway: 10.9.0.1\n",
        )
        .expect("valid");
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("gateway is reserved and handed to nobody")),
            "{:?}",
            plan.warnings
        );
        let body = plan.networks[0].body.as_ref().expect("a body");
        let ipam = body.ipam.as_ref().expect("ipam");
        assert_eq!(ipam.config[0].subnet, "10.9.0.0/24");
        assert_eq!(ipam.config[0].gateway, "10.9.0.1");
    }

    // -----------------------------------------------------------------------
    // Small pure pieces
    // -----------------------------------------------------------------------

    #[test]
    fn a_command_string_is_split_the_way_a_shell_would() {
        assert_eq!(
            shell_words("nginx -g 'daemon off;'").expect("valid"),
            ["nginx", "-g", "daemon off;"]
        );
        assert_eq!(
            shell_words(r#"sh -c "echo \"hi\" there""#).expect("valid"),
            ["sh", "-c", r#"echo "hi" there"#]
        );
        assert_eq!(shell_words("a\\ b c").expect("valid"), ["a b", "c"]);
        assert_eq!(shell_words("   ").expect("valid"), Vec::<String>::new());
        for bad in ["'unterminated", "\"unterminated", "trailing\\"] {
            assert!(shell_words(bad).is_err(), "{bad} must be refused");
        }
    }

    /// A list is an argv, verbatim: no splitting, so an argument with a space in
    /// it survives.
    #[test]
    fn a_command_list_is_taken_verbatim() {
        let plan = plan_of(&one_service(
            "    command: ['/bin/sh', '-c', 'echo one two']\n",
        ))
        .expect("valid");
        assert_eq!(
            service(&plan, "web").spec.task_template.container_spec.args,
            ["/bin/sh", "-c", "echo one two"]
        );
    }

    // -----------------------------------------------------------------------
    // The two worlds (M11a)
    //
    // Every test above plans with `Scope::Cluster`, so between them they are
    // the guard that `satl stack` did not move. These are what `satl compose`
    // does differently.
    // -----------------------------------------------------------------------

    #[test]
    fn local_names_with_a_hyphen_and_cluster_with_an_underscore() {
        let text = "services:\n  web:\n    image: nginx\n    networks: [front]\n\
                    networks:\n  front:\nvolumes:\n  data:\n";
        let cluster = build_project(text, "demo").expect("cluster plans");
        assert_eq!(service(&cluster, "web").name, "demo_web");
        assert_eq!(cluster.networks[0].name, "demo_front");
        assert_eq!(cluster.volumes[0].name, "demo_data");

        let local = local_of(text).expect("local plans");
        assert_eq!(service(&local, "web").name, "demo-web");
        assert_eq!(local.networks[0].name, "demo-front");
        assert_eq!(local.volumes[0].name, "demo-data");
    }

    #[test]
    fn local_pins_every_service_to_the_receiving_node() {
        let plan = local_of(&one_service("")).expect("local plans");
        let placement = service(&plan, "web")
            .spec
            .task_template
            .placement
            .as_ref()
            .expect("the pin is always there");
        assert_eq!(placement.constraints, [format!("node.id=={TEST_NODE}")]);

        // The cluster world places nothing of its own.
        let cluster = build_project(&one_service(""), "demo").expect("cluster plans");
        assert!(
            service(&cluster, "web")
                .spec
                .task_template
                .placement
                .is_none()
        );
    }

    #[test]
    fn local_refuses_a_placement_block_and_points_at_stack_deploy() {
        let body = concat!(
            "    deploy:\n",
            "      placement:\n",
            "        constraints:\n",
            "          - node.role == worker\n",
        );
        let err = local_of(&one_service(body)).expect_err("nothing left to place");
        let message = format!("{err:#}");
        assert!(
            message.contains("services.web.deploy.placement")
                && message.contains("satl stack deploy"),
            "{message}"
        );
        // The same file is fine in the world that has somewhere to place it.
        build_project(&one_service(body), "demo").expect("cluster honours placement");
    }

    #[test]
    fn local_publishes_on_the_host_and_cluster_on_the_ingress_mesh() {
        let body = "    ports:\n      - \"8080:80\"\n";
        let local = local_of(&one_service(body)).expect("local plans");
        let ports = &service(&local, "web")
            .spec
            .endpoint_spec
            .as_ref()
            .expect("a published port")
            .ports;
        assert_eq!(ports[0].publish_mode, "host");
        assert_eq!(ports[0].published_port, 8080);

        let cluster = build_project(&one_service(body), "demo").expect("cluster plans");
        assert_eq!(
            cluster.services[0]
                .spec
                .endpoint_spec
                .as_ref()
                .expect("a published port")
                .ports[0]
                .publish_mode,
            "ingress"
        );
    }

    #[test]
    fn local_refuses_an_explicit_ingress_publish_mode() {
        let body = concat!(
            "    ports:\n",
            "      - target: 80\n",
            "        published: 8080\n",
            "        mode: ingress\n",
        );
        let err = local_of(&one_service(body)).expect_err("no mesh on one node");
        let message = format!("{err:#}");
        assert!(
            message.contains("ingress routing mesh") && message.contains("satl stack deploy"),
            "{message}"
        );
    }

    #[test]
    fn local_refuses_a_fixed_host_port_with_more_than_one_replica() {
        let body = "    ports:\n      - \"8080:80\"\n    deploy:\n      replicas: 3\n";
        let err = local_of(&one_service(body)).expect_err("a host port is taken once");
        let message = format!("{err:#}");
        assert!(
            message.contains("services.web: 3 replicas with host port 8080")
                && message.contains("satl stack deploy"),
            "{message}"
        );

        // An ephemeral host port has nothing to collide over.
        let ephemeral = "    ports:\n      - \"80\"\n    deploy:\n      replicas: 3\n";
        local_of(&one_service(ephemeral)).expect("no fixed port, no conflict");

        // And the cluster world spreads them over nodes, so it is fine.
        build_project(&one_service(body), "demo").expect("cluster spreads the replicas");
    }

    #[test]
    fn local_resolves_a_relative_bind_against_the_project_directory() {
        for (written, expected) in [
            ("./conf:/etc/nginx", "/srv/demo/conf"),
            ("conf/nginx:/etc/nginx", "/srv/demo/conf/nginx"),
            ("../shared:/etc/nginx", "/srv/shared"),
        ] {
            let body = format!("    volumes:\n      - \"{written}\"\n");
            let plan = local_of(&one_service(&body)).expect("local resolves the bind");
            let mounts = &service(&plan, "web")
                .spec
                .task_template
                .container_spec
                .mounts;
            assert_eq!(mounts[0]["Source"], expected, "{written}");
            assert_eq!(mounts[0]["Type"], "bind", "{written}");

            // The cluster world still refuses it, and now says where it works.
            let err = build_project(&one_service(&body), "demo").expect_err("not on the nodes");
            let message = format!("{err:#}");
            assert!(message.contains("satl compose"), "{message}");
        }
    }

    #[test]
    fn each_world_creates_its_own_driver_and_refuses_the_others() {
        // Declared explicitly, each in the world it belongs to.
        let bridge = "services:\n  web:\n    image: nginx\n    networks: [front]\n\
                      networks:\n  front:\n    driver: bridge\n";
        let overlay = "services:\n  web:\n    image: nginx\n    networks: [front]\n\
                       networks:\n  front:\n    driver: overlay\n";
        let implicit = "services:\n  web:\n    image: nginx\n    networks: [front]\n\
                        networks:\n  front:\n";

        let driver_of = |plan: &Plan| {
            plan.networks[0]
                .body
                .as_ref()
                .expect("a created network")
                .driver
                .clone()
        };
        assert_eq!(driver_of(&local_of(bridge).expect("local plans")), "bridge");
        assert_eq!(
            driver_of(&local_of(implicit).expect("local plans")),
            "bridge"
        );
        assert_eq!(
            driver_of(&build_project(overlay, "demo").expect("cluster plans")),
            "overlay"
        );
        assert_eq!(
            driver_of(&build_project(implicit, "demo").expect("cluster plans")),
            "overlay"
        );

        // And each refuses the other's, naming the verb that would work.
        let err = format!(
            "{:#}",
            local_of(overlay).expect_err("no overlay on one node")
        );
        assert!(
            err.contains("satl stack deploy") && err.contains("bridge networks"),
            "{err}"
        );
        let err = format!(
            "{:#}",
            build_project(bridge, "demo").expect_err("a stack spans the cluster")
        );
        assert!(
            err.contains("cannot carry a stack") && err.contains("satl compose up"),
            "{err}"
        );
    }

    // -----------------------------------------------------------------------
    // build:  (M11e)
    // -----------------------------------------------------------------------

    #[test]
    fn a_built_service_needs_no_image_and_is_tagged_after_the_project() {
        let plan = local_of("services:\n  web:\n    build: ./web\n").expect("build plans");
        let service = service(&plan, "web");
        let build = service.build.as_ref().expect("a planned build");
        assert_eq!(build.context, std::path::Path::new("/srv/demo/web"));
        // The build file is the Satlfile in the context, not a Dockerfile.
        assert_eq!(build.file, std::path::Path::new("/srv/demo/web/Satlfile"));
        assert_eq!(build.tag, "demo-web:latest");
        // And what the service deploys is exactly what the build registers.
        assert_eq!(
            service.spec.task_template.container_spec.image,
            "demo-web:latest"
        );
    }

    #[test]
    fn an_explicit_image_wins_over_the_derived_tag() {
        let plan = local_of(
            "services:\n  web:\n    image: registry.example.com/web:7\n    build: ./web\n",
        )
        .expect("build plans");
        let service = service(&plan, "web");
        assert_eq!(
            service.build.as_ref().expect("a planned build").tag,
            "registry.example.com/web:7"
        );
        assert_eq!(
            service.spec.task_template.container_spec.image,
            "registry.example.com/web:7"
        );
    }

    #[test]
    fn the_long_form_takes_a_context_and_a_build_file() {
        let body = concat!(
            "services:\n",
            "  web:\n",
            "    build:\n",
            "      context: ./web\n",
            "      dockerfile: Satlfile.prod\n",
        );
        let plan = local_of(body).expect("the long form plans");
        let build = service(&plan, "web").build.as_ref().expect("a build");
        assert_eq!(build.context, std::path::Path::new("/srv/demo/web"));
        assert_eq!(
            build.file,
            std::path::Path::new("/srv/demo/web/Satlfile.prod")
        );
    }

    #[test]
    fn build_keys_the_builder_cannot_honour_are_refused_by_name() {
        for (key, needle) in [
            ("      args:\n        VERSION: '7'\n", "has no `ARG`"),
            ("      target: builder\n", "always packs the last one"),
            ("      platform: linux/amd64\n", "the node it runs on"),
        ] {
            let body = format!("services:\n  web:\n    build:\n      context: ./web\n{key}");
            let err = local_of(&body).expect_err("the builder cannot honour it");
            let message = format!("{err:#}");
            assert!(message.contains("services.web.build"), "{message}");
            assert!(message.contains(needle), "{message}");
        }
    }

    #[test]
    fn a_stack_refuses_to_build_and_says_where_the_image_must_come_from() {
        let err = build_project("services:\n  web:\n    build: ./web\n", "demo")
            .expect_err("a stack's tasks are placed on any node");
        let message = format!("{err:#}");
        assert!(message.contains("could not pull the result"), "{message}");
        assert!(message.contains("--push"), "{message}");
        assert!(message.contains("satl compose up --build"), "{message}");
    }

    #[test]
    fn a_service_with_neither_image_nor_build_is_refused_in_both_worlds() {
        let err = format!(
            "{:#}",
            local_of("services:\n  web: {}\n").expect_err("nothing to run")
        );
        assert!(err.contains("no `image:` and no `build:`"), "{err}");

        let err = format!(
            "{:#}",
            build_project("services:\n  web: {}\n", "demo").expect_err("nothing to run")
        );
        assert!(err.contains("no `image:` given"), "{err}");
        assert!(err.contains("satl compose"), "{err}");
    }

    #[test]
    fn an_env_file_that_does_not_exist_names_the_path() {
        let err = plan_of(&one_service("    env_file: nope.env\n")).expect_err("no such file");
        let message = format!("{err:#}");
        assert!(
            message.contains("services.web.env_file: cannot read /srv/demo/nope.env"),
            "{message}"
        );
    }
}
