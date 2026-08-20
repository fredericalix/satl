// SPDX-License-Identifier: BSD-2-Clause
//! `satl node ls|ps|inspect|update|rm|promote|demote`.
//!
//! `update` (and its `promote`/`demote` wrappers) follows docker's
//! read-modify-write: inspect the node, edit the spec, then `POST
//! /nodes/{id}/update?version=<index>` so the daemon can reject a concurrent
//! change with `409`.

use std::collections::BTreeMap;

use crate::api::cluster::{Node, NodeSpec, SystemInfo, Task};
use crate::client::{self, Host};
use crate::cmd::{FAILURE, service};
use crate::format::{self, Table};
use crate::output::Streams;
use crate::parse;

/// Subcommands of `satl node`.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum NodeCommand {
    /// List nodes in the swarm.
    Ls(LsArgs),
    /// List the tasks running on one or more nodes.
    Ps(PsArgs),
    /// Display detailed information on one or more nodes.
    Inspect(InspectArgs),
    /// Update a node.
    Update(UpdateArgs),
    /// Remove one or more nodes from the swarm.
    Rm(RmArgs),
    /// Promote one or more nodes to manager in the swarm.
    Promote(RoleArgs),
    /// Demote one or more nodes from manager in the swarm.
    Demote(RoleArgs),
}

/// Flags of `satl node ls`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct LsArgs {
    /// Only display IDs.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Flags of `satl node ps`.
#[derive(Debug, Clone, clap::Args)]
pub struct PsArgs {
    /// Don't truncate output.
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,

    /// Only display task IDs.
    #[arg(short, long)]
    pub quiet: bool,

    /// Nodes whose tasks to list; defaults to this one, as docker does.
    #[arg(value_name = "NODE", default_value = "self")]
    pub nodes: Vec<String>,
}

impl Default for PsArgs {
    fn default() -> Self {
        Self {
            no_trunc: false,
            quiet: false,
            nodes: vec!["self".to_owned()],
        }
    }
}

/// Flags of `satl node inspect`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct InspectArgs {
    /// Print the information in a human friendly format.
    #[arg(long)]
    pub pretty: bool,

    /// Nodes to inspect; `self` means the node serving this request.
    #[arg(required = true, value_name = "NODE")]
    pub nodes: Vec<String>,
}

/// Flags of `satl node update`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct UpdateArgs {
    /// Add or update a node label (`key=value`).
    #[arg(long = "label-add", value_name = "KEY=VALUE")]
    pub label_add: Vec<String>,

    /// Remove a node label if it exists.
    #[arg(long = "label-rm", value_name = "KEY")]
    pub label_rm: Vec<String>,

    /// Availability of the node.
    #[arg(long, value_name = "STATE", value_parser = ["active", "pause", "drain"])]
    pub availability: Option<String>,

    /// Role of the node.
    #[arg(long, value_name = "ROLE", value_parser = ["worker", "manager"])]
    pub role: Option<String>,

    /// The node to update.
    #[arg(value_name = "NODE")]
    pub node: String,
}

/// Flags of `satl node rm`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RmArgs {
    /// Force remove a node from the swarm.
    #[arg(short, long)]
    pub force: bool,

    /// Nodes to remove.
    #[arg(required = true, value_name = "NODE")]
    pub nodes: Vec<String>,
}

/// Flags of `satl node promote` / `satl node demote`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RoleArgs {
    /// Nodes to promote or demote.
    #[arg(required = true, value_name = "NODE")]
    pub nodes: Vec<String>,
}

/// Dispatch a `satl node` subcommand.
pub async fn execute(
    host: &Host,
    command: &NodeCommand,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    match command {
        NodeCommand::Ls(args) => {
            let nodes: Vec<Node> = client::get_json(host, "/nodes").await?;
            // Docker marks the node serving the request with `*`; it learns
            // which one that is from /info, exactly as we do here.
            let local = client::get_json::<SystemInfo>(host, "/info")
                .await
                .map(|info| info.swarm.node_id)
                .unwrap_or_default();
            streams.out(render(&nodes, &local, args).as_bytes()).await;
            Ok(0)
        }
        NodeCommand::Ps(args) => ps(host, args, streams).await,
        NodeCommand::Inspect(args) => inspect(host, args, streams).await,
        NodeCommand::Update(args) => {
            update(host, &args.node, |spec| apply(spec, args)).await?;
            streams.outln(&args.node).await;
            Ok(0)
        }
        NodeCommand::Rm(args) => remove(host, args, streams).await,
        NodeCommand::Promote(args) => set_role(host, args, "manager", streams).await,
        NodeCommand::Demote(args) => set_role(host, args, "worker", streams).await,
    }
}

/// `satl node ps [NODE...]` — the tasks bound to each node, in `satl service
/// ps`'s table.
///
/// **Manager-only.** `/tasks` is served from the Raft store, and the daemon's
/// `list_tasks` requires a manager, so this answers `503` on a worker. That
/// is unlike `satl images rm`, which is node-local by nature: a task is a
/// cluster object and only a manager can enumerate them.
async fn ps(host: &Host, args: &PsArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut tasks: Vec<Task> = Vec::new();
    let mut failed = false;
    for reference in &args.nodes {
        // `self` is a node ID the daemon knows and we do not; the same
        // resolution every other node verb does.
        let resolved = resolve_self(host, reference).await;
        match client::get_json::<Vec<Task>>(host, &tasks_path(&resolved)).await {
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
    let render_args = service::PsArgs {
        no_trunc: args.no_trunc,
        quiet: args.quiet,
        services: Vec::new(),
    };
    streams
        .out(service::render_ps(&tasks, &hostnames, &render_args, format::now_unix()).as_bytes())
        .await;
    Ok(if failed { FAILURE } else { 0 })
}

/// Build the `GET /tasks` URL for one node (pure). `node` is a real filter
/// the daemon understands, matched against the node ID *or* its hostname.
#[must_use]
pub fn tasks_path(node: &str) -> String {
    let filters = serde_json::json!({ "node": { node: true } }).to_string();
    format!("/tasks{}", client::query(&[("filters", filters.as_str())]))
}

async fn inspect(host: &Host, args: &InspectArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut failed = false;
    let mut found: Vec<Node> = Vec::new();
    let mut raw: Vec<serde_json::Value> = Vec::new();
    for reference in &args.nodes {
        let reference = resolve_self(host, reference).await;
        let path = format!("/nodes/{reference}");
        match client::get_json::<serde_json::Value>(host, &path).await {
            Ok(value) => {
                if args.pretty {
                    match serde_json::from_value::<Node>(value) {
                        Ok(node) => found.push(node),
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
        for node in &found {
            streams.out(pretty(node).as_bytes()).await;
        }
    } else {
        streams.outln(&crate::cmd::inspect::render(&raw)).await;
    }
    Ok(if failed { FAILURE } else { 0 })
}

/// Docker accepts `self` wherever a node reference is expected.
async fn resolve_self(host: &Host, reference: &str) -> String {
    if reference != "self" {
        return reference.to_owned();
    }
    client::get_json::<SystemInfo>(host, "/info")
        .await
        .map_or_else(|_| reference.to_owned(), |info| info.swarm.node_id)
}

/// Reads the node, applies `edit` to its spec and writes it back against the
/// version that was read (docker's optimistic-concurrency dance).
async fn update<F>(host: &Host, reference: &str, edit: F) -> anyhow::Result<()>
where
    F: FnOnce(&mut NodeSpec) -> anyhow::Result<()>,
{
    let resolved = resolve_self(host, reference).await;
    let node: Node = client::get_json(host, &format!("/nodes/{resolved}")).await?;
    let mut spec = node.spec.clone();
    edit(&mut spec)?;
    let version = node.version.index.to_string();
    let path = format!(
        "/nodes/{}/update{}",
        node.id,
        client::query(&[("version", version.as_str())])
    );
    client::post_ok(host, &path, Some(&spec)).await
}

/// Applies `satl node update`'s flags to a spec.
fn apply(spec: &mut NodeSpec, args: &UpdateArgs) -> anyhow::Result<()> {
    for label in &args.label_add {
        let (key, value) = parse::parse_label(label)?;
        spec.labels.insert(key, value);
    }
    for key in &args.label_rm {
        spec.labels.remove(key);
    }
    if let Some(availability) = &args.availability {
        spec.availability.clone_from(availability);
    }
    if let Some(role) = &args.role {
        spec.role.clone_from(role);
    }
    Ok(())
}

async fn set_role(
    host: &Host,
    args: &RoleArgs,
    role: &str,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    let mut failed = false;
    for reference in &args.nodes {
        let outcome = update(host, reference, |spec| {
            role.clone_into(&mut spec.role);
            Ok(())
        })
        .await;
        match outcome {
            Ok(()) => {
                let message = if role == "manager" {
                    format!("Node {reference} promoted to a manager in the swarm.")
                } else {
                    format!("Manager {reference} demoted in the swarm.")
                };
                streams.outln(&message).await;
            }
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    Ok(if failed { FAILURE } else { 0 })
}

async fn remove(host: &Host, args: &RmArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let query = client::query(&[("force", if args.force { "true" } else { "false" })]);
    let mut failed = false;
    for reference in &args.nodes {
        let resolved = resolve_self(host, reference).await;
        let path = format!("/nodes/{resolved}{query}");
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

/// Render `node ls` (pure, for goldens). `local` is the node ID `/info`
/// reported for this daemon; that row is marked with `*`, as docker does.
pub fn render(nodes: &[Node], local: &str, args: &LsArgs) -> String {
    if args.quiet {
        let mut out = String::new();
        for node in nodes {
            out.push_str(&node.id);
            out.push('\n');
        }
        return out;
    }

    let mut table = Table::new(&[
        "ID",
        "HOSTNAME",
        "STATUS",
        "AVAILABILITY",
        "MANAGER STATUS",
        "ENGINE VERSION",
    ]);
    for node in nodes {
        let id = if !local.is_empty() && node.id == local {
            format!("{} *", node.id)
        } else {
            node.id.clone()
        };
        table.push(vec![
            id,
            node.display_name().to_owned(),
            format::capitalize(&node.status.state),
            format::capitalize(&node.spec.availability),
            manager_status(node),
            node.description.engine.engine_version.clone(),
        ]);
    }
    table.render()
}

/// The `MANAGER STATUS` cell: `Leader` for the leader, otherwise the
/// reachability, and empty on workers (docker's rule).
fn manager_status(node: &Node) -> String {
    match &node.manager_status {
        None => String::new(),
        Some(status) if status.leader => "Leader".to_owned(),
        Some(status) => format::capitalize(&status.reachability),
    }
}

/// `satl node inspect --pretty` (pure, for goldens).
// Writing into a `String` is infallible; the `let _` discards a `fmt::Result`
// that cannot be an error.
pub fn pretty(node: &Node) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "ID:\t\t\t{}", node.id);
    let _ = writeln!(out, "Hostname:\t\t{}", node.description.hostname);
    if !node.spec.labels.is_empty() {
        out.push_str("Labels:\n");
        for (key, value) in &node.spec.labels {
            let _ = writeln!(out, " - {key}={value}");
        }
    }
    out.push_str("Status:\n");
    let _ = writeln!(
        out,
        " State:\t\t\t{}",
        format::capitalize(&node.status.state)
    );
    let _ = writeln!(
        out,
        " Availability:\t\t{}",
        format::capitalize(&node.spec.availability)
    );
    let _ = writeln!(out, " Address:\t\t{}", node.status.addr);
    if let Some(status) = &node.manager_status {
        out.push_str("Manager Status:\n");
        let _ = writeln!(out, " Address:\t\t{}", status.addr);
        let _ = writeln!(
            out,
            " Raft Status:\t\t{}",
            format::capitalize(&status.reachability)
        );
        let _ = writeln!(
            out,
            " Leader:\t\t{}",
            if status.leader { "Yes" } else { "No" }
        );
    }
    out.push_str("Platform:\n");
    let _ = writeln!(out, " Operating System:\t{}", node.description.platform.os);
    let _ = writeln!(
        out,
        " Architecture:\t\t{}",
        node.description.platform.architecture
    );
    out.push_str("Resources:\n");
    let _ = writeln!(
        out,
        " CPUs:\t\t\t{}",
        node.description.resources.nano_cpus / 1_000_000_000
    );
    let _ = writeln!(
        out,
        " Memory:\t\t{}",
        format::human_size(node.description.resources.memory_bytes)
    );
    let _ = writeln!(
        out,
        "Engine Version:\t\t{}",
        node.description.engine.engine_version
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;
    use crate::stub::{Reply, Stub};

    const ALPHA: &str = "1hvy0lj3x0b883f8e30fyp217";
    const BETA: &str = "2hvy0lj3x0b883f8e30fyp218";

    fn nodes_json() -> String {
        format!(
            r#"[
            {{"ID":"{ALPHA}","Version":{{"Index":7}},
              "Spec":{{"Role":"manager","Availability":"active","Labels":{{"zone":"a"}}}},
              "Description":{{"Hostname":"alpha",
                 "Platform":{{"Architecture":"amd64","OS":"freebsd"}},
                 "Resources":{{"NanoCPUs":8000000000,"MemoryBytes":34359738368}},
                 "Engine":{{"EngineVersion":"0.1.0"}}}},
              "Status":{{"State":"ready","Addr":"10.2.0.11"}},
              "ManagerStatus":{{"Leader":true,"Reachability":"reachable","Addr":"10.2.0.11:2377"}}}},
            {{"ID":"{BETA}","Version":{{"Index":9}},
              "Spec":{{"Role":"worker","Availability":"drain"}},
              "Description":{{"Hostname":"beta","Engine":{{"EngineVersion":"0.1.0"}}}},
              "Status":{{"State":"down","Addr":"10.2.0.12"}}}}
        ]"#
        )
    }

    fn alpha_json() -> String {
        format!(
            r#"{{"ID":"{ALPHA}","Version":{{"Index":7}},
              "Spec":{{"Role":"manager","Availability":"active","Labels":{{"zone":"a"}}}},
              "Description":{{"Hostname":"alpha",
                 "Platform":{{"Architecture":"amd64","OS":"freebsd"}},
                 "Resources":{{"NanoCPUs":8000000000,"MemoryBytes":34359738368}},
                 "Engine":{{"EngineVersion":"0.1.0"}}}},
              "Status":{{"State":"ready","Addr":"10.2.0.11"}},
              "ManagerStatus":{{"Leader":true,"Reachability":"reachable","Addr":"10.2.0.11:2377"}}}}"#
        )
    }

    fn sample() -> Vec<Node> {
        serde_json::from_str(&nodes_json()).expect("fixture parses")
    }

    #[test]
    fn ls_column_golden_marks_the_local_node() {
        let expected = format!(
            "\
ID                            HOSTNAME   STATUS   AVAILABILITY   MANAGER STATUS   ENGINE VERSION
{ALPHA} *   alpha      Ready    Active         Leader           0.1.0
{BETA}     beta       Down     Drain                           0.1.0
"
        );
        assert_eq!(render(&sample(), ALPHA, &LsArgs::default()), expected);
    }

    #[test]
    fn ls_without_a_local_node_marks_nothing() {
        let rendered = render(&sample(), "", &LsArgs::default());
        assert!(!rendered.contains('*'), "{rendered}");
    }

    #[test]
    fn ls_quiet_prints_full_ids() {
        let args = LsArgs { quiet: true };
        assert_eq!(
            render(&sample(), ALPHA, &args),
            format!("{ALPHA}\n{BETA}\n")
        );
    }

    #[test]
    fn ls_of_an_empty_cluster_still_prints_headers() {
        let rendered = render(&[], "", &LsArgs::default());
        assert_eq!(rendered.lines().count(), 1);
        assert!(rendered.starts_with("ID "));
        assert!(rendered.ends_with("ENGINE VERSION\n"));
    }

    #[test]
    fn pretty_golden() {
        let expected = format!(
            "\
ID:\t\t\t{ALPHA}
Hostname:\t\talpha
Labels:
 - zone=a
Status:
 State:\t\t\tReady
 Availability:\t\tActive
 Address:\t\t10.2.0.11
Manager Status:
 Address:\t\t10.2.0.11:2377
 Raft Status:\t\tReachable
 Leader:\t\tYes
Platform:
 Operating System:\tfreebsd
 Architecture:\t\tamd64
Resources:
 CPUs:\t\t\t8
 Memory:\t\t34.36GB
Engine Version:\t\t0.1.0
"
        );
        assert_eq!(pretty(&sample()[0]), expected);
    }

    #[test]
    fn pretty_omits_the_manager_block_on_a_worker() {
        let rendered = pretty(&sample()[1]);
        assert!(!rendered.contains("Manager Status"), "{rendered}");
        assert!(rendered.contains("State:\t\t\tDown"), "{rendered}");
    }

    #[tokio::test]
    async fn ls_fetches_the_nodes_and_the_local_id() {
        let stub = Stub::start().await;
        stub.on("GET", "/nodes", Reply::json(200, &nodes_json()))
            .on(
                "GET",
                "/info",
                Reply::json(200, &format!(r#"{{"Swarm":{{"NodeID":"{ALPHA}"}}}}"#)),
            );
        let (mut streams, out, _err) = testing::streams();
        execute(
            &stub.host(),
            &NodeCommand::Ls(LsArgs::default()),
            &mut streams,
        )
        .await
        .expect("ls succeeds");
        assert!(
            out.contents().contains(&format!("{ALPHA} *")),
            "{}",
            out.contents()
        );
        assert_eq!(stub.routes(), vec!["GET /nodes", "GET /info"]);
    }

    #[tokio::test]
    async fn update_reads_then_writes_with_the_current_version() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            &format!("/nodes/{ALPHA}"),
            Reply::json(200, &alpha_json()),
        )
        .on("POST", &format!("/nodes/{ALPHA}/update"), Reply::empty(200));

        let (mut streams, out, _err) = testing::streams();
        let args = UpdateArgs {
            label_add: vec!["role=web".to_owned()],
            label_rm: vec!["zone".to_owned()],
            availability: Some("drain".to_owned()),
            role: None,
            node: ALPHA.to_owned(),
        };
        execute(&stub.host(), &NodeCommand::Update(args), &mut streams)
            .await
            .expect("update succeeds");

        assert_eq!(out.contents(), format!("{ALPHA}\n"));
        let call = stub
            .first_call(&format!("POST /nodes/{ALPHA}/update"))
            .expect("update call");
        assert_eq!(call.query, "version=7");
        assert_eq!(
            call.body,
            r#"{"Labels":{"role":"web"},"Role":"manager","Availability":"drain"}"#
        );
    }

    #[tokio::test]
    async fn promote_and_demote_are_role_updates() {
        for (command, role, message) in [
            (
                NodeCommand::Promote(RoleArgs {
                    nodes: vec![BETA.to_owned()],
                }),
                "manager",
                format!("Node {BETA} promoted to a manager in the swarm.\n"),
            ),
            (
                NodeCommand::Demote(RoleArgs {
                    nodes: vec![BETA.to_owned()],
                }),
                "worker",
                format!("Manager {BETA} demoted in the swarm.\n"),
            ),
        ] {
            let stub = Stub::start().await;
            stub.on(
                "GET",
                &format!("/nodes/{BETA}"),
                Reply::json(
                    200,
                    &format!(
                        r#"{{"ID":"{BETA}","Version":{{"Index":9}},
                            "Spec":{{"Role":"worker","Availability":"active"}}}}"#
                    ),
                ),
            )
            .on("POST", &format!("/nodes/{BETA}/update"), Reply::empty(200));

            let (mut streams, out, _err) = testing::streams();
            execute(&stub.host(), &command, &mut streams)
                .await
                .expect("role change succeeds");
            assert_eq!(out.contents(), message);
            let call = stub
                .first_call(&format!("POST /nodes/{BETA}/update"))
                .expect("update call");
            assert_eq!(call.query, "version=9");
            assert!(
                call.body.contains(&format!(r#""Role":"{role}""#)),
                "{}",
                call.body
            );
        }
    }

    #[tokio::test]
    async fn rm_forwards_force_and_reports_failures() {
        let stub = Stub::start().await;
        stub.on("DELETE", &format!("/nodes/{BETA}"), Reply::empty(200))
            .on(
                "DELETE",
                "/nodes/ghost",
                Reply::json(404, r#"{"message":"node ghost not found"}"#),
            );

        let (mut streams, out, err) = testing::streams();
        let args = RmArgs {
            force: true,
            nodes: vec![BETA.to_owned(), "ghost".to_owned()],
        };
        let code = execute(&stub.host(), &NodeCommand::Rm(args), &mut streams)
            .await
            .expect("rm returns an exit code");
        assert_eq!(code, FAILURE);
        assert_eq!(out.contents(), format!("{BETA}\n"));
        assert_eq!(
            err.contents(),
            "Error response from daemon: node ghost not found\n"
        );
        assert_eq!(
            stub.first_call(&format!("DELETE /nodes/{BETA}"))
                .expect("delete")
                .query,
            "force=true"
        );
    }

    #[tokio::test]
    async fn inspect_pretty_and_raw() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            &format!("/nodes/{ALPHA}"),
            Reply::json(
                200,
                &format!(
                    r#"{{"ID":"{ALPHA}","Description":{{"Hostname":"alpha"}},
                        "Status":{{"State":"ready","Addr":"10.2.0.11"}},
                        "Spec":{{"Availability":"active","Role":"manager"}}}}"#
                ),
            ),
        );

        let (mut streams, out, _err) = testing::streams();
        let args = InspectArgs {
            pretty: true,
            nodes: vec![ALPHA.to_owned()],
        };
        execute(&stub.host(), &NodeCommand::Inspect(args), &mut streams)
            .await
            .expect("inspect succeeds");
        assert!(out.contents().starts_with(&format!("ID:\t\t\t{ALPHA}\n")));
        assert!(out.contents().contains("Hostname:\t\talpha"));

        let (mut streams, out, _err) = testing::streams();
        let args = InspectArgs {
            pretty: false,
            nodes: vec![ALPHA.to_owned()],
        };
        execute(&stub.host(), &NodeCommand::Inspect(args), &mut streams)
            .await
            .expect("inspect succeeds");
        assert!(
            out.contents().starts_with("[\n    {\n"),
            "{}",
            out.contents()
        );
        assert!(out.contents().contains(&format!("\"ID\": \"{ALPHA}\"")));
    }

    #[tokio::test]
    async fn inspect_reports_a_missing_node_and_exits_1() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/nodes/ghost",
            Reply::json(404, r#"{"message":"node ghost not found"}"#),
        );
        let (mut streams, _out, err) = testing::streams();
        let args = InspectArgs {
            pretty: false,
            nodes: vec!["ghost".to_owned()],
        };
        let code = execute(&stub.host(), &NodeCommand::Inspect(args), &mut streams)
            .await
            .expect("inspect returns an exit code");
        assert_eq!(code, FAILURE);
        assert_eq!(
            err.contents(),
            "Error response from daemon: node ghost not found\n"
        );
    }

    #[tokio::test]
    async fn self_resolves_through_info() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/info",
            Reply::json(200, &format!(r#"{{"Swarm":{{"NodeID":"{ALPHA}"}}}}"#)),
        )
        .on("DELETE", &format!("/nodes/{ALPHA}"), Reply::empty(200));

        let (mut streams, out, _err) = testing::streams();
        let args = RmArgs {
            force: false,
            nodes: vec!["self".to_owned()],
        };
        execute(&stub.host(), &NodeCommand::Rm(args), &mut streams)
            .await
            .expect("rm succeeds");
        assert_eq!(out.contents(), "self\n");
        assert!(stub.routes().contains(&format!("DELETE /nodes/{ALPHA}")));
    }

    #[test]
    fn tasks_path_is_dockers_node_filter() {
        assert_eq!(
            tasks_path("alpha"),
            "/tasks?filters=%7B%22node%22%3A%7B%22alpha%22%3Atrue%7D%7D"
        );
        // Percent-decoded, that is `{"node":{"alpha":true}}`.
        assert_eq!(
            tasks_path(ALPHA),
            format!("/tasks?filters=%7B%22node%22%3A%7B%22{ALPHA}%22%3Atrue%7D%7D")
        );
    }

    fn tasks_json() -> String {
        format!(
            r#"[{{"ID":"2ju54ic19pyb0mmqmb4z2ncdo","Name":"web.1.2ju54ic19pyb",
                 "ServiceID":"9hvy0lj3x0b883f8e30fyp211","Slot":1,"NodeID":"{ALPHA}",
                 "Spec":{{"ContainerSpec":{{"Image":"nginx:1.27"}}}},
                 "DesiredState":"running",
                 "Status":{{"State":"running","Timestamp":"2026-08-19T14:00:00Z"}}}}]"#
        )
    }

    #[tokio::test]
    async fn ps_defaults_to_self_and_renders_the_task_table() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/info",
            Reply::json(200, &format!(r#"{{"Swarm":{{"NodeID":"{ALPHA}"}}}}"#)),
        )
        .on("GET", "/tasks", Reply::json(200, &tasks_json()))
        .on("GET", "/nodes", Reply::json(200, &nodes_json()));

        let (mut streams, out, _err) = testing::streams();
        let code = execute(
            &stub.host(),
            &NodeCommand::Ps(PsArgs::default()),
            &mut streams,
        )
        .await
        .expect("ps succeeds");
        assert_eq!(code, 0);
        // `self` was resolved through /info before the tasks were asked for.
        assert_eq!(stub.routes(), vec!["GET /info", "GET /tasks", "GET /nodes"]);
        assert_eq!(
            stub.first_call("GET /tasks").unwrap().query,
            format!("filters=%7B%22node%22%3A%7B%22{ALPHA}%22%3Atrue%7D%7D")
        );
        let printed = out.contents();
        assert!(printed.starts_with("ID  "), "{printed}");
        // The NODE column shows the hostname, not the node ID.
        assert!(printed.contains("alpha"), "{printed}");
        assert!(printed.contains("web.1"), "{printed}");
        assert!(printed.contains("nginx:1.27"), "{printed}");
        assert!(
            !printed.contains(ALPHA),
            "the node ID is not a column: {printed}"
        );
    }

    #[tokio::test]
    async fn ps_queries_every_named_node_and_never_resolves_self() {
        let stub = Stub::start().await;
        stub.on("GET", "/tasks", Reply::json(200, "[]")).on(
            "GET",
            "/nodes",
            Reply::json(200, "[]"),
        );

        let (mut streams, _out, _err) = testing::streams();
        let args = PsArgs {
            nodes: vec!["alpha".to_owned(), "beta".to_owned()],
            ..PsArgs::default()
        };
        execute(&stub.host(), &NodeCommand::Ps(args), &mut streams)
            .await
            .expect("ps succeeds");
        let task_calls: Vec<_> = stub
            .calls()
            .into_iter()
            .filter(|call| call.route() == "GET /tasks")
            .collect();
        assert_eq!(task_calls.len(), 2, "one query per node");
        assert!(
            task_calls[0].query.contains("alpha"),
            "{:?}",
            task_calls[0].query
        );
        assert!(
            task_calls[1].query.contains("beta"),
            "{:?}",
            task_calls[1].query
        );
        assert!(
            !stub.routes().contains(&"GET /info".to_owned()),
            "a named node needs no resolution"
        );
    }

    #[tokio::test]
    async fn ps_quiet_prints_only_task_ids() {
        let stub = Stub::start().await;
        stub.on("GET", "/tasks", Reply::json(200, &tasks_json()))
            .on("GET", "/nodes", Reply::json(200, "[]"));

        let (mut streams, out, _err) = testing::streams();
        let args = PsArgs {
            quiet: true,
            no_trunc: true,
            nodes: vec!["alpha".to_owned()],
        };
        execute(&stub.host(), &NodeCommand::Ps(args), &mut streams)
            .await
            .expect("ps succeeds");
        assert_eq!(out.contents(), "2ju54ic19pyb0mmqmb4z2ncdo\n");
    }

    /// `/tasks` is manager-only; a worker answers 503 and the operator has to
    /// see why rather than an empty table.
    #[tokio::test]
    async fn ps_on_a_worker_reports_the_managers_only_error_and_exits_1() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/tasks",
            Reply::json(503, r#"{"message":"This node is not a swarm manager."}"#),
        )
        .on("GET", "/nodes", Reply::json(200, "[]"));

        let (mut streams, out, err) = testing::streams();
        let args = PsArgs {
            nodes: vec!["beta".to_owned()],
            ..PsArgs::default()
        };
        let code = execute(&stub.host(), &NodeCommand::Ps(args), &mut streams)
            .await
            .expect("ps returns an exit code");
        assert_eq!(code, FAILURE);
        assert_eq!(
            err.contents(),
            "Error response from daemon: This node is not a swarm manager.\n"
        );
        // The header is still printed, as `service ps` does with no tasks.
        assert!(out.contents().starts_with("ID  "), "{}", out.contents());
    }
}
