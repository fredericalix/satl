// SPDX-License-Identifier: BSD-2-Clause
//! `satl volume ls|create|inspect|rm|prune`.
//!
//! Volumes are node-local (api-compat #130): every verb here acts on the
//! store of the daemon that answered, not on the cluster's.

use std::collections::BTreeMap;

use crate::api::{CreateVolumeBody, Volume, VolumeListResponse, VolumesPruneResponse};
use crate::client::{self, Host};
use crate::cmd::{FAILURE, system};
use crate::format::Table;
use crate::output::Streams;
use crate::parse;

/// Subcommands of `satl volume`.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum VolumeCommand {
    /// List volumes.
    Ls(LsArgs),
    /// Create a volume.
    Create(CreateArgs),
    /// Display detailed information on one or more volumes.
    Inspect(InspectArgs),
    /// Remove one or more volumes.
    Rm(RmArgs),
    /// Remove all unused local volumes.
    Prune(PruneArgs),
}

/// Flags of `satl volume ls`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct LsArgs {
    /// Only display volume names.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Flags of `satl volume create`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct CreateArgs {
    /// Specify volume driver name.
    #[arg(short, long, value_name = "DRIVER")]
    pub driver: Option<String>,

    /// Set metadata for a volume.
    #[arg(long, value_name = "KEY=VALUE")]
    pub label: Vec<String>,

    /// Volume name; the daemon generates one when omitted.
    #[arg(value_name = "VOLUME")]
    pub name: Option<String>,
}

/// Flags of `satl volume inspect`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct InspectArgs {
    /// Volumes to inspect.
    #[arg(required = true, value_name = "VOLUME")]
    pub volumes: Vec<String>,
}

/// Flags of `satl volume rm`.
#[derive(Debug, Clone, clap::Args)]
pub struct RmArgs {
    /// Force the removal of one or more volumes.
    #[arg(short, long)]
    pub force: bool,

    /// Volumes to remove.
    #[arg(required = true, value_name = "VOLUME")]
    pub volumes: Vec<String>,
}

/// Flags of `satl volume prune`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct PruneArgs {
    /// Do not prompt for confirmation.
    #[arg(short, long)]
    pub force: bool,
}

/// Dispatch a `satl volume` subcommand.
pub async fn execute(
    host: &Host,
    command: &VolumeCommand,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    match command {
        VolumeCommand::Ls(args) => {
            let response: VolumeListResponse = client::get_json(host, "/volumes").await?;
            streams
                .out(render(&response.volumes, args).as_bytes())
                .await;
            Ok(0)
        }
        VolumeCommand::Create(args) => {
            let body = create_body(args)?;
            let volume: Volume = client::post_json(host, "/volumes/create", Some(&body)).await?;
            let name = if volume.name.is_empty() {
                body.name.clone()
            } else {
                volume.name
            };
            streams.outln(&name).await;
            Ok(0)
        }
        VolumeCommand::Inspect(args) => inspect(host, args, streams).await,
        VolumeCommand::Rm(args) => remove(host, args, streams).await,
        VolumeCommand::Prune(args) => prune(host, args, streams).await,
    }
}

/// `satl volume inspect NAME...` — the daemon's raw document, in
/// `satl inspect`'s array, with its multi-argument semantics: a missing
/// volume is reported on stderr and makes the command exit 1, and the ones
/// that were found are still printed.
async fn inspect(host: &Host, args: &InspectArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut found: Vec<serde_json::Value> = Vec::new();
    let mut failed = false;
    for volume in &args.volumes {
        let path = format!("/volumes/{volume}");
        match client::get_json::<serde_json::Value>(host, &path).await {
            Ok(value) => found.push(value),
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    streams.outln(&crate::cmd::inspect::render(&found)).await;
    Ok(if failed { FAILURE } else { 0 })
}

/// `satl volume prune [-f]`. Node-local, so the summary names the node
/// (api-compat #130).
async fn prune(host: &Host, args: &PruneArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let node = system::node_name(host).await;
    if !args.force {
        streams.out(prune_warning(node.as_deref()).as_bytes()).await;
        if !system::confirmed().await {
            streams.outln("Total reclaimed space: 0B").await;
            return Ok(0);
        }
    }
    let pruned: VolumesPruneResponse = client::post_empty_json(host, "/volumes/prune").await?;
    streams
        .out(render_prune(&pruned, node.as_deref()).as_bytes())
        .await;
    Ok(0)
}

/// The confirmation text of `satl volume prune`, naming the node it acts on.
#[must_use]
pub fn prune_warning(node: Option<&str>) -> String {
    format!(
        "WARNING! This will remove all volumes not used by at least one container.\n\
         Volumes live on {} ONLY: run this on every node to reclaim the cluster.\n\
         Are you sure you want to continue? [y/N] ",
        node.unwrap_or("this node")
    )
}

/// Docker's `volume prune` summary plus the node-local statement (pure).
#[must_use]
pub fn render_prune(pruned: &VolumesPruneResponse, node: Option<&str>) -> String {
    let mut text = String::new();
    if !pruned.volumes_deleted.is_empty() {
        text.push_str("Deleted Volumes:\n");
        for name in &pruned.volumes_deleted {
            text.push_str(name);
            text.push('\n');
        }
    }
    text.push('\n');
    text.push_str(&system::reclaimed_line(pruned.space_reclaimed, node));
    text
}

fn create_body(args: &CreateArgs) -> anyhow::Result<CreateVolumeBody> {
    let mut labels = BTreeMap::new();
    for label in &args.label {
        let (key, value) = parse::parse_label(label)?;
        labels.insert(key, value);
    }
    Ok(CreateVolumeBody {
        name: args.name.clone().unwrap_or_default(),
        driver: args.driver.clone().unwrap_or_default(),
        labels,
    })
}

async fn remove(host: &Host, args: &RmArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let query = client::query(&[("force", if args.force { "true" } else { "false" })]);
    let mut failed = false;
    for volume in &args.volumes {
        let path = format!("/volumes/{volume}{query}");
        match client::delete_ok(host, &path).await {
            Ok(()) => streams.outln(volume).await,
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    Ok(if failed { FAILURE } else { 0 })
}

/// Render `volume ls` (pure, for goldens).
pub fn render(volumes: &[Volume], args: &LsArgs) -> String {
    if args.quiet {
        let mut out = String::new();
        for volume in volumes {
            out.push_str(&volume.name);
            out.push('\n');
        }
        return out;
    }
    let mut table = Table::new(&["DRIVER", "VOLUME NAME"]);
    for volume in volumes {
        table.push(vec![volume.driver.clone(), volume.name.clone()]);
    }
    table.render()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Volume> {
        vec![
            Volume {
                name: "web-data".to_owned(),
                driver: "local".to_owned(),
            },
            Volume {
                name: "8f2a1c0e9b".to_owned(),
                driver: "local".to_owned(),
            },
        ]
    }

    #[test]
    fn ls_golden() {
        let expected = "\
DRIVER   VOLUME NAME
local    web-data
local    8f2a1c0e9b
";
        assert_eq!(render(&sample(), &LsArgs::default()), expected);
    }

    #[test]
    fn ls_quiet_prints_names() {
        let args = LsArgs { quiet: true };
        assert_eq!(render(&sample(), &args), "web-data\n8f2a1c0e9b\n");
    }

    #[test]
    fn create_body_carries_name_driver_and_labels() {
        let args = CreateArgs {
            driver: Some("local".to_owned()),
            label: vec!["role=web".to_owned(), "marker".to_owned()],
            name: Some("web-data".to_owned()),
        };
        let body = create_body(&args).unwrap();
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"Name":"web-data","Driver":"local","Labels":{"marker":"","role":"web"}}"#
        );
    }

    #[test]
    fn create_body_without_options_is_empty() {
        let body = create_body(&CreateArgs::default()).unwrap();
        assert_eq!(serde_json::to_string(&body).unwrap(), "{}");
    }

    #[tokio::test]
    async fn ls_create_and_rm_over_the_socket() {
        use crate::output::testing;
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/volumes",
            Reply::json(
                200,
                r#"{"Volumes":[{"Name":"web-data","Driver":"local","Mountpoint":"/zroot/satl/volumes/web-data"}]}"#,
            ),
        )
        .on(
            "POST",
            "/volumes/create",
            Reply::json(201, r#"{"Name":"web-data","Driver":"local"}"#),
        )
        .on("DELETE", "/volumes/web-data", Reply::empty(204));

        let (mut streams, out, _err) = testing::streams();
        execute(
            &stub.host(),
            &VolumeCommand::Ls(LsArgs::default()),
            &mut streams,
        )
        .await
        .unwrap();
        assert_eq!(out.contents(), "DRIVER   VOLUME NAME\nlocal    web-data\n");

        let (mut streams, out, _err) = testing::streams();
        let create = VolumeCommand::Create(CreateArgs {
            name: Some("web-data".to_owned()),
            ..CreateArgs::default()
        });
        execute(&stub.host(), &create, &mut streams).await.unwrap();
        assert_eq!(out.contents(), "web-data\n");

        let (mut streams, out, _err) = testing::streams();
        let remove = VolumeCommand::Rm(RmArgs {
            force: true,
            volumes: vec!["web-data".to_owned()],
        });
        assert_eq!(
            execute(&stub.host(), &remove, &mut streams).await.unwrap(),
            0
        );
        assert_eq!(out.contents(), "web-data\n");
        assert_eq!(
            stub.first_call("DELETE /volumes/web-data").unwrap().query,
            "force=true"
        );
    }

    #[tokio::test]
    async fn rm_reports_a_volume_in_use() {
        use crate::output::testing;
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on(
            "DELETE",
            "/volumes/web-data",
            Reply::json(409, r#"{"message":"volume is in use"}"#),
        );
        let (mut streams, out, err) = testing::streams();
        let remove = VolumeCommand::Rm(RmArgs {
            force: false,
            volumes: vec!["web-data".to_owned()],
        });
        let code = execute(&stub.host(), &remove, &mut streams).await.unwrap();
        assert_eq!(code, FAILURE);
        assert!(out.contents().is_empty());
        assert_eq!(
            err.contents(),
            "Error response from daemon: volume is in use\n"
        );
    }

    #[tokio::test]
    async fn inspect_prints_the_found_documents_and_reports_the_missing_ones() {
        use crate::output::testing;
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/volumes/web-data",
            Reply::json(
                200,
                r#"{"Name":"web-data","Driver":"local","Mountpoint":"/zroot/satl/volumes/web-data"}"#,
            ),
        )
        .on(
            "GET",
            "/volumes/ghost",
            Reply::json(404, r#"{"message":"no such volume: ghost"}"#),
        );

        let (mut streams, out, err) = testing::streams();
        let command = VolumeCommand::Inspect(InspectArgs {
            volumes: vec!["web-data".to_owned(), "ghost".to_owned()],
        });
        let code = execute(&stub.host(), &command, &mut streams).await.unwrap();

        assert_eq!(code, FAILURE);
        assert_eq!(
            err.contents(),
            "Error response from daemon: no such volume: ghost\n"
        );
        // `cmd::inspect::render`'s exact shape: one array, four-space indent.
        assert_eq!(
            out.contents(),
            "[\n    {\n        \"Driver\": \"local\",\n        \"Mountpoint\": \
             \"/zroot/satl/volumes/web-data\",\n        \"Name\": \"web-data\"\n    }\n]\n"
        );
        assert_eq!(
            stub.routes(),
            vec!["GET /volumes/web-data", "GET /volumes/ghost"]
        );
    }

    fn pruned(raw: &str) -> VolumesPruneResponse {
        serde_json::from_str(raw).expect("fixture parses")
    }

    #[test]
    fn prune_summary_golden() {
        assert_eq!(
            render_prune(
                &pruned(r#"{"VolumesDeleted":["web-data","scratch"],"SpaceReclaimed":62337024}"#),
                Some("alpha")
            ),
            "Deleted Volumes:\n\
             web-data\n\
             scratch\n\
             \n\
             Total reclaimed space: 62.34MB (on alpha; images, layers and volumes are \
             node-local)\n"
        );
    }

    #[test]
    fn a_prune_that_freed_nothing_still_names_the_node() {
        assert_eq!(
            render_prune(&pruned("{}"), None),
            "\nTotal reclaimed space: 0B (on this node; images, layers and volumes are \
             node-local)\n"
        );
    }

    #[test]
    fn the_prune_prompt_names_the_node_it_acts_on() {
        let text = prune_warning(Some("alpha"));
        assert!(
            text.contains("all volumes not used by at least one container"),
            "{text}"
        );
        assert!(text.contains("Volumes live on alpha ONLY"), "{text}");
        assert!(
            text.ends_with("Are you sure you want to continue? [y/N] "),
            "{text}"
        );
        assert!(text.is_ascii(), "operator text must be ASCII");
        assert!(prune_warning(None).contains("live on this node ONLY"));
    }

    #[tokio::test]
    async fn prune_with_force_reads_the_node_name_then_prunes() {
        use crate::output::testing;
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on("GET", "/info", Reply::json(200, r#"{"Name":"alpha"}"#))
            .on(
                "POST",
                "/volumes/prune",
                Reply::json(
                    200,
                    r#"{"VolumesDeleted":["scratch"],"SpaceReclaimed":2048}"#,
                ),
            );

        let (mut streams, out, _err) = testing::streams();
        let command = VolumeCommand::Prune(PruneArgs { force: true });
        let code = execute(&stub.host(), &command, &mut streams).await.unwrap();
        assert_eq!(code, 0);
        assert_eq!(stub.routes(), vec!["GET /info", "POST /volumes/prune"]);
        assert_eq!(
            out.contents(),
            "Deleted Volumes:\nscratch\n\nTotal reclaimed space: 2.048kB (on alpha; images, \
             layers and volumes are node-local)\n"
        );
    }

    #[tokio::test]
    async fn prune_surfaces_a_daemon_error() {
        use crate::output::testing;
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on("GET", "/info", Reply::json(200, r#"{"Name":"alpha"}"#))
            .on(
                "POST",
                "/volumes/prune",
                Reply::json(
                    500,
                    r#"{"message":"cannot unmount /zroot/satl/volumes/web-data"}"#,
                ),
            );

        let (mut streams, out, _err) = testing::streams();
        let command = VolumeCommand::Prune(PruneArgs { force: true });
        let err = execute(&stub.host(), &command, &mut streams)
            .await
            .expect_err("a 500 is an error");
        assert_eq!(
            err.to_string(),
            "Error response from daemon: cannot unmount /zroot/satl/volumes/web-data"
        );
        assert!(out.contents().is_empty());
    }
}
