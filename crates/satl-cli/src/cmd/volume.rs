// SPDX-License-Identifier: BSD-2-Clause
//! `satl volume ls|create|rm`.

use std::collections::BTreeMap;

use crate::api::{CreateVolumeBody, Volume, VolumeListResponse};
use crate::client::{self, Host};
use crate::cmd::FAILURE;
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
    /// Remove one or more volumes.
    Rm(RmArgs),
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
        VolumeCommand::Rm(args) => remove(host, args, streams).await,
    }
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
}
