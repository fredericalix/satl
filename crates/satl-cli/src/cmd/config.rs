// SPDX-License-Identifier: BSD-2-Clause
//! `satl config create|ls|inspect|rm`.
//!
//! The twin of [`crate::cmd::secret`], with two differences that are docker's:
//! the payload cap is 1000 KiB rather than 500, and `config ls` has no `DRIVER`
//! column. A config is not a secret — `config inspect` does return `Data` — so
//! the passthrough prints whatever the daemon sent, and nothing else here reads
//! it.

use std::collections::BTreeMap;

use base64::Engine as _;
use tokio::io::AsyncReadExt as _;

use crate::api::cluster::{Config, ConfigSpec, IdResponse};
use crate::client::{self, Host};
use crate::cmd::FAILURE;
use crate::format::{self, Table};
use crate::output::Streams;
use crate::parse;

/// Largest payload `satl config create` will send (docker's 1000 KiB cap).
const MAX_DATA_BYTES: usize = 1000 * 1024 - 1;

/// Subcommands of `satl config`.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum ConfigCommand {
    /// Create a config from a file or STDIN.
    Create(CreateArgs),
    /// List configs.
    Ls(LsArgs),
    /// Display detailed information on one or more configs.
    Inspect(InspectArgs),
    /// Remove one or more configs.
    Rm(RmArgs),
}

/// Flags of `satl config create`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct CreateArgs {
    /// Config labels.
    #[arg(short, long, value_name = "KEY=VALUE")]
    pub label: Vec<String>,

    /// Config name.
    #[arg(value_name = "CONFIG")]
    pub name: String,

    /// File holding the config, or - to read STDIN.
    #[arg(value_name = "FILE")]
    pub file: String,
}

/// Flags of `satl config ls`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct LsArgs {
    /// Only display IDs.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Flags of `satl config inspect`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct InspectArgs {
    /// Configs to inspect.
    #[arg(required = true, value_name = "CONFIG")]
    pub configs: Vec<String>,
}

/// Flags of `satl config rm`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RmArgs {
    /// Configs to remove.
    #[arg(required = true, value_name = "CONFIG")]
    pub configs: Vec<String>,
}

/// Dispatch a `satl config` subcommand.
pub async fn execute(
    host: &Host,
    command: &ConfigCommand,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    match command {
        ConfigCommand::Create(args) => create(host, args, streams).await,
        ConfigCommand::Ls(args) => {
            let configs: Vec<Config> = client::get_json(host, "/configs").await?;
            streams
                .out(render(&configs, args, format::now_unix()).as_bytes())
                .await;
            Ok(0)
        }
        ConfigCommand::Inspect(args) => inspect(host, args, streams).await,
        ConfigCommand::Rm(args) => remove(host, args, streams).await,
    }
}

async fn create(host: &Host, args: &CreateArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let data = read_payload(&args.file).await?;
    let body = create_body(args, &data)?;
    let created: IdResponse = client::post_json(host, "/configs/create", Some(&body)).await?;
    let id = if created.id.is_empty() {
        body.name.clone()
    } else {
        created.id
    };
    streams.outln(&id).await;
    Ok(0)
}

/// Read the payload from a path, or from STDIN for `-`.
async fn read_payload(path: &str) -> anyhow::Result<Vec<u8>> {
    if path == "-" {
        let mut payload = Vec::new();
        tokio::io::stdin()
            .read_to_end(&mut payload)
            .await
            .map_err(|err| anyhow::anyhow!("could not read the config from stdin: {err}"))?;
        return Ok(payload);
    }
    std::fs::read(path).map_err(|err| anyhow::anyhow!("could not read {path}: {err}"))
}

/// Build the `POST /configs/create` body (pure, for goldens). The size is
/// checked before encoding.
pub fn create_body(args: &CreateArgs, data: &[u8]) -> anyhow::Result<ConfigSpec> {
    if data.len() > MAX_DATA_BYTES {
        anyhow::bail!("config data is {} bytes; the limit is 1000 KiB", data.len());
    }
    let mut labels = BTreeMap::new();
    for label in &args.label {
        let (key, value) = parse::parse_label(label)?;
        labels.insert(key, value);
    }
    Ok(ConfigSpec {
        name: args.name.clone(),
        labels,
        data: base64::engine::general_purpose::STANDARD.encode(data),
    })
}

/// Render `config ls` (pure: the clock is injected so goldens are stable). IDs
/// are printed whole, as docker does for cluster objects of this kind.
pub fn render(configs: &[Config], args: &LsArgs, now_unix: i64) -> String {
    if args.quiet {
        let mut out = String::new();
        for config in configs {
            out.push_str(&config.id);
            out.push('\n');
        }
        return out;
    }
    let mut table = Table::new(&["ID", "NAME", "CREATED", "UPDATED"]);
    for config in configs {
        table.push(vec![
            config.id.clone(),
            config.spec.name.clone(),
            format::timestamp_cell(&config.created_at, now_unix),
            format::timestamp_cell(&config.updated_at, now_unix),
        ]);
    }
    table.render()
}

async fn inspect(host: &Host, args: &InspectArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut found: Vec<serde_json::Value> = Vec::new();
    let mut failed = false;
    for config in &args.configs {
        let path = format!("/configs/{config}");
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

async fn remove(host: &Host, args: &RmArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut failed = false;
    for config in &args.configs {
        let path = format!("/configs/{config}");
        match client::delete_ok(host, &path).await {
            Ok(()) => streams.outln(config).await,
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    Ok(if failed { FAILURE } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;
    use crate::stub::{Reply, Stub};

    const NOW: i64 = 1_770_000_600;
    const CONFIG_ID: &str = "6hvy0lj3x0b883f8e30fyp222";

    fn config_json() -> String {
        format!(
            r#"{{"ID":"{CONFIG_ID}","Version":{{"Index":2}},
              "CreatedAt":"2026-02-02T02:40:00Z","UpdatedAt":"2026-02-02T02:45:00Z",
              "Spec":{{"Name":"nginx-conf","Labels":null,"Data":"c2VydmVyIHt9Cg=="}}}}"#
        )
    }

    fn sample() -> Vec<Config> {
        vec![serde_json::from_str(&config_json()).expect("fixture parses")]
    }

    #[test]
    fn create_body_encodes_the_payload_and_the_labels() {
        let args = CreateArgs {
            label: vec!["role=web".to_owned()],
            name: "nginx-conf".to_owned(),
            file: "-".to_owned(),
        };
        let body = create_body(&args, b"server {}\n").expect("valid");
        assert_eq!(
            serde_json::to_string(&body).expect("serializable"),
            r#"{"Name":"nginx-conf","Labels":{"role":"web"},"Data":"c2VydmVyIHt9Cg=="}"#
        );
    }

    #[test]
    fn an_oversized_payload_is_refused_before_it_is_encoded() {
        let args = CreateArgs {
            name: "big".to_owned(),
            file: "/tmp/big".to_owned(),
            ..CreateArgs::default()
        };
        let too_big = vec![0u8; MAX_DATA_BYTES + 1];
        let err = create_body(&args, &too_big).expect_err("over the cap");
        assert_eq!(
            err.to_string(),
            "config data is 1024000 bytes; the limit is 1000 KiB"
        );
        assert!(create_body(&args, &too_big[1..]).is_ok());
    }

    #[test]
    fn ls_golden_has_no_driver_column() {
        let rendered = render(&sample(), &LsArgs::default(), NOW);
        assert!(!rendered.contains("DRIVER"), "{rendered}");
        assert_eq!(
            rendered,
            format!(
                "\
ID                          NAME         CREATED          UPDATED
{CONFIG_ID}   nginx-conf   10 minutes ago   5 minutes ago
"
            )
        );
    }

    #[test]
    fn ls_quiet_prints_whole_ids() {
        let args = LsArgs { quiet: true };
        assert_eq!(render(&sample(), &args, NOW), format!("{CONFIG_ID}\n"));
    }

    #[tokio::test]
    async fn create_posts_the_encoded_payload_and_prints_the_id() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/configs/create",
            Reply::json(201, &format!(r#"{{"ID":"{CONFIG_ID}"}}"#)),
        );
        let (mut streams, out, _err) = testing::streams();

        let file = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(file.path(), b"server {}\n").expect("write the payload");
        let args = CreateArgs {
            name: "nginx-conf".to_owned(),
            file: file.path().display().to_string(),
            ..CreateArgs::default()
        };
        execute(&stub.host(), &ConfigCommand::Create(args), &mut streams)
            .await
            .expect("create succeeds");

        assert_eq!(out.contents(), format!("{CONFIG_ID}\n"));
        assert_eq!(
            stub.first_call("POST /configs/create")
                .expect("create")
                .body,
            r#"{"Name":"nginx-conf","Data":"c2VydmVyIHt9Cg=="}"#
        );
    }

    #[tokio::test]
    async fn ls_inspect_and_rm_over_the_socket() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/configs",
            Reply::json(200, &format!("[{}]", config_json())),
        )
        .on(
            "GET",
            "/configs/nginx-conf",
            Reply::json(200, &config_json()),
        )
        .on("DELETE", "/configs/nginx-conf", Reply::empty(204));

        let (mut streams, out, _err) = testing::streams();
        execute(
            &stub.host(),
            &ConfigCommand::Ls(LsArgs::default()),
            &mut streams,
        )
        .await
        .expect("ls succeeds");
        assert!(out.contents().contains("nginx-conf"), "{}", out.contents());

        // The passthrough is the daemon's document, `Data` included: a config is
        // not a secret.
        let (mut streams, out, _err) = testing::streams();
        let args = InspectArgs {
            configs: vec!["nginx-conf".to_owned()],
        };
        execute(&stub.host(), &ConfigCommand::Inspect(args), &mut streams)
            .await
            .expect("inspect succeeds");
        let printed = out.contents();
        assert!(printed.starts_with("[\n    {\n"), "{printed}");
        assert!(
            printed.contains("\"Data\": \"c2VydmVyIHt9Cg==\""),
            "{printed}"
        );

        let (mut streams, out, _err) = testing::streams();
        let args = RmArgs {
            configs: vec!["nginx-conf".to_owned()],
        };
        assert_eq!(
            execute(&stub.host(), &ConfigCommand::Rm(args), &mut streams)
                .await
                .expect("rm returns an exit code"),
            0
        );
        assert_eq!(out.contents(), "nginx-conf\n");
    }

    #[tokio::test]
    async fn rm_reports_a_missing_config_and_exits_1() {
        let stub = Stub::start().await;
        stub.on(
            "DELETE",
            "/configs/ghost",
            Reply::json(404, r#"{"message":"config ghost not found"}"#),
        );
        let (mut streams, out, err) = testing::streams();
        let args = RmArgs {
            configs: vec!["ghost".to_owned()],
        };
        let code = execute(&stub.host(), &ConfigCommand::Rm(args), &mut streams)
            .await
            .expect("rm returns an exit code");
        assert_eq!(code, FAILURE);
        assert!(out.contents().is_empty());
        assert_eq!(
            err.contents(),
            "Error response from daemon: config ghost not found\n"
        );
    }
}
