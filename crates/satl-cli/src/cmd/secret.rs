// SPDX-License-Identifier: BSD-2-Clause
//! `satl secret create|ls|inspect|rm`.
//!
//! The payload is the one thing this module never shows. It is read from a file
//! (or stdin), base64-encoded and posted; nothing prints it, no error quotes it,
//! and the daemon never sends it back (invariant 7: secrets reach a jail through
//! tmpfs and nowhere else). Errors name the secret or the path instead.

use std::collections::BTreeMap;

use base64::Engine as _;
use tokio::io::AsyncReadExt as _;

use crate::api::cluster::{IdResponse, Secret, SecretSpec};
use crate::client::{self, Host};
use crate::cmd::FAILURE;
use crate::format::{self, Table};
use crate::output::Streams;
use crate::parse;

/// Largest payload `satl secret create` will send. The daemon enforces the same
/// cap; refusing it here means half a megabyte is not encoded and shipped only
/// to be turned away.
const MAX_DATA_BYTES: usize = 500 * 1024 - 1;

/// Subcommands of `satl secret`.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum SecretCommand {
    /// Create a secret from a file or STDIN.
    Create(CreateArgs),
    /// List secrets.
    Ls(LsArgs),
    /// Display detailed information on one or more secrets.
    Inspect(InspectArgs),
    /// Remove one or more secrets.
    Rm(RmArgs),
}

/// Flags of `satl secret create`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct CreateArgs {
    /// Secret labels.
    #[arg(short, long, value_name = "KEY=VALUE")]
    pub label: Vec<String>,

    /// Secret name.
    #[arg(value_name = "SECRET")]
    pub name: String,

    /// File holding the secret, or - to read STDIN.
    #[arg(value_name = "FILE")]
    pub file: String,
}

/// Flags of `satl secret ls`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct LsArgs {
    /// Only display IDs.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Flags of `satl secret inspect`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct InspectArgs {
    /// Secrets to inspect.
    #[arg(required = true, value_name = "SECRET")]
    pub secrets: Vec<String>,
}

/// Flags of `satl secret rm`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RmArgs {
    /// Secrets to remove.
    #[arg(required = true, value_name = "SECRET")]
    pub secrets: Vec<String>,
}

/// Dispatch a `satl secret` subcommand.
pub async fn execute(
    host: &Host,
    command: &SecretCommand,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    match command {
        SecretCommand::Create(args) => create(host, args, streams).await,
        SecretCommand::Ls(args) => {
            let secrets: Vec<Secret> = client::get_json(host, "/secrets").await?;
            streams
                .out(render(&secrets, args, format::now_unix()).as_bytes())
                .await;
            Ok(0)
        }
        SecretCommand::Inspect(args) => inspect(host, args, streams).await,
        SecretCommand::Rm(args) => remove(host, args, streams).await,
    }
}

async fn create(host: &Host, args: &CreateArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let data = read_payload(&args.file).await?;
    let body = create_body(args, &data)?;
    let created: IdResponse = client::post_json(host, "/secrets/create", Some(&body)).await?;
    // Docker prints the ID of the object it created; fall back to the name if a
    // daemon answers without one.
    let id = if created.id.is_empty() {
        body.name.clone()
    } else {
        created.id
    };
    streams.outln(&id).await;
    Ok(0)
}

/// Read the payload from a path, or from STDIN for `-`. The bytes are returned
/// and never rendered; a failure names the path, not the contents.
async fn read_payload(path: &str) -> anyhow::Result<Vec<u8>> {
    if path == "-" {
        let mut payload = Vec::new();
        tokio::io::stdin()
            .read_to_end(&mut payload)
            .await
            .map_err(|err| anyhow::anyhow!("could not read the secret from stdin: {err}"))?;
        return Ok(payload);
    }
    std::fs::read(path).map_err(|err| anyhow::anyhow!("could not read {path}: {err}"))
}

/// Build the `POST /secrets/create` body (pure, for goldens). The size is
/// checked *before* encoding, so an oversized payload never grows by a third
/// only to be rejected.
pub fn create_body(args: &CreateArgs, data: &[u8]) -> anyhow::Result<SecretSpec> {
    if data.len() > MAX_DATA_BYTES {
        anyhow::bail!("secret data is {} bytes; the limit is 500 KiB", data.len());
    }
    let mut labels = BTreeMap::new();
    for label in &args.label {
        let (key, value) = parse::parse_label(label)?;
        labels.insert(key, value);
    }
    Ok(SecretSpec {
        name: args.name.clone(),
        labels,
        data: base64::engine::general_purpose::STANDARD.encode(data),
    })
}

/// Render `secret ls` (pure: the clock is injected so goldens are stable).
///
/// IDs are not truncated: docker prints a secret's full ID here, and a 25-char
/// cluster ID is what `--secret` and `service inspect` show too.
pub fn render(secrets: &[Secret], args: &LsArgs, now_unix: i64) -> String {
    if args.quiet {
        let mut out = String::new();
        for secret in secrets {
            out.push_str(&secret.id);
            out.push('\n');
        }
        return out;
    }
    let mut table = Table::new(&["ID", "NAME", "DRIVER", "CREATED", "UPDATED"]);
    for secret in secrets {
        table.push(vec![
            secret.id.clone(),
            secret.spec.name.clone(),
            // Docker prints the column for external secret drivers; SatL has
            // none, so it is always blank — as it is for docker's own secrets.
            String::new(),
            format::timestamp_cell(&secret.created_at, now_unix),
            format::timestamp_cell(&secret.updated_at, now_unix),
        ]);
    }
    table.render()
}

async fn inspect(host: &Host, args: &InspectArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut found: Vec<serde_json::Value> = Vec::new();
    let mut failed = false;
    for secret in &args.secrets {
        let path = format!("/secrets/{secret}");
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
    for secret in &args.secrets {
        let path = format!("/secrets/{secret}");
        match client::delete_ok(host, &path).await {
            Ok(()) => streams.outln(secret).await,
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
    const SECRET_ID: &str = "5hvy0lj3x0b883f8e30fyp221";

    fn secret_json() -> String {
        format!(
            r#"{{"ID":"{SECRET_ID}","Version":{{"Index":3}},
              "CreatedAt":"2026-02-02T02:40:00Z","UpdatedAt":"2026-02-02T02:45:00Z",
              "Spec":{{"Name":"site-cert","Labels":{{"env":"prod"}}}}}}"#
        )
    }

    fn sample() -> Vec<Secret> {
        vec![serde_json::from_str(&secret_json()).expect("fixture parses")]
    }

    #[test]
    fn create_body_encodes_the_payload_and_the_labels() {
        let args = CreateArgs {
            label: vec!["env=prod".to_owned(), "marker".to_owned()],
            name: "site-cert".to_owned(),
            file: "-".to_owned(),
        };
        let body = create_body(&args, b"hunter2\n").expect("valid");
        assert_eq!(
            serde_json::to_string(&body).expect("serializable"),
            r#"{"Name":"site-cert","Labels":{"env":"prod","marker":""},"Data":"aHVudGVyMgo="}"#
        );
    }

    /// Standard alphabet, padding included — the daemon decodes with
    /// `STANDARD`, and an unpadded payload would be rejected.
    #[test]
    fn the_payload_is_padded_standard_base64() {
        let args = CreateArgs {
            name: "s".to_owned(),
            file: "-".to_owned(),
            ..CreateArgs::default()
        };
        for (payload, encoded) in [
            (&b"a"[..], "YQ=="),
            (&b"ab"[..], "YWI="),
            (&b"abc"[..], "YWJj"),
            (&b""[..], ""),
            // Bytes that are not text, and the two characters that separate the
            // standard alphabet from base64url.
            (&[0xff, 0xef, 0xbe][..], "/+++"),
        ] {
            let body = create_body(&args, payload).expect("valid");
            assert_eq!(body.data, encoded, "{payload:?}");
        }
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
            "secret data is 512000 bytes; the limit is 500 KiB"
        );
        // One byte less is accepted.
        assert!(create_body(&args, &too_big[1..]).is_ok());
    }

    #[test]
    fn ls_golden() {
        let expected = format!(
            "\
ID                          NAME        DRIVER   CREATED          UPDATED
{SECRET_ID}   site-cert            10 minutes ago   5 minutes ago
"
        );
        assert_eq!(render(&sample(), &LsArgs::default(), NOW), expected);
    }

    #[test]
    fn ls_quiet_prints_whole_ids() {
        let args = LsArgs { quiet: true };
        assert_eq!(render(&sample(), &args, NOW), format!("{SECRET_ID}\n"));
        let empty = render(&[], &LsArgs::default(), NOW);
        assert_eq!(empty.lines().count(), 1);
        assert!(empty.starts_with("ID "));
    }

    #[test]
    fn ls_without_timestamps_leaves_the_columns_blank() {
        let mut secrets = sample();
        secrets[0].created_at = String::new();
        secrets[0].updated_at = String::new();
        let rendered = render(&secrets, &LsArgs::default(), NOW);
        assert!(rendered.contains("site-cert"), "{rendered}");
        assert!(!rendered.contains("ago"), "{rendered}");
    }

    #[tokio::test]
    async fn create_posts_the_encoded_payload_and_prints_the_id() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/secrets/create",
            Reply::json(201, &format!(r#"{{"Id":"{SECRET_ID}"}}"#)),
        );
        let (mut streams, out, err) = testing::streams();

        let file = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(file.path(), b"hunter2\n").expect("write the payload");
        let args = CreateArgs {
            label: vec!["env=prod".to_owned()],
            name: "site-cert".to_owned(),
            file: file.path().display().to_string(),
        };
        let code = execute(&stub.host(), &SecretCommand::Create(args), &mut streams)
            .await
            .expect("create succeeds");

        assert_eq!(code, 0);
        assert_eq!(out.contents(), format!("{SECRET_ID}\n"));
        assert!(err.contents().is_empty());
        let call = stub.first_call("POST /secrets/create").expect("create");
        assert_eq!(
            call.body,
            r#"{"Name":"site-cert","Labels":{"env":"prod"},"Data":"aHVudGVyMgo="}"#
        );
    }

    #[tokio::test]
    async fn create_from_a_missing_file_names_the_path_and_never_calls_the_daemon() {
        let stub = Stub::start().await;
        let (mut streams, out, _err) = testing::streams();
        let args = CreateArgs {
            name: "site-cert".to_owned(),
            file: "/nonexistent/site.pem".to_owned(),
            ..CreateArgs::default()
        };
        let err = execute(&stub.host(), &SecretCommand::Create(args), &mut streams)
            .await
            .expect_err("the file is not there");
        assert!(
            err.to_string()
                .starts_with("could not read /nonexistent/site.pem: "),
            "{err}"
        );
        assert!(out.contents().is_empty());
        assert!(stub.calls().is_empty(), "nothing was sent");
    }

    #[tokio::test]
    async fn ls_inspect_and_rm_over_the_socket() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/secrets",
            Reply::json(200, &format!("[{}]", secret_json())),
        )
        .on(
            "GET",
            "/secrets/site-cert",
            Reply::json(200, &secret_json()),
        )
        .on("DELETE", "/secrets/site-cert", Reply::empty(204));

        let (mut streams, out, _err) = testing::streams();
        execute(
            &stub.host(),
            &SecretCommand::Ls(LsArgs::default()),
            &mut streams,
        )
        .await
        .expect("ls succeeds");
        assert!(out.contents().contains("site-cert"), "{}", out.contents());
        assert!(out.contents().contains(SECRET_ID), "{}", out.contents());

        // Inspect prints the daemon's document verbatim — and the daemon's
        // document has no `Data` key, which is why nothing here can leak one.
        let (mut streams, out, _err) = testing::streams();
        let args = InspectArgs {
            secrets: vec!["site-cert".to_owned()],
        };
        execute(&stub.host(), &SecretCommand::Inspect(args), &mut streams)
            .await
            .expect("inspect succeeds");
        let printed = out.contents();
        assert!(printed.starts_with("[\n    {\n"), "{printed}");
        assert!(
            printed.contains(&format!("\"ID\": \"{SECRET_ID}\"")),
            "{printed}"
        );
        assert!(printed.contains("\"Name\": \"site-cert\""), "{printed}");
        assert!(!printed.contains("Data"), "{printed}");

        let (mut streams, out, _err) = testing::streams();
        let args = RmArgs {
            secrets: vec!["site-cert".to_owned()],
        };
        assert_eq!(
            execute(&stub.host(), &SecretCommand::Rm(args), &mut streams)
                .await
                .expect("rm returns an exit code"),
            0
        );
        assert_eq!(out.contents(), "site-cert\n");
    }

    #[tokio::test]
    async fn inspect_and_rm_report_a_missing_secret_and_exit_1() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/secrets/ghost",
            Reply::json(404, r#"{"message":"secret ghost not found"}"#),
        )
        .on(
            "DELETE",
            "/secrets/ghost",
            Reply::json(404, r#"{"message":"secret ghost not found"}"#),
        );

        let (mut streams, out, err) = testing::streams();
        let args = InspectArgs {
            secrets: vec!["ghost".to_owned()],
        };
        let code = execute(&stub.host(), &SecretCommand::Inspect(args), &mut streams)
            .await
            .expect("inspect returns an exit code");
        assert_eq!(code, FAILURE);
        assert_eq!(out.contents(), "[]\n");
        assert_eq!(
            err.contents(),
            "Error response from daemon: secret ghost not found\n"
        );

        let (mut streams, out, err) = testing::streams();
        let args = RmArgs {
            secrets: vec!["ghost".to_owned()],
        };
        let code = execute(&stub.host(), &SecretCommand::Rm(args), &mut streams)
            .await
            .expect("rm returns an exit code");
        assert_eq!(code, FAILURE);
        assert!(out.contents().is_empty());
        assert_eq!(
            err.contents(),
            "Error response from daemon: secret ghost not found\n"
        );
    }
}
