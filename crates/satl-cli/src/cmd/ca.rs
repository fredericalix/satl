// SPDX-License-Identifier: BSD-2-Clause
//! `satl ca [rotate]` — view and rotate the cluster root CA.
//!
//! Mirrors `docker swarm ca` (moved to a top-level verb, `--rotate` kept as
//! an alias of the `rotate` subcommand): bare `satl ca` prints the root CA
//! certificate, `satl ca rotate` starts a root rotation through Docker's own
//! surface for it — `POST /swarm/update` with `Spec.CAConfig.ForceRotate`
//! incremented — then waits for the cluster to converge, exactly as the
//! docker CLI does.
//!
//! The wait reads `GET /swarm`: `RootRotationInProgress` goes true while the
//! transitional two-root bundle is in force and every node is re-issued, and
//! flips back once the old root is dropped. Convergence can take a while on
//! a cluster with offline nodes — a node that never comes back holds the
//! rotation open until it is removed (`satl node rm --force`), which is
//! exactly what the progress line says.

use crate::api::cluster::Swarm;
use crate::client::{self, Host};
use crate::output::Streams;

/// How often the rotation wait polls `GET /swarm`.
const POLL: std::time::Duration = std::time::Duration::from_secs(2);

/// How often the wait reminds the operator it is still waiting (in polls).
const REMIND_EVERY: u32 = 15;

/// Flags of `satl ca`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct CaArgs {
    /// Rotate the cluster root CA (alias of `satl ca rotate`).
    #[arg(long)]
    pub rotate: bool,

    /// Exit immediately instead of waiting for the rotation to converge.
    #[arg(short, long)]
    pub detach: bool,

    /// Only print the root CA certificate.
    #[arg(short, long)]
    pub quiet: bool,

    /// The ca subcommand.
    #[command(subcommand)]
    pub command: Option<CaCommand>,
}

/// Subcommands of `satl ca`.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum CaCommand {
    /// Rotate the cluster root CA: mint a new root, cross-sign the
    /// transition, re-issue every node's certificate under the new root
    /// with no downtime, regenerate the join tokens, drop the old root.
    Rotate(RotateArgs),
}

/// Flags of `satl ca rotate`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RotateArgs {
    /// Exit immediately instead of waiting for the rotation to converge.
    #[arg(short, long)]
    pub detach: bool,

    /// Only print the new root CA certificate when the rotation completes.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Dispatch a `satl ca` invocation.
pub async fn execute(host: &Host, args: &CaArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    match (&args.command, args.rotate) {
        (Some(CaCommand::Rotate(rotate)), _) => rotate_ca(host, rotate, streams).await,
        (None, true) => {
            let rotate = RotateArgs {
                detach: args.detach,
                quiet: args.quiet,
            };
            rotate_ca(host, &rotate, streams).await
        }
        (None, false) => show_root(host, streams).await,
    }
}

/// `satl ca`: the current root CA certificate, PEM on stdout.
async fn show_root(host: &Host, streams: &mut Streams) -> anyhow::Result<u8> {
    let swarm: Swarm = client::get_json(host, "/swarm").await?;
    let root = swarm.tls_info.trust_root;
    anyhow::ensure!(
        !root.is_empty(),
        "the daemon reported no root CA certificate; is this node a swarm manager?"
    );
    streams.out(root.as_bytes()).await;
    Ok(0)
}

/// `satl ca rotate`: bump `CAConfig.ForceRotate` and wait for convergence.
async fn rotate_ca(host: &Host, args: &RotateArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let swarm: Swarm = client::get_json(host, "/swarm").await?;
    let old_root = swarm.tls_info.trust_root.clone();
    anyhow::ensure!(
        !old_root.is_empty(),
        "the daemon reported no root CA certificate; is this node a swarm manager?"
    );

    // Docker's read-modify-write: resend the spec with ForceRotate bumped.
    let mut spec = swarm.spec.clone();
    let current = spec
        .get("CAConfig")
        .and_then(|ca| ca.get("ForceRotate"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let wanted = current + 1;
    if !spec.is_object() {
        spec = serde_json::json!({});
    }
    let ca_config = spec
        .as_object_mut()
        .and_then(|spec| {
            spec.entry("CAConfig")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
        })
        .ok_or_else(|| anyhow::anyhow!("the swarm spec's CAConfig is not a JSON object"))?;
    ca_config.insert("ForceRotate".to_owned(), serde_json::json!(wanted));

    let version = swarm.version.index.to_string();
    let path = format!(
        "/swarm/update{}",
        client::query(&[("version", version.as_str())])
    );
    client::post_ok(host, &path, Some(&spec)).await?;

    if !args.quiet {
        streams
            .outln("Root CA rotation started: a new root was minted and cross-signed;")
            .await;
        streams
            .outln("every node's certificate is being re-issued under it, live.")
            .await;
    }
    if args.detach {
        return Ok(0);
    }

    // Wait for the transitional bundle to be gone again: rotation no longer
    // in progress, a single root in the bundle, and not the one we started
    // from. (The started rotation is observable immediately — the update
    // above committed — so a poll that still sees the old state is a
    // follower lagging, and reads as "not converged yet".)
    let mut polls: u32 = 0;
    let done = loop {
        let current: Swarm = client::get_json(host, "/swarm").await?;
        let root = &current.tls_info.trust_root;
        let roots = root.matches("BEGIN CERTIFICATE").count();
        if !current.root_rotation_in_progress && roots == 1 && *root != old_root {
            break current;
        }
        polls += 1;
        if !args.quiet && polls.is_multiple_of(REMIND_EVERY) {
            streams
                .outln(
                    "still rotating: waiting for every node to hold a certificate from the \
                     new root ('satl node ls'; a node that will never return holds the \
                     rotation open until 'satl node rm --force <node>')",
                )
                .await;
        }
        tokio::time::sleep(POLL).await;
    };

    if args.quiet {
        streams.out(done.tls_info.trust_root.as_bytes()).await;
        return Ok(0);
    }
    streams
        .outln("Root CA rotation complete: the old root is no longer trusted.")
        .await;
    streams
        .outln("Both join tokens were regenerated; print them with 'satl swarm join-token'.")
        .await;
    streams.out(done.tls_info.trust_root.as_bytes()).await;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;
    use crate::stub::{Reply, Stub};

    const OLD_PEM: &str = "-----BEGIN CERTIFICATE-----\\nold\\n-----END CERTIFICATE-----\\n";
    const NEW_PEM: &str = "-----BEGIN CERTIFICATE-----\\nnew\\n-----END CERTIFICATE-----\\n";

    fn swarm_json(trust_root: &str, rotating: bool, force_rotate: u64) -> String {
        format!(
            r#"{{"ID":"c1","Version":{{"Index":7}},
                "JoinTokens":{{"Worker":"SATL-1-w","Manager":"SATL-1-m"}},
                "TLSInfo":{{"TrustRoot":"{trust_root}"}},
                "RootRotationInProgress":{rotating},
                "Spec":{{"Name":"default","CAConfig":{{"ForceRotate":{force_rotate}}}}}}}"#
        )
    }

    #[tokio::test]
    async fn bare_ca_prints_the_trust_root() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/swarm",
            Reply::json(200, &swarm_json(OLD_PEM, false, 0)),
        );
        let (mut streams, out, _err) = testing::streams();
        let code = execute(&stub.host(), &CaArgs::default(), &mut streams)
            .await
            .expect("ca succeeds");
        assert_eq!(code, 0);
        assert_eq!(out.contents(), OLD_PEM.replace("\\n", "\n"));
    }

    #[tokio::test]
    async fn rotate_bumps_force_rotate_with_the_current_version() {
        let stub = Stub::start().await;
        // First GET: pre-rotation. After the update, the poll immediately
        // sees the completed state (new single root, not rotating).
        stub.on(
            "GET",
            "/swarm",
            Reply::json(200, &swarm_json(OLD_PEM, false, 3)),
        )
        .on(
            "GET",
            "/swarm",
            Reply::json(200, &swarm_json(NEW_PEM, false, 4)),
        )
        .on("POST", "/swarm/update", Reply::empty(200));

        let (mut streams, out, _err) = testing::streams();
        let args = CaArgs {
            command: Some(CaCommand::Rotate(RotateArgs::default())),
            ..CaArgs::default()
        };
        let code = execute(&stub.host(), &args, &mut streams)
            .await
            .expect("rotate succeeds");
        assert_eq!(code, 0);

        let call = stub.first_call("POST /swarm/update").expect("update call");
        assert_eq!(call.query, "version=7");
        assert!(
            call.body.contains(r#""ForceRotate":4"#),
            "the spec must carry the bumped counter: {}",
            call.body
        );
        let printed = out.contents();
        assert!(printed.contains("rotation started"), "{printed}");
        assert!(printed.contains("rotation complete"), "{printed}");
        assert!(
            printed.contains("join tokens were regenerated"),
            "{printed}"
        );
        assert!(
            printed.ends_with(&NEW_PEM.replace("\\n", "\n")),
            "{printed}"
        );
    }

    #[tokio::test]
    async fn rotate_detach_returns_without_polling() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/swarm",
            Reply::json(200, &swarm_json(OLD_PEM, false, 0)),
        )
        .on("POST", "/swarm/update", Reply::empty(200));
        let (mut streams, _out, _err) = testing::streams();
        let args = CaArgs {
            rotate: true,
            detach: true,
            ..CaArgs::default()
        };
        execute(&stub.host(), &args, &mut streams)
            .await
            .expect("detached rotate succeeds");
        // One GET (the read-modify-write) and one POST; no poll afterwards.
        assert_eq!(
            stub.routes(),
            vec!["GET /swarm", "POST /swarm/update"],
            "detach must not poll"
        );
    }

    #[tokio::test]
    async fn rotate_waits_through_the_transitional_bundle() {
        let stub = Stub::start().await;
        let transitional = format!("{OLD_PEM}{NEW_PEM}");
        stub.on(
            "GET",
            "/swarm",
            Reply::json(200, &swarm_json(OLD_PEM, false, 0)),
        )
        // Mid-rotation: two roots, flag up — not done.
        .on(
            "GET",
            "/swarm",
            Reply::json(200, &swarm_json(&transitional, true, 1)),
        )
        .on(
            "GET",
            "/swarm",
            Reply::json(200, &swarm_json(NEW_PEM, false, 1)),
        )
        .on("POST", "/swarm/update", Reply::empty(200));

        let (mut streams, out, _err) = testing::streams();
        let args = CaArgs {
            rotate: true,
            ..CaArgs::default()
        };
        execute(&stub.host(), &args, &mut streams)
            .await
            .expect("rotate waits and succeeds");
        assert!(
            out.contents().ends_with(&NEW_PEM.replace("\\n", "\n")),
            "the final root is the new one alone: {}",
            out.contents()
        );
    }

    #[tokio::test]
    async fn a_manager_without_a_ca_is_an_error() {
        let stub = Stub::start().await;
        stub.on("GET", "/swarm", Reply::json(200, &swarm_json("", false, 0)));
        let (mut streams, out, _err) = testing::streams();
        let err = execute(&stub.host(), &CaArgs::default(), &mut streams)
            .await
            .expect_err("no CA is an error");
        assert!(err.to_string().contains("no root CA"), "{err}");
        assert!(out.contents().is_empty());
    }
}
