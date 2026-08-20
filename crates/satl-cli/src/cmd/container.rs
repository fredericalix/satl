// SPDX-License-Identifier: BSD-2-Clause
//! `satl container prune` -- the one container verb with no top-level
//! spelling.
//!
//! This noun exists for exactly that reason and holds exactly that verb. The
//! lifecycle verbs stay where docker puts them, at the top level (`satl ps`,
//! `satl rm`, `satl stop`, `satl logs`, `satl inspect`): Docker's container
//! surface is flat, muscle memory is flat, and a `satl container ls` that
//! mirrored `satl ps` would be a second spelling of a verb that already has
//! one. `prune` has no flat spelling to collide with, so it lives here.
//!
//! What it prunes is cluster-wide, because a container is a Task of a Service
//! and both are store objects (invariant #2): running it on one manager
//! removes stopped containers across the cluster. The space it reports freed,
//! however, is this node's -- api-compat #130 -- so the summary names the
//! node, exactly as `satl system prune` does.

use crate::api::ContainersPruneResponse;
use crate::client::{self, Host};
use crate::cmd::system;
use crate::output::Streams;

/// Subcommands of `satl container`.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum ContainerCommand {
    /// Remove all stopped containers.
    Prune(PruneArgs),
}

/// Flags of `satl container prune`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct PruneArgs {
    /// Do not prompt for confirmation.
    #[arg(short, long)]
    pub force: bool,
}

/// Dispatch a `satl container` subcommand.
pub async fn execute(
    host: &Host,
    command: &ContainerCommand,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    match command {
        ContainerCommand::Prune(args) => prune(host, args, streams).await,
    }
}

/// `satl container prune [-f]`.
async fn prune(host: &Host, args: &PruneArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let node = system::node_name(host).await;
    if !args.force {
        streams.out(WARNING.as_bytes()).await;
        if !system::confirmed().await {
            streams.outln("Total reclaimed space: 0B").await;
            return Ok(0);
        }
    }
    let pruned: ContainersPruneResponse =
        client::post_empty_json(host, "/containers/prune").await?;
    streams
        .out(render(&pruned, node.as_deref()).as_bytes())
        .await;
    Ok(0)
}

/// The confirmation text. It says "and the service backing each one" because
/// that is what actually goes: `satl run` created a Service with one Task
/// (invariant #2), and pruning the container removes both.
const WARNING: &str = "WARNING! This will remove all stopped containers, and the service backing \
                       each one.\nStopped containers are cluster objects, so this acts on the \
                       whole cluster.\nAre you sure you want to continue? [y/N] ";

/// Docker's `container prune` summary plus the node-local statement (pure).
#[must_use]
pub fn render(pruned: &ContainersPruneResponse, node: Option<&str>) -> String {
    let mut text = String::new();
    if !pruned.containers_deleted.is_empty() {
        text.push_str("Deleted Containers:\n");
        for id in &pruned.containers_deleted {
            text.push_str(id);
            text.push('\n');
        }
    }
    text.push('\n');
    text.push_str(&system::reclaimed_line(pruned.space_reclaimed, node));
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;
    use crate::stub::{Reply, Stub};

    fn response(raw: &str) -> ContainersPruneResponse {
        serde_json::from_str(raw).expect("fixture parses")
    }

    #[test]
    fn summary_golden() {
        let pruned = response(
            r#"{"ContainersDeleted":["2ju54ic19pyb","1q8c4zamgo7w"],"SpaceReclaimed":62337024}"#,
        );
        assert_eq!(
            render(&pruned, Some("alpha")),
            "Deleted Containers:\n\
             2ju54ic19pyb\n\
             1q8c4zamgo7w\n\
             \n\
             Total reclaimed space: 62.34MB (on alpha; images, layers and volumes are \
             node-local)\n"
        );
    }

    #[test]
    fn a_prune_that_removed_nothing_is_one_line() {
        assert_eq!(
            render(&response("{}"), None),
            "\nTotal reclaimed space: 0B (on this node; images, layers and volumes are \
             node-local)\n"
        );
    }

    /// api-compat #130: the operator has to know the space is one node's.
    #[test]
    fn the_summary_always_names_the_node() {
        assert!(render(&response("{}"), Some("beta")).contains("(on beta;"));
    }

    #[tokio::test]
    async fn force_skips_the_prompt_and_prints_the_summary() {
        let stub = Stub::start().await;
        stub.on("GET", "/info", Reply::json(200, r#"{"Name":"alpha"}"#))
            .on(
                "POST",
                "/containers/prune",
                Reply::json(
                    200,
                    r#"{"ContainersDeleted":["2ju54ic19pyb"],"SpaceReclaimed":2048}"#,
                ),
            );

        let (mut streams, out, _err) = testing::streams();
        let args = PruneArgs { force: true };
        let code = execute(&stub.host(), &ContainerCommand::Prune(args), &mut streams)
            .await
            .expect("prune succeeds");
        assert_eq!(code, 0);
        assert_eq!(stub.routes(), vec!["GET /info", "POST /containers/prune"]);
        assert_eq!(
            out.contents(),
            "Deleted Containers:\n2ju54ic19pyb\n\nTotal reclaimed space: 2.048kB (on alpha; \
             images, layers and volumes are node-local)\n"
        );
    }

    #[tokio::test]
    async fn a_daemon_error_surfaces() {
        let stub = Stub::start().await;
        stub.on("GET", "/info", Reply::json(200, r#"{"Name":"alpha"}"#))
            .on(
                "POST",
                "/containers/prune",
                Reply::json(503, r#"{"message":"this node is not a swarm manager"}"#),
            );

        let (mut streams, _out, _err) = testing::streams();
        let args = PruneArgs { force: true };
        let err = execute(&stub.host(), &ContainerCommand::Prune(args), &mut streams)
            .await
            .expect_err("a 503 is an error");
        assert_eq!(
            err.to_string(),
            "Error response from daemon: this node is not a swarm manager"
        );
    }

    #[test]
    fn the_prompt_says_what_goes_and_how_far_it_reaches() {
        assert!(WARNING.contains("all stopped containers"), "{WARNING}");
        assert!(
            WARNING.contains("the service backing each one"),
            "{WARNING}"
        );
        assert!(WARNING.contains("whole cluster"), "{WARNING}");
        assert!(WARNING.ends_with("Are you sure you want to continue? [y/N] "));
        assert!(WARNING.is_ascii(), "operator text must be ASCII");
    }
}
