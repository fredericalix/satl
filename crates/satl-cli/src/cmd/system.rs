// SPDX-License-Identifier: BSD-2-Clause
//! `satl system prune`.
//!
//! Docker's shape, verified against `docker system prune --help` on this host
//! (docker-cli 29.4.2): `-a/--all`, `--volumes`, `-f/--force`, and — because
//! `--force` exists — a confirmation prompt by default that names what will go.
//! `--filter` is deliberately absent (api-compat 134).
//!
//! The one thing Docker's wording cannot express is SatL's: **what this
//! reclaims is not all in one place.** Containers and networks are cluster
//! objects, so pruning them acts on the whole cluster; images, layers and
//! volumes live on the node whose daemon this is. An operator who ran prune on
//! one manager and believed the cluster's disks were reclaimed would be wrong by
//! however many nodes there are, so the warning and the summary both say which
//! node answered.

use std::fmt::Write as _;

use crate::api::cluster::SystemInfo;
use crate::api::{
    ContainersPruneResponse, ImagesPruneResponse, NetworksPruneResponse, VolumesPruneResponse,
};
use crate::client::{self, Host};
use crate::format::human_size;
use crate::output::Streams;

/// Subcommands of `satl system`.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum SystemCommand {
    /// Remove unused data.
    Prune(PruneArgs),
}

/// Flags of `satl system prune`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct PruneArgs {
    /// Remove all unused images not just dangling ones.
    #[arg(short, long)]
    pub all: bool,

    /// Prune volumes no container uses.
    #[arg(long)]
    pub volumes: bool,

    /// Do not prompt for confirmation.
    #[arg(short, long)]
    pub force: bool,
}

/// Dispatch a `satl system` subcommand.
pub async fn execute(
    host: &Host,
    command: &SystemCommand,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    match command {
        SystemCommand::Prune(args) => prune(host, args, streams).await,
    }
}

/// What one prune reclaimed, gathered from the four endpoints.
#[derive(Debug, Default)]
pub struct PruneOutcome {
    /// Container IDs removed (cluster-wide).
    pub containers: Vec<String>,
    /// Network names removed (cluster-wide).
    pub networks: Vec<String>,
    /// Image references untagged on this node.
    pub untagged: Vec<String>,
    /// Content and layer datasets deleted on this node.
    pub deleted: Vec<String>,
    /// Volume names removed on this node.
    pub volumes: Vec<String>,
    /// Layer chains that need a second agreeing pass before they can go.
    pub deferred: Vec<String>,
    /// Total bytes freed, as the daemon measured them.
    pub reclaimed: u64,
}

/// `satl system prune [-a] [--volumes] [-f]`.
async fn prune(host: &Host, args: &PruneArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let node = node_name(host).await;
    if !args.force {
        streams.out(warning(args, node.as_deref()).as_bytes()).await;
        if !confirmed().await {
            streams.outln("Total reclaimed space: 0B").await;
            return Ok(0);
        }
    }

    let mut outcome = PruneOutcome::default();

    let containers: ContainersPruneResponse =
        client::post_empty_json(host, "/containers/prune").await?;
    outcome.containers = containers.containers_deleted;
    outcome.reclaimed += containers.space_reclaimed;

    let networks: NetworksPruneResponse = client::post_empty_json(host, "/networks/prune").await?;
    outcome.networks = networks.networks_deleted;

    if args.volumes {
        let volumes: VolumesPruneResponse = client::post_empty_json(host, "/volumes/prune").await?;
        outcome.volumes = volumes.volumes_deleted;
        outcome.reclaimed += volumes.space_reclaimed;
    }

    // Images last, and after the containers: a container removed a moment ago
    // still holds a clone of its image's top layer, so pruning images first
    // would find every layer claimed and reclaim nothing. Docker orders it the
    // same way, for the same reason.
    let path = if args.all {
        // Docker's wire form of `-a`.
        "/images/prune?filters=%7B%22dangling%22%3A%5B%22false%22%5D%7D"
    } else {
        "/images/prune"
    };
    let images: ImagesPruneResponse = client::post_empty_json(host, path).await?;
    for item in images.images_deleted {
        if let Some(reference) = item.untagged {
            outcome.untagged.push(reference);
        }
        if let Some(what) = item.deleted {
            outcome.deleted.push(what);
        }
    }
    outcome.reclaimed += images.space_reclaimed;
    outcome.deferred = images.deferred;

    streams
        .out(render(&outcome, node.as_deref()).as_bytes())
        .await;
    Ok(0)
}

/// The daemon's own name, for the node-local statement. Best effort: a prune
/// that cannot read `/info` still prunes, it just says "this node".
pub(crate) async fn node_name(host: &Host) -> Option<String> {
    let info: SystemInfo = client::get_json(host, "/info").await.ok()?;
    (!info.name.is_empty()).then_some(info.name)
}

/// api-compat #130's node-local statement, in one place.
///
/// Every verb that reclaims disk ends on this exact line -- `satl system
/// prune`, `satl container prune`, `satl volume prune`, `satl images prune`
/// -- so an operator who meets it on two different verbs meets the same
/// words. `satl network prune` is the one that does not: a network is not
/// disk, and there is no space to report.
#[must_use]
pub fn reclaimed_line(reclaimed: u64, node: Option<&str>) -> String {
    format!(
        "Total reclaimed space: {} (on {}; images, layers and volumes are node-local)\n",
        human_size(i64::try_from(reclaimed).unwrap_or(i64::MAX)),
        node.unwrap_or("this node")
    )
}

/// The confirmation text, exactly what will be removed and where.
#[must_use]
pub fn warning(args: &PruneArgs, node: Option<&str>) -> String {
    let mut text = String::from("WARNING! This will remove:\n");
    text.push_str("  - all stopped containers, and the service backing each one\n");
    text.push_str("  - all networks not used by at least one container\n");
    if args.volumes {
        text.push_str("  - all volumes not used by at least one container\n");
    }
    if args.all {
        text.push_str("  - all images without at least one container associated to them\n");
    } else {
        text.push_str(
            "  - all dangling image content (blobs, manifests and configs nothing references)\n",
        );
    }
    text.push_str("  - all unreferenced image layer datasets\n");
    let _ = writeln!(
        text,
        "\nContainers and networks are cluster-wide. {} are \
         reclaimed on {} ONLY:\nrun this on every node to reclaim the cluster.",
        if args.volumes {
            "Images, layers and volumes"
        } else {
            "Images and layers"
        },
        node.unwrap_or("this node")
    );
    text.push_str("\nAre you sure you want to continue? [y/N] ");
    text
}

/// Read one line from stdin and decide. `n` on anything unclear, including a
/// stdin that cannot be read at all — a prune that proceeds because it could not
/// ask is the worst possible reading of silence.
pub(crate) async fn confirmed() -> bool {
    use tokio::io::AsyncBufReadExt as _;
    let mut line = String::new();
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => false,
        Ok(_) => answer_is_yes(&line),
    }
}

/// Whether an answer to `[y/N]` means yes. Docker accepts `y` and `yes`,
/// case-insensitively, and treats everything else as no.
#[must_use]
pub fn answer_is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// The two-pass deferral hint (api-compat #131), in one place.
///
/// Every verb that can defer a layer prints this exact sentence -- `satl
/// system prune`, `satl images prune` and `satl images rm` -- so an operator
/// who meets it twice meets the same words and does not wonder whether two
/// different things happened.
#[must_use]
pub fn deferred_hint(count: usize) -> String {
    format!(
        "\n{count} layer(s) were unreferenced on only one of the two passes and were \
         left alone.\nRun prune again to reclaim them.\n"
    )
}

/// The summary, Docker's layout plus the node-local statement and the deferrals.
#[must_use]
pub fn render(outcome: &PruneOutcome, node: Option<&str>) -> String {
    let mut text = String::new();
    let mut section = |title: &str, items: &[String]| {
        if items.is_empty() {
            return;
        }
        text.push_str(title);
        text.push('\n');
        for item in items {
            text.push_str(item);
            text.push('\n');
        }
    };
    section("Deleted Containers:", &outcome.containers);
    section("Deleted Networks:", &outcome.networks);
    section("Deleted Volumes:", &outcome.volumes);
    if !outcome.untagged.is_empty() || !outcome.deleted.is_empty() {
        text.push_str("Deleted Images:\n");
        for reference in &outcome.untagged {
            let _ = writeln!(text, "untagged: {reference}");
        }
        for what in &outcome.deleted {
            let _ = writeln!(text, "deleted: {what}");
        }
    }
    if !outcome.deferred.is_empty() {
        text.push_str(&deferred_hint(outcome.deferred.len()));
    }
    text.push('\n');
    text.push_str(&reclaimed_line(outcome.reclaimed, node));
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stub::{Reply, Stub};

    fn ids(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn the_warning_names_what_will_go_and_where() {
        let text = warning(&PruneArgs::default(), Some("alpha"));
        assert!(text.contains("all stopped containers"), "{text}");
        assert!(text.contains("dangling image content"), "{text}");
        assert!(!text.contains("all volumes"), "{text}");
        assert!(
            text.contains("reclaimed on alpha ONLY"),
            "the node-local statement is the whole point: {text}"
        );
        assert!(
            text.ends_with("Are you sure you want to continue? [y/N] "),
            "{text}"
        );
    }

    #[test]
    fn all_and_volumes_each_add_their_line() {
        let text = warning(
            &PruneArgs {
                all: true,
                volumes: true,
                force: false,
            },
            Some("node2"),
        );
        assert!(text.contains("all volumes not used"), "{text}");
        assert!(
            text.contains("all images without at least one container"),
            "{text}"
        );
        assert!(!text.contains("dangling image content"), "{text}");
        assert!(text.contains("layers and volumes are"), "{text}");
    }

    #[test]
    fn a_daemon_that_cannot_be_named_still_says_it_is_one_node() {
        let text = warning(&PruneArgs::default(), None);
        assert!(text.contains("reclaimed on this node ONLY"), "{text}");
    }

    #[test]
    fn only_y_and_yes_mean_yes() {
        for yes in ["y", "Y", "yes", "YES", " y \n", "Yes\n"] {
            assert!(answer_is_yes(yes), "{yes:?}");
        }
        for no in ["", "\n", "n", "no", "sure", "yy", "ok"] {
            assert!(!answer_is_yes(no), "{no:?}");
        }
    }

    #[test]
    fn the_summary_is_dockers_layout_plus_the_node() {
        let outcome = PruneOutcome {
            containers: ids(&["2ju54ic19pyb", "1q8c4zamgo7w"]),
            networks: ids(&["scratch"]),
            volumes: Vec::new(),
            untagged: ids(&["127.0.0.1:5000/satl-test/alpine:latest"]),
            deleted: ids(&["sha256:aaaa", "blob:sha256:bbbb"]),
            deferred: Vec::new(),
            reclaimed: 62_337_024,
        };
        assert_eq!(
            render(&outcome, Some("alpha")),
            "Deleted Containers:\n\
             2ju54ic19pyb\n\
             1q8c4zamgo7w\n\
             Deleted Networks:\n\
             scratch\n\
             Deleted Images:\n\
             untagged: 127.0.0.1:5000/satl-test/alpine:latest\n\
             deleted: sha256:aaaa\n\
             deleted: blob:sha256:bbbb\n\
             \n\
             Total reclaimed space: 62.34MB (on alpha; images, layers and volumes are \
             node-local)\n"
        );
    }

    #[test]
    fn a_prune_that_freed_nothing_says_so_in_one_line() {
        assert_eq!(
            render(&PruneOutcome::default(), Some("alpha")),
            "\nTotal reclaimed space: 0B (on alpha; images, layers and volumes are \
             node-local)\n"
        );
    }

    /// The two-pass rule is visible to the operator, or a prune that reclaimed
    /// less than expected looks like a bug.
    #[test]
    fn deferred_layers_are_reported_with_what_to_do_about_them() {
        let outcome = PruneOutcome {
            deferred: ids(&["aa", "bb"]),
            ..PruneOutcome::default()
        };
        let text = render(&outcome, None);
        assert!(text.contains("2 layer(s)"), "{text}");
        assert!(text.contains("only one of the two passes"), "{text}");
        assert!(text.contains("Run prune again"), "{text}");
    }

    /// Order matters on the wire: containers before images, or every layer is
    /// still claimed by a container clone when the image prune looks.
    #[tokio::test]
    async fn prune_calls_the_endpoints_in_dockers_order() {
        let stub = Stub::start().await;
        stub.on("GET", "/info", Reply::json(200, r#"{"Name":"alpha"}"#));
        stub.on("POST", "/containers/prune", Reply::json(200, "{}"));
        stub.on("POST", "/networks/prune", Reply::json(200, "{}"));
        stub.on("POST", "/images/prune", Reply::json(200, "{}"));
        let (mut streams, out, _err) = crate::output::testing::streams();
        let code = prune(
            &stub.host(),
            &PruneArgs {
                all: false,
                volumes: false,
                force: true,
            },
            &mut streams,
        )
        .await
        .expect("prune");
        assert_eq!(code, 0);
        assert_eq!(
            stub.routes(),
            vec![
                "GET /info",
                "POST /containers/prune",
                "POST /networks/prune",
                "POST /images/prune",
            ]
        );
        assert!(
            out.contents()
                .contains("Total reclaimed space: 0B (on alpha"),
            "{}",
            out.contents()
        );
    }

    #[tokio::test]
    async fn volumes_are_only_pruned_when_asked_for() {
        let stub = Stub::start().await;
        stub.on("GET", "/info", Reply::json(200, r#"{"Name":"alpha"}"#));
        stub.on("POST", "/containers/prune", Reply::json(200, "{}"));
        stub.on("POST", "/networks/prune", Reply::json(200, "{}"));
        stub.on(
            "POST",
            "/volumes/prune",
            Reply::json(200, r#"{"VolumesDeleted":["data"],"SpaceReclaimed":2048}"#),
        );
        stub.on("POST", "/images/prune", Reply::json(200, "{}"));
        let (mut streams, out, _err) = crate::output::testing::streams();
        prune(
            &stub.host(),
            &PruneArgs {
                all: false,
                volumes: true,
                force: true,
            },
            &mut streams,
        )
        .await
        .expect("prune");
        assert!(stub.routes().contains(&"POST /volumes/prune".to_owned()));
        assert!(
            out.contents().contains("Deleted Volumes:\ndata"),
            "{}",
            out.contents()
        );
        assert!(out.contents().contains("2.048kB"), "{}", out.contents());
    }

    /// `-a` has to reach the daemon as Docker's filter, or it does nothing.
    #[tokio::test]
    async fn all_is_sent_as_dockers_dangling_false_filter() {
        let stub = Stub::start().await;
        stub.on("GET", "/info", Reply::json(200, r#"{"Name":"alpha"}"#));
        stub.on("POST", "/containers/prune", Reply::json(200, "{}"));
        stub.on("POST", "/networks/prune", Reply::json(200, "{}"));
        stub.on("POST", "/images/prune", Reply::json(200, "{}"));
        let (mut streams, _out, _err) = crate::output::testing::streams();
        prune(
            &stub.host(),
            &PruneArgs {
                all: true,
                volumes: false,
                force: true,
            },
            &mut streams,
        )
        .await
        .expect("prune");
        let call = stub
            .first_call("POST /images/prune")
            .expect("the images prune call");
        // Percent-encoded on the wire; this is Docker's `{"dangling":["false"]}`.
        assert_eq!(
            call.query,
            "filters=%7B%22dangling%22%3A%5B%22false%22%5D%7D"
        );
    }
}
