// SPDX-License-Identifier: BSD-2-Clause
//! `satl images` — the image noun: list, remove, prune, inspect.
//!
//! Bare `satl images` is Docker's `docker images`, byte for byte. The
//! subcommands are SatL's own spelling: Docker has `docker image rm` and never
//! `docker images rm`, because `docker images` takes a positional
//! `[REPOSITORY[:TAG]]` filter that a subcommand name would be ambiguous with.
//! `satl images` has never taken a positional, so the noun is free — at the
//! cost, recorded in `docs/api-compat.md` 154, that it can never grow that
//! filter later.

use std::fmt::Write as _;

use crate::api::{ImageDeleteItem, ImageSummary, ImagesPruneResponse};
use crate::client::{self, Host};
use crate::cmd::{FAILURE, system};
use crate::format::{self, Table};
use crate::output::Streams;
use crate::parse;

/// The header the daemon puts what does not fit Docker's array in.
const DEFERRED_HEADER: &str = "x-satl-deferred-layers";

/// `satl images` — bare it lists, with a subcommand it manages.
#[derive(Debug, Clone, Default, clap::Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct ImagesArgs {
    /// Listing flags, which bare `satl images` uses.
    #[command(flatten)]
    pub ls: LsArgs,

    /// The subcommand, when there is one.
    #[command(subcommand)]
    pub command: Option<ImagesCommand>,
}

/// Subcommands of `satl images`.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum ImagesCommand {
    /// List images.
    Ls(LsArgs),
    /// Remove one or more images.
    Rm(RmArgs),
    /// Remove unused images.
    Prune(PruneArgs),
    /// Return low-level information on images.
    Inspect(InspectArgs),
}

/// Flags of `satl images` and `satl images ls`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct LsArgs {
    /// Don't truncate output.
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,

    /// Only show image IDs.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Flags of `satl images rm` (and of its `satl rmi` alias).
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RmArgs {
    /// Force removal of the image.
    #[arg(short, long)]
    pub force: bool,

    /// Do not reclaim layers and content. Skips the two agreeing passes and
    /// the second and a half they take (docs/api-compat.md 155).
    #[arg(long = "no-prune")]
    pub no_prune: bool,

    /// Images to remove: a reference, an image ID, or an ID prefix.
    #[arg(required = true, value_name = "IMAGE")]
    pub images: Vec<String>,
}

/// Flags of `satl images prune`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct PruneArgs {
    /// Remove all unused images, not just dangling content.
    #[arg(short, long)]
    pub all: bool,

    /// Do not prompt for confirmation.
    #[arg(short, long)]
    pub force: bool,
}

/// Flags of `satl images inspect`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct InspectArgs {
    /// Images to inspect.
    #[arg(required = true, value_name = "IMAGE")]
    pub images: Vec<String>,
}

/// Dispatch `satl images`, with or without a subcommand.
pub async fn execute(host: &Host, args: &ImagesArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    match &args.command {
        None => list(host, &args.ls, streams).await,
        Some(ImagesCommand::Ls(ls)) => list(host, ls, streams).await,
        Some(ImagesCommand::Rm(rm)) => remove(host, rm, streams).await,
        Some(ImagesCommand::Prune(prune)) => prune_images(host, prune, streams).await,
        Some(ImagesCommand::Inspect(inspect)) => inspect_images(host, inspect, streams).await,
    }
}

/// `satl images` / `satl images ls`.
async fn list(host: &Host, args: &LsArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let images: Vec<ImageSummary> = client::get_json(host, "/images/json").await?;
    streams
        .out(render(&images, args, format::now_unix()).as_bytes())
        .await;
    Ok(0)
}

/// `DELETE /images/<image>?force=&noprune=`.
///
/// The reference goes into the path **unencoded**: it legitimately carries
/// slashes and colons, and percent-encoding them would stop the daemon's tail
/// wildcard from seeing the name the operator typed.
#[must_use]
pub fn remove_path(image: &str, args: &RmArgs) -> String {
    let query = client::query(&[
        ("force", if args.force { "1" } else { "0" }),
        ("noprune", if args.no_prune { "1" } else { "0" }),
    ]);
    format!("/images/{image}{query}")
}

/// `GET /images/<image>/json`.
#[must_use]
pub fn inspect_path(image: &str) -> String {
    format!("/images/{image}/json")
}

/// `satl images rm IMAGE...`, and `satl rmi IMAGE...`.
///
/// Docker's multi-argument shape: every image is attempted, a failure is
/// reported on stderr and does not stop the rest, and the exit code is 1 if
/// anything failed.
pub async fn remove(host: &Host, args: &RmArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut code = 0;
    let mut deferred = 0usize;
    for image in &args.images {
        match client::delete_json::<Vec<ImageDeleteItem>>(host, &remove_path(image, args)).await {
            Ok((items, headers)) => {
                deferred += headers
                    .get(DEFERRED_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                streams.out(render_rm(&items).as_bytes()).await;
            }
            Err(error) => {
                streams.error(&format!("{error:#}")).await;
                code = FAILURE;
            }
        }
    }
    if deferred > 0 {
        streams
            .out(system::deferred_hint(deferred).as_bytes())
            .await;
    }
    Ok(code)
}

/// One removal's reply, in Docker's `rmi` wording.
#[must_use]
pub fn render_rm(items: &[ImageDeleteItem]) -> String {
    let mut text = String::new();
    for item in items {
        if let Some(reference) = &item.untagged {
            let _ = writeln!(text, "Untagged: {reference}");
        }
        if let Some(what) = &item.deleted {
            let _ = writeln!(text, "Deleted: {what}");
        }
    }
    text
}

/// `satl images prune [-a] [-f]`.
async fn prune_images(host: &Host, args: &PruneArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let node = system::node_name(host).await;
    if !args.force {
        streams
            .out(prune_warning(args, node.as_deref()).as_bytes())
            .await;
        if !system::confirmed().await {
            streams.outln("Total reclaimed space: 0B").await;
            return Ok(0);
        }
    }
    // Docker's wire form of `-a` is a `dangling=false` filter.
    let path = if args.all {
        "/images/prune?filters=%7B%22dangling%22%3A%5B%22false%22%5D%7D"
    } else {
        "/images/prune"
    };
    let pruned: ImagesPruneResponse = client::post_empty_json(host, path).await?;
    streams
        .out(render_prune(&pruned, node.as_deref()).as_bytes())
        .await;
    Ok(0)
}

/// The confirmation text, naming what goes and where.
#[must_use]
pub fn prune_warning(args: &PruneArgs, node: Option<&str>) -> String {
    let mut text = String::from("WARNING! This will remove:\n");
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
        "\nImages and layers are reclaimed on {} ONLY:\nrun this on every node to \
         reclaim the cluster.",
        node.unwrap_or("this node")
    );
    text.push_str("\nAre you sure you want to continue? [y/N] ");
    text
}

/// The prune summary, in `satl system prune`'s wording.
#[must_use]
pub fn render_prune(pruned: &ImagesPruneResponse, node: Option<&str>) -> String {
    let mut text = String::new();
    if !pruned.images_deleted.is_empty() {
        text.push_str("Deleted Images:\n");
        for item in &pruned.images_deleted {
            if let Some(reference) = &item.untagged {
                let _ = writeln!(text, "untagged: {reference}");
            }
            if let Some(what) = &item.deleted {
                let _ = writeln!(text, "deleted: {what}");
            }
        }
    }
    if !pruned.deferred.is_empty() {
        text.push_str(&system::deferred_hint(pruned.deferred.len()));
    }
    text.push('\n');
    text.push_str(&system::reclaimed_line(pruned.space_reclaimed, node));
    text
}

/// `satl images inspect IMAGE...` — the daemon's JSON, verbatim.
async fn inspect_images(
    host: &Host,
    args: &InspectArgs,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    let mut documents = Vec::new();
    let mut code = 0;
    for image in &args.images {
        match client::get_json::<serde_json::Value>(host, &inspect_path(image)).await {
            Ok(document) => documents.push(document),
            Err(error) => {
                streams.error(&format!("{error:#}")).await;
                code = FAILURE;
            }
        }
    }
    streams
        .out(crate::cmd::inspect::render(&documents).as_bytes())
        .await;
    Ok(code)
}

/// Render the table (pure: the clock is injected so goldens are stable).
pub fn render(images: &[ImageSummary], args: &LsArgs, now_unix: i64) -> String {
    let mut sorted: Vec<&ImageSummary> = images.iter().collect();
    // Docker lists the most recently created image first.
    sorted.sort_by_key(|image| std::cmp::Reverse(image.created));

    if args.quiet {
        let mut out = String::new();
        for image in sorted {
            out.push_str(&id_cell(&image.id, args.no_trunc));
            out.push('\n');
        }
        return out;
    }

    let mut table = Table::new(&[
        "REPOSITORY",
        "TAG",
        "IMAGE ID",
        "CREATED",
        "SIZE",
        "PLATFORM",
    ]);
    for image in sorted {
        for (repository, tag) in repo_tags(image) {
            table.push(vec![
                repository,
                tag,
                id_cell(&image.id, args.no_trunc),
                format::created_ago(image.created, now_unix),
                format::human_size(image.size),
                image.platform.clone(),
            ]);
        }
    }
    table.render()
}

fn id_cell(id: &str, no_trunc: bool) -> String {
    if no_trunc {
        format::strip_digest_prefix(id)
    } else {
        format::truncate_id(id)
    }
}

/// One row per tag; dangling images get docker's `<none>` pair.
fn repo_tags(image: &ImageSummary) -> Vec<(String, String)> {
    let mut rows: Vec<(String, String)> = image
        .repo_tags
        .iter()
        .filter(|tag| *tag != "<none>:<none>")
        .filter_map(|reference| {
            let parsed = parse::parse_image_ref(reference).ok()?;
            let tag = if parsed.is_digest {
                "<none>".to_owned()
            } else {
                parsed.tag
            };
            Some((parsed.name, tag))
        })
        .collect();
    if rows.is_empty() {
        rows.push(("<none>".to_owned(), "<none>".to_owned()));
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stub::{Recorded, Reply, Stub};

    const NOW: i64 = 1_800_000_000;

    fn sample() -> Vec<ImageSummary> {
        vec![
            ImageSummary {
                id: "sha256:9c7a54a9a43cabcdef0123456789abcdef".to_owned(),
                repo_tags: vec!["127.0.0.1:5000/freebsd-nginx:v1".to_owned()],
                created: NOW - 3600,
                size: 187_000_000,
                platform: "freebsd/amd64".to_owned(),
            },
            ImageSummary {
                id: "sha256:1111222233334444555566667777".to_owned(),
                repo_tags: vec!["alpine:3.20".to_owned(), "alpine:latest".to_owned()],
                created: NOW - 2 * 24 * 3600,
                size: 7_800_000,
                platform: "linux/amd64".to_owned(),
            },
            ImageSummary {
                id: "sha256:deadbeefdeadbeefdeadbeef".to_owned(),
                repo_tags: Vec::new(),
                created: NOW - 90 * 24 * 3600,
                size: 1_093_000_000,
                platform: "freebsd/amd64".to_owned(),
            },
        ]
    }

    #[test]
    fn column_golden() {
        let rendered = render(&sample(), &LsArgs::default(), NOW);
        let expected = "\
REPOSITORY                     TAG      IMAGE ID       CREATED             SIZE      PLATFORM
127.0.0.1:5000/freebsd-nginx   v1       9c7a54a9a43c   About an hour ago   187MB     freebsd/amd64
alpine                         3.20     111122223333   2 days ago          7.8MB     linux/amd64
alpine                         latest   111122223333   2 days ago          7.8MB     linux/amd64
<none>                         <none>   deadbeefdead   3 months ago        1.093GB   freebsd/amd64
";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn quiet_lists_truncated_ids() {
        let args = LsArgs {
            quiet: true,
            ..LsArgs::default()
        };
        assert_eq!(
            render(&sample(), &args, NOW),
            "9c7a54a9a43c\n111122223333\ndeadbeefdead\n"
        );
    }

    #[test]
    fn no_trunc_keeps_the_full_id_without_the_algorithm_prefix() {
        let args = LsArgs {
            no_trunc: true,
            ..LsArgs::default()
        };
        let rendered = render(&sample()[..1], &args, NOW);
        assert!(
            rendered.contains("9c7a54a9a43cabcdef0123456789abcdef"),
            "{rendered}"
        );
        assert!(!rendered.contains("sha256:"), "{rendered}");
    }

    #[test]
    fn empty_list_still_prints_headers() {
        let rendered = render(&[], &LsArgs::default(), NOW);
        assert_eq!(
            rendered,
            "REPOSITORY   TAG   IMAGE ID   CREATED   SIZE   PLATFORM\n"
        );
    }

    // --- rm / prune / inspect ------------------------------------------

    fn rm_args(images: &[&str]) -> RmArgs {
        RmArgs {
            images: images.iter().map(|i| (*i).to_owned()).collect(),
            ..RmArgs::default()
        }
    }

    /// The reference goes into the path whole: percent-encoding its slashes
    /// and colon would stop the daemon's tail wildcard from seeing it.
    #[test]
    fn remove_path_leaves_the_reference_alone() {
        assert_eq!(
            remove_path("ghcr.io/team/app:v1", &rm_args(&[])),
            "/images/ghcr.io/team/app:v1?force=0&noprune=0"
        );
        assert_eq!(
            remove_path("sha256:deadbeef", &rm_args(&[])),
            "/images/sha256:deadbeef?force=0&noprune=0"
        );
        let forced = RmArgs {
            force: true,
            no_prune: true,
            ..RmArgs::default()
        };
        assert_eq!(
            remove_path("nginx:1.25", &forced),
            "/images/nginx:1.25?force=1&noprune=1"
        );
        assert_eq!(inspect_path("nginx:1.25"), "/images/nginx:1.25/json");
    }

    #[test]
    fn render_rm_is_dockers_wording() {
        let items = vec![
            ImageDeleteItem {
                untagged: Some("docker.io/library/nginx:1.25".to_owned()),
                deleted: None,
            },
            ImageDeleteItem {
                untagged: None,
                deleted: Some("sha256:abc".to_owned()),
            },
        ];
        assert_eq!(
            render_rm(&items),
            "Untagged: docker.io/library/nginx:1.25\nDeleted: sha256:abc\n"
        );
        assert_eq!(render_rm(&[]), "");
    }

    #[tokio::test]
    async fn rm_echoes_each_removal_and_asks_the_right_path() {
        let stub = Stub::start().await;
        stub.on(
            "DELETE",
            "/images/nginx:1.25",
            Reply::json(200, r#"[{"Untagged":"docker.io/library/nginx:1.25"}]"#),
        );
        let (mut streams, out, _err) = crate::output::testing::streams();
        let code = remove(&stub.host(), &rm_args(&["nginx:1.25"]), &mut streams)
            .await
            .expect("rm");
        assert_eq!(code, 0);
        assert_eq!(out.contents(), "Untagged: docker.io/library/nginx:1.25\n");
        let call = stub
            .first_call("DELETE /images/nginx:1.25")
            .expect("the delete");
        assert_eq!(call.query, "force=0&noprune=0");
    }

    /// A failure on one image is reported and does not stop the others; the
    /// exit code is 1 because something failed.
    #[tokio::test]
    async fn rm_keeps_going_after_a_conflict_and_still_fails() {
        let stub = Stub::start().await;
        stub.on(
            "DELETE",
            "/images/busy",
            Reply::json(
                409,
                r#"{"message":"conflict: unable to delete busy (cannot be forced) - image is being used by running container 1kql"}"#,
            ),
        );
        stub.on(
            "DELETE",
            "/images/free",
            Reply::json(200, r#"[{"Untagged":"docker.io/library/free:latest"}]"#),
        );
        let (mut streams, out, err) = crate::output::testing::streams();
        let code = remove(&stub.host(), &rm_args(&["busy", "free"]), &mut streams)
            .await
            .expect("rm");
        assert_eq!(code, FAILURE);
        assert!(
            err.contents().contains("cannot be forced"),
            "{}",
            err.contents()
        );
        assert!(
            out.contents()
                .contains("Untagged: docker.io/library/free:latest"),
            "the second image is still removed: {}",
            out.contents()
        );
    }

    /// The deferred count rides on a header and prints the same sentence
    /// `satl system prune` prints, once, after the loop.
    #[tokio::test]
    async fn rm_prints_the_deferral_hint_from_the_header() {
        let stub = Stub::start().await;
        stub.on(
            "DELETE",
            "/images/nginx:1.25",
            Reply::json(200, r#"[{"Untagged":"nginx:1.25"}]"#)
                .with_header("X-Satl-Deferred-Layers", "2"),
        );
        let (mut streams, out, _err) = crate::output::testing::streams();
        remove(&stub.host(), &rm_args(&["nginx:1.25"]), &mut streams)
            .await
            .expect("rm");
        assert!(
            out.contents().contains(&system::deferred_hint(2)),
            "{}",
            out.contents()
        );
    }

    /// `satl rmi` and `satl images rm` are one implementation, reached from
    /// two entry points: `cli.rs` dispatches both arms to `remove`, so the
    /// only thing that could differ is the parse, which `cli.rs`'s own test
    /// pins. Here we pin that the shared body issues exactly one DELETE.
    #[tokio::test]
    async fn rm_issues_exactly_one_delete_per_image() {
        let stub = Stub::start().await;
        stub.on("DELETE", "/images/a", Reply::json(200, "[]"));
        stub.on("DELETE", "/images/b", Reply::json(200, "[]"));
        let (mut streams, _out, _err) = crate::output::testing::streams();
        remove(&stub.host(), &rm_args(&["a", "b"]), &mut streams)
            .await
            .expect("rm");
        let routes: Vec<String> = stub.calls().iter().map(Recorded::route).collect();
        assert_eq!(routes, ["DELETE /images/a", "DELETE /images/b"]);
    }

    #[tokio::test]
    async fn prune_sends_dockers_dangling_filter_for_all() {
        let stub = Stub::start().await;
        stub.on("GET", "/info", Reply::json(200, r#"{"Name":"alpha"}"#));
        stub.on(
            "POST",
            "/images/prune",
            Reply::json(200, r#"{"ImagesDeleted":[],"SpaceReclaimed":0}"#),
        );
        let args = PruneArgs {
            all: true,
            force: true,
        };
        let (mut streams, out, _err) = crate::output::testing::streams();
        prune_images(&stub.host(), &args, &mut streams)
            .await
            .expect("prune");
        let call = stub.first_call("POST /images/prune").expect("the prune");
        assert_eq!(
            call.query,
            "filters=%7B%22dangling%22%3A%5B%22false%22%5D%7D"
        );
        assert!(out.contents().contains("on alpha"), "{}", out.contents());
    }

    #[tokio::test]
    async fn inspect_prints_the_document_and_reports_a_miss() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/images/nginx:1.25/json",
            Reply::json(200, r#"{"Id":"sha256:abc"}"#),
        );
        stub.on(
            "GET",
            "/images/ghost/json",
            Reply::json(404, r#"{"message":"No such image: ghost"}"#),
        );
        let args = InspectArgs {
            images: vec!["nginx:1.25".to_owned(), "ghost".to_owned()],
        };
        let (mut streams, out, err) = crate::output::testing::streams();
        let code = inspect_images(&stub.host(), &args, &mut streams)
            .await
            .expect("inspect");
        assert_eq!(code, FAILURE);
        assert!(out.contents().contains("sha256:abc"), "{}", out.contents());
        assert!(
            err.contents().contains("No such image"),
            "{}",
            err.contents()
        );
    }
}
