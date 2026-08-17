// SPDX-License-Identifier: BSD-2-Clause
//! `satl images` — list images in the local content store.

use crate::api::ImageSummary;
use crate::client::{self, Host};
use crate::format::{self, Table};
use crate::parse;

/// Flags of `satl images`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct ImagesArgs {
    /// Don't truncate output.
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,

    /// Only show image IDs.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Fetch the image list and render it.
pub async fn execute(host: &Host, args: &ImagesArgs) -> anyhow::Result<String> {
    let images: Vec<ImageSummary> = client::get_json(host, "/images/json").await?;
    Ok(render(&images, args, format::now_unix()))
}

/// Render the table (pure: the clock is injected so goldens are stable).
pub fn render(images: &[ImageSummary], args: &ImagesArgs, now_unix: i64) -> String {
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
        let rendered = render(&sample(), &ImagesArgs::default(), NOW);
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
        let args = ImagesArgs {
            quiet: true,
            ..ImagesArgs::default()
        };
        assert_eq!(
            render(&sample(), &args, NOW),
            "9c7a54a9a43c\n111122223333\ndeadbeefdead\n"
        );
    }

    #[test]
    fn no_trunc_keeps_the_full_id_without_the_algorithm_prefix() {
        let args = ImagesArgs {
            no_trunc: true,
            ..ImagesArgs::default()
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
        let rendered = render(&[], &ImagesArgs::default(), NOW);
        assert_eq!(
            rendered,
            "REPOSITORY   TAG   IMAGE ID   CREATED   SIZE   PLATFORM\n"
        );
    }
}
