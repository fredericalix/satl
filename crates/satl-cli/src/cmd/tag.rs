// SPDX-License-Identifier: BSD-2-Clause
//! `satl tag` — make a target reference an additional name of a local image.
//!
//! A daemon call, exactly like `docker tag`: the image store is the daemon's,
//! so the CLI posts to `POST /images/{name}/tag` (Docker's route) and prints
//! nothing on success. Both names keep working afterwards; `satl images`
//! shows both.

use clap::Args;

use crate::client::{self, Host};
use crate::output::Streams;
use crate::parse::{self, ImageRef};

/// Flags of `satl tag`.
#[derive(Debug, Clone, Args)]
pub struct TagArgs {
    /// The existing local image.
    #[arg(value_name = "SOURCE_IMAGE[:TAG]")]
    pub source: String,

    /// The additional reference to point at the same image.
    #[arg(value_name = "TARGET_IMAGE[:TAG]")]
    pub target: String,
}

/// Run `satl tag`: `POST /images/{source}/tag?repo=&tag=`.
pub async fn execute(host: &Host, args: &TagArgs, _streams: &mut Streams) -> anyhow::Result<u8> {
    // Validate both ends client-side, as docker does; the daemon validates
    // again (it is the one that knows the store).
    parse::parse_image_ref(&args.source)?;
    let target = parse::parse_image_ref(&args.target)?;
    if target.is_digest {
        anyhow::bail!(
            "invalid target {:?}: a digest pin cannot be tagged, give a name[:tag]",
            args.target
        );
    }
    client::post_empty_ok(host, &tag_path(&args.source, &target)).await?;
    Ok(0)
}

/// Build the `POST /images/{name}/tag` URL. The source keeps its slashes —
/// the daemon's route is Docker's wildcard — and the target is split into
/// Docker's `repo`/`tag` query parameters.
pub fn tag_path(source: &str, target: &ImageRef) -> String {
    let query = client::query(&[("repo", target.name.as_str()), ("tag", &target.tag)]);
    format!("/images/{source}/tag{query}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;
    use crate::stub::{Reply, Stub};

    fn args(source: &str, target: &str) -> TagArgs {
        TagArgs {
            source: source.to_owned(),
            target: target.to_owned(),
        }
    }

    #[tokio::test]
    async fn tag_posts_the_source_path_and_the_target_query() {
        let stub = Stub::start().await;
        stub.on("POST", "/images/alpine:3.20/tag", Reply::empty(201));

        let (mut streams, out, err) = testing::streams();
        let args = args("alpine:3.20", "registry.example.com/mirror/alpine:3.20");
        assert_eq!(execute(&stub.host(), &args, &mut streams).await.unwrap(), 0);

        // docker prints nothing on a successful tag.
        assert!(out.contents().is_empty());
        assert!(err.contents().is_empty());
        let call = stub.first_call("POST /images/alpine:3.20/tag").unwrap();
        assert_eq!(
            call.query,
            "repo=registry.example.com%2Fmirror%2Falpine&tag=3.20"
        );
        assert!(call.body.is_empty());
    }

    #[tokio::test]
    async fn tag_keeps_the_slashes_of_a_registry_prefixed_source() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/images/127.0.0.1:5000/satl-test/freebsd-nginx:v1/tag",
            Reply::empty(201),
        );

        let (mut streams, _out, _err) = testing::streams();
        let args = args(
            "127.0.0.1:5000/satl-test/freebsd-nginx:v1",
            "mirror.example.com/freebsd-nginx",
        );
        assert_eq!(execute(&stub.host(), &args, &mut streams).await.unwrap(), 0);

        let call = stub
            .first_call("POST /images/127.0.0.1:5000/satl-test/freebsd-nginx:v1/tag")
            .unwrap();
        // An untagged target goes up as repo + the default tag.
        assert_eq!(
            call.query,
            "repo=mirror.example.com%2Ffreebsd-nginx&tag=latest"
        );
    }

    #[tokio::test]
    async fn tag_surfaces_the_daemon_error_verbatim() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/images/ghost:1/tag",
            Reply::json(
                404,
                r#"{"message":"no such image in the local store: docker.io/library/ghost:1"}"#,
            ),
        );

        let (mut streams, _out, _err) = testing::streams();
        let err = execute(&stub.host(), &args("ghost:1", "other:1"), &mut streams)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Error response from daemon: no such image in the local store: docker.io/library/ghost:1"
        );
    }

    #[tokio::test]
    async fn tag_rejects_a_digest_target_before_any_call() {
        let stub = Stub::start().await;
        let (mut streams, _out, _err) = testing::streams();
        let args = args(
            "alpine:3.20",
            "mirror/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
        );
        let err = execute(&stub.host(), &args, &mut streams)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("digest pin"), "{err}");
        assert!(
            stub.calls().is_empty(),
            "a client-side rejection must not reach the daemon"
        );
    }
}
