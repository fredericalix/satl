// SPDX-License-Identifier: BSD-2-Clause
//! Multi-layer build integration test: a two-step Satlfile against the local
//! test registry's FreeBSD base, asserting the manifest is base layers + one
//! layer per step, and that a rebuild reuses the cached steps.
//!
//! Root-gated (`#[ignore]`, run via `sudo make integration`): the build
//! unpacks root-owned base layers and pkg/chroot semantics want root, and
//! the base image comes from the local test registry (see
//! `tests/integration/README.md`).

use satl_build::{BuildCache, Satlfile};
use satl_image::{ImageReference, ImageStore};

/// The FreeBSD base every integration test pulls from the local registry.
const BASE: &str = "127.0.0.1:5000/satl-test/freebsd-runtime:15.1";

/// Builds the two-step fixture image into `store`, returning the registered
/// image's diff IDs and layer count.
async fn build_fixture(
    store: &ImageStore,
    cache: &BuildCache,
    context: &std::path::Path,
    tag: &ImageReference,
) -> (Vec<String>, usize) {
    let spec = Satlfile::parse(&format!(
        "FROM {BASE}\nCOPY app.js /srv/app.js\nCOPY data.txt /srv/data/\n"
    ))
    .expect("Satlfile parses");
    let outcome = satl_build::build(
        store,
        &spec,
        tag,
        satl_build::DEFAULT_PKG_ABI,
        context,
        Some(cache),
    )
    .await
    .expect("build");
    let diff_ids: Vec<String> = outcome
        .image
        .layers
        .iter()
        .map(|layer| layer.diff_id.to_string())
        .collect();
    (diff_ids, outcome.image.layers.len())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "root + local registry (sudo make integration)"]
async fn a_two_step_build_layers_per_step_and_caches() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ImageStore::open(dir.path().join("images")).expect("open store");
    let cache = BuildCache::new(dir.path().join("build-cache"));
    let context = dir.path().join("context");
    std::fs::create_dir_all(&context).expect("context");
    std::fs::write(context.join("app.js"), "// app v1\n").expect("write");
    std::fs::write(context.join("data.txt"), "data\n").expect("write");
    let tag = ImageReference::parse("127.0.0.1:5000/satl-test/build-fixture:dev").expect("tag");

    // The base is pulled first, so its layer count is the reference point.
    let policy = satl_image::PlatformPolicy::for_host(false);
    let base_ref = ImageReference::parse(BASE).expect("base ref");
    let base = store
        .pull(&base_ref, &policy, None)
        .await
        .expect("base pull");
    let base_layers = base.layers.len();

    let (first_ids, first_count) = build_fixture(&store, &cache, &context, &tag).await;
    assert_eq!(
        first_count,
        base_layers + 2,
        "the manifest is the base plus one layer per COPY step"
    );
    assert_eq!(
        &first_ids[..base_layers],
        base.layers
            .iter()
            .map(|layer| layer.diff_id.to_string())
            .collect::<Vec<_>>()
            .as_slice(),
        "the base's diff_ids are the image's first diff_ids"
    );

    // A rebuild with unchanged inputs: every step is a cache hit, so the
    // diff_ids are byte-identical.
    let (second_ids, _) = build_fixture(&store, &cache, &context, &tag).await;
    assert_eq!(first_ids, second_ids, "a cached rebuild reuses the layers");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "root + local registry (sudo make integration)"]
async fn a_two_stage_build_registers_only_the_last_stage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ImageStore::open(dir.path().join("images")).expect("open store");
    let cache = BuildCache::new(dir.path().join("build-cache"));
    let context = dir.path().join("context");
    std::fs::create_dir_all(&context).expect("context");
    std::fs::write(context.join("app.js"), "// app v1\n").expect("write");
    let spec = Satlfile::parse(&format!(
        "FROM {BASE} AS builder\n\
         COPY app.js /src/app.js\n\
         RUN cp /src/app.js /src/out\n\
         FROM scratch\n\
         COPY --from=builder /src/out /srv/out\n\
         ENTRYPOINT [\"/srv/out\"]\n"
    ))
    .expect("Satlfile parses");
    let tag = ImageReference::parse("127.0.0.1:5000/satl-test/build-stages:dev").expect("tag");

    let build = || async {
        satl_build::build(
            &store,
            &spec,
            &tag,
            satl_build::DEFAULT_PKG_ABI,
            &context,
            Some(&cache),
        )
        .await
        .expect("build")
    };
    let first = build().await;
    // The scratch final stage has no base; the image is exactly its one
    // step layer — the builder's base and step layers never enter it.
    assert_eq!(
        first.image.layers.len(),
        1,
        "only the last stage's COPY --from layer"
    );
    assert_eq!(first.image.config.entrypoint, ["/srv/out".to_owned()]);

    // A rebuild reuses both stages' cached steps: identical diff_id.
    let second = build().await;
    assert_eq!(
        first.image.layers[0].diff_id, second.image.layers[0].diff_id,
        "a cached two-stage rebuild reuses the layer"
    );
}
