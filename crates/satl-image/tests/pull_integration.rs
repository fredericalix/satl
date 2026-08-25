// SPDX-License-Identifier: BSD-2-Clause
//! Full-pull integration test (network required, `#[ignore]`-gated; run via
//! `make integration` or `cargo test -p satl-image -- --ignored`).
//!
//! Prefers the local test registry at `127.0.0.1:5000` when it is up and has
//! a usable image; otherwise pulls `docker.io/library/alpine:3.20`.

use sha2::{Digest as _, Sha256};

use satl_image::{Digest, ImageReference, ImageStore, PlatformPolicy, PullProgress};

/// The local test registry another dev task may have seeded.
const LOCAL_REGISTRY: &str = "127.0.0.1:5000";
/// Fallback public image (small, multi-platform).
const PUBLIC_FALLBACK: &str = "docker.io/library/alpine:3.20";

/// A policy that resolves on any dev machine: linux/amd64 via emulation
/// covers alpine when the index has no freebsd entries.
fn policy() -> PlatformPolicy {
    PlatformPolicy::for_host(true)
}

/// Discovers pullable references on the local registry (`/v2/_catalog` +
/// `/v2/<repo>/tags/list`), returning an empty list when the registry is
/// down, unreadable, or empty.
async fn local_registry_references() -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct Catalog {
        repositories: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    struct Tags {
        tags: Option<Vec<String>>,
    }

    let Ok(client) = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .build()
    else {
        return Vec::new();
    };
    let catalog: Catalog = match client
        .get(format!("http://{LOCAL_REGISTRY}/v2/_catalog"))
        .send()
        .await
    {
        Ok(response) => match response.json().await {
            Ok(catalog) => catalog,
            Err(_) => return Vec::new(),
        },
        Err(_) => return Vec::new(),
    };

    let mut references = Vec::new();
    for repo in catalog.repositories.iter().take(3) {
        let Ok(response) = client
            .get(format!("http://{LOCAL_REGISTRY}/v2/{repo}/tags/list"))
            .send()
            .await
        else {
            continue;
        };
        let Ok(tags) = response.json::<Tags>().await else {
            continue;
        };
        if let Some(tag) = tags.tags.unwrap_or_default().first() {
            references.push(format!("{LOCAL_REGISTRY}/{repo}:{tag}"));
        }
    }
    references
}

#[tokio::test]
#[ignore = "requires network access (local registry or docker.io)"]
async fn full_pull_into_tempdir_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ImageStore::open(dir.path().join("images")).expect("open store");

    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();

    // Pick a source: local registry if it is up and has a pullable image,
    // else Docker Hub.
    let mut pulled = None;
    for candidate in local_registry_references().await {
        let reference = ImageReference::parse(&candidate).expect("parse local reference");
        match store
            .pull_with_progress(&reference, &policy(), None, Some(progress_tx.clone()))
            .await
        {
            Ok(image) => {
                eprintln!("pulled {candidate} from the local registry");
                pulled = Some(image);
                break;
            }
            Err(error) => eprintln!("local registry pull of {candidate} failed: {error}"),
        }
    }
    let image = if let Some(image) = pulled {
        image
    } else {
        let reference = ImageReference::parse(PUBLIC_FALLBACK).expect("parse fallback");
        store
            .pull_with_progress(&reference, &policy(), None, Some(progress_tx.clone()))
            .await
            .expect("pull from docker.io")
    };
    drop(progress_tx);

    // The pull reported progress including a completion event.
    let mut saw_complete = false;
    let mut saw_layer_activity = false;
    while let Some(event) = progress_rx.recv().await {
        match event {
            PullProgress::Complete { .. } => saw_complete = true,
            PullProgress::LayerDone { .. } | PullProgress::LayerAlreadyPresent { .. } => {
                saw_layer_activity = true;
            }
            _ => {}
        }
    }
    assert!(saw_complete, "no Complete progress event");
    assert!(saw_layer_activity, "no layer progress events");

    // Every layer blob exists on disk and re-hashes to its digest.
    assert!(!image.layers.is_empty(), "image has no layers");
    for layer in &image.layers {
        let path = store.blob_path(&layer.blob_digest);
        let bytes =
            std::fs::read(&path).unwrap_or_else(|e| panic!("blob {} missing: {e}", path.display()));
        assert_eq!(bytes.len() as u64, layer.size, "blob size mismatch");
        let actual = Digest::from_sha256_hash(&Sha256::digest(&bytes));
        assert_eq!(actual, layer.blob_digest, "blob content digest mismatch");
        layer.compression().expect("known layer compression");
    }

    // Config was parsed into something runnable-looking.
    assert!(!image.config.os.is_empty());
    assert!(!image.config.architecture.is_empty());
    assert!(
        !image.config.cmd.is_empty() || !image.config.entrypoint.is_empty(),
        "image has neither cmd nor entrypoint"
    );

    // The image resolves from local metadata alone and matches the pull.
    let reference = ImageReference::parse(&image.reference).expect("canonical reparses");
    let resolved = store
        .resolve(&reference)
        .await
        .expect("resolve")
        .expect("image present after pull");
    assert_eq!(resolved.manifest_digest, image.manifest_digest);
    assert_eq!(resolved.layers, image.layers);

    // Idempotency: a re-pull re-downloads no blobs.
    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();
    let repulled = store
        .pull_with_progress(&reference, &policy(), None, Some(progress_tx))
        .await
        .expect("re-pull");
    assert_eq!(repulled.manifest_digest, image.manifest_digest);
    while let Some(event) = progress_rx.recv().await {
        assert!(
            !matches!(event, PullProgress::LayerStarted { .. }),
            "re-pull should not re-download layers"
        );
    }
}

/// The failure a fresh FreeBSD node meets on its first command.
///
/// Against the **real** `docker.io/library/alpine` index, so the platform list
/// in the message is the registry's and not a fixture's: with emulation off,
/// the pull must refuse *and* name the command that fixes it. Unit tests pin
/// the policy; this pins that the refusal survives the whole pull path, index
/// fetch and registry auth included.
#[tokio::test]
#[ignore = "requires network access (docker.io)"]
async fn pull_without_emulation_refuses_and_names_the_fix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ImageStore::open(dir.path().join("images")).expect("open store");
    let reference = ImageReference::parse("docker.io/library/alpine:3.20").expect("parse");

    let error = store
        .pull(&reference, &PlatformPolicy::for_host(false), None)
        .await
        .expect_err("alpine publishes no freebsd platform, so this cannot succeed");

    let rendered = error.to_string();
    eprintln!("{rendered}");
    assert!(
        matches!(error, satl_image::ImageError::LinuxEmulationDisabled { .. }),
        "expected LinuxEmulationDisabled, got {error:?}"
    );
    assert!(
        rendered.contains("linux/amd64 is there")
            && rendered.contains("service linux start")
            && rendered.contains("linux_enable=YES"),
        "the message must be the actionable one: {rendered}"
    );

    // And nothing was written: a refused pull leaves no half-image behind.
    assert!(
        store
            .resolve(&reference)
            .await
            .expect("store read")
            .is_none(),
        "the refused image must not be in the store"
    );
}
