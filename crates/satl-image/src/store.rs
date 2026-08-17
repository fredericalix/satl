// SPDX-License-Identifier: BSD-2-Clause
//! Node-local image content and metadata store.
//!
//! Layout under a configurable root (`/var/db/satl/images` in production;
//! the `images` ZFS dataset, architecture §10):
//!
//! ```text
//! <root>/
//!   blobs/sha256/<hex>          layer blobs, compressed verbatim as
//!                               downloaded (decompression happens in
//!                               satl-storage during layer unpack)
//!   tmp/                        in-flight downloads and atomic-write staging
//!   meta/manifests/<hex>.json   raw manifest/index bytes, digest-addressed
//!   meta/configs/<hex>.json     raw image config bytes, digest-addressed
//!   meta/repositories.json      canonical reference → digests + platform
//! ```
//!
//! All metadata writes are write-to-temp + atomic rename. `satld` is the
//! only writer, so there is no cross-process locking; concurrent pulls
//! *within* the daemon serialize per canonical reference through an
//! in-memory lock map, and `repositories.json` read-modify-write is guarded
//! by a store-wide lock.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info, instrument};

use crate::RegistryAuth;
use crate::RegistryClient;
use crate::error::ImageError;
use crate::manifest::{
    ImageConfig, ImageManifest, LayerCompression, ManifestKind, layer_compression, parse_config,
};
use crate::platform::{Platform, PlatformPolicy};
use crate::reference::{Digest, ImageReference};

/// A locally built image's pieces, for [`ImageStore::register_local`]
/// (M6f, `satl build`). Blobs are staged files under the store's `tmp/`;
/// registration renames them into place and re-reads the image through the
/// pull read path, so a malformed build fails at build time.
#[derive(Debug)]
pub struct LocalImage {
    /// Raw OCI image manifest bytes (`application/vnd.oci.image.manifest.v1+json`).
    pub manifest: Vec<u8>,
    /// Raw OCI image config bytes.
    pub config: Vec<u8>,
    /// Compressed layer blobs as staged files, each with its verified digest.
    pub layers: Vec<(Digest, PathBuf)>,
    /// The platform the image was built for.
    pub platform: Platform,
}

/// One layer of a pulled image: the compressed blob in the store zipped with
/// its uncompressed diff ID from the image config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerDescriptor {
    /// Digest of the compressed blob as stored under `blobs/sha256/`.
    pub blob_digest: Digest,
    /// Digest of the uncompressed tar (config `rootfs.diff_ids`); the input
    /// to OCI chain-ID computation in `satl-storage`.
    pub diff_id: Digest,
    /// The layer's media type, recording its compression.
    pub media_type: String,
    /// Compressed size in bytes (from the manifest descriptor).
    pub size: u64,
}

impl LayerDescriptor {
    /// The compression recorded in [`Self::media_type`].
    pub fn compression(&self) -> Result<LayerCompression, ImageError> {
        layer_compression(&self.media_type)
    }
}

/// What kind of file in the content store a reclaimable item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    /// A layer blob under `blobs/sha256/`.
    Blob,
    /// A manifest or index under `meta/manifests/`.
    Manifest,
    /// An image config under `meta/configs/`.
    Config,
}

impl ContentKind {
    /// The word this kind goes by in operator-facing output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Manifest => "manifest",
            Self::Config => "config",
        }
    }
}

/// One file in the content store that no image record reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFile {
    /// Absolute path, so a caller can delete it without re-deriving the layout.
    pub path: PathBuf,
    /// What it is, for the report.
    pub kind: ContentKind,
    /// The digest hex naming it.
    pub digest: String,
    /// Size in bytes.
    pub size: u64,
}

/// What a content audit found.
///
/// SatL has no untagged image records — `repositories.json` maps a canonical
/// reference to digests and nothing else, so an image with no reference simply
/// has no record. What Docker calls a **dangling** image therefore shows up here
/// instead: blobs, manifests and configs that were reachable until a tag was
/// re-pulled onto a new digest and are now reachable from nothing.
#[derive(Debug, Clone, Default)]
pub struct ContentAudit {
    /// Files no image record reaches, largest first.
    pub unreferenced: Vec<ContentFile>,
    /// How many files *are* reachable, so a report can say what it kept.
    pub referenced: usize,
    /// How many pulls hold a per-reference lock right now. A blob is written
    /// before the `repositories.json` entry that names it, so a pull in flight
    /// makes the reachable set incomplete by construction and nothing may be
    /// deleted on this reading.
    pub pulls_in_flight: usize,
}

impl ContentAudit {
    /// Total bytes the unreferenced files hold.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.unreferenced.iter().map(|file| file.size).sum()
    }
}

/// The result of a pull (or a local [`ImageStore::resolve`]): everything
/// `satl-storage` and `satl-runtime` need to materialize the image.
#[derive(Debug, Clone)]
pub struct PulledImage {
    /// Canonical reference this image was stored under
    /// (e.g. `docker.io/library/alpine:3.20`).
    pub reference: String,
    /// Digest of the (platform-specific) image manifest.
    pub manifest_digest: Digest,
    /// Flattened runnable config (env, entrypoint, cmd, ...).
    pub config: ImageConfig,
    /// The platform that was selected/validated for this node.
    pub platform: Platform,
    /// Layers, base first, blob digests zipped with diff IDs.
    pub layers: Vec<LayerDescriptor>,
    /// The image config's `created` timestamp, when the builder set one.
    /// `None` renders as the epoch in `/images/json` — Docker's own fallback
    /// for a missing field.
    pub created: Option<std::time::SystemTime>,
}

/// Progress events emitted during a pull. The REST API layer will forward
/// these onto the Docker-compatible pull progress stream later.
#[derive(Debug, Clone)]
pub enum PullProgress {
    /// Resolving the reference against the registry.
    Resolving {
        /// Canonical reference being resolved.
        reference: String,
    },
    /// Manifest resolved; platform chosen.
    Resolved {
        /// Digest of the selected image manifest.
        manifest_digest: Digest,
        /// The platform that was selected.
        platform: Platform,
    },
    /// A layer download started.
    LayerStarted {
        /// Blob digest of the layer.
        digest: Digest,
        /// Compressed size in bytes.
        size: u64,
    },
    /// A layer was already present in the store (not re-downloaded).
    LayerAlreadyPresent {
        /// Blob digest of the layer.
        digest: Digest,
    },
    /// A layer finished downloading and verified.
    LayerDone {
        /// Blob digest of the layer.
        digest: Digest,
    },
    /// The pull completed and metadata was recorded.
    Complete {
        /// Digest of the selected image manifest.
        manifest_digest: Digest,
    },
}

/// Channel end used to report [`PullProgress`] events.
pub type ProgressSender = tokio::sync::mpsc::UnboundedSender<PullProgress>;

/// `repositories.json` content.
#[derive(Debug, Default, Serialize, Deserialize)]
struct RepositoriesFile {
    repositories: std::collections::BTreeMap<String, RepositoryEntry>,
}

/// One `repositories.json` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepositoryEntry {
    /// Digest of the index / manifest list the manifest was selected from,
    /// when the reference resolved through one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest_list_digest: Option<Digest>,
    /// Digest of the platform-specific manifest.
    manifest_digest: Digest,
    /// The platform selected at pull time.
    platform: Platform,
}

/// Counter for unique temp-file names within the process.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The image content + metadata store.
pub struct ImageStore {
    root: PathBuf,
    /// Per-canonical-reference pull serialization. Entries are never
    /// removed; the map is bounded by the number of distinct references
    /// pulled over the daemon's lifetime.
    pull_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Guards read-modify-write of `repositories.json`.
    repositories_lock: Mutex<()>,
}

impl ImageStore {
    /// Opens (creating if needed) a store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ImageError> {
        let root = root.into();
        for dir in [
            root.join("blobs").join("sha256"),
            root.join("tmp"),
            root.join("meta").join("manifests"),
            root.join("meta").join("configs"),
        ] {
            std::fs::create_dir_all(&dir).map_err(|source| ImageError::io(&dir, source))?;
        }
        Ok(Self {
            root,
            pull_locks: Mutex::new(HashMap::new()),
            repositories_lock: Mutex::new(()),
        })
    }

    /// Path of a (present or future) blob in the store.
    #[must_use]
    pub fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.root.join("blobs").join("sha256").join(digest.hex())
    }

    /// Stage a blob file under the store's `tmp/` for [`Self::register_local`]
    /// (moved when possible, copied across filesystems).
    pub async fn stage_blob(&self, source: &Path) -> Result<PathBuf, std::io::Error> {
        let target = self.tmp_path("blob");
        if tokio::fs::rename(source, &target).await.is_ok() {
            return Ok(target);
        }
        tokio::fs::copy(source, &target).await?;
        Ok(target)
    }

    /// Pulls `reference` for `policy`, storing blobs and metadata.
    ///
    /// Idempotent: blobs already in the store are not re-downloaded; a
    /// re-pull refreshes the metadata (tag moves are picked up).
    pub async fn pull(
        &self,
        reference: &ImageReference,
        policy: &PlatformPolicy,
        auth: Option<RegistryAuth>,
    ) -> Result<PulledImage, ImageError> {
        self.pull_with_progress(reference, policy, auth, None).await
    }

    /// [`Self::pull`] with progress reporting.
    #[instrument(
        name = "image.pull",
        skip(self, policy, auth, progress),
        fields(reference = %reference, registry = %reference.registry)
    )]
    pub async fn pull_with_progress(
        &self,
        reference: &ImageReference,
        policy: &PlatformPolicy,
        auth: Option<RegistryAuth>,
        progress: Option<ProgressSender>,
    ) -> Result<PulledImage, ImageError> {
        let canonical = reference.canonical();

        // Serialize concurrent pulls of the same reference.
        let ref_lock = {
            let mut locks = self.pull_locks.lock().await;
            Arc::clone(locks.entry(canonical.clone()).or_default())
        };
        let _pull_guard = ref_lock.lock().await;

        send_progress(
            progress.as_ref(),
            PullProgress::Resolving {
                reference: canonical.clone(),
            },
        );

        let client = RegistryClient::for_reference(reference, auth)?;

        // 1. Resolve the manifest, going through an index if there is one.
        let resolved = resolve_remote_manifest(&client, reference, policy, &canonical).await?;

        // 2. Fetch and parse the image config.
        let config_bytes = self
            .fetch_config(&client, &resolved.manifest.config.digest)
            .await?;
        let parsed_config = parse_config(&config_bytes, &canonical)?;

        // For single-manifest images the config carries the only platform
        // information there is; it must satisfy the policy.
        let platform = if let Some(platform) = resolved.platform {
            platform
        } else {
            policy.validate(&parsed_config.platform, &canonical)?;
            parsed_config.platform.clone()
        };
        let (index_raw, manifest_raw, manifest) =
            (resolved.index_raw, resolved.manifest_raw, resolved.manifest);
        send_progress(
            progress.as_ref(),
            PullProgress::Resolved {
                manifest_digest: manifest_raw.digest.clone(),
                platform: platform.clone(),
            },
        );

        // 3. Zip manifest layers with config diff IDs.
        let layers = zip_layers(&manifest, &parsed_config.diff_ids, &canonical)?;

        // 4. Download missing layer blobs.
        self.download_layers(&client, &layers, progress.as_ref())
            .await?;

        // 5. Persist metadata (manifest, index, repositories.json).
        self.write_meta_atomic(
            &self.manifest_meta_path(&manifest_raw.digest),
            &manifest_raw.bytes,
        )
        .await?;
        let manifest_list_digest = match &index_raw {
            Some(index) => {
                self.write_meta_atomic(&self.manifest_meta_path(&index.digest), &index.bytes)
                    .await?;
                Some(index.digest.clone())
            }
            None => None,
        };
        self.record_repository(
            &canonical,
            RepositoryEntry {
                manifest_list_digest,
                manifest_digest: manifest_raw.digest.clone(),
                platform: platform.clone(),
            },
        )
        .await?;

        send_progress(
            progress.as_ref(),
            PullProgress::Complete {
                manifest_digest: manifest_raw.digest.clone(),
            },
        );
        info!(
            manifest_digest = %manifest_raw.digest,
            platform = %platform,
            layers = layers.len(),
            "image pulled"
        );

        Ok(PulledImage {
            reference: canonical,
            manifest_digest: manifest_raw.digest.clone(),
            config: parsed_config.config,
            platform,
            layers,
            created: parsed_config.created,
        })
    }

    /// Registers a locally built image (M6f, `satl build`): layer blobs
    /// staged under `tmp/`, raw manifest and config bytes. Digests are
    /// verified on the way in, and the result is re-loaded through the same
    /// read path a pull lands on, so a malformed registration fails here
    /// rather than at container start.
    ///
    /// **A second writer exists since M6f**: `satl build` writes through this
    /// method while the daemon may be pulling. The in-memory pull locks do
    /// not cover another process; the accepted window is a concurrent pull of
    /// the *same* reference interleaving with a build of it — both writers
    /// produce the same content-addressed blobs, and `repositories.json` is
    /// last-writer-wins.
    pub async fn register_local(
        &self,
        reference: &ImageReference,
        image: LocalImage,
    ) -> Result<PulledImage, ImageError> {
        let canonical = reference.canonical();
        for (digest, staged) in &image.layers {
            let final_path = self.blob_path(digest);
            if final_path.exists() {
                continue;
            }
            tokio::fs::rename(staged, &final_path)
                .await
                .map_err(|source| ImageError::io(&final_path, source))?;
        }
        let config_digest = Digest::sha256_of(&image.config);
        self.write_meta_atomic(&self.config_meta_path(&config_digest), &image.config)
            .await?;
        let manifest_digest = Digest::sha256_of(&image.manifest);
        self.write_meta_atomic(&self.manifest_meta_path(&manifest_digest), &image.manifest)
            .await?;
        self.record_repository(
            &canonical,
            RepositoryEntry {
                manifest_list_digest: None,
                manifest_digest: manifest_digest.clone(),
                platform: image.platform.clone(),
            },
        )
        .await?;
        info!(
            reference = %canonical,
            manifest_digest = %manifest_digest,
            "locally built image registered"
        );
        let repositories = self.read_repositories().await?;
        let entry = repositories
            .repositories
            .get(&canonical)
            .expect("just written");
        self.load_image(&canonical, entry).await
    }

    /// Makes `target` an additional reference to the image `source` names
    /// (`satl tag`, `POST /images/{name}/tag`).
    ///
    /// A tag is one more `repositories.json` entry pointing at the *same*
    /// digests and platform — no blob is copied, both names keep working and
    /// both show up in [`Self::list`], exactly Docker's semantics. Tagging an
    /// image with the name it already has is a no-op success (also Docker's),
    /// but the source must exist either way.
    ///
    /// The write takes the target's per-reference lock — the discipline
    /// [`Self::pull_with_progress`] sets — so a concurrent pull of the target
    /// cannot interleave with the alias write, and a content audit taken
    /// mid-tag reports a writer in flight and reclaims nothing on that
    /// reading.
    #[instrument(
        name = "image.tag",
        skip(self),
        fields(source = %source, target = %target)
    )]
    pub async fn tag(
        &self,
        source: &ImageReference,
        target: &ImageReference,
    ) -> Result<(), ImageError> {
        let source_canonical = source.canonical();
        let target_canonical = target.canonical();

        let ref_lock = {
            let mut locks = self.pull_locks.lock().await;
            Arc::clone(locks.entry(target_canonical.clone()).or_default())
        };
        let _tag_guard = ref_lock.lock().await;

        let entry = {
            let repositories = self.read_repositories().await?;
            repositories
                .repositories
                .get(&source_canonical)
                .ok_or_else(|| ImageError::NotFound {
                    reference: source_canonical.clone(),
                })?
                .clone()
        };
        if source_canonical == target_canonical {
            return Ok(());
        }
        self.record_repository(&target_canonical, entry).await?;
        info!(source = %source_canonical, target = %target_canonical, "image tagged");
        Ok(())
    }

    /// Push a locally stored image to its registry (M8a): every blob the
    /// registry does not already hold (config, then layers), then the
    /// manifest under the reference's tag.
    ///
    /// The reference's registry prefix is the destination — pushing
    /// `registry.example.com/app:1` pushes there; a bare name goes to Docker
    /// Hub, as everywhere else in SatL. Client-side and node-local, like
    /// `satl build`: the store is this node's, and so is what it pushes.
    pub async fn push(
        &self,
        reference: &ImageReference,
        credentials: Option<RegistryAuth>,
    ) -> Result<Digest, ImageError> {
        let canonical = reference.canonical();
        let repositories = self.read_repositories().await?;
        let entry =
            repositories
                .repositories
                .get(&canonical)
                .ok_or_else(|| ImageError::NotFound {
                    reference: canonical.clone(),
                })?;
        let manifest_bytes = tokio::fs::read(self.manifest_meta_path(&entry.manifest_digest))
            .await
            .map_err(|source| ImageError::io(self.repositories_path(), source))?;
        let manifest: crate::manifest::ImageManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|source| ImageError::Parse {
                what: "stored image manifest",
                reference: canonical.clone(),
                source,
            })?;

        let client = RegistryClient::for_push(reference, credentials)?;
        // Blobs first, manifest last: a registry may refuse a manifest that
        // references blobs it does not hold yet.
        let mut blobs: Vec<(Digest, PathBuf)> = Vec::new();
        blobs.push((
            manifest.config.digest.clone(),
            self.config_meta_path(&manifest.config.digest),
        ));
        for layer in &manifest.layers {
            blobs.push((layer.digest.clone(), self.blob_path(&layer.digest)));
        }
        for (digest, path) in blobs {
            if client.blob_exists(&digest).await? {
                debug!(%digest, "blob already in the registry; skipped");
                continue;
            }
            let bytes = tokio::fs::read(&path)
                .await
                .map_err(|source| ImageError::io(&path, source))?;
            client.push_blob(&digest, bytes).await?;
        }
        let media_type = if manifest.media_type.is_empty() {
            "application/vnd.oci.image.manifest.v1+json"
        } else {
            manifest.media_type.as_str()
        };
        client
            .put_manifest(&reference.tag, media_type, manifest_bytes)
            .await?;
        info!(reference = %canonical, manifest_digest = %entry.manifest_digest, "image pushed");
        Ok(entry.manifest_digest.clone())
    }

    /// Downloads the layer blobs that are not yet in the store.
    async fn download_layers(
        &self,
        client: &RegistryClient,
        layers: &[LayerDescriptor],
        progress: Option<&ProgressSender>,
    ) -> Result<(), ImageError> {
        for layer in layers {
            let final_path = self.blob_path(&layer.blob_digest);
            if blob_present(&final_path, layer.size).await {
                debug!(digest = %layer.blob_digest, "layer blob already present");
                send_progress(
                    progress,
                    PullProgress::LayerAlreadyPresent {
                        digest: layer.blob_digest.clone(),
                    },
                );
                continue;
            }
            send_progress(
                progress,
                PullProgress::LayerStarted {
                    digest: layer.blob_digest.clone(),
                    size: layer.size,
                },
            );
            let tmp_path = self.tmp_path("blob");
            client
                .get_blob(&layer.blob_digest, &tmp_path, &final_path)
                .await?;
            send_progress(
                progress,
                PullProgress::LayerDone {
                    digest: layer.blob_digest.clone(),
                },
            );
        }
        Ok(())
    }

    /// Resolves a reference from local metadata only (no network).
    pub async fn resolve(
        &self,
        reference: &ImageReference,
    ) -> Result<Option<PulledImage>, ImageError> {
        let canonical = reference.canonical();
        let repositories = self.read_repositories().await?;
        match repositories.repositories.get(&canonical) {
            Some(entry) => self.load_image(&canonical, entry).await.map(Some),
            None => Ok(None),
        }
    }

    /// Lists all locally stored images.
    pub async fn list(&self) -> Result<Vec<PulledImage>, ImageError> {
        let repositories = self.read_repositories().await?;
        let mut images = Vec::with_capacity(repositories.repositories.len());
        for (canonical, entry) in &repositories.repositories {
            images.push(self.load_image(canonical, entry).await?);
        }
        Ok(images)
    }

    /// Forget the image record for `canonical`; `Ok(false)` when there was none.
    ///
    /// **The record goes first and the content stays.** `load_image` treats a
    /// missing manifest or config as [`ImageError::StoreCorrupt`], so deleting
    /// content before the entry that points at it would break [`Self::list`],
    /// `/images/json` and `/info` for every image in the store, not just this
    /// one. Removing the entry makes the content unreachable, and
    /// [`Self::audit_content`] is what then finds it.
    ///
    /// # Errors
    ///
    /// [`ImageError`] when `repositories.json` cannot be read or rewritten.
    pub async fn remove(&self, canonical: &str) -> Result<bool, ImageError> {
        let _guard = self.repositories_lock.lock().await;
        let mut repositories = self.read_repositories().await?;
        if repositories.repositories.remove(canonical).is_none() {
            return Ok(false);
        }
        let bytes =
            serde_json::to_vec_pretty(&repositories).map_err(|source| ImageError::Parse {
                what: "repositories.json",
                reference: canonical.to_owned(),
                source,
            })?;
        self.write_meta_atomic(&self.repositories_path(), &bytes)
            .await?;
        info!(reference = %canonical, "image record removed");
        Ok(true)
    }

    /// How many pulls are holding a per-reference lock right now.
    ///
    /// The claim set for content reclamation is only complete when this is
    /// zero: a pull writes blobs, then the manifest, then the config, and only
    /// then the `repositories.json` entry that makes any of it reachable.
    #[must_use]
    pub fn pulls_in_flight(&self) -> usize {
        // A contended map means a pull is doing exactly the bookkeeping that
        // would make this count wrong; report it as busy.
        let Ok(locks) = self.pull_locks.try_lock() else {
            return 1;
        };
        locks
            .values()
            .filter(|lock| lock.try_lock().is_err())
            .count()
    }

    /// Which files in the content store no image record reaches.
    ///
    /// Reachability is one hop per level: every record names a manifest (and
    /// possibly the index it was selected from), a manifest names a config and
    /// a set of layer blobs. Anything on disk outside that closure is content a
    /// re-pulled tag left behind.
    ///
    /// A record whose manifest or config is already missing is **skipped with a
    /// warning rather than failing the audit**: that store is already corrupt,
    /// and refusing to reclaim anything until an operator repairs it by hand is
    /// the opposite of useful. What such a record cannot do is make its blobs
    /// look unreachable, because its own layers are then unknown — so the audit
    /// reports the corruption and returns nothing at all for safety.
    ///
    /// # Errors
    ///
    /// [`ImageError`] when the metadata cannot be read or a directory cannot be
    /// walked.
    pub async fn audit_content(&self) -> Result<ContentAudit, ImageError> {
        let pulls_in_flight = self.pulls_in_flight();
        let repositories = self.read_repositories().await?;
        let mut manifests: BTreeSet<String> = BTreeSet::new();
        let mut configs: BTreeSet<String> = BTreeSet::new();
        let mut blobs: BTreeSet<String> = BTreeSet::new();
        let mut corrupt = false;

        for (canonical, entry) in &repositories.repositories {
            manifests.insert(entry.manifest_digest.hex().to_owned());
            if let Some(list) = &entry.manifest_list_digest {
                manifests.insert(list.hex().to_owned());
            }
            let path = self.manifest_meta_path(&entry.manifest_digest);
            let bytes = match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    tracing::warn!(
                        reference = %canonical,
                        manifest = %entry.manifest_digest,
                        "image record points at a missing manifest; its layers cannot be \
                         accounted for, so nothing will be reclaimed on this pass"
                    );
                    corrupt = true;
                    continue;
                }
                Err(source) => return Err(ImageError::io(&path, source)),
            };
            let manifest = parse_image_manifest(&bytes, "", canonical)?;
            configs.insert(manifest.config.digest.hex().to_owned());
            for layer in &manifest.layers {
                blobs.insert(layer.digest.hex().to_owned());
            }
        }

        let referenced = manifests.len() + configs.len() + blobs.len();
        if corrupt {
            return Ok(ContentAudit {
                unreferenced: Vec::new(),
                referenced,
                pulls_in_flight,
            });
        }

        let mut unreferenced = Vec::new();
        for (dir, kind, keep, suffix) in [
            (
                self.root.join("blobs").join("sha256"),
                ContentKind::Blob,
                &blobs,
                "",
            ),
            (
                self.root.join("meta").join("manifests"),
                ContentKind::Manifest,
                &manifests,
                ".json",
            ),
            (
                self.root.join("meta").join("configs"),
                ContentKind::Config,
                &configs,
                ".json",
            ),
        ] {
            unreferenced.extend(unreferenced_in(&dir, kind, keep, suffix).await?);
        }
        unreferenced.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.digest.cmp(&b.digest)));
        Ok(ContentAudit {
            unreferenced,
            referenced,
            pulls_in_flight,
        })
    }

    /// Delete one file the audit reported unreferenced. "Already gone" is
    /// success: two passes over the same reading must not disagree.
    ///
    /// # Errors
    ///
    /// [`ImageError`] when the file exists and cannot be removed.
    pub async fn remove_content(&self, file: &ContentFile) -> Result<(), ImageError> {
        match tokio::fs::remove_file(&file.path).await {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(ImageError::io(&file.path, source)),
        }
    }

    /// Rebuilds a [`PulledImage`] from stored manifest + config bytes.
    async fn load_image(
        &self,
        canonical: &str,
        entry: &RepositoryEntry,
    ) -> Result<PulledImage, ImageError> {
        let manifest_path = self.manifest_meta_path(&entry.manifest_digest);
        let manifest_bytes = tokio::fs::read(&manifest_path).await.map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                ImageError::StoreCorrupt {
                    reason: format!(
                        "repositories.json entry {canonical} points at missing manifest {}",
                        entry.manifest_digest
                    ),
                }
            } else {
                ImageError::io(&manifest_path, source)
            }
        })?;
        let manifest = parse_image_manifest(&manifest_bytes, "", canonical)?;

        let config_path = self.config_meta_path(&manifest.config.digest);
        let config_bytes = tokio::fs::read(&config_path).await.map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                ImageError::StoreCorrupt {
                    reason: format!(
                        "manifest {} of {canonical} points at missing config {}",
                        entry.manifest_digest, manifest.config.digest
                    ),
                }
            } else {
                ImageError::io(&config_path, source)
            }
        })?;
        let parsed_config = parse_config(&config_bytes, canonical)?;
        let layers = zip_layers(&manifest, &parsed_config.diff_ids, canonical)?;

        Ok(PulledImage {
            reference: canonical.to_owned(),
            manifest_digest: entry.manifest_digest.clone(),
            config: parsed_config.config,
            platform: entry.platform.clone(),
            layers,
            created: parsed_config.created,
        })
    }

    /// Fetches the config blob into `meta/configs/`, or reuses a verified
    /// existing copy.
    async fn fetch_config(
        &self,
        client: &RegistryClient,
        digest: &Digest,
    ) -> Result<Vec<u8>, ImageError> {
        let final_path = self.config_meta_path(digest);
        if let Ok(existing) = tokio::fs::read(&final_path).await {
            if Digest::sha256_of(&existing) == *digest {
                debug!(%digest, "image config already present");
                return Ok(existing);
            }
            // Corrupt cached config: re-download below.
            debug!(%digest, "cached image config failed verification, refetching");
        }
        let tmp_path = self.tmp_path("config");
        client.get_blob(digest, &tmp_path, &final_path).await?;
        // get_blob verified the digest before renaming the file into place.
        tokio::fs::read(&final_path)
            .await
            .map_err(|source| ImageError::io(&final_path, source))
    }

    /// Inserts/overwrites a `repositories.json` entry (read-modify-write
    /// under the store-wide lock, atomic rename).
    async fn record_repository(
        &self,
        canonical: &str,
        entry: RepositoryEntry,
    ) -> Result<(), ImageError> {
        let _guard = self.repositories_lock.lock().await;
        let mut repositories = self.read_repositories().await?;
        repositories
            .repositories
            .insert(canonical.to_owned(), entry);
        let bytes =
            serde_json::to_vec_pretty(&repositories).map_err(|source| ImageError::Parse {
                what: "repositories.json",
                reference: canonical.to_owned(),
                source,
            })?;
        self.write_meta_atomic(&self.repositories_path(), &bytes)
            .await
    }

    /// Reads `repositories.json` (empty map if absent).
    async fn read_repositories(&self) -> Result<RepositoriesFile, ImageError> {
        let path = self.repositories_path();
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RepositoriesFile::default());
            }
            Err(source) => return Err(ImageError::io(&path, source)),
        };
        serde_json::from_slice(&bytes).map_err(|source| ImageError::Parse {
            what: "repositories.json",
            reference: path.display().to_string(),
            source,
        })
    }

    /// Writes `bytes` to `path` via a unique temp file in `tmp/` plus an
    /// atomic rename (same filesystem: `tmp/` lives under the store root).
    async fn write_meta_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), ImageError> {
        let tmp_path = self.tmp_path("meta");
        tokio::fs::write(&tmp_path, bytes)
            .await
            .map_err(|source| ImageError::io(&tmp_path, source))?;
        tokio::fs::rename(&tmp_path, path)
            .await
            .map_err(|source| ImageError::io(path, source))
    }

    /// A unique path in the store's staging directory.
    fn tmp_path(&self, kind: &str) -> PathBuf {
        let unique = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.root
            .join("tmp")
            .join(format!("{kind}-{}-{unique}", std::process::id()))
    }

    fn repositories_path(&self) -> PathBuf {
        self.root.join("meta").join("repositories.json")
    }

    fn manifest_meta_path(&self, digest: &Digest) -> PathBuf {
        self.root
            .join("meta")
            .join("manifests")
            .join(format!("{}.json", digest.hex()))
    }

    fn config_meta_path(&self, digest: &Digest) -> PathBuf {
        self.root
            .join("meta")
            .join("configs")
            .join(format!("{}.json", digest.hex()))
    }
}

/// The files in `dir` whose digest (file stem, once `suffix` is stripped) is
/// not in `keep`. A missing directory is empty, not an error: a store that has
/// never held a config has no `meta/configs`.
async fn unreferenced_in(
    dir: &Path,
    kind: ContentKind,
    keep: &BTreeSet<String>,
    suffix: &str,
) -> Result<Vec<ContentFile>, ImageError> {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(ImageError::io(dir, source)),
    };
    let mut out = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|source| ImageError::io(dir, source))?
    {
        let path = entry.path();
        let metadata = match entry.metadata().await {
            Ok(metadata) if metadata.is_file() => metadata,
            // A directory here is not ours, and a file that vanished between
            // read_dir and stat is already reclaimed.
            _ => continue,
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(digest) = name.strip_suffix(suffix) else {
            continue;
        };
        if keep.contains(digest) {
            continue;
        }
        out.push(ContentFile {
            path,
            kind,
            digest: digest.to_owned(),
            size: metadata.len(),
        });
    }
    Ok(out)
}

/// Outcome of resolving a reference against the registry: the raw documents
/// plus the platform chosen from the index (if there was one).
struct ResolvedManifest {
    /// The raw index/manifest-list response, when the reference resolved
    /// through one.
    index_raw: Option<crate::client::FetchedManifest>,
    /// The raw platform-specific manifest response.
    manifest_raw: crate::client::FetchedManifest,
    /// The parsed platform-specific manifest.
    manifest: ImageManifest,
    /// The platform selected from the index; `None` for single-manifest
    /// images (the config's platform is validated instead).
    platform: Option<Platform>,
}

/// Fetches the manifest for `reference`, selecting a platform when the
/// registry answers with an index / manifest list.
async fn resolve_remote_manifest(
    client: &RegistryClient,
    reference: &ImageReference,
    policy: &PlatformPolicy,
    canonical: &str,
) -> Result<ResolvedManifest, ImageError> {
    let first = client.get_manifest(reference.manifest_reference()).await?;
    match ManifestKind::parse(&first.bytes, &first.media_type, canonical)? {
        ManifestKind::Index(index) => {
            let platforms = index.platforms();
            let chosen = policy.select(&platforms, canonical)?.clone();
            let entry = index
                .entry_for(&chosen)
                .ok_or_else(|| ImageError::StoreCorrupt {
                    reason: format!(
                        "selected platform {chosen} vanished from index of {canonical}"
                    ),
                })?;
            let fetched = client.get_manifest(entry.digest.as_str()).await?;
            let manifest = parse_image_manifest(&fetched.bytes, &fetched.media_type, canonical)?;
            Ok(ResolvedManifest {
                index_raw: Some(first),
                manifest_raw: fetched,
                manifest,
                platform: Some(chosen),
            })
        }
        ManifestKind::Manifest(manifest) => Ok(ResolvedManifest {
            index_raw: None,
            manifest_raw: first,
            manifest,
            platform: None,
        }),
    }
}

/// Parses bytes that must be a single-platform image manifest.
fn parse_image_manifest(
    bytes: &[u8],
    media_type: &str,
    reference: &str,
) -> Result<ImageManifest, ImageError> {
    match ManifestKind::parse(bytes, media_type, reference)? {
        ManifestKind::Manifest(manifest) => Ok(manifest),
        ManifestKind::Index(_) => Err(ImageError::UnsupportedMediaType {
            media_type: media_type.to_owned(),
            context: format!("nested image index for {reference} (expected an image manifest)"),
        }),
    }
}

/// Zips manifest layers with config diff IDs, validating counts and media
/// types.
fn zip_layers(
    manifest: &ImageManifest,
    diff_ids: &[Digest],
    reference: &str,
) -> Result<Vec<LayerDescriptor>, ImageError> {
    if manifest.layers.len() != diff_ids.len() {
        return Err(ImageError::LayerCountMismatch {
            reference: reference.to_owned(),
            manifest_layers: manifest.layers.len(),
            diff_ids: diff_ids.len(),
        });
    }
    manifest
        .layers
        .iter()
        .zip(diff_ids)
        .map(|(descriptor, diff_id)| {
            // Reject media types we cannot classify now rather than at
            // unpack time in satl-storage.
            layer_compression(&descriptor.media_type)?;
            Ok(LayerDescriptor {
                blob_digest: descriptor.digest.clone(),
                diff_id: diff_id.clone(),
                media_type: descriptor.media_type.clone(),
                size: descriptor.size,
            })
        })
        .collect()
}

/// Whether a verified blob is already on disk (existence + size check; the
/// store only ever places digest-verified blobs via atomic rename).
async fn blob_present(path: &Path, expected_size: u64) -> bool {
    match tokio::fs::metadata(path).await {
        Ok(meta) => expected_size == 0 || meta.len() == expected_size,
        Err(_) => false,
    }
}

fn send_progress(sender: Option<&ProgressSender>, event: PullProgress) {
    if let Some(sender) = sender {
        // A dropped receiver must not fail the pull.
        let _ = sender.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPINE_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/alpine-manifest.json");
    const ALPINE_CONFIG: &[u8] = include_bytes!("../tests/fixtures/alpine-config.json");
    const ALPINE_MANIFEST_DIGEST: &str =
        "sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e";
    const ALPINE_CONFIG_DIGEST: &str =
        "sha256:bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731";

    fn open_temp_store() -> (tempfile::TempDir, ImageStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::open(dir.path().join("images")).unwrap();
        (dir, store)
    }

    /// Plants the alpine fixture metadata as a completed pull would.
    async fn plant_alpine(store: &ImageStore, canonical: &str) {
        let manifest_digest: Digest = ALPINE_MANIFEST_DIGEST.parse().unwrap();
        let config_digest: Digest = ALPINE_CONFIG_DIGEST.parse().unwrap();
        store
            .write_meta_atomic(&store.manifest_meta_path(&manifest_digest), ALPINE_MANIFEST)
            .await
            .unwrap();
        store
            .write_meta_atomic(&store.config_meta_path(&config_digest), ALPINE_CONFIG)
            .await
            .unwrap();
        store
            .record_repository(
                canonical,
                RepositoryEntry {
                    manifest_list_digest: None,
                    manifest_digest,
                    platform: Platform::new("linux", "amd64"),
                },
            )
            .await
            .unwrap();
    }

    #[test]
    fn open_creates_layout() {
        let (_dir, store) = open_temp_store();
        for sub in ["blobs/sha256", "tmp", "meta/manifests", "meta/configs"] {
            assert!(store.root.join(sub).is_dir(), "{sub} missing");
        }
    }

    #[test]
    fn blob_path_shape() {
        let (_dir, store) = open_temp_store();
        let digest: Digest = ALPINE_CONFIG_DIGEST.parse().unwrap();
        let path = store.blob_path(&digest);
        assert!(path.ends_with(PathBuf::from("blobs/sha256").join(digest.hex())));
    }

    #[tokio::test]
    async fn store_roundtrip_resolve_and_list() {
        let (_dir, store) = open_temp_store();
        let reference = ImageReference::parse("alpine:3.20").unwrap();
        let canonical = reference.canonical();
        plant_alpine(&store, &canonical).await;

        let resolved = store.resolve(&reference).await.unwrap().unwrap();
        assert_eq!(resolved.reference, canonical);
        assert_eq!(resolved.manifest_digest.as_str(), ALPINE_MANIFEST_DIGEST);
        assert_eq!(resolved.platform.to_string(), "linux/amd64");
        assert_eq!(resolved.config.cmd, ["/bin/sh"]);
        assert_eq!(resolved.layers.len(), 1);
        assert_eq!(
            resolved.layers[0].compression().unwrap(),
            LayerCompression::Gzip
        );
        // diff_id comes from the config, blob digest from the manifest.
        assert_ne!(resolved.layers[0].blob_digest, resolved.layers[0].diff_id);

        let listed = store.list().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].reference, canonical);

        // An unknown reference resolves to None.
        let other = ImageReference::parse("alpine:edge").unwrap();
        assert!(store.resolve(&other).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn repositories_json_updates_are_atomic_and_additive() {
        let (_dir, store) = open_temp_store();
        let manifest_digest: Digest = ALPINE_MANIFEST_DIGEST.parse().unwrap();
        let entry = |platform: Platform| RepositoryEntry {
            manifest_list_digest: None,
            manifest_digest: manifest_digest.clone(),
            platform,
        };
        store
            .record_repository(
                "docker.io/library/a:1",
                entry(Platform::new("linux", "amd64")),
            )
            .await
            .unwrap();
        store
            .record_repository(
                "docker.io/library/b:2",
                entry(Platform::new("freebsd", "amd64")),
            )
            .await
            .unwrap();
        // Overwrite refreshes an existing entry (re-pull semantics).
        store
            .record_repository(
                "docker.io/library/a:1",
                entry(Platform::new("freebsd", "amd64")),
            )
            .await
            .unwrap();

        let repositories = store.read_repositories().await.unwrap();
        assert_eq!(repositories.repositories.len(), 2);
        assert_eq!(
            repositories.repositories["docker.io/library/a:1"]
                .platform
                .to_string(),
            "freebsd/amd64"
        );

        // No stray temp files: every write renamed its staging file away.
        let mut tmp_entries = tokio::fs::read_dir(store.root.join("tmp")).await.unwrap();
        assert!(
            tmp_entries.next_entry().await.unwrap().is_none(),
            "staging directory must be empty after atomic writes"
        );

        // And the final file is valid JSON on disk.
        let raw = tokio::fs::read(store.repositories_path()).await.unwrap();
        let parsed: RepositoriesFile = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed.repositories.len(), 2);
    }

    #[tokio::test]
    async fn missing_manifest_is_reported_as_store_corruption() {
        let (_dir, store) = open_temp_store();
        let manifest_digest: Digest = ALPINE_MANIFEST_DIGEST.parse().unwrap();
        store
            .record_repository(
                "docker.io/library/ghost:1",
                RepositoryEntry {
                    manifest_list_digest: None,
                    manifest_digest,
                    platform: Platform::new("linux", "amd64"),
                },
            )
            .await
            .unwrap();
        let reference = ImageReference::parse("ghost:1").unwrap();
        let err = store.resolve(&reference).await.unwrap_err();
        assert!(
            matches!(err, ImageError::StoreCorrupt { .. }),
            "expected StoreCorrupt, got {err}"
        );
    }

    #[tokio::test]
    async fn zip_layers_validates_counts_and_media_types() {
        let manifest = parse_image_manifest(ALPINE_MANIFEST, "", "alpine").unwrap();
        let no_ids: [Digest; 0] = [];
        let err = zip_layers(&manifest, &no_ids, "alpine").unwrap_err();
        assert!(
            matches!(
                err,
                ImageError::LayerCountMismatch {
                    manifest_layers: 1,
                    diff_ids: 0,
                    ..
                }
            ),
            "got {err}"
        );

        let diff_ids = [Digest::sha256_of(b"layer0")];
        let layers = zip_layers(&manifest, &diff_ids, "alpine").unwrap();
        assert_eq!(layers[0].diff_id, diff_ids[0]);
        assert_eq!(layers[0].size, 3_630_321);
    }

    // ---- content reclamation ----------------------------------------------

    const ALPINE_LAYER_DIGEST: &str =
        "sha256:25f1d6b1951ac8eb3740558fe94cb83d377bdadf95fd9f98b50d2e1b96130471";

    /// Write a blob file with `bytes` of content under its digest.
    async fn plant_blob(store: &ImageStore, digest: &str, bytes: usize) {
        let digest: Digest = digest.parse().unwrap();
        tokio::fs::write(store.blob_path(&digest), vec![0u8; bytes])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_stored_image_makes_its_manifest_config_and_blobs_reachable() {
        let (_dir, store) = open_temp_store();
        plant_alpine(&store, "docker.io/library/alpine:3.20").await;
        plant_blob(&store, ALPINE_LAYER_DIGEST, 4096).await;

        let audit = store.audit_content().await.unwrap();
        assert!(
            audit.unreferenced.is_empty(),
            "nothing may be reclaimed while the record points at it: {:?}",
            audit.unreferenced
        );
        // manifest + config + one layer blob.
        assert_eq!(audit.referenced, 3);
        assert_eq!(audit.pulls_in_flight, 0);
    }

    /// What Docker calls a dangling image: the tag was re-pulled onto a new
    /// digest, `repositories.json` was overwritten in place, and the old
    /// content is now reachable from nothing.
    #[tokio::test]
    async fn content_a_moved_tag_left_behind_is_unreferenced() {
        let (_dir, store) = open_temp_store();
        plant_alpine(&store, "docker.io/library/alpine:3.20").await;
        plant_blob(&store, ALPINE_LAYER_DIGEST, 4096).await;
        // A blob from the tag's previous digest, no longer named by anything.
        let orphan = Digest::sha256_of(b"an older layer nothing points at");
        tokio::fs::write(store.blob_path(&orphan), vec![7u8; 8192])
            .await
            .unwrap();

        let audit = store.audit_content().await.unwrap();
        assert_eq!(audit.unreferenced.len(), 1, "{:?}", audit.unreferenced);
        let file = &audit.unreferenced[0];
        assert_eq!(file.kind, ContentKind::Blob);
        assert_eq!(file.digest, orphan.hex());
        assert_eq!(file.size, 8192);
        assert_eq!(audit.bytes(), 8192);

        store.remove_content(file).await.unwrap();
        assert!(!file.path.exists());
        // Deleting twice is not a failure: two passes read the same list.
        store.remove_content(file).await.unwrap();
        // And the live blob was never touched.
        assert!(
            store
                .blob_path(&ALPINE_LAYER_DIGEST.parse::<Digest>().unwrap())
                .exists()
        );
    }

    /// Removing the record is what makes content unreclaimable-to-reachable,
    /// and the order matters: the record first, always.
    #[tokio::test]
    async fn removing_the_record_makes_its_whole_stack_unreferenced() {
        let (_dir, store) = open_temp_store();
        plant_alpine(&store, "docker.io/library/alpine:3.20").await;
        plant_blob(&store, ALPINE_LAYER_DIGEST, 4096).await;

        assert!(store.remove("docker.io/library/alpine:3.20").await.unwrap());
        assert!(
            !store.remove("docker.io/library/alpine:3.20").await.unwrap(),
            "removing a record twice reports that there was none"
        );
        assert!(store.list().await.unwrap().is_empty());

        let audit = store.audit_content().await.unwrap();
        assert_eq!(audit.referenced, 0);
        let kinds: std::collections::BTreeSet<&str> = audit
            .unreferenced
            .iter()
            .map(|file| file.kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            std::collections::BTreeSet::from(["blob", "config", "manifest"]),
            "{:?}",
            audit.unreferenced
        );
        // Largest first, so a report leads with what matters.
        assert!(audit.unreferenced[0].size >= audit.unreferenced[1].size);
    }

    /// A record whose manifest is missing means this store cannot say which
    /// blobs it needs. Reclaiming on that reading could delete a live layer, so
    /// the audit reports the corruption and offers nothing.
    #[tokio::test]
    async fn a_corrupt_record_makes_the_audit_reclaim_nothing() {
        let (_dir, store) = open_temp_store();
        plant_alpine(&store, "docker.io/library/alpine:3.20").await;
        plant_blob(&store, ALPINE_LAYER_DIGEST, 4096).await;
        let manifest_digest: Digest = ALPINE_MANIFEST_DIGEST.parse().unwrap();
        tokio::fs::remove_file(store.manifest_meta_path(&manifest_digest))
            .await
            .unwrap();

        let audit = store.audit_content().await.unwrap();
        assert!(
            audit.unreferenced.is_empty(),
            "an unreadable record must not make live blobs look orphaned: {:?}",
            audit.unreferenced
        );
    }

    #[tokio::test]
    async fn an_empty_store_audits_clean() {
        let (_dir, store) = open_temp_store();
        let audit = store.audit_content().await.unwrap();
        assert!(audit.unreferenced.is_empty());
        assert_eq!(audit.referenced, 0);
        assert_eq!(audit.bytes(), 0);
    }

    #[tokio::test]
    async fn a_pull_in_flight_is_reported_so_nothing_is_reclaimed_on_that_reading() {
        let (_dir, store) = open_temp_store();
        // Take the per-reference lock the way `pull` does.
        let gate = {
            let mut locks = store.pull_locks.lock().await;
            Arc::clone(
                locks
                    .entry("docker.io/library/alpine:3.20".to_owned())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let held = gate.lock().await;
        assert_eq!(store.pulls_in_flight(), 1);
        assert_eq!(store.audit_content().await.unwrap().pulls_in_flight, 1);
        drop(held);
        assert_eq!(store.pulls_in_flight(), 0);
    }

    // ---- tagging ----------------------------------------------------------

    #[tokio::test]
    async fn tag_adds_an_alias_for_the_same_digests() {
        let (_dir, store) = open_temp_store();
        plant_alpine(&store, "docker.io/library/alpine:3.20").await;
        let source = ImageReference::parse("alpine:3.20").unwrap();
        let target = ImageReference::parse("registry.example.com/mirror/alpine:3.20").unwrap();
        store.tag(&source, &target).await.unwrap();

        // Both references resolve to the same manifest digest and platform.
        let by_source = store.resolve(&source).await.unwrap().unwrap();
        let by_target = store.resolve(&target).await.unwrap().unwrap();
        assert_eq!(by_source.manifest_digest, by_target.manifest_digest);
        assert_eq!(
            by_target.reference,
            "registry.example.com/mirror/alpine:3.20"
        );
        assert_eq!(by_target.platform.to_string(), "linux/amd64");

        // And both names show up in the list.
        assert_eq!(store.list().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn tag_an_unknown_source_is_not_found() {
        let (_dir, store) = open_temp_store();
        let source = ImageReference::parse("ghost:1").unwrap();
        let target = ImageReference::parse("other:1").unwrap();
        let err = store.tag(&source, &target).await.unwrap_err();
        assert!(
            matches!(err, ImageError::NotFound { .. }),
            "expected NotFound, got {err}"
        );
        assert!(store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn tag_to_the_same_name_is_a_no_op() {
        let (_dir, store) = open_temp_store();
        plant_alpine(&store, "docker.io/library/alpine:3.20").await;
        let alpine = ImageReference::parse("alpine:3.20").unwrap();
        store.tag(&alpine, &alpine).await.unwrap();
        assert_eq!(store.list().await.unwrap().len(), 1);

        // Docker errors on a self-tag of an image that does not exist.
        let ghost = ImageReference::parse("ghost:1").unwrap();
        let err = store.tag(&ghost, &ghost).await.unwrap_err();
        assert!(matches!(err, ImageError::NotFound { .. }), "got {err}");
    }

    /// The tag write serializes with a pull of the target reference: while
    /// the target's per-reference lock is held, the tag cannot proceed.
    #[tokio::test]
    async fn tag_takes_the_target_reference_lock() {
        use futures_util::FutureExt as _;

        let (_dir, store) = open_temp_store();
        plant_alpine(&store, "docker.io/library/alpine:3.20").await;
        let source = ImageReference::parse("alpine:3.20").unwrap();
        let target = ImageReference::parse("alpine:mirror").unwrap();

        // Hold the target's per-reference lock the way a pull of it would.
        let gate = {
            let mut locks = store.pull_locks.lock().await;
            Arc::clone(locks.entry(target.canonical()).or_default())
        };
        let held = gate.lock().await;

        let tag = store.tag(&source, &target);
        tokio::pin!(tag);
        assert!(
            tag.as_mut().now_or_never().is_none(),
            "the tag must wait for the target's per-reference lock"
        );
        drop(held);
        tag.await.unwrap();
        assert_eq!(store.list().await.unwrap().len(), 2);
    }

    /// A blob reachable from two references must survive the loss of one of
    /// them: tag, forget the source record (what `prune -a` does to an unused
    /// reference), and the target keeps the whole stack reachable and
    /// resolvable.
    #[tokio::test]
    async fn content_tagged_twice_survives_the_loss_of_one_reference() {
        let (_dir, store) = open_temp_store();
        plant_alpine(&store, "docker.io/library/alpine:3.20").await;
        plant_blob(&store, ALPINE_LAYER_DIGEST, 4096).await;
        let source = ImageReference::parse("alpine:3.20").unwrap();
        let target = ImageReference::parse("registry.example.com/mirror/alpine:3.20").unwrap();
        store.tag(&source, &target).await.unwrap();

        assert!(store.remove("docker.io/library/alpine:3.20").await.unwrap());
        let audit = store.audit_content().await.unwrap();
        assert!(
            audit.unreferenced.is_empty(),
            "the target still reaches every file: {:?}",
            audit.unreferenced
        );
        let image = store.resolve(&target).await.unwrap().unwrap();
        assert_eq!(image.manifest_digest.as_str(), ALPINE_MANIFEST_DIGEST);
        assert_eq!(store.list().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn blob_present_checks_existence_and_size() {
        let (_dir, store) = open_temp_store();
        let digest = Digest::sha256_of(b"some blob");
        let path = store.blob_path(&digest);
        assert!(!blob_present(&path, 9).await);
        tokio::fs::write(&path, b"some blob").await.unwrap();
        assert!(blob_present(&path, 9).await);
        assert!(
            !blob_present(&path, 10).await,
            "size mismatch → re-download"
        );
        assert!(
            blob_present(&path, 0).await,
            "unknown size → trust existence"
        );
    }
}
