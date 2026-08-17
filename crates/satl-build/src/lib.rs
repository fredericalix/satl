// SPDX-License-Identifier: BSD-2-Clause
//! `satl build` — build a FreeBSD OCI image without a hand-written shell
//! script per application (M6f, `docs/image-sources.md`; multi-layer with an
//! incremental cache since M8b).
//!
//! The build file is a `Satlfile`, the subset of Dockerfile verbs that makes
//! sense for pkg-based FreeBSD images:
//!
//! ```text
//! FROM 127.0.0.1:5000/satl-test/freebsd-runtime:15.1
//! PKG nginx pcre2
//! COPY app/ /srv/app
//! EXPOSE 80/tcp
//! ENTRYPOINT ["/usr/local/sbin/nginx", "-g", "daemon off;"]
//! ```
//!
//! The pipeline is what `hack/images/build-freebsd-nginx.sh` proved, grown
//! up: pull the base into the content store, materialize its layers into a
//! temp rootfs (`chflags -R noschg` first — the base carries schg flags),
//! then run the mutating steps **one layer each** — the PKG group, each
//! COPY, each RUN — through the incremental cache ([`cache`]): a step whose
//! inputs (parent layer chain + payload) are unchanged is not re-executed;
//! its cached layer is applied to the rootfs and adopted. The result is
//! packed as base layers + step layers ([`repack`]) and registered through
//! `satl-image` — no skopeo.
//!
//! Since M8c the Satlfile may hold several stages (`FROM` … `FROM` …) and
//! the literal `scratch` base. Every stage runs the pipeline above in full —
//! `FROM scratch` simply starts from an empty rootfs and the canonical empty
//! chain — but only the *last* stage is packed and registered; the earlier
//! ones exist so a `COPY --from` can lift artifacts out of their finished
//! rootfses.

mod cache;
mod inventory;
mod layer;
mod repack;
mod satlfile;

pub use cache::{BuildCache, DEFAULT_CACHE_DIR};
pub use repack::{PackageError, StepRecord, package_image};
pub use satlfile::{Satlfile, SatlfileError, Stage, Step};

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;

use satl_image::{ImageReference, ImageStore, PlatformPolicy, PulledImage};

use crate::inventory::{Diff, Inventory};

/// Default package ABI: the FreeBSD major the test bases are built from.
/// Override with `--pkg-abi` when the base is a different major.
pub const DEFAULT_PKG_ABI: &str = "FreeBSD:15:amd64";

/// What a completed build reports.
#[derive(Debug)]
pub struct BuildOutcome {
    /// The registered image, as the store sees it.
    pub image: PulledImage,
    /// The canonical reference it was registered under.
    pub reference: String,
}

/// A build step's external command failed. Carries the full argv and stderr —
/// an operator must be able to re-run it by hand.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The build file is malformed.
    #[error("build file: {0}")]
    Satlfile(#[from] SatlfileError),
    /// The base image could not be pulled or read.
    #[error("image store: {0}")]
    Image(#[from] satl_image::ImageError),
    /// A layer of the base image failed to unpack.
    #[error("layer unpack: {0}")]
    Unpack(#[from] satl_storage::unpack::UnpackError),
    /// Packaging (assembly + register) failed.
    #[error("packaging: {0}")]
    Package(#[from] PackageError),
    /// Packing a step's layer failed.
    #[error("step layer: {0}")]
    Layer(#[from] layer::LayerError),
    /// A COPY source could not be resolved under its source root (the build
    /// context, or a `--from` stage's rootfs).
    #[error("COPY: cannot read {path:?} under {root}: {source}")]
    Context {
        /// The path that failed.
        path: PathBuf,
        /// What the sources resolve under, for the message.
        root: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A COPY source resolves outside its source root (a symlink escape).
    #[error("COPY: {path:?} resolves outside {root}")]
    Escape {
        /// The source as written.
        path: PathBuf,
        /// What the sources resolve under, for the message.
        root: String,
    },
    /// Several COPY sources with a destination that is not a directory.
    #[error("COPY: {dest:?} must name a directory (trailing /) with several sources")]
    CopyNotDir {
        /// The destination as resolved.
        dest: PathBuf,
    },
    /// An external command (pkg, chflags, tar, ldconfig) failed.
    #[error("`{argv}` failed with {status}; stderr: {stderr}")]
    Command {
        /// Full rendered command line.
        argv: String,
        /// What the exit looked like.
        status: String,
        /// Raw stderr.
        stderr: String,
    },
    /// An I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// The chain ID of an empty layer stack — the parent a `FROM scratch`
/// stage's first step keys off. `satl_storage::chain::chains_of` yields no
/// chain for zero diff IDs, and `base_chain_id` renders that as the empty
/// string; the same string names the scratch base, so a scratch stage and a
/// real base (which always carries at least one layer) can never collide on
/// a cache key.
pub const SCRATCH_CHAIN_ID: &str = "";

/// Run one external command to completion; on failure, an error naming the
/// exact argv and its stderr.
async fn run(argv: &[&str]) -> Result<(), BuildError> {
    let rendered = argv.join(" ");
    tracing::debug!(command = %rendered, "build step");
    let output = tokio::process::Command::new(argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .output()
        .await?;
    if output.status.success() {
        return Ok(());
    }
    Err(BuildError::Command {
        argv: rendered,
        status: match output.status.code() {
            Some(code) => format!("exit code {code}"),
            None => "termination by signal".to_owned(),
        },
        stderr: String::from_utf8_lossy(&output.stderr)
            .trim_end()
            .to_owned(),
    })
}

/// Build the image described by `spec` and register it under `tag` in `store`.
///
/// `context` is the build context `COPY` sources resolve against — the
/// Satlfile's directory. `cache` is the incremental build cache (`None` =
/// `--no-cache`). Needs root: pkg's `--rootdir`, the chroot for ldconfig and
/// RUN steps, and the store itself are all root-owned on a SatL node. The
/// CLI re-execs through sudo.
pub async fn build(
    store: &ImageStore,
    spec: &Satlfile,
    tag: &ImageReference,
    pkg_abi: &str,
    context: &Path,
    cache: Option<&BuildCache>,
) -> Result<BuildOutcome, BuildError> {
    // The build host runs no Linux images here: a Satlfile builds *FreeBSD*
    // images.
    let policy = PlatformPolicy::for_host(false);
    // Every stage's scratch dir lives for the whole build: a later stage's
    // `COPY --from` reads an earlier stage's finished rootfs.
    let build_dir = tempfile::Builder::new()
        .prefix("satl-build.")
        .tempdir()
        .map_err(BuildError::Io)?;
    let mut finished: Vec<StageOutput> = Vec::with_capacity(spec.stages.len());
    for (index, stage) in spec.stages.iter().enumerate() {
        let output = build_stage(
            store,
            stage,
            index,
            pkg_abi,
            context,
            cache,
            &finished,
            build_dir.path(),
            &policy,
        )
        .await?;
        finished.push(output);
    }

    // Only the last stage becomes the image: its layers, its metadata.
    let last = finished.last().expect("parse requires a stage");
    let image = package_image(spec.last_stage(), &last.base_layers, &last.records)?;
    let reference = tag.canonical();
    let pulled = store.register_local(tag, image).await?;
    Ok(BuildOutcome {
        image: pulled,
        reference,
    })
}

/// A stage built and set aside. The last one's layers go into the manifest;
/// every one's rootfs stays on disk for later stages' `COPY --from`.
struct StageOutput {
    /// The stage's own base layers (empty for `FROM scratch`).
    base_layers: Vec<satl_image::LayerDescriptor>,
    /// One record per layer-making step.
    records: Vec<StepRecord>,
    /// The finished rootfs, under the build dir.
    rootfs: PathBuf,
}

/// Build one stage: materialize its base (nothing, for `FROM scratch`), run
/// its steps through the cache, and return what the image assembly and the
/// later stages need of it.
#[allow(clippy::too_many_arguments)] // one pass; every argument decides part of it
async fn build_stage(
    store: &ImageStore,
    stage: &Stage,
    index: usize,
    pkg_abi: &str,
    context: &Path,
    cache: Option<&BuildCache>,
    prior: &[StageOutput],
    build_dir: &Path,
    policy: &PlatformPolicy,
) -> Result<StageOutput, BuildError> {
    let stage_dir = build_dir.join(format!("stage-{index}"));
    let rootfs = stage_dir.join("rootfs");
    std::fs::create_dir_all(&rootfs).map_err(BuildError::Io)?;

    // 1. The base image, into the store (pulls are idempotent), then
    //    materialized: each layer unpacked in order, diff IDs verified by
    //    the unpacker. `FROM scratch` is the empty base: no pull, no layers,
    //    the canonical empty chain to key the steps.
    let mut base_layers = Vec::new();
    let mut base_chain = SCRATCH_CHAIN_ID.to_owned();
    if !stage.is_scratch() {
        let base_ref = ImageReference::parse(&stage.from)?;
        let base = store.pull(&base_ref, policy, None).await?;
        for layer in &base.layers {
            let blob = store.blob_path(&layer.blob_digest);
            unpack_one(&blob, layer, &rootfs).await?;
        }
        // The base layer carries schg flags (root-extraction restores them);
        // nothing below can delete or rewrite a flagged file otherwise.
        run(&["/bin/chflags", "-R", "noschg", &rootfs.to_string_lossy()]).await?;
        base_chain = base_chain_id(&base)?;
        base_layers = base.layers.clone();
    }

    // 2. The mutating steps, each through the cache: the PKG group first (a
    //    package must be installed before a step can use it), then the
    //    COPY/RUN steps in file order.
    let env = StepEnv {
        stage,
        context,
        rootfs: &rootfs,
        prior,
        pkg_abi,
    };
    let mut steps: Vec<PlannedStep> = Vec::new();
    if !stage.packages.is_empty() {
        steps.push(PlannedStep::Pkg);
    }
    steps.extend(stage.steps.iter().map(PlannedStep::of));
    let mut inventory = walk(&rootfs).await?;
    let mut executor = RealExecutor;
    let records = run_steps(
        env,
        store,
        &steps,
        base_chain,
        cache,
        &mut executor,
        &mut inventory,
        &stage_dir,
    )
    .await?;
    Ok(StageOutput {
        base_layers,
        records,
        rootfs,
    })
}

/// One mutating step of the build, in execution order.
#[derive(Debug, Clone)]
enum PlannedStep {
    /// The PKG group (install + residue cleanup + ldconfig hints).
    Pkg,
    /// One COPY.
    Copy {
        /// The `--from` stage's index; `None` = the build context.
        from: Option<usize>,
        /// Sources (context-relative, or stage-absolute with `--from`).
        sources: Vec<PathBuf>,
        /// Resolved destination inside the image.
        dest: PathBuf,
    },
    /// One RUN.
    Run(String),
}

impl PlannedStep {
    /// The planned form of a parsed COPY/RUN step.
    fn of(step: &Step) -> Self {
        match step {
            Step::Copy {
                from,
                sources,
                dest,
            } => Self::Copy {
                from: *from,
                sources: sources.clone(),
                dest: dest.clone(),
            },
            Step::Run(command) => Self::Run(command.clone()),
        }
    }

    /// The instruction text, for the cache entry and the image history.
    fn describe(&self, stage: &Stage) -> String {
        match self {
            Self::Pkg => format!("PKG {}", stage.packages.join(" ")),
            Self::Copy {
                from,
                sources,
                dest,
            } => {
                let origin = from.map_or_else(String::new, |index| format!("--from={index} "));
                format!(
                    "COPY {origin}{} {}",
                    sources
                        .iter()
                        .map(|s| s.display().to_string())
                        .collect::<Vec<_>>()
                        .join(" "),
                    dest.display()
                )
            }
            Self::Run(command) => format!("RUN {command}"),
        }
    }
}

/// What a step needs beyond itself: the stage's and the build's constants.
#[derive(Clone, Copy)]
struct StepEnv<'a> {
    stage: &'a Stage,
    context: &'a Path,
    rootfs: &'a Path,
    /// The stages built before this one, for `COPY --from`.
    prior: &'a [StageOutput],
    pkg_abi: &'a str,
}

impl StepEnv<'_> {
    /// The root a COPY's sources resolve under: the build context, or the
    /// `--from` stage's finished rootfs.
    fn copy_root(&self, from: Option<usize>) -> &Path {
        from.map_or(self.context, |index| &self.prior[index].rootfs)
    }

    /// How that root reads in an error message.
    fn copy_root_name(from: Option<usize>) -> String {
        from.map_or_else(
            || "the build context".to_owned(),
            |index| format!("stage {index}"),
        )
    }
}

/// The step's cache payload (see [`cache`]'s module docs for the shape).
fn payload_of(env: &StepEnv<'_>, step: &PlannedStep) -> Result<serde_json::Value, BuildError> {
    Ok(match step {
        PlannedStep::Pkg => {
            let mut packages: Vec<&str> = env.stage.packages.iter().map(String::as_str).collect();
            packages.sort_unstable();
            serde_json::json!({
                "kind": "pkg",
                "abi": env.pkg_abi,
                "packages": packages,
            })
        }
        PlannedStep::Copy {
            from,
            sources,
            dest,
        } => {
            let root = env.copy_root(*from);
            let root_name = StepEnv::copy_root_name(*from);
            let mut hashed = Vec::new();
            for source in sources {
                let canonical = resolve_copy_source(root, &root_name, source)?;
                let hash = inventory::source_hash(&canonical).map_err(BuildError::Io)?;
                hashed.push(serde_json::json!([source.display().to_string(), hash]));
            }
            hashed.sort_by(|a, b| a[0].as_str().cmp(&b[0].as_str()));
            let mut payload = serde_json::json!({
                "kind": "copy",
                "dest": dest.to_string_lossy(),
                "sources": hashed,
            });
            // Only a cross-stage COPY carries `from` — a plain context COPY
            // keeps its M8b key shape, so existing cache entries still hit.
            if let Some(index) = from {
                payload["from"] = serde_json::json!(index);
            }
            payload
        }
        PlannedStep::Run(command) => {
            let env_vars: Vec<[&str; 2]> = env
                .stage
                .env
                .iter()
                .map(|(key, value)| [key.as_str(), value.as_str()])
                .collect();
            serde_json::json!({
                "kind": "run",
                "command": command,
                "env": env_vars,
                "workdir": env.stage.workdir,
            })
        }
    })
}

/// What running one step means. The production executor shells out (pkg,
/// cp, chroot); the tests substitute a counting one.
trait Executor {
    fn execute<'a>(
        &'a mut self,
        env: StepEnv<'a>,
        step: &'a PlannedStep,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), BuildError>> + Send + 'a>>;
}

/// The production executor: pkg, `/bin/cp`, chroot.
struct RealExecutor;

impl Executor for RealExecutor {
    fn execute<'a>(
        &'a mut self,
        env: StepEnv<'a>,
        step: &'a PlannedStep,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), BuildError>> + Send + 'a>> {
        Box::pin(async move {
            match step {
                PlannedStep::Pkg => pkg_step(env).await,
                PlannedStep::Copy {
                    from,
                    sources,
                    dest,
                } => {
                    copy_step(
                        env.copy_root(*from),
                        &StepEnv::copy_root_name(*from),
                        sources,
                        dest,
                        env.rootfs,
                    )
                    .await
                }
                PlannedStep::Run(command) => run_step(env.stage, command, env.rootfs).await,
            }
        })
    }
}

/// The cache-aware driver: for each step in order, hit ⇒ apply the cached
/// layer to the rootfs and adopt its inventory; miss ⇒ execute, diff, pack,
/// store. Returns the step layer records for the manifest (a step with an
/// empty diff contributes none, and advances no chain link).
#[allow(clippy::too_many_arguments)] // one pass; every argument decides part of it
async fn run_steps(
    env: StepEnv<'_>,
    store: &ImageStore,
    steps: &[PlannedStep],
    base_chain: String,
    cache: Option<&BuildCache>,
    executor: &mut dyn Executor,
    inventory: &mut Inventory,
    scratch: &Path,
) -> Result<Vec<StepRecord>, BuildError> {
    let mut records = Vec::new();
    let mut parent_chain = base_chain;
    for step in steps {
        let payload = payload_of(&env, step)?;
        let key = cache::key(&parent_chain, &payload);
        let instruction = step.describe(env.stage);
        let cached = cache.and_then(|cache| cache.load(&key));
        let record = match cached {
            Some(entry) => {
                let (record, adopted) = apply_cached(
                    env,
                    store,
                    cache.expect("an entry implies a cache"),
                    &key,
                    entry,
                    &instruction,
                )
                .await?;
                *inventory = adopted;
                record
            }
            None => {
                execute_step(
                    env,
                    store,
                    scratch,
                    cache,
                    &key,
                    &instruction,
                    step,
                    executor,
                    inventory,
                )
                .await?
            }
        };
        if let Some(record) = record {
            parent_chain = chain_id(&parent_chain, &record.diff_id)?;
            records.push(record);
        }
    }
    Ok(records)
}

/// The hit half of the driver: apply the cached layer to the rootfs — never
/// skip applying, a later miss needs the real tree — and return both the
/// manifest record and the cached inventory to adopt.
async fn apply_cached(
    env: StepEnv<'_>,
    store: &ImageStore,
    cache: &BuildCache,
    key: &str,
    entry: cache::CacheEntry,
    instruction: &str,
) -> Result<(Option<StepRecord>, Inventory), BuildError> {
    tracing::info!(instruction, "cache hit: applying the cached layer");
    let record = match (&entry.diff_id, &entry.blob_digest) {
        (Some(diff_id), Some(blob_digest)) => {
            let blob = cache.blob_path(key);
            apply_layer(&blob, diff_id, env.rootfs).await?;
            let staged = stage_cached_blob(store, &blob).await?;
            Some(StepRecord {
                instruction: instruction.to_owned(),
                diff_id: diff_id.clone(),
                blob_digest: blob_digest.clone(),
                size: entry.size,
                staged,
            })
        }
        // An empty-diff outcome: nothing to apply, nothing to register.
        _ => None,
    };
    Ok((record, cache::inventory_from_wire(entry.inventory)))
}

/// The miss half: execute, walk, diff, pack, and record the outcome in the
/// cache (best-effort — a cache that cannot be written never fails a build).
#[allow(clippy::too_many_arguments)]
async fn execute_step(
    env: StepEnv<'_>,
    store: &ImageStore,
    scratch: &Path,
    cache: Option<&BuildCache>,
    key: &str,
    instruction: &str,
    step: &PlannedStep,
    executor: &mut dyn Executor,
    inventory: &mut Inventory,
) -> Result<Option<StepRecord>, BuildError> {
    tracing::info!(instruction, "cache miss: executing");
    executor.execute(env, step).await?;
    let after = walk(env.rootfs).await?;
    let diff = inventory::diff(inventory, &after);
    let layer = pack_layer(env.rootfs, &diff, &after)?;

    let (record, blob) = if let Some(blob) = layer {
        let gz_path = scratch.join("layer.tar.gz");
        std::fs::write(&gz_path, &blob.gz).map_err(BuildError::Io)?;
        let staged = store.stage_blob(&gz_path).await.map_err(BuildError::Io)?;
        let record = StepRecord {
            instruction: instruction.to_owned(),
            diff_id: blob.diff_id.clone(),
            blob_digest: blob.blob_digest.clone(),
            size: blob.size,
            staged,
        };
        (Some(record), Some(blob.gz))
    } else {
        tracing::debug!(instruction, "step changed nothing; no layer");
        (None, None)
    };
    if let Some(cache) = cache {
        let entry = cache::CacheEntry {
            instruction: instruction.to_owned(),
            diff_id: record.as_ref().map(|record| record.diff_id.clone()),
            blob_digest: record.as_ref().map(|record| record.blob_digest.clone()),
            size: record.as_ref().map_or(0, |record| record.size),
            inventory: cache::inventory_to_wire(&after),
        };
        if let Err(error) = cache.store(key, &entry, blob.as_deref()) {
            tracing::warn!(instruction, %error, "could not write the build cache; continuing");
        }
    }
    *inventory = after;
    Ok(record)
}

/// Stage a cache-hit blob for registration **without emptying the cache**:
/// hardlink it out first (same filesystem), copy as the fallback, then let
/// `stage_blob` move the link. The cache's own path keeps its inode either
/// way.
async fn stage_cached_blob(store: &ImageStore, blob: &Path) -> Result<PathBuf, BuildError> {
    let link = blob.with_extension("stage");
    if link.exists() {
        std::fs::remove_file(&link).map_err(BuildError::Io)?;
    }
    if std::fs::hard_link(blob, &link).is_err() {
        tokio::fs::copy(blob, &link).await.map_err(BuildError::Io)?;
    }
    let staged = store.stage_blob(&link).await.map_err(BuildError::Io)?;
    Ok(staged)
}

/// Apply a cached layer blob to the rootfs; the unpacker verifies the
/// `diff_id`, so a corrupted cache blob fails loudly rather than poisoning
/// the image.
async fn apply_layer(blob: &Path, diff_id: &str, rootfs: &Path) -> Result<(), BuildError> {
    let blob = blob.to_path_buf();
    let diff_id = diff_id.to_owned();
    let target = rootfs.to_path_buf();
    tokio::task::spawn_blocking(move || {
        satl_storage::unpack::unpack_layer_sync(
            &blob,
            satl_storage::LayerCompression::Gzip,
            &diff_id,
            &target,
        )
    })
    .await
    .expect("spawn_blocking panicked")?;
    Ok(())
}

/// Walk the rootfs, off the async runtime.
async fn walk(rootfs: &Path) -> Result<Inventory, BuildError> {
    let rootfs = rootfs.to_path_buf();
    tokio::task::spawn_blocking(move || inventory::walk(&rootfs))
        .await
        .expect("spawn_blocking panicked")
        .map_err(BuildError::Io)
}

/// Pack one step's diff, off the async runtime.
fn pack_layer(
    rootfs: &Path,
    diff: &Diff,
    inventory: &Inventory,
) -> Result<Option<layer::LayerBlob>, BuildError> {
    layer::build_layer(rootfs, diff, inventory).map_err(BuildError::Layer)
}

/// `chain_id(parent, diff_id)` as a digest string (satl-storage's OCI math).
/// The empty parent — [`SCRATCH_CHAIN_ID`], a `FROM scratch` stage's first
/// layer — chains onto nothing.
fn chain_id(parent: &str, diff_id: &str) -> Result<String, BuildError> {
    let parent = if parent.is_empty() {
        None
    } else {
        Some(
            satl_storage::chain::ChainId::from_digest(parent).map_err(|error| {
                BuildError::Command {
                    argv: format!("chain id of {parent:?}"),
                    status: "invalid base chain".to_owned(),
                    stderr: error.to_string(),
                }
            })?,
        )
    };
    satl_storage::chain::chain_id(parent.as_ref(), diff_id)
        .map(|chain| chain.digest())
        .map_err(|error| BuildError::Command {
            argv: format!("chain id with {diff_id:?}"),
            status: "invalid diff id".to_owned(),
            stderr: error.to_string(),
        })
}

/// The base image's top chain ID: the parent of the first step's key.
fn base_chain_id(base: &PulledImage) -> Result<String, BuildError> {
    let chains =
        satl_storage::chain::chains_of(base.layers.iter().map(|layer| layer.diff_id.to_string()))
            .map_err(|error| BuildError::Command {
            argv: "base image chain".to_owned(),
            status: "invalid base diff id".to_owned(),
            stderr: error.to_string(),
        })?;
    Ok(chains
        .last()
        .map_or_else(String::new, satl_storage::ChainId::digest))
}

/// The PKG step: install, drop the pkg residue (the repo catalogs and the
/// cache do not belong in an image; local.sqlite stays, so `pkg info` works
/// inside the container), then bake the runtime-linker hints — no rc runs in
/// a jail, so without them the loader never searches /usr/local/lib. The
/// hints run inside this step so a later RUN can execute what PKG installed.
async fn pkg_step(env: StepEnv<'_>) -> Result<(), BuildError> {
    let rootfs_text = env.rootfs.to_string_lossy().into_owned();
    let mut argv = vec!["/usr/sbin/pkg", "-o", env.pkg_abi];
    argv.push("--rootdir");
    argv.push(&rootfs_text);
    argv.extend(["install", "-y"]);
    let packages: Vec<&str> = env.stage.packages.iter().map(String::as_str).collect();
    argv.extend(packages);
    run(&argv).await?;
    let residue = env.rootfs.join("var/db/pkg/repos");
    if residue.exists() {
        std::fs::remove_dir_all(&residue).map_err(BuildError::Io)?;
    }
    let cache = env.rootfs.join("var/cache/pkg");
    if cache.exists() {
        std::fs::remove_dir_all(&cache).map_err(BuildError::Io)?;
        std::fs::create_dir(&cache).map_err(BuildError::Io)?;
    }
    run(&[
        "/usr/sbin/chroot",
        &env.rootfs.to_string_lossy(),
        "/sbin/ldconfig",
        "/lib",
        "/usr/lib",
        "/usr/local/lib",
    ])
    .await?;
    Ok(())
}

/// Resolve one COPY source under `root` to its canonical path, refusing
/// anything that escapes it (a symlink pointing out). A `--from` source is
/// absolute inside the stage's rootfs; stripping the leading `/` leaves both
/// readings root-relative — the parse-time checks decided which shape is
/// legal.
fn resolve_copy_source(root: &Path, root_name: &str, source: &Path) -> Result<PathBuf, BuildError> {
    let root_canon = root
        .canonicalize()
        .map_err(|source_err| BuildError::Context {
            path: root.to_path_buf(),
            root: root_name.to_owned(),
            source: source_err,
        })?;
    let absolute = root_canon.join(source.strip_prefix("/").unwrap_or(source));
    let canonical = absolute
        .canonicalize()
        .map_err(|source_err| BuildError::Context {
            path: absolute.clone(),
            root: root_name.to_owned(),
            source: source_err,
        })?;
    if !canonical.starts_with(&root_canon) {
        return Err(BuildError::Escape {
            path: source.to_path_buf(),
            root: root_name.to_owned(),
        });
    }
    Ok(canonical)
}

/// One `COPY` step. Sources resolve under `root` — the build context, or a
/// `--from` stage's finished rootfs (validated at parse); a directory source
/// copies its *contents*, a file source lands at the destination unless that
/// names a directory (trailing slash, or an existing one in the rootfs) —
/// Docker's COPY semantics. Several sources force the directory reading.
async fn copy_step(
    root: &Path,
    root_name: &str,
    sources: &[PathBuf],
    dest: &Path,
    rootfs: &Path,
) -> Result<(), BuildError> {
    let target = rootfs.join(dest.strip_prefix("/").unwrap_or(dest));
    let dest_is_dir = dest.to_string_lossy().ends_with('/') || target.is_dir();
    if sources.len() > 1 && !dest_is_dir {
        return Err(BuildError::CopyNotDir {
            dest: dest.to_path_buf(),
        });
    }
    for source in sources {
        let canonical = resolve_copy_source(root, root_name, source)?;
        // A directory copies its contents (`src/.`); a file copies into a
        // directory destination or onto the destination path itself.
        let (from, into) = if canonical.is_dir() {
            std::fs::create_dir_all(&target).map_err(BuildError::Io)?;
            (canonical.join("."), target.clone())
        } else if dest_is_dir {
            std::fs::create_dir_all(&target).map_err(BuildError::Io)?;
            (canonical, target.clone())
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(BuildError::Io)?;
            }
            (canonical, target.clone())
        };
        run(&[
            "/bin/cp",
            "-Rp",
            &from.to_string_lossy(),
            &into.to_string_lossy(),
        ])
        .await?;
    }
    Ok(())
}

/// One `RUN` step: `/bin/sh -c <cmd>` chrooted into the rootfs, with the
/// stage's ENV and its WORKDIR as the initial directory. Runs on the
/// build host's kernel — build on the same FreeBSD major you deploy.
async fn run_step(stage: &Stage, command: &str, rootfs: &Path) -> Result<(), BuildError> {
    // DNS inside the chroot: the base image may carry no resolv.conf. The
    // controller rewrites it per container at start, so the host's copy is
    // safe to leave behind.
    let resolv = rootfs.join("etc/resolv.conf");
    if !resolv.exists() {
        std::fs::copy("/etc/resolv.conf", &resolv).map_err(BuildError::Io)?;
    }
    let command = match &stage.workdir {
        Some(dir) => format!("cd {dir} && {command}"),
        None => command.to_owned(),
    };
    let rendered = format!("chroot <rootfs> /bin/sh -c {command:?}");
    tracing::debug!(command = %rendered, "build step");
    let mut process = tokio::process::Command::new("/usr/sbin/chroot");
    process
        .arg(rootfs)
        .arg("/bin/sh")
        .arg("-c")
        .arg(&command)
        .stdin(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/root");
    for (key, value) in &stage.env {
        process.env(key, value);
    }
    let output = process.output().await.map_err(BuildError::Io)?;
    if output.status.success() {
        return Ok(());
    }
    Err(BuildError::Command {
        argv: rendered,
        status: match output.status.code() {
            Some(code) => format!("exit code {code}"),
            None => "termination by signal".to_owned(),
        },
        stderr: String::from_utf8_lossy(&output.stderr)
            .trim_end()
            .to_owned(),
    })
}

/// Unpack one base layer into the rootfs, off the async runtime (tar parsing
/// is blocking work).
async fn unpack_one(
    blob: &Path,
    layer: &satl_image::LayerDescriptor,
    rootfs: &Path,
) -> Result<(), BuildError> {
    let blob = blob.to_path_buf();
    // satl-image and satl-storage each define their own LayerCompression.
    let compression = match layer.compression()? {
        satl_image::LayerCompression::Gzip => satl_storage::LayerCompression::Gzip,
        satl_image::LayerCompression::Zstd => satl_storage::LayerCompression::Zstd,
        satl_image::LayerCompression::None => satl_storage::LayerCompression::None,
    };
    let diff_id = layer.diff_id.to_string();
    let target = rootfs.to_path_buf();
    tokio::task::spawn_blocking(move || {
        satl_storage::unpack::unpack_layer_sync(&blob, compression, &diff_id, &target)
    })
    .await
    .expect("spawn_blocking panicked")?;
    Ok(())
}

/// The default build-file name `satl build` reads.
pub const DEFAULT_BUILD_FILE: &str = "Satlfile";

/// A path that must exist for the build to make sense, for early failure.
#[must_use]
pub fn build_file(path: Option<&Path>) -> PathBuf {
    path.map_or_else(|| PathBuf::from(DEFAULT_BUILD_FILE), Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A scratch build context and image rootfs, with the files each test
    /// declares created on the fly.
    struct Fixture {
        context: PathBuf,
        rootfs: PathBuf,
        scratch: PathBuf,
        _dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let context = dir.path().join("context");
            let rootfs = dir.path().join("rootfs");
            let scratch = dir.path().join("scratch");
            std::fs::create_dir_all(&context).unwrap();
            std::fs::create_dir_all(&rootfs).unwrap();
            std::fs::create_dir_all(&scratch).unwrap();
            Self {
                context,
                rootfs,
                scratch,
                _dir: dir,
            }
        }

        fn write(&self, relative: &str, content: &str) {
            let path = self.context.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }

        fn read_image(&self, absolute: &str) -> String {
            String::from_utf8(
                std::fs::read(self.rootfs.join(absolute.trim_start_matches('/'))).unwrap(),
            )
            .unwrap()
        }
    }

    #[tokio::test]
    async fn copy_file_to_file_and_file_to_directory() {
        let fixture = Fixture::new();
        fixture.write("app.js", "// app");
        copy_step(
            &fixture.context,
            "the build context",
            &[PathBuf::from("app.js")],
            Path::new("/srv/app.js"),
            &fixture.rootfs,
        )
        .await
        .unwrap();
        assert_eq!(fixture.read_image("/srv/app.js"), "// app");

        fixture.write("package.json", "{}");
        copy_step(
            &fixture.context,
            "the build context",
            &[PathBuf::from("package.json")],
            Path::new("/srv/"),
            &fixture.rootfs,
        )
        .await
        .unwrap();
        assert_eq!(fixture.read_image("/srv/package.json"), "{}");
    }

    #[tokio::test]
    async fn copy_directory_copies_its_contents() {
        let fixture = Fixture::new();
        fixture.write("app/index.js", "// index");
        fixture.write("app/lib/util.js", "// util");
        copy_step(
            &fixture.context,
            "the build context",
            &[PathBuf::from("app")],
            Path::new("/srv/app"),
            &fixture.rootfs,
        )
        .await
        .unwrap();
        assert_eq!(fixture.read_image("/srv/app/index.js"), "// index");
        assert_eq!(fixture.read_image("/srv/app/lib/util.js"), "// util");
        assert!(!fixture.rootfs.join("srv/app/app").exists());
    }

    #[tokio::test]
    async fn several_sources_need_a_directory_destination() {
        let fixture = Fixture::new();
        fixture.write("a", "a");
        fixture.write("b", "b");
        let err = copy_step(
            &fixture.context,
            "the build context",
            &[PathBuf::from("a"), PathBuf::from("b")],
            Path::new("/srv/file"),
            &fixture.rootfs,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, BuildError::CopyNotDir { .. }), "{err}");
    }

    #[tokio::test]
    async fn a_symlink_escaping_the_context_is_refused() {
        let fixture = Fixture::new();
        let outside = fixture.context.parent().unwrap().join("outside.txt");
        std::fs::write(&outside, "secret").unwrap();
        std::os::unix::fs::symlink(&outside, fixture.context.join("link")).unwrap();
        let err = copy_step(
            &fixture.context,
            "the build context",
            &[PathBuf::from("link")],
            Path::new("/x"),
            &fixture.rootfs,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, BuildError::Escape { .. }), "{err}");
    }

    // -- the cache driver ----------------------------------------------------

    /// An executor that counts: COPY runs for real (plain fs), RUN writes a
    /// marker line into `/markers` — both observable in the rootfs, and the
    /// counter proves whether either happened at all.
    struct CountingExecutor {
        executions: AtomicUsize,
    }

    impl Executor for CountingExecutor {
        fn execute<'a>(
            &'a mut self,
            env: StepEnv<'a>,
            step: &'a PlannedStep,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<(), BuildError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.executions.fetch_add(1, Ordering::SeqCst);
                match step {
                    PlannedStep::Copy {
                        from,
                        sources,
                        dest,
                    } => {
                        copy_step(
                            env.copy_root(*from),
                            &StepEnv::copy_root_name(*from),
                            sources,
                            dest,
                            env.rootfs,
                        )
                        .await
                    }
                    PlannedStep::Run(command) => {
                        let markers = env.rootfs.join("markers");
                        std::fs::create_dir_all(&markers).map_err(BuildError::Io)?;
                        let mut content =
                            std::fs::read_to_string(markers.join("log")).unwrap_or_default();
                        content.push_str(command);
                        content.push('\n');
                        std::fs::write(markers.join("log"), content).map_err(BuildError::Io)
                    }
                    PlannedStep::Pkg => unreachable!("no PKG step in these tests"),
                }
            })
        }
    }

    /// The shared shape: a fixture, a tempdir store and cache, and one drive
    /// of `steps` over `rootfs`. Returns the step records.
    #[allow(clippy::too_many_arguments)]
    async fn drive(
        fixture: &Fixture,
        stage: &Stage,
        steps: &[PlannedStep],
        rootfs: &Path,
        store: &ImageStore,
        cache: &BuildCache,
        parent: &str,
        prior: &[StageOutput],
        executor: &mut dyn Executor,
    ) -> Vec<StepRecord> {
        let env = StepEnv {
            stage,
            context: &fixture.context,
            rootfs,
            prior,
            pkg_abi: DEFAULT_PKG_ABI,
        };
        let mut inventory = inventory::walk(rootfs).unwrap();
        run_steps(
            env,
            store,
            steps,
            parent.to_owned(),
            Some(cache),
            executor,
            &mut inventory,
            &fixture.scratch,
        )
        .await
        .expect("drive")
    }

    fn copy(source: &str, dest: &str) -> PlannedStep {
        PlannedStep::Copy {
            from: None,
            sources: vec![PathBuf::from(source)],
            dest: PathBuf::from(dest),
        }
    }

    fn spec() -> Satlfile {
        Satlfile::parse("FROM base\nCOPY app.js /srv/app.js\nRUN first\n").unwrap()
    }

    /// A do-nothing executor that only counts, for the empty-diff test.
    struct Noop(AtomicUsize);

    impl Executor for Noop {
        fn execute<'a>(
            &'a mut self,
            _env: StepEnv<'a>,
            _step: &'a PlannedStep,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<(), BuildError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    /// A plausible base chain ID (sha256-shaped).
    fn base_chain() -> String {
        "sha256:0139c1c77468f75e6763a4612262743bd47a36b26cb2863d662756b3377bb029".to_owned()
    }

    #[tokio::test]
    async fn a_hit_applies_the_cached_layer_without_executing() {
        let fixture = Fixture::new();
        fixture.write("app.js", "// v1");
        let spec = spec();
        let steps = vec![
            copy("app.js", "/srv/app.js"),
            PlannedStep::Run("first".to_owned()),
        ];
        let store = ImageStore::open(fixture.scratch.join("images")).unwrap();
        let cache = BuildCache::new(fixture.scratch.join("cache"));
        let mut executor = CountingExecutor {
            executions: AtomicUsize::new(0),
        };

        let first = drive(
            &fixture,
            spec.last_stage(),
            &steps,
            &fixture.rootfs,
            &store,
            &cache,
            &base_chain(),
            &[],
            &mut executor,
        )
        .await;
        assert_eq!(first.len(), 2, "both steps made a layer");
        assert_eq!(executor.executions.load(Ordering::SeqCst), 2);

        // Roll the rootfs back to the base state, as a fresh build would see
        // it, and drive again: nothing executes, and the cached layers
        // rebuild the exact post-build tree.
        std::fs::remove_dir_all(&fixture.rootfs).unwrap();
        std::fs::create_dir(&fixture.rootfs).unwrap();
        let second = drive(
            &fixture,
            spec.last_stage(),
            &steps,
            &fixture.rootfs,
            &store,
            &cache,
            &base_chain(),
            &[],
            &mut executor,
        )
        .await;
        assert_eq!(
            executor.executions.load(Ordering::SeqCst),
            2,
            "a full-hit rebuild executes nothing"
        );
        assert_eq!(fixture.read_image("/srv/app.js"), "// v1");
        assert_eq!(
            std::fs::read_to_string(fixture.rootfs.join("markers/log")).unwrap(),
            "first\n"
        );
        let first_ids: Vec<&str> = first.iter().map(|r| r.diff_id.as_str()).collect();
        let second_ids: Vec<&str> = second.iter().map(|r| r.diff_id.as_str()).collect();
        assert_eq!(first_ids, second_ids, "same steps, same layers");
    }

    #[tokio::test]
    async fn a_changed_copy_source_invalidates_its_step_only() {
        let fixture = Fixture::new();
        fixture.write("app.js", "// v1");
        let spec = spec();
        let steps = vec![
            copy("app.js", "/srv/app.js"),
            PlannedStep::Run("first".to_owned()),
        ];
        let store = ImageStore::open(fixture.scratch.join("images")).unwrap();
        let cache = BuildCache::new(fixture.scratch.join("cache"));
        let mut executor = CountingExecutor {
            executions: AtomicUsize::new(0),
        };
        drive(
            &fixture,
            spec.last_stage(),
            &steps,
            &fixture.rootfs,
            &store,
            &cache,
            &base_chain(),
            &[],
            &mut executor,
        )
        .await;

        fixture.write("app.js", "// v2");
        std::fs::remove_dir_all(&fixture.rootfs).unwrap();
        std::fs::create_dir(&fixture.rootfs).unwrap();
        let rebuilt = drive(
            &fixture,
            spec.last_stage(),
            &steps,
            &fixture.rootfs,
            &store,
            &cache,
            &base_chain(),
            &[],
            &mut executor,
        )
        .await;
        // Both steps re-executed: step 1's payload changed, and step 2 keys
        // off step 1's new chain link. The image carries v2.
        assert_eq!(executor.executions.load(Ordering::SeqCst), 4);
        assert_eq!(fixture.read_image("/srv/app.js"), "// v2");
        assert_eq!(rebuilt.len(), 2);
    }

    #[tokio::test]
    async fn a_different_base_invalidates_everything() {
        let fixture = Fixture::new();
        fixture.write("app.js", "// v1");
        let spec = spec();
        let steps = vec![copy("app.js", "/srv/app.js")];
        let store = ImageStore::open(fixture.scratch.join("images")).unwrap();
        let cache = BuildCache::new(fixture.scratch.join("cache"));
        let mut executor = CountingExecutor {
            executions: AtomicUsize::new(0),
        };
        drive(
            &fixture,
            spec.last_stage(),
            &steps,
            &fixture.rootfs,
            &store,
            &cache,
            &base_chain(),
            &[],
            &mut executor,
        )
        .await;
        let other_base = "sha256:4381142a944dccfafc4428f3b1d4469713054b918f3c97f2e7f1cac2c25e0cc4";
        drive(
            &fixture,
            spec.last_stage(),
            &steps,
            &fixture.rootfs,
            &store,
            &cache,
            other_base,
            &[],
            &mut executor,
        )
        .await;
        assert_eq!(
            executor.executions.load(Ordering::SeqCst),
            2,
            "a new base means a new first key"
        );
    }

    #[tokio::test]
    async fn an_empty_diff_step_is_cached_as_empty() {
        let fixture = Fixture::new();
        fixture.write("app.js", "// v1");
        let spec = spec();
        // COPY of a file already identical in the rootfs: cp -Rp preserves
        // the source's mtime, so the second build's diff is empty... but the
        // first build's is not. The honest empty case here is a RUN whose
        // executor is a no-op — drive it through a do-nothing executor.
        let store = ImageStore::open(fixture.scratch.join("images")).unwrap();
        let cache = BuildCache::new(fixture.scratch.join("cache"));
        let mut executor = Noop(AtomicUsize::new(0));
        let steps = vec![PlannedStep::Run("true".to_owned())];

        let first = drive(
            &fixture,
            spec.last_stage(),
            &steps,
            &fixture.rootfs,
            &store,
            &cache,
            &base_chain(),
            &[],
            &mut executor,
        )
        .await;
        assert!(first.is_empty(), "an empty diff makes no layer");
        let second = drive(
            &fixture,
            spec.last_stage(),
            &steps,
            &fixture.rootfs,
            &store,
            &cache,
            &base_chain(),
            &[],
            &mut executor,
        )
        .await;
        assert!(second.is_empty());
        assert_eq!(
            executor.0.load(Ordering::SeqCst),
            1,
            "the no-op ran once; the cached empty outcome answered the rebuild"
        );
    }

    // -- FROM scratch and multi-stage builds (M8c) ----------------------------

    /// Another empty rootfs next to the fixture's, for a second stage.
    fn stage_dir(fixture: &Fixture, name: &str) -> PathBuf {
        let path = fixture.scratch.join(name);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    /// Roll a rootfs back to empty, as a fresh build would see it.
    fn wipe(rootfs: &Path) {
        std::fs::remove_dir_all(rootfs).unwrap();
        std::fs::create_dir(rootfs).unwrap();
    }

    #[tokio::test]
    async fn a_from_scratch_stage_chains_off_the_empty_base() {
        let fixture = Fixture::new();
        fixture.write("app.js", "// v1");
        let spec = Satlfile::parse("FROM scratch\nCOPY app.js /srv/app.js\n").unwrap();
        let steps = vec![copy("app.js", "/srv/app.js")];
        let store = ImageStore::open(fixture.scratch.join("images")).unwrap();
        let cache = BuildCache::new(fixture.scratch.join("cache"));
        let mut executor = CountingExecutor {
            executions: AtomicUsize::new(0),
        };

        // The scratch chain is the empty string: the first step's key and
        // the chain link after it must read it as "no parent", not parse it.
        let records = drive(
            &fixture,
            spec.last_stage(),
            &steps,
            &fixture.rootfs,
            &store,
            &cache,
            SCRATCH_CHAIN_ID,
            &[],
            &mut executor,
        )
        .await;
        assert_eq!(records.len(), 1);
        assert!(records[0].diff_id.starts_with("sha256:"));

        wipe(&fixture.rootfs);
        drive(
            &fixture,
            spec.last_stage(),
            &steps,
            &fixture.rootfs,
            &store,
            &cache,
            SCRATCH_CHAIN_ID,
            &[],
            &mut executor,
        )
        .await;
        assert_eq!(
            executor.executions.load(Ordering::SeqCst),
            1,
            "a scratch-based step caches like any other"
        );
        assert_eq!(fixture.read_image("/srv/app.js"), "// v1");
    }

    /// The two-stage fixture: a scratch builder copies `app.js` to
    /// `/src/out`, the scratch final stage lifts it to `/bin/out`.
    struct TwoStage {
        spec: Satlfile,
        builder_steps: Vec<PlannedStep>,
        final_steps: Vec<PlannedStep>,
    }

    impl TwoStage {
        fn parse() -> Self {
            let spec = Satlfile::parse(
                "FROM scratch AS builder\n\
                 COPY app.js /src/out\n\
                 FROM scratch\n\
                 COPY --from=builder /src/out /bin/out\n",
            )
            .unwrap();
            let builder_steps = spec.stages[0].steps.iter().map(PlannedStep::of).collect();
            let final_steps = spec.stages[1].steps.iter().map(PlannedStep::of).collect();
            Self {
                spec,
                builder_steps,
                final_steps,
            }
        }

        /// One full build: the builder stage, then the final stage reading
        /// its rootfs through `COPY --from`.
        async fn build(
            &self,
            fixture: &Fixture,
            builder: &Path,
            store: &ImageStore,
            cache: &BuildCache,
            executor: &mut dyn Executor,
        ) {
            drive(
                fixture,
                &self.spec.stages[0],
                &self.builder_steps,
                builder,
                store,
                cache,
                SCRATCH_CHAIN_ID,
                &[],
                executor,
            )
            .await;
            let prior = [StageOutput {
                base_layers: Vec::new(),
                records: Vec::new(),
                rootfs: builder.to_path_buf(),
            }];
            drive(
                fixture,
                &self.spec.stages[1],
                &self.final_steps,
                &fixture.rootfs,
                store,
                cache,
                SCRATCH_CHAIN_ID,
                &prior,
                executor,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn a_copy_from_another_stage_tracks_its_output() {
        let fixture = Fixture::new();
        fixture.write("app.js", "// v1");
        let two_stage = TwoStage::parse();
        let builder = stage_dir(&fixture, "builder");
        let store = ImageStore::open(fixture.scratch.join("images")).unwrap();
        let cache = BuildCache::new(fixture.scratch.join("cache"));
        let mut executor = CountingExecutor {
            executions: AtomicUsize::new(0),
        };

        // First build: both steps execute; the artifact crosses the stages.
        two_stage
            .build(&fixture, &builder, &store, &cache, &mut executor)
            .await;
        assert_eq!(executor.executions.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.read_image("/bin/out"), "// v1");

        // A rebuild from empty rootfses: full cache hits, nothing executes.
        wipe(&builder);
        wipe(&fixture.rootfs);
        two_stage
            .build(&fixture, &builder, &store, &cache, &mut executor)
            .await;
        assert_eq!(
            executor.executions.load(Ordering::SeqCst),
            2,
            "an unchanged rebuild is all hits, across stages too"
        );
        assert_eq!(fixture.read_image("/bin/out"), "// v1");

        // The builder's input moves: its step re-executes, and the final
        // stage's COPY --from misses on the moved content hash of /src/out —
        // its own spelling (dest, source path, scratch parent) did not
        // change.
        fixture.write("app.js", "// v2");
        wipe(&builder);
        wipe(&fixture.rootfs);
        two_stage
            .build(&fixture, &builder, &store, &cache, &mut executor)
            .await;
        assert_eq!(
            executor.executions.load(Ordering::SeqCst),
            4,
            "a moved builder output invalidates the final stage's copy"
        );
        assert_eq!(fixture.read_image("/bin/out"), "// v2");
    }

    #[tokio::test]
    async fn a_copy_from_a_stage_cannot_escape_it() {
        let fixture = Fixture::new();
        let stage_root = stage_dir(&fixture, "stage");
        // A symlink inside the stage rootfs pointing outside it.
        fixture.write("secret.txt", "secret");
        std::os::unix::fs::symlink(fixture.context.join("secret.txt"), stage_root.join("link"))
            .unwrap();
        let err = copy_step(
            &stage_root,
            "stage 0",
            &[PathBuf::from("/link")],
            Path::new("/x"),
            &fixture.rootfs,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, BuildError::Escape { .. }), "{err}");
    }
}
