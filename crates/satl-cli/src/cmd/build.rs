// SPDX-License-Identifier: BSD-2-Clause
//! `satl build` — build a FreeBSD OCI image from a `Satlfile` and register it
//! in this node's image store (M6f, `docs/image-sources.md`).
//!
//! This is deliberately *not* Docker's `POST /build`: the build runs
//! client-side against the local content store, exactly where the daemon will
//! read it. The build context — what `COPY` reads — is the Satlfile's own
//! directory. The API deviation is recorded in `docs/api-compat.md`.

use std::path::PathBuf;

use clap::Args;

use crate::api::cluster::{SwarmInfo, SystemInfo};
use crate::client::{self, Host};
use crate::output::Streams;

/// The default image store root (the daemon's `state_dir/images`).
const DEFAULT_STORE: &str = "/var/db/satl/images";

/// Build an image from a Satlfile.
#[derive(Debug, Args)]
pub struct BuildArgs {
    /// Name and tag for the image (`name[:tag]`, optionally registry-prefixed).
    #[arg(short = 't', long = "tag", value_name = "NAME[:TAG]")]
    pub tag: String,

    /// Build file to read (default: ./Satlfile).
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    pub file: Option<PathBuf>,

    /// Package ABI for the pkg install (default: FreeBSD:15:amd64).
    #[arg(long, value_name = "ABI", default_value = satl_build::DEFAULT_PKG_ABI)]
    pub pkg_abi: String,

    /// Image store to register into (default: the local daemon's).
    #[arg(long, value_name = "PATH", default_value = DEFAULT_STORE)]
    pub store: PathBuf,

    /// Disable the incremental build cache: every step re-executes.
    #[arg(long)]
    pub no_cache: bool,

    /// Build cache directory (default: /var/db/satl/build-cache).
    #[arg(long, value_name = "PATH", default_value = satl_build::DEFAULT_CACHE_DIR)]
    pub cache_dir: PathBuf,

    /// Push the image to its registry after a successful build.
    #[arg(long)]
    pub push: bool,

    /// Registry username for --push (with --password-stdin).
    #[arg(short, long, value_name = "USER")]
    pub username: Option<String>,

    /// Read the registry password for --push from stdin.
    #[arg(long)]
    pub password_stdin: bool,
}

/// Run `satl build`.
pub async fn execute(host: &Host, args: &BuildArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let file = args
        .file
        .clone()
        .unwrap_or_else(|| PathBuf::from("Satlfile"));
    let text = std::fs::read_to_string(&file)
        .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", file.display()))?;
    let spec = satl_build::Satlfile::parse(&text)?;
    // The build context is the Satlfile's own directory (Docker's `PATH`
    // argument, minus the argument).
    let context = file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let tag = satl_image::ImageReference::parse(&args.tag)
        .map_err(|error| anyhow::anyhow!("invalid -t/--tag value: {error}"))?;

    let store = satl_image::ImageStore::open(&args.store).map_err(|error| {
        anyhow::anyhow!(
            "cannot open the image store at {}: {error} (satl build needs root — re-run with sudo)",
            args.store.display()
        )
    })?;
    let cache = (!args.no_cache).then(|| satl_build::BuildCache::new(args.cache_dir.clone()));
    let outcome = satl_build::build(&store, &spec, &tag, &args.pkg_abi, &context, cache.as_ref())
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "{error}\n(satl build needs root — if this is a permission error, re-run with sudo)"
            )
        })?;
    streams
        .outln(&format!(
            "Built and registered {} (manifest {})",
            outcome.reference, outcome.image.manifest_digest
        ))
        .await;
    if args.push {
        let credentials = match (&args.username, args.password_stdin) {
            (Some(username), true) => {
                let mut password = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut password)?;
                Some(satl_image::RegistryAuth {
                    username: username.clone(),
                    password: password.trim_end_matches('\n').to_owned(),
                })
            }
            (None, false) => None,
            _ => anyhow::bail!("--username and --password-stdin go together"),
        };
        let digest = store.push(&tag, credentials).await?;
        streams
            .outln(&format!("{}: pushed (manifest {digest})", tag.canonical()))
            .await;
    }
    // A pushed image is pullable from every node; an unpushed one is not.
    if !args.push {
        warn_local_only_if_multi_node(host, streams, &tag.canonical()).await;
    }
    Ok(0)
}

/// Audit N3: after a successful build, warn when this node is not the only
/// one tasks can land on — the image just landed in *this* node's local
/// store and the other nodes cannot pull it (api-compat #144). Best-effort:
/// an unreachable daemon or a failed `/info` query prints nothing, so the
/// hint can never break a build.
async fn warn_local_only_if_multi_node(host: &Host, streams: &mut Streams, reference: &str) {
    let Ok(info) = client::get_json::<SystemInfo>(host, "/info").await else {
        return;
    };
    if let Some(line) = node_local_store_warning(&info.swarm, reference) {
        streams.warn(&line).await;
    }
}

/// The warning text, or `None` when `/info`'s swarm section says this node
/// is alone (or in no swarm at all). Pure, for goldens.
fn node_local_store_warning(swarm: &SwarmInfo, reference: &str) -> Option<String> {
    if swarm.local_node_state != "active" {
        return None;
    }
    // A manager sees the member count in `Swarm.Nodes`; a worker is served
    // no count, but being an *active* worker means at least one manager
    // exists besides this node — already multi-node.
    let multi_node = if swarm.control_available {
        swarm.nodes > 1
    } else {
        true
    };
    multi_node.then(|| {
        format!(
            "image {reference} exists only in this node's local store; other nodes cannot \
             run it until it is pushed (`satl push {reference}`) or the service is \
             constrained to this node"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing::streams as memory_streams;
    use crate::stub::{Reply, Stub};

    fn swarm(local_node_state: &str, control_available: bool, nodes: i64) -> SwarmInfo {
        SwarmInfo {
            local_node_state: local_node_state.to_owned(),
            control_available,
            nodes,
            ..SwarmInfo::default()
        }
    }

    /// Audit N3: on a multi-node cluster the freshly built image is runnable
    /// only here; the build must say so.
    #[test]
    fn a_multi_node_cluster_earns_a_warning_naming_the_reference() {
        // A manager sees the member count in `Swarm.Nodes`.
        let line = node_local_store_warning(&swarm("active", true, 3), "node1:5000/web:latest")
            .expect("multi-node manager warns");
        assert!(line.contains("node1:5000/web:latest"), "{line}");
        assert!(line.contains("this node's local store"), "{line}");
        assert!(line.contains("satl push"), "{line}");

        // A worker is served no `Nodes` count, but being an active worker
        // means at least one manager exists besides this node.
        let line = node_local_store_warning(&swarm("active", false, 0), "web:latest")
            .expect("an active worker is never alone");
        assert!(line.contains("satl push"), "{line}");
    }

    #[test]
    fn single_node_and_inactive_swarms_stay_silent() {
        assert_eq!(
            node_local_store_warning(&swarm("active", true, 1), "web:latest"),
            None,
            "single-node manager"
        );
        assert_eq!(
            node_local_store_warning(&swarm("inactive", false, 0), "web:latest"),
            None,
            "swarm inactive"
        );
        assert_eq!(
            node_local_store_warning(&swarm("locked", true, 3), "web:latest"),
            None,
            "not active"
        );
    }

    #[tokio::test]
    async fn the_warning_rides_stderr_when_the_cluster_has_other_nodes() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/info",
            Reply::json(
                200,
                r#"{"Swarm":{"NodeID":"n1","LocalNodeState":"active","ControlAvailable":true,"Nodes":2,"Managers":2}}"#,
            ),
        );
        let (mut streams, _out, err) = memory_streams();
        warn_local_only_if_multi_node(&stub.host(), &mut streams, "web:latest").await;
        let err = err.contents();
        assert!(err.starts_with("WARNING: "), "{err}");
        assert!(err.contains("web:latest"), "{err}");
        assert!(err.contains("satl push"), "{err}");
    }

    #[tokio::test]
    async fn a_single_node_cluster_prints_nothing() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/info",
            Reply::json(
                200,
                r#"{"Swarm":{"NodeID":"n1","LocalNodeState":"active","ControlAvailable":true,"Nodes":1,"Managers":1}}"#,
            ),
        );
        let (mut streams, _out, err) = memory_streams();
        warn_local_only_if_multi_node(&stub.host(), &mut streams, "web:latest").await;
        assert_eq!(err.contents(), "");
    }

    /// The hint must never break a build: a daemon that fails the query — or
    /// is not there at all — prints nothing.
    #[tokio::test]
    async fn a_failed_info_query_is_silent() {
        let stub = Stub::start().await;
        stub.on("GET", "/info", Reply::json(500, r#"{"message":"boom"}"#));
        let (mut streams, _out, err) = memory_streams();
        warn_local_only_if_multi_node(&stub.host(), &mut streams, "web:latest").await;
        assert_eq!(err.contents(), "");

        let unreachable = Host::parse("unix:///nonexistent/satl.sock").expect("host");
        let (mut streams, _out, err) = memory_streams();
        warn_local_only_if_multi_node(&unreachable, &mut streams, "web:latest").await;
        assert_eq!(err.contents(), "");
    }
}
