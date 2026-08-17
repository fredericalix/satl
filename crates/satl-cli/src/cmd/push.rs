// SPDX-License-Identifier: BSD-2-Clause
//! `satl push` — push a locally stored image to its registry (M8a).
//!
//! Client-side and node-local, exactly like `satl build`: the store being
//! read is this node's, so the push happens from the host, not the daemon.
//! Docker clients pushing against satld's API get a 404 — the deviation is
//! recorded in `docs/api-compat.md`.

use clap::Args;

use crate::client::Host;
use crate::output::Streams;

/// The default image store root (the daemon's `state_dir/images`).
const DEFAULT_STORE: &str = "/var/db/satl/images";

/// Push an image to a registry.
#[derive(Debug, Args)]
pub struct PushArgs {
    /// Image reference (`name[:tag]`, optionally registry-prefixed).
    #[arg(value_name = "NAME[:TAG]")]
    pub image: String,

    /// Registry username (with --password-stdin).
    #[arg(short, long, value_name = "USER")]
    pub username: Option<String>,

    /// Read the registry password from stdin.
    #[arg(long)]
    pub password_stdin: bool,

    /// Image store to read (default: the local daemon's).
    #[arg(long, value_name = "PATH", default_value = DEFAULT_STORE)]
    pub store: std::path::PathBuf,
}

/// Run `satl push`.
pub async fn execute(_host: &Host, args: &PushArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let reference = satl_image::ImageReference::parse(&args.image)
        .map_err(|error| anyhow::anyhow!("invalid image reference: {error}"))?;
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
    let store = satl_image::ImageStore::open(&args.store).map_err(|error| {
        anyhow::anyhow!(
            "cannot open the image store at {}: {error} (satl push needs root — re-run with sudo)",
            args.store.display()
        )
    })?;
    let digest = store.push(&reference, credentials).await?;
    streams
        .outln(&format!(
            "{}: pushed (manifest {digest})",
            reference.canonical()
        ))
        .await;
    Ok(0)
}
