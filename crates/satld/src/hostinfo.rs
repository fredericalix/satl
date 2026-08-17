// SPDX-License-Identifier: BSD-2-Clause
//! Host facts gathered at startup: hostname, CPU count, physical memory,
//! OS release. satld-local for M0; moves to `satl-agent` with the node
//! description work (architecture §8.3).

use anyhow::Context as _;

use crate::sysctl::Sysctl;

/// Facts about the host, gathered once at startup.
#[derive(Debug, Clone)]
pub struct HostInfo {
    /// System hostname.
    pub hostname: String,
    /// Number of usable CPUs.
    pub ncpu: usize,
    /// Physical memory in bytes (`hw.physmem`).
    pub physmem_bytes: u64,
    /// OS release string (`kern.osrelease`, e.g. `15.1-RELEASE-p2`).
    pub os_release: String,
}

/// The system hostname (used before config load for the `node_name` default).
pub fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

/// Number of usable CPUs; falls back to 1 if the OS refuses to say.
fn ncpu() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// Gather all host facts.
pub async fn gather(sysctl: &Sysctl) -> anyhow::Result<HostInfo> {
    let physmem_bytes = sysctl
        .get_u64("hw.physmem")
        .await
        .context("failed to determine physical memory")?;
    let os_release = sysctl
        .get("kern.osrelease")
        .await
        .context("failed to determine OS release")?;
    Ok(HostInfo {
        hostname: hostname(),
        ncpu: ncpu(),
        physmem_bytes,
        os_release,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_is_not_empty() {
        assert!(!hostname().is_empty());
    }

    #[test]
    fn ncpu_is_at_least_one() {
        assert!(ncpu() >= 1);
    }
}
