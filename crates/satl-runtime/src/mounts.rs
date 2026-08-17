// SPDX-License-Identifier: BSD-2-Clause
//! Mount-leak cleanup: enumerate active mounts under a container rootfs and
//! unmount them deepest-first.
//!
//! Why this exists (docs/ocijail.md §4.4, docs/linuxulator.md "Mount
//! lifecycle"): ocijail performs all bundle mounts host-side at `create`
//! time, but they are **not reliably unmounted** afterwards — `delete` of an
//! id whose state entry is missing is a silent no-op, a crash between mount
//! and jail creation leaks mounts with no state at all, a failed create can
//! leak nested mounts (`/dev/fd`, `/dev/shm`), and delete with a relative
//! `root.path` recorded leaks the whole set (observed live in the
//! linuxulator experiments). `satl-runtime` therefore sweeps everything
//! mounted strictly below the rootfs after every delete, and satld's startup
//! reconciliation runs the same sweep for orphans.
//!
//! ## `mount -p` parsing notes (fixtures captured on this host)
//!
//! `mount -p` prints fstab-style lines: `special node fstype options freq
//! passno`. Field separators are runs of **tabs**, except that a field
//! longer than its tab-stop column is followed by a **single space**
//! (verified: `tests/fixtures/mount_p_spaces.txt`, where a mountpoint
//! containing spaces is followed by ` tmpfs`). Paths containing spaces are
//! therefore representable but ambiguous; the parser resolves them by
//! scanning fields from the right (freq/passno/options/fstype contain no
//! spaces) and then splitting `special` from `node` at the last tab run —
//! or, when only a space separates them, at the first `" /"` boundary (a
//! mountpoint is always absolute). Paths containing tabs, or a special whose
//! name contains `" /"`, are not supported; SatL controls its own mount
//! sources and never generates such paths.

use std::path::{Path, PathBuf};

use crate::runner::{CommandOutput, CommandRunner, SystemRunner, render_argv};

/// Default location of the `mount` binary on FreeBSD.
pub const DEFAULT_MOUNT_BINARY: &str = "/sbin/mount";

/// Default location of the `umount` binary on FreeBSD.
pub const DEFAULT_UMOUNT_BINARY: &str = "/sbin/umount";

/// One line of `mount -p` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// The mounted device / dataset / source path / pseudo-fs token.
    pub special: String,
    /// The mountpoint.
    pub node: PathBuf,
    /// Filesystem type (`zfs`, `devfs`, `tmpfs`, `nullfs`, `linprocfs`, ...).
    pub fstype: String,
    /// Comma-separated mount options as printed (e.g. `rw,nosuid`).
    pub options: String,
}

/// Error from mount enumeration or unmounting. Every variant carries the
/// full command line; failures carry exit status and raw stderr.
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    /// A binary could not be spawned.
    #[error("failed to spawn `{argv}`: {source}")]
    Spawn {
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// A command ran but exited unsuccessfully.
    #[error("`{argv}` failed with {status}; stderr: {stderr}", status = render_exit(*exit_code), stderr = stderr.trim_end())]
    CommandFailed {
        /// Full rendered command line.
        argv: String,
        /// Exit code; `None` when killed by a signal.
        exit_code: Option<i32>,
        /// Raw stderr from the command.
        stderr: String,
    },

    /// `mount -p` output did not have the expected shape.
    #[error("unexpected output from `{argv}`: {reason}; offending line: {line:?}")]
    UnexpectedOutput {
        /// Full rendered command line.
        argv: String,
        /// Why the output was rejected.
        reason: String,
        /// The line that failed to parse.
        line: String,
    },

    /// A mountpoint survived both `umount` and `umount -f`.
    #[error(
        "cannot unmount {node} (leaked container mount): plain unmount said {plain_stderr:?}, \
         forced `{argv}` failed with {status}; stderr: {stderr}",
        status = render_exit(*exit_code), stderr = stderr.trim_end()
    )]
    UnmountFailed {
        /// The mountpoint that could not be unmounted.
        node: PathBuf,
        /// stderr of the initial non-forced attempt.
        plain_stderr: String,
        /// Full rendered command line of the forced attempt.
        argv: String,
        /// Exit code of the forced attempt.
        exit_code: Option<i32>,
        /// Raw stderr of the forced attempt.
        stderr: String,
    },
}

fn render_exit(exit_code: Option<i32>) -> String {
    match exit_code {
        Some(code) => format!("exit code {code}"),
        None => "termination by signal".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Pure argv builders.
// ---------------------------------------------------------------------------

fn args_mount_p() -> Vec<String> {
    vec!["-p".to_owned()]
}

fn args_umount(node: &Path, force: bool) -> Vec<String> {
    let mut args = Vec::new();
    if force {
        args.push("-f".to_owned());
    }
    args.push(node.display().to_string());
    args
}

// ---------------------------------------------------------------------------
// Pure parsers.
// ---------------------------------------------------------------------------

/// Strip one whitespace-separated token off the right end of `s`.
/// Returns `(head, token)` with `head` right-trimmed.
fn rsplit_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_end();
    let idx = s.rfind(|c: char| c.is_ascii_whitespace())?;
    Some((s[..idx].trim_end(), &s[idx + 1..]))
}

/// Split the `special SEP node` remainder of a `mount -p` line (see module
/// docs for the separator rules).
fn split_special_node(head: &str) -> Result<(String, PathBuf), String> {
    if let Some(tab) = head.rfind('\t') {
        // Separator is a run of tabs; `special` may itself contain spaces.
        let special = head[..tab].trim_end();
        let node = &head[tab + 1..];
        if !node.starts_with('/') {
            return Err(format!("mountpoint {node:?} is not an absolute path"));
        }
        return Ok((special.to_owned(), PathBuf::from(node)));
    }
    // Overflowed tab stop: a single space separates the fields. The
    // mountpoint is absolute, so split at the first `" /"` boundary.
    let Some(idx) = head.find(" /") else {
        return Err("cannot locate the special/mountpoint boundary".to_owned());
    };
    Ok((head[..idx].to_owned(), PathBuf::from(&head[idx + 1..])))
}

/// Parse one `mount -p` line.
fn parse_mount_p_line(line: &str) -> Result<MountEntry, String> {
    let (head, passno) = rsplit_token(line).ok_or("line has too few fields")?;
    let (head, freq) = rsplit_token(head).ok_or("line has too few fields")?;
    for (label, num) in [("passno", passno), ("dump freq", freq)] {
        if num.parse::<u32>().is_err() {
            return Err(format!("{label} field {num:?} is not a number"));
        }
    }
    let (head, options) = rsplit_token(head).ok_or("line has too few fields")?;
    let (head, fstype) = rsplit_token(head).ok_or("line has too few fields")?;
    let (special, node) = split_special_node(head)?;
    Ok(MountEntry {
        special,
        node,
        fstype: fstype.to_owned(),
        options: options.to_owned(),
    })
}

/// Parse full `mount -p` output.
fn parse_mount_p(stdout: &str) -> Result<Vec<MountEntry>, (String, String)> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| parse_mount_p_line(line).map_err(|reason| (reason, line.to_owned())))
        .collect()
}

/// The entries mounted **strictly below** `root` (never `root` itself: the
/// rootfs is a ZFS dataset owned by satl-storage, not ours to unmount).
/// Comparison is component-wise (`Path::starts_with`).
#[must_use]
pub fn entries_under<'e>(entries: &'e [MountEntry], root: &Path) -> Vec<&'e MountEntry> {
    entries
        .iter()
        .filter(|entry| entry.node.starts_with(root) && entry.node != root)
        .collect()
}

/// The task id a mount under a containers root belongs to: the first path
/// component below `containers_root`.
///
/// `None` for the containers root itself, for a path that is not under it, and
/// for the per-task rootfs directory (which has no component *below* the id and
/// is a ZFS dataset owned by `satl-storage`, never ours to unmount).
#[must_use]
pub fn task_of_mount(entry: &MountEntry, containers_root: &Path) -> Option<String> {
    let relative = entry.node.strip_prefix(containers_root).ok()?;
    let mut components = relative.components();
    let id = components.next()?;
    // Something below the id, or this is the rootfs dataset itself.
    components.next()?;
    Some(id.as_os_str().to_str()?.to_owned())
}

/// Mounts under `<containers_root>/<task id>/…` whose task id nothing claims,
/// deepest-first.
///
/// **This is the leak nothing else could see.** ocijail performs its bundle
/// mounts with `MNT_IGNORE`, so plain `mount`(8) does not list them at all
/// (mount(8): `-v` "show all file systems, including those that were mounted
/// with the `MNT_IGNORE` flag") -- which is why an audit that looks at jails,
/// epairs and datasets reports a clean node while devfs, fdescfs and a tmpfs
/// per dead task sit there. Worse, once the rootfs dataset under them is gone
/// they are orphaned: `statfs` on them fails, so `df` skips them silently too.
///
/// A mount whose task **is** claimed is left strictly alone: a stopped
/// container still holds its jail and its rootfs, and its `/tmp` is part of a
/// container that still exists as a record.
#[must_use]
pub fn orphan_mounts<'e>(
    entries: &'e [MountEntry],
    containers_root: &Path,
    claimed: &std::collections::BTreeSet<String>,
) -> Vec<&'e MountEntry> {
    let mut orphans: Vec<&MountEntry> = entries
        .iter()
        .filter(|entry| {
            task_of_mount(entry, containers_root).is_some_and(|task| !claimed.contains(&task))
        })
        .collect();
    let mut nodes: Vec<PathBuf> = orphans.iter().map(|entry| entry.node.clone()).collect();
    deepest_first(&mut nodes);
    orphans.sort_by_key(|entry| nodes.iter().position(|node| *node == entry.node));
    orphans
}

/// Order mountpoints deepest-first so nested mounts (`/dev/fd` inside
/// `/dev`) unmount before their parents.
fn deepest_first(nodes: &mut [PathBuf]) {
    nodes.sort_by(|a, b| {
        let depth = |p: &PathBuf| p.components().count();
        depth(b)
            .cmp(&depth(a))
            .then_with(|| b.as_os_str().len().cmp(&a.as_os_str().len()))
            .then_with(|| a.cmp(b))
    });
}

// ---------------------------------------------------------------------------
// The wrapper itself.
// ---------------------------------------------------------------------------

/// Typed async wrapper around `mount -p` / `umount(8)`.
#[derive(Debug, Clone)]
pub struct Mounts<R = SystemRunner> {
    mount_binary: PathBuf,
    umount_binary: PathBuf,
    runner: R,
}

impl Mounts<SystemRunner> {
    /// Wrapper executing the real binaries at [`DEFAULT_MOUNT_BINARY`] /
    /// [`DEFAULT_UMOUNT_BINARY`].
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for Mounts<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner> Mounts<R> {
    /// Wrapper using `runner` to execute commands (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            mount_binary: PathBuf::from(DEFAULT_MOUNT_BINARY),
            umount_binary: PathBuf::from(DEFAULT_UMOUNT_BINARY),
            runner,
        }
    }

    /// Override the binary paths (tests).
    #[must_use]
    pub fn with_binaries(
        mut self,
        mount_binary: impl Into<PathBuf>,
        umount_binary: impl Into<PathBuf>,
    ) -> Self {
        self.mount_binary = mount_binary.into();
        self.umount_binary = umount_binary.into();
        self
    }

    async fn exec(
        &self,
        binary: &Path,
        args: Vec<String>,
    ) -> Result<(String, CommandOutput), MountError> {
        let rendered = render_argv(binary, &args);
        tracing::debug!(command = %rendered, "running mount tool");
        let output = self
            .runner
            .run(binary, &args)
            .await
            .map_err(|source| MountError::Spawn {
                argv: rendered.clone(),
                source,
            })?;
        Ok((rendered, output))
    }

    /// All active mounts (`mount -p`). Note: plain `mount` does *not* list
    /// ocijail's nmount(2) mounts — `-p` (or `-v`) is required
    /// (docs/linuxulator.md).
    pub async fn list(&self) -> Result<Vec<MountEntry>, MountError> {
        let (argv, output) = self
            .exec(&self.mount_binary.clone(), args_mount_p())
            .await?;
        if !output.success() {
            return Err(MountError::CommandFailed {
                argv,
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }
        parse_mount_p(&output.stdout).map_err(|(reason, line)| MountError::UnexpectedOutput {
            argv,
            reason,
            line,
        })
    }

    /// Active mounts strictly below `root`, deepest-first.
    pub async fn active_mounts_under(&self, root: &Path) -> Result<Vec<MountEntry>, MountError> {
        let entries = self.list().await?;
        let mut under: Vec<MountEntry> =
            entries_under(&entries, root).into_iter().cloned().collect();
        let mut nodes: Vec<PathBuf> = under.iter().map(|entry| entry.node.clone()).collect();
        deepest_first(&mut nodes);
        under.sort_by_key(|entry| nodes.iter().position(|node| *node == entry.node));
        Ok(under)
    }

    /// Every mount under `containers_root` belonging to a task nothing claims,
    /// deepest-first ([`orphan_mounts`]).
    pub async fn orphan_mounts_under(
        &self,
        containers_root: &Path,
        claimed: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<MountEntry>, MountError> {
        let entries = self.list().await?;
        Ok(orphan_mounts(&entries, containers_root, claimed)
            .into_iter()
            .cloned()
            .collect())
    }

    /// Unmount the mounts of tasks nothing claims under `containers_root`.
    /// Returns what was unmounted.
    ///
    /// Unlike [`Self::unmount_all_under`] one failure does not abandon the
    /// rest: these are leftovers of different tasks with nothing in common, and
    /// a single busy mount must not stop the other fifty-three from being
    /// reclaimed. Each failure is one warn line naming the mountpoint and both
    /// attempts.
    pub async fn unmount_orphans_under(
        &self,
        containers_root: &Path,
        claimed: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<PathBuf>, MountError> {
        let orphans = self.orphan_mounts_under(containers_root, claimed).await?;
        let mut unmounted = Vec::with_capacity(orphans.len());
        for entry in orphans {
            let task = task_of_mount(&entry, containers_root).unwrap_or_default();
            match self.unmount_one(&entry).await? {
                Ok(()) => {
                    tracing::info!(
                        task_id = %task,
                        node = %entry.node.display(),
                        fstype = %entry.fstype,
                        "unmounted a leftover container mount no live task claims"
                    );
                    unmounted.push(entry.node);
                }
                Err(error) => tracing::warn!(
                    task_id = %task,
                    node = %entry.node.display(),
                    fstype = %entry.fstype,
                    %error,
                    "cannot unmount this leftover container mount; the next sweep \
                     will try again"
                ),
            }
        }
        Ok(unmounted)
    }

    /// Plain `umount`, then `umount -f`. The outer error is a failure to *run*
    /// the tool; the inner one is the mountpoint refusing both attempts.
    async fn unmount_one(&self, entry: &MountEntry) -> Result<Result<(), MountError>, MountError> {
        let (argv, output) = self
            .exec(&self.umount_binary.clone(), args_umount(&entry.node, false))
            .await?;
        if output.success() {
            return Ok(Ok(()));
        }
        let plain_stderr = output.stderr;
        tracing::debug!(node = %entry.node.display(), command = %argv,
            stderr = %plain_stderr.trim_end(), "plain umount failed; forcing");
        let (argv, output) = self
            .exec(&self.umount_binary.clone(), args_umount(&entry.node, true))
            .await?;
        if output.success() {
            return Ok(Ok(()));
        }
        Ok(Err(MountError::UnmountFailed {
            node: entry.node.clone(),
            plain_stderr,
            argv,
            exit_code: output.exit_code,
            stderr: output.stderr,
        }))
    }

    /// Unmount everything strictly below `root`, deepest-first. Returns the
    /// mountpoints that were unmounted.
    ///
    /// Each mountpoint gets a plain `umount` first; on failure it is retried
    /// as `umount -f` (`MNT_FORCE` — the same flag ocijail's own delete path
    /// uses; needed when a leaked devfs/tmpfs is still busy, e.g. a process
    /// with an open file or cwd inside). Only a failed *forced* unmount is an
    /// error, and it names the mountpoint plus both attempts' diagnostics.
    pub async fn unmount_all_under(&self, root: &Path) -> Result<Vec<PathBuf>, MountError> {
        let entries = self.active_mounts_under(root).await?;
        let mut unmounted = Vec::with_capacity(entries.len());
        for entry in entries {
            let (argv, output) = self
                .exec(&self.umount_binary.clone(), args_umount(&entry.node, false))
                .await?;
            if output.success() {
                tracing::info!(node = %entry.node.display(), fstype = %entry.fstype,
                    "unmounted leaked container mount");
                unmounted.push(entry.node);
                continue;
            }
            let plain_stderr = output.stderr;
            tracing::warn!(node = %entry.node.display(), command = %argv,
                stderr = %plain_stderr.trim_end(), "plain umount failed; forcing");
            let (argv, output) = self
                .exec(&self.umount_binary.clone(), args_umount(&entry.node, true))
                .await?;
            if output.success() {
                tracing::info!(node = %entry.node.display(), fstype = %entry.fstype,
                    "force-unmounted leaked container mount");
                unmounted.push(entry.node);
            } else {
                return Err(MountError::UnmountFailed {
                    node: entry.node,
                    plain_stderr,
                    argv,
                    exit_code: output.exit_code,
                    stderr: output.stderr,
                });
            }
        }
        Ok(unmounted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    const FIXTURE_HOST: &str = include_str!("../tests/fixtures/mount_p_host.txt");
    const FIXTURE_SPACES: &str = include_str!("../tests/fixtures/mount_p_spaces.txt");

    #[test]
    fn argv_builders() {
        assert_eq!(args_mount_p(), ["-p"]);
        assert_eq!(args_umount(Path::new("/a/b"), false), ["/a/b"]);
        assert_eq!(args_umount(Path::new("/a/b"), true), ["-f", "/a/b"]);
    }

    #[test]
    fn parse_real_host_output() {
        let entries = parse_mount_p(FIXTURE_HOST).unwrap();
        assert!(
            entries.len() >= 20,
            "host fixture has {} lines",
            entries.len()
        );
        let root = &entries[0];
        assert_eq!(root.special, "zroot/ROOT/default");
        assert_eq!(root.node, PathBuf::from("/"));
        assert_eq!(root.fstype, "zfs");
        assert_eq!(root.options, "rw,nfsv4acls");
        // The linuxulator host mounts exercise every fstype we care about.
        let by_node = |node: &str| {
            entries
                .iter()
                .find(|entry| entry.node == Path::new(node))
                .unwrap_or_else(|| panic!("no entry for {node}"))
        };
        assert_eq!(by_node("/compat/linux/proc").fstype, "linprocfs");
        assert_eq!(by_node("/compat/linux/dev/fd").fstype, "fdescfs");
        assert_eq!(by_node("/compat/linux/dev/shm").fstype, "tmpfs");
        assert_eq!(by_node("/dev").special, "devfs");
    }

    #[test]
    fn parse_paths_with_spaces() {
        // Real captured output: a tmpfs on a mountpoint containing spaces
        // (single-space separator after the long node) and a nullfs whose
        // special contains spaces (tab separator).
        let entries = parse_mount_p(FIXTURE_SPACES).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].special, "tmpfs");
        assert_eq!(entries[0].node, PathBuf::from("/tmp/rtest mount dir/inner"));
        assert_eq!(entries[0].fstype, "tmpfs");
        assert_eq!(entries[1].special, "/tmp/rtest src dir");
        assert_eq!(entries[1].node, PathBuf::from("/tmp/rtest-plainmnt"));
        assert_eq!(entries[1].fstype, "nullfs");
        assert_eq!(entries[1].options, "ro");
    }

    #[test]
    fn parse_rejects_garbage() {
        let err = parse_mount_p("not a mount line\n").unwrap_err();
        assert!(err.0.contains("not a number"), "{err:?}");
    }

    #[test]
    fn entries_under_is_strict() {
        let entries = parse_mount_p(FIXTURE_HOST).unwrap();
        let under = entries_under(&entries, Path::new("/compat/linux"));
        let nodes: Vec<_> = under
            .iter()
            .map(|entry| entry.node.display().to_string())
            .collect();
        assert_eq!(
            nodes,
            [
                "/compat/linux/proc",
                "/compat/linux/sys",
                "/compat/linux/dev",
                "/compat/linux/dev/fd",
                "/compat/linux/dev/shm",
            ]
        );
        // Prefix matching is component-wise: /compat/linux-foo must not match.
        assert!(entries_under(&entries, Path::new("/compat/li")).is_empty());
        // The root itself is never returned.
        assert!(
            entries_under(&entries, Path::new("/dev"))
                .iter()
                .all(|entry| entry.node != Path::new("/dev"))
        );
    }

    // ---- leftover container mounts -----------------------------------------

    /// Captured on cluster node1 with `mount -p`: two tasks that were removed
    /// long ago, each still holding devfs, fdescfs and a tmpfs `/tmp`, with no
    /// container dataset left under them. Neither plain `mount` nor
    /// `df -t tmpfs` shows any of it.
    const FIXTURE_ORPHANS: &str = include_str!("../tests/fixtures/mount_p_orphan_containers.txt");
    /// Captured on the dev host: containers that still exist as records
    /// (stopped, not removed), each with its rootfs dataset and its bundle
    /// mounts. Every one of these must be left alone.
    const FIXTURE_LIVE: &str = include_str!("../tests/fixtures/mount_p_live_containers.txt");

    const CONTAINERS_ROOT: &str = "/var/db/satl/containers";

    fn claims(ids: &[&str]) -> std::collections::BTreeSet<String> {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    #[test]
    fn the_task_a_mount_belongs_to_is_the_component_below_the_root() {
        let entries = parse_mount_p(FIXTURE_LIVE).unwrap();
        let root = Path::new(CONTAINERS_ROOT);
        let tmp = entries
            .iter()
            .find(|entry| entry.node.ends_with("2qw3gxb4uklpaowonekzukj02/tmp"))
            .expect("the nginx container's /tmp");
        assert_eq!(
            task_of_mount(tmp, root).as_deref(),
            Some("2qw3gxb4uklpaowonekzukj02")
        );
        // The containers root itself and a task's rootfs dataset are not
        // per-task mounts: the rootfs belongs to satl-storage.
        for node in [
            CONTAINERS_ROOT,
            "/var/db/satl/containers/2qw3gxb4uklpaowonekzukj02",
        ] {
            let entry = entries
                .iter()
                .find(|entry| entry.node == Path::new(node))
                .unwrap_or_else(|| panic!("no entry for {node}"));
            assert_eq!(task_of_mount(entry, root), None, "{node}");
        }
    }

    /// The measured leak: 54 task ids per node with three mounts each, all of
    /// them invisible to the tools an audit normally reaches for.
    #[test]
    fn every_mount_of_a_task_nothing_claims_is_an_orphan() {
        let entries = parse_mount_p(FIXTURE_ORPHANS).unwrap();
        let orphans = orphan_mounts(&entries, Path::new(CONTAINERS_ROOT), &claims(&[]));
        assert_eq!(orphans.len(), 6, "{orphans:?}");
        let fstypes: std::collections::BTreeSet<&str> =
            orphans.iter().map(|entry| entry.fstype.as_str()).collect();
        assert_eq!(
            fstypes,
            std::collections::BTreeSet::from(["devfs", "fdescfs", "tmpfs"]),
            "the leak is the whole bundle mount set, not only the tmpfs"
        );
        // Every `/dev/fd` comes before every `/dev`, or the parent unmount is
        // refused for a reason nobody had to guess at.
        let last_fd = orphans
            .iter()
            .rposition(|entry| entry.fstype == "fdescfs")
            .expect("an fdescfs orphan");
        let first_dev = orphans
            .iter()
            .position(|entry| entry.fstype == "devfs")
            .expect("a devfs orphan");
        assert!(last_fd < first_dev, "{orphans:?}");
    }

    /// A stopped container is still a record, still has a jail and still has a
    /// rootfs. Its `/tmp` is not a leftover, and unmounting it would break a
    /// container the operator can still inspect.
    #[test]
    fn the_mounts_of_a_claimed_task_are_never_orphans() {
        let entries = parse_mount_p(FIXTURE_LIVE).unwrap();
        let claimed = claims(&[
            "1q8c4zamgo7wdgxj13tcoepua",
            "1jwtggzjzcfp20d23s2rwv72f",
            "2blf7rzo7agylb7ixbkafhaff",
            "2qw3gxb4uklpaowonekzukj02",
        ]);
        assert!(
            orphan_mounts(&entries, Path::new(CONTAINERS_ROOT), &claimed).is_empty(),
            "a claimed task's mounts must be left strictly alone"
        );
        // Drop one claim and only that task's mounts become orphans.
        let mut partial = claimed.clone();
        partial.remove("1q8c4zamgo7wdgxj13tcoepua");
        let orphans = orphan_mounts(&entries, Path::new(CONTAINERS_ROOT), &partial);
        assert_eq!(orphans.len(), 6, "{orphans:?}");
        assert!(orphans.iter().all(|entry| {
            entry
                .node
                .starts_with("/var/db/satl/containers/1q8c4zamgo7wdgxj13tcoepua")
        }));
    }

    /// Nothing outside the containers root is any of this sweep's business —
    /// the host's own `/compat/linux` mounts look exactly like a container's.
    #[test]
    fn mounts_outside_the_containers_root_are_ignored() {
        let entries = parse_mount_p(FIXTURE_HOST).unwrap();
        assert!(
            orphan_mounts(&entries, Path::new(CONTAINERS_ROOT), &claims(&[])).is_empty(),
            "the host fixture has no container mounts at all"
        );
    }

    #[tokio::test]
    async fn unmounting_orphans_carries_on_past_one_that_refuses() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_ORPHANS, ""); // mount -p
        mock.push_output(0, "", ""); // orphan 1: fine
        mock.push_output(1, "", "umount: Device busy\n"); // orphan 2: plain fails
        mock.push_output(1, "", "umount: unmount failed\n"); //           forced too
        for _ in 0..4 {
            mock.push_output(0, "", ""); // orphans 3-6: fine
        }
        let mounts = Mounts::with_runner(&mock);
        let unmounted = mounts
            .unmount_orphans_under(Path::new(CONTAINERS_ROOT), &claims(&[]))
            .await
            .unwrap();
        assert_eq!(
            unmounted.len(),
            5,
            "one busy mountpoint must not abandon the other five: {unmounted:?}"
        );
        assert_eq!(
            mock.calls().len(),
            8,
            "one listing, then six mountpoints (one of them twice): {:?}",
            mock.calls()
        );
    }

    #[test]
    fn deepest_first_orders_nested_before_parent() {
        let mut nodes = vec![
            PathBuf::from("/r/dev"),
            PathBuf::from("/r/dev/fd"),
            PathBuf::from("/r/tmp"),
            PathBuf::from("/r/dev/shm"),
        ];
        deepest_first(&mut nodes);
        // Same depth ties break on length, then lexicographically — the only
        // property that matters is child-before-parent.
        assert_eq!(
            nodes,
            [
                PathBuf::from("/r/dev/shm"),
                PathBuf::from("/r/dev/fd"),
                PathBuf::from("/r/dev"),
                PathBuf::from("/r/tmp"),
            ]
        );
    }

    #[tokio::test]
    async fn unmount_all_under_runs_deepest_first_with_force_fallback() {
        let mock = MockRunner::new();
        let listing = "devfs\t\t\t/r/c1/dev devfs\trw\t\t0 0\n\
                       fdescfs\t\t\t/r/c1/dev/fd fdescfs\trw\t\t0 0\n\
                       tmpfs\t\t\t/r/c1/tmp tmpfs\trw\t\t0 0\n\
                       zroot/other\t\t/elsewhere\tzfs\trw\t\t0 0\n";
        mock.push_output(0, listing, "");
        mock.push_output(0, "", ""); // umount /r/c1/dev/fd
        mock.push_output(1, "", "umount: /r/c1/dev: Device busy\n"); // plain fails
        mock.push_output(0, "", ""); // umount -f /r/c1/dev
        mock.push_output(0, "", ""); // umount /r/c1/tmp
        let mounts = Mounts::with_runner(&mock);
        let unmounted = mounts.unmount_all_under(Path::new("/r/c1")).await.unwrap();
        assert_eq!(
            unmounted,
            [
                PathBuf::from("/r/c1/dev/fd"),
                PathBuf::from("/r/c1/dev"),
                PathBuf::from("/r/c1/tmp"),
            ]
        );
        assert_eq!(
            mock.calls(),
            [
                "/sbin/mount -p",
                "/sbin/umount /r/c1/dev/fd",
                "/sbin/umount /r/c1/dev",
                "/sbin/umount -f /r/c1/dev",
                "/sbin/umount /r/c1/tmp",
            ]
        );
    }

    #[tokio::test]
    async fn forced_unmount_failure_names_the_mountpoint() {
        let mock = MockRunner::new();
        mock.push_output(0, "devfs\t\t\t/r/c1/dev devfs\trw\t\t0 0\n", "");
        mock.push_output(1, "", "umount: /r/c1/dev: Device busy\n");
        mock.push_output(1, "", "umount: /r/c1/dev: unmount failed\n");
        let mounts = Mounts::with_runner(&mock);
        let err = mounts
            .unmount_all_under(Path::new("/r/c1"))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/r/c1/dev"), "{msg}");
        assert!(msg.contains("/sbin/umount -f /r/c1/dev"), "{msg}");
        assert!(msg.contains("Device busy"), "{msg}");
        assert!(msg.contains("unmount failed"), "{msg}");
    }
}
