// SPDX-License-Identifier: BSD-2-Clause
//! Emits the `SATL_GIT_COMMIT` / `SATL_BUILD_TIME` variables that
//! `src/main.rs` reads through `option_env!` for the startup banner and the
//! `/version` reply.
//!
//! The build must not fail outside a git checkout (release tarball, pkg
//! source tree): when `.git/HEAD` is absent or `git` fails, the commit
//! variable is simply not emitted and `option_env!` falls back to
//! `"unknown"`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Emitting ANY `cargo:rerun-if-changed` opts this script out of cargo's
    // default "re-run when any file in the package changed". Narrowing it to
    // `.git/HEAD` alone is what made `satl --version` lie: a source change
    // rebuilt the binary without re-running this script, so the new binary
    // carried the previous build's timestamp. Observed as a binary rebuilt at
    // 07:38 reporting `Built: 2026-08-23T11:35:34Z`, and it cost real time --
    // the deployment looked like it had not happened.
    //
    // Three signals, each covering one way the answer can go stale:
    //   * the crate's own sources — a rebuilt binary gets a fresh timestamp;
    //   * `.git/HEAD` — a branch switch or a detached checkout;
    //   * the ref `.git/HEAD` points at — a commit on the current branch,
    //     which does not touch `HEAD` itself.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");

    let git_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.git");
    let git_head = git_dir.join("HEAD");
    if git_head.exists() {
        println!("cargo:rerun-if-changed={}", git_head.display());
        if let Some(ref_path) = head_ref_path(&git_dir, &git_head) {
            // Absent on a branch whose ref lives in `packed-refs` (a fresh
            // clone), where `HEAD` moving is the only signal there is.
            if ref_path.exists() {
                println!("cargo:rerun-if-changed={}", ref_path.display());
            }
        }
        if let Some(commit) = git_commit() {
            println!("cargo:rustc-env=SATL_GIT_COMMIT={commit}");
        }
    }

    println!("cargo:rustc-env=SATL_BUILD_TIME={}", utc_now());
}

/// The file `.git/HEAD` points at, for a HEAD on a branch.
///
/// `None` for a detached HEAD, where `HEAD` holds the sha itself and is
/// already tracked.
fn head_ref_path(git_dir: &Path, git_head: &Path) -> Option<PathBuf> {
    let head = std::fs::read_to_string(git_head).ok()?;
    let reference = head.trim().strip_prefix("ref:")?.trim();
    Some(git_dir.join(reference))
}

/// `git rev-parse --short HEAD`, or `None` when git is missing or unhappy.
fn git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!commit.is_empty()).then_some(commit)
}

/// Current time as `YYYY-MM-DDTHH:MM:SSZ` in UTC, formatted by hand: the
/// workspace has no date/time crate and this conversion is a few lines of
/// well-known arithmetic (Howard Hinnant's civil-from-days algorithm).
fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
    )
}

/// Days since 1970-01-01 → (year, month, day) in the proleptic Gregorian
/// calendar.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    // Shift the epoch to 0000-03-01 so leap days fall at the end of each
    // 400-year era.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era, [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, [0, 365]
    let mp = (5 * doy + 2) / 153; // month index from March, [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}
