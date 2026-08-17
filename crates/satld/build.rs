// SPDX-License-Identifier: BSD-2-Clause
//! Emits the `SATL_GIT_COMMIT` / `SATL_BUILD_TIME` variables that
//! `src/main.rs` reads through `option_env!` for the startup banner and the
//! `/version` reply.
//!
//! The build must not fail outside a git checkout (release tarball, pkg
//! source tree): when `.git/HEAD` is absent or `git` fails, the commit
//! variable is simply not emitted and `option_env!` falls back to
//! `"unknown"`.

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let git_head = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.git/HEAD");

    if git_head.exists() {
        // Rebuild on branch switches / checkouts; commits on the current
        // branch do not touch `.git/HEAD` itself, but tracking the ref file
        // too would rebuild on every commit — this is the standard trade-off.
        println!("cargo:rerun-if-changed={}", git_head.display());
        if let Some(commit) = git_commit() {
            println!("cargo:rustc-env=SATL_GIT_COMMIT={commit}");
        }
    }

    println!("cargo:rustc-env=SATL_BUILD_TIME={}", utc_now());
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
