// SPDX-License-Identifier: BSD-2-Clause
//! `satl-jail-arp` — the ARP helper child, as a standalone binary.
//!
//! **This is not how the daemon uses the mechanism.** `satld` re-executes
//! *itself* with `satl_overlay::HELPER_SUBCOMMAND` (see
//! `satl_overlay::arphelper`), precisely so that there is one artefact to build,
//! install and version. This binary exists for two narrower reasons:
//!
//! 1. **The integration tests need a real child.** Cargo's test harness parses
//!    argv before any `#[test]` body runs, so a test binary cannot be given a
//!    second personality by argument; `CARGO_BIN_EXE_satl-jail-arp` gives the
//!    tests an exact path to a process that runs the real
//!    [`satl_overlay::child_main`], so the production code path is what gets
//!    exercised rather than a re-implementation of it.
//! 2. **It is a usable diagnostic.** A container has no `arp`(8), so there is
//!    otherwise no way to look at a task's ARP table by hand. This reads it:
//!
//!    ```sh
//!    printf 'satl-arp-request 1\njail 12\n' | satl-jail-arp
//!    ```
//!
//! It is deliberately not installed by `make install`.

fn main() -> std::process::ExitCode {
    // One statement, because everything the child does has to happen after the
    // `exec` and nothing may happen before it: this process calls
    // `jail_attach`(2) and can never leave.
    std::process::ExitCode::from(satl_overlay::child_main())
}
