// SPDX-License-Identifier: BSD-2-Clause
//! `satl` binary entry point; everything else lives in the library so it can
//! be tested in-process against a stub daemon.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    satl_cli::cli::main().await
}
