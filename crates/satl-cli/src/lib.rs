// SPDX-License-Identifier: BSD-2-Clause
//! `satl` — docker-compatible CLI client for satld.
//!
//! Thin REST client: every command talks Docker Engine API v1.43 to the
//! daemon socket; the CLI never speaks gRPC (architecture §1). The whole CLI
//! lives in this library so the verbs can be driven in-process against a stub
//! daemon in tests; `src/main.rs` is only an entry point.

pub mod api;
pub mod cli;
pub mod client;
pub mod cmd;
pub mod format;
pub mod frames;
pub mod ndjson;
pub mod output;
pub mod parse;
pub mod version;

#[cfg(test)]
mod stub;
