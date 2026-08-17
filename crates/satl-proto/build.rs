// SPDX-License-Identifier: BSD-2-Clause
//! Generates the tonic client/server stubs for `proto/*.proto`.
//!
//! Two deliberate choices here:
//!
//! 1. **No `protoc`.** The `.proto` files are compiled to a
//!    `FileDescriptorSet` by [`protox`], a pure-Rust protobuf compiler, and
//!    that descriptor set is handed to `tonic-prost-build`. `prost-build` 0.14
//!    otherwise requires a `protoc` binary on the build host (it has no
//!    vendored-protobuf feature), which would put a C++ toolchain dependency in
//!    the path of every `cargo build` — on the dev host, on the cluster VMs,
//!    and in any future CI image. `cargo build` is the only build requirement.
//!
//! 2. **Lints are suppressed at the module level, not here.** The generated
//!    code does not satisfy the workspace's `clippy::pedantic -D warnings`
//!    gate, and `#[allow]`s injected through the builder would have to be
//!    repeated per type. `src/lib.rs` wraps each generated module in a single
//!    `#[allow(...)]` block instead — see the comment there.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    let proto_dir = proto_dir.canonicalize().map_err(|e| {
        format!(
            "cannot locate the proto directory at {}: {e}",
            proto_dir.display()
        )
    })?;

    // Every file is listed explicitly: a new `.proto` that nobody adds here is
    // a silent no-op, which is a worse failure than a compile error.
    let files = [
        "common.proto",
        "dispatcher.proto",
        "ca.proto",
        "raft.proto",
        "control.proto",
        "health.proto",
    ];

    println!("cargo:rerun-if-changed={}", proto_dir.display());
    for file in files {
        println!("cargo:rerun-if-changed={}", proto_dir.join(file).display());
    }

    let paths: Vec<PathBuf> = files.iter().map(|f| proto_dir.join(f)).collect();

    // The descriptor set keeps the transitively imported well-known types
    // (`google/protobuf/*.proto`). They must stay: `prost-build` walks the
    // message graph of every field type, so removing them panics it. Their
    // Rust types are still not emitted: `prost-build` maps the
    // `google.protobuf` package onto the `prost-types` crate, so OUT_DIR ends
    // up with exactly the two modules `src/lib.rs` includes.
    let descriptors = protox::compile(&paths, [&proto_dir])?;

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(descriptors)?;

    Ok(())
}
