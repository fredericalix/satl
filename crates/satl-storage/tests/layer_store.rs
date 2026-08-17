// SPDX-License-Identifier: BSD-2-Clause
//! Real-ZFS integration tests for the layer store (`docs/architecture.md`
//! §10). Root + ZFS required; `#[ignore]`-gated, run via `make integration`.
//!
//! Everything happens inside a sandbox dataset (`zroot/satl-inttest-<pid>`)
//! created here and destroyed by a drop guard even on panic — never under
//! `zroot/satl`.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use satl_storage::{ContainerFsStore, LayerCompression, LayerSource, LayerStore, Zfs};
use sha2::{Digest as _, Sha256};

const ZFS: &str = "/sbin/zfs";

/// Run a zfs command, panicking with full context on failure (test setup /
/// assertions only — production code goes through the typed wrapper).
fn zfs_cmd(args: &[&str]) -> String {
    let output = Command::new(ZFS)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to spawn `{ZFS} {}`: {err}", args.join(" ")));
    assert!(
        output.status.success(),
        "`{ZFS} {}` failed ({}): {}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn zfs_dataset_exists(name: &str) -> bool {
    Command::new(ZFS)
        .args(["list", "-H", "-o", "name", name])
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Sandbox dataset tree, destroyed on drop (also on panic).
struct Sandbox {
    root: String,
    mountpoint: PathBuf,
}

impl Sandbox {
    fn create() -> Self {
        let root = format!("zroot/satl-inttest-{}", std::process::id());
        let mountpoint = PathBuf::from(format!("/tmp/{}", root.replace('/', "-")));
        assert!(
            !zfs_dataset_exists(&root),
            "sandbox dataset {root} already exists; clean it up first"
        );
        zfs_cmd(&[
            "create",
            "-o",
            &format!("mountpoint={}", mountpoint.display()),
            &root,
        ]);
        zfs_cmd(&["create", &format!("{root}/layers")]);
        zfs_cmd(&["create", &format!("{root}/containers")]);
        Self { root, mountpoint }
    }

    fn layers_root(&self) -> String {
        format!("{}/layers", self.root)
    }

    fn containers_root(&self) -> String {
        format!("{}/containers", self.root)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let status = Command::new(ZFS)
            .args(["destroy", "-r", &self.root])
            .status();
        match status {
            Ok(status) if status.success() => {}
            other => eprintln!(
                "WARNING: failed to destroy sandbox dataset {}: {other:?}; \
                 clean up manually with `zfs destroy -r {}`",
                self.root, self.root
            ),
        }
        let _ = fs::remove_dir_all(&self.mountpoint);
    }
}

// ---------------------------------------------------------------------------
// In-memory synthetic layers
// ---------------------------------------------------------------------------

fn base_header(entry_type: tar::EntryType, mode: u32, size: u64) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(mode);
    header.set_size(size);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(1_700_000_000);
    header
}

fn add_file(b: &mut tar::Builder<Vec<u8>>, path: &str, content: &[u8]) {
    let mut header = base_header(tar::EntryType::Regular, 0o644, content.len() as u64);
    b.append_data(&mut header, path, content).unwrap();
}

fn add_dir(b: &mut tar::Builder<Vec<u8>>, path: &str) {
    let mut header = base_header(tar::EntryType::Directory, 0o755, 0);
    b.append_data(&mut header, path, &[][..]).unwrap();
}

fn add_symlink(b: &mut tar::Builder<Vec<u8>>, path: &str, target: &str) {
    let mut header = base_header(tar::EntryType::Symlink, 0o777, 0);
    b.append_link(&mut header, path, target).unwrap();
}

fn build_tar(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    build(&mut builder);
    builder.into_inner().unwrap()
}

fn diff_id_of(tar_bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(tar_bytes)))
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

/// Two-layer synthetic image: layer 2 whiteouts a layer-1 file and makes a
/// layer-1 directory opaque. Layer 1 is uncompressed, layer 2 gzipped.
fn synthetic_image(blob_dir: &Path) -> Vec<LayerSource> {
    let layer1 = build_tar(|b| {
        add_dir(b, "etc");
        add_file(b, "etc/hello.txt", b"hello from layer one\n");
        add_dir(b, "data");
        add_file(b, "data/keep.txt", b"keep me\n");
        add_file(b, "data/removeme.txt", b"doomed\n");
        add_dir(b, "opq");
        add_file(b, "opq/old1.txt", b"lower 1\n");
        add_file(b, "opq/old2.txt", b"lower 2\n");
        add_symlink(b, "link-to-hello", "etc/hello.txt");
    });
    let layer2 = build_tar(|b| {
        add_dir(b, "etc");
        add_file(b, "etc/hello2.txt", b"hello from layer two\n");
        add_file(b, "data/.wh.removeme.txt", b"");
        add_dir(b, "opq");
        add_file(b, "opq/.wh..wh..opq", b"");
        add_file(b, "opq/new.txt", b"fresh in layer two\n");
    });

    let blob1 = blob_dir.join("layer1.tar");
    fs::write(&blob1, &layer1).unwrap();
    let blob2 = blob_dir.join("layer2.tar.gz");
    fs::write(&blob2, gzip(&layer2)).unwrap();

    vec![
        LayerSource {
            diff_id: diff_id_of(&layer1),
            blob_path: blob1,
            compression: LayerCompression::None,
        },
        LayerSource {
            diff_id: diff_id_of(&layer2),
            blob_path: blob2,
            compression: LayerCompression::Gzip,
        },
    ]
}

/// `name<TAB>createtxg` per dataset — a changed `createtxg` would prove a
/// dataset was re-created behind our back.
fn datasets_with_createtxg(root: &str) -> String {
    zfs_cmd(&["list", "-H", "-p", "-r", "-o", "name,createtxg", root])
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires root and ZFS (sandbox dataset); run via make integration"]
async fn layer_store_end_to_end() {
    let sandbox = Sandbox::create();
    let blob_dir = tempfile::tempdir().unwrap();
    let layers = synthetic_image(blob_dir.path());

    // --- apply the 2-layer image -------------------------------------------
    let store = LayerStore::new(Zfs::system(), sandbox.layers_root());
    let top = store.apply_image(&layers).await.unwrap();

    let top_mount = sandbox.mountpoint.join("layers").join(top.hex());
    assert_eq!(
        fs::read_to_string(top_mount.join("etc/hello.txt")).unwrap(),
        "hello from layer one\n"
    );
    assert_eq!(
        fs::read_to_string(top_mount.join("etc/hello2.txt")).unwrap(),
        "hello from layer two\n"
    );
    assert!(top_mount.join("data/keep.txt").exists());
    assert!(
        !top_mount.join("data/removeme.txt").exists(),
        "whiteout in layer 2 must remove the layer-1 file"
    );
    let mut opq_children: Vec<String> = fs::read_dir(top_mount.join("opq"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    opq_children.sort();
    assert_eq!(
        opq_children,
        ["new.txt"],
        "opaque marker must hide all layer-1 children"
    );
    assert_eq!(
        fs::read_link(top_mount.join("link-to-hello")).unwrap(),
        PathBuf::from("etc/hello.txt")
    );

    // Both layer datasets carry their @final snapshot.
    let snapshots = zfs_cmd(&[
        "list",
        "-H",
        "-t",
        "snapshot",
        "-o",
        "name",
        "-r",
        &sandbox.layers_root(),
    ]);
    let snapshot_count = snapshots
        .lines()
        .filter(|line| line.ends_with("@final"))
        .count();
    assert_eq!(snapshot_count, 2, "snapshots seen:\n{snapshots}");

    // --- idempotent re-apply: zero new (or re-created) datasets ------------
    let before = datasets_with_createtxg(&sandbox.layers_root());
    let top_again = store.apply_image(&layers).await.unwrap();
    assert_eq!(top_again, top);
    let after = datasets_with_createtxg(&sandbox.layers_root());
    assert_eq!(
        before, after,
        "re-apply must neither create nor re-create datasets"
    );

    // --- container clone lifecycle -----------------------------------------
    let containers = ContainerFsStore::new(Zfs::system(), sandbox.containers_root());
    let rootfs = containers
        .create("task-inttest-1", &top, &sandbox.layers_root())
        .await
        .unwrap();
    assert_eq!(
        fs::read_to_string(rootfs.join("etc/hello.txt")).unwrap(),
        "hello from layer one\n"
    );
    // The clone is writable and writes stay out of the image layers.
    fs::write(rootfs.join("scratch.txt"), "container-local\n").unwrap();
    assert!(!top_mount.join("scratch.txt").exists());
    assert_eq!(containers.list().await.unwrap(), ["task-inttest-1"]);

    containers.destroy("task-inttest-1").await.unwrap();
    assert!(
        !zfs_dataset_exists(&format!("{}/task-inttest-1", sandbox.containers_root())),
        "container dataset must be gone after destroy"
    );
    assert!(containers.list().await.unwrap().is_empty());
}
