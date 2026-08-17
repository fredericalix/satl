// SPDX-License-Identifier: BSD-2-Clause
//! ZFS layer store: typed zfs(8) wrappers, datasets, snapshots, clones, GC.
//! See `docs/architecture.md` §10.
//!
//! - [`zfs`]: the typed zfs(8) wrapper (injectable runner, fixture-tested
//!   parsers) and the [`preflight`] check validating the dataset layout.
//! - [`chain`]: pure OCI chain-ID computation (dataset naming scheme).
//! - [`unpack`]: layer tar application into a directory (whiteouts, digest
//!   verification), sync core + `spawn_blocking` async wrapper.
//! - [`layers`]: [`LayerStore`] — one dataset per applied layer chain,
//!   `@final` snapshots, idempotent image application.
//! - [`container_fs`]: [`ContainerFsStore`] — per-task writable clones of an
//!   image's top layer.
//! - [`volumes`]: [`VolumeStore`] — named node-local volumes, one dataset
//!   each, nullfs-mounted into jails.
//!
//! - [`gc`]: the pure planner behind `satl system prune`'s layer reclamation —
//!   what nothing references, and the two-pass agreement that has to hold
//!   before anything is destroyed.

pub mod chain;
pub mod container_fs;
pub mod gc;
pub mod layers;
pub mod preflight;
pub mod unpack;
pub mod volumes;
pub mod zfs;

pub use chain::{ChainId, ChainIdError, chain_id, chains_of};
pub use container_fs::{ContainerFsError, ContainerFsStore};
pub use gc::{LayerClaims, LayerOnDisk, LayerSweeper, unreferenced};
pub use layers::{FINAL_SNAPSHOT, LayerSource, LayerStore, LayerStoreError};
pub use preflight::{CHILD_DATASETS, PreflightError, StoragePreflight, preflight};
pub use unpack::{LayerCompression, UnpackError, UnpackSummary, unpack_layer, unpack_layer_sync};
pub use volumes::{VolumeInfo, VolumeStore, VolumeStoreError};
pub use zfs::{
    CommandOutput, CommandRunner, DatasetInfo, DatasetOriginInfo, DatasetSpace, SystemRunner, Zfs,
    ZfsError,
};
