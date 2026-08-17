// SPDX-License-Identifier: BSD-2-Clause
//! Layer garbage collection: deciding which layer datasets nothing references
//! any more, and refusing to decide it from one look.
//!
//! Everything in this module is **pure**. It takes a reading of the disk and a
//! reading of the node's records, and returns names. Nothing here runs `zfs`,
//! which is what makes the dangerous part of `satl system prune` testable at
//! all: the interesting cases (a layer held only by a stopped container, a
//! chain whose image record is gone, a claim set that was momentarily
//! incomplete) are all expressible as data.
//!
//! ## What counts as a reference
//!
//! A layer dataset `<layers_root>/<chain hex>` is referenced when any of these
//! holds:
//!
//! 1. **An image record names it.** Folding [`crate::chain_id`] over an image's
//!    `diff_ids` yields every chain in that image's stack, not only the top
//!    one, and all of them are references. Image records are written *before*
//!    the datasets they describe are created (`satl-image` records the
//!    repository entry during `pull`, `satl-storage` applies layers after), so
//!    a layer can never exist with its record still missing.
//! 2. **A clone holds its `@final` snapshot.** A container's writable layer is
//!    a clone of the image's top `@final`, and layer N+1 is a clone of layer
//!    N's. ZFS itself reports that edge as the clone's `origin`, and it is the
//!    only claim that survives the image record being replaced — a re-pulled
//!    tag overwrites its entry in place, so a **stopped** container can easily
//!    be the last thing in the world that wants a chain. Collecting it would
//!    destroy that container's filesystem, which is why the origin edge is a
//!    first-class reference here and not an afterthought.
//! 3. **It is being applied right now.** [`crate::LayerStore`] serializes
//!    applies of one chain behind a mutex; a chain holding that mutex is
//!    claimed even though no snapshot proves it yet.
//!
//! And the claim is **transitive upward**: whatever claims a chain claims its
//! whole ancestry, reconstructed from the `origin` edges on disk. Without that
//! closure a stopped container would protect only its top layer and the GC
//! would go after the layers underneath it — where ZFS would refuse
//! (`filesystem has dependent clones`) and the sweep would report the same
//! failure forever.
//!
//! ## Two passes, and why one is not enough
//!
//! [`LayerSweeper`] destroys nothing that was not unreferenced on **two
//! consecutive passes**, exactly as `satld`'s dataset sweep does (commit
//! `27ccb64`). The reason is the same and it is not theoretical: the claim set
//! is assembled from readings that are each momentarily incomplete at
//! different times — a store just after a leadership change, a worker just
//! after a restart, an image store mid-pull. One pass in which a reading
//! disagrees with the disk must not be enough to destroy a layer a live task
//! depends on, and the second pass costs nothing that matters, because
//! reclaiming disk space is never urgent.
//!
//! ZFS provides a last line of defence underneath all of this — it refuses to
//! destroy a snapshot that still has clones — but it protects only case 2, and
//! only for the layer directly below the clone. Nothing in ZFS knows that an
//! *image* still needs a layer, so the planner cannot be replaced by it.

use std::collections::{BTreeMap, BTreeSet};

/// One layer dataset as it exists on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerOnDisk {
    /// The chain ID hex naming the dataset (`<layers_root>/<chain>`).
    pub chain: String,
    /// Whether the `@final` snapshot is there. A layer without it is a
    /// half-applied leftover **or** an apply in progress; either way it is
    /// [`crate::LayerStore::ensure_layer`]'s business, never the GC's.
    pub complete: bool,
    /// The chain this one was cloned from, from the ZFS `origin` property.
    /// `None` for a base layer (a plain `zfs create`).
    pub parent: Option<String>,
    /// What `zfs list -o used` reports for the dataset and its snapshots, in
    /// bytes. Only ever used to report what a sweep freed.
    pub used: u64,
}

/// Everything on this node that may legitimately want a layer chain.
///
/// Three readings, deliberately kept apart so a caller cannot quietly drop
/// one: each is complete at a moment the others are not (see the module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayerClaims {
    /// Every chain in every image record's stack, top and all its prefixes.
    pub image_chains: BTreeSet<String>,
    /// Chains whose `@final` snapshot some clone outside the layers root
    /// holds — in practice a container's writable layer.
    pub clone_chains: BTreeSet<String>,
    /// Chains being applied right now (the layer store's per-chain gate).
    pub applying: BTreeSet<String>,
}

impl LayerClaims {
    /// The claim set before the ancestry closure: the union of the three
    /// readings, restricted to nothing.
    fn roots(&self) -> BTreeSet<&str> {
        self.image_chains
            .iter()
            .chain(&self.clone_chains)
            .chain(&self.applying)
            .map(String::as_str)
            .collect()
    }

    /// How many distinct chains are claimed, before the closure — logged so an
    /// operator can see that a pass had a claim set at all.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roots().len()
    }

    /// Whether nothing at all claims a layer. A node in this state either has
    /// no images or could not read its records, and the difference matters
    /// enough that callers check it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.image_chains.is_empty() && self.clone_chains.is_empty() && self.applying.is_empty()
    }
}

/// Close a claim set upward through the `origin` edges: whatever wants a chain
/// wants everything it was built on.
fn reachable(layers: &[LayerOnDisk], claims: &LayerClaims) -> BTreeSet<String> {
    let parents: BTreeMap<&str, &str> = layers
        .iter()
        .filter_map(|layer| Some((layer.chain.as_str(), layer.parent.as_deref()?)))
        .collect();
    let mut closed: BTreeSet<String> = BTreeSet::new();
    for root in claims.roots() {
        let mut cursor = Some(root);
        while let Some(chain) = cursor {
            if !closed.insert(chain.to_owned()) {
                // Already walked from here; the rest of the ancestry is in.
                break;
            }
            cursor = parents.get(chain).copied();
        }
    }
    closed
}

/// Depth of a chain in the origin graph, used to order destruction leaf-first.
///
/// A layer must be destroyed after its clones, and `zfs destroy` enforces that
/// by refusing — so ordering is not what makes the GC safe, only what stops it
/// from reporting a failure it could have avoided.
fn depth(layers: &BTreeMap<&str, Option<&str>>, chain: &str) -> usize {
    let mut depth = 0;
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut cursor = Some(chain);
    while let Some(current) = cursor {
        if !seen.insert(current) {
            // A cycle cannot happen in a clone graph, but a corrupted reading
            // must not hang a sweep.
            break;
        }
        cursor = layers.get(current).copied().flatten();
        depth += 1;
    }
    depth
}

/// The layer chains nothing references, deepest first.
///
/// Two kinds of dataset are never returned, for opposite reasons:
///
/// - one **without** `@final` is mid-apply or half-applied, and
///   [`crate::LayerStore::ensure_layer`] destroys and rebuilds it on the next
///   attempt. Collecting it here would race a pull;
/// - one that is reachable from any claim, or from any claim's ancestry.
#[must_use]
pub fn unreferenced(layers: &[LayerOnDisk], claims: &LayerClaims) -> Vec<String> {
    let referenced = reachable(layers, claims);
    let parents: BTreeMap<&str, Option<&str>> = layers
        .iter()
        .map(|layer| (layer.chain.as_str(), layer.parent.as_deref()))
        .collect();
    let mut due: Vec<&LayerOnDisk> = layers
        .iter()
        .filter(|layer| layer.complete && !referenced.contains(&layer.chain))
        .collect();
    due.sort_by(|a, b| {
        depth(&parents, &b.chain)
            .cmp(&depth(&parents, &a.chain))
            .then_with(|| a.chain.cmp(&b.chain))
    });
    due.into_iter().map(|layer| layer.chain.clone()).collect()
}

/// What one pass of the layer GC remembers from the previous one.
///
/// The same shape and the same reason as `satld`'s `DatasetSweeper`: a layer is
/// destroyed only if it was unreferenced on **two consecutive passes**, so a
/// claim set that was momentarily incomplete cannot cost anyone a layer. What
/// is new here is that a layer's loss is not recoverable by re-running anything
/// — a container dataset can be rebuilt from its image, an image layer can only
/// be re-pulled from a registry that may not answer.
#[derive(Debug, Default)]
pub struct LayerSweeper {
    /// Chains that were unreferenced on the previous pass.
    unreferenced: BTreeSet<String>,
}

impl LayerSweeper {
    /// The chains to destroy this pass — unreferenced now *and* last time —
    /// deepest first.
    ///
    /// Also forgets everything no longer on disk, so the set cannot grow
    /// without bound on a node that churns images.
    pub fn plan(&mut self, layers: &[LayerOnDisk], claims: &LayerClaims) -> Vec<String> {
        let now: BTreeSet<String> = unreferenced(layers, claims).into_iter().collect();
        let due = unreferenced(layers, claims)
            .into_iter()
            .filter(|chain| self.unreferenced.contains(chain))
            .collect();
        self.unreferenced = now;
        due
    }

    /// What the previous pass found unreferenced but did not destroy — the
    /// "deferred to the next pass" set, for the operator-facing report.
    #[must_use]
    pub fn awaiting_agreement(&self) -> &BTreeSet<String> {
        &self.unreferenced
    }

    /// A chain that is gone: nothing about it is worth remembering.
    pub fn forget(&mut self, chain: &str) {
        self.unreferenced.remove(chain);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete layer with no parent.
    fn base(chain: &str, used: u64) -> LayerOnDisk {
        LayerOnDisk {
            chain: chain.to_owned(),
            complete: true,
            parent: None,
            used,
        }
    }

    /// A complete layer stacked on `parent`.
    fn stacked(chain: &str, parent: &str, used: u64) -> LayerOnDisk {
        LayerOnDisk {
            chain: chain.to_owned(),
            complete: true,
            parent: Some(parent.to_owned()),
            used,
        }
    }

    fn set(chains: &[&str]) -> BTreeSet<String> {
        chains.iter().map(|c| (*c).to_owned()).collect()
    }

    fn claims_from_images(chains: &[&str]) -> LayerClaims {
        LayerClaims {
            image_chains: set(chains),
            ..LayerClaims::default()
        }
    }

    #[test]
    fn a_layer_no_image_and_no_clone_names_is_unreferenced() {
        let layers = [base("aa", 100), base("bb", 200)];
        assert_eq!(
            unreferenced(&layers, &claims_from_images(&["aa"])),
            ["bb"],
            "only the layer nothing names may be collected"
        );
    }

    #[test]
    fn nothing_is_unreferenced_when_every_layer_is_named() {
        let layers = [base("aa", 100), stacked("bb", "aa", 200)];
        assert!(unreferenced(&layers, &claims_from_images(&["aa", "bb"])).is_empty());
    }

    /// **The one that must never regress.** A container that exited days ago
    /// still has a rootfs, and that rootfs is a clone of its image's top
    /// `@final`. If the image record is gone — a re-pulled tag overwrites its
    /// entry in place, so this is the ordinary case and not a corner — the
    /// clone edge is the *only* thing left that wants the chain. Collecting it
    /// destroys a container's filesystem.
    #[test]
    fn a_layer_held_only_by_a_stopped_container_is_never_collected() {
        let layers = [base("base", 5_000), stacked("top", "base", 1_000)];
        let claims = LayerClaims {
            // No image record names anything: the tag moved.
            image_chains: BTreeSet::new(),
            // A stopped container's writable layer is a clone of top@final.
            clone_chains: set(&["top"]),
            applying: BTreeSet::new(),
        };
        assert!(
            unreferenced(&layers, &claims).is_empty(),
            "a chain a stopped container's rootfs is cloned from must survive, \
             and so must every layer underneath it"
        );
    }

    /// The ancestry closure, stated on its own: claiming a chain claims
    /// everything it was built on. Without it the GC would go after the layers
    /// *below* a live container's top layer, where ZFS would refuse with
    /// `filesystem has dependent clones` on every pass, forever.
    #[test]
    fn claiming_a_chain_claims_its_whole_ancestry() {
        let layers = [
            base("l1", 10),
            stacked("l2", "l1", 20),
            stacked("l3", "l2", 30),
            base("orphan", 40),
        ];
        assert_eq!(
            unreferenced(&layers, &claims_from_images(&["l3"])),
            ["orphan"]
        );
    }

    /// A dataset with no `@final` is either mid-apply or a half-applied
    /// leftover, and `ensure_layer` destroys and rebuilds it on the next
    /// attempt. Collecting it here would race a pull.
    #[test]
    fn an_incomplete_layer_is_left_to_the_layer_store() {
        let layers = [LayerOnDisk {
            chain: "half".to_owned(),
            complete: false,
            parent: None,
            used: 7,
        }];
        assert!(unreferenced(&layers, &LayerClaims::default()).is_empty());
    }

    /// A chain whose apply holds the gate is claimed even though no snapshot
    /// and no image record prove it yet.
    #[test]
    fn a_chain_being_applied_is_claimed() {
        let layers = [base("aa", 1)];
        let claims = LayerClaims {
            applying: set(&["aa"]),
            ..LayerClaims::default()
        };
        assert!(unreferenced(&layers, &claims).is_empty());
    }

    /// Destruction order: a clone must go before the layer it was cloned from,
    /// or `zfs destroy` refuses and the pass reports a failure it could have
    /// avoided.
    #[test]
    fn unreferenced_layers_come_back_deepest_first() {
        let layers = [
            base("l1", 10),
            stacked("l2", "l1", 20),
            stacked("l3", "l2", 30),
        ];
        assert_eq!(
            unreferenced(&layers, &LayerClaims::default()),
            ["l3", "l2", "l1"]
        );
    }

    /// An `origin` pointing outside the layers root is not a layer edge, and
    /// treating it as one would invent a parent that does not exist.
    #[test]
    fn a_layer_with_no_parent_edge_is_its_own_root() {
        let layers = [base("aa", 1), base("bb", 2)];
        assert_eq!(unreferenced(&layers, &claims_from_images(&["bb"])), ["aa"]);
    }

    // ---- the two-pass agreement -------------------------------------------

    #[test]
    fn a_layer_is_destroyed_only_after_two_unreferenced_passes() {
        let mut sweeper = LayerSweeper::default();
        let layers = [base("aa", 100)];
        assert!(
            sweeper.plan(&layers, &LayerClaims::default()).is_empty(),
            "one pass is never enough: the claim set can be momentarily incomplete"
        );
        assert_eq!(sweeper.plan(&layers, &LayerClaims::default()), ["aa"]);
    }

    #[test]
    fn a_layer_claimed_on_the_second_pass_is_spared() {
        let mut sweeper = LayerSweeper::default();
        let layers = [base("aa", 100)];
        assert!(sweeper.plan(&layers, &LayerClaims::default()).is_empty());
        assert!(
            sweeper
                .plan(&layers, &claims_from_images(&["aa"]))
                .is_empty(),
            "an image turned up naming it, so it is not a leftover"
        );
        // ... and the strike is spent: it has to disagree twice again.
        assert!(sweeper.plan(&layers, &LayerClaims::default()).is_empty());
    }

    #[test]
    fn a_claimed_layer_is_never_planned_for_destruction() {
        let mut sweeper = LayerSweeper::default();
        let layers = [base("aa", 1), stacked("bb", "aa", 2)];
        for _ in 0..5 {
            assert!(
                sweeper
                    .plan(&layers, &claims_from_images(&["bb"]))
                    .is_empty()
            );
        }
    }

    #[test]
    fn the_second_pass_keeps_the_deepest_first_order() {
        let mut sweeper = LayerSweeper::default();
        let layers = [base("l1", 1), stacked("l2", "l1", 2)];
        assert!(sweeper.plan(&layers, &LayerClaims::default()).is_empty());
        assert_eq!(sweeper.plan(&layers, &LayerClaims::default()), ["l2", "l1"]);
    }

    #[test]
    fn a_layer_that_left_the_disk_is_forgotten() {
        let mut sweeper = LayerSweeper::default();
        let layers = [base("aa", 1)];
        sweeper.plan(&layers, &LayerClaims::default());
        assert_eq!(sweeper.awaiting_agreement(), &set(&["aa"]));
        // Gone from disk: the next pass must not carry a strike for it.
        assert!(sweeper.plan(&[], &LayerClaims::default()).is_empty());
        assert!(sweeper.awaiting_agreement().is_empty());
    }

    #[test]
    fn forget_drops_a_destroyed_layers_strike() {
        let mut sweeper = LayerSweeper::default();
        let layers = [base("aa", 1)];
        sweeper.plan(&layers, &LayerClaims::default());
        sweeper.forget("aa");
        assert!(
            sweeper.plan(&layers, &LayerClaims::default()).is_empty(),
            "a layer that came back has to earn two passes again"
        );
    }

    #[test]
    fn a_claim_set_reports_its_size_and_emptiness() {
        assert!(LayerClaims::default().is_empty());
        assert_eq!(LayerClaims::default().len(), 0);
        let claims = LayerClaims {
            image_chains: set(&["aa", "bb"]),
            clone_chains: set(&["bb"]),
            applying: set(&["cc"]),
        };
        assert!(!claims.is_empty());
        assert_eq!(claims.len(), 3, "distinct chains, not row count");
    }
}
