// SPDX-License-Identifier: BSD-2-Clause
//! Which manager an agent talks to (architecture §7.2, SWK §13.1, §20.2).
//!
//! Two rules, in order:
//!
//! 1. **The local socket wins.** A manager runs an agent too and schedules
//!    work to itself; routing that through the network stack would make a
//!    node's own tasks depend on its own reachability, and would break the
//!    moment the advertised address is wrong. Architecture §7.2 pins the
//!    preference.
//! 2. Otherwise, **weighted-random** over the manager list the session stream
//!    pushed. SwarmKit weights every manager equally at 10 and picks at
//!    random rather than round-robin, so that agents spread themselves across
//!    managers without coordinating; a weight of 0 means "do not dial" (a
//!    manager that is draining or demoted).

use std::path::PathBuf;

use rand::{Rng, RngExt as _};
use satl_core::Id;

/// A manager endpoint offered to an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerPeer {
    /// Node ID of the manager (matches its certificate CN).
    pub node_id: Id,
    /// `host:port` of that manager's internal gRPC listener.
    pub addr: String,
    /// Selection weight; higher is more likely, 0 means "do not dial".
    pub weight: i64,
}

impl ManagerPeer {
    /// A peer at the default weight.
    #[must_use]
    pub fn new(node_id: Id, addr: impl Into<String>) -> Self {
        Self {
            node_id,
            addr: addr.into(),
            weight: crate::MANAGER_WEIGHT,
        }
    }
}

/// Where the agent will dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// This node is itself a manager: its own dispatcher over the local unix
    /// socket, which is the preferred path.
    Local(PathBuf),
    /// A remote manager over mTLS.
    Remote(ManagerPeer),
    /// The address a follower redirected us to in the `satl-leader-addr`
    /// response metadata. Its node ID is not known yet — and does not need to
    /// be: mTLS pins the server *name* (`satl-manager`), never the node ID,
    /// so a redirect is safe to follow blindly within the cluster's trust
    /// perimeter.
    Redirect(String),
}

impl Endpoint {
    /// The `host:port` this endpoint dials, if it is a network address.
    #[must_use]
    pub fn addr(&self) -> Option<&str> {
        match self {
            Self::Local(_) => None,
            Self::Remote(peer) => Some(&peer.addr),
            Self::Redirect(addr) => Some(addr),
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local(path) => write!(f, "local socket {}", path.display()),
            Self::Remote(peer) => write!(f, "manager {} at {}", peer.node_id, peer.addr),
            Self::Redirect(addr) => {
                write!(f, "the leader this cluster redirected us to, at {addr}")
            }
        }
    }
}

/// Picks a manager by weight from `peers`, ignoring zero-weighted ones.
///
/// `pick` is a fraction in `[0, 1)` — injected so the choice is
/// deterministic in tests.
#[must_use]
pub fn weighted_choice(peers: &[ManagerPeer], pick: f64) -> Option<&ManagerPeer> {
    let total: i64 = peers.iter().map(|peer| peer.weight.max(0)).sum();
    if total <= 0 {
        return None;
    }
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    let mut target = (pick.clamp(0.0, 1.0) * total as f64) as i64;
    target = target.min(total - 1);
    for peer in peers {
        let weight = peer.weight.max(0);
        if weight == 0 {
            continue;
        }
        if target < weight {
            return Some(peer);
        }
        target -= weight;
    }
    // Unreachable for a positive total, but a fallback beats a panic on a
    // rounding edge: the last dialable peer is a correct answer.
    peers.iter().find(|peer| peer.weight > 0)
}

/// The endpoint to dial next: the local socket when this node is a manager,
/// else a weighted-random peer.
#[must_use]
pub fn choose_endpoint(
    local: Option<&PathBuf>,
    peers: &[ManagerPeer],
    pick: f64,
) -> Option<Endpoint> {
    if let Some(path) = local {
        return Some(Endpoint::Local(path.clone()));
    }
    weighted_choice(peers, pick).map(|peer| Endpoint::Remote(peer.clone()))
}

/// [`choose_endpoint`] with the pick drawn from `rng`.
pub fn choose_endpoint_with<R: Rng + ?Sized>(
    local: Option<&PathBuf>,
    peers: &[ManagerPeer],
    rng: &mut R,
) -> Option<Endpoint> {
    choose_endpoint(local, peers, rng.random_range(0.0..1.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn peers(weights: &[i64]) -> Vec<ManagerPeer> {
        weights
            .iter()
            .enumerate()
            .map(|(index, weight)| ManagerPeer {
                node_id: Id::generate(),
                addr: format!("10.2.0.{}:2377", index + 1),
                weight: *weight,
            })
            .collect()
    }

    #[test]
    fn a_co_located_manager_always_wins() {
        let socket = PathBuf::from("/var/run/satl-dispatcher.sock");
        let peers = peers(&[10, 10, 10]);
        for pick in [0.0, 0.25, 0.5, 0.99] {
            assert_eq!(
                choose_endpoint(Some(&socket), &peers, pick),
                Some(Endpoint::Local(socket.clone())),
                "architecture §7.2: the local socket is preferred"
            );
        }
        // …even with no remote managers at all.
        assert_eq!(
            choose_endpoint(Some(&socket), &[], 0.5),
            Some(Endpoint::Local(socket))
        );
    }

    #[test]
    fn with_no_managers_and_no_socket_there_is_nowhere_to_go() {
        assert_eq!(choose_endpoint(None, &[], 0.5), None);
        assert_eq!(weighted_choice(&[], 0.5), None);
    }

    #[test]
    fn equal_weights_partition_the_range_evenly() {
        let peers = peers(&[10, 10, 10]);
        assert_eq!(weighted_choice(&peers, 0.0), Some(&peers[0]));
        assert_eq!(weighted_choice(&peers, 0.32), Some(&peers[0]));
        assert_eq!(weighted_choice(&peers, 0.34), Some(&peers[1]));
        assert_eq!(weighted_choice(&peers, 0.67), Some(&peers[2]));
        assert_eq!(weighted_choice(&peers, 0.999), Some(&peers[2]));
    }

    #[test]
    fn a_zero_weight_manager_is_never_dialed() {
        let one_dialable = peers(&[0, 10, 0]);
        for pick in [0.0, 0.1, 0.5, 0.9, 0.999] {
            assert_eq!(weighted_choice(&one_dialable, pick), Some(&one_dialable[1]));
        }
        assert_eq!(weighted_choice(&peers(&[0, 0]), 0.5), None);
    }

    #[test]
    fn weights_bias_the_choice_proportionally() {
        let peers = peers(&[1, 9]);
        let mut counts: BTreeMap<&Id, usize> = BTreeMap::new();
        for step in 0..1_000 {
            #[allow(clippy::cast_precision_loss)]
            let pick = f64::from(step) / 1_000.0;
            let chosen = weighted_choice(&peers, pick).expect("a peer");
            *counts.entry(&chosen.node_id).or_default() += 1;
        }
        assert_eq!(counts[&peers[0].node_id], 100);
        assert_eq!(counts[&peers[1].node_id], 900);
    }

    #[test]
    fn an_out_of_range_pick_still_yields_a_peer() {
        let peers = peers(&[10]);
        assert_eq!(weighted_choice(&peers, -1.0), Some(&peers[0]));
        assert_eq!(weighted_choice(&peers, 2.0), Some(&peers[0]));
        assert_eq!(weighted_choice(&peers, 1.0), Some(&peers[0]));
    }

    #[test]
    fn the_endpoint_display_names_what_an_operator_needs() {
        let peer = ManagerPeer::new(Id::generate(), "10.2.0.1:2377");
        let text = Endpoint::Remote(peer.clone()).to_string();
        assert!(text.contains("10.2.0.1:2377"), "{text}");
        assert!(text.contains(&peer.node_id.to_string()), "{text}");
        let text = Endpoint::Local(PathBuf::from("/var/run/x.sock")).to_string();
        assert!(text.contains("/var/run/x.sock"), "{text}");
        let text = Endpoint::Redirect("10.2.0.2:2377".to_owned()).to_string();
        assert!(text.contains("10.2.0.2:2377"), "{text}");
    }

    #[test]
    fn only_network_endpoints_have_an_address() {
        let peer = ManagerPeer::new(Id::generate(), "10.2.0.1:2377");
        assert_eq!(Endpoint::Remote(peer).addr(), Some("10.2.0.1:2377"));
        assert_eq!(
            Endpoint::Redirect("10.2.0.2:2377".to_owned()).addr(),
            Some("10.2.0.2:2377")
        );
        assert_eq!(
            Endpoint::Local(PathBuf::from("/var/run/x.sock")).addr(),
            None
        );
    }
}
