// SPDX-License-Identifier: BSD-2-Clause
//! `satl-ca` — the embedded cluster certificate authority (architecture §12,
//! SWK §16).
//!
//! Everything here is **pure**: no network, no gRPC, no store access. The
//! daemon wires these pieces into the `NodeCA` service (architecture §7) and
//! into the Raft-held [`satl_core::Cluster`] object; this crate only knows how
//! to mint, sign, verify, persist and schedule.
//!
//! - [`token`] — `SATL-1-<digest>-<secret>` join tokens: generation, parsing,
//!   constant-time matching, and the root-CA-bundle digest that pins the CA
//!   against a MITM on first contact (SWK §16.2).
//! - [`root`] — the self-signed ECDSA P-256 root and the node-certificate
//!   signing policy (only the public key comes from the CSR, SWK §16.3).
//! - [`csr`] — the joiner side: key generation, CSR serialization, and
//!   verification of what came back.
//! - [`store`] — `<state_dir>/certs/{node.key,node.crt,ca.crt}` with the mode
//!   and atomicity discipline of SwarmKit's `KeyReadWriter` (SWK §16.6).
//! - [`tls`] — rustls server/client configs, peer identity extraction and the
//!   RPC authorization matrix the tonic interceptors apply (SWK §16.7).
//! - [`renewal`] — the 50–80 % renewal window and the expired-certificate
//!   backoff (SWK §16.4), as pure functions over an injected clock and RNG.
//!
//! # Identity encoding (pinned contract)
//!
//! Node certificates carry `CN = <node id>`, `OU = satl-manager | satl-worker`,
//! `O = <cluster id>`. Managers additionally carry the DNS SANs
//! [`SAN_MANAGER`] and [`SAN_CA`] — the server names peers verify. The root is
//! `CN = satl-ca`.
//!
//! # Out of scope (architecture §14)
//!
//! External CAs (CFSSL), autolock / KEK-encrypted key files, and root rotation
//! with cross-signed intermediates (M5) are deliberately absent. Where a design
//! decision here constrains them, the doc comment says so.

pub mod base36;
pub mod csr;
pub mod error;
pub mod live;
pub mod renewal;
pub mod root;
pub mod store;
pub mod tls;
pub mod token;

pub use csr::{CsrError, NodeKeyPair, certificate_matches_key, verify_issued_cert};
pub use error::CaError;
pub use live::{
    IdentitySwap, LiveIdentity, live_anonymous_server_config, live_client_config,
    live_server_config,
};
pub use renewal::{
    RENEWAL_WINDOW_END, RENEWAL_WINDOW_START, RETRY_BACKOFF_BASE, RETRY_BACKOFF_CAP, is_expired,
    next_renewal, renewal_delay, retry_backoff,
};
pub use root::{CertPem, ROOT_CA_VALIDITY, RootCa, RootCaError};
pub use store::{CertPaths, CertStore, NodeIdentity, StoreError};
pub use tls::{
    AuthzError, CertBlacklist, PeerIdentity, PeerIdentityError, REJOIN_AFTER_ROTATION_HINT,
    RoleRequirement, TlsError, certificate_validity, client_config, crypto_provider, root_store,
    server_config,
};
pub use token::{
    DIGEST_LEN, JoinToken, JoinTokens, SECRET_LEN, TOKEN_PREFIX, TOKEN_VERSION, TokenError,
};

use std::time::Duration;

use satl_core::NodeRole;

/// Common name of the root CA certificate (architecture §12.1).
pub const ROOT_CA_CN: &str = "satl-ca";

/// Organizational unit stamped into manager certificates.
pub const OU_MANAGER: &str = "satl-manager";

/// Organizational unit stamped into worker certificates.
pub const OU_WORKER: &str = "satl-worker";

/// DNS SAN (and TLS server name) every manager certificate carries.
pub const SAN_MANAGER: &str = "satl-manager";

/// DNS SAN managers carry for the CA bootstrap endpoint.
pub const SAN_CA: &str = "satl-ca";

/// Validity of an issued node certificate (architecture §12.3, SWK §16.3).
pub const NODE_CERT_VALIDITY: Duration = Duration::from_hours(90 * 24);

/// Shortest node-certificate validity a **production** configuration may ask
/// for (SWK §16.3). The daemon warns loudly below this; the signer's own
/// floor is [`HARD_MIN_CERT_VALIDITY`], lower only so a test cluster can
/// issue minutes-long certificates to exercise renewal end to end.
pub const MIN_CERT_VALIDITY: Duration = Duration::from_hours(1);

/// Hard floor of the signer: a requested validity below this is refused
/// outright. Anything in `[HARD_MIN_CERT_VALIDITY, MIN_CERT_VALIDITY)` is a
/// testing configuration (`cert_validity` in `satld.toml`) and is issued
/// under a warning.
pub const HARD_MIN_CERT_VALIDITY: Duration = Duration::from_mins(1);

/// Every certificate is backdated by up to this much to absorb clock skew
/// between the signing manager and the joining node (architecture §12.3).
/// The applied backdate is capped at an eighth of the requested validity, so
/// a short-lived test certificate's renewal window (50-80 % of the
/// NotBefore..NotAfter span, SWK §16.4) still lies in its future — a fixed
/// one-hour backdate on a five-minute certificate would put the whole window
/// in the past and turn the renewal loop into a hot loop. At production
/// validities the cap is far above one hour, so nothing changes there.
pub const CERT_BACKDATE: Duration = Duration::from_hours(1);

/// The `OU` value stamped into certificates for `role`.
#[must_use]
pub fn role_ou(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Manager => OU_MANAGER,
        NodeRole::Worker => OU_WORKER,
    }
}

/// The role a certificate `OU` denotes, if it denotes one at all.
#[must_use]
pub fn role_from_ou(ou: &str) -> Option<NodeRole> {
    match ou {
        OU_MANAGER => Some(NodeRole::Manager),
        OU_WORKER => Some(NodeRole::Worker),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_ou_roundtrips() {
        for role in [NodeRole::Manager, NodeRole::Worker] {
            assert_eq!(role_from_ou(role_ou(role)), Some(role));
        }
        assert_eq!(role_from_ou("swarm-manager"), None);
        assert_eq!(role_from_ou(""), None);
    }
}
