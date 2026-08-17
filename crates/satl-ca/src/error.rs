// SPDX-License-Identifier: BSD-2-Clause
//! Crate-level error type composing the per-module errors.
//!
//! Library crates use `thiserror` (project convention); the two binaries wrap
//! these in `anyhow`. Each variant is `#[from]`-convertible so daemon code can
//! use a single `Result` across the join flow — token parse, CSR, signature,
//! disk, TLS setup — without a match arm per step.

use crate::csr::CsrError;
use crate::root::RootCaError;
use crate::store::StoreError;
use crate::tls::{AuthzError, PeerIdentityError, TlsError};
use crate::token::TokenError;

/// Any failure surfaced by `satl-ca`.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    /// A join token was malformed, or did not match the root CA bundle.
    #[error(transparent)]
    Token(#[from] TokenError),

    /// The root CA could not be generated, loaded, or used to sign.
    #[error(transparent)]
    Root(#[from] RootCaError),

    /// The joiner side of issuance failed.
    #[error(transparent)]
    Csr(#[from] CsrError),

    /// The on-disk TLS material could not be read or written.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// A rustls configuration could not be built.
    #[error(transparent)]
    Tls(#[from] TlsError),

    /// A peer certificate could not be read.
    #[error(transparent)]
    Identity(#[from] PeerIdentityError),

    /// A peer was authenticated but not authorized (SWK §16.7).
    #[error(transparent)]
    Authz(#[from] AuthzError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_converts_from_its_module_error() {
        let token: CaError = TokenError::FieldCount { fields: 2 }.into();
        assert!(matches!(token, CaError::Token(_)));
        assert!(token.to_string().contains("malformed join token"));

        let store: CaError = StoreError::KeyPermissions {
            path: "/var/db/satl/certs/node.key".into(),
            mode: 0o644,
            expected: 0o600,
        }
        .into();
        assert!(matches!(store, CaError::Store(_)));
        // `transparent` means the operator sees the specific message, not a
        // generic wrapper.
        assert!(store.to_string().contains("node.key"));

        let authz: CaError = AuthzError::Blacklisted {
            node_id: "abc".to_owned(),
        }
        .into();
        assert!(matches!(authz, CaError::Authz(_)));

        let identity: CaError = PeerIdentityError::NoCertificate.into();
        assert!(matches!(identity, CaError::Identity(_)));
    }
}
