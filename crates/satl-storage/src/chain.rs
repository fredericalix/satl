// SPDX-License-Identifier: BSD-2-Clause
//! OCI chain IDs (image spec, "Layer `ChainID`"): the digest identifying a
//! *stack* of applied layers, used as the dataset name component under
//! `<root>/layers/` (`docs/architecture.md` §10) so images sharing a layer
//! prefix share datasets.
//!
//! ```text
//! ChainID(L1)      = DiffID(L1)
//! ChainID(L1..Ln)  = Digest(ChainID(L1..Ln-1) + " " + DiffID(Ln))
//! ```
//!
//! The hashed string includes the `sha256:` prefixes of both digests, per the
//! OCI image spec. Everything in this module is pure — no I/O, no zfs.

use std::fmt;

use sha2::{Digest as _, Sha256};

/// The digest algorithm prefix used throughout ("sha256:<64 lowercase hex>").
pub const SHA256_PREFIX: &str = "sha256:";

/// A layer-stack chain ID: a sha256 digest stored as 64 lowercase hex chars.
///
/// The [`ChainId::hex`] form (no `sha256:` prefix) names the layer dataset
/// (`<layers-root>/<hex>`); [`fmt::Display`] renders the full
/// `sha256:<hex>` digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainId(String);

impl ChainId {
    /// Parse a full digest of the form `sha256:<64 lowercase hex>`.
    ///
    /// # Errors
    ///
    /// [`ChainIdError::InvalidDigest`] when the prefix, length, or character
    /// set is wrong.
    pub fn from_digest(digest: &str) -> Result<Self, ChainIdError> {
        parse_sha256_digest(digest).map(Self)
    }

    /// The 64-char lowercase hex, without the `sha256:` prefix — the layer
    /// dataset name component.
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.0
    }

    /// The full digest, `sha256:<hex>`.
    #[must_use]
    pub fn digest(&self) -> String {
        format!("{SHA256_PREFIX}{}", self.0)
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SHA256_PREFIX}{}", self.0)
    }
}

/// Invalid digest input to chain-ID computation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainIdError {
    /// The digest string is not `sha256:<64 lowercase hex>`.
    #[error("invalid sha256 digest {digest:?}: {reason}")]
    InvalidDigest {
        /// The offending input.
        digest: String,
        /// What was wrong with it.
        reason: String,
    },
}

/// Validate a `sha256:<64 lowercase hex>` digest string, returning the bare
/// hex part. Shared by chain-ID computation and blob digest verification.
pub(crate) fn parse_sha256_digest(digest: &str) -> Result<String, ChainIdError> {
    let invalid = |reason: &str| ChainIdError::InvalidDigest {
        digest: digest.to_owned(),
        reason: reason.to_owned(),
    };
    let hex = digest
        .strip_prefix(SHA256_PREFIX)
        .ok_or_else(|| invalid("missing 'sha256:' prefix"))?;
    if hex.len() != 64 {
        return Err(invalid("expected 64 hex characters after the prefix"));
    }
    if !hex
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(invalid(
            "expected lowercase hexadecimal characters after the prefix",
        ));
    }
    Ok(hex.to_owned())
}

/// Compute the chain ID of a stack extended by one layer, per the OCI image
/// spec:
///
/// - `parent = None`: `ChainID(L1) = DiffID(L1)`.
/// - `parent = Some(c)`: `sha256` of the ASCII string
///   `"sha256:<parent hex> sha256:<diff hex>"`.
///
/// # Errors
///
/// [`ChainIdError::InvalidDigest`] when `diff_id` is not a well-formed
/// `sha256:<64 lowercase hex>` digest.
/// Every chain ID of a layer stack, base first: the top one **and all its
/// prefixes**.
///
/// That whole set is what an image needs on disk — each chain is one dataset —
/// and it is what the GC's claim set is built from. Only the top chain is ever
/// cloned to make a container rootfs, so a claim set assembled from top chains
/// alone would leave every layer underneath an image looking unreferenced.
///
/// # Errors
///
/// [`ChainIdError::InvalidDigest`] for the first `diff_id` that is not a
/// well-formed `sha256:<64 lowercase hex>` — the same rejection layer
/// application makes.
pub fn chains_of<I, S>(diff_ids: I) -> Result<Vec<ChainId>, ChainIdError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut chains = Vec::new();
    let mut parent: Option<ChainId> = None;
    for diff_id in diff_ids {
        let chain = chain_id(parent.as_ref(), diff_id.as_ref())?;
        parent = Some(chain.clone());
        chains.push(chain);
    }
    Ok(chains)
}

pub fn chain_id(parent: Option<&ChainId>, diff_id: &str) -> Result<ChainId, ChainIdError> {
    let diff_hex = parse_sha256_digest(diff_id)?;
    match parent {
        None => Ok(ChainId(diff_hex)),
        Some(parent) => {
            let mut hasher = Sha256::new();
            hasher.update(parent.digest().as_bytes());
            hasher.update(b" ");
            hasher.update(SHA256_PREFIX.as_bytes());
            hasher.update(diff_hex.as_bytes());
            Ok(ChainId(hex::encode(hasher.finalize())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vectors computed independently with FreeBSD sha256(1):
    //
    //   $ printf '%s' 'layer-one'   | sha256 -q
    //   0139c1c77468f75e6763a4612262743bd47a36b26cb2863d662756b3377bb029    (= D1)
    //   $ printf '%s' 'layer-two'   | sha256 -q
    //   4381142a944dccfafc4428f3b1d4469713054b918f3c97f2e7f1cac2c25e0cc4    (= D2)
    //   $ printf '%s' 'layer-three' | sha256 -q
    //   6c743db43f0448c007a51265ac822887f39ea7e6600820511cc46f9f63690fd5    (= D3)
    //   $ printf '%s' "sha256:$D1 sha256:$D2" | sha256 -q
    //   aff998a96a2f925843dfb74108505e06ba8a26c9ff277ee74ede14a9bd9090b0    (= C2)
    //   $ printf '%s' "sha256:$C2 sha256:$D3" | sha256 -q
    //   0c591124fb48bc3416c43b04465bf075a13e4949d16e3c58b274b18a00494da7    (= C3)
    const D1: &str = "sha256:0139c1c77468f75e6763a4612262743bd47a36b26cb2863d662756b3377bb029";
    const D2: &str = "sha256:4381142a944dccfafc4428f3b1d4469713054b918f3c97f2e7f1cac2c25e0cc4";
    const D3: &str = "sha256:6c743db43f0448c007a51265ac822887f39ea7e6600820511cc46f9f63690fd5";
    const C2_HEX: &str = "aff998a96a2f925843dfb74108505e06ba8a26c9ff277ee74ede14a9bd9090b0";
    const C3_HEX: &str = "0c591124fb48bc3416c43b04465bf075a13e4949d16e3c58b274b18a00494da7";

    /// The GC's claim set: an image's whole stack, not just its top chain.
    #[test]
    fn chains_of_returns_every_prefix_base_first() {
        let chains = chains_of([D1, D2, D3]).unwrap();
        let hexes: Vec<&str> = chains.iter().map(ChainId::hex).collect();
        assert_eq!(
            hexes,
            [
                "0139c1c77468f75e6763a4612262743bd47a36b26cb2863d662756b3377bb029",
                C2_HEX,
                C3_HEX
            ]
        );
    }

    #[test]
    fn chains_of_an_empty_stack_is_empty() {
        assert!(chains_of(Vec::<String>::new()).unwrap().is_empty());
    }

    #[test]
    fn chains_of_rejects_a_malformed_diff_id() {
        let err = chains_of([D1, "not-a-digest"]).unwrap_err();
        assert!(matches!(err, ChainIdError::InvalidDigest { .. }), "{err}");
    }

    #[test]
    fn single_layer_chain_id_is_the_diff_id() {
        let c1 = chain_id(None, D1).unwrap();
        assert_eq!(c1.digest(), D1);
        assert_eq!(format!("{c1}"), D1);
        assert_eq!(
            c1.hex(),
            "0139c1c77468f75e6763a4612262743bd47a36b26cb2863d662756b3377bb029"
        );
    }

    #[test]
    fn two_layer_chain_id_matches_independent_vector() {
        let c1 = chain_id(None, D1).unwrap();
        let c2 = chain_id(Some(&c1), D2).unwrap();
        assert_eq!(c2.hex(), C2_HEX);
    }

    #[test]
    fn three_layer_chain_id_matches_independent_vector() {
        let c1 = chain_id(None, D1).unwrap();
        let c2 = chain_id(Some(&c1), D2).unwrap();
        let c3 = chain_id(Some(&c2), D3).unwrap();
        assert_eq!(c3.hex(), C3_HEX);
    }

    #[test]
    fn from_digest_round_trips() {
        let c = ChainId::from_digest(D2).unwrap();
        assert_eq!(c.digest(), D2);
    }

    #[test]
    fn rejects_missing_prefix() {
        let err = chain_id(None, C2_HEX).unwrap_err();
        assert!(
            err.to_string().contains("missing 'sha256:' prefix"),
            "{err}"
        );
    }

    #[test]
    fn rejects_wrong_length() {
        let err = ChainId::from_digest("sha256:abcd").unwrap_err();
        assert!(err.to_string().contains("64 hex characters"), "{err}");
    }

    #[test]
    fn rejects_uppercase_and_non_hex() {
        let upper = format!("sha256:{}", C2_HEX.to_uppercase());
        assert!(ChainId::from_digest(&upper).is_err());
        let non_hex = format!("sha256:{}", "z".repeat(64));
        assert!(ChainId::from_digest(&non_hex).is_err());
    }
}
