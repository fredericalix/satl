// SPDX-License-Identifier: BSD-2-Clause
//! Join tokens (architecture §12.2, SWK §16.2).
//!
//! Format: `SATL-1-<digest>-<secret>`
//!
//! - `digest` — base36 of the SHA-256 over the **whole** root CA bundle,
//!   zero-padded to 50 characters. The joiner fetches the root CA over an
//!   unauthenticated channel (`GetRootCACertificate` takes no client cert) and
//!   checks it against this digest; computing it over the whole bundle rather
//!   than a single certificate is what stops a MITM from *appending* a root of
//!   its own (SWK §16.2).
//! - `secret` — base36 of 16 CSPRNG bytes, zero-padded to 25 characters. The
//!   CA compares it against the cluster's two tokens in constant time; **the
//!   token that matches determines the role** the node joins with.
//!
//! Rotation regenerates the secret and keeps the digest (the root is
//! unchanged); a root rotation regenerates both (M5).

use std::fmt;
use std::str::FromStr;

use rand::Rng;
use satl_core::NodeRole;
use sha2::{Digest as _, Sha256};
use subtle::{Choice, ConstantTimeEq};

use crate::base36;

/// Fixed prefix of every SatL join token.
///
/// SwarmKit uses `SWMTKN`; SatL deliberately differs so tooling that
/// pattern-matches Docker tokens does not mistake one for the other (recorded
/// in `docs/api-compat.md`).
pub const TOKEN_PREFIX: &str = "SATL";

/// Token format version. Bumped only for an incompatible field layout.
pub const TOKEN_VERSION: &str = "1";

/// Width of the base36 digest field: `ceil(log36(2^256))`.
pub const DIGEST_LEN: usize = 50;

/// Width of the base36 secret field: `ceil(log36(2^128))`.
pub const SECRET_LEN: usize = 25;

/// Number of CSPRNG bytes behind the secret field.
const SECRET_BYTES: usize = 16;

/// A join token failed to parse, or failed to authenticate a root CA bundle.
///
/// No variant ever echoes the secret field: these errors are logged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// Wrong number of dash-separated fields.
    #[error(
        "malformed join token: expected 4 dash-separated fields \
         ({TOKEN_PREFIX}-{TOKEN_VERSION}-<{DIGEST_LEN} char digest>-<{SECRET_LEN} char secret>), \
         found {fields}"
    )]
    FieldCount {
        /// How many fields the input actually had.
        fields: usize,
    },

    /// The token does not start with [`TOKEN_PREFIX`].
    #[error("malformed join token: prefix is {found:?}, expected {TOKEN_PREFIX:?}")]
    Prefix {
        /// The prefix that was presented.
        found: String,
    },

    /// The token announces a format version this build does not speak.
    #[error(
        "unsupported join token version {found:?}: this build of satl speaks version \
         {TOKEN_VERSION}; the token was issued by a newer cluster"
    )]
    Version {
        /// The version field that was presented.
        found: String,
    },

    /// A fixed-width field has the wrong length.
    #[error("malformed join token: {field} field is {len} characters, expected exactly {expected}")]
    FieldLength {
        /// Which field (`digest` or `secret`).
        field: &'static str,
        /// Length that was presented.
        len: usize,
        /// Length the format pins.
        expected: usize,
    },

    /// A field contains something outside the base36 alphabet.
    #[error("malformed join token: {field} field contains characters outside base36 [0-9a-z]")]
    Alphabet {
        /// Which field (`digest` or `secret`).
        field: &'static str,
    },

    /// The downloaded root CA bundle does not hash to the token's digest.
    #[error(
        "root CA bundle does not match the join token: token pins digest {expected}, the \
         {bundle_len} byte bundle received hashes to {actual}. Refusing to trust it (a \
         man-in-the-middle may have replaced or appended a root certificate). Check that the \
         join token was copied from this cluster; if its root CA was rotated since \
         (satl ca rotate), every older token is void - fetch a fresh one with \
         'satl swarm join-token' on a manager"
    )]
    BundleDigestMismatch {
        /// Digest pinned by the token.
        expected: String,
        /// Digest of the bundle that was offered.
        actual: String,
        /// Size of the offered bundle, in bytes.
        bundle_len: usize,
    },
}

/// One join token: a CA-bundle digest plus a shared secret.
///
/// `Debug` redacts the secret. [`Display`](fmt::Display) does **not** — it
/// renders the complete token, because that string is the token: it is what
/// `satl swarm join-token` prints and what lives in
/// [`satl_core::Cluster::join_tokens`]. Never log a `JoinToken` through
/// `Display`; use [`JoinToken::redacted`].
#[derive(Clone)]
pub struct JoinToken {
    role: Option<NodeRole>,
    digest: String,
    secret: String,
}

impl JoinToken {
    /// Mints a token for `role` pinning `ca_bundle`, drawing the secret from
    /// the process CSPRNG.
    #[must_use]
    pub fn generate(role: NodeRole, ca_bundle: &[u8]) -> Self {
        let mut bytes = [0_u8; SECRET_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        Self::from_secret_bytes(role, ca_bundle, &bytes)
    }

    /// [`JoinToken::generate`] with an explicit RNG (deterministic in tests).
    #[must_use]
    pub fn generate_with<R: Rng + ?Sized>(role: NodeRole, ca_bundle: &[u8], rng: &mut R) -> Self {
        let mut bytes = [0_u8; SECRET_BYTES];
        rng.fill_bytes(&mut bytes);
        Self::from_secret_bytes(role, ca_bundle, &bytes)
    }

    fn from_secret_bytes(role: NodeRole, ca_bundle: &[u8], secret: &[u8]) -> Self {
        Self {
            role: Some(role),
            digest: bundle_digest(ca_bundle),
            secret: base36::encode(secret, SECRET_LEN),
        }
    }

    /// Parses the textual form, validating prefix, version, field widths and
    /// alphabet.
    ///
    /// A parsed token carries **no role**: which role a token grants is not
    /// encoded in it, it is decided by which of the cluster's two tokens the
    /// secret matches ([`JoinTokens::role_for`]).
    pub fn parse(s: &str) -> Result<Self, TokenError> {
        let fields: Vec<&str> = s.trim().split('-').collect();
        let [prefix, version, digest, secret] = fields[..] else {
            return Err(TokenError::FieldCount {
                fields: fields.len(),
            });
        };

        if prefix != TOKEN_PREFIX {
            return Err(TokenError::Prefix {
                found: prefix.to_owned(),
            });
        }
        if version != TOKEN_VERSION {
            return Err(TokenError::Version {
                found: version.to_owned(),
            });
        }
        check_field("digest", digest, DIGEST_LEN)?;
        check_field("secret", secret, SECRET_LEN)?;

        Ok(Self {
            role: None,
            digest: digest.to_owned(),
            secret: secret.to_owned(),
        })
    }

    /// The role this token was minted for, when known.
    ///
    /// `None` for a token that came off the wire or out of the store — see
    /// [`JoinToken::parse`].
    #[must_use]
    pub fn role(&self) -> Option<NodeRole> {
        self.role
    }

    /// Attaches a role to a parsed token (after [`JoinTokens::role_for`]
    /// established which one it is).
    #[must_use]
    pub fn with_role(mut self, role: NodeRole) -> Self {
        self.role = Some(role);
        self
    }

    /// The pinned root-CA-bundle digest (public; safe to log).
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The shared secret. **Never log this.**
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Constant-time comparison of the two secrets.
    ///
    /// This is the check the CA runs on every `IssueNodeCertificate`; a
    /// short-circuiting `==` would leak the secret one character at a time
    /// (SWK §16.3 step 2).
    #[must_use]
    pub fn matches_secret(&self, other: &Self) -> bool {
        bool::from(self.secret_ct_eq(&other.secret))
    }

    /// Constant-time comparison against a bare secret field.
    #[must_use]
    pub fn matches_secret_str(&self, secret: &str) -> bool {
        bool::from(self.secret_ct_eq(secret))
    }

    fn secret_ct_eq(&self, other: &str) -> Choice {
        // `subtle`'s slice impl yields 0 for differing lengths without
        // inspecting the contents.
        self.secret.as_bytes().ct_eq(other.as_bytes())
    }

    /// Checks a downloaded root CA bundle against the token's digest.
    ///
    /// The digest covers the **entire** bundle: a MITM that appends its own
    /// root to the legitimate one changes the hash and is rejected here
    /// (SWK §16.2).
    pub fn verify_ca_bundle(&self, bundle: &[u8]) -> Result<(), TokenError> {
        let actual = bundle_digest(bundle);
        if bool::from(actual.as_bytes().ct_eq(self.digest.as_bytes())) {
            Ok(())
        } else {
            Err(TokenError::BundleDigestMismatch {
                expected: self.digest.clone(),
                actual,
                bundle_len: bundle.len(),
            })
        }
    }

    /// A fresh secret for the same role and CA bundle (SWK §16.2 rotation).
    #[must_use]
    pub fn rotate(&self) -> Self {
        let mut bytes = [0_u8; SECRET_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        Self {
            role: self.role,
            digest: self.digest.clone(),
            secret: base36::encode(&bytes, SECRET_LEN),
        }
    }

    /// The token with its secret elided — the only form safe for logs and
    /// error messages.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!(
            "{TOKEN_PREFIX}-{TOKEN_VERSION}-{}-<secret redacted>",
            self.digest
        )
    }
}

fn check_field(name: &'static str, value: &str, expected: usize) -> Result<(), TokenError> {
    if value.chars().count() != expected {
        return Err(TokenError::FieldLength {
            field: name,
            len: value.chars().count(),
            expected,
        });
    }
    if !base36::is_base36(value) {
        return Err(TokenError::Alphabet { field: name });
    }
    Ok(())
}

/// SHA-256 over the whole bundle, base36, zero-padded to [`DIGEST_LEN`].
#[must_use]
pub fn bundle_digest(ca_bundle: &[u8]) -> String {
    base36::encode(&Sha256::digest(ca_bundle), DIGEST_LEN)
}

impl fmt::Display for JoinToken {
    /// Renders the complete token, secret included — this is the operator- and
    /// store-facing form. Use [`JoinToken::redacted`] for logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{TOKEN_PREFIX}-{TOKEN_VERSION}-{}-{}",
            self.digest, self.secret
        )
    }
}

impl fmt::Debug for JoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinToken")
            .field("role", &self.role)
            .field("digest", &self.digest)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl PartialEq for JoinToken {
    /// Secrets compare in constant time; the role and digest are public.
    fn eq(&self, other: &Self) -> bool {
        self.role == other.role
            && self.digest == other.digest
            && bool::from(self.secret_ct_eq(&other.secret))
    }
}

impl Eq for JoinToken {}

impl FromStr for JoinToken {
    type Err = TokenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// The cluster's two join tokens (architecture §12.2).
///
/// `Debug` redacts both secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct JoinTokens {
    /// Token that joins a node as a worker.
    pub worker: JoinToken,
    /// Token that joins a node as a manager.
    pub manager: JoinToken,
}

impl JoinTokens {
    /// Mints both tokens over the same CA bundle.
    #[must_use]
    pub fn generate(ca_bundle: &[u8]) -> Self {
        Self {
            worker: JoinToken::generate(NodeRole::Worker, ca_bundle),
            manager: JoinToken::generate(NodeRole::Manager, ca_bundle),
        }
    }

    /// [`JoinTokens::generate`] with an explicit RNG (deterministic in tests).
    #[must_use]
    pub fn generate_with<R: Rng + ?Sized>(ca_bundle: &[u8], rng: &mut R) -> Self {
        Self {
            worker: JoinToken::generate_with(NodeRole::Worker, ca_bundle, rng),
            manager: JoinToken::generate_with(NodeRole::Manager, ca_bundle, rng),
        }
    }

    /// The token for `role`.
    #[must_use]
    pub fn for_role(&self, role: NodeRole) -> &JoinToken {
        match role {
            NodeRole::Manager => &self.manager,
            NodeRole::Worker => &self.worker,
        }
    }

    /// The role a presented secret grants, or `None` if it matches neither.
    ///
    /// Both comparisons always run — the function never short-circuits on the
    /// first match — so the time taken does not depend on which token was
    /// presented (SWK §16.3).
    #[must_use]
    pub fn role_for(&self, secret: &str) -> Option<NodeRole> {
        let worker = self.worker.secret_ct_eq(secret);
        let manager = self.manager.secret_ct_eq(secret);
        if bool::from(manager) {
            Some(NodeRole::Manager)
        } else if bool::from(worker) {
            Some(NodeRole::Worker)
        } else {
            None
        }
    }

    /// [`JoinTokens::role_for`] against a parsed token.
    #[must_use]
    pub fn role_for_token(&self, token: &JoinToken) -> Option<NodeRole> {
        self.role_for(token.secret())
    }

    /// Rotates one token's secret, leaving the other alone (SWK §16.2).
    #[must_use]
    pub fn rotate(&self, role: NodeRole) -> Self {
        match role {
            NodeRole::Manager => Self {
                worker: self.worker.clone(),
                manager: self.manager.rotate(),
            },
            NodeRole::Worker => Self {
                worker: self.worker.rotate(),
                manager: self.manager.clone(),
            },
        }
    }
}

impl fmt::Debug for JoinTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinTokens")
            .field("worker", &self.worker)
            .field("manager", &self.manager)
            .finish()
    }
}

impl From<&JoinTokens> for satl_core::JoinTokens {
    /// Renders both tokens for storage in the cluster object.
    fn from(tokens: &JoinTokens) -> Self {
        Self {
            worker: tokens.worker.to_string(),
            manager: tokens.manager.to_string(),
        }
    }
}

impl TryFrom<&satl_core::JoinTokens> for JoinTokens {
    type Error = TokenError;

    fn try_from(tokens: &satl_core::JoinTokens) -> Result<Self, Self::Error> {
        Ok(Self {
            worker: JoinToken::parse(&tokens.worker)?.with_role(NodeRole::Worker),
            manager: JoinToken::parse(&tokens.manager)?.with_role(NodeRole::Manager),
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    const BUNDLE: &[u8] =
        b"-----BEGIN CERTIFICATE-----\nnot a real cert\n-----END CERTIFICATE-----\n";

    #[test]
    fn generated_token_has_the_pinned_shape() {
        let token = JoinToken::generate(NodeRole::Worker, BUNDLE);
        let text = token.to_string();
        let fields: Vec<&str> = text.split('-').collect();
        assert_eq!(fields.len(), 4, "{text}");
        assert_eq!(fields[0], "SATL");
        assert_eq!(fields[1], "1");
        assert_eq!(fields[2].len(), DIGEST_LEN);
        assert_eq!(fields[3].len(), SECRET_LEN);
        assert!(base36::is_base36(fields[2]));
        assert!(base36::is_base36(fields[3]));
        assert_eq!(token.role(), Some(NodeRole::Worker));
    }

    #[test]
    fn roundtrips_through_text() {
        let token = JoinToken::generate(NodeRole::Manager, BUNDLE);
        let parsed = JoinToken::parse(&token.to_string()).expect("round-trip must parse");
        assert_eq!(parsed.digest(), token.digest());
        assert!(parsed.matches_secret(&token));
        // A parsed token has no role until the cluster tells it one.
        assert_eq!(parsed.role(), None);
        assert_eq!(parsed.with_role(NodeRole::Manager), token);
        assert_eq!(
            token.to_string().parse::<JoinToken>().expect("FromStr"),
            JoinToken::parse(&token.to_string()).expect("parse")
        );
    }

    #[test]
    fn generation_is_deterministic_under_a_seeded_rng() {
        let a = JoinToken::generate_with(NodeRole::Worker, BUNDLE, &mut StdRng::seed_from_u64(7));
        let b = JoinToken::generate_with(NodeRole::Worker, BUNDLE, &mut StdRng::seed_from_u64(7));
        assert_eq!(a, b);
        let c = JoinToken::generate_with(NodeRole::Worker, BUNDLE, &mut StdRng::seed_from_u64(8));
        assert_ne!(a, c);
    }

    #[test]
    fn secrets_are_unique_across_generations() {
        let seen: std::collections::HashSet<String> = (0..256)
            .map(|_| JoinToken::generate(NodeRole::Worker, BUNDLE).secret)
            .collect();
        assert_eq!(seen.len(), 256);
    }

    #[test]
    fn digest_is_the_sha256_of_the_whole_bundle() {
        let token = JoinToken::generate(NodeRole::Worker, BUNDLE);
        assert_eq!(token.digest(), bundle_digest(BUNDLE));
        assert_eq!(token.digest().len(), DIGEST_LEN);
        token
            .verify_ca_bundle(BUNDLE)
            .expect("same bundle verifies");
    }

    /// SWK §16.2: the digest is computed over the whole bundle precisely so an
    /// appended root is detected.
    #[test]
    fn appended_root_is_detected() {
        let token = JoinToken::generate(NodeRole::Manager, BUNDLE);
        let mut tampered = BUNDLE.to_vec();
        tampered.extend_from_slice(
            b"-----BEGIN CERTIFICATE-----\nattacker root\n-----END CERTIFICATE-----\n",
        );
        let err = token
            .verify_ca_bundle(&tampered)
            .expect_err("appended root must be rejected");
        match err {
            TokenError::BundleDigestMismatch {
                expected,
                actual,
                bundle_len,
            } => {
                assert_eq!(expected, token.digest());
                assert_ne!(actual, expected);
                assert_eq!(bundle_len, tampered.len());
            }
            other => panic!("unexpected error: {other}"),
        }
        // Truncation and single-byte edits too.
        assert!(token.verify_ca_bundle(&BUNDLE[..BUNDLE.len() - 1]).is_err());
        let mut flipped = BUNDLE.to_vec();
        flipped[10] ^= 0x01;
        assert!(token.verify_ca_bundle(&flipped).is_err());
        assert!(token.verify_ca_bundle(b"").is_err());
    }

    #[test]
    fn a_tampered_digest_field_no_longer_matches_the_bundle() {
        let token = JoinToken::generate(NodeRole::Worker, BUNDLE);
        let mut text = token.to_string();
        // Flip one digest character (position 7 is inside the digest field).
        let idx = TOKEN_PREFIX.len() + 2 + 7;
        let replacement = if text.as_bytes()[idx] == b'a' {
            'b'
        } else {
            'a'
        };
        text.replace_range(idx..=idx, &replacement.to_string());
        let tampered = JoinToken::parse(&text).expect("still well-formed");
        assert_ne!(tampered.digest(), token.digest());
        assert!(tampered.verify_ca_bundle(BUNDLE).is_err());
    }

    /// One rejection case: a label, the input, and the error it must produce.
    type Case = (&'static str, String, fn(&TokenError) -> bool);

    fn digest_field() -> String {
        "0".repeat(DIGEST_LEN)
    }

    fn secret_field() -> String {
        "0".repeat(SECRET_LEN)
    }

    /// Runs a rejection table and checks no message leaks a secret-shaped
    /// field.
    fn assert_all_rejected(cases: Vec<Case>) {
        for (name, input, predicate) in cases {
            let err = JoinToken::parse(&input)
                .err()
                .unwrap_or_else(|| panic!("case {name:?} should have been rejected"));
            assert!(predicate(&err), "case {name:?}: unexpected error {err}");
            assert!(
                !err.to_string().contains(&secret_field()),
                "case {name:?} leaked the secret field"
            );
        }
    }

    #[test]
    fn rejects_a_bad_envelope() {
        let digest = digest_field();
        let secret = secret_field();
        assert_all_rejected(vec![
            ("empty", String::new(), |e| {
                matches!(e, TokenError::FieldCount { .. })
            }),
            ("too few fields", format!("SATL-1-{digest}"), |e| {
                matches!(e, TokenError::FieldCount { fields: 3 })
            }),
            (
                "too many fields",
                format!("SATL-1-{digest}-{secret}-extra"),
                |e| matches!(e, TokenError::FieldCount { fields: 5 }),
            ),
            ("wrong prefix", format!("SWMTKN-1-{digest}-{secret}"), |e| {
                matches!(e, TokenError::Prefix { .. })
            }),
            (
                "lowercase prefix",
                format!("satl-1-{digest}-{secret}"),
                |e| matches!(e, TokenError::Prefix { .. }),
            ),
            ("wrong version", format!("SATL-2-{digest}-{secret}"), |e| {
                matches!(e, TokenError::Version { .. })
            }),
            (
                "non numeric version",
                format!("SATL-x-{digest}-{secret}"),
                |e| matches!(e, TokenError::Version { .. }),
            ),
        ]);
    }

    #[test]
    fn rejects_wrong_field_widths() {
        let digest = digest_field();
        let secret = secret_field();
        let good = JoinToken::generate(NodeRole::Worker, BUNDLE).to_string();
        assert_all_rejected(vec![
            (
                "short digest",
                format!("SATL-1-{}-{secret}", "0".repeat(DIGEST_LEN - 1)),
                |e| {
                    matches!(
                        e,
                        TokenError::FieldLength {
                            field: "digest",
                            ..
                        }
                    )
                },
            ),
            (
                "long digest",
                format!("SATL-1-{}-{secret}", "0".repeat(DIGEST_LEN + 1)),
                |e| {
                    matches!(
                        e,
                        TokenError::FieldLength {
                            field: "digest",
                            ..
                        }
                    )
                },
            ),
            (
                "short secret",
                format!("SATL-1-{digest}-{}", "0".repeat(SECRET_LEN - 1)),
                |e| {
                    matches!(
                        e,
                        TokenError::FieldLength {
                            field: "secret",
                            ..
                        }
                    )
                },
            ),
            (
                "long secret",
                format!("SATL-1-{digest}-{}", "0".repeat(SECRET_LEN + 1)),
                |e| {
                    matches!(
                        e,
                        TokenError::FieldLength {
                            field: "secret",
                            ..
                        }
                    )
                },
            ),
            (
                "truncated good token",
                good[..good.len() - 1].to_owned(),
                |e| {
                    matches!(
                        e,
                        TokenError::FieldLength {
                            field: "secret",
                            ..
                        }
                    )
                },
            ),
        ]);

        // The well-formed token it was derived from still parses.
        assert!(JoinToken::parse(&good).is_ok());
    }

    #[test]
    fn rejects_non_base36_fields() {
        let digest = digest_field();
        let secret = secret_field();
        assert_all_rejected(vec![
            (
                "uppercase digest",
                format!("SATL-1-{}-{secret}", "A".repeat(DIGEST_LEN)),
                |e| matches!(e, TokenError::Alphabet { field: "digest" }),
            ),
            (
                "uppercase secret",
                format!("SATL-1-{digest}-{}", "A".repeat(SECRET_LEN)),
                |e| matches!(e, TokenError::Alphabet { field: "secret" }),
            ),
            (
                "punctuation in secret",
                format!("SATL-1-{digest}-{}!", "0".repeat(SECRET_LEN - 1)),
                |e| matches!(e, TokenError::Alphabet { field: "secret" }),
            ),
            (
                "non ascii secret",
                format!("SATL-1-{digest}-{}\u{e9}", "0".repeat(SECRET_LEN - 1)),
                |e| matches!(e, TokenError::Alphabet { field: "secret" }),
            ),
        ]);
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let token = JoinToken::generate(NodeRole::Worker, BUNDLE);
        let padded = format!("  {token}\n");
        assert_eq!(
            JoinToken::parse(&padded).expect("trimmed").digest(),
            token.digest()
        );
    }

    #[test]
    fn role_for_selects_the_matching_token_only() {
        let tokens = JoinTokens::generate(BUNDLE);
        assert_eq!(
            tokens.role_for(tokens.worker.secret()),
            Some(NodeRole::Worker)
        );
        assert_eq!(
            tokens.role_for(tokens.manager.secret()),
            Some(NodeRole::Manager)
        );
        assert_eq!(tokens.role_for(&"0".repeat(SECRET_LEN)), None);
        assert_eq!(tokens.role_for(""), None);
        assert_eq!(tokens.role_for("short"), None);
        assert_eq!(
            tokens.role_for_token(&JoinToken::parse(&tokens.manager.to_string()).expect("parse")),
            Some(NodeRole::Manager)
        );
        assert_ne!(tokens.worker.secret(), tokens.manager.secret());
        assert_eq!(tokens.worker.digest(), tokens.manager.digest());
    }

    /// A near-miss secret (last character changed) must not match: this is the
    /// property a short-circuiting comparison would still satisfy, but it
    /// guards the `ct_eq` wiring against being accidentally inverted.
    #[test]
    fn constant_time_compare_rejects_near_misses() {
        let tokens = JoinTokens::generate(BUNDLE);
        let mut near = tokens.worker.secret().to_owned();
        let last = near.pop().unwrap_or('0');
        near.push(if last == 'z' { 'y' } else { 'z' });
        assert_eq!(near.len(), SECRET_LEN);
        assert_eq!(tokens.role_for(&near), None);
        assert!(!tokens.worker.matches_secret_str(&near));

        let prefix = &tokens.worker.secret()[..SECRET_LEN - 1];
        assert!(!tokens.worker.matches_secret_str(prefix));
    }

    /// The comparison used for secrets must be `subtle`'s, not `==`: assert on
    /// the observable contract (length-independent `Choice`) and that the
    /// public `PartialEq` also routes through it.
    #[test]
    fn secret_comparison_goes_through_subtle() {
        let token = JoinToken::generate(NodeRole::Worker, BUNDLE);
        let choice: Choice = token.secret_ct_eq(token.secret());
        assert!(bool::from(choice));
        assert!(!bool::from(token.secret_ct_eq("")));
        let same = JoinToken::parse(&token.to_string())
            .expect("parse")
            .with_role(NodeRole::Worker);
        assert_eq!(token, same);
    }

    #[test]
    fn rotation_keeps_the_digest_and_replaces_the_secret() {
        let tokens = JoinTokens::generate(BUNDLE);
        let rotated = tokens.rotate(NodeRole::Worker);
        assert_eq!(rotated.worker.digest(), tokens.worker.digest());
        assert_ne!(rotated.worker.secret(), tokens.worker.secret());
        assert_eq!(rotated.manager.secret(), tokens.manager.secret());
        // The old worker secret no longer opens the door.
        assert_eq!(rotated.role_for(tokens.worker.secret()), None);
        assert_eq!(
            rotated.role_for(rotated.worker.secret()),
            Some(NodeRole::Worker)
        );
    }

    #[test]
    fn debug_never_reveals_the_secret() {
        let tokens = JoinTokens::generate(BUNDLE);
        for rendered in [
            format!("{:?}", tokens.worker),
            format!("{:?}", tokens.manager),
            format!("{tokens:?}"),
            tokens.worker.redacted(),
            tokens.manager.redacted(),
        ] {
            assert!(
                !rendered.contains(tokens.worker.secret()),
                "leaked worker secret in {rendered}"
            );
            assert!(
                !rendered.contains(tokens.manager.secret()),
                "leaked manager secret in {rendered}"
            );
        }
        // Display is the exception, and is documented as such.
        assert!(tokens.worker.to_string().contains(tokens.worker.secret()));
    }

    #[test]
    fn converts_to_and_from_the_core_cluster_representation() {
        let tokens = JoinTokens::generate(BUNDLE);
        let stored: satl_core::JoinTokens = (&tokens).into();
        assert!(stored.worker.starts_with("SATL-1-"));
        let back = JoinTokens::try_from(&stored).expect("stored tokens parse");
        assert_eq!(back, tokens);

        let bad = satl_core::JoinTokens {
            worker: "nope".to_owned(),
            manager: stored.manager,
        };
        assert!(JoinTokens::try_from(&bad).is_err());
    }
}
