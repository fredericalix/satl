// SPDX-License-Identifier: BSD-2-Clause
//! The cluster root CA and the node-certificate signing policy
//! (architecture §12.1/§12.3, SWK §16.2/§16.3).
//!
//! The root is a self-signed ECDSA P-256 certificate, `CN = satl-ca`,
//! `O = <cluster id>`, valid 20 years. Its key lives in the Raft store
//! (`Cluster.encrypted_root_ca_key`), protected by the log's at-rest
//! encryption — this crate never decides where it is kept, only how it is
//! generated, loaded and used.
//!
//! Signing policy (SWK §16.3 step 5): **only the public key and its signature
//! algorithm come from the CSR.** Subject (`CN`/`OU`/`O`), SANs, validity, key
//! usages and serial number are all chosen by the signer, so a joiner cannot
//! talk its way into a role, a node id or a cluster it was not granted.

use std::time::{Duration, SystemTime};

use rand::Rng;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls_pki_types::CertificateDer;
use satl_core::{Id, NodeRole};
use time::OffsetDateTime;
use tracing::{debug, info};

use crate::{CERT_BACKDATE, HARD_MIN_CERT_VALIDITY, ROOT_CA_CN, SAN_CA, SAN_MANAGER, role_ou, tls};

/// Validity of the root certificate: 20 years, as SwarmKit's
/// `RootCAExpiration = 630720000s` (SWK §16.2).
pub const ROOT_CA_VALIDITY: Duration = Duration::from_hours(20 * 365 * 24);

/// Number of random bytes in an issued certificate's serial number.
const SERIAL_BYTES: usize = 16;

/// A PEM-encoded certificate.
///
/// A newtype rather than a bare `String` so the daemon cannot accidentally
/// hand a key where a certificate is expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPem(String);

impl CertPem {
    /// Wraps an already PEM-encoded certificate.
    #[must_use]
    pub fn new(pem: String) -> Self {
        Self(pem)
    }

    /// The PEM text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The PEM text as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Unwraps into the PEM text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for CertPem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for CertPem {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<CertPem> for String {
    fn from(pem: CertPem) -> Self {
        pem.0
    }
}

/// Anything that can go wrong generating, loading or using the root CA.
#[derive(Debug, thiserror::Error)]
pub enum RootCaError {
    /// Key generation failed (the platform CSPRNG or aws-lc-rs refused).
    #[error("failed to generate the root CA ECDSA P-256 key pair: {source}")]
    GenerateKey {
        /// Underlying rcgen error.
        source: rcgen::Error,
    },

    /// Self-signing the root certificate failed.
    #[error(
        "failed to self-sign the root CA certificate (CN={ROOT_CA_CN}, O={cluster_id}): {source}"
    )]
    SelfSign {
        /// Cluster the root was being minted for.
        cluster_id: String,
        /// Underlying rcgen error.
        source: rcgen::Error,
    },

    /// The stored root certificate PEM does not parse.
    #[error("failed to parse the stored root CA certificate ({len} bytes of PEM): {reason}")]
    ParseCert {
        /// Size of the input, for the operator to sanity-check.
        len: usize,
        /// What the parser objected to.
        reason: String,
    },

    /// The stored root key PEM does not parse.
    #[error("failed to parse the stored root CA private key ({len} bytes of PEM): {source}")]
    ParseKey {
        /// Size of the input.
        len: usize,
        /// Underlying rcgen error.
        source: rcgen::Error,
    },

    /// The certificate is not the one the key belongs to.
    #[error(
        "the stored root CA key does not match the stored root CA certificate (CN={cn}): the \
         certificate's public key differs from the key's, so the cluster object holds a \
         mismatched root_ca_cert / encrypted_root_ca_key pair"
    )]
    KeyCertMismatch {
        /// Common name found in the certificate.
        cn: String,
    },

    /// The certificate loaded is not a SatL root.
    #[error(
        "the stored root CA certificate has CN={cn:?}, expected {ROOT_CA_CN:?}; this is not a \
         SatL cluster root"
    )]
    NotARoot {
        /// Common name found in the certificate.
        cn: String,
    },

    /// The CSR did not parse, or its self-signature did not verify.
    #[error(
        "rejecting the certificate signing request for node {node_id} ({len} bytes of DER): \
         {source}. The request must be a PKCS#10 CSR self-signed with the requesting node's key"
    )]
    Csr {
        /// Node the request was for.
        node_id: String,
        /// Size of the offered DER.
        len: usize,
        /// Underlying rcgen error.
        source: rcgen::Error,
    },

    /// The CSR asked for a key type SatL does not issue against.
    #[error(
        "rejecting the certificate signing request for node {node_id}: key algorithm {algorithm} \
         is not accepted; SatL node certificates are ECDSA P-256 (architecture section 12.1)"
    )]
    UnsupportedKeyAlgorithm {
        /// Node the request was for.
        node_id: String,
        /// The algorithm the CSR presented.
        algorithm: String,
    },

    /// The requested validity is below the floor.
    #[error(
        "refusing to issue a certificate for node {node_id} valid for {requested:?}: the minimum \
         node certificate validity is {minimum:?} (architecture section 12.3)"
    )]
    ValidityTooShort {
        /// Node the request was for.
        node_id: String,
        /// What the caller asked for.
        requested: Duration,
        /// The floor.
        minimum: Duration,
    },

    /// The signer was asked to stamp a different cluster id than its own.
    #[error(
        "refusing to issue a certificate for node {node_id} in cluster {requested}: this root CA \
         belongs to cluster {root}"
    )]
    ClusterIdMismatch {
        /// Node the request was for.
        node_id: String,
        /// Cluster id the caller asked for.
        requested: String,
        /// Cluster id the root certificate carries.
        root: String,
    },

    /// A pinned SAN constant is not a valid DNS name (unreachable in practice;
    /// carried as an error rather than a panic per the no-`expect` rule).
    #[error("internal error: pinned SAN {name:?} is not a valid DNS name: {source}")]
    InvalidSan {
        /// The offending constant.
        name: &'static str,
        /// Underlying rcgen error.
        source: rcgen::Error,
    },

    /// Signing the leaf failed.
    #[error(
        "failed to sign the certificate for node {node_id} (OU={ou}, O={cluster_id}): {source}"
    )]
    Sign {
        /// Node the request was for.
        node_id: String,
        /// Role stamped into the leaf.
        ou: &'static str,
        /// Cluster stamped into the leaf.
        cluster_id: String,
        /// Underlying rcgen error.
        source: rcgen::Error,
    },
}

/// The cluster root certificate authority.
///
/// `Debug` redacts the private key.
#[derive(Clone)]
pub struct RootCa {
    cert_pem: String,
    key_pem: String,
    cert_der: CertificateDer<'static>,
    cluster_id: Option<String>,
}

impl RootCa {
    /// Mints a fresh self-signed root for `cluster_id`.
    ///
    /// ECDSA P-256, `CN = satl-ca`, `O = <cluster id>`, valid
    /// [`ROOT_CA_VALIDITY`] and backdated [`CERT_BACKDATE`] for clock skew.
    pub fn generate(cluster_id: &str) -> Result<Self, RootCaError> {
        let key = KeyPair::generate().map_err(|source| RootCaError::GenerateKey { source })?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, ROOT_CA_CN);
        dn.push(DnType::OrganizationName, cluster_id);

        let now = SystemTime::now();
        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = offset(now - CERT_BACKDATE);
        params.not_after = offset(now + ROOT_CA_VALIDITY);
        params.serial_number = Some(random_serial());

        let cert = params
            .self_signed(&key)
            .map_err(|source| RootCaError::SelfSign {
                cluster_id: cluster_id.to_owned(),
                source,
            })?;

        info!(
            cluster_id,
            common_name = ROOT_CA_CN,
            validity_secs = ROOT_CA_VALIDITY.as_secs(),
            "generated cluster root CA"
        );

        Ok(Self {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            cert_der: cert.der().clone(),
            cluster_id: Some(cluster_id.to_owned()),
        })
    }

    /// Reloads a root from its stored PEM material.
    ///
    /// Verifies that the certificate is a SatL root (`CN = satl-ca`) and that
    /// the key actually belongs to it — a mismatched pair would otherwise only
    /// surface as unverifiable signatures on every issued certificate.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, RootCaError> {
        let key = KeyPair::from_pem(key_pem).map_err(|source| RootCaError::ParseKey {
            len: key_pem.len(),
            source,
        })?;
        let cert_der =
            tls::first_certificate(cert_pem.as_bytes()).map_err(|err| RootCaError::ParseCert {
                len: cert_pem.len(),
                reason: err.to_string(),
            })?;

        let (cn, org, spki) = {
            let (_, parsed) = x509_parser::parse_x509_certificate(&cert_der).map_err(|err| {
                RootCaError::ParseCert {
                    len: cert_pem.len(),
                    reason: err.to_string(),
                }
            })?;
            let cn = tls::single_attribute(parsed.subject().iter_common_name()).unwrap_or_default();
            let org = tls::single_attribute(parsed.subject().iter_organization());
            let spki = parsed
                .public_key()
                .subject_public_key
                .data
                .as_ref()
                .to_vec();
            (cn, org, spki)
        };

        if cn != ROOT_CA_CN {
            return Err(RootCaError::NotARoot { cn });
        }
        if spki != key.public_key_raw() {
            return Err(RootCaError::KeyCertMismatch { cn });
        }

        debug!(cluster_id = ?org, "loaded cluster root CA from stored PEM");

        Ok(Self {
            cert_pem: cert_pem.to_owned(),
            key_pem: key_pem.to_owned(),
            cert_der,
            cluster_id: org,
        })
    }

    /// The root certificate, PEM-encoded.
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The root private key, PEM-encoded PKCS#8. **Never log this.**
    #[must_use]
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// The root certificate in DER form.
    #[must_use]
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// The trust bundle a joining node downloads and the join token digest is
    /// computed over.
    ///
    /// Today that is exactly the root certificate. Under root rotation (M5)
    /// the bundle grows to old + new roots, and the tokens are regenerated
    /// over the new bundle — which is why the digest is defined over the whole
    /// bundle and not over a single certificate (SWK §16.2/§16.5).
    #[must_use]
    pub fn bundle(&self) -> &[u8] {
        self.cert_pem.as_bytes()
    }

    /// The cluster id stamped into the root's `O`, if it carries one.
    #[must_use]
    pub fn cluster_id(&self) -> Option<&str> {
        self.cluster_id.as_deref()
    }

    /// Digest (base36 SHA-256) of this root's certificate PEM — the value
    /// recorded as a node's `certificate_issuer` and compared by the rotation
    /// reconciler (architecture §12.3). Same encoding as the join-token
    /// digest, but over one certificate rather than the whole bundle.
    #[must_use]
    pub fn cert_digest(&self) -> String {
        crate::token::bundle_digest(self.cert_pem.as_bytes())
    }

    /// Cross-signs `new_root` with this (old) root's key: a certificate with
    /// the new root's subject and public key, issued by this root
    /// (SWK §16.5, architecture §12.3).
    ///
    /// Appended to every leaf issued during a rotation, it makes the chain
    /// `leaf → cross-signed intermediate → old root` valid for verifiers
    /// still anchored on the old root, while the same leaf chains directly
    /// to the new root for verifiers already carrying it — the property that
    /// lets the trust anchors and the issued certificates converge in any
    /// order, with no flag day.
    ///
    /// The intermediate copies the new root's validity and CA constraints;
    /// only the serial number is fresh (two certificates from one issuer may
    /// not share one, RFC 5280 §4.1.2.2).
    pub fn cross_sign(&self, new_root: &Self) -> Result<CertPem, RootCaError> {
        // The new root's key pair carries the public key to certify. The
        // rotation state holds both keys, so this is not a constraint.
        let new_key =
            KeyPair::from_pem(new_root.key_pem()).map_err(|source| RootCaError::ParseKey {
                len: new_root.key_pem().len(),
                source,
            })?;

        let (not_before, not_after) = {
            let (_, parsed) =
                x509_parser::parse_x509_certificate(&new_root.cert_der).map_err(|err| {
                    RootCaError::ParseCert {
                        len: new_root.cert_pem.len(),
                        reason: err.to_string(),
                    }
                })?;
            (
                parsed.validity().not_before.to_datetime(),
                parsed.validity().not_after.to_datetime(),
            )
        };

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, ROOT_CA_CN);
        if let Some(cluster_id) = new_root.cluster_id() {
            dn.push(DnType::OrganizationName, cluster_id);
        }

        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = not_before;
        params.not_after = not_after;
        params.serial_number = Some(random_serial());
        params.use_authority_key_identifier_extension = true;

        let old_key = KeyPair::from_pem(&self.key_pem).map_err(|source| RootCaError::ParseKey {
            len: self.key_pem.len(),
            source,
        })?;
        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, old_key).map_err(|source| {
            RootCaError::ParseCert {
                len: self.cert_pem.len(),
                reason: source.to_string(),
            }
        })?;

        let cert = params
            .signed_by(&new_key, &issuer)
            .map_err(|source| RootCaError::Sign {
                node_id: ROOT_CA_CN.to_owned(),
                ou: "cross-signed intermediate",
                cluster_id: new_root.cluster_id().unwrap_or_default().to_owned(),
                source,
            })?;

        info!(
            old_digest = %self.cert_digest(),
            new_digest = %new_root.cert_digest(),
            "cross-signed the new root CA with the old root's key"
        );
        Ok(CertPem(cert.pem()))
    }

    /// Signs a node certificate from a CSR (SWK §16.3 step 5).
    ///
    /// Everything except the public key and its algorithm is decided here:
    /// `CN = node_id`, `OU = satl-manager|satl-worker`, `O = cluster_id`, DNS
    /// SANs `satl-manager` and `satl-ca` for managers, validity backdated
    /// [`CERT_BACKDATE`] (capped at an eighth of the validity, see that
    /// constant), a fresh random serial. Whatever subject or extension the
    /// CSR asked for is discarded.
    ///
    /// The CSR's self-signature is verified before anything else: it proves
    /// the requester holds the private key for the public key being certified.
    pub fn sign_node_csr(
        &self,
        csr_der: &[u8],
        node_id: &Id,
        role: NodeRole,
        cluster_id: &str,
        validity: Duration,
    ) -> Result<CertPem, RootCaError> {
        if validity < HARD_MIN_CERT_VALIDITY {
            return Err(RootCaError::ValidityTooShort {
                node_id: node_id.to_string(),
                requested: validity,
                minimum: HARD_MIN_CERT_VALIDITY,
            });
        }
        if let Some(root_cluster) = self.cluster_id()
            && root_cluster != cluster_id
        {
            return Err(RootCaError::ClusterIdMismatch {
                node_id: node_id.to_string(),
                requested: cluster_id.to_owned(),
                root: root_cluster.to_owned(),
            });
        }

        // Parses *and verifies the self-signature*; everything but the public
        // key in the result is deliberately dropped on the floor.
        let request = rcgen::CertificateSigningRequestParams::from_der(&csr_der.into()).map_err(
            |source| RootCaError::Csr {
                node_id: node_id.to_string(),
                len: csr_der.len(),
                source,
            },
        )?;
        let public_key = request.public_key;
        let algorithm = format!("{:?}", public_key.algorithm());
        if !is_supported_key_algorithm(public_key.algorithm()) {
            return Err(RootCaError::UnsupportedKeyAlgorithm {
                node_id: node_id.to_string(),
                algorithm,
            });
        }

        let ou = role_ou(role);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, node_id.as_str());
        dn.push(DnType::OrganizationalUnitName, ou);
        dn.push(DnType::OrganizationName, cluster_id);

        let now = SystemTime::now();
        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyAgreement,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.subject_alt_names = manager_sans(role)?;
        // The backdate absorbs clock skew but must never dominate a short
        // test validity, or the 50-80 % renewal window lands in the past
        // (see CERT_BACKDATE's docs). At the production validity the cap is
        // 11 days, so the full hour applies.
        params.not_before = offset(now - CERT_BACKDATE.min(validity / 8));
        params.not_after = offset(now + validity);
        params.serial_number = Some(random_serial());
        params.use_authority_key_identifier_extension = true;

        let key = KeyPair::from_pem(&self.key_pem).map_err(|source| RootCaError::ParseKey {
            len: self.key_pem.len(),
            source,
        })?;
        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, key).map_err(|source| {
            RootCaError::ParseCert {
                len: self.cert_pem.len(),
                reason: source.to_string(),
            }
        })?;

        let cert = params
            .signed_by(&public_key, &issuer)
            .map_err(|source| RootCaError::Sign {
                node_id: node_id.to_string(),
                ou,
                cluster_id: cluster_id.to_owned(),
                source,
            })?;

        info!(
            node_id = %node_id,
            role = ou,
            cluster_id,
            validity_secs = validity.as_secs(),
            "issued node certificate"
        );

        Ok(CertPem(cert.pem()))
    }
}

impl std::fmt::Debug for RootCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootCa")
            .field("cluster_id", &self.cluster_id)
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Managers present `satl-manager` (peer RPC) and `satl-ca` (bootstrap
/// endpoint); workers never serve TLS (invariant #3: managers never dial
/// workers) and therefore get no DNS SANs at all.
fn manager_sans(role: NodeRole) -> Result<Vec<SanType>, RootCaError> {
    if role == NodeRole::Worker {
        return Ok(Vec::new());
    }
    let mut sans = Vec::with_capacity(2);
    for name in [SAN_MANAGER, SAN_CA] {
        // Both are compile-time constants and valid DNS labels; the conversion
        // cannot fail, but there is no infallible constructor.
        let dns = name
            .to_owned()
            .try_into()
            .map_err(|source| RootCaError::InvalidSan { name, source })?;
        sans.push(SanType::DnsName(dns));
    }
    Ok(sans)
}

fn is_supported_key_algorithm(algorithm: &rcgen::SignatureAlgorithm) -> bool {
    algorithm == &rcgen::PKCS_ECDSA_P256_SHA256 || algorithm == &rcgen::PKCS_ECDSA_P384_SHA384
}

fn random_serial() -> SerialNumber {
    let mut bytes = [0_u8; SERIAL_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    // Keep the DER INTEGER positive (RFC 5280 §4.1.2.2).
    bytes[0] &= 0x7f;
    bytes[0] |= 0x01;
    SerialNumber::from_slice(&bytes)
}

fn offset(time: SystemTime) -> OffsetDateTime {
    OffsetDateTime::from(time)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use x509_parser::prelude::FromDer;

    use super::*;
    use crate::csr::NodeKeyPair;
    use crate::{OU_MANAGER, OU_WORKER};

    const CLUSTER: &str = "3n2ff1rvrc4mn3s2fu6zlt6tw";

    fn node_id() -> Id {
        Id::generate()
    }

    /// Holds the DER a parsed certificate borrows from.
    struct Der(Vec<u8>);

    impl Der {
        fn cert(&self) -> x509_parser::certificate::X509Certificate<'_> {
            x509_parser::certificate::X509Certificate::from_der(&self.0)
                .expect("certificate parses")
                .1
        }
    }

    fn der_of(pem: &str) -> Der {
        Der(tls::first_certificate(pem.as_bytes())
            .expect("PEM certificate")
            .to_vec())
    }

    #[test]
    fn root_has_the_pinned_subject_and_validity() {
        let root = RootCa::generate(CLUSTER).expect("generate root");
        let der = der_of(root.cert_pem());
        let cert = der.cert();

        assert_eq!(
            tls::single_attribute(cert.subject().iter_common_name()).as_deref(),
            Some(ROOT_CA_CN)
        );
        assert_eq!(
            tls::single_attribute(cert.subject().iter_organization()).as_deref(),
            Some(CLUSTER)
        );
        assert_eq!(root.cluster_id(), Some(CLUSTER));
        assert!(cert.is_ca(), "root must carry basicConstraints CA:TRUE");
        assert_eq!(cert.subject(), cert.issuer(), "root is self-signed");
        cert.verify_signature(None)
            .expect("root self-signature verifies");

        let span = cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
        let expected =
            i64::try_from((ROOT_CA_VALIDITY + CERT_BACKDATE).as_secs()).expect("fits in i64");
        assert!(
            (span - expected).abs() <= 2,
            "root validity span {span}s, expected ~{expected}s"
        );
    }

    #[test]
    fn root_is_ecdsa_p256() {
        let root = RootCa::generate(CLUSTER).expect("generate root");
        let der = der_of(root.cert_pem());
        let cert = der.cert();
        let algorithm = cert.public_key().algorithm.algorithm.to_id_string();
        // 1.2.840.10045.2.1 = id-ecPublicKey
        assert_eq!(algorithm, "1.2.840.10045.2.1");
        assert!(root.key_pem().contains("PRIVATE KEY"));
    }

    #[test]
    fn each_root_is_unique() {
        let a = RootCa::generate(CLUSTER).expect("generate");
        let b = RootCa::generate(CLUSTER).expect("generate");
        assert_ne!(a.cert_pem(), b.cert_pem());
        assert_ne!(a.key_pem(), b.key_pem());
        assert_ne!(a.bundle(), b.bundle());
    }

    #[test]
    fn root_roundtrips_through_pem() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let back = RootCa::from_pem(root.cert_pem(), root.key_pem()).expect("reload");
        assert_eq!(back.cert_pem(), root.cert_pem());
        assert_eq!(back.cluster_id(), Some(CLUSTER));
        assert_eq!(back.bundle(), root.cert_pem().as_bytes());
    }

    #[test]
    fn reload_rejects_a_mismatched_key() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let other = RootCa::generate(CLUSTER).expect("generate");
        let err = RootCa::from_pem(root.cert_pem(), other.key_pem())
            .expect_err("mismatched key must be refused");
        assert!(
            matches!(err, RootCaError::KeyCertMismatch { .. }),
            "unexpected error: {err}"
        );
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn reload_rejects_a_foreign_certificate() {
        let key = KeyPair::generate().expect("key");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "not-satl");
        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).expect("self sign");
        let err = RootCa::from_pem(&cert.pem(), &key.serialize_pem())
            .expect_err("foreign root must be refused");
        assert!(matches!(err, RootCaError::NotARoot { .. }), "{err}");
    }

    #[test]
    fn reload_rejects_garbage() {
        assert!(RootCa::from_pem("not pem", "not pem either").is_err());
        let root = RootCa::generate(CLUSTER).expect("generate");
        assert!(RootCa::from_pem("not pem", root.key_pem()).is_err());
        assert!(RootCa::from_pem(root.cert_pem(), "not pem").is_err());
    }

    #[test]
    fn signs_a_worker_certificate_with_the_server_controlled_subject() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let node = NodeKeyPair::generate().expect("node key");
        let id = node_id();

        let issued = root
            .sign_node_csr(
                &node.csr_der().expect("csr"),
                &id,
                NodeRole::Worker,
                CLUSTER,
                crate::NODE_CERT_VALIDITY,
            )
            .expect("sign");
        let der = der_of(issued.as_str());
        let cert = der.cert();

        assert_eq!(
            tls::single_attribute(cert.subject().iter_common_name()).as_deref(),
            Some(id.as_str())
        );
        assert_eq!(
            tls::single_attribute(cert.subject().iter_organizational_unit()).as_deref(),
            Some(OU_WORKER)
        );
        assert_eq!(
            tls::single_attribute(cert.subject().iter_organization()).as_deref(),
            Some(CLUSTER)
        );
        assert!(!cert.is_ca());
        assert!(
            cert.subject_alternative_name()
                .expect("san lookup")
                .is_none(),
            "workers get no DNS SANs"
        );

        // Chains to the root.
        let root_der = der_of(root.cert_pem());
        let root_cert = root_der.cert();
        cert.verify_signature(Some(root_cert.public_key()))
            .expect("leaf is signed by the root");
        assert_eq!(cert.issuer(), root_cert.subject());
    }

    #[test]
    fn manager_certificates_carry_the_pinned_dns_sans() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let node = NodeKeyPair::generate().expect("node key");
        let id = node_id();
        let issued = root
            .sign_node_csr(
                &node.csr_der().expect("csr"),
                &id,
                NodeRole::Manager,
                CLUSTER,
                crate::NODE_CERT_VALIDITY,
            )
            .expect("sign");
        let der = der_of(issued.as_str());
        let cert = der.cert();

        assert_eq!(
            tls::single_attribute(cert.subject().iter_organizational_unit()).as_deref(),
            Some(OU_MANAGER)
        );
        let san = cert
            .subject_alternative_name()
            .expect("san lookup")
            .expect("managers have SANs");
        let names: Vec<String> = san
            .value
            .general_names
            .iter()
            .map(|name| format!("{name:?}"))
            .collect();
        let joined = names.join(",");
        assert!(joined.contains(SAN_MANAGER), "{joined}");
        assert!(joined.contains(SAN_CA), "{joined}");
    }

    /// SWK §16.3 step 5 — the CSR's own subject must be ignored entirely.
    #[test]
    fn a_csr_supplied_subject_is_ignored() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let key = KeyPair::generate().expect("key");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "attacker-chosen-node-id");
        dn.push(DnType::OrganizationalUnitName, OU_MANAGER);
        dn.push(DnType::OrganizationName, "some-other-cluster");
        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        let csr = params.serialize_request(&key).expect("csr");

        let id = node_id();
        let issued = root
            .sign_node_csr(
                csr.der(),
                &id,
                NodeRole::Worker,
                CLUSTER,
                crate::NODE_CERT_VALIDITY,
            )
            .expect("sign");
        let der = der_of(issued.as_str());
        let cert = der.cert();

        assert_eq!(
            tls::single_attribute(cert.subject().iter_common_name()).as_deref(),
            Some(id.as_str()),
            "CN must be the server-assigned node id"
        );
        assert_eq!(
            tls::single_attribute(cert.subject().iter_organizational_unit()).as_deref(),
            Some(OU_WORKER),
            "OU must be the granted role, not the requested one"
        );
        assert_eq!(
            tls::single_attribute(cert.subject().iter_organization()).as_deref(),
            Some(CLUSTER)
        );
        // ...but the key from the CSR *is* the one certified.
        assert_eq!(
            cert.public_key().subject_public_key.data.as_ref(),
            key.public_key_raw()
        );
    }

    #[test]
    fn issued_validity_is_backdated_and_bounded() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let node = NodeKeyPair::generate().expect("node key");
        let validity = crate::NODE_CERT_VALIDITY;
        let issued = root
            .sign_node_csr(
                &node.csr_der().expect("csr"),
                &node_id(),
                NodeRole::Worker,
                CLUSTER,
                validity,
            )
            .expect("sign");
        let der = der_of(issued.as_str());
        let cert = der.cert();

        let now = i64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("after epoch")
                .as_secs(),
        )
        .expect("fits");
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        let backdate = i64::try_from(CERT_BACKDATE.as_secs()).expect("fits");

        assert!(
            (now - not_before - backdate).abs() <= 2,
            "not_before should be ~1h in the past, got {}s",
            now - not_before
        );
        assert!(
            (not_after - now - i64::try_from(validity.as_secs()).expect("fits")).abs() <= 2,
            "not_after should be ~90d out"
        );
    }

    #[test]
    fn serial_numbers_are_unique_and_positive() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let node = NodeKeyPair::generate().expect("node key");
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            let issued = root
                .sign_node_csr(
                    &node.csr_der().expect("csr"),
                    &node_id(),
                    NodeRole::Worker,
                    CLUSTER,
                    crate::NODE_CERT_VALIDITY,
                )
                .expect("sign");
            let der = der_of(issued.as_str());
            let cert = der.cert();
            assert!(cert.raw_serial()[0] & 0x80 == 0, "serial must be positive");
            assert!(seen.insert(cert.raw_serial().to_vec()), "serial reused");
        }
    }

    #[test]
    fn rejects_a_tampered_csr() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let node = NodeKeyPair::generate().expect("node key");
        let mut der = node.csr_der().expect("csr");
        // Corrupt a byte inside the signed body; the self-signature no longer
        // verifies.
        let idx = der.len() / 2;
        der[idx] ^= 0xff;
        let err = root
            .sign_node_csr(
                &der,
                &node_id(),
                NodeRole::Worker,
                CLUSTER,
                crate::NODE_CERT_VALIDITY,
            )
            .expect_err("tampered CSR must be refused");
        assert!(matches!(err, RootCaError::Csr { .. }), "{err}");
        assert!(err.to_string().contains("certificate signing request"));
    }

    #[test]
    fn rejects_junk_and_empty_csrs() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        for der in [Vec::new(), b"not a csr".to_vec(), vec![0x30; 64]] {
            let err = root
                .sign_node_csr(
                    &der,
                    &node_id(),
                    NodeRole::Worker,
                    CLUSTER,
                    crate::NODE_CERT_VALIDITY,
                )
                .expect_err("junk must be refused");
            assert!(matches!(err, RootCaError::Csr { .. }), "{err}");
        }
    }

    #[test]
    fn rejects_a_non_ecdsa_csr() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 key");
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .expect("csr");
        let err = root
            .sign_node_csr(
                csr.der(),
                &node_id(),
                NodeRole::Worker,
                CLUSTER,
                crate::NODE_CERT_VALIDITY,
            )
            .expect_err("ed25519 must be refused");
        assert!(
            matches!(err, RootCaError::UnsupportedKeyAlgorithm { .. }),
            "{err}"
        );
    }

    #[test]
    fn rejects_a_too_short_validity() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let node = NodeKeyPair::generate().expect("node key");
        let err = root
            .sign_node_csr(
                &node.csr_der().expect("csr"),
                &node_id(),
                NodeRole::Worker,
                CLUSTER,
                Duration::from_secs(30),
            )
            .expect_err("30s is below the hard floor and must be refused");
        assert!(matches!(err, RootCaError::ValidityTooShort { .. }), "{err}");
        // Exactly the hard floor is fine (a *testing* validity; the config
        // layer is what warns below MIN_CERT_VALIDITY).
        root.sign_node_csr(
            &node.csr_der().expect("csr"),
            &node_id(),
            NodeRole::Worker,
            CLUSTER,
            HARD_MIN_CERT_VALIDITY,
        )
        .expect("the hard floor is accepted");
    }

    /// A short-lived test certificate must keep its renewal window in the
    /// future: the backdate is capped at an eighth of the validity, so the
    /// 50-80 % window over NotBefore..NotAfter always starts after issuance.
    #[test]
    fn a_short_validity_scales_the_backdate_so_renewal_stays_ahead() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let node = NodeKeyPair::generate().expect("node key");
        let validity = Duration::from_mins(5);
        let issued = root
            .sign_node_csr(
                &node.csr_der().expect("csr"),
                &node_id(),
                NodeRole::Worker,
                CLUSTER,
                validity,
            )
            .expect("sign");
        let (not_before, not_after) =
            tls::certificate_validity(issued.as_str()).expect("validity parses");

        let span = not_after.duration_since(not_before).expect("ordered");
        assert!(
            span <= validity + validity / 8 + Duration::from_secs(2),
            "the backdate must be capped at validity/8, span was {span:?}"
        );
        // The earliest possible renewal point (50 % of the span) is after
        // issuance — the schedule cannot degenerate into an immediate-renew
        // hot loop.
        let earliest_renewal = not_before + span / 2;
        assert!(
            earliest_renewal > SystemTime::now(),
            "the renewal window must start in the future"
        );
    }

    #[test]
    fn refuses_to_stamp_a_foreign_cluster_id() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let node = NodeKeyPair::generate().expect("node key");
        let err = root
            .sign_node_csr(
                &node.csr_der().expect("csr"),
                &node_id(),
                NodeRole::Worker,
                "some-other-cluster",
                crate::NODE_CERT_VALIDITY,
            )
            .expect_err("foreign cluster id must be refused");
        assert!(
            matches!(err, RootCaError::ClusterIdMismatch { .. }),
            "{err}"
        );
    }

    /// The rotation property, end to end at the signing layer: a leaf signed
    /// by the new root, presented with the cross-signed intermediate,
    /// verifies against the old root alone *and* against the new root alone.
    #[test]
    fn a_cross_signed_chain_verifies_against_either_root() {
        let old = RootCa::generate(CLUSTER).expect("old root");
        let new = RootCa::generate(CLUSTER).expect("new root");
        let cross = old.cross_sign(&new).expect("cross-sign");

        // The intermediate carries the new root's subject and public key,
        // and the old root's issuer.
        let cross_der = der_of(cross.as_str());
        let cross_cert = cross_der.cert();
        let new_der = der_of(new.cert_pem());
        let new_cert = new_der.cert();
        let old_der = der_of(old.cert_pem());
        let old_cert = old_der.cert();
        assert_eq!(cross_cert.subject(), new_cert.subject());
        assert_eq!(
            cross_cert.public_key().subject_public_key,
            new_cert.public_key().subject_public_key
        );
        assert_eq!(cross_cert.issuer(), old_cert.subject());
        assert!(cross_cert.is_ca(), "the intermediate must be a CA");
        cross_cert
            .verify_signature(Some(old_cert.public_key()))
            .expect("the old root signed the intermediate");

        // A leaf signed by the new root, with the intermediate appended.
        let node = NodeKeyPair::generate().expect("node key");
        let id = node_id();
        let leaf = new
            .sign_node_csr(
                &node.csr_der().expect("csr"),
                &id,
                NodeRole::Worker,
                CLUSTER,
                crate::NODE_CERT_VALIDITY,
            )
            .expect("sign");
        let chain = format!("{}{}", leaf.as_str(), cross.as_str());

        // Old-root-only verifier: the chain passes through the intermediate.
        let old_pool = tls::root_store(old.cert_pem().as_bytes()).expect("old pool");
        crate::verify_issued_cert(&chain, &id, NodeRole::Worker, &old_pool)
            .expect("the old trust anchor accepts the cross-signed chain");
        // New-root-only verifier: the leaf chains directly.
        let new_pool = tls::root_store(new.cert_pem().as_bytes()).expect("new pool");
        crate::verify_issued_cert(&chain, &id, NodeRole::Worker, &new_pool)
            .expect("the new trust anchor accepts the leaf directly");
        // A third, unrelated root accepts neither.
        let other = RootCa::generate(CLUSTER).expect("other root");
        let other_pool = tls::root_store(other.cert_pem().as_bytes()).expect("other pool");
        assert!(
            crate::verify_issued_cert(&chain, &id, NodeRole::Worker, &other_pool).is_err(),
            "an unrelated root must reject the chain"
        );
    }

    #[test]
    fn cross_signing_yields_a_distinct_serial_and_digest() {
        let old = RootCa::generate(CLUSTER).expect("old root");
        let new = RootCa::generate(CLUSTER).expect("new root");
        let cross = old.cross_sign(&new).expect("cross-sign");
        let cross_der = der_of(cross.as_str());
        let new_der = der_of(new.cert_pem());
        assert_ne!(
            cross_der.cert().raw_serial(),
            new_der.cert().raw_serial(),
            "one issuer must never mint two certificates with one serial"
        );
        assert_ne!(old.cert_digest(), new.cert_digest());
        assert_eq!(
            new.cert_digest(),
            crate::token::bundle_digest(new.cert_pem().as_bytes())
        );
    }

    #[test]
    fn debug_does_not_leak_the_private_key() {
        let root = RootCa::generate(CLUSTER).expect("generate");
        let rendered = format!("{root:?}");
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
        let body: String = root
            .key_pem()
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert!(!body.is_empty());
        assert!(!rendered.contains(&body), "{rendered}");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn cert_pem_newtype_is_transparent() {
        let pem = CertPem::new("x".to_owned());
        assert_eq!(pem.as_str(), "x");
        assert_eq!(pem.as_bytes(), b"x");
        assert_eq!(pem.to_string(), "x");
        assert_eq!(String::from(pem.clone()), "x");
        assert_eq!(pem.into_string(), "x");
    }

    #[test]
    fn id_from_str_is_what_cn_carries() {
        // Guards the CN contract: the value we stamp is exactly a satl-core Id.
        let root = RootCa::generate(CLUSTER).expect("generate");
        let node = NodeKeyPair::generate().expect("node key");
        let id = node_id();
        let issued = root
            .sign_node_csr(
                &node.csr_der().expect("csr"),
                &id,
                NodeRole::Manager,
                CLUSTER,
                crate::NODE_CERT_VALIDITY,
            )
            .expect("sign");
        let der = der_of(issued.as_str());
        let cert = der.cert();
        let cn = tls::single_attribute(cert.subject().iter_common_name()).expect("cn");
        assert_eq!(Id::from_str(&cn).expect("cn parses as an Id"), id);
    }
}
