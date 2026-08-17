// SPDX-License-Identifier: BSD-2-Clause
//! gRPC channel construction — the one place in `satld` that dials.
//!
//! Four kinds of channel exist, and the difference between them is entirely
//! about *what authenticates whom*:
//!
//! | Channel | Server verified by | Client presents |
//! |---|---|---|
//! | [`unverified_tls_channel`] | nothing — first contact | nothing |
//! | [`pinned_tls_channel`] | the bundle the join token pinned | nothing |
//! | [`MtlsChannels`] | the cluster root, name `satl-manager` | this node's certificate |
//! | [`local_channel`] | the filesystem (root-owned socket) | nothing |
//!
//! The first two exist only for the join flow (`proto/ca.proto`'s
//! chicken-and-egg exemption); the third is every other node-to-node call;
//! the fourth is the co-located manager, which an agent prefers over the
//! network (architecture §7.2).
//!
//! # Why the unverified channel is not a hole
//!
//! `GetRootCACertificate` returns only public material and the joiner refuses
//! to trust a byte of it until [`satl_ca::JoinToken::verify_ca_bundle`] has
//! matched it against the digest baked into the token the operator carried
//! out of band. The token *secret* never travels on that connection — it goes
//! out on the next call, which is pinned. So an attacker who intercepts first
//! contact can hand over a bundle, and the joiner will notice and abort.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use satl_ca::LiveIdentity;
use satl_dispatcher::{ChannelFactory, ConnectError, Endpoint as PeerEndpoint};
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint};

/// Connect timeout on every channel this module builds.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Channel construction failed before a single byte was sent.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    /// The address is not something tonic can turn into an endpoint.
    #[error("cannot dial {addr}: {reason}")]
    Address {
        /// The address that was rejected.
        addr: String,
        /// Why.
        reason: String,
    },

    /// A TLS configuration could not be built.
    #[error("TLS configuration for {addr}: {source}")]
    Tls {
        /// The peer the configuration was for.
        addr: String,
        /// Underlying failure.
        #[source]
        source: satl_ca::TlsError,
    },
}

fn endpoint(addr: &str) -> Result<Endpoint, ChannelError> {
    // Scheme `http`: the connectors below own the TLS handshake, so tonic
    // must not layer its own on top.
    Endpoint::from_shared(format!("http://{addr}"))
        .map_err(|err| ChannelError::Address {
            addr: addr.to_owned(),
            reason: err.to_string(),
        })
        .map(|endpoint| endpoint.connect_timeout(CONNECT_TIMEOUT).tcp_nodelay(true))
}

/// A lazily-connecting TLS channel to `addr` using `config`.
fn tls_channel(addr: &str, config: Arc<rustls::ClientConfig>) -> Result<Channel, ChannelError> {
    let endpoint = endpoint(addr)?;
    let target = addr.to_owned();
    let connector = tower::service_fn(move |_: http::Uri| {
        let config = Arc::clone(&config);
        let target = target.clone();
        async move {
            let stream = tokio::net::TcpStream::connect(&target).await?;
            stream.set_nodelay(true)?;
            // The verifiers below pin the name they want themselves, so this
            // one only has to be a syntactically valid DNS name.
            let name = rustls_pki_types::ServerName::try_from(satl_ca::SAN_CA)
                .map_err(std::io::Error::other)?;
            let stream = TlsConnector::from(config).connect(name, stream).await?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
        }
    });
    Ok(endpoint.connect_with_connector_lazy(connector))
}

/// A channel that presents no client certificate and verifies no server
/// certificate: the very first call of a join (`GetRootCACertificate`).
pub fn unverified_tls_channel(addr: &str) -> Result<Channel, ChannelError> {
    let config = rustls::ClientConfig::builder_with_provider(satl_ca::crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|source| ChannelError::Tls {
            addr: addr.to_owned(),
            source: satl_ca::TlsError::Config {
                side: "client",
                source,
            },
        })?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier::AcceptAnyServer::new()))
        .with_no_client_auth();
    tls_channel(addr, Arc::new(config))
}

/// A channel that verifies the server against `ca_bundle` — the bundle the
/// join token's digest just pinned — and presents no client certificate.
pub fn pinned_tls_channel(addr: &str, ca_bundle: &[u8]) -> Result<Channel, ChannelError> {
    let roots = satl_ca::root_store(ca_bundle).map_err(|source| ChannelError::Tls {
        addr: addr.to_owned(),
        source,
    })?;
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        satl_ca::crypto_provider(),
    )
    .build()
    .map_err(|source| ChannelError::Tls {
        addr: addr.to_owned(),
        source: satl_ca::TlsError::NoTrustAnchors {
            len: ca_bundle.len(),
            source,
        },
    })?;
    let config = rustls::ClientConfig::builder_with_provider(satl_ca::crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|source| ChannelError::Tls {
            addr: addr.to_owned(),
            source: satl_ca::TlsError::Config {
                side: "client",
                source,
            },
        })?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier::PinnedName::new(
            verifier,
            satl_ca::SAN_CA,
        )))
        .with_no_client_auth();
    tls_channel(addr, Arc::new(config))
}

/// A channel to the co-located manager's dispatcher over its unix socket.
///
/// The socket is root-owned inside the state directory, so possession of it
/// *is* the authorization — which is why the local dispatcher server injects
/// this node's own identity rather than reading a certificate
/// ([`crate::cluster::local_dispatcher`]).
pub fn local_channel(socket: &Path) -> Result<Channel, ChannelError> {
    // The authority is ignored by the connector but must parse.
    let endpoint = endpoint("localhost:2377")?;
    let socket = socket.to_path_buf();
    let connector = tower::service_fn(move |_: http::Uri| {
        let socket = socket.clone();
        async move {
            let stream = tokio::net::UnixStream::connect(&socket).await?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
        }
    });
    Ok(endpoint.connect_with_connector_lazy(connector))
}

/// The agent's [`ChannelFactory`]: mTLS for remote managers, a unix socket
/// for the co-located one.
///
/// This is the whole of the glue `satl-dispatcher` asks `satld` for. It holds
/// one `rustls::ClientConfig` (built once over this node's **live** identity)
/// and one channel cache, because a `tonic::Channel` is a pool: rebuilding it
/// per session would drop the connection every time the agent reconnects.
/// The configuration resolves the certificate through the live identity per
/// handshake, so a renewal swapped by [`crate::identity::spawn_renewal`] is
/// what the next (re)connect presents — cached channels included.
#[derive(Clone)]
pub struct MtlsChannels {
    tls: Arc<rustls::ClientConfig>,
    cache: Arc<std::sync::Mutex<std::collections::HashMap<String, Channel>>>,
}

impl std::fmt::Debug for MtlsChannels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtlsChannels").finish_non_exhaustive()
    }
}

impl MtlsChannels {
    /// Builds the client configuration over this node's live identity,
    /// pinning the server name every manager certificate carries.
    pub fn new(identity: &Arc<LiveIdentity>) -> Result<Self, ChannelError> {
        let tls =
            satl_ca::live_client_config(identity, satl_ca::SAN_MANAGER).map_err(|source| {
                ChannelError::Tls {
                    addr: satl_ca::SAN_MANAGER.to_owned(),
                    source,
                }
            })?;
        Ok(Self {
            tls: Arc::new(tls),
            cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    /// A cached (or freshly built) mTLS channel to `addr`.
    pub fn channel(&self, addr: &str) -> Result<Channel, ChannelError> {
        if let Ok(cache) = self.cache.lock()
            && let Some(channel) = cache.get(addr)
        {
            return Ok(channel.clone());
        }
        let channel = tls_channel(addr, Arc::clone(&self.tls))?;
        if let Ok(mut cache) = self.cache.lock() {
            return Ok(cache.entry(addr.to_owned()).or_insert(channel).clone());
        }
        Ok(channel)
    }
}

/// The agent's connector: the local socket when this node is a manager, mTLS
/// otherwise.
#[derive(Clone, Debug)]
pub struct AgentChannels {
    channels: MtlsChannels,
    local_socket: Option<PathBuf>,
}

impl AgentChannels {
    /// A connector over `channels`, preferring `local_socket` when the agent
    /// asks for the co-located manager.
    #[must_use]
    pub fn new(channels: MtlsChannels, local_socket: Option<PathBuf>) -> Self {
        Self {
            channels,
            local_socket,
        }
    }
}

impl ChannelFactory for AgentChannels {
    async fn connect(&self, endpoint: &PeerEndpoint) -> Result<Channel, ConnectError> {
        match endpoint {
            PeerEndpoint::Local(path) => {
                // The agent only ever asks for the socket it was configured
                // with; honour whatever it hands back so a test can point it
                // somewhere else.
                let path = self.local_socket.as_deref().unwrap_or(path.as_path());
                local_channel(path).map_err(ConnectError::new)
            }
            PeerEndpoint::Remote(peer) => {
                self.channels.channel(&peer.addr).map_err(ConnectError::new)
            }
            PeerEndpoint::Redirect(addr) => self.channels.channel(addr).map_err(ConnectError::new),
        }
    }
}

/// Server-certificate verifiers the join flow needs and rustls does not ship.
mod verifier {
    use std::sync::Arc;

    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    /// Verifies nothing. Used for exactly one RPC —
    /// `NodeCA.GetRootCACertificate` — whose response is public material the
    /// caller then pins against its join token digest.
    ///
    /// It carries no `Debug` detail and no constructor other than this one on
    /// purpose: it must be impossible to reach for by accident.
    #[derive(Debug)]
    pub struct AcceptAnyServer {
        provider: Arc<rustls::crypto::CryptoProvider>,
    }

    impl AcceptAnyServer {
        pub fn new() -> Self {
            Self {
                provider: satl_ca::crypto_provider(),
            }
        }
    }

    impl ServerCertVerifier for AcceptAnyServer {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// Web PKI verification with the expected server name fixed at
    /// configuration time rather than taken from the dial site — managers are
    /// dialed by address but their certificates carry `satl-ca` /
    /// `satl-manager`.
    #[derive(Debug)]
    pub struct PinnedName {
        inner: Arc<WebPkiServerVerifier>,
        expected: ServerName<'static>,
    }

    impl PinnedName {
        pub fn new(inner: Arc<WebPkiServerVerifier>, expected: &str) -> Self {
            Self {
                inner,
                // `satl-ca` and `satl-manager` are compile-time constants and
                // both are valid DNS names; a failure here is unreachable, so
                // falling back to the other constant keeps this total without
                // a panic.
                expected: ServerName::try_from(expected.to_owned()).unwrap_or(
                    ServerName::try_from("satl-manager").unwrap_or(ServerName::IpAddress(
                        rustls_pki_types::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST.into()),
                    )),
                ),
            }
        }
    }

    impl ServerCertVerifier for PinnedName {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            ocsp: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            self.inner
                .verify_server_cert(end_entity, intermediates, &self.expected, ocsp, now)
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A lazy channel still registers with the tokio reactor when it is built,
    // so this needs a runtime even though nothing connects.
    #[tokio::test]
    async fn every_channel_kind_builds_from_a_plausible_address() {
        let identity = satl_cluster::testing::test_live_identity();
        let channels = MtlsChannels::new(&identity).expect("mtls config");
        // Lazy channels: building one proves the configuration is sound
        // without needing anything to listen.
        channels.channel("10.2.0.4:2377").expect("mtls channel");
        // ...and the second call is served from the cache.
        channels.channel("10.2.0.4:2377").expect("cached channel");
        unverified_tls_channel("10.2.0.4:2378").expect("bootstrap channel");
        pinned_tls_channel("10.2.0.4:2378", identity.identity().ca_pem.as_bytes())
            .expect("pinned channel");
        local_channel(std::path::Path::new("/var/run/satl-dispatcher.sock")).expect("unix channel");
    }

    #[test]
    fn an_unusable_address_is_reported_with_the_address_in_it() {
        let err = unverified_tls_channel("").expect_err("empty address");
        assert!(matches!(err, ChannelError::Address { .. }), "{err}");
    }

    #[test]
    fn a_bundle_with_no_certificates_is_refused() {
        let err = pinned_tls_channel("10.2.0.4:2378", b"not a pem").expect_err("no anchors");
        assert!(matches!(err, ChannelError::Tls { .. }), "{err}");
    }
}
