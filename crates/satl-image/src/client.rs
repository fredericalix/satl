// SPDX-License-Identifier: BSD-2-Clause
//! Pull-only OCI distribution HTTP client.
//!
//! Built on `reqwest` with **rustls** (`default-features = false`,
//! `features = ["rustls", "json", "stream"]` — the feature was named
//! `rustls-tls` before reqwest 0.13): SatL dials arbitrary registries on
//! operator request, so it needs a boring, maintained, memory-safe TLS stack
//! with no OpenSSL system dependency to track for the FreeBSD package.
//!
//! Plain HTTP is used **only** for loopback registries (`localhost`,
//! `127.0.0.1`, `[::1]`, any port) — that is what the local test registry
//! needs; every other registry is contacted over HTTPS, and there is no
//! insecure-registry override (an explicit non-loopback HTTP request fails
//! with [`ImageError::PlainHttpRefused`]).

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::StreamExt as _;
use reqwest::header::{ACCEPT, CONTENT_TYPE, WWW_AUTHENTICATE};
use reqwest::{Response, StatusCode};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;
use tracing::{debug, instrument, warn};

use crate::auth::{AuthChallenge, RegistryAuth, TokenCache, TokenResponse, parse_www_authenticate};
use crate::error::ImageError;
use crate::manifest::MANIFEST_ACCEPT;
use crate::reference::{Digest, ImageReference};

/// Attempts for transient failures (connect errors, 5xx).
const MAX_ATTEMPTS: u32 = 3;
/// Base backoff between attempts (doubles each retry).
const BACKOFF_BASE: Duration = Duration::from_millis(250);

/// A manifest response: raw bytes (digest-verified), the content type the
/// registry declared, and the digest the bytes actually hash to.
#[derive(Debug)]
pub struct FetchedManifest {
    /// Raw manifest bytes, exactly as served.
    pub bytes: Vec<u8>,
    /// The `Content-Type` of the response.
    pub media_type: String,
    /// sha256 of `bytes` (verified against the request digest and the
    /// `Docker-Content-Digest` header when present).
    pub digest: Digest,
}

/// Pull client for one repository on one registry.
///
/// Owns the per-pull token cache; nothing outlives the pull
/// (architecture §9: credentials are never persisted).
pub struct RegistryClient {
    http: reqwest::Client,
    /// Normalized registry name (for error messages), e.g. `docker.io`.
    registry: String,
    /// `scheme://api-host/v2` base.
    base_url: String,
    repository: String,
    scope: String,
    credentials: Option<RegistryAuth>,
    tokens: TokenCache,
    /// Set after a `Basic` challenge: send Basic credentials directly.
    use_basic: AtomicBool,
}

impl RegistryClient {
    /// Builds a client for the registry and repository of `reference`.
    pub fn for_reference(
        reference: &ImageReference,
        credentials: Option<RegistryAuth>,
    ) -> Result<Self, ImageError> {
        Self::build(reference, credentials, false)
    }

    /// Shared constructor: `push` selects the token scope.
    fn build(
        reference: &ImageReference,
        credentials: Option<RegistryAuth>,
        push: bool,
    ) -> Result<Self, ImageError> {
        let api_host = reference.api_host();
        let scheme = if is_loopback_host(api_host) {
            "http"
        } else {
            "https"
        };
        let http = reqwest::Client::builder()
            .user_agent(concat!("satl/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_mins(1))
            .build()
            .map_err(|source| ImageError::Http {
                registry: reference.registry.clone(),
                repository: reference.repository.clone(),
                context: "building HTTP client".to_owned(),
                source,
            })?;
        Ok(Self {
            http,
            registry: reference.registry.clone(),
            base_url: format!("{scheme}://{api_host}/v2"),
            repository: reference.repository.clone(),
            scope: if push {
                reference.push_scope()
            } else {
                reference.pull_scope()
            },
            credentials,
            tokens: TokenCache::default(),
            use_basic: AtomicBool::new(false),
        })
    }

    /// A client scoped for pushing to `reference`'s repository.
    pub fn for_push(
        reference: &ImageReference,
        credentials: Option<RegistryAuth>,
    ) -> Result<Self, ImageError> {
        Self::build(reference, credentials, true)
    }

    /// Fetches a manifest by tag or digest.
    ///
    /// Sends the combined OCI + Docker `Accept` header, reads the body and
    /// verifies its sha256 against the requested digest (when pulling by
    /// digest) and against the `Docker-Content-Digest` header when present.
    #[instrument(
        name = "image.manifest",
        skip(self),
        fields(registry = %self.registry, repository = %self.repository)
    )]
    pub async fn get_manifest(&self, manifest_ref: &str) -> Result<FetchedManifest, ImageError> {
        let url = format!(
            "{}/{}/manifests/{manifest_ref}",
            self.base_url, self.repository
        );
        // Load-bearing prefix: satl-agent's controller matches "GET manifest "
        // to classify the error as ManifestUnknown.
        let context = format!("GET manifest {manifest_ref}");
        let response = self
            .get_authorized(&url, Some(MANIFEST_ACCEPT), &context)
            .await?;
        let media_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let header_digest = response
            .headers()
            .get("docker-content-digest")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<Digest>().ok());
        let bytes = response
            .bytes()
            .await
            .map_err(|source| self.http_error(&context, source))?;

        let actual = Digest::sha256_of(&bytes);
        if let Ok(requested) = manifest_ref.parse::<Digest>()
            && requested != actual
        {
            return Err(self.digest_mismatch("manifest", &requested, &actual));
        }
        if let Some(expected) = header_digest
            && expected != actual
        {
            return Err(self.digest_mismatch(
                "manifest (Docker-Content-Digest)",
                &expected,
                &actual,
            ));
        }
        debug!(digest = %actual, media_type, size = bytes.len(), "manifest fetched");
        Ok(FetchedManifest {
            bytes: bytes.to_vec(),
            media_type,
            digest: actual,
        })
    }

    /// Downloads a blob: streams into `tmp_path`, verifies its sha256
    /// against `digest`, then atomically renames onto `final_path`.
    ///
    /// The whole download is retried up to 3 times on transient failures;
    /// the partial file is removed on any error.
    #[instrument(
        name = "image.blob",
        skip(self, tmp_path, final_path),
        fields(registry = %self.registry, repository = %self.repository)
    )]
    pub async fn get_blob(
        &self,
        digest: &Digest,
        tmp_path: &Path,
        final_path: &Path,
    ) -> Result<(), ImageError> {
        let mut attempt = 0;
        loop {
            match self.download_blob_once(digest, tmp_path, final_path).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    let _ = tokio::fs::remove_file(tmp_path).await;
                    attempt += 1;
                    if attempt >= MAX_ATTEMPTS || !is_transient_error(&error) {
                        return Err(error);
                    }
                    warn!(%digest, %error, attempt, "retrying blob download");
                    tokio::time::sleep(BACKOFF_BASE * 2_u32.pow(attempt - 1)).await;
                }
            }
        }
    }

    async fn download_blob_once(
        &self,
        digest: &Digest,
        tmp_path: &Path,
        final_path: &Path,
    ) -> Result<(), ImageError> {
        let url = format!("{}/{}/blobs/{digest}", self.base_url, self.repository);
        let context = format!("GET blob {digest}");
        let response = self.get_authorized(&url, None, &context).await?;

        let mut file = tokio::fs::File::create(tmp_path)
            .await
            .map_err(|source| ImageError::io(tmp_path, source))?;
        let mut hasher = Sha256::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|source| self.http_error(&context, source))?;
            hasher.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(|source| ImageError::io(tmp_path, source))?;
        }
        file.sync_all()
            .await
            .map_err(|source| ImageError::io(tmp_path, source))?;
        drop(file);

        let actual = Digest::from_sha256_hash(&hasher.finalize());
        if actual != *digest {
            return Err(self.digest_mismatch("blob", digest, &actual));
        }
        tokio::fs::rename(tmp_path, final_path)
            .await
            .map_err(|source| ImageError::io(final_path, source))?;
        debug!(%digest, path = %final_path.display(), "blob stored");
        Ok(())
    }

    /// Whether the registry already holds `digest` (a HEAD on the blob —
    /// the push path skips what is already there).
    pub async fn blob_exists(&self, digest: &Digest) -> Result<bool, ImageError> {
        let url = format!("{}/{}/blobs/{digest}", self.base_url, self.repository);
        let context = format!("HEAD blob {digest}");
        match self
            .send_authorized(reqwest::Method::HEAD, &url, None, None, None, &context)
            .await
        {
            Ok(_) => Ok(true),
            Err(ImageError::RegistryStatus { status: 404, .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Upload one blob: `POST` to open an upload session, then the monolithic
    /// `PUT` carrying the digest (OCI distribution spec, "pushing blobs").
    pub async fn push_blob(&self, digest: &Digest, bytes: Vec<u8>) -> Result<(), ImageError> {
        let open_url = format!("{}/{}/blobs/uploads/", self.base_url, self.repository);
        let context = format!("POST blob upload for {digest}");
        let response = self
            .send_authorized(reqwest::Method::POST, &open_url, None, None, None, &context)
            .await?;
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ImageError::MissingUploadLocation {
                registry: self.registry.clone(),
                repository: self.repository.clone(),
            })?;
        // The Location may be relative to the registry root.
        let upload_url = if location.starts_with("http") {
            location.to_owned()
        } else {
            format!(
                "{}/{}",
                self.base_url.trim_end_matches("/v2"),
                location.trim_start_matches('/')
            )
        };
        let separator = if upload_url.contains('?') { '&' } else { '?' };
        let put_url = format!("{upload_url}{separator}digest={digest}");
        let context = format!("PUT blob {digest} ({} bytes)", bytes.len());
        self.send_authorized(
            reqwest::Method::PUT,
            &put_url,
            None,
            None,
            Some(bytes),
            &context,
        )
        .await?;
        debug!(%digest, "blob pushed");
        Ok(())
    }

    /// Put a manifest under `manifest_ref` (a tag, normally).
    pub async fn put_manifest(
        &self,
        manifest_ref: &str,
        media_type: &str,
        bytes: Vec<u8>,
    ) -> Result<(), ImageError> {
        let url = format!(
            "{}/{}/manifests/{manifest_ref}",
            self.base_url, self.repository
        );
        let context = format!("PUT manifest {manifest_ref}");
        self.send_authorized(
            reqwest::Method::PUT,
            &url,
            None,
            Some((reqwest::header::CONTENT_TYPE, media_type)),
            Some(bytes),
            &context,
        )
        .await?;
        debug!(%manifest_ref, "manifest pushed");
        Ok(())
    }

    /// GET with token-auth handling and transient-failure retries.
    /// Flow: send (anonymous, cached token, or Basic) → on 401 parse the
    /// `WWW-Authenticate` challenge, obtain a bearer token (or switch to
    /// Basic) and retry once → on 5xx/connect errors retry with backoff.
    async fn get_authorized(
        &self,
        url: &str,
        accept: Option<&str>,
        context: &str,
    ) -> Result<Response, ImageError> {
        self.send_authorized(reqwest::Method::GET, url, accept, None, None, context)
            .await
    }

    /// The auth/retry core, generalized to writes for the push path (M8a):
    /// same challenge dance as [`get_authorized`], with an optional
    /// content-type header and body.
    async fn send_authorized(
        &self,
        method: reqwest::Method,
        url: &str,
        accept: Option<&str>,
        content_type: Option<(reqwest::header::HeaderName, &str)>,
        body: Option<Vec<u8>>,
        context: &str,
    ) -> Result<Response, ImageError> {
        let mut attempt = 0;
        let mut challenge_handled = false;
        loop {
            let mut request = self.http.request(method.clone(), url);
            if let Some(accept) = accept {
                request = request.header(ACCEPT, accept);
            }
            if let Some((name, value)) = &content_type {
                request = request.header(name.clone(), *value);
            }
            if let Some(body) = &body {
                request = request.body(body.clone());
            }
            if let Some(token) = self.tokens.get(&self.registry, &self.scope) {
                request = request.bearer_auth(token);
            } else if self.use_basic.load(Ordering::Relaxed)
                && let Some(auth) = &self.credentials
            {
                request = request.basic_auth(&auth.username, Some(&auth.password));
            }

            match request.send().await {
                Err(source) => {
                    attempt += 1;
                    if attempt >= MAX_ATTEMPTS || !is_transient_reqwest(&source) {
                        return Err(self.http_error(context, source));
                    }
                    warn!(url, %source, attempt, "retrying after connect error");
                    tokio::time::sleep(BACKOFF_BASE * 2_u32.pow(attempt - 1)).await;
                }
                Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                    let header = response
                        .headers()
                        .get(WWW_AUTHENTICATE)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned);
                    if challenge_handled {
                        return Err(ImageError::Unauthorized {
                            registry: self.registry.clone(),
                            repository: self.repository.clone(),
                            reason: "credentials rejected after auth challenge".to_owned(),
                            challenge: header,
                        });
                    }
                    self.handle_challenge(header.as_deref()).await?;
                    challenge_handled = true;
                }
                Ok(response)
                    if response.status().is_server_error() && attempt + 1 < MAX_ATTEMPTS =>
                {
                    attempt += 1;
                    warn!(url, status = %response.status(), attempt, "retrying after 5xx");
                    tokio::time::sleep(BACKOFF_BASE * 2_u32.pow(attempt - 1)).await;
                }
                Ok(response) if !response.status().is_success() => {
                    let status = response.status().as_u16();
                    let body = response.text().await.unwrap_or_default();
                    return Err(ImageError::RegistryStatus {
                        registry: self.registry.clone(),
                        repository: self.repository.clone(),
                        context: context.to_owned(),
                        status,
                        body: body.chars().take(300).collect(),
                    });
                }
                Ok(response) => return Ok(response),
            }
        }
    }

    /// Reacts to a 401: fetches a bearer token or enables Basic auth.
    async fn handle_challenge(&self, header: Option<&str>) -> Result<(), ImageError> {
        let unauthorized = |reason: &str| ImageError::Unauthorized {
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            reason: reason.to_owned(),
            challenge: header.map(str::to_owned),
        };
        let Some(challenge) = header.and_then(parse_www_authenticate) else {
            return Err(unauthorized(
                "registry sent 401 without a usable WWW-Authenticate challenge",
            ));
        };
        match challenge {
            AuthChallenge::Basic => {
                if self.credentials.is_none() {
                    return Err(unauthorized(
                        "registry requires Basic credentials and none were provided",
                    ));
                }
                self.use_basic.store(true, Ordering::Relaxed);
                Ok(())
            }
            AuthChallenge::Bearer(bearer) => {
                // The challenge's scope wins over our derived pull scope.
                let scope = bearer.scope.clone().unwrap_or_else(|| self.scope.clone());
                let token = self
                    .fetch_token(&bearer.realm, bearer.service.as_deref(), &scope)
                    .await?;
                self.tokens.put(&self.registry, &self.scope, token);
                Ok(())
            }
        }
    }

    /// `GET realm?service=...&scope=...`, with Basic credentials when the
    /// caller supplied any (that is how Docker Hub grants private pulls).
    async fn fetch_token(
        &self,
        realm: &str,
        service: Option<&str>,
        scope: &str,
    ) -> Result<String, ImageError> {
        let token_error = |reason: String| ImageError::TokenFetch {
            registry: self.registry.clone(),
            realm: realm.to_owned(),
            scope: scope.to_owned(),
            reason,
        };
        let mut query: Vec<(&str, &str)> = vec![("scope", scope)];
        if let Some(service) = service {
            query.push(("service", service));
        }
        let mut request = self.http.get(realm).query(&query);
        if let Some(auth) = &self.credentials {
            request = request.basic_auth(&auth.username, Some(&auth.password));
        }
        let response = request
            .send()
            .await
            .map_err(|source| token_error(source.to_string()))?;
        if !response.status().is_success() {
            return Err(token_error(format!("HTTP {}", response.status().as_u16())));
        }
        let token: TokenResponse = response
            .json()
            .await
            .map_err(|source| token_error(format!("invalid token response: {source}")))?;
        token
            .into_token()
            .ok_or_else(|| token_error("token response had no usable token".to_owned()))
    }

    fn http_error(&self, context: &str, source: reqwest::Error) -> ImageError {
        ImageError::Http {
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            context: context.to_owned(),
            source,
        }
    }

    fn digest_mismatch(&self, context: &str, expected: &Digest, actual: &Digest) -> ImageError {
        ImageError::DigestMismatch {
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            context: context.to_owned(),
            expected: expected.to_string(),
            actual: actual.to_string(),
        }
    }
}

/// Whether `host` (with optional port) is loopback — the only hosts we may
/// contact over plain HTTP.
fn is_loopback_host(host: &str) -> bool {
    let bare = host
        .rsplit_once(':')
        .map_or(host, |(front, _port)| front)
        .trim_start_matches('[')
        .trim_end_matches(']');
    bare == "localhost" || bare == "127.0.0.1" || bare == "::1"
}

/// Connect/timeout errors are worth retrying; protocol errors are not.
fn is_transient_reqwest(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_timeout() || error.is_request() || error.is_body()
}

/// Blob downloads retry on transport errors and 5xx, not on auth or digest
/// failures.
fn is_transient_error(error: &ImageError) -> bool {
    match error {
        ImageError::Http { source, .. } => is_transient_reqwest(source),
        ImageError::RegistryStatus { status, .. } => *status >= 500,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("localhost:5000"));
        assert!(is_loopback_host("127.0.0.1:5000"));
        assert!(is_loopback_host("[::1]:5000"));
        assert!(!is_loopback_host("ghcr.io"));
        assert!(!is_loopback_host("myhost:5000"));
        assert!(!is_loopback_host("10.0.0.1:5000"));
    }

    #[test]
    fn loopback_registries_use_http_others_https() {
        let local = ImageReference::parse("localhost:5000/x").unwrap();
        let client = RegistryClient::for_reference(&local, None).unwrap();
        assert_eq!(client.base_url, "http://localhost:5000/v2");

        let hub = ImageReference::parse("nginx").unwrap();
        let client = RegistryClient::for_reference(&hub, None).unwrap();
        assert_eq!(client.base_url, "https://registry-1.docker.io/v2");

        let ghcr = ImageReference::parse("ghcr.io/x/y").unwrap();
        let client = RegistryClient::for_reference(&ghcr, None).unwrap();
        assert_eq!(client.base_url, "https://ghcr.io/v2");
    }

    #[test]
    fn digest_verification_rejects_tampered_body() {
        // The verification path get_manifest/get_blob rely on: recompute
        // sha256 and compare. A tampered body must produce a mismatch.
        let expected = Digest::sha256_of(b"genuine manifest bytes");
        let tampered = Digest::sha256_of(b"tampered manifest bytes");
        assert_ne!(expected, tampered);

        let hub = ImageReference::parse("alpine").unwrap();
        let client = RegistryClient::for_reference(&hub, None).unwrap();
        let err = client.digest_mismatch("manifest", &expected, &tampered);
        let message = err.to_string();
        assert!(message.contains("docker.io"), "{message}");
        assert!(message.contains("library/alpine"), "{message}");
        assert!(message.contains(expected.as_str()), "{message}");
    }
}
