// SPDX-License-Identifier: BSD-2-Clause
//! Registry authentication: `WWW-Authenticate` challenge parsing, bearer
//! token acquisition, and an in-memory per-`(registry, scope)` token cache.
//!
//! Flow (OCI distribution spec / Docker registry v2 token auth):
//! anonymous request → `401` with a `Bearer` challenge → `GET
//! realm?service=...&scope=...` (with Basic credentials if the caller has
//! any) → retry the original request with the token. Registries that
//! challenge with `Basic` get the credentials directly.
//!
//! Decoding Docker's `X-Registry-Auth` header into [`RegistryAuth`] is the
//! REST API layer's job (`satl-api`); this crate only consumes the struct.

use std::collections::HashMap;
use std::sync::Mutex;

/// Registry credentials for one pull. Never persisted by the daemon
/// (architecture §9): they arrive per-request and die with the pull.
#[derive(Clone)]
pub struct RegistryAuth {
    /// Registry account name.
    pub username: String,
    /// Registry password or personal access token.
    pub password: String,
}

impl std::fmt::Debug for RegistryAuth {
    /// Redacts the password so credentials cannot leak into logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryAuth")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// A parsed `WWW-Authenticate` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthChallenge {
    /// Token-based auth (`Bearer realm=...,service=...,scope=...`).
    Bearer(BearerChallenge),
    /// Plain HTTP Basic auth.
    Basic,
}

/// Parameters of a `Bearer` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BearerChallenge {
    /// Token endpoint URL.
    pub realm: String,
    /// `service` parameter to forward to the token endpoint.
    pub service: Option<String>,
    /// `scope` parameter; when absent we fall back to the scope we derived
    /// from the repository (`repository:<name>:pull`).
    pub scope: Option<String>,
}

/// Parses a `WWW-Authenticate` header value.
///
/// Returns `None` for schemes we do not speak or a malformed `Bearer`
/// challenge (missing `realm`).
pub(crate) fn parse_www_authenticate(header: &str) -> Option<AuthChallenge> {
    let header = header.trim();
    let (scheme, params) = match header.split_once(char::is_whitespace) {
        Some((scheme, params)) => (scheme, params),
        None => (header, ""),
    };
    if scheme.eq_ignore_ascii_case("basic") {
        return Some(AuthChallenge::Basic);
    }
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for (key, value) in parse_auth_params(params) {
        match key.to_ascii_lowercase().as_str() {
            "realm" => realm = Some(value),
            "service" => service = Some(value),
            "scope" => scope = Some(value),
            _ => {}
        }
    }
    Some(AuthChallenge::Bearer(BearerChallenge {
        realm: realm?,
        service,
        scope,
    }))
}

/// Splits `key="value",key=value,...`, honouring commas inside quotes.
fn parse_auth_params(params: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut rest = params.trim();
    while !rest.is_empty() {
        let Some(eq) = rest.find('=') else { break };
        let key = rest[..eq].trim().to_owned();
        rest = &rest[eq + 1..];
        let value;
        if let Some(after_quote) = rest.strip_prefix('"') {
            let Some(close) = after_quote.find('"') else {
                // Unterminated quote: take everything.
                result.push((key, after_quote.to_owned()));
                break;
            };
            value = after_quote[..close].to_owned();
            rest = after_quote[close + 1..].trim_start();
            rest = rest.strip_prefix(',').unwrap_or(rest);
        } else if let Some(comma) = rest.find(',') {
            value = rest[..comma].trim().to_owned();
            rest = &rest[comma + 1..];
        } else {
            value = rest.trim().to_owned();
            rest = "";
        }
        rest = rest.trim_start();
        result.push((key, value));
    }
    result
}

/// Token endpoint response. Registries answer with `token`
/// (Docker Hub, ghcr.io) or `access_token` (OAuth2-flavoured registries);
/// accept both.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

impl TokenResponse {
    /// The usable token, whichever key it arrived under.
    pub(crate) fn into_token(self) -> Option<String> {
        self.token
            .filter(|t| !t.is_empty())
            .or(self.access_token.filter(|t| !t.is_empty()))
    }
}

/// In-memory bearer token cache, keyed by `(registry, scope)`.
///
/// Lives for the duration of one [`crate::client::RegistryClient`] (i.e. one
/// pull); nothing is persisted. A `std::sync::Mutex` is fine here: it is
/// never held across an `.await`.
#[derive(Default)]
pub(crate) struct TokenCache {
    tokens: Mutex<HashMap<(String, String), String>>,
}

impl TokenCache {
    pub(crate) fn get(&self, registry: &str, scope: &str) -> Option<String> {
        // Lock poisoning cannot happen: no panics occur while holding it.
        self.tokens
            .lock()
            .ok()?
            .get(&(registry.to_owned(), scope.to_owned()))
            .cloned()
    }

    pub(crate) fn put(&self, registry: &str, scope: &str, token: String) {
        if let Ok(mut map) = self.tokens.lock() {
            map.insert((registry.to_owned(), scope.to_owned()), token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_hub_challenge() {
        // Captured from registry-1.docker.io (2026-08-09).
        let header = "Bearer realm=\"https://auth.docker.io/token\",\
                      service=\"registry.docker.io\",\
                      scope=\"repository:library/alpine:pull\"";
        let AuthChallenge::Bearer(challenge) = parse_www_authenticate(header).unwrap() else {
            panic!("expected bearer challenge");
        };
        assert_eq!(challenge.realm, "https://auth.docker.io/token");
        assert_eq!(challenge.service.as_deref(), Some("registry.docker.io"));
        assert_eq!(
            challenge.scope.as_deref(),
            Some("repository:library/alpine:pull")
        );
    }

    #[test]
    fn parses_ghcr_challenge() {
        // Captured from ghcr.io (2026-08-09).
        let header = "Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\",\
                      scope=\"repository:user/image:pull\"";
        let AuthChallenge::Bearer(challenge) = parse_www_authenticate(header).unwrap() else {
            panic!("expected bearer challenge");
        };
        assert_eq!(challenge.realm, "https://ghcr.io/token");
        assert_eq!(challenge.service.as_deref(), Some("ghcr.io"));
    }

    #[test]
    fn parses_scope_with_comma_inside_quotes() {
        let header = "Bearer realm=\"https://r.example/token\",\
                      scope=\"repository:a/b:pull,push\",service=\"r.example\"";
        let AuthChallenge::Bearer(challenge) = parse_www_authenticate(header).unwrap() else {
            panic!("expected bearer challenge");
        };
        assert_eq!(challenge.scope.as_deref(), Some("repository:a/b:pull,push"));
        assert_eq!(challenge.service.as_deref(), Some("r.example"));
    }

    #[test]
    fn parses_unquoted_params() {
        let header = "Bearer realm=https://t.example/auth,service=t.example";
        let AuthChallenge::Bearer(challenge) = parse_www_authenticate(header).unwrap() else {
            panic!("expected bearer challenge");
        };
        assert_eq!(challenge.realm, "https://t.example/auth");
        assert_eq!(challenge.service.as_deref(), Some("t.example"));
        assert_eq!(challenge.scope, None);
    }

    #[test]
    fn parses_basic_challenge() {
        // registry:2 with htpasswd answers like this.
        assert_eq!(
            parse_www_authenticate("Basic realm=\"Registry Realm\""),
            Some(AuthChallenge::Basic)
        );
        assert_eq!(parse_www_authenticate("Basic"), Some(AuthChallenge::Basic));
    }

    #[test]
    fn rejects_malformed_challenges() {
        assert_eq!(parse_www_authenticate("Negotiate"), None);
        assert_eq!(
            parse_www_authenticate("Bearer service=\"x\""),
            None,
            "bearer without realm is unusable"
        );
        assert_eq!(parse_www_authenticate(""), None);
    }

    #[test]
    fn token_response_accepts_both_keys() {
        let t: TokenResponse = serde_json::from_str(r#"{"token":"abc"}"#).unwrap();
        assert_eq!(t.into_token().as_deref(), Some("abc"));
        let t: TokenResponse = serde_json::from_str(r#"{"access_token":"xyz"}"#).unwrap();
        assert_eq!(t.into_token().as_deref(), Some("xyz"));
        let t: TokenResponse =
            serde_json::from_str(r#"{"token":"","access_token":"fallback"}"#).unwrap();
        assert_eq!(t.into_token().as_deref(), Some("fallback"));
        let t: TokenResponse = serde_json::from_str("{}").unwrap();
        assert_eq!(t.into_token(), None);
    }

    #[test]
    fn token_cache_roundtrip() {
        let cache = TokenCache::default();
        assert_eq!(cache.get("r.example", "repository:a/b:pull"), None);
        cache.put("r.example", "repository:a/b:pull", "tok".to_owned());
        assert_eq!(
            cache.get("r.example", "repository:a/b:pull").as_deref(),
            Some("tok")
        );
        assert_eq!(
            cache.get("other.example", "repository:a/b:pull"),
            None,
            "cache is per registry"
        );
    }

    #[test]
    fn registry_auth_debug_redacts_password() {
        let auth = RegistryAuth {
            username: "user".to_owned(),
            password: "hunter2".to_owned(),
        };
        let debug = format!("{auth:?}");
        assert!(
            !debug.contains("hunter2"),
            "password must not leak: {debug}"
        );
    }
}
