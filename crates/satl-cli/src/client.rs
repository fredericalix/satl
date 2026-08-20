// SPDX-License-Identifier: BSD-2-Clause
//! Minimal HTTP client speaking the Docker REST API over a unix socket.
//!
//! Deliberately lightweight: raw `tokio::net::UnixStream` +
//! `hyper::client::conn::http1` — no connection pooling, no TLS, no
//! heavyweight client stack. The CLI opens one connection per request; the
//! streaming and hijack helpers keep theirs open for the duration of the
//! stream.

use std::fmt;
use std::path::PathBuf;

use anyhow::Context as _;
use http_body_util::BodyExt as _;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::HeaderMap;
use hyper::{Method, StatusCode};
use hyper_util::rt::TokioIo;

/// Default daemon endpoint (architecture §15).
pub const DEFAULT_HOST: &str = "unix:///var/run/satl.sock";

/// Request body type used for every request (empty bodies are `Bytes::new()`).
type RequestBody = Full<Bytes>;

/// Parsed `--host` / `DOCKER_HOST` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// `unix://<path>` — the only scheme supported in M0/M1.
    Unix(PathBuf),
}

impl Host {
    /// Parse a docker-style host URL. Only `unix://` is supported in M0/M1
    /// (TCP+mTLS comes with the cluster milestones).
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        if let Some(path) = value.strip_prefix("unix://") {
            if path.is_empty() {
                anyhow::bail!("invalid host {value:?}: empty unix socket path");
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        anyhow::bail!("unsupported host {value:?}: only unix:// sockets are supported");
    }

    /// The docker-style URL form, for error messages.
    fn url(&self) -> String {
        match self {
            Self::Unix(path) => format!("unix://{}", path.display()),
        }
    }
}

/// A non-2xx reply from the daemon, carrying the Docker error envelope's
/// message. Rendered exactly like docker renders it; callers that need to
/// branch on the status (e.g. pull-on-404) downcast to this type.
#[derive(Debug)]
pub struct DaemonError {
    pub status: StatusCode,
    pub message: String,
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error response from daemon: {}", self.message)
    }
}

impl std::error::Error for DaemonError {}

/// Build the daemon error for a non-2xx response, extracting the Docker
/// error envelope (`{"message": "..."}`) when present.
pub fn daemon_error(status: StatusCode, body: &[u8]) -> anyhow::Error {
    #[derive(serde::Deserialize)]
    struct Envelope {
        message: String,
    }
    let message = serde_json::from_slice::<Envelope>(body).map_or_else(
        |_| String::from_utf8_lossy(body).trim().to_owned(),
        |envelope| envelope.message,
    );
    let message = if message.is_empty() {
        format!("unexpected status {status}")
    } else {
        message
    };
    anyhow::Error::new(DaemonError { status, message })
}

/// A completed HTTP response: status code, headers and raw body bytes.
///
/// The headers are here for the one thing Docker's response shapes have no
/// room for: `DELETE /images/{name}` answers a bare JSON array, so SatL's
/// deferred-layer count (api-compat 156) rides on `X-Satl-Deferred-Layers`.
#[derive(Debug)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl HttpResponse {
    /// Turn a non-2xx response into the docker-style daemon error.
    pub fn ensure_success(self) -> anyhow::Result<Self> {
        if self.status.is_success() {
            Ok(self)
        } else {
            Err(daemon_error(self.status, &self.body))
        }
    }
}

/// Connect to the daemon socket and complete the HTTP/1.1 handshake.
///
/// A refused/failed connection produces the docker-style operator message
/// (`Cannot connect to the SatL daemon at <host>. Is satld running?`). The
/// returned task drives the connection (with upgrade support, for hijack)
/// until it is dropped or completes.
async fn dial(
    host: &Host,
) -> anyhow::Result<(
    hyper::client::conn::http1::SendRequest<RequestBody>,
    tokio::task::JoinHandle<()>,
)> {
    let Host::Unix(socket_path) = host;
    let stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Cannot connect to the SatL daemon at {}. Is satld running?",
                host.url()
            )
        })?;

    let io = TokioIo::new(stream);
    let (sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP handshake with the daemon failed")?;
    // Drive the connection in the background while we await the response.
    // `with_upgrades` so the same path serves the exec hijack.
    let task = tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    Ok((sender, task))
}

fn build_request(
    method: &Method,
    path: &str,
    json: Option<Bytes>,
) -> anyhow::Result<hyper::Request<RequestBody>> {
    let mut builder = hyper::Request::builder()
        .method(method.clone())
        .uri(path)
        // Required by HTTP/1.1; the daemon ignores it on a unix socket.
        .header(hyper::header::HOST, "localhost");
    if json.is_some() {
        builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
    }
    builder
        .body(Full::new(json.unwrap_or_default()))
        .context("failed to build HTTP request")
}

/// Send `method path` and collect the whole response body.
pub async fn request(
    host: &Host,
    method: &Method,
    path: &str,
    json: Option<Bytes>,
) -> anyhow::Result<HttpResponse> {
    let (mut sender, connection_task) = dial(host).await?;
    let request = build_request(method, path, json)?;
    let response = sender
        .send_request(request)
        .await
        .with_context(|| format!("request {method} {path} to the daemon failed"))?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .with_context(|| format!("failed to read response body of {method} {path}"))?
        .to_bytes();

    drop(sender);
    connection_task.abort();

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn decode_json<T: serde::de::DeserializeOwned>(body: &[u8], path: &str) -> anyhow::Result<T> {
    serde_json::from_slice(body)
        .with_context(|| format!("failed to decode the daemon's response to {path}"))
}

fn encode_json<B: serde::Serialize>(body: &B) -> anyhow::Result<Bytes> {
    let raw = serde_json::to_vec(body).context("failed to encode request body as JSON")?;
    Ok(Bytes::from(raw))
}

/// `GET <path>` and decode the JSON body.
pub async fn get_json<T: serde::de::DeserializeOwned>(
    host: &Host,
    path: &str,
) -> anyhow::Result<T> {
    let response = request(host, &Method::GET, path, None)
        .await?
        .ensure_success()?;
    decode_json(&response.body, path)
}

/// `POST <path>` with an optional JSON body; decode the JSON response.
pub async fn post_json<T: serde::de::DeserializeOwned, B: serde::Serialize>(
    host: &Host,
    path: &str,
    body: Option<&B>,
) -> anyhow::Result<T> {
    let json = body.map(encode_json).transpose()?;
    let response = request(host, &Method::POST, path, json)
        .await?
        .ensure_success()?;
    decode_json(&response.body, path)
}

/// `POST <path>` with an optional JSON body; only check for success.
pub async fn post_ok<B: serde::Serialize>(
    host: &Host,
    path: &str,
    body: Option<&B>,
) -> anyhow::Result<()> {
    let json = body.map(encode_json).transpose()?;
    request(host, &Method::POST, path, json)
        .await?
        .ensure_success()?;
    Ok(())
}

/// `POST <path>` with no request body; decode the JSON response.
pub async fn post_empty_json<T: serde::de::DeserializeOwned>(
    host: &Host,
    path: &str,
) -> anyhow::Result<T> {
    post_json::<T, ()>(host, path, None).await
}

/// `POST <path>` with no request body; only check for success.
pub async fn post_empty_ok(host: &Host, path: &str) -> anyhow::Result<()> {
    post_ok::<()>(host, path, None).await
}

/// `DELETE <path>`; only check for success.
pub async fn delete_ok(host: &Host, path: &str) -> anyhow::Result<()> {
    request(host, &Method::DELETE, path, None)
        .await?
        .ensure_success()?;
    Ok(())
}

/// `DELETE <path>`; decode the JSON body and keep the response headers.
///
/// The headers matter for `DELETE /images/{name}`, whose body is Docker's bare
/// array with nowhere to carry SatL's deferred-layer count (api-compat 156).
pub async fn delete_json<T: serde::de::DeserializeOwned>(
    host: &Host,
    path: &str,
) -> anyhow::Result<(T, HeaderMap)> {
    let response = request(host, &Method::DELETE, path, None)
        .await?
        .ensure_success()?;
    let decoded = decode_json(&response.body, path)?;
    Ok((decoded, response.headers))
}

/// A streaming response body. Holds the connection task alive for the
/// lifetime of the stream; dropping the stream tears the connection down.
pub struct BodyStream {
    body: hyper::body::Incoming,
    connection_task: tokio::task::JoinHandle<()>,
}

impl BodyStream {
    /// Next chunk of body data, `None` at end of stream. Trailer frames are
    /// skipped.
    pub async fn next_chunk(&mut self) -> anyhow::Result<Option<Bytes>> {
        loop {
            match self.body.frame().await {
                None => return Ok(None),
                Some(Err(err)) => {
                    return Err(anyhow::Error::new(err).context("reading the daemon stream failed"));
                }
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        return Ok(Some(data));
                    }
                }
            }
        }
    }
}

impl Drop for BodyStream {
    fn drop(&mut self) {
        self.connection_task.abort();
    }
}

/// Send `method path` and return the response body as a stream (progress
/// lines, log follow). Non-2xx responses are collected and turned into the
/// docker-style daemon error.
pub async fn stream(
    host: &Host,
    method: &Method,
    path: &str,
    json: Option<Bytes>,
) -> anyhow::Result<BodyStream> {
    let (mut sender, connection_task) = dial(host).await?;
    let request = build_request(method, path, json)?;
    let response = sender
        .send_request(request)
        .await
        .with_context(|| format!("request {method} {path} to the daemon failed"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response
            .into_body()
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_default();
        connection_task.abort();
        return Err(daemon_error(status, &body));
    }
    // Keeping `sender` alive is not required to read the response body; the
    // connection task drives I/O until the stream ends or is dropped.
    drop(sender);
    Ok(BodyStream {
        body: response.into_body(),
        connection_task,
    })
}

/// Raw duplex stream obtained by hijacking the HTTP connection (exec).
pub type HijackedStream = TokioIo<hyper::upgrade::Upgraded>;

/// `POST <path>` with `Upgrade: tcp` and take over the connection after the
/// `101 Switching Protocols` response (Docker exec-start hijack).
pub async fn hijack<B: serde::Serialize>(
    host: &Host,
    path: &str,
    body: &B,
) -> anyhow::Result<HijackedStream> {
    let (mut sender, _connection_task) = dial(host).await?;
    let json = encode_json(body)?;
    let request = hyper::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(hyper::header::HOST, "localhost")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::UPGRADE, "tcp")
        .header(hyper::header::CONNECTION, "Upgrade")
        .body(Full::new(json))
        .context("failed to build HTTP request")?;
    let response = sender
        .send_request(request)
        .await
        .with_context(|| format!("request POST {path} to the daemon failed"))?;
    let status = response.status();
    if status != StatusCode::SWITCHING_PROTOCOLS {
        let body = response
            .into_body()
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_default();
        return Err(daemon_error(status, &body));
    }
    let upgraded = hyper::upgrade::on(response)
        .await
        .with_context(|| format!("connection hijack after POST {path} failed"))?;
    Ok(TokioIo::new(upgraded))
}

/// Encode query parameters: `&[("all", "true")]` → `?all=true`. Values are
/// percent-encoded (RFC 3986 unreserved characters pass through); keys are
/// trusted literals. Empty slice → empty string.
pub fn query(pairs: &[(&str, &str)]) -> String {
    if pairs.is_empty() {
        return String::new();
    }
    let mut out = String::from("?");
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(key);
        out.push('=');
        out.push_str(&percent_encode(value));
    }
    out
}

fn percent_encode(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unix_host() {
        assert_eq!(
            Host::parse("unix:///var/run/satl.sock").unwrap(),
            Host::Unix(PathBuf::from("/var/run/satl.sock"))
        );
    }

    #[test]
    fn rejects_tcp_host_for_now() {
        let err = Host::parse("tcp://10.2.0.5:2375").unwrap_err();
        assert!(err.to_string().contains("only unix://"), "{err}");
    }

    #[test]
    fn rejects_empty_unix_path() {
        assert!(Host::parse("unix://").is_err());
    }

    #[test]
    fn host_url_round_trips() {
        let host = Host::parse(DEFAULT_HOST).unwrap();
        assert_eq!(host.url(), DEFAULT_HOST);
    }

    #[test]
    fn daemon_error_uses_docker_message_format() {
        let err = daemon_error(
            StatusCode::NOT_FOUND,
            br#"{"message":"No such container: web"}"#,
        );
        assert_eq!(
            err.to_string(),
            "Error response from daemon: No such container: web"
        );
        let daemon = err.downcast_ref::<DaemonError>().unwrap();
        assert_eq!(daemon.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn daemon_error_falls_back_to_raw_body() {
        let err = daemon_error(StatusCode::INTERNAL_SERVER_ERROR, b"zfs clone failed\n");
        assert_eq!(
            err.to_string(),
            "Error response from daemon: zfs clone failed"
        );
    }

    #[test]
    fn daemon_error_with_empty_body_names_the_status() {
        let err = daemon_error(StatusCode::BAD_GATEWAY, b"");
        assert_eq!(
            err.to_string(),
            "Error response from daemon: unexpected status 502 Bad Gateway"
        );
    }

    #[test]
    fn query_encoding() {
        assert_eq!(query(&[]), "");
        assert_eq!(query(&[("all", "true")]), "?all=true");
        assert_eq!(
            query(&[("fromImage", "library/nginx"), ("tag", "1.25")]),
            "?fromImage=library%2Fnginx&tag=1.25"
        );
        assert_eq!(query(&[("signal", "SIGKILL")]), "?signal=SIGKILL");
        assert_eq!(query(&[("name", "a b+c")]), "?name=a%20b%2Bc");
    }
}
