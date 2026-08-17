// SPDX-License-Identifier: BSD-2-Clause
//! `satl version` — docker-style client/server version report.

use std::fmt::Write as _;

use serde::Deserialize;

use crate::client::{self, Host};

/// Docker Engine API version this client speaks.
pub const CLIENT_API_VERSION: &str = "1.43";

/// Client-side view of the daemon's `GET /version` response (Docker
/// `SystemVersion` shape). Lenient: unknown fields are ignored and missing
/// ones default to empty so older/newer daemons still render.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VersionResponse {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub api_version: String,
    #[serde(default, rename = "MinAPIVersion")]
    pub min_api_version: String,
    #[serde(default)]
    pub git_commit: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub kernel_version: String,
    #[serde(default)]
    pub build_time: String,
}

/// Render the `Client:` block (always printable, even with no daemon).
pub fn render_client(client_version: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Client:");
    let _ = writeln!(out, " {:<19}{}", "Version:", client_version);
    let _ = writeln!(out, " {:<19}{}", "API version:", CLIENT_API_VERSION);
    out
}

/// Render the `Server:` block from the daemon's response.
pub fn render_server(response: &VersionResponse) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Server:");
    let _ = writeln!(out, " Engine:");
    let _ = writeln!(out, "  {:<18}{}", "Version:", response.version);
    if response.min_api_version.is_empty() {
        let _ = writeln!(out, "  {:<18}{}", "API version:", response.api_version);
    } else {
        let _ = writeln!(
            out,
            "  {:<18}{} (minimum version {})",
            "API version:", response.api_version, response.min_api_version
        );
    }
    let _ = writeln!(out, "  {:<18}{}", "Git commit:", response.git_commit);
    let _ = writeln!(out, "  {:<18}{}", "Built:", response.build_time);
    let _ = writeln!(out, "  {:<18}{}/{}", "OS/Arch:", response.os, response.arch);
    let _ = writeln!(
        out,
        "  {:<18}{}",
        "Kernel Version:", response.kernel_version
    );
    out
}

/// Write to stdout, tolerating a closed pipe (`satl version | head` must not
/// panic; `print!` would).
fn emit(text: &str) {
    use std::io::Write as _;
    let _ = std::io::stdout().write_all(text.as_bytes());
}

/// Run `satl version`: print the client block, then query the daemon and
/// print the server block. Connection failure still shows the client block
/// (docker behavior) before the error propagates.
pub async fn run(host: &Host) -> anyhow::Result<()> {
    emit(&render_client(env!("CARGO_PKG_VERSION")));
    let response: VersionResponse = client::get_json(host, "/version").await?;
    emit("\n");
    emit(&render_server(&response));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VersionResponse {
        VersionResponse {
            version: "0.1.0".to_owned(),
            api_version: "1.43".to_owned(),
            min_api_version: "1.24".to_owned(),
            git_commit: "abc1234".to_owned(),
            os: "freebsd".to_owned(),
            arch: "amd64".to_owned(),
            kernel_version: "15.1-RELEASE-p2".to_owned(),
            build_time: "2026-08-09T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn client_block_layout() {
        assert_eq!(
            render_client("0.1.0"),
            "Client:\n Version:           0.1.0\n API version:       1.43\n"
        );
    }

    #[test]
    fn server_block_layout() {
        let expected = "\
Server:
 Engine:
  Version:          0.1.0
  API version:      1.43 (minimum version 1.24)
  Git commit:       abc1234
  Built:            2026-08-09T00:00:00Z
  OS/Arch:          freebsd/amd64
  Kernel Version:   15.1-RELEASE-p2
";
        assert_eq!(render_server(&sample()), expected);
    }

    #[test]
    fn server_block_without_min_api_version() {
        let response = VersionResponse {
            min_api_version: String::new(),
            ..sample()
        };
        let rendered = render_server(&response);
        assert!(
            rendered.contains("  API version:      1.43\n"),
            "{rendered}"
        );
        assert!(!rendered.contains("minimum version"), "{rendered}");
    }

    #[test]
    fn parses_daemon_version_json() {
        // Shape as served by satl-api's GET /version (Docker SystemVersion).
        let json = r#"{
            "Platform": {"Name": "SatL"},
            "Components": [{"Name": "Engine", "Version": "0.1.0", "Details": {}}],
            "Version": "0.1.0",
            "ApiVersion": "1.43",
            "MinAPIVersion": "1.24",
            "GitCommit": "abc1234",
            "Os": "freebsd",
            "Arch": "amd64",
            "KernelVersion": "15.1-RELEASE-p2",
            "BuildTime": "2026-08-09T00:00:00Z"
        }"#;
        let parsed: VersionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.version, "0.1.0");
        assert_eq!(parsed.api_version, "1.43");
        assert_eq!(parsed.min_api_version, "1.24");
        assert_eq!(parsed.kernel_version, "15.1-RELEASE-p2");
    }

    #[test]
    fn tolerates_missing_fields() {
        let parsed: VersionResponse = serde_json::from_str("{}").unwrap();
        assert!(parsed.version.is_empty());
        assert!(parsed.min_api_version.is_empty());
    }
}
