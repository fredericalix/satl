// SPDX-License-Identifier: BSD-2-Clause
//! `satl inspect` — the daemon's raw inspect JSON, pretty-printed.
//!
//! Docker prints the API response verbatim inside a JSON array, indented with
//! four spaces; tooling parses it, so nothing is reshaped here.

use crate::client::{self, Host};
use crate::cmd::FAILURE;
use crate::output::Streams;

/// Flags of `satl inspect`.
#[derive(Debug, Clone, clap::Args)]
pub struct InspectArgs {
    /// Containers to inspect.
    #[arg(required = true, value_name = "CONTAINER")]
    pub containers: Vec<String>,
}

/// Inspect every reference; missing ones are reported on stderr and make the
/// command exit 1, but the ones that were found are still printed.
pub async fn execute(host: &Host, args: &InspectArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut found: Vec<serde_json::Value> = Vec::new();
    let mut failed = false;
    for container in &args.containers {
        let path = format!("/containers/{container}/json");
        match client::get_json::<serde_json::Value>(host, &path).await {
            Ok(value) => found.push(value),
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    streams.outln(&render(&found)).await;
    Ok(if failed { FAILURE } else { 0 })
}

/// Docker's `json.MarshalIndent(v, "", "    ")` over the array of bodies.
pub fn render(values: &[serde_json::Value]) -> String {
    let mut buffer = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut buffer, formatter);
    if serde::Serialize::serialize(&values, &mut serializer).is_err() {
        // Values came from `serde_json`, so re-serializing them cannot fail;
        // fall back to the compact form rather than losing the output.
        return serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_owned());
    }
    String::from_utf8(buffer).unwrap_or_else(|_| "[]".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_result_is_an_empty_array() {
        assert_eq!(render(&[]), "[]");
    }

    /// Field *order* is `serde_json`'s (alphabetical) rather than the daemon's:
    /// `satl` does not pull in the `preserve_order` feature. Values, types
    /// and nesting are untouched, which is what tooling parses.
    #[test]
    fn bodies_are_printed_verbatim_with_four_space_indent() {
        let value: serde_json::Value = serde_json::from_str(
            r#"{"Id":"abc","State":{"Running":true},"Platform":"freebsd/amd64"}"#,
        )
        .unwrap();
        let expected = "\
[
    {
        \"Id\": \"abc\",
        \"Platform\": \"freebsd/amd64\",
        \"State\": {
            \"Running\": true
        }
    }
]";
        assert_eq!(render(&[value]), expected);
    }

    #[tokio::test]
    async fn prints_the_found_bodies_and_reports_the_missing_ones() {
        use crate::output::testing;
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/containers/web/json",
            Reply::json(200, r#"{"Id":"abc","Platform":"freebsd/amd64"}"#),
        )
        .on(
            "GET",
            "/containers/gone/json",
            Reply::json(404, r#"{"message":"No such container: gone"}"#),
        );

        let (mut streams, out, err) = testing::streams();
        let args = InspectArgs {
            containers: vec!["web".to_owned(), "gone".to_owned()],
        };
        let code = execute(&stub.host(), &args, &mut streams).await.unwrap();

        assert_eq!(code, FAILURE);
        assert_eq!(
            err.contents(),
            "Error response from daemon: No such container: gone\n"
        );
        assert_eq!(
            out.contents(),
            "[\n    {\n        \"Id\": \"abc\",\n        \"Platform\": \"freebsd/amd64\"\n    }\n]\n"
        );
    }
}
