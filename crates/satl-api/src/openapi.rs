// SPDX-License-Identifier: BSD-2-Clause
//! The `OpenAPI` 3.1 document for the Docker Engine REST API this crate serves.
//!
//! The document is not written by hand: [`crate::routes::api_router`]
//! registers every operation through `utoipa_axum::routes!`, which reads the
//! handler's own `#[utoipa::path]` for its method and path, so a route and its
//! documentation are one declaration. This module adds what a route cannot
//! carry -- the `info` block, the tag order, and the server list -- and the
//! three operations of the `/images/{name}/*` tail wildcard, which `OpenAPI` has
//! no way to express as a route.
//!
//! `docs/openapi.yaml` and `docs/openapi.js` are generated from
//! [`spec`] and committed. The tests below fail on drift; `make openapi`
//! rewrites them.

// The document is a build artifact, not a runtime feature: the daemon never
// reads it, only the generator tests below do. Allowing dead code in a
// *non-test* build is what lets `mod openapi;` sit beside the other private
// modules -- compiled, linted and rustdoc'd on every build -- instead of
// hiding the whole module behind `cfg(test)`. Under `cfg(test)` the lint is
// live, so genuinely unused code here is still caught.
#![cfg_attr(not(test), allow(dead_code))]

use utoipa::OpenApi as _;
use utoipa::openapi::{OpenApi, Server, ServerBuilder, ServerVariableBuilder};

use crate::middleware::{MAX_VERSION, MIN_VERSION};

/// Everything about the document that is not derived from a route.
///
/// `paths` here lists **only** the three operations behind the
/// `/images/{name}/*` tail wildcard (`crate::routes::images`): an image name
/// may carry slashes, so the family is registered as one `any` route and its
/// operations have to be declared by hand. Every other operation arrives via
/// `crate::routes::openapi`.
#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "SatL Engine API",
        description = "\
The Docker Engine REST API v1.43 as `satld` implements it -- the only external \
surface SatL has (invariant #8). Every intentional divergence from Docker \
carries a numbered entry in `docs/api-compat.md`, cited inline throughout this \
document.

The daemon listens on the unix socket `/var/run/satl.sock`. There is no TCP \
listener for this API: the cluster's own protocol (`satl.internal.v1`) is a \
separate, node-to-node-only surface on ports 2377 and 2378.

## Version prefixes

Every operation is reachable both on its bare path (`/info`) and under a \
Docker version prefix (`/v1.43/info`). Prefixes are accepted from 1.24 up to \
1.43; a prefix outside that range is a `400` in Docker's error shape, not a \
404. A leading segment that merely starts with `v` but is not \
`v<major>.<minor>` -- `/v1/info` -- is not version negotiation at all and \
routes (and 404s) as an ordinary path, where Docker would parse `1` as a \
version.

## Responses this document cannot attach to an operation

- **Unknown path**: `404` with the body `{\"message\": \"page not found\"}`. \
  Every Docker endpoint SatL does not implement answers this shape -- attach, \
  commit, export, rename, restart, pause, update, top, stats, changes, \
  archive, build, push, and the rest of the `/images/{name}/*` family \
  (api-compat #22, #144, #152).
- **Wrong method on a known path**: `405` with an **empty body**, where \
  Docker returns a JSON error body. This is a deviation, recorded in the \
  daemon-wide table of `docs/api-compat.md`.
- **Out-of-range version prefix**: `400` with Docker's error body, minted \
  before routing.

## Locked manager

A manager whose raft data encryption key is sealed (`swarm update \
--autolock=true`, api-compat #151) boots into a two-route API: `GET /_ping`, \
so a client can see the daemon is alive, and `POST /swarm/unlock`, the one way \
forward. **Every other operation in this document answers `503`** with a body \
naming that state until the unlock key is presented. Both routes behave \
exactly as documented here; the rest of the surface is simply absent.

## Error shape

Every non-2xx response body is Docker's `{\"message\": \"...\"}` envelope \
(`ErrorBody`). The mapping is fixed: `404` not found, `409` conflict, `400` \
invalid parameter, `501` not implemented, `503` unavailable (which includes \
\"this node is not a swarm manager\"), `500` internal.",
        version = crate::API_VERSION,
        license(name = "BSD-2-Clause")
    ),
    tags(
        (name = "Container", description = "Containers. A container **is** a Task of a Service (invariant #2), which is where most of the model deviations come from."),
        (name = "Image", description = "Images and layers. Node-local: an image lives on whichever node pulled it (api-compat #130)."),
        (name = "Network", description = "Cluster networks. `Scope` follows the driver: `overlay` is `swarm`, `bridge` is `local` (api-compat #60)."),
        (name = "Volume", description = "Node-local ZFS datasets (invariant #5); the `local` driver is the only one."),
        (name = "Exec", description = "Non-interactive exec: no TTY, stdin discarded (api-compat #17, #38)."),
        (name = "Swarm", description = "Cluster lifecycle. A SatL node bootstraps a single-node cluster at first boot, so these answer on a fresh daemon."),
        (name = "Node", description = "Cluster members: listing, inspection, promotion, demotion and removal."),
        (name = "Service", description = "Services: the orchestrated unit every container belongs to."),
        (name = "Task", description = "Tasks: immutable, one-shot, never moved and never re-executed (invariant #2)."),
        (name = "Secret", description = "Secrets. A payload never reaches a worker's disk and is never returned in a response (invariant #7)."),
        (name = "Config", description = "Configs: a secret without the secrecy -- the payload is returned on list and inspect."),
        (name = "System", description = "Daemon-level endpoints: ping, version, info and the event stream.")
    ),
    paths(
        crate::routes::images::tag,
        crate::routes::images::inspect,
        crate::routes::images::remove
    )
)]
pub(crate) struct ApiDoc;

/// The complete document: the route set, dressed with info, tags and servers.
pub(crate) fn spec() -> OpenApi {
    let mut doc = ApiDoc::openapi();
    doc.merge(crate::routes::openapi());
    doc.servers = Some(servers());
    doc
}

/// The two ways to address this API: bare paths, and any supported `/vX.Y/`
/// prefix.
///
/// The prefixed form is one server with a `version` variable rather than 64
/// duplicated operations, and its enum is generated from the range the
/// [`crate::middleware`] actually accepts -- widening that range updates this
/// document on the next `make openapi`.
fn servers() -> Vec<Server> {
    let (major, max_minor) = MAX_VERSION;
    let (min_major, min_minor) = MIN_VERSION;
    assert_eq!(
        major, min_major,
        "the version-prefix range spans two major versions; the server variable enum \
         below only walks the minor component"
    );
    let versions: Vec<String> = (min_minor..=max_minor)
        .map(|minor| format!("{major}.{minor}"))
        .collect();
    let default = format!("{major}.{max_minor}");
    vec![
        ServerBuilder::new()
            .url("/")
            .description(Some(
                "Bare paths, with no version negotiation. What the daemon serves on \
                 /var/run/satl.sock.",
            ))
            .build(),
        ServerBuilder::new()
            .url("/v{version}")
            .description(Some(
                "Docker version negotiation. Any prefix in the supported range routes \
                 exactly like the bare path; one outside it is a 400.",
            ))
            .parameter(
                "version",
                ServerVariableBuilder::new()
                    .enum_values(Some(versions))
                    .default_value(default)
                    .description(Some(
                        "Docker Engine API version. The range this daemon accepts.",
                    )),
            )
            .build(),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;
    use utoipa::openapi::path::{Operation, PathItem};

    use super::{MAX_VERSION, MIN_VERSION, spec};
    use crate::state::{ApiState, SystemInfo, VersionInfo};
    use crate::types::SwarmInfo;

    /// `docs/openapi.yaml`, relative to this crate.
    const YAML: &str = "../../docs/openapi.yaml";

    /// `docs/openapi.js`, relative to this crate. A `.js` rather than a second
    /// copy of the JSON because `docs/api.html` has to work from `file://`,
    /// where Chrome blocks `fetch`/XHR: a `spec-url` would spin forever
    /// offline, a `<script src>` will not.
    const JS: &str = "../../docs/openapi.js";

    fn repo_file(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
    }

    /// The YAML rendering, exactly as it is committed.
    fn render_yaml() -> String {
        spec().to_yaml().expect("the document renders as YAML")
    }

    /// The JavaScript rendering: the same document as a global, for
    /// `docs/api.html` to read without a network fetch.
    fn render_js() -> String {
        let json = spec()
            .to_pretty_json()
            .expect("the document renders as JSON");
        format!(
            "// SPDX-License-Identifier: BSD-2-Clause\n\
             // Generated by `make openapi` from crates/satl-api. Do not edit.\n\
             window.SATL_OPENAPI = {json};\n"
        )
    }

    /// Compares a rendering against its committed file, or rewrites it when
    /// `UPDATE_OPENAPI` is set.
    ///
    /// The environment gate is the whole point: a generator that rewrites the
    /// file it diffs is a gate that always passes.
    fn check(relative: &str, rendered: &str) {
        let path = repo_file(relative);
        if std::env::var_os("UPDATE_OPENAPI").is_some() {
            std::fs::write(&path, rendered)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
            return;
        }
        let on_disk = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        if on_disk == rendered {
            return;
        }
        let (line, was, now) = first_difference(&on_disk, rendered);
        panic!(
            "{} is out of date at line {line}:\n  committed: {was}\n  generated: {now}\n\
             run `make openapi`",
            path.display()
        );
    }

    /// The first differing line, so the failure names one line instead of
    /// dumping two nine-thousand-line files.
    fn first_difference(on_disk: &str, rendered: &str) -> (usize, String, String) {
        let mut committed = on_disk.lines();
        let mut generated = rendered.lines();
        let mut line = 0;
        loop {
            line += 1;
            match (committed.next(), generated.next()) {
                (None, None) => {
                    return (line, "<end of file>".to_owned(), "<end of file>".to_owned());
                }
                (was, now) if was != now => {
                    return (
                        line,
                        was.unwrap_or("<end of file>").to_owned(),
                        now.unwrap_or("<end of file>").to_owned(),
                    );
                }
                _ => {}
            }
        }
    }

    #[test]
    fn openapi_yaml_matches_the_code() {
        check(YAML, &render_yaml());
    }

    #[test]
    fn openapi_js_matches_the_code() {
        check(JS, &render_js());
    }

    /// utoipa models a path item as eight optional fields rather than a map;
    /// this is the missing iterator.
    fn item_operations(item: &PathItem) -> Vec<(&'static str, &Operation)> {
        [
            ("GET", item.get.as_ref()),
            ("PUT", item.put.as_ref()),
            ("POST", item.post.as_ref()),
            ("DELETE", item.delete.as_ref()),
            ("OPTIONS", item.options.as_ref()),
            ("HEAD", item.head.as_ref()),
            ("PATCH", item.patch.as_ref()),
            ("TRACE", item.trace.as_ref()),
        ]
        .into_iter()
        .filter_map(|(method, operation)| operation.map(|operation| (method, operation)))
        .collect()
    }

    /// Every `(method, path)` the document declares.
    fn operations() -> Vec<(&'static str, String)> {
        spec()
            .paths
            .paths
            .iter()
            .flat_map(|(path, item)| {
                item_operations(item)
                    .into_iter()
                    .map(|(method, _)| (method, path.clone()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn test_state() -> ApiState {
        ApiState::new(
            VersionInfo {
                version: "0.1.0".to_owned(),
                api_version: crate::API_VERSION.to_owned(),
                min_api_version: crate::MIN_API_VERSION.to_owned(),
                git_commit: "deadbeef".to_owned(),
                os: "freebsd".to_owned(),
                arch: "amd64".to_owned(),
                kernel_version: "15.1-RELEASE".to_owned(),
                build_time: "2026-08-09T00:00:00Z".to_owned(),
            },
            SystemInfo {
                id: "TEST:NODE:0001".to_owned(),
                name: "alpha".to_owned(),
                ncpu: 8,
                mem_total: 34_359_738_368,
                operating_system: "FreeBSD".to_owned(),
                os_version: "15.1-RELEASE".to_owned(),
                server_version: "0.1.0".to_owned(),
            },
            SwarmInfo {
                node_id: "1hvy0lj3x0b883f8e30fyp217".to_owned(),
                node_addr: String::new(),
                local_node_state: "active".to_owned(),
                control_available: true,
                error: String::new(),
                remote_managers: None,
            },
        )
    }

    /// The test that cannot be faked by editing the document: every documented
    /// operation is driven through the **real** router, whose backend is
    /// `UnwiredBackend` and answers 501 to everything, and must come back as
    /// something other than "no such route".
    ///
    /// The two shapes that mean "not routed" are the fallback's
    /// `404 {"message":"page not found"}` and axum's empty-body `405`. Any
    /// other answer -- 501, 400, 503, even a 404 with a different message --
    /// proves a handler ran. This is what covers the wildcard family, whose
    /// paths are declared by hand.
    #[tokio::test]
    async fn every_documented_operation_is_actually_routed() {
        for (method, path) in operations() {
            let uri = substitute(&path);
            let request = Request::builder()
                .method(method)
                .uri(&uri)
                .body(Body::empty())
                .expect("request");
            let response = crate::routes::router(test_state())
                .oneshot(request)
                .await
                .expect("response");
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            assert_ne!(
                status,
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {uri} is documented but no handler is registered for that method"
            );
            let text = String::from_utf8_lossy(&body);
            assert!(
                !(status == StatusCode::NOT_FOUND && text.contains("page not found")),
                "{method} {uri} is documented but falls through to the 404 fallback"
            );
        }
    }

    /// A concrete URI for a documented path template.
    fn substitute(path: &str) -> String {
        let mut out = String::with_capacity(path.len());
        let mut rest = path;
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let close = open
                + rest[open..]
                    .find('}')
                    .unwrap_or_else(|| panic!("unbalanced path template in {path}"));
            out.push('x');
            rest = &rest[close + 1..];
        }
        out.push_str(rest);
        out
    }

    /// Duplicate operation IDs make the document invalid and break every
    /// client generator -- and utoipa's default is the *function* name, of
    /// which this crate has eight `create` and seven `list`.
    #[test]
    fn operation_ids_are_unique_and_present() {
        let mut seen = BTreeSet::new();
        for (path, item) in &spec().paths.paths {
            for (method, operation) in item_operations(item) {
                let id = operation
                    .operation_id
                    .as_deref()
                    .unwrap_or_else(|| panic!("{method} {path} has no operationId"));
                assert!(
                    seen.insert(id.to_owned()),
                    "duplicate operationId {id:?} ({method} {path})"
                );
            }
        }
    }

    /// Every operation carries a tag, and every tag it carries is declared.
    #[test]
    fn every_operation_carries_a_declared_tag() {
        let doc = spec();
        let declared: BTreeSet<&str> = doc
            .tags
            .as_ref()
            .expect("tags are declared")
            .iter()
            .map(|tag| tag.name.as_str())
            .collect();
        for (path, item) in &doc.paths.paths {
            for (method, operation) in item_operations(item) {
                let tags = operation
                    .tags
                    .as_ref()
                    .unwrap_or_else(|| panic!("{method} {path} has no tag"));
                assert!(!tags.is_empty(), "{method} {path} has no tag");
                for tag in tags {
                    assert!(
                        declared.contains(tag.as_str()),
                        "{method} {path} carries undeclared tag {tag:?}"
                    );
                }
            }
        }
    }

    /// The `/vX.Y/` server variable covers exactly the range the middleware
    /// accepts.
    #[test]
    fn the_server_variable_covers_the_accepted_version_range() {
        let doc = spec();
        let servers = doc.servers.as_ref().expect("servers are declared");
        assert_eq!(servers.len(), 2, "bare paths and the version prefix");
        assert_eq!(servers[0].url, "/");
        assert_eq!(servers[1].url, "/v{version}");
        let variable = servers[1]
            .variables
            .as_ref()
            .expect("the prefix server has variables")
            .get("version")
            .expect("a `version` variable");
        let expected: Vec<String> = (MIN_VERSION.1..=MAX_VERSION.1)
            .map(|minor| format!("{}.{minor}", MAX_VERSION.0))
            .collect();
        assert_eq!(
            variable.enum_values.as_ref().expect("an enum"),
            &expected,
            "the server variable must list every accepted /vX.Y/ prefix"
        );
        assert_eq!(
            variable.default_value,
            format!("{}.{}", MAX_VERSION.0, MAX_VERSION.1)
        );
    }

    /// The two routes a locked manager serves (`crate::locked`) are both in
    /// the document: an operator reading it while locked out must find them.
    #[test]
    fn the_locked_manager_routes_are_a_subset_of_the_document() {
        let doc = spec();
        for (method, path) in [("GET", "/_ping"), ("POST", "/swarm/unlock")] {
            let item = doc
                .paths
                .paths
                .get(path)
                .unwrap_or_else(|| panic!("{path} is missing from the document"));
            assert!(
                item_operations(item)
                    .iter()
                    .any(|(declared, _)| *declared == method),
                "{method} {path} is missing from the document"
            );
        }
    }

    /// The document and the route table are one declaration, and this pins
    /// both directions of that claim.
    ///
    /// Forward: every `#[utoipa::path]` in the crate reaches the document --
    /// a handler annotated but never registered (in `routes!` or in `ApiDoc`'s
    /// `paths`) shows up as a count mismatch. Backward: nothing is in the
    /// document that is not annotated, because the annotation is the only
    /// source there is. The reachability test above then proves each one is
    /// routed.
    #[test]
    fn every_annotated_handler_reaches_the_document() {
        let annotated: usize = ROUTE_SOURCES
            .iter()
            .map(|(_, source)| source.matches("\n#[utoipa::path(").count())
            .sum();
        assert_eq!(
            annotated,
            operations().len(),
            "every #[utoipa::path] handler must be registered exactly once, through \
             routes!() or ApiDoc's paths(...)"
        );
    }

    /// `routes.rs` registers exactly one raw axum route: the
    /// `/images/{*rest}` tail wildcard, which `OpenAPI` cannot express. Every
    /// other route goes through `routes!`, which is what keeps the document
    /// honest -- so a reviewer greps `.route(` in that file and expects
    /// exactly one hit.
    #[test]
    fn routes_rs_registers_exactly_one_raw_route() {
        let source = include_str!("routes.rs");
        let raw: Vec<&str> = source
            .lines()
            .filter(|line| line.trim_start().starts_with(".route("))
            .collect();
        assert_eq!(raw.len(), 1, "unexpected raw axum routes: {raw:?}");
        assert!(
            raw[0].contains("/images/{*rest}"),
            "the one raw route must be the images tail wildcard, got {:?}",
            raw[0]
        );
    }

    /// Every source file that carries `#[utoipa::path]` attributes.
    const ROUTE_SOURCES: [(&str, &str); 14] = [
        ("routes.rs", include_str!("routes.rs")),
        ("configs.rs", include_str!("routes/configs.rs")),
        ("containers.rs", include_str!("routes/containers.rs")),
        ("events.rs", include_str!("routes/events.rs")),
        ("exec.rs", include_str!("routes/exec.rs")),
        ("images.rs", include_str!("routes/images.rs")),
        ("networks.rs", include_str!("routes/networks.rs")),
        ("nodes.rs", include_str!("routes/nodes.rs")),
        ("prune.rs", include_str!("routes/prune.rs")),
        ("secrets.rs", include_str!("routes/secrets.rs")),
        ("services.rs", include_str!("routes/services.rs")),
        ("swarm.rs", include_str!("routes/swarm.rs")),
        ("tasks.rs", include_str!("routes/tasks.rs")),
        ("volumes.rs", include_str!("routes/volumes.rs")),
    ];

    /// Every `param(&params, "x")` and `flag(&params, "x")` a handler reads
    /// must be declared in that handler's `#[utoipa::path]`.
    ///
    /// Each module is split on `#[utoipa::path(` boundaries, so a chunk is one
    /// operation plus whatever private helpers follow it; a literal read by a
    /// helper counts against the operation that owns it, which is exactly
    /// right -- `prune::volumes` really does read `filters`, through
    /// `reject_filters`.
    ///
    /// `routes.rs` is the one file this cannot read that way: the shared
    /// `flag`/`param`/`reject_filters` helpers sit below its last handler, so
    /// their own literals would be attributed to `info`. Its four system
    /// handlers take no query parameters at all -- none of them even has a
    /// `Query` extractor -- so nothing is lost by skipping it.
    #[test]
    fn every_query_parameter_a_handler_reads_is_declared() {
        for (name, source) in ROUTE_SOURCES
            .into_iter()
            .filter(|(name, _)| *name != "routes.rs")
        {
            for chunk in source.split("\n#[utoipa::path(").skip(1) {
                for key in read_query_keys(chunk) {
                    assert!(
                        chunk.contains(&format!("(\"{key}\" = Option<String>, Query")),
                        "{name}: a handler reads the query parameter {key:?} but does not \
                         declare it in its #[utoipa::path]"
                    );
                }
            }
        }
    }

    /// The `"x"` of every `param(.., "x")` / `flag(.., "x")` call in `chunk`.
    fn read_query_keys(chunk: &str) -> BTreeSet<&str> {
        let mut keys = BTreeSet::new();
        for call in [
            "param(&params, \"",
            "flag(&params, \"",
            "param(params, \"",
            "flag(params, \"",
        ] {
            let mut rest = chunk;
            while let Some(at) = rest.find(call) {
                let tail = &rest[at + call.len()..];
                if let Some(end) = tail.find('"') {
                    keys.insert(&tail[..end]);
                }
                rest = tail;
            }
        }
        keys
    }
}
