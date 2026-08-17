// SPDX-License-Identifier: BSD-2-Clause
//! Docker-compatibility tests for the router: the M0 system endpoints
//! (`/_ping`, `/version`, `/info`, version negotiation, error shapes) and the
//! M1 container/image/exec/volume/event endpoints, driven through a
//! [`MockBackend`] that records every call and returns canned answers.

mod mock;

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use base64::Engine as _;
use http::{Request, Response, StatusCode};
use mock::{Call, MockBackend};
use satl_api::model::{
    BackendError, ChangeOutcome, ConfigCreated, ContainerConfig, ContainerInspect,
    ContainerRuntimeState, ContainerSummary, Counts, CreatedContainer, EventActor, EventMessage,
    ExecInspect, ExposedPort, HostConfig, ImageSummary, LocalNodeState, LogFrame, LogStream,
    ManagerPeer, NetworkConnectOptions, NetworkCreated, NetworkDetail, NetworkDisconnectOptions,
    NetworkEndpointInfo, NetworkSettings, NetworkSummary, NodeDetail, NodeSummary, PortMapping,
    ProgressDetail, PullProgressLine, SecretCreated, ServiceCreated, ServiceDetail, ServiceSummary,
    ServiceTaskCounts, SwarmDetail, SwarmStatus, TaskDetail, TaskFilters, TaskSummary, TokenRole,
    VolumeInfo, WaitCondition, WaitResult,
};
use satl_api::{ApiState, router};
use satl_core::{
    Annotations, Availability, ClusterSpec, Config, ConfigSpec, ContainerSpec, DesiredState,
    EngineDescription, Id, IpamConfig, JoinTokens, ManagerStatus, Meta, Mount, MountType, Network,
    NetworkDriver, NetworkSpec, Node, NodeDescription, NodeRole, NodeSpec, NodeState, NodeStatus,
    Placement, Platform, PortConfig, PortProtocol, PublishMode, Reachability, Resources,
    RestartCondition, RestartPolicy, Secret, SecretSpec, Service, ServiceMode, ServiceSpec, Task,
    TaskSpec, TaskState, TaskStatus, Version,
};
use serde_json::Value;
use tower::ServiceExt;

/// The M0 daemon facts, shared with the mock-backed tests (`mock::test_state`
/// is the single definition; the M0 tests below still see an unwired
/// backend, exactly as `satld` builds it before wiring).
use mock::test_state;

async fn send(method: &str, path: &str) -> Response<Body> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    router(test_state()).oneshot(request).await.unwrap()
}

async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec()
}

async fn body_json(response: Response<Body>) -> Value {
    serde_json::from_slice(&body_bytes(response).await).unwrap()
}

fn assert_ping_headers(response: &Response<Body>) {
    let headers = response.headers();
    assert_eq!(headers.get("Api-Version").unwrap(), "1.43");
    assert_eq!(headers.get("Ostype").unwrap(), "freebsd");
    assert_eq!(headers.get("Docker-Experimental").unwrap(), "false");
    assert_eq!(
        headers.get("Cache-Control").unwrap(),
        "no-cache, no-store, must-revalidate"
    );
    assert_eq!(headers.get("Pragma").unwrap(), "no-cache");
    assert_eq!(headers.get("Server").unwrap(), "SatL/0.1.0");
}

#[tokio::test]
async fn ping_get_returns_ok_with_negotiation_headers() {
    let response = send("GET", "/_ping").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_ping_headers(&response);
    assert!(
        response
            .headers()
            .get("Content-Type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    assert_eq!(body_bytes(response).await, b"OK");
}

#[tokio::test]
async fn ping_head_returns_empty_body_with_same_headers() {
    let response = send("HEAD", "/_ping").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_ping_headers(&response);
    assert!(body_bytes(response).await.is_empty());
}

#[tokio::test]
async fn version_matches_docker_pascal_case_shape() {
    let response = send("GET", "/version").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("Content-Type").unwrap(),
        "application/json"
    );
    let json = body_json(response).await;

    assert_eq!(json["Platform"]["Name"], "SatL");
    assert_eq!(json["Version"], "0.1.0");
    assert_eq!(json["ApiVersion"], "1.43");
    assert_eq!(json["MinAPIVersion"], "1.24");
    assert_eq!(json["GitCommit"], "deadbeef");
    assert_eq!(json["Os"], "freebsd");
    assert_eq!(json["Arch"], "amd64");
    assert_eq!(json["KernelVersion"], "15.1-RELEASE");
    assert_eq!(json["BuildTime"], "2026-08-09T00:00:00Z");

    let engine = &json["Components"][0];
    assert_eq!(engine["Name"], "Engine");
    assert_eq!(engine["Version"], "0.1.0");
    let details = engine["Details"].as_object().unwrap();
    for key in [
        "ApiVersion",
        "Arch",
        "BuildTime",
        "GitCommit",
        "KernelVersion",
        "MinAPIVersion",
        "Os",
    ] {
        assert!(details.contains_key(key), "Details missing key {key}");
    }
    assert_eq!(details["Os"], "freebsd");

    // Exact key spellings at the top level (PascalCase incl. Docker's
    // irregular MinAPIVersion) — no snake_case leakage.
    let top = json.as_object().unwrap();
    for key in [
        "Platform",
        "Components",
        "Version",
        "ApiVersion",
        "MinAPIVersion",
        "GitCommit",
        "Os",
        "Arch",
        "KernelVersion",
        "BuildTime",
    ] {
        assert!(top.contains_key(key), "missing top-level key {key}");
    }
    assert_eq!(top.len(), 10, "unexpected extra top-level keys: {top:?}");
}

#[tokio::test]
async fn info_has_minimal_v143_shape() {
    let response = send("GET", "/info").await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;

    assert_eq!(json["ID"], "TEST:NODE:0001");
    assert_eq!(json["Name"], "alpha");
    assert_eq!(json["NCPU"], 8);
    assert_eq!(json["MemTotal"], 34_359_738_368_i64);
    assert_eq!(json["OperatingSystem"], "FreeBSD");
    assert_eq!(json["OSVersion"], "15.1-RELEASE");
    assert_eq!(json["OSType"], "freebsd");
    assert_eq!(json["Architecture"], "amd64");
    assert_eq!(json["ServerVersion"], "0.1.0");
    assert_eq!(json["Driver"], "zfs");
    for key in [
        "Containers",
        "ContainersRunning",
        "ContainersPaused",
        "ContainersStopped",
        "Images",
    ] {
        assert_eq!(json[key], 0, "{key} must be 0 in M0");
    }
    // The Swarm section reflects whatever the daemon injected (here: the
    // active single-node cluster identity from test_state).
    assert_eq!(json["Swarm"]["NodeID"], "1hvy0lj3x0b883f8e30fyp217");
    assert_eq!(json["Swarm"]["NodeAddr"], "");
    assert_eq!(json["Swarm"]["LocalNodeState"], "active");
    assert_eq!(json["Swarm"]["ControlAvailable"], true);
    assert_eq!(json["Swarm"]["Error"], "");
    assert!(json["Swarm"]["RemoteManagers"].is_null());
    assert_eq!(json["Warnings"], serde_json::json!([]));
}

#[tokio::test]
async fn versioned_paths_are_equivalent_to_bare_paths() {
    let bare = body_bytes(send("GET", "/version").await).await;
    let versioned = send("GET", "/v1.43/version").await;
    assert_eq!(versioned.status(), StatusCode::OK);
    assert_eq!(body_bytes(versioned).await, bare);

    // Whole supported range, boundaries included.
    for path in ["/v1.24/_ping", "/v1.30/_ping", "/v1.43/_ping"] {
        let response = send("GET", path).await;
        assert_eq!(response.status(), StatusCode::OK, "{path} must be accepted");
        assert_ping_headers(&response);
        assert_eq!(body_bytes(response).await, b"OK");
    }

    let info = send("GET", "/v1.43/info").await;
    assert_eq!(info.status(), StatusCode::OK);
}

#[tokio::test]
async fn too_new_api_version_is_rejected_with_docker_error() {
    for (path, version) in [("/v1.44/version", "1.44"), ("/v2.0/_ping", "2.0")] {
        let response = send("GET", path).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "for {path}");
        assert_eq!(response.headers().get("Server").unwrap(), "SatL/0.1.0");
        let json = body_json(response).await;
        assert_eq!(
            json["message"],
            format!(
                "client version {version} is too new. \
                 Maximum supported API version is 1.43"
            )
        );
    }
}

#[tokio::test]
async fn too_old_api_version_is_rejected_with_docker_error() {
    for (path, version) in [("/v1.23/version", "1.23"), ("/v0.9/info", "0.9")] {
        let response = send("GET", path).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "for {path}");
        let json = body_json(response).await;
        assert_eq!(
            json["message"],
            format!(
                "client version {version} is too old. \
                 Minimum supported API version is 1.24"
            )
        );
    }
}

#[tokio::test]
async fn unknown_routes_return_docker_404_shape() {
    // `/build` is a real Docker path SatL does not serve (no builder); the
    // others are simply unknown.
    for path in ["/nope", "/v1.43/nope", "/build"] {
        let response = send("GET", path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "for {path}");
        assert_eq!(response.headers().get("Server").unwrap(), "SatL/0.1.0");
        let json = body_json(response).await;
        assert_eq!(json["message"], "page not found");
    }
}

#[tokio::test]
async fn non_version_v_prefix_is_not_negotiated() {
    // A leading segment that merely starts with "v" is not an API version:
    // it routes normally and 404s instead of being negotiated.
    for path in ["/vfoo/version", "/v1x2/_ping", "/v1/_ping"] {
        let response = send("GET", path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "for {path}");
        let json = body_json(response).await;
        assert_eq!(json["message"], "page not found");
    }
}

// ---------------------------------------------------------------------------
// M1 — helpers and fixtures
// ---------------------------------------------------------------------------

/// An instant far enough in the past that `Status` strings are stable.
fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// Sends a request built by the caller against a mock-backed router.
async fn send_to(state: &ApiState, request: Request<Body>) -> Response<Body> {
    router(state.clone())
        .oneshot(request)
        .await
        .expect("the router is infallible")
}

/// `method path` with an optional JSON body.
async fn send_json(
    state: &ApiState,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Response<Body> {
    let builder = Request::builder().method(method).uri(path);
    let request = match body {
        None => builder.body(Body::empty()),
        Some(json) => builder
            .header("Content-Type", "application/json")
            .body(Body::from(json.to_string())),
    }
    .expect("valid request");
    send_to(state, request).await
}

/// A container summary with every field the CLI renders.
fn sample_summary() -> ContainerSummary {
    ContainerSummary {
        id: "1hvy0lj3x0b883f8e30fyp217".to_owned(),
        name: "web".to_owned(),
        image: "registry.example.com/nginx:1.27".to_owned(),
        image_id: "sha256:c0ffee".to_owned(),
        command: vec![
            "nginx".to_owned(),
            "-g".to_owned(),
            "daemon off;".to_owned(),
        ],
        created: at(1_770_000_000),
        state: ContainerRuntimeState {
            task_state: TaskState::Running,
            desired_state: DesiredState::Running,
            started_at: Some(at(1_770_000_000)),
            pid: Some(4242),
            ..ContainerRuntimeState::default()
        },
        ports: vec![PortMapping {
            host_ip: None,
            host_port: 8080,
            container_port: 80,
            protocol: PortProtocol::Tcp,
        }],
        labels: BTreeMap::from([("tier".to_owned(), "web".to_owned())]),
        mounts: vec![Mount {
            kind: MountType::Bind,
            source: Some("/host/data".to_owned()),
            target: "/data".to_owned(),
            read_only: true,
        }],
        network_name: "bridge".to_owned(),
        ip_address: Some("10.88.0.5".to_owned()),
        platform: Some(Platform {
            os: "freebsd".to_owned(),
            arch: "amd64".to_owned(),
        }),
    }
}

/// A full inspect document.
fn sample_inspect() -> ContainerInspect {
    ContainerInspect {
        id: "1hvy0lj3x0b883f8e30fyp217".to_owned(),
        name: "web".to_owned(),
        created: at(1_770_000_000),
        image: "registry.example.com/nginx:1.27".to_owned(),
        image_id: "sha256:c0ffee".to_owned(),
        path: "nginx".to_owned(),
        args: vec!["-g".to_owned(), "daemon off;".to_owned()],
        state: ContainerRuntimeState {
            task_state: TaskState::Failed,
            desired_state: DesiredState::Running,
            exit_code: Some(137),
            error: Some("killed by the restart supervisor".to_owned()),
            started_at: Some(at(1_770_000_000)),
            finished_at: Some(at(1_770_000_060)),
            pid: None,
            health: None,
        },
        config: ContainerConfig {
            hostname: Some("web-1".to_owned()),
            user: Some("www".to_owned()),
            env: vec!["RUST_LOG=info".to_owned()],
            cmd: vec!["-g".to_owned(), "daemon off;".to_owned()],
            entrypoint: vec!["nginx".to_owned()],
            working_dir: Some("/srv".to_owned()),
            labels: BTreeMap::from([("tier".to_owned(), "web".to_owned())]),
            tty: false,
            open_stdin: false,
            image: "registry.example.com/nginx:1.27".to_owned(),
            exposed_ports: vec![ExposedPort {
                port: 80,
                protocol: PortProtocol::Tcp,
            }],
        },
        host_config: HostConfig {
            binds: vec!["/host/data:/data:ro".to_owned()],
            tmpfs: BTreeMap::from([("/run".to_owned(), "rw,size=64m".to_owned())]),
            port_bindings: vec![PortMapping {
                host_ip: Some("127.0.0.1".to_owned()),
                host_port: 8080,
                container_port: 80,
                protocol: PortProtocol::Tcp,
            }],
            memory: 536_870_912,
            nano_cpus: 1_500_000_000,
            restart_policy: RestartPolicy {
                condition: RestartCondition::OnFailure,
                max_attempts: 3,
                ..RestartPolicy::default()
            },
            auto_remove: false,
            network_mode: "bridge".to_owned(),
        },
        network: NetworkSettings {
            network_name: "bridge".to_owned(),
            network_id: Some("net-1".to_owned()),
            ip_address: Some("10.88.0.5".to_owned()),
            ip_prefix_len: 24,
            gateway: Some("10.88.0.1".to_owned()),
            mac_address: Some("02:ff:60:00:00:05".to_owned()),
            ports: vec![PortMapping {
                host_ip: Some("127.0.0.1".to_owned()),
                host_port: 8080,
                container_port: 80,
                protocol: PortProtocol::Tcp,
            }],
        },
        mounts: vec![Mount {
            kind: MountType::Bind,
            source: Some("/host/data".to_owned()),
            target: "/data".to_owned(),
            read_only: true,
        }],
        platform: Some(Platform {
            os: "freebsd".to_owned(),
            arch: "amd64".to_owned(),
        }),
        jail_id: Some("1hvy0lj3x0b883f8e30fyp217".to_owned()),
        restart_count: 2,
    }
}

// ---------------------------------------------------------------------------
// M1 — containers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_container_returns_201_and_records_converted_options() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.created = CreatedContainer {
                id: "1hvy0lj3x0b883f8e30fyp217".to_owned(),
                warnings: vec!["rctl is disabled: --memory will not be enforced".to_owned()],
            };
        })
        .into_state();

    let response = send_json(
        &state,
        "POST",
        "/v1.43/containers/create?name=web&platform=freebsd%2Famd64",
        Some(serde_json::json!({
            "Image": "nginx:1.27",
            "Cmd": ["nginx", "-g", "daemon off;"],
            "Env": ["A=1"],
            "Labels": {"tier": "web"},
            "ExposedPorts": {"80/tcp": {}},
            "HostConfig": {
                "Binds": ["/host/data:/data:ro"],
                "PortBindings": {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]},
                "Memory": 536_870_912_i64,
                "NanoCpus": 1_500_000_000_i64,
                "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3}
            }
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    assert_eq!(json["Id"], "1hvy0lj3x0b883f8e30fyp217");
    assert_eq!(
        json["Warnings"][0],
        "rctl is disabled: --memory will not be enforced"
    );
    assert_eq!(json.as_object().expect("object").len(), 2);

    let Call::CreateContainer(options) = recorder.only_call() else {
        panic!("expected a create_container call");
    };
    assert_eq!(options.name.as_deref(), Some("web"));
    assert_eq!(options.image, "nginx:1.27");
    assert_eq!(options.cmd, ["nginx", "-g", "daemon off;"]);
    assert_eq!(options.env, ["A=1"]);
    assert_eq!(options.memory, Some(536_870_912));
    assert_eq!(options.nano_cpus, Some(1_500_000_000));
    assert_eq!(
        options.restart_policy.condition,
        RestartCondition::OnFailure
    );
    assert_eq!(
        options.platform,
        Some(Platform {
            os: "freebsd".to_owned(),
            arch: "amd64".to_owned()
        })
    );
    assert_eq!(options.binds.len(), 1);
    assert_eq!(options.port_bindings[0].host_port, 8080);
}

#[tokio::test]
async fn create_container_rejects_bad_input_with_docker_error_shape() {
    let cases: [(&str, Value, &str); 4] = [
        (
            "/containers/create",
            serde_json::json!({}),
            "no image specified",
        ),
        (
            "/containers/create",
            serde_json::json!({"Image": "n", "HostConfig": {"Binds": ["nope"]}}),
            "invalid bind mount",
        ),
        (
            "/containers/create?name=my.app",
            serde_json::json!({"Image": "n"}),
            "invalid container name",
        ),
        (
            "/containers/create?platform=freebsd",
            serde_json::json!({"Image": "n"}),
            "invalid platform",
        ),
    ];
    for (path, body, expected) in cases {
        let (state, recorder) = MockBackend::new().into_state();
        let response = send_json(&state, "POST", path, Some(body)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "for {path}");
        let json = body_json(response).await;
        let message = json["message"].as_str().expect("Docker error envelope");
        assert!(message.contains(expected), "for {path}: got {message:?}");
        assert!(
            recorder.calls().is_empty(),
            "a rejected request must not reach the backend"
        );
    }
}

#[tokio::test]
async fn create_container_rejects_malformed_json() {
    let (state, _) = MockBackend::new().into_state();
    let request = Request::builder()
        .method("POST")
        .uri("/containers/create")
        .header("Content-Type", "application/json")
        .body(Body::from("{not json"))
        .expect("valid request");
    let response = send_to(&state, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_json(response).await;
    assert!(
        json["message"]
            .as_str()
            .expect("message")
            .contains("invalid JSON in request body"),
        "{json}"
    );
}

#[tokio::test]
async fn start_and_stop_answer_204_or_304() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "POST", "/containers/web/start", None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(recorder.only_call(), Call::StartContainer("web".to_owned()));

    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.start = Some(ChangeOutcome::Unchanged))
        .into_state();
    let response = send_json(&state, "POST", "/containers/web/start", None).await;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(recorder.calls().len(), 1);

    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "POST", "/containers/web/stop?t=30", None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        recorder.only_call(),
        Call::StopContainer("web".to_owned(), Some(Duration::from_secs(30)))
    );

    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.stop = Some(ChangeOutcome::Unchanged))
        .into_state();
    let response = send_json(&state, "POST", "/containers/web/stop", None).await;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        recorder.only_call(),
        Call::StopContainer("web".to_owned(), None),
        "an absent ?t= leaves the timeout to the daemon"
    );

    // Docker's "wait forever" (-1) degrades to the daemon default.
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "POST", "/containers/web/stop?t=-1", None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        recorder.only_call(),
        Call::StopContainer("web".to_owned(), None)
    );

    let (state, _) = MockBackend::new().into_state();
    let response = send_json(&state, "POST", "/containers/web/stop?t=soon", None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn kill_defaults_to_sigkill_and_passes_the_signal_through() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "POST", "/containers/web/kill", None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        recorder.only_call(),
        Call::KillContainer("web".to_owned(), "SIGKILL".to_owned())
    );

    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "POST", "/containers/web/kill?signal=SIGHUP", None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        recorder.only_call(),
        Call::KillContainer("web".to_owned(), "SIGHUP".to_owned())
    );
}

#[tokio::test]
async fn wait_returns_the_status_code_document() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.wait = WaitResult {
                status_code: 137,
                error: None,
            };
        })
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/containers/web/wait?condition=next-exit",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["StatusCode"], 137);
    assert!(json["Error"].is_null());
    assert_eq!(
        recorder.only_call(),
        Call::WaitContainer("web".to_owned(), WaitCondition::NextExit)
    );

    let (state, _) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/containers/web/wait?condition=whenever",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn remove_container_forwards_force_and_volume_flags() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "DELETE", "/containers/web?force=1&v=true", None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        recorder.only_call(),
        Call::RemoveContainer("web".to_owned(), true, true)
    );

    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "DELETE", "/containers/web?force=0", None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        recorder.only_call(),
        Call::RemoveContainer("web".to_owned(), false, false)
    );

    let (state, _) = MockBackend::new().into_state();
    let response = send_json(&state, "DELETE", "/containers/web?link=1", None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_containers_uses_docker_keys_and_the_platform_extension() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.containers = vec![sample_summary()])
        .into_state();
    let response = send_json(&state, "GET", "/containers/json?all=1", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let row = &json[0];

    assert_eq!(row["Id"], "1hvy0lj3x0b883f8e30fyp217");
    assert_eq!(row["Names"][0], "/web");
    assert_eq!(row["Image"], "registry.example.com/nginx:1.27");
    assert_eq!(row["ImageID"], "sha256:c0ffee");
    assert_eq!(row["Command"], "nginx -g daemon off;");
    assert_eq!(row["Created"], 1_770_000_000_i64);
    assert_eq!(row["State"], "running");
    assert!(
        row["Status"].as_str().expect("status").starts_with("Up "),
        "{row}"
    );
    assert_eq!(row["Labels"]["tier"], "web");
    assert_eq!(row["Ports"][0]["PrivatePort"], 80);
    assert_eq!(row["Ports"][0]["PublicPort"], 8080);
    assert_eq!(row["Ports"][0]["Type"], "tcp");
    assert_eq!(row["Ports"][0]["IP"], "0.0.0.0");
    assert_eq!(row["Mounts"][0]["Type"], "bind");
    assert_eq!(row["Mounts"][0]["Destination"], "/data");
    assert_eq!(row["Mounts"][0]["RW"], false);
    assert_eq!(row["HostConfig"]["NetworkMode"], "bridge");
    assert_eq!(
        row["NetworkSettings"]["Networks"]["bridge"]["IPAddress"],
        "10.88.0.5"
    );
    assert_eq!(row["Platform"], "freebsd/amd64");

    let keys: Vec<&str> = row
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    for key in [
        "Id",
        "Names",
        "Image",
        "ImageID",
        "Command",
        "Created",
        "Ports",
        "Labels",
        "State",
        "Status",
        "HostConfig",
        "NetworkSettings",
        "Mounts",
        "Platform",
    ] {
        assert!(keys.contains(&key), "missing key {key} in {keys:?}");
    }
    assert_eq!(recorder.only_call(), Call::ListContainers(true));
}

#[tokio::test]
async fn list_containers_defaults_to_running_only() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/containers/json", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await, serde_json::json!([]));
    assert_eq!(recorder.only_call(), Call::ListContainers(false));
}

#[tokio::test]
async fn inspect_container_renders_state_config_network_and_satl_extensions() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.inspect = Some(sample_inspect()))
        .into_state();
    let response = send_json(&state, "GET", "/containers/web/json", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;

    assert_eq!(json["Id"], "1hvy0lj3x0b883f8e30fyp217");
    assert_eq!(json["Name"], "/web");
    assert_eq!(json["Created"], "2026-02-02T02:40:00Z");
    assert_eq!(json["Path"], "nginx");
    assert_eq!(json["Args"][1], "daemon off;");
    assert_eq!(json["Image"], "sha256:c0ffee");
    assert_eq!(json["Driver"], "zfs");
    assert_eq!(json["RestartCount"], 2);

    let state_doc = &json["State"];
    assert_eq!(state_doc["Status"], "exited");
    assert_eq!(state_doc["Running"], false);
    assert_eq!(state_doc["Paused"], false);
    assert_eq!(state_doc["Dead"], false);
    assert_eq!(state_doc["ExitCode"], 137);
    assert_eq!(state_doc["Pid"], 0);
    assert_eq!(state_doc["Error"], "killed by the restart supervisor");
    assert_eq!(state_doc["StartedAt"], "2026-02-02T02:40:00Z");
    assert_eq!(state_doc["FinishedAt"], "2026-02-02T02:41:00Z");
    assert_eq!(state_doc["OOMKilled"], false);

    let config = &json["Config"];
    assert_eq!(config["Hostname"], "web-1");
    assert_eq!(config["User"], "www");
    assert_eq!(config["Env"][0], "RUST_LOG=info");
    assert_eq!(config["Cmd"][0], "-g");
    assert_eq!(config["Entrypoint"][0], "nginx");
    assert_eq!(config["WorkingDir"], "/srv");
    assert_eq!(config["Image"], "registry.example.com/nginx:1.27");
    assert_eq!(config["Labels"]["tier"], "web");
    assert!(config["ExposedPorts"]["80/tcp"].is_object());

    let host = &json["HostConfig"];
    assert_eq!(host["Binds"][0], "/host/data:/data:ro");
    assert_eq!(host["Tmpfs"]["/run"], "rw,size=64m");
    assert_eq!(host["PortBindings"]["80/tcp"][0]["HostPort"], "8080");
    assert_eq!(host["PortBindings"]["80/tcp"][0]["HostIp"], "127.0.0.1");
    assert_eq!(host["RestartPolicy"]["Name"], "on-failure");
    assert_eq!(host["RestartPolicy"]["MaximumRetryCount"], 3);
    assert_eq!(host["Memory"], 536_870_912_i64);
    assert_eq!(host["NanoCpus"], 1_500_000_000_i64);
    assert_eq!(host["NetworkMode"], "bridge");
    assert_eq!(host["AutoRemove"], false);

    let network = &json["NetworkSettings"];
    assert_eq!(network["IPAddress"], "10.88.0.5");
    assert_eq!(network["IPPrefixLen"], 24);
    assert_eq!(network["Gateway"], "10.88.0.1");
    assert_eq!(network["MacAddress"], "02:ff:60:00:00:05");
    assert_eq!(network["Ports"]["80/tcp"][0]["HostPort"], "8080");
    assert_eq!(network["Networks"]["bridge"]["NetworkID"], "net-1");

    // SatL extensions.
    assert_eq!(json["Platform"], "freebsd/amd64");
    assert_eq!(json["JailID"], "1hvy0lj3x0b883f8e30fyp217");

    assert_eq!(
        recorder.only_call(),
        Call::InspectContainer("web".to_owned())
    );
}

#[tokio::test]
async fn inspect_unknown_container_is_a_docker_404() {
    let (state, _) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/containers/ghost/json", None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = body_json(response).await;
    assert_eq!(json["message"], "no such container: ghost");
}

// ---------------------------------------------------------------------------
// M1 — logs and framing
// ---------------------------------------------------------------------------

/// Two frames: `hello\n` on stdout, `boom\n` on stderr.
fn sample_log_frames() -> Vec<LogFrame> {
    vec![
        LogFrame {
            stream: LogStream::Stdout,
            timestamp: UNIX_EPOCH + Duration::new(1_770_000_000, 42),
            data: bytes::Bytes::from_static(b"hello\n"),
        },
        LogFrame {
            stream: LogStream::Stderr,
            timestamp: UNIX_EPOCH + Duration::new(1_770_000_001, 0),
            data: bytes::Bytes::from_static(b"boom\n"),
        },
    ]
}

/// Decodes a multiplexed stream fed in arbitrary chunks, the way a Docker
/// client must: 8-byte header, then exactly `length` payload bytes.
fn decode_multiplexed(chunks: &[&[u8]]) -> Vec<(u8, Vec<u8>)> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut frames = Vec::new();
    for chunk in chunks {
        buffer.extend_from_slice(chunk);
        loop {
            if buffer.len() < 8 {
                break;
            }
            let length = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as usize;
            if buffer.len() < 8 + length {
                break;
            }
            frames.push((buffer[0], buffer[8..8 + length].to_vec()));
            buffer.drain(..8 + length);
        }
    }
    assert!(buffer.is_empty(), "trailing bytes after the last frame");
    frames
}

#[tokio::test]
async fn logs_stream_docker_multiplexed_frames_byte_for_byte() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.log_frames = sample_log_frames())
        .into_state();
    let response = send_json(
        &state,
        "GET",
        "/containers/web/logs?stdout=1&stderr=1&tail=20",
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("Content-Type")
            .expect("content type"),
        "application/vnd.docker.multiplexed-stream"
    );
    let body = body_bytes(response).await;
    assert_eq!(
        body,
        b"\x01\x00\x00\x00\x00\x00\x00\x06hello\n\x02\x00\x00\x00\x00\x00\x00\x05boom\n".to_vec()
    );

    let Call::ContainerLogs(id, options) = recorder.only_call() else {
        panic!("expected a container_logs call");
    };
    assert_eq!(id, "web");
    assert!(options.stdout && options.stderr && !options.follow && !options.timestamps);
    assert_eq!(options.tail, Some(20));
    assert_eq!(options.since, None);
}

#[tokio::test]
async fn log_frames_decode_across_every_chunk_boundary() {
    let (state, _) = MockBackend::new()
        .answer(|answers| answers.log_frames = sample_log_frames())
        .into_state();
    let response = send_json(
        &state,
        "GET",
        "/containers/web/logs?stdout=1&stderr=1",
        None,
    )
    .await;
    let body = body_bytes(response).await;
    let expected = vec![(1_u8, b"hello\n".to_vec()), (2_u8, b"boom\n".to_vec())];

    // Whole body in one piece, then split at every possible boundary: a
    // frame cut in half must still decode to the same two frames.
    assert_eq!(decode_multiplexed(&[&body]), expected);
    for split in 1..body.len() {
        assert_eq!(
            decode_multiplexed(&[&body[..split], &body[split..]]),
            expected,
            "split at {split}"
        );
    }
}

#[tokio::test]
async fn logs_with_timestamps_prefix_rfc3339_nano_inside_the_frame() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.log_frames = sample_log_frames())
        .into_state();
    let response = send_json(
        &state,
        "GET",
        "/containers/web/logs?stdout=1&stderr=1&timestamps=1&follow=1&since=1770000000",
        None,
    )
    .await;
    let body = body_bytes(response).await;
    assert_eq!(
        body,
        [
            b"\x01\x00\x00\x00\x00\x00\x00\x25".as_slice(),
            b"2026-02-02T02:40:00.000000042Z hello\n".as_slice(),
            b"\x02\x00\x00\x00\x00\x00\x00\x1a".as_slice(),
            b"2026-02-02T02:40:01Z boom\n".as_slice(),
        ]
        .concat()
    );

    let Call::ContainerLogs(_, options) = recorder.only_call() else {
        panic!("expected a container_logs call");
    };
    assert!(options.timestamps && options.follow);
    assert_eq!(options.since, Some(at(1_770_000_000)));
}

#[tokio::test]
async fn logs_without_a_stream_selection_are_rejected() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/containers/web/logs", None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_json(response).await;
    assert_eq!(
        json["message"],
        "Bad parameters: you must choose at least one stream"
    );
    assert!(recorder.calls().is_empty());
}

// ---------------------------------------------------------------------------
// M1 — images
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pull_streams_json_progress_lines_terminated_by_crlf() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.pull_lines = vec![
                PullProgressLine::status("Pulling from library/nginx"),
                PullProgressLine {
                    status: "Downloading".to_owned(),
                    id: Some("c0ffee".to_owned()),
                    progress_detail: Some(ProgressDetail {
                        current: Some(512),
                        total: Some(1024),
                    }),
                    progress: Some("[=====>   ]  512B/1kB".to_owned()),
                    error: None,
                },
                PullProgressLine {
                    error: Some("manifest unknown".to_owned()),
                    ..PullProgressLine::default()
                },
            ];
        })
        .into_state();

    let response = send_json(
        &state,
        "POST",
        "/images/create?fromImage=nginx&tag=1.27&platform=freebsd%2Famd64",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("Content-Type")
            .expect("content type"),
        "application/json"
    );

    let body = body_bytes(response).await;
    let text = String::from_utf8(body).expect("utf-8 progress stream");
    let lines: Vec<&str> = text.split_terminator("\r\n").collect();
    assert_eq!(lines.len(), 3, "one JSON document per line: {text:?}");
    let first: Value = serde_json::from_str(lines[0]).expect("valid JSON line");
    assert_eq!(first["status"], "Pulling from library/nginx");
    assert!(first.get("id").is_none(), "absent fields are omitted");
    let second: Value = serde_json::from_str(lines[1]).expect("valid JSON line");
    assert_eq!(second["id"], "c0ffee");
    assert_eq!(second["progressDetail"]["current"], 512);
    assert_eq!(second["progressDetail"]["total"], 1024);
    assert_eq!(second["progress"], "[=====>   ]  512B/1kB");
    let third: Value = serde_json::from_str(lines[2]).expect("valid JSON line");
    assert_eq!(third["error"], "manifest unknown");
    assert_eq!(third["errorDetail"]["message"], "manifest unknown");

    let Call::PullImage(reference, auth, platform) = recorder.only_call() else {
        panic!("expected a pull_image call");
    };
    assert_eq!(reference, "nginx:1.27");
    assert_eq!(auth, None);
    assert_eq!(
        platform,
        Some(Platform {
            os: "freebsd".to_owned(),
            arch: "amd64".to_owned()
        })
    );
}

#[tokio::test]
async fn pull_decodes_the_x_registry_auth_header() {
    let payload = serde_json::json!({
        "username": "frederic",
        "password": "hunter2",
        "serveraddress": "registry.example.com"
    })
    .to_string();
    let header = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE.encode(payload)
    };

    let (state, recorder) = MockBackend::new().into_state();
    let request = Request::builder()
        .method("POST")
        .uri("/images/create?fromImage=nginx")
        .header("X-Registry-Auth", header)
        .body(Body::empty())
        .expect("valid request");
    let response = send_to(&state, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let Call::PullImage(reference, auth, _) = recorder.only_call() else {
        panic!("expected a pull_image call");
    };
    assert_eq!(reference, "nginx");
    let auth = auth.expect("credentials must reach the backend");
    assert_eq!(auth.username, "frederic");
    assert_eq!(auth.password, "hunter2");
    assert_eq!(auth.server_address, "registry.example.com");
}

#[tokio::test]
async fn pull_rejects_an_undecodable_auth_header_and_a_missing_image() {
    let (state, recorder) = MockBackend::new().into_state();
    let request = Request::builder()
        .method("POST")
        .uri("/images/create?fromImage=nginx")
        .header("X-Registry-Auth", "%%%not base64%%%")
        .body(Body::empty())
        .expect("valid request");
    let response = send_to(&state, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_json(response).await["message"]
            .as_str()
            .expect("message")
            .contains("X-Registry-Auth"),
    );
    assert!(recorder.calls().is_empty());

    let (state, _) = MockBackend::new().into_state();
    let response = send_json(&state, "POST", "/images/create", None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_images_uses_docker_keys_and_the_platform_extension() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.images = vec![ImageSummary {
                id: "sha256:c0ffee".to_owned(),
                parent_id: String::new(),
                repo_tags: vec!["nginx:1.27".to_owned()],
                repo_digests: vec!["nginx@sha256:c0ffee".to_owned()],
                created: Some(at(1_770_000_000)),
                size: 42_000_000,
                shared_size: -1,
                labels: BTreeMap::from([(
                    "org.opencontainers.image.version".to_owned(),
                    "1.27".to_owned(),
                )]),
                containers: -1,
                platform: Some(Platform {
                    os: "linux".to_owned(),
                    arch: "amd64".to_owned(),
                }),
            }];
        })
        .into_state();

    let response = send_json(&state, "GET", "/images/json", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let row = &json[0];
    assert_eq!(row["Id"], "sha256:c0ffee");
    assert_eq!(row["ParentId"], "");
    assert_eq!(row["RepoTags"][0], "nginx:1.27");
    assert_eq!(row["RepoDigests"][0], "nginx@sha256:c0ffee");
    assert_eq!(row["Created"], 1_770_000_000_i64);
    assert_eq!(row["Size"], 42_000_000_i64);
    assert_eq!(row["VirtualSize"], 42_000_000_i64);
    assert_eq!(row["SharedSize"], -1);
    assert_eq!(row["Containers"], -1);
    assert_eq!(row["Labels"]["org.opencontainers.image.version"], "1.27");
    assert_eq!(row["Platform"], "linux/amd64");
    assert_eq!(recorder.only_call(), Call::ListImages);
}

#[tokio::test]
async fn tag_image_posts_repo_and_tag_and_answers_201() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/images/nginx:1.25/tag?repo=registry.example.com%2Fapp&tag=v1",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        recorder.only_call(),
        Call::TagImage(
            "nginx:1.25".to_owned(),
            "registry.example.com/app:v1".to_owned()
        )
    );
}

#[tokio::test]
async fn tag_image_accepts_a_name_with_slashes_and_defaults_the_tag() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/images/ghcr.io/x/y:v1/tag?repo=127.0.0.1:5000/mirror/y",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        recorder.only_call(),
        Call::TagImage(
            "ghcr.io/x/y:v1".to_owned(),
            "127.0.0.1:5000/mirror/y".to_owned()
        ),
        "an absent ?tag= leaves the tag to the daemon (latest)"
    );
}

#[tokio::test]
async fn tag_image_maps_backend_errors_to_docker_statuses() {
    // An unknown source is a 404.
    let (state, _) = MockBackend::failing(BackendError::not_found(
        "no such image in the local store: docker.io/library/ghost:1",
    ))
    .into_state();
    let response = send_json(&state, "POST", "/images/ghost:1/tag?repo=other", None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        body_json(response).await["message"]
            .as_str()
            .expect("message")
            .contains("no such image in the local store")
    );

    // An unparseable target is a 400 (the daemon validates the joined
    // reference).
    let (state, _) = MockBackend::failing(BackendError::invalid(
        "invalid reference UPPER: repository names must be lowercase",
    ))
    .into_state();
    let response = send_json(&state, "POST", "/images/nginx/tag?repo=UPPER", None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tag_image_requires_a_repo_and_the_other_image_name_verbs_stay_404() {
    // No repo: 400, and the backend is never called.
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "POST", "/images/nginx:1.25/tag", None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_json(response).await["message"]
            .as_str()
            .expect("message")
            .contains("repo")
    );
    assert!(
        recorder.calls().is_empty(),
        "a rejected request must not reach the backend"
    );

    // The rest of the /images/{name}/* family keeps the fallback's 404 shape
    // (docs/api-compat.md #22).
    let (state, _) = MockBackend::new().into_state();
    for (method, path) in [
        ("POST", "/images/nginx/push"),
        ("GET", "/images/nginx/json"),
        ("DELETE", "/images/nginx:1.25"),
    ] {
        let response = send_json(&state, method, path, None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(
            body_json(response).await["message"]
                .as_str()
                .expect("message"),
            "page not found",
            "{method} {path}"
        );
    }
}

// ---------------------------------------------------------------------------
// M1 — exec
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_exec_returns_201_with_the_instance_id() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.exec_id = "exec-1".to_owned())
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/containers/web/exec",
        Some(serde_json::json!({
            "Cmd": ["sh", "-c", "echo hi"],
            "AttachStdout": true,
            "AttachStderr": true,
            "Env": ["A=1"],
            "User": "root"
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    assert_eq!(json["Id"], "exec-1");
    assert_eq!(json.as_object().expect("object").len(), 1);

    let Call::CreateExec(container, config) = recorder.only_call() else {
        panic!("expected a create_exec call");
    };
    assert_eq!(container, "web");
    assert_eq!(config.cmd, ["sh", "-c", "echo hi"]);
    assert_eq!(config.env, ["A=1"]);
    assert_eq!(config.user.as_deref(), Some("root"));
    assert!(config.attach_stdout && config.attach_stderr);
}

#[tokio::test]
async fn create_exec_rejects_tty_and_empty_commands() {
    for (body, expected) in [
        (
            serde_json::json!({"Cmd": ["sh"], "Tty": true}),
            "tty not supported yet",
        ),
        (serde_json::json!({}), "no command specified"),
    ] {
        let (state, recorder) = MockBackend::new().into_state();
        let response = send_json(&state, "POST", "/containers/web/exec", Some(body)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(response).await["message"], expected);
        assert!(recorder.calls().is_empty());
    }
}

#[tokio::test]
async fn start_exec_rejects_tty_and_detach() {
    for (body, status, expected) in [
        (
            serde_json::json!({"Tty": true}),
            StatusCode::BAD_REQUEST,
            "tty not supported yet",
        ),
        (
            serde_json::json!({"Detach": true}),
            StatusCode::NOT_IMPLEMENTED,
            "detached exec (Detach=true) is not supported yet",
        ),
    ] {
        let (state, recorder) = MockBackend::new().into_state();
        let response = send_json(&state, "POST", "/exec/exec-1/start", Some(body)).await;
        assert_eq!(response.status(), status);
        assert_eq!(body_json(response).await["message"], expected);
        assert!(recorder.calls().is_empty());
    }
}

#[tokio::test]
async fn start_exec_without_an_upgrade_streams_the_same_frames() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.exec_frames = sample_log_frames();
            answers.exec_exit_code = 0;
        })
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/exec/exec-1/start",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("Content-Type")
            .expect("content type"),
        "application/vnd.docker.raw-stream"
    );
    assert_eq!(
        body_bytes(response).await,
        b"\x01\x00\x00\x00\x00\x00\x00\x06hello\n\x02\x00\x00\x00\x00\x00\x00\x05boom\n".to_vec()
    );
    assert_eq!(recorder.only_call(), Call::StartExec("exec-1".to_owned()));
}

#[tokio::test]
async fn inspect_exec_renders_docker_process_config() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.exec_inspect = Some(ExecInspect {
                id: "exec-1".to_owned(),
                container_id: "1hvy0lj3x0b883f8e30fyp217".to_owned(),
                running: false,
                exit_code: Some(3),
                pid: Some(1234),
                cmd: vec!["sh".to_owned(), "-c".to_owned(), "exit 3".to_owned()],
                tty: false,
                open_stdin: false,
                open_stdout: true,
                open_stderr: true,
            });
        })
        .into_state();
    let response = send_json(&state, "GET", "/exec/exec-1/json", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["ID"], "exec-1");
    assert_eq!(json["ContainerID"], "1hvy0lj3x0b883f8e30fyp217");
    assert_eq!(json["Running"], false);
    assert_eq!(json["ExitCode"], 3);
    assert_eq!(json["Pid"], 1234);
    assert_eq!(json["OpenStdout"], true);
    assert_eq!(json["CanRemove"], true);
    assert_eq!(json["ProcessConfig"]["entrypoint"], "sh");
    assert_eq!(json["ProcessConfig"]["arguments"][1], "exit 3");
    assert_eq!(json["ProcessConfig"]["tty"], false);
    assert_eq!(recorder.only_call(), Call::InspectExec("exec-1".to_owned()));
}

// ---------------------------------------------------------------------------
// M1 — volumes
// ---------------------------------------------------------------------------

fn sample_volume() -> VolumeInfo {
    VolumeInfo {
        name: "data".to_owned(),
        driver: "local".to_owned(),
        mountpoint: "/var/db/satl/volumes/data".to_owned(),
        created_at: Some(at(1_770_000_000)),
        labels: BTreeMap::from([("owner".to_owned(), "web".to_owned())]),
        options: BTreeMap::new(),
    }
}

#[tokio::test]
async fn volume_endpoints_cover_list_create_inspect_and_remove() {
    // Create.
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.volumes = vec![sample_volume()])
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/volumes/create",
        Some(serde_json::json!({"Name": "data", "Labels": {"owner": "web"}})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    assert_eq!(json["Name"], "data");
    assert_eq!(json["Driver"], "local");
    assert_eq!(json["Mountpoint"], "/var/db/satl/volumes/data");
    assert_eq!(json["CreatedAt"], "2026-02-02T02:40:00Z");
    assert_eq!(json["Scope"], "local");
    assert_eq!(json["Labels"]["owner"], "web");
    assert!(json["Options"].is_object() && json["Status"].is_object());
    let Call::CreateVolume(options) = recorder.only_call() else {
        panic!("expected a create_volume call");
    };
    assert_eq!(options.name, "data");
    assert_eq!(options.driver, "local");

    // List.
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.volumes = vec![sample_volume()])
        .into_state();
    let response = send_json(&state, "GET", "/volumes", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["Volumes"][0]["Name"], "data");
    assert_eq!(json["Warnings"], serde_json::json!([]));
    assert_eq!(recorder.only_call(), Call::ListVolumes);

    // Inspect.
    let (state, _) = MockBackend::new()
        .answer(|answers| answers.volumes = vec![sample_volume()])
        .into_state();
    let response = send_json(&state, "GET", "/volumes/data", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["Name"], "data");

    let (state, _) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/volumes/ghost", None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(response).await["message"],
        "get ghost: no such volume"
    );

    // Remove.
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "DELETE", "/volumes/data?force=1", None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        recorder.only_call(),
        Call::RemoveVolume("data".to_owned(), true)
    );
}

#[tokio::test]
async fn volume_create_rejects_foreign_drivers() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/volumes/create",
        Some(serde_json::json!({"Name": "data", "Driver": "nfs"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_json(response).await["message"]
            .as_str()
            .expect("message")
            .contains("not supported")
    );
    assert!(recorder.calls().is_empty());
}

// ---------------------------------------------------------------------------
// M1 — events and /info
// ---------------------------------------------------------------------------

#[tokio::test]
async fn events_stream_one_json_object_per_line() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.events = vec![
                EventMessage {
                    kind: "container".to_owned(),
                    action: "create".to_owned(),
                    actor: EventActor {
                        id: "1hvy0lj3x0b883f8e30fyp217".to_owned(),
                        attributes: BTreeMap::from([
                            ("name".to_owned(), "web".to_owned()),
                            ("image".to_owned(), "nginx:1.27".to_owned()),
                        ]),
                    },
                    scope: "local".to_owned(),
                    time: UNIX_EPOCH + Duration::new(1_770_000_000, 123_456_789),
                },
                EventMessage {
                    kind: "container".to_owned(),
                    action: "die".to_owned(),
                    actor: EventActor {
                        id: "1hvy0lj3x0b883f8e30fyp217".to_owned(),
                        attributes: BTreeMap::from([("exitCode".to_owned(), "137".to_owned())]),
                    },
                    scope: "local".to_owned(),
                    time: at(1_770_000_060),
                },
            ];
        })
        .into_state();

    let response = send_json(&state, "GET", "/events?since=1770000000", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("Content-Type")
            .expect("content type"),
        "application/json"
    );
    let text = String::from_utf8(body_bytes(response).await).expect("utf-8 event stream");
    let lines: Vec<&str> = text.split_terminator('\n').collect();
    assert_eq!(lines.len(), 2, "one JSON object per line: {text:?}");

    let first: Value = serde_json::from_str(lines[0]).expect("valid JSON line");
    assert_eq!(first["Type"], "container");
    assert_eq!(first["Action"], "create");
    assert_eq!(first["Actor"]["ID"], "1hvy0lj3x0b883f8e30fyp217");
    assert_eq!(first["Actor"]["Attributes"]["name"], "web");
    assert_eq!(first["scope"], "local");
    assert_eq!(first["time"], 1_770_000_000_i64);
    assert_eq!(first["timeNano"], 1_770_000_000_123_456_789_i64);

    let second: Value = serde_json::from_str(lines[1]).expect("valid JSON line");
    assert_eq!(second["Action"], "die");
    assert_eq!(second["Actor"]["Attributes"]["exitCode"], "137");

    assert_eq!(recorder.only_call(), Call::Events(Some(at(1_770_000_000))));
}

#[tokio::test]
async fn events_reject_an_unparsable_since() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/events?since=yesterday", None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(recorder.calls().is_empty());
}

#[tokio::test]
async fn info_reports_the_backend_counts() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.counts = Counts {
                containers: 5,
                containers_running: 3,
                containers_paused: 0,
                containers_stopped: 2,
                images: 7,
            };
        })
        .into_state();
    let response = send_json(&state, "GET", "/info", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["Containers"], 5);
    assert_eq!(json["ContainersRunning"], 3);
    assert_eq!(json["ContainersPaused"], 0);
    assert_eq!(json["ContainersStopped"], 2);
    assert_eq!(json["Images"], 7);
    assert_eq!(json["Driver"], "zfs");
    // `/info` asks the backend for the counts and for live cluster state; the
    // mock has no swarm status, so the static section from `ApiState` is used.
    assert_eq!(recorder.calls(), [Call::SystemCounts, Call::SwarmStatus]);
    assert_eq!(json["Swarm"]["NodeID"], "1hvy0lj3x0b883f8e30fyp217");
}

// ---------------------------------------------------------------------------
// M1 — error mapping and the unwired backend
// ---------------------------------------------------------------------------

#[tokio::test]
async fn backend_errors_map_to_docker_status_codes() {
    let cases = [
        (
            BackendError::not_found("no such container: web"),
            StatusCode::NOT_FOUND,
        ),
        (
            BackendError::conflict("container web is already running"),
            StatusCode::CONFLICT,
        ),
        (
            BackendError::invalid("bad parameter"),
            StatusCode::BAD_REQUEST,
        ),
        (
            BackendError::not_implemented("not yet"),
            StatusCode::NOT_IMPLEMENTED,
        ),
        (
            BackendError::internal("zfs clone failed"),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ];
    for (error, status) in cases {
        let expected = error.to_string();
        let (state, _) = MockBackend::failing(error).into_state();
        let response = send_json(&state, "POST", "/containers/web/start", None).await;
        assert_eq!(response.status(), status, "for {expected}");
        assert_eq!(
            response.headers().get("Server").expect("server"),
            "SatL/0.1.0"
        );
        let json = body_json(response).await;
        assert_eq!(json["message"], expected);
        assert_eq!(
            json.as_object().expect("object").len(),
            1,
            "Docker's error envelope has exactly one member"
        );
    }
}

#[tokio::test]
async fn unwired_backend_answers_501_but_keeps_info_working() {
    // `ApiState::new` alone (what satld builds before wiring its backend).
    let state = mock::test_state();
    for (method, path) in [
        ("GET", "/containers/json"),
        ("GET", "/images/json"),
        ("GET", "/volumes"),
        ("POST", "/containers/web/start"),
        ("GET", "/events"),
    ] {
        let response = send_json(&state, method, path, None).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_IMPLEMENTED,
            "for {method} {path}"
        );
        assert_eq!(
            body_json(response).await["message"],
            "daemon wiring pending"
        );
    }

    let response = send_json(&state, "GET", "/info", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["Containers"], 0);
}

#[tokio::test]
async fn m1_paths_are_reachable_under_a_version_prefix() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/v1.43/containers/json?all=1", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorder.only_call(), Call::ListContainers(true));

    let (state, _) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/v1.44/containers/json", None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// M1 — the exec hijack, over a real unix socket
// ---------------------------------------------------------------------------

/// `POST /exec/{id}/start` with Docker's upgrade headers must answer `101
/// Switching Protocols` and then own the socket, writing multiplexed frames
/// on it. `tower::ServiceExt::oneshot` cannot exercise this — the connection
/// upgrade only exists in a real hyper server — so this test speaks HTTP/1.1
/// on a unix socket the way the docker CLI does.
#[tokio::test]
async fn start_exec_hijacks_the_connection_and_streams_frames() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.exec_frames = sample_log_frames();
            answers.exec_exit_code = 3;
        })
        .into_state();

    let dir = std::env::temp_dir().join(format!("satl-api-hijack-{}", std::process::id()));
    tokio::fs::create_dir_all(&dir).await.expect("scratch dir");
    let socket_path = dir.join("satld.sock");

    let serve_path = socket_path.clone();
    let server = tokio::spawn(async move {
        let _ = satl_api::serve_unix(&serve_path, router(state), std::future::pending()).await;
    });

    // Wait for the socket to accept connections.
    let mut stream = None;
    for _ in 0..200 {
        if let Ok(connected) = tokio::net::UnixStream::connect(&socket_path).await {
            stream = Some(connected);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut stream = stream.expect("server never started listening");

    stream
        .write_all(
            b"POST /v1.43/exec/exec-1/start HTTP/1.1\r\n\
              Host: satl\r\n\
              Content-Type: application/json\r\n\
              Connection: Upgrade\r\n\
              Upgrade: tcp\r\n\
              Content-Length: 2\r\n\
              \r\n\
              {}",
        )
        .await
        .expect("request written");
    // Whatever the client sends after the handshake is discarded (stdin).
    stream
        .write_all(b"this is stdin and must be ignored\n")
        .await
        .expect("stdin written");

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("the daemon must close the hijacked stream when the exec exits")
        .expect("read the hijacked stream");

    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("headers must be terminated");
    let headers = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    let payload = &raw[split + 4..];

    assert!(
        headers.starts_with("http/1.1 101 switching protocols"),
        "expected a hijack handshake, got: {headers}"
    );
    assert!(
        headers.contains("content-type: application/vnd.docker.raw-stream"),
        "{headers}"
    );
    assert!(headers.contains("upgrade: tcp"), "{headers}");
    assert!(headers.contains("connection: upgrade"), "{headers}");

    assert_eq!(
        payload, b"\x01\x00\x00\x00\x00\x00\x00\x06hello\n\x02\x00\x00\x00\x00\x00\x00\x05boom\n",
        "the hijacked stream carries multiplexed frames, unchunked"
    );
    assert_eq!(recorder.only_call(), Call::StartExec("exec-1".to_owned()));

    server.abort();
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

// ---------------------------------------------------------------------------
// M2 — cluster fixtures
// ---------------------------------------------------------------------------

/// A fixed ID so the assertions can name it.
fn id(text: &str) -> Id {
    text.parse().expect("test IDs are well-formed")
}

const NODE_ID: &str = "1hvy0lj3x0b883f8e30fyp217";
const SERVICE_ID: &str = "2hvy0lj3x0b883f8e30fyp218";
const TASK_ID: &str = "3hvy0lj3x0b883f8e30fyp219";

fn sample_meta() -> Meta {
    Meta {
        version: Version(7),
        created_at: at(1_770_000_000),
        updated_at: at(1_770_000_600),
    }
}

fn sample_node() -> Node {
    Node {
        id: id(NODE_ID),
        meta: sample_meta(),
        spec: NodeSpec {
            name: Some("alpha".to_owned()),
            labels: BTreeMap::from([("zone".to_owned(), "a".to_owned())]),
            role: NodeRole::Manager,
            availability: Availability::Active,
        },
        description: Some(NodeDescription {
            hostname: "alpha".to_owned(),
            platform: Platform {
                os: "freebsd".to_owned(),
                arch: "amd64".to_owned(),
            },
            resources: Resources {
                nano_cpus: 8_000_000_000,
                memory_bytes: 34_359_738_368,
            },
            engine: EngineDescription {
                version: "0.1.0".to_owned(),
                labels: BTreeMap::new(),
            },
            linux_emulation: true,
            racct_enabled: true,
            data_addr: Some("10.2.0.11".to_owned()),
        }),
        status: NodeStatus {
            state: NodeState::Ready,
            message: String::new(),
            addr: "10.2.0.11".to_owned(),
        },
        manager_status: Some(ManagerStatus {
            raft_id: 42,
            addr: "10.2.0.11:2377".to_owned(),
            leader: true,
            reachability: Reachability::Reachable,
        }),
        certificate_status: satl_core::CertificateStatus::Issued,
        certificate_issuer: None,
    }
}

fn sample_service_spec() -> ServiceSpec {
    ServiceSpec {
        annotations: Annotations {
            name: "web".to_owned(),
            labels: BTreeMap::new(),
        },
        task: TaskSpec {
            container: ContainerSpec {
                image: "nginx:1.27".to_owned(),
                labels: BTreeMap::new(),
                command: Vec::new(),
                args: Vec::new(),
                hostname: None,
                env: Vec::new(),
                dir: None,
                user: None,
                groups: Vec::new(),
                tty: false,
                open_stdin: false,
                read_only: false,
                stop_signal: None,
                stop_grace_period: None,
                healthcheck: None,
                hosts: Vec::new(),
                dns_config: None,
                mounts: Vec::new(),
                secrets: Vec::new(),
                configs: Vec::new(),
                pull_options: None,
                platform: None,
            },
            resources: satl_core::ResourceRequirements::default(),
            restart: RestartPolicy::default(),
            placement: Placement::default(),
            networks: Vec::new(),
            force_update: 0,
        },
        mode: ServiceMode::Replicated { replicas: 3 },
        update: None,
        rollback: None,
        endpoint: None,
    }
}

fn sample_service() -> Service {
    Service {
        id: id(SERVICE_ID),
        meta: sample_meta(),
        spec: sample_service_spec(),
        endpoint: Some(satl_core::Endpoint {
            spec: satl_core::EndpointSpec::default(),
            ports: vec![PortConfig {
                name: String::new(),
                protocol: PortProtocol::Tcp,
                target_port: 80,
                published_port: 8080,
                publish_mode: PublishMode::Ingress,
            }],
        }),
        spec_version: satl_core::Version(0),
        previous_spec: None,
        update_status: None,
    }
}

fn sample_task() -> Task {
    Task {
        id: id(TASK_ID),
        meta: sample_meta(),
        spec: sample_service_spec().task,
        spec_version: Some(Version(7)),
        service_id: Some(id(SERVICE_ID)),
        slot: 1,
        node_id: Some(id(NODE_ID)),
        annotations: Annotations {
            name: format!("web.1.{TASK_ID}"),
            labels: BTreeMap::new(),
        },
        service_annotations: Annotations::default(),
        status: TaskStatus {
            timestamp: at(1_770_000_300),
            state: TaskState::Running,
            message: "started".to_owned(),
            err: None,
            container: Some(satl_core::ContainerStatus {
                jail_id: Some(TASK_ID.to_owned()),
                pid: Some(4242),
                exit_code: None,
            }),
            port_status: Vec::new(),
            applied_by: None,
            applied_at: None,
        },
        desired_state: DesiredState::Running,
        networks: Vec::new(),
        endpoint: None,
        job_iteration: None,
    }
}

fn sample_swarm() -> SwarmDetail {
    SwarmDetail {
        cluster_id: "0hvy0lj3x0b883f8e30fyp210".to_owned(),
        created_at: at(1_770_000_000),
        updated_at: at(1_770_000_600),
        version: Version(11),
        join_tokens: JoinTokens {
            worker: "SATL-1-worker-token".to_owned(),
            manager: "SATL-1-manager-token".to_owned(),
        },
        root_ca_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n".to_owned(),
        root_rotation_in_progress: false,
        spec: ClusterSpec {
            annotations: Annotations {
                name: "default".to_owned(),
                labels: BTreeMap::new(),
            },
            raft: satl_core::RaftConfig::default(),
            dispatcher: satl_core::DispatcherConfig::default(),
            ca: satl_core::CaConfig::default(),
            task_defaults: satl_core::TaskDefaults::default(),
            default_address_pool: vec!["10.100.0.0/14".to_owned()],
            subnet_size: 24,
            autolock: false,
            unlock_key: None,
        },
    }
}

// ---------------------------------------------------------------------------
// M2 — swarm
// ---------------------------------------------------------------------------

#[tokio::test]
async fn swarm_inspect_renders_the_cluster_document() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.swarm = Some(sample_swarm()))
        .into_state();
    let response = send_json(&state, "GET", "/v1.43/swarm", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;

    assert_eq!(json["ID"], "0hvy0lj3x0b883f8e30fyp210");
    assert_eq!(json["Version"]["Index"], 11);
    assert_eq!(json["CreatedAt"], "2026-02-02T02:40:00Z");
    assert_eq!(json["UpdatedAt"], "2026-02-02T02:50:00Z");
    assert_eq!(json["JoinTokens"]["Worker"], "SATL-1-worker-token");
    assert_eq!(json["JoinTokens"]["Manager"], "SATL-1-manager-token");
    assert_eq!(json["Spec"]["Name"], "default");
    assert_eq!(json["Spec"]["Raft"]["SnapshotInterval"], 10_000);
    assert_eq!(
        json["Spec"]["CAConfig"]["NodeCertExpiry"],
        7_776_000_000_000_000_i64
    );
    assert_eq!(json["Spec"]["EncryptionConfig"]["AutoLockManagers"], false);
    assert!(
        json["TLSInfo"]["TrustRoot"]
            .as_str()
            .expect("trust root")
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
    assert_eq!(json["SubnetSize"], 24);
    assert_eq!(json["DefaultAddrPool"][0], "10.100.0.0/14");
    assert_eq!(recorder.only_call(), Call::SwarmInspect);
}

/// Docker answers a swarm-scoped call on a worker with 503 and the exact
/// `errNoManager` wording (moby `daemon/cluster/cluster.go`; the
/// `notAvailableError` type maps to `http.StatusServiceUnavailable` in
/// `api/server/httpstatus`). Both the status and the sentence are
/// compatibility surfaces.
#[tokio::test]
async fn swarm_inspect_on_a_worker_is_a_docker_503() {
    let (state, _) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/swarm", None).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_json(response).await["message"],
        satl_api::model::NOT_A_SWARM_MANAGER
    );
}

#[tokio::test]
async fn swarm_init_answers_the_node_id_as_a_json_string() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.swarm_node_id = NODE_ID.to_owned())
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/v1.43/swarm/init",
        Some(serde_json::json!({
            "ListenAddr": "0.0.0.0:2377",
            "AdvertiseAddr": "10.2.0.11:2377",
            "ForceNewCluster": true
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await, serde_json::json!(NODE_ID));

    let Call::SwarmInit(options) = recorder.only_call() else {
        panic!("expected a swarm_init call");
    };
    assert_eq!(options.advertise_addr.as_deref(), Some("10.2.0.11:2377"));
    assert_eq!(options.listen_addr.as_deref(), Some("0.0.0.0:2377"));
    assert!(options.force_new_cluster);
}

#[tokio::test]
async fn swarm_init_passes_autolock_through() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/swarm/init",
        Some(serde_json::json!({"AutoLockManagers": true})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let Call::SwarmInit(options) = recorder.only_call() else {
        panic!("expected a swarm_init call");
    };
    assert!(options.auto_lock);
}

#[tokio::test]
async fn swarm_join_sends_the_addresses_and_token_through() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/swarm/join",
        Some(serde_json::json!({
            "RemoteAddrs": ["10.2.0.11:2377", "10.2.0.12:2377"],
            "JoinToken": "SATL-1-worker-token",
            "AdvertiseAddr": "10.2.0.13:2377"
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let Call::SwarmJoin(options) = recorder.only_call() else {
        panic!("expected a swarm_join call");
    };
    assert_eq!(options.remote_addrs, ["10.2.0.11:2377", "10.2.0.12:2377"]);
    assert_eq!(options.join_token, "SATL-1-worker-token");
    assert_eq!(options.advertise_addr.as_deref(), Some("10.2.0.13:2377"));
}

#[tokio::test]
async fn swarm_join_validates_its_body() {
    for (body, expected) in [
        (
            serde_json::json!({"JoinToken": "t"}),
            "RemoteAddrs must name at least one",
        ),
        (
            serde_json::json!({"RemoteAddrs": ["10.2.0.11:2377"]}),
            "JoinToken is required",
        ),
    ] {
        let (state, recorder) = MockBackend::new().into_state();
        let response = send_json(&state, "POST", "/swarm/join", Some(body)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            body_json(response).await["message"]
                .as_str()
                .expect("message")
                .contains(expected)
        );
        assert!(recorder.calls().is_empty());
    }
}

#[tokio::test]
async fn swarm_leave_forwards_the_force_flag() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "POST", "/swarm/leave", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorder.only_call(), Call::SwarmLeave(false));

    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "POST", "/swarm/leave?force=1", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorder.only_call(), Call::SwarmLeave(true));
}

#[tokio::test]
async fn swarm_update_rotates_the_requested_tokens() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.swarm = Some(sample_swarm()))
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/swarm/update?version=11&rotateWorkerToken=true",
        Some(serde_json::json!({"Name": "default"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    // SatL answers with the refreshed document where Docker sends no body.
    assert_eq!(
        body_json(response).await["JoinTokens"]["Worker"],
        "SATL-1-worker-token"
    );
    assert_eq!(
        recorder.only_call(),
        Call::SwarmRotateToken(TokenRole::Worker)
    );

    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.swarm = Some(sample_swarm()))
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/swarm/update?version=11&rotateWorkerToken=1&rotateManagerToken=1",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        recorder.calls(),
        [
            Call::SwarmRotateToken(TokenRole::Worker),
            Call::SwarmRotateToken(TokenRole::Manager),
        ]
    );
}

/// `docker swarm ca --rotate` semantics: a `CAConfig.ForceRotate` above the
/// stored counter starts a root CA rotation; the same value resent (what a
/// token-rotation client's read-modify-write carries) starts nothing.
#[tokio::test]
async fn swarm_update_rotates_the_root_ca_on_a_force_rotate_bump() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.swarm = Some(sample_swarm()))
        .into_state();
    // sample_swarm's spec has ForceRotate 0; asking for 1 is a rotation.
    let response = send_json(
        &state,
        "POST",
        "/swarm/update?version=11",
        Some(serde_json::json!({"Name": "default", "CAConfig": {"ForceRotate": 1}})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        recorder.calls(),
        [Call::SwarmInspect, Call::SwarmRotateCa(1)]
    );

    // The stored value resent verbatim triggers nothing — with a token
    // rotation alongside, only the token rotates.
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.swarm = Some(sample_swarm()))
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/swarm/update?version=11&rotateWorkerToken=1",
        Some(serde_json::json!({"Name": "default", "CAConfig": {"ForceRotate": 0}})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        recorder.calls(),
        [
            Call::SwarmInspect,
            Call::SwarmRotateToken(TokenRole::Worker)
        ]
    );

    // And alone, it is the unsupported-spec-update refusal.
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.swarm = Some(sample_swarm()))
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/swarm/update?version=11",
        Some(serde_json::json!({"Name": "default", "CAConfig": {"ForceRotate": 0}})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(recorder.calls(), [Call::SwarmInspect]);
}

#[tokio::test]
async fn swarm_update_refuses_what_it_cannot_do() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "POST", "/swarm/update?version=11", None).await;
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert!(
        body_json(response).await["message"]
            .as_str()
            .expect("message")
            .contains("updating the cluster spec is not supported"),
    );
    assert!(recorder.calls().is_empty());
}

#[tokio::test]
async fn swarm_update_toggles_autolock_and_rotates_the_unlock_key() {
    // Autolock on: a changed EncryptionConfig reaches the backend.
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.swarm = Some(sample_swarm()))
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/swarm/update?version=11",
        Some(serde_json::json!({
            "Name": "default",
            "EncryptionConfig": {"AutoLockManagers": true}
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        recorder.calls(),
        [Call::SwarmInspect, Call::SwarmSetAutolock(true)]
    );

    // The same flag again: no change, no call.
    let mut locked = sample_swarm();
    locked.spec.autolock = true;
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.swarm = Some(locked.clone()))
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/swarm/update?version=12",
        Some(serde_json::json!({
            "Name": "default",
            "EncryptionConfig": {"AutoLockManagers": true}
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(recorder.calls(), [Call::SwarmInspect]);

    // Key rotation goes straight to the backend.
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.swarm = Some(locked))
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/swarm/update?version=12&rotateManagerUnlockKey=1",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorder.calls(), [Call::SwarmRotateUnlockKey]);
}

/// `POST /swarm/unlock` on a daemon whose store is open is always a 503 —
/// the locked listener answers it only while the store is sealed.
#[tokio::test]
async fn swarm_unlock_on_a_running_daemon_is_a_503() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/swarm/unlock",
        Some(serde_json::json!({"UnlockKey": "anything"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body_json(response).await["message"]
            .as_str()
            .expect("message")
            .contains("not locked")
    );
    assert!(recorder.calls().is_empty());
}

#[tokio::test]
async fn swarm_unlockkey_reads_the_key_from_the_backend() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.unlock_key = "dGhlLWtleQ==".to_owned())
        .into_state();
    let response = send_json(&state, "GET", "/swarm/unlockkey", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["UnlockKey"], "dGhlLWtleQ==");
    assert_eq!(recorder.calls(), [Call::SwarmUnlockKey]);
}

// ---------------------------------------------------------------------------
// M2 — nodes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_nodes_uses_docker_keys() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.nodes = vec![NodeSummary::from(sample_node())])
        .into_state();
    let response = send_json(&state, "GET", "/v1.43/nodes", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;

    let node = &json[0];
    assert_eq!(node["ID"], NODE_ID);
    assert_eq!(node["Version"]["Index"], 7);
    assert_eq!(node["CreatedAt"], "2026-02-02T02:40:00Z");
    assert_eq!(node["Spec"]["Name"], "alpha");
    assert_eq!(node["Spec"]["Role"], "manager");
    assert_eq!(node["Spec"]["Availability"], "active");
    assert_eq!(node["Spec"]["Labels"]["zone"], "a");
    assert_eq!(node["Description"]["Hostname"], "alpha");
    assert_eq!(node["Description"]["Platform"]["OS"], "freebsd");
    assert_eq!(node["Description"]["Platform"]["Architecture"], "amd64");
    assert_eq!(
        node["Description"]["Resources"]["MemoryBytes"],
        34_359_738_368_i64
    );
    assert_eq!(node["Description"]["Engine"]["EngineVersion"], "0.1.0");
    assert_eq!(node["Status"]["State"], "ready");
    assert_eq!(node["Status"]["Addr"], "10.2.0.11");
    assert_eq!(node["ManagerStatus"]["Leader"], true);
    assert_eq!(node["ManagerStatus"]["Reachability"], "reachable");
    assert_eq!(node["ManagerStatus"]["Addr"], "10.2.0.11:2377");
    assert_eq!(recorder.only_call(), Call::ListNodes);
}

#[tokio::test]
async fn list_nodes_refuses_filters_rather_than_ignoring_them() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "GET",
        "/nodes?filters=%7B%22role%22%3A%5B%22manager%22%5D%7D",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert!(
        body_json(response).await["message"]
            .as_str()
            .expect("message")
            .contains("filtering nodes is not supported")
    );
    assert!(recorder.calls().is_empty());
}

#[tokio::test]
async fn inspect_node_and_its_404() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.node = Some(NodeDetail::from(sample_node())))
        .into_state();
    let response = send_json(&state, "GET", "/nodes/alpha", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["ID"], NODE_ID);
    assert_eq!(recorder.only_call(), Call::InspectNode("alpha".to_owned()));

    let (state, _) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/nodes/ghost", None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(response).await["message"], "node ghost not found");
}

#[tokio::test]
async fn update_node_carries_the_version_and_the_whole_spec() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/nodes/alpha/update?version=7",
        Some(serde_json::json!({
            "Name": "alpha",
            "Labels": {"zone": "b"},
            "Role": "worker",
            "Availability": "drain"
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let Call::UpdateNode(node, version, spec) = recorder.only_call() else {
        panic!("expected an update_node call");
    };
    assert_eq!(node, "alpha");
    assert_eq!(version, Version(7));
    assert_eq!(spec.name.as_deref(), Some("alpha"));
    assert_eq!(spec.labels["zone"], "b");
    assert_eq!(spec.role, NodeRole::Worker);
    assert_eq!(spec.availability, Availability::Drain);
}

#[tokio::test]
async fn update_node_rejects_a_missing_version_and_bad_enums() {
    for (path, body, expected) in [
        (
            "/nodes/alpha/update",
            serde_json::json!({"Role": "worker", "Availability": "active"}),
            "version is required",
        ),
        (
            "/nodes/alpha/update?version=abc",
            serde_json::json!({"Role": "worker", "Availability": "active"}),
            "invalid version",
        ),
        (
            "/nodes/alpha/update?version=7",
            serde_json::json!({"Role": "boss", "Availability": "active"}),
            "invalid role",
        ),
        (
            "/nodes/alpha/update?version=7",
            serde_json::json!({"Role": "worker", "Availability": "asleep"}),
            "invalid availability",
        ),
    ] {
        let (state, recorder) = MockBackend::new().into_state();
        let response = send_json(&state, "POST", path, Some(body)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "for {path}");
        assert!(
            body_json(response).await["message"]
                .as_str()
                .expect("message")
                .contains(expected),
            "for {path}"
        );
        assert!(recorder.calls().is_empty());
    }
}

#[tokio::test]
async fn remove_node_forwards_force() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "DELETE", "/nodes/alpha?force=1", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        recorder.only_call(),
        Call::RemoveNode("alpha".to_owned(), true)
    );
}

// ---------------------------------------------------------------------------
// M2 — services
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_service_returns_201_and_converts_the_spec() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.service_created = ServiceCreated {
                id: SERVICE_ID.to_owned(),
                warnings: vec!["rctl is disabled: --limit-memory will not be enforced".to_owned()],
            };
        })
        .into_state();

    let response = send_json(
        &state,
        "POST",
        "/v1.43/services/create",
        Some(serde_json::json!({
            "Name": "web",
            "Labels": {"tier": "front"},
            "TaskTemplate": {
                "ContainerSpec": {"Image": "nginx:1.27", "Env": ["A=1"]},
                "Resources": {"Limits": {"NanoCPUs": 1_500_000_000_i64, "MemoryBytes": 536_870_912_i64}},
                "RestartPolicy": {"Condition": "on-failure", "Delay": 5_000_000_000_i64},
                "Placement": {"Constraints": ["node.labels.zone == a"], "MaxReplicas": 2},
                "Networks": [{"Target": "backend"}]
            },
            "Mode": {"Replicated": {"Replicas": 3}},
            "UpdateConfig": {"Parallelism": 2, "Delay": 10_000_000_000_i64},
            "EndpointSpec": {"Ports": [
                {"Protocol": "tcp", "TargetPort": 80, "PublishedPort": 8080, "PublishMode": "ingress"}
            ]}
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    assert_eq!(json["ID"], SERVICE_ID);
    assert_eq!(
        json["Warnings"][0],
        "rctl is disabled: --limit-memory will not be enforced"
    );
    assert_eq!(json.as_object().expect("object").len(), 2);

    let Call::CreateService(options) = recorder.only_call() else {
        panic!("expected a create_service call");
    };
    let spec = &options.spec;
    assert_eq!(spec.annotations.name, "web");
    assert_eq!(spec.annotations.labels["tier"], "front");
    assert_eq!(spec.mode, ServiceMode::Replicated { replicas: 3 });
    assert_eq!(spec.task.container.image, "nginx:1.27");
    assert_eq!(spec.task.container.env, ["A=1"]);
    assert_eq!(
        spec.task.resources.limits.expect("limits").memory_bytes,
        536_870_912
    );
    assert_eq!(spec.task.restart.condition, RestartCondition::OnFailure);
    assert_eq!(spec.task.placement.constraints, ["node.labels.zone == a"]);
    assert_eq!(spec.task.placement.max_replicas, 2);
    assert_eq!(spec.task.networks[0].target, "backend");
    assert_eq!(spec.update.expect("update").parallelism, 2);
    let endpoint = spec.endpoint.as_ref().expect("endpoint");
    assert_eq!(endpoint.ports[0].published_port, 8080);
    assert_eq!(endpoint.ports[0].publish_mode, PublishMode::Ingress);
    assert!(options.registry_auth.is_none());
}

#[tokio::test]
async fn create_service_decodes_the_registry_auth_header() {
    use base64::Engine as _;

    let (state, recorder) = MockBackend::new().into_state();
    let auth = base64::engine::general_purpose::URL_SAFE
        .encode(serde_json::json!({"username": "bob", "password": "s3cret"}).to_string());
    let request = Request::builder()
        .method("POST")
        .uri("/services/create")
        .header("Content-Type", "application/json")
        .header("X-Registry-Auth", auth)
        .body(Body::from(
            serde_json::json!({
                "Name": "web",
                "TaskTemplate": {"ContainerSpec": {"Image": "nginx"}}
            })
            .to_string(),
        ))
        .expect("valid request");
    let response = send_to(&state, request).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let Call::CreateService(options) = recorder.only_call() else {
        panic!("expected a create_service call");
    };
    let auth = options.registry_auth.expect("decoded auth");
    assert_eq!(auth.username, "bob");
    assert_eq!(auth.password, "s3cret");
}

#[tokio::test]
async fn create_service_rejects_unsupported_specs_with_docker_error_shape() {
    let cases: [(Value, &str); 6] = [
        (
            serde_json::json!({"Name": "web", "TaskTemplate": {"ContainerSpec": {}}}),
            "no image specified",
        ),
        (
            serde_json::json!({"Name": "web",
                "TaskTemplate": {"ContainerSpec": {"Image": "n"}},
                "EndpointSpec": {"Mode": "vip"}}),
            "Mode=vip is not supported",
        ),
        (
            serde_json::json!({"Name": "web", "TaskTemplate": {
                "ContainerSpec": {"Image": "n", "Sysctls": {"a": "b"}}}}),
            "Sysctls is not supported",
        ),
        (
            serde_json::json!({"Name": "web", "TaskTemplate": {
                "ContainerSpec": {"Image": "n"},
                "Placement": {"Preferences": [{"Spread": {}}]}}}),
            "invalid spread descriptor",
        ),
        (
            serde_json::json!({"Name": "web", "TaskTemplate": {
                "ContainerSpec": {"Image": "n"},
                "Placement": {"Preferences": [{"Pin": {"Node": "a"}}]}}}),
            "only `spread` is implemented",
        ),
        (
            serde_json::json!({"Name": "web",
                "TaskTemplate": {"ContainerSpec": {"Image": "n"}},
                "Mode": {"Replicated": {"Replicas": 1}, "Global": {}}}),
            "exactly one of Replicated, Global",
        ),
    ];
    for (body, expected) in cases {
        let (state, recorder) = MockBackend::new().into_state();
        let response = send_json(&state, "POST", "/services/create", Some(body.clone())).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "for {body}");
        let message = body_json(response).await;
        let message = message["message"].as_str().expect("Docker error envelope");
        assert!(message.contains(expected), "for {body}: got {message:?}");
        assert!(recorder.calls().is_empty());
    }
}

#[tokio::test]
async fn list_services_attaches_status_only_when_asked() {
    let answers = |answers: &mut mock::Answers| {
        answers.services = vec![ServiceSummary {
            service: sample_service(),
            tasks: ServiceTaskCounts {
                running: 2,
                desired: 3,
                completed: 0,
            },
        }];
    };

    let (state, recorder) = MockBackend::new().answer(answers).into_state();
    let response = send_json(&state, "GET", "/services", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json[0]["ID"], SERVICE_ID);
    assert_eq!(json[0]["Spec"]["Name"], "web");
    assert_eq!(json[0]["Spec"]["Mode"]["Replicated"]["Replicas"], 3);
    assert_eq!(
        json[0]["Spec"]["TaskTemplate"]["ContainerSpec"]["Image"],
        "nginx:1.27"
    );
    assert_eq!(json[0]["Endpoint"]["Ports"][0]["PublishedPort"], 8080);
    assert!(json[0].get("ServiceStatus").is_none());
    assert_eq!(recorder.only_call(), Call::ListServices);

    let (state, _) = MockBackend::new().answer(answers).into_state();
    let response = send_json(&state, "GET", "/v1.43/services?status=true", None).await;
    let json = body_json(response).await;
    assert_eq!(json[0]["ServiceStatus"]["RunningTasks"], 2);
    assert_eq!(json[0]["ServiceStatus"]["DesiredTasks"], 3);
}

#[tokio::test]
async fn inspect_service_and_its_404() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.service = Some(ServiceDetail {
                service: sample_service(),
            });
        })
        .into_state();
    let response = send_json(&state, "GET", "/services/web", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["ID"], SERVICE_ID);
    assert_eq!(json["Version"]["Index"], 7);
    assert!(json.get("ServiceStatus").is_none());
    assert_eq!(recorder.only_call(), Call::InspectService("web".to_owned()));

    let (state, _) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/services/ghost", None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_service_returns_warnings_and_records_the_version() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.service_warnings = vec!["image pinned to a digest".to_owned()])
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/services/web/update?version=7",
        Some(serde_json::json!({
            "Name": "web",
            "TaskTemplate": {"ContainerSpec": {"Image": "nginx:1.28"}},
            "Mode": {"Replicated": {"Replicas": 5}}
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["Warnings"][0], "image pinned to a digest");

    let Call::UpdateService(service, version, options) = recorder.only_call() else {
        panic!("expected an update_service call");
    };
    assert_eq!(service, "web");
    assert_eq!(version, Version(7));
    assert!(!options.rollback);
    assert_eq!(options.spec.task.container.image, "nginx:1.28");
    assert_eq!(options.spec.mode, ServiceMode::Replicated { replicas: 5 });
}

#[tokio::test]
async fn update_service_understands_rollback_and_rejects_junk() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/services/web/update?version=7&rollback=previous",
        Some(serde_json::json!({
            "Name": "web",
            "TaskTemplate": {"ContainerSpec": {"Image": "nginx"}}
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let Call::UpdateService(_, _, options) = recorder.only_call() else {
        panic!("expected an update_service call");
    };
    assert!(options.rollback);

    let (state, _) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/services/web/update?version=7&rollback=forward",
        Some(serde_json::json!({"TaskTemplate": {"ContainerSpec": {"Image": "n"}}})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_json(response).await["message"]
            .as_str()
            .expect("message")
            .contains("invalid rollback")
    );
}

#[tokio::test]
async fn remove_service_answers_200() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "DELETE", "/services/web", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorder.only_call(), Call::RemoveService("web".to_owned()));
}

// ---------------------------------------------------------------------------
// M2 — tasks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_tasks_renders_docker_task_documents() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.tasks = vec![TaskSummary::from(sample_task())])
        .into_state();
    let response = send_json(&state, "GET", "/v1.43/tasks", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;

    let task = &json[0];
    assert_eq!(task["ID"], TASK_ID);
    assert_eq!(task["Version"]["Index"], 7);
    assert_eq!(task["Name"], format!("web.1.{TASK_ID}"));
    assert_eq!(task["ServiceID"], SERVICE_ID);
    assert_eq!(task["NodeID"], NODE_ID);
    assert_eq!(task["Slot"], 1);
    assert_eq!(task["DesiredState"], "running");
    assert_eq!(task["Status"]["State"], "running");
    assert_eq!(task["Status"]["Message"], "started");
    assert_eq!(task["Status"]["Timestamp"], "2026-02-02T02:45:00Z");
    assert_eq!(task["Status"]["ContainerStatus"]["ContainerID"], TASK_ID);
    assert_eq!(task["Status"]["ContainerStatus"]["PID"], 4242);
    assert_eq!(task["Spec"]["ContainerSpec"]["Image"], "nginx:1.27");
    assert_eq!(
        recorder.only_call(),
        Call::ListTasks(TaskFilters::default())
    );
}

#[tokio::test]
async fn list_tasks_parses_both_docker_filter_encodings() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "GET",
        "/tasks?filters=%7B%22service%22%3A%7B%22web%22%3Atrue%7D%2C%22desired-state%22%3A%5B%22running%22%5D%7D",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let Call::ListTasks(filters) = recorder.only_call() else {
        panic!("expected a list_tasks call");
    };
    assert_eq!(filters.services, ["web"]);
    assert_eq!(filters.desired_states, [DesiredState::Running]);
    assert!(filters.nodes.is_empty());
}

#[tokio::test]
async fn list_tasks_rejects_unknown_filters() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "GET",
        "/tasks?filters=%7B%22colour%22%3A%5B%22red%22%5D%7D",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_json(response).await["message"]
            .as_str()
            .expect("message")
            .contains("invalid filter")
    );
    assert!(recorder.calls().is_empty());
}

#[tokio::test]
async fn inspect_task_and_its_404() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.task = Some(TaskDetail::from(sample_task())))
        .into_state();
    let response = send_json(&state, "GET", &format!("/tasks/{TASK_ID}"), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["ID"], TASK_ID);
    assert_eq!(recorder.only_call(), Call::InspectTask(TASK_ID.to_owned()));

    let (state, _) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/tasks/ghost", None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// M2 — /info's Swarm section and the unwired backend
// ---------------------------------------------------------------------------

#[tokio::test]
async fn info_reports_live_cluster_state_when_the_backend_has_it() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.swarm_status = Some(SwarmStatus {
                node_id: NODE_ID.to_owned(),
                node_addr: "10.2.0.11".to_owned(),
                local_node_state: LocalNodeState::Active,
                control_available: true,
                error: String::new(),
                remote_managers: vec![ManagerPeer {
                    node_id: NODE_ID.to_owned(),
                    addr: "10.2.0.11:2377".to_owned(),
                }],
                nodes: 3,
                managers: 1,
            });
        })
        .into_state();
    let response = send_json(&state, "GET", "/info", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;

    assert_eq!(json["Swarm"]["NodeID"], NODE_ID);
    assert_eq!(json["Swarm"]["NodeAddr"], "10.2.0.11");
    assert_eq!(json["Swarm"]["LocalNodeState"], "active");
    assert_eq!(json["Swarm"]["ControlAvailable"], true);
    assert_eq!(json["Swarm"]["Nodes"], 3);
    assert_eq!(json["Swarm"]["Managers"], 1);
    assert_eq!(json["Swarm"]["RemoteManagers"][0]["NodeID"], NODE_ID);
    assert_eq!(json["Swarm"]["RemoteManagers"][0]["Addr"], "10.2.0.11:2377");
    assert_eq!(recorder.calls(), [Call::SystemCounts, Call::SwarmStatus]);
}

#[tokio::test]
async fn info_reports_an_inactive_swarm_on_a_node_that_left() {
    let (state, _) = MockBackend::new()
        .answer(|answers| answers.swarm_status = Some(SwarmStatus::default()))
        .into_state();
    let json = body_json(send_json(&state, "GET", "/info", None).await).await;
    assert_eq!(json["Swarm"]["LocalNodeState"], "inactive");
    assert_eq!(json["Swarm"]["ControlAvailable"], false);
    assert!(json["Swarm"]["RemoteManagers"].is_null());
    assert!(json["Swarm"].get("Nodes").is_none());
}

#[tokio::test]
async fn m2_endpoints_answer_501_on_an_unwired_backend() {
    let state = mock::test_state();
    for (method, path) in [
        ("GET", "/swarm"),
        ("POST", "/swarm/init"),
        ("POST", "/swarm/leave"),
        ("GET", "/nodes"),
        ("GET", "/nodes/alpha"),
        ("DELETE", "/nodes/alpha"),
        ("GET", "/services"),
        ("GET", "/services/web"),
        ("DELETE", "/services/web"),
        ("GET", "/tasks"),
        ("GET", "/tasks/abc"),
    ] {
        let response = send_json(&state, method, path, None).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_IMPLEMENTED,
            "for {method} {path}"
        );
        assert_eq!(
            body_json(response).await["message"],
            "daemon wiring pending",
            "for {method} {path}"
        );
    }
}

#[tokio::test]
async fn m2_backend_errors_map_to_docker_status_codes() {
    for (error, status) in [
        (
            BackendError::not_found("no such service: web"),
            StatusCode::NOT_FOUND,
        ),
        (
            BackendError::conflict("update out of sequence"),
            StatusCode::CONFLICT,
        ),
        (BackendError::invalid("bad spec"), StatusCode::BAD_REQUEST),
        (
            BackendError::internal("raft proposal failed"),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ] {
        let expected = error.to_string();
        let (state, _) = MockBackend::failing(error).into_state();
        let response = send_json(&state, "GET", "/services", None).await;
        assert_eq!(response.status(), status, "for {expected}");
        assert_eq!(body_json(response).await["message"], expected);
    }
}

#[tokio::test]
async fn m2_paths_are_reachable_under_a_version_prefix() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/v1.43/tasks", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        recorder.only_call(),
        Call::ListTasks(TaskFilters::default())
    );

    let (state, _) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/v1.44/nodes", None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// M3 — networks
// ---------------------------------------------------------------------------

/// An overlay network as the allocator leaves it, with a gateway address on the
/// node answering the request (`Network.node_gateways`).
fn sample_network() -> Network {
    Network {
        id: "1hvy0lj3x0b883f8e30fyp217".parse().expect("valid id"),
        meta: Meta {
            version: Version(7),
            created_at: at(1_770_000_000),
            updated_at: at(1_770_000_500),
        },
        spec: NetworkSpec {
            annotations: Annotations {
                name: "blue".to_owned(),
                labels: BTreeMap::from([("owner".to_owned(), "web".to_owned())]),
            },
            driver: NetworkDriver::Overlay,
            ipam: Some(IpamConfig {
                subnet: Some("10.100.4.0/24".to_owned()),
                gateway: None,
                ip_range: None,
            }),
            internal: false,
            attachable: false,
            ingress: false,
            encrypted: false,
        },
        vni: Some(4_096),
        vxlan_port: None,
        subnet: Some("10.100.4.0/24".to_owned()),
        node_gateways: BTreeMap::new(),
        keys: Vec::new(),
        keys_updated_at: None,
    }
}

fn sample_network_summary() -> NetworkSummary {
    NetworkSummary {
        network: sample_network(),
        gateway: Some("10.100.4.2".to_owned()),
    }
}

#[tokio::test]
async fn network_list_and_inspect_render_docker_shapes() {
    // List.
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.networks = vec![sample_network_summary()])
        .into_state();
    let response = send_json(&state, "GET", "/networks", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json[0]["Name"], "blue");
    assert_eq!(json[0]["Id"], "1hvy0lj3x0b883f8e30fyp217");
    assert_eq!(json[0]["Driver"], "overlay");
    assert_eq!(json[0]["Scope"], "swarm", "an overlay is cluster-wide");
    assert_eq!(json[0]["Created"], "2026-02-02T02:40:00Z");
    assert_eq!(json[0]["EnableIPv6"], false);
    assert_eq!(json[0]["Internal"], false);
    assert_eq!(json[0]["Attachable"], false);
    assert_eq!(json[0]["Ingress"], false);
    assert_eq!(json[0]["ConfigOnly"], false);
    assert_eq!(json[0]["IPAM"]["Driver"], "default");
    assert_eq!(json[0]["IPAM"]["Config"][0]["Subnet"], "10.100.4.0/24");
    assert_eq!(
        json[0]["IPAM"]["Config"][0]["Gateway"], "10.100.4.2",
        "the gateway is this node's, not a cluster-wide one"
    );
    assert_eq!(json[0]["Labels"]["owner"], "web");
    assert_eq!(json[0]["Vni"], 4096, "the SatL vni extension");
    assert!(json[0]["Containers"].is_object());
    assert_eq!(recorder.only_call(), Call::ListNetworks);

    // A bridge network is node-local.
    let mut local = sample_network_summary();
    local.network.spec.driver = NetworkDriver::Bridge;
    local.network.vni = None;
    let (state, _) = MockBackend::new()
        .answer(|answers| answers.networks = vec![local])
        .into_state();
    let json = body_json(send_json(&state, "GET", "/networks", None).await).await;
    assert_eq!(json[0]["Driver"], "bridge");
    assert_eq!(json[0]["Scope"], "local");
    assert!(json[0].get("Vni").is_none(), "no vni without an overlay");

    // Inspect, with the attached tasks in Docker's `Containers` map.
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.network = Some(NetworkDetail {
                network: sample_network(),
                gateway: Some("10.100.4.2".to_owned()),
                endpoints: vec![NetworkEndpointInfo {
                    task_id: "2r1h539fesw6ri0hn141a994y".to_owned(),
                    name: "web.1.2r1h539fesw6ri0hn141a994y".to_owned(),
                    address: "10.100.4.5/24".to_owned(),
                    mac_address: "02:42:0a:64:04:05".to_owned(),
                }],
            });
        })
        .into_state();
    let response = send_json(&state, "GET", "/networks/blue", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let entry = &json["Containers"]["2r1h539fesw6ri0hn141a994y"];
    assert_eq!(entry["Name"], "web.1.2r1h539fesw6ri0hn141a994y");
    assert_eq!(entry["EndpointID"], "2r1h539fesw6ri0hn141a994y");
    assert_eq!(entry["IPv4Address"], "10.100.4.5/24");
    assert_eq!(
        entry["MacAddress"], "02:42:0a:64:04:05",
        "derived from the address, never allocated"
    );
    assert_eq!(entry["IPv6Address"], "");
    assert_eq!(
        recorder.only_call(),
        Call::InspectNetwork("blue".to_owned())
    );

    // A missing network is Docker's 404.
    let (state, _) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/networks/ghost", None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(response).await["message"],
        "network ghost not found"
    );
}

#[tokio::test]
async fn network_create_and_remove_convert_the_body_and_answer_docker_codes() {
    // Create.
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.network_created = NetworkCreated {
                id: "1hvy0lj3x0b883f8e30fyp217".to_owned(),
                warning: String::new(),
            };
        })
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/networks/create",
        Some(serde_json::json!({
            "Name": "blue",
            "Driver": "overlay",
            "CheckDuplicate": null,
            "EnableIPv6": null,
            "Labels": {"owner": "web"},
            "IPAM": {"Driver": "default", "Config": [{"Subnet": "10.100.4.0/24", "Gateway": "10.100.4.1"}]}
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    assert_eq!(json["Id"], "1hvy0lj3x0b883f8e30fyp217");
    assert_eq!(json["Warning"], "");
    let Call::CreateNetwork(options) = recorder.only_call() else {
        panic!("expected a create_network call");
    };
    assert_eq!(options.spec.annotations.name, "blue");
    assert_eq!(options.spec.driver, NetworkDriver::Overlay);
    assert!(!options.spec.ingress);
    let ipam = options.spec.ipam.expect("ipam");
    assert_eq!(ipam.subnet.as_deref(), Some("10.100.4.0/24"));
    assert_eq!(ipam.gateway.as_deref(), Some("10.100.4.1"));

    // Create with nothing but a name: the allocator picks everything.
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/networks/create",
        Some(serde_json::json!({"Name": "green"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let Call::CreateNetwork(options) = recorder.only_call() else {
        panic!("expected a create_network call");
    };
    assert_eq!(
        options.spec.driver,
        NetworkDriver::Bridge,
        "docker's default driver is bridge"
    );
    assert!(options.spec.ipam.is_none());

    // Remove.
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "DELETE", "/networks/blue", None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(recorder.only_call(), Call::RemoveNetwork("blue".to_owned()));
}

#[tokio::test]
async fn network_create_rejects_everything_satl_cannot_honour() {
    let cases: Vec<(Value, &str)> = vec![
        (
            serde_json::json!({"Name": "blue", "EnableIPv6": true}),
            "EnableIPv6",
        ),
        (
            serde_json::json!({"Name": "blue", "Internal": true}),
            "Internal",
        ),
        (
            serde_json::json!({"Name": "blue", "Attachable": true}),
            "Attachable",
        ),
        (
            serde_json::json!({"Name": "blue", "ConfigOnly": true}),
            "ConfigOnly",
        ),
        (
            serde_json::json!({"Name": "blue", "ConfigFrom": {"Network": "template"}}),
            "ConfigFrom",
        ),
        (
            serde_json::json!({"Name": "blue", "Driver": "macvlan"}),
            "macvlan",
        ),
        (
            serde_json::json!({"Name": "blue", "Options": {"com.docker.network.driver.mtu": "1450"}}),
            "com.docker.network.driver.mtu",
        ),
        (
            serde_json::json!({"Name": "blue", "IPAM": {"Driver": "weave"}}),
            "IPAM driver",
        ),
        (
            serde_json::json!({"Name": "blue", "IPAM": {"Options": {"foo": "bar"}}}),
            "IPAM.Options",
        ),
        (
            serde_json::json!({"Name": "blue", "IPAM": {"Config": [
                {"Subnet": "10.100.4.0/24"}, {"Subnet": "10.100.5.0/24"}
            ]}}),
            "exactly one subnet",
        ),
        (
            serde_json::json!({"Name": "blue", "IPAM": {"Config": [{"Subnet": "fd00::/64"}]}}),
            "IPv4-only",
        ),
        (
            serde_json::json!({"Name": "blue", "IPAM": {"Config": [{"Subnet": "not-a-subnet"}]}}),
            "IPAM.Config.Subnet",
        ),
        (
            serde_json::json!({"Name": "blue", "IPAM": {"Config": [{"Gateway": "10.100.4.1"}]}}),
            "without a Subnet",
        ),
        (serde_json::json!({"Name": "a.b"}), "invalid network name"),
        (
            serde_json::json!({"Name": "blue", "Driver": "overlay", "Scope": "local"}),
            "the scope follows the driver",
        ),
    ];
    for (body, expected) in cases {
        let (state, recorder) = MockBackend::new().into_state();
        let response = send_json(&state, "POST", "/networks/create", Some(body.clone())).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "for {body}");
        let message = body_json(response).await["message"]
            .as_str()
            .expect("a message")
            .to_owned();
        assert!(
            message.contains(expected),
            "expected {expected:?} in {message:?}"
        );
        assert!(
            recorder.calls().is_empty(),
            "nothing reaches the daemon: {:?}",
            recorder.calls()
        );
    }
}

/// A cluster has exactly one ingress network, and the API is where the second
/// request for one is refused.
#[tokio::test]
async fn a_second_ingress_network_is_refused_before_the_daemon_sees_it() {
    let mut existing = sample_network_summary();
    existing.network.spec.ingress = true;
    existing.network.spec.annotations.name = "ingress".to_owned();
    let (state, recorder) = MockBackend::new()
        .answer(|answers| answers.networks = vec![existing])
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/networks/create",
        Some(serde_json::json!({"Name": "second", "Driver": "overlay", "Ingress": true})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let message = body_json(response).await["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(
        message.contains("already the cluster's ingress network"),
        "{message}"
    );
    assert_eq!(
        recorder.calls(),
        vec![Call::ListNetworks],
        "the create never happened"
    );

    // The first one is allowed through.
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/networks/create",
        Some(serde_json::json!({"Name": "ingress", "Driver": "overlay", "Ingress": true})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let calls = recorder.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let Call::CreateNetwork(options) = &calls[1] else {
        panic!("expected a create_network call: {calls:?}");
    };
    assert!(options.spec.ingress);
}

#[tokio::test]
async fn connect_and_disconnect_pass_the_container_and_its_aliases_through() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/networks/blue/connect",
        Some(serde_json::json!({
            "Container": "web",
            "EndpointConfig": {"Aliases": ["db", "primary"], "IPAMConfig": null}
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        recorder.only_call(),
        Call::ConnectNetwork(
            "blue".to_owned(),
            NetworkConnectOptions {
                container: "web".to_owned(),
                aliases: vec!["db".to_owned(), "primary".to_owned()],
            }
        )
    );

    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/networks/blue/disconnect",
        Some(serde_json::json!({"Container": "web", "Force": true})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        recorder.only_call(),
        Call::DisconnectNetwork(
            "blue".to_owned(),
            NetworkDisconnectOptions {
                container: "web".to_owned(),
                force: true,
            }
        )
    );
}

#[tokio::test]
async fn connect_rejects_what_the_cluster_allocator_owns() {
    let cases: Vec<(Value, &str)> = vec![
        (serde_json::json!({}), "Container is required"),
        (
            serde_json::json!({"Container": "web", "EndpointConfig": {
                "IPAMConfig": {"IPv4Address": "10.100.4.9"}
            }}),
            "IPAMConfig",
        ),
        (
            serde_json::json!({"Container": "web", "EndpointConfig": {"Links": ["db"]}}),
            "Links",
        ),
        (
            serde_json::json!({"Container": "web", "EndpointConfig": {
                "DriverOpts": {"foo": "bar"}
            }}),
            "DriverOpts",
        ),
    ];
    for (body, expected) in cases {
        let (state, recorder) = MockBackend::new().into_state();
        let response =
            send_json(&state, "POST", "/networks/blue/connect", Some(body.clone())).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "for {body}");
        let message = body_json(response).await["message"]
            .as_str()
            .expect("a message")
            .to_owned();
        assert!(
            message.contains(expected),
            "expected {expected:?} in {message:?}"
        );
        assert!(recorder.calls().is_empty());
    }

    // Disconnect needs a container too.
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/networks/blue/disconnect",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(recorder.calls().is_empty());
}

#[tokio::test]
async fn network_listing_refuses_filters_it_does_not_implement() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "GET",
        "/networks?filters=%7B%22driver%22%3A%5B%22overlay%22%5D%7D",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert!(recorder.calls().is_empty());
}

#[tokio::test]
async fn network_paths_are_reachable_under_a_version_prefix() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "GET", "/v1.43/networks", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorder.only_call(), Call::ListNetworks);
}

// ---------------------------------------------------------------------------
// M5 — secrets and configs
// ---------------------------------------------------------------------------

/// `s3cr3t` in standard base64, and the payload every secret test round-trips.
const SECRET_PAYLOAD: &str = "czNjcjN0";

fn secret_object(name: &str, payload: &[u8]) -> Secret {
    Secret {
        id: Id::generate(),
        meta: Meta {
            version: Version(3),
            created_at: at(1_770_000_000),
            updated_at: at(1_770_000_600),
        },
        spec: SecretSpec::new(
            Annotations {
                name: name.to_owned(),
                labels: BTreeMap::from([("env".to_owned(), "prod".to_owned())]),
            },
            payload.to_vec(),
        )
        .expect("a valid secret"),
    }
}

fn config_object(name: &str, payload: &[u8]) -> Config {
    Config {
        id: Id::generate(),
        meta: Meta {
            version: Version(4),
            created_at: at(1_770_000_000),
            updated_at: at(1_770_000_600),
        },
        spec: ConfigSpec::new(
            Annotations {
                name: name.to_owned(),
                labels: BTreeMap::new(),
            },
            payload.to_vec(),
        )
        .expect("a valid config"),
    }
}

/// Create answers Docker's 201 + `{"ID": ...}`, and the payload the client
/// base64-encoded arrives at the backend as the bytes it started as.
#[tokio::test]
async fn secret_create_answers_an_id_and_decodes_the_payload() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.secret_created = SecretCreated {
                id: "1hvy0lj3x0b883f8e30fyp217".to_owned(),
            };
        })
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/secrets/create",
        Some(serde_json::json!({
            "Name": "db_password",
            "Labels": {"env": "prod"},
            "Data": SECRET_PAYLOAD
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(body_json(response).await["ID"], "1hvy0lj3x0b883f8e30fyp217");
    let Call::CreateSecret(spec) = recorder.only_call() else {
        panic!("expected a create_secret call");
    };
    assert_eq!(spec.annotations.name, "db_password");
    assert_eq!(spec.annotations.labels["env"], "prod");
    assert_eq!(spec.data(), b"s3cr3t");
    assert!(
        !format!("{spec:?}").contains("s3cr3t"),
        "even Debug must redact the payload"
    );
}

/// The same for a config, whose limit (and therefore whose body cap) is twice a
/// secret's.
#[tokio::test]
async fn config_create_answers_an_id_and_decodes_the_payload() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.config_created = ConfigCreated {
                id: "2hvy0lj3x0b883f8e30fyp217".to_owned(),
            };
        })
        .into_state();
    let response = send_json(
        &state,
        "POST",
        "/v1.43/configs/create",
        Some(serde_json::json!({"Name": "nginx_conf", "Data": "c2VydmVyIHt9"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(body_json(response).await["ID"], "2hvy0lj3x0b883f8e30fyp217");
    let Call::CreateConfig(spec) = recorder.only_call() else {
        panic!("expected a create_config call");
    };
    assert_eq!(spec.annotations.name, "nginx_conf");
    assert_eq!(spec.data(), b"server {}");
}

/// The compatibility surface that is also a security property: no response on
/// `/secrets` carries a payload, on list or on inspect.
#[tokio::test]
async fn secret_reads_never_carry_the_payload() {
    let object = secret_object("db_password", b"s3cr3t");
    let id = object.id.to_string();
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.secrets = vec![object.clone()];
            answers.secret = Some(object.clone());
        })
        .into_state();

    for path in ["/secrets", &format!("/secrets/{id}")] {
        let response = send_json(&state, "GET", path, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let raw = String::from_utf8(body_bytes(response).await).expect("utf-8");
        assert!(
            !raw.contains("s3cr3t") && !raw.contains(SECRET_PAYLOAD),
            "{path} leaked a payload: {raw}"
        );
        assert!(
            !raw.contains("\"Data\""),
            "{path} rendered a Data key: {raw}"
        );
        let json: Value = serde_json::from_str(&raw).expect("valid json");
        let document = if json.is_array() { &json[0] } else { &json };
        assert_eq!(document["ID"], id);
        assert_eq!(document["Version"]["Index"], 3);
        assert_eq!(document["Spec"]["Name"], "db_password");
        assert_eq!(document["Spec"]["Labels"]["env"], "prod");
    }
    assert_eq!(
        recorder.calls(),
        vec![Call::ListSecrets, Call::InspectSecret(id)]
    );
}

/// A config *does* return its payload — Docker's does, and `satl config
/// inspect` has nothing to show otherwise.
#[tokio::test]
async fn config_reads_carry_the_payload_base64_encoded() {
    let object = config_object("nginx_conf", b"server {}");
    let id = object.id.to_string();
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.configs = vec![object.clone()];
            answers.config = Some(object.clone());
        })
        .into_state();

    let response = send_json(&state, "GET", "/configs", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json[0]["Spec"]["Data"], "c2VydmVyIHt9");

    let response = send_json(&state, "GET", &format!("/configs/{id}"), None).await;
    let json = body_json(response).await;
    assert_eq!(json["ID"], id);
    assert_eq!(json["Version"]["Index"], 4);
    assert_eq!(json["Spec"]["Data"], "c2VydmVyIHt9");
    assert_eq!(
        recorder.calls(),
        vec![Call::ListConfigs, Call::InspectConfig(id)]
    );
}

/// Every 400 a create can answer, and the one thing none of them may contain.
#[tokio::test]
async fn secret_create_rejects_bad_bodies_without_echoing_the_payload() {
    let cases: Vec<(Value, &str)> = vec![
        (
            serde_json::json!({"Name": "-bad-", "Data": SECRET_PAYLOAD}),
            "invalid secret name",
        ),
        (
            serde_json::json!({"Name": "db_password"}),
            "data is required",
        ),
        (
            serde_json::json!({"Name": "db_password", "Data": ""}),
            "data is required",
        ),
        (
            serde_json::json!({"Name": "db_password", "Data": "!!not base64!!"}),
            "base64",
        ),
        (
            serde_json::json!({"Name": "db_password", "Data": SECRET_PAYLOAD,
                "Driver": {"Name": "vault"}}),
            "secret drivers are not supported",
        ),
    ];
    for (body, expected) in cases {
        let (state, recorder) = MockBackend::new().into_state();
        let response = send_json(&state, "POST", "/secrets/create", Some(body.clone())).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "must reject {body}"
        );
        let message = body_json(response).await["message"]
            .as_str()
            .expect("a message")
            .to_owned();
        assert!(message.contains(expected), "for {body}: {message}");
        assert!(
            !message.contains(SECRET_PAYLOAD),
            "a 400 must not echo the payload: {message}"
        );
        assert!(recorder.calls().is_empty(), "for {body}");
    }
}

/// The size limit is `satl-core`'s, and the refusal says where it is.
#[tokio::test]
async fn an_oversized_secret_is_refused_with_the_limit_in_the_message() {
    let oversized = base64::engine::general_purpose::STANDARD.encode(vec![b'x'; 500 * 1024]);
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/secrets/create",
        Some(serde_json::json!({"Name": "big", "Data": oversized})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let message = body_json(response).await["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(message.contains("512000"), "{message}");
    assert!(!message.contains("xxxx"), "{message}");
    assert!(recorder.calls().is_empty());
}

/// Removal is Docker's 204, and it forwards the client's own reference.
#[tokio::test]
async fn secret_and_config_removal_answer_204() {
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "DELETE", "/secrets/db_password", None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        recorder.only_call(),
        Call::RemoveSecret("db_password".to_owned())
    );

    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(&state, "DELETE", "/configs/nginx_conf", None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        recorder.only_call(),
        Call::RemoveConfig("nginx_conf".to_owned())
    );
}

/// The update endpoint exists and refuses, with the rotation recipe in the
/// message — a 404 would look like a missing route.
#[tokio::test]
async fn the_update_endpoints_refuse_with_the_rotation_recipe() {
    for (path, kind) in [
        ("/secrets/db_password/update?version=3", "secrets"),
        ("/configs/nginx_conf/update?version=4", "configs"),
    ] {
        let (state, recorder) = MockBackend::new().into_state();
        let response = send_json(&state, "POST", path, Some(serde_json::json!({}))).await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED, "{path}");
        let message = body_json(response).await["message"]
            .as_str()
            .expect("a message")
            .to_owned();
        assert!(
            message.contains(&format!("{kind} are immutable")),
            "{message}"
        );
        assert!(message.contains("rotate by creating a new"), "{message}");
        assert!(recorder.calls().is_empty(), "{path}");
    }
}

/// Filtering is refused rather than ignored (the M2/M3 precedent).
#[tokio::test]
async fn secret_and_config_listings_refuse_filters() {
    for path in [
        "/secrets?filters=%7B%22name%22%3A%5B%22db%22%5D%7D",
        "/configs?filters=%7B%22name%22%3A%5B%22db%22%5D%7D",
    ] {
        let (state, recorder) = MockBackend::new().into_state();
        let response = send_json(&state, "GET", path, None).await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED, "{path}");
        assert!(recorder.calls().is_empty(), "{path}");
    }
}

/// On a worker every one of these endpoints answers Docker's 503 refusal — the
/// backend's own error, passed through unchanged.
#[tokio::test]
async fn secret_and_config_endpoints_are_refused_on_a_worker() {
    let requests: Vec<(&str, &str, Option<Value>)> = vec![
        ("GET", "/secrets", None),
        (
            "POST",
            "/secrets/create",
            Some(serde_json::json!({"Name": "db_password", "Data": SECRET_PAYLOAD})),
        ),
        ("GET", "/secrets/db_password", None),
        ("DELETE", "/secrets/db_password", None),
        ("GET", "/configs", None),
        (
            "POST",
            "/configs/create",
            Some(serde_json::json!({"Name": "nginx_conf", "Data": "eA=="})),
        ),
        ("GET", "/configs/nginx_conf", None),
        ("DELETE", "/configs/nginx_conf", None),
    ];
    for (method, path, body) in requests {
        let (state, _) = MockBackend::failing(BackendError::not_a_swarm_manager()).into_state();
        let response = send_json(&state, method, path, body).await;
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{method} {path}"
        );
        assert_eq!(
            body_json(response).await["message"],
            satl_api::model::NOT_A_SWARM_MANAGER,
            "{method} {path}"
        );
    }
}

/// A service create carrying references: the short `--secret` form gets
/// Docker's file defaults, and an absolute secret target is refused because
/// secrets are materialized under `/run/secrets` and nowhere else.
#[tokio::test]
async fn service_create_converts_secret_references_and_refuses_absolute_targets() {
    let secret_id = Id::generate();
    let config_id = Id::generate();
    let (state, recorder) = MockBackend::new().into_state();
    let response = send_json(
        &state,
        "POST",
        "/services/create",
        Some(serde_json::json!({
            "Name": "web",
            "TaskTemplate": {"ContainerSpec": {"Image": "nginx:1.27",
                "Secrets": [{"SecretID": secret_id.as_str(), "SecretName": "db_password"}],
                "Configs": [{"ConfigID": config_id.as_str(), "ConfigName": "nginx_conf",
                    "File": {"Name": "/etc/nginx/nginx.conf", "Mode": 384}}]
            }}
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let Call::CreateService(options) = recorder.only_call() else {
        panic!("expected a create_service call");
    };
    let secrets = &options.spec.task.container.secrets;
    assert_eq!(secrets[0].secret_id, secret_id);
    assert_eq!(secrets[0].secret_name, "db_password");
    assert_eq!(secrets[0].file.name, "db_password");
    assert_eq!(secrets[0].file.uid, "0");
    assert_eq!(secrets[0].file.gid, "0");
    assert_eq!(secrets[0].file.mode, 0o444);
    let configs = &options.spec.task.container.configs;
    assert_eq!(configs[0].config_id, config_id);
    assert_eq!(configs[0].file.name, "/etc/nginx/nginx.conf");
    assert_eq!(configs[0].file.mode, 0o600);

    let bad: Vec<(Value, &str)> = vec![
        (
            serde_json::json!([{"SecretID": secret_id.as_str(), "SecretName": "db",
                "File": {"Name": "/run/secrets/db"}}]),
            "must be a relative path",
        ),
        (
            serde_json::json!([
                {"SecretID": secret_id.as_str(), "SecretName": "db", "File": {"Name": "creds"}},
                {"SecretID": secret_id.as_str(), "SecretName": "api", "File": {"Name": "creds"}}
            ]),
            "duplicate secret target creds",
        ),
        (
            serde_json::json!([{"SecretID": secret_id.as_str(), "SecretName": "db",
                "File": {"Name": "db", "Mode": 65535}}]),
            "is not a permission bit pattern",
        ),
        (
            serde_json::json!([{"SecretName": "db"}]),
            "SecretID is required",
        ),
    ];
    for (secrets, expected) in bad {
        let (state, recorder) = MockBackend::new().into_state();
        let response = send_json(
            &state,
            "POST",
            "/services/create",
            Some(serde_json::json!({
                "Name": "web",
                "TaskTemplate": {"ContainerSpec": {"Image": "nginx:1.27", "Secrets": secrets}}
            })),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "must reject {secrets:?}"
        );
        let message = body_json(response).await["message"]
            .as_str()
            .expect("a message")
            .to_owned();
        assert!(message.contains(expected), "{message}");
        assert!(recorder.calls().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Prune (M5)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn container_prune_answers_dockers_shape() {
    let (state, recorder) = MockBackend::new()
        .answer(|answers| {
            answers.error = None;
        })
        .into_state();
    // The mock's default answer is an empty prune; inject a populated one via
    // the failing/answer seam is not needed — the shape is what matters here.
    let response = send_json(&state, "POST", "/containers/prune", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert!(json["ContainersDeleted"].is_array(), "{json}");
    assert_eq!(json["SpaceReclaimed"], 0);
    assert_eq!(recorder.only_call(), Call::PruneContainers);
}

/// The `-a` contract, end to end through the router: Docker's filter has to
/// arrive at the backend as `all = true`, or `satl system prune -a` reclaims
/// nothing extra and nobody can tell.
#[tokio::test]
async fn images_prune_maps_dockers_dangling_filter_onto_all() {
    for (filters, expected_all) in [
        (None, false),
        (Some(r#"{"dangling":["true"]}"#), false),
        (Some(r#"{"dangling":["false"]}"#), true),
        (Some(r#"{"dangling":{"false":true}}"#), true),
    ] {
        let (state, recorder) = MockBackend::new().into_state();
        let path = match filters {
            None => "/images/prune".to_owned(),
            Some(raw) => format!("/images/prune?filters={}", urlencode(raw)),
        };
        let response = send_json(&state, "POST", &path, None).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            recorder.only_call(),
            Call::PruneImages(expected_all),
            "{path}"
        );
    }
}

/// A filter that would widen what gets deleted must be a 400 and must never
/// reach the backend.
#[tokio::test]
async fn an_unsupported_prune_filter_is_rejected_before_the_backend() {
    for (path, raw) in [
        ("/images/prune", r#"{"until":["24h"]}"#),
        ("/containers/prune", r#"{"until":["24h"]}"#),
        ("/networks/prune", r#"{"label":["keep"]}"#),
        ("/volumes/prune", r#"{"all":["true"]}"#),
    ] {
        let (state, recorder) = MockBackend::new().into_state();
        let response = send_json(
            &state,
            "POST",
            &format!("{path}?filters={}", urlencode(raw)),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path} {raw}");
        let message = body_json(response).await["message"]
            .as_str()
            .expect("a message")
            .to_owned();
        assert!(message.contains("not supported by SatL"), "{message}");
        assert!(recorder.calls().is_empty(), "{path} reached the backend");
    }
}

#[tokio::test]
async fn network_and_volume_prune_answer_dockers_shapes() {
    let (state, recorder) = MockBackend::new().into_state();
    let json = body_json(send_json(&state, "POST", "/networks/prune", None).await).await;
    assert!(json["NetworksDeleted"].is_array(), "{json}");
    assert!(
        json.get("SpaceReclaimed").is_none(),
        "docker's network prune has no SpaceReclaimed: {json}"
    );
    assert_eq!(recorder.only_call(), Call::PruneNetworks);

    let (state, recorder) = MockBackend::new().into_state();
    let json = body_json(send_json(&state, "POST", "/volumes/prune", None).await).await;
    assert!(json["VolumesDeleted"].is_array(), "{json}");
    assert_eq!(json["SpaceReclaimed"], 0);
    assert_eq!(recorder.only_call(), Call::PruneVolumes);
}

/// `Deferred` is SatL's own field (api-compat 131) and it must not appear when
/// there is nothing to defer, so a Docker client never sees an unknown key on
/// an ordinary prune.
#[tokio::test]
async fn deferred_is_absent_when_nothing_was_deferred() {
    let (state, _recorder) = MockBackend::new().into_state();
    let json = body_json(send_json(&state, "POST", "/images/prune", None).await).await;
    assert!(json.get("Deferred").is_none(), "{json}");
    assert!(json["ImagesDeleted"].is_array(), "{json}");
}

/// Minimal percent-encoding for the JSON filter values above.
fn urlencode(raw: &str) -> String {
    raw.chars()
        .map(|c| match c {
            '{' => "%7B".to_owned(),
            '}' => "%7D".to_owned(),
            '"' => "%22".to_owned(),
            '[' => "%5B".to_owned(),
            ']' => "%5D".to_owned(),
            ':' => "%3A".to_owned(),
            ',' => "%2C".to_owned(),
            other => other.to_string(),
        })
        .collect()
}
