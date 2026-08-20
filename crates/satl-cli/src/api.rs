// SPDX-License-Identifier: BSD-2-Clause
//! Wire types for the Docker Engine API v1.43 endpoints the CLI uses.
//!
//! Deserialization is deliberately lenient (missing fields default, `null`
//! reads as the default, unknown fields are ignored) so a newer or older
//! daemon never breaks `satl`.
//! Serialization skips empty fields so request bodies stay close to what the
//! docker CLI sends — the create-body goldens depend on it.

pub mod cluster;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Accept `null` for a field the daemon models as optional (`"Platform":
/// null`, `"Volumes": null`, …) and fall back to the type's default. Plain
/// `#[serde(default)]` only covers *missing* fields, not explicit nulls —
/// and satld does send nulls for the optional SatL extensions.
pub(crate) fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// `{}` — the value type of `ExposedPorts` and friends.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Empty {}

/// Body of `POST /containers/create` (Docker `ContainerConfig` + `HostConfig`).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CreateContainerBody {
    /// Image reference to run.
    pub image: String,
    /// Command and arguments; `None` keeps the image's own command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    /// `--entrypoint`, as docker sends it: a one-element vector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    /// `KEY=VALUE` pairs from `-e`/`--env-file`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// `-w`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub working_dir: String,
    /// `-u`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user: String,
    /// `--hostname`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    /// `--label`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Container-side ports of every `-p`, as `"80/tcp"` keys. The zero-sized
    /// value is Docker's wire shape (`{"80/tcp": {}}`), not a modelling slip.
    #[allow(clippy::zero_sized_map_values)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub exposed_ports: BTreeMap<String, Empty>,
    /// `-i`.
    pub open_stdin: bool,
    /// Always false: tty containers are not supported yet.
    pub tty: bool,
    /// Node-local placement and resource settings.
    pub host_config: HostConfig,
}

/// `HostConfig` subset the CLI sets.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct HostConfig {
    /// `-v` values, in docker's `src:dst[:ro]` form.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub binds: Vec<String>,
    /// `-p` mappings, keyed by `"80/tcp"`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub port_bindings: BTreeMap<String, Vec<PortBinding>>,
    /// `--tmpfs`, keyed by mount point.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub tmpfs: BTreeMap<String, String>,
    /// `--restart`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<RestartPolicy>,
    /// `--memory`, in bytes.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub memory: i64,
    /// `--cpus`, in units of 1e-9 CPU.
    #[serde(skip_serializing_if = "is_zero_i64", rename = "NanoCpus")]
    pub nano_cpus: i64,
    /// `--rm`.
    #[serde(skip_serializing_if = "is_false")]
    pub auto_remove: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_false(value: &bool) -> bool {
    !*value
}

/// One host-side binding of a published port.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct PortBinding {
    /// Host IP; always empty for now (see `--publish` handling).
    #[serde(rename = "HostIp")]
    pub host_ip: String,
    /// Host port as a string; empty means "daemon picks one".
    pub host_port: String,
}

/// `HostConfig.RestartPolicy`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RestartPolicy {
    /// `no`, `on-failure` or `always`.
    pub name: String,
    /// Only meaningful with `on-failure`.
    pub maximum_retry_count: u32,
}

/// Response of `POST /containers/create`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateContainerResponse {
    /// Full container ID.
    #[serde(default, deserialize_with = "null_as_default", rename = "Id")]
    pub id: String,
    /// Non-fatal warnings the daemon wants the operator to see.
    #[serde(default, deserialize_with = "null_as_default")]
    pub warnings: Vec<String>,
}

/// One entry of `GET /containers/json`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerSummary {
    /// Full container ID.
    #[serde(default, deserialize_with = "null_as_default", rename = "Id")]
    pub id: String,
    /// Names, each with a leading `/`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub names: Vec<String>,
    /// Image reference the container was created from.
    #[serde(default, deserialize_with = "null_as_default")]
    pub image: String,
    /// Command line, already joined by the daemon.
    #[serde(default, deserialize_with = "null_as_default")]
    pub command: String,
    /// Creation time (unix seconds).
    #[serde(default, deserialize_with = "null_as_default")]
    pub created: i64,
    /// Published/exposed ports.
    #[serde(default, deserialize_with = "null_as_default")]
    pub ports: Vec<PortSummary>,
    /// `running`, `exited`, …
    #[serde(default, deserialize_with = "null_as_default")]
    pub state: String,
    /// Human status the daemon computed (`Up 3 minutes`).
    #[serde(default, deserialize_with = "null_as_default")]
    pub status: String,
    /// SatL extension: resolved image platform (`freebsd/amd64`).
    #[serde(default, deserialize_with = "null_as_default")]
    pub platform: String,
}

/// One entry of `ContainerSummary::ports`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct PortSummary {
    /// Host IP the port is published on.
    #[serde(default, deserialize_with = "null_as_default", rename = "IP")]
    pub ip: String,
    /// Container-side port.
    #[serde(default, deserialize_with = "null_as_default")]
    pub private_port: u16,
    /// Host-side port, absent when the port is only exposed.
    #[serde(default, deserialize_with = "null_as_default")]
    pub public_port: Option<u16>,
    /// `tcp` or `udp`.
    #[serde(default, deserialize_with = "null_as_default", rename = "Type")]
    pub typ: String,
}

/// One entry of `GET /images/json`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageSummary {
    /// Content-addressed image ID (`sha256:…`).
    #[serde(default, deserialize_with = "null_as_default", rename = "Id")]
    pub id: String,
    /// `repo:tag` strings; empty for dangling images.
    #[serde(default, deserialize_with = "null_as_default")]
    pub repo_tags: Vec<String>,
    /// Creation time (unix seconds).
    #[serde(default, deserialize_with = "null_as_default")]
    pub created: i64,
    /// Total size in bytes.
    #[serde(default, deserialize_with = "null_as_default")]
    pub size: i64,
    /// SatL extension: image platform (`freebsd/amd64`).
    #[serde(default, deserialize_with = "null_as_default")]
    pub platform: String,
}

/// Response of `POST /containers/{id}/wait`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WaitResponse {
    /// The container's exit code.
    #[serde(default, deserialize_with = "null_as_default")]
    pub status_code: i64,
    /// Set when the daemon could not wait for the container.
    #[serde(default, deserialize_with = "null_as_default")]
    pub error: Option<WaitError>,
}

/// `WaitResponse.Error`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WaitError {
    /// Why the wait failed.
    #[serde(default, deserialize_with = "null_as_default")]
    pub message: String,
}

/// Body of `POST /containers/{id}/exec`.
// The four booleans are Docker's field names; grouping them would break the
// wire shape.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCreateBody {
    /// `-i`.
    pub attach_stdin: bool,
    /// Always true — the CLI always relays output.
    pub attach_stdout: bool,
    /// Always true.
    pub attach_stderr: bool,
    /// Always false: tty exec is not supported yet.
    pub tty: bool,
    /// `-e`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// `-w`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub working_dir: String,
    /// `-u`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user: String,
    /// The command to run.
    pub cmd: Vec<String>,
}

/// Response of `POST /containers/{id}/exec`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCreateResponse {
    /// Exec instance ID.
    #[serde(default, deserialize_with = "null_as_default", rename = "Id")]
    pub id: String,
}

/// Body of `POST /exec/{id}/start`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ExecStartBody {
    /// Always false — the CLI attaches.
    pub detach: bool,
    /// Always false: tty exec is not supported yet.
    pub tty: bool,
}

/// Response of `GET /exec/{id}/json`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecInspect {
    /// Still running? Then `exit_code` is not final yet.
    #[serde(default, deserialize_with = "null_as_default")]
    pub running: bool,
    /// The command's exit code once it has finished.
    #[serde(default, deserialize_with = "null_as_default")]
    pub exit_code: Option<i64>,
}

/// Response of `POST /containers/prune`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainersPruneResponse {
    /// IDs of the containers removed.
    #[serde(default)]
    pub containers_deleted: Vec<String>,
    /// Bytes freed.
    #[serde(default)]
    pub space_reclaimed: u64,
}

/// One entry of `POST /images/prune`'s `ImagesDeleted`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageDeleteItem {
    /// A reference that stopped pointing at an image.
    #[serde(default)]
    pub untagged: Option<String>,
    /// Content that was deleted.
    #[serde(default)]
    pub deleted: Option<String>,
}

/// Response of `POST /images/prune`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImagesPruneResponse {
    /// What was untagged and what was deleted.
    #[serde(default)]
    pub images_deleted: Vec<ImageDeleteItem>,
    /// Bytes freed.
    #[serde(default)]
    pub space_reclaimed: u64,
    /// Layer chains awaiting a second agreeing pass (SatL's addition).
    #[serde(default)]
    pub deferred: Vec<String>,
}

/// Response of `POST /networks/prune`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworksPruneResponse {
    /// Names of the networks removed.
    #[serde(default)]
    pub networks_deleted: Vec<String>,
}

/// Response of `POST /volumes/prune`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumesPruneResponse {
    /// Names of the volumes removed.
    #[serde(default)]
    pub volumes_deleted: Vec<String>,
    /// Bytes freed.
    #[serde(default)]
    pub space_reclaimed: u64,
}

/// One line of the `GET /events` stream.
///
/// The daemon renders it in `satl-api`'s `render::event`, so the casing is
/// Docker's own and deliberately inconsistent: `Type`, `Action` and `Actor`
/// are capitalised, `scope`, `time` and `timeNano` are not.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventMessage {
    /// Object kind (`container`, `image`).
    #[serde(default, deserialize_with = "null_as_default", rename = "Type")]
    pub kind: String,
    /// What happened (`create`, `start`, `die`, `destroy`, `pull`, `tag`, ...).
    #[serde(default, deserialize_with = "null_as_default")]
    pub action: String,
    /// Who it happened to.
    #[serde(default, deserialize_with = "null_as_default")]
    pub actor: EventActor,
    /// `local` or `swarm`.
    #[serde(default, deserialize_with = "null_as_default", rename = "scope")]
    pub scope: String,
    /// Event time, unix seconds.
    #[serde(default, deserialize_with = "null_as_default", rename = "time")]
    pub time: i64,
    /// Event time, unix nanoseconds — the field the human line is built from.
    #[serde(default, deserialize_with = "null_as_default", rename = "timeNano")]
    pub time_nano: i64,
}

/// `Actor` of an [`EventMessage`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventActor {
    /// Task ID for a container event, image reference for an image one.
    #[serde(default, deserialize_with = "null_as_default", rename = "ID")]
    pub id: String,
    /// Free-form attributes: always `name`, plus `image` and the container
    /// labels on a container event, plus `exitCode` on a `die`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub attributes: BTreeMap<String, String>,
}

/// Response of `GET /volumes`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumeListResponse {
    /// Known volumes; the daemon may send `null`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub volumes: Vec<Volume>,
}

/// One entry of `VolumeListResponse::volumes`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Volume {
    /// Volume name.
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    /// Volume driver (`local`).
    #[serde(default, deserialize_with = "null_as_default")]
    pub driver: String,
}

/// Body of `POST /volumes/create`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CreateVolumeBody {
    /// Requested name; empty asks the daemon to generate one.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Volume driver.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub driver: String,
    /// `--label`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// One entry of `GET /networks`, and the shape `GET /networks/{id}` answers.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Network {
    /// Full network ID.
    #[serde(default, deserialize_with = "null_as_default", rename = "Id")]
    pub id: String,
    /// Network name.
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    /// Driver (`bridge`, `overlay`).
    #[serde(default, deserialize_with = "null_as_default")]
    pub driver: String,
    /// `local` for node-local networks, `swarm` for cluster-wide ones.
    #[serde(default, deserialize_with = "null_as_default")]
    pub scope: String,
    /// Labels, which is how `satl compose down` tells a network it created from
    /// one somebody else made.
    #[serde(default, deserialize_with = "null_as_default")]
    pub labels: BTreeMap<String, String>,
}

/// Body of `POST /networks/create`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CreateNetworkBody {
    /// Network name.
    pub name: String,
    /// `-d/--driver`; omitted when unset, so the daemon's default applies.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub driver: String,
    /// `--subnet` / `--gateway`; omitted when neither was given.
    #[serde(rename = "IPAM", skip_serializing_if = "Option::is_none")]
    pub ipam: Option<Ipam>,
    /// `--opt`; omitted when empty. `encrypted` is the only valid key.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
    /// `--label`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// `IPAM` of a create body.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Ipam {
    /// Exactly one entry: a SatL network has one subnet.
    pub config: Vec<IpamConfig>,
}

/// One entry of `Ipam::config`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct IpamConfig {
    /// `--subnet`, in CIDR form.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subnet: String,
    /// `--gateway`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub gateway: String,
}

/// Response of `POST /networks/create`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateNetworkResponse {
    /// Full network ID.
    #[serde(default, deserialize_with = "null_as_default", rename = "Id")]
    pub id: String,
    /// A note the daemon wants the operator to see.
    #[serde(default, deserialize_with = "null_as_default")]
    pub warning: String,
}

/// One JSON line of a pull progress stream (Docker `JSONMessage`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct JsonMessage {
    /// What is happening (`Downloading`, `Pull complete`, …).
    #[serde(default, deserialize_with = "null_as_default")]
    pub status: String,
    /// Layer (or image reference) the status is about.
    #[serde(default, deserialize_with = "null_as_default")]
    pub id: String,
    /// Pre-rendered progress bar from the daemon.
    #[serde(default, deserialize_with = "null_as_default")]
    pub progress: String,
    /// Set when the pull failed.
    #[serde(default, deserialize_with = "null_as_default")]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_body_omits_everything_unset() {
        let body = CreateContainerBody {
            image: "nginx:1.25".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"Image":"nginx:1.25","OpenStdin":false,"Tty":false,"HostConfig":{}}"#
        );
    }

    #[test]
    fn container_summary_reads_the_platform_extension() {
        let json = r#"[{
            "Id": "0123456789abcdef",
            "Names": ["/web"],
            "Image": "nginx:1.25",
            "Command": "nginx -g 'daemon off;'",
            "Created": 1000,
            "State": "running",
            "Status": "Up 2 minutes",
            "Platform": "freebsd/amd64",
            "Ports": [{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}],
            "SomethingNewer": 42
        }]"#;
        let parsed: Vec<ContainerSummary> = serde_json::from_str(json).unwrap();
        assert_eq!(parsed[0].platform, "freebsd/amd64");
        assert_eq!(parsed[0].ports[0].public_port, Some(8080));
        assert_eq!(parsed[0].ports[0].ip, "0.0.0.0");
    }

    #[test]
    fn missing_fields_default() {
        let parsed: ContainerSummary = serde_json::from_str("{}").unwrap();
        assert!(parsed.id.is_empty());
        assert!(parsed.ports.is_empty());
    }

    /// satld models the SatL extensions as optional and sends `null` when it
    /// has no value; that must not fail the whole listing.
    #[test]
    fn null_fields_read_as_defaults() {
        let json = r#"{
            "Id": "abc", "Names": null, "Ports": null, "Platform": null,
            "Status": null, "Image": null, "Command": null
        }"#;
        let parsed: ContainerSummary = serde_json::from_str(json).unwrap();
        assert!(parsed.platform.is_empty());
        assert!(parsed.names.is_empty());
        assert!(parsed.ports.is_empty());

        let parsed: ImageSummary =
            serde_json::from_str(r#"{"Id":"sha256:a","RepoTags":null,"Platform":null}"#).unwrap();
        assert!(parsed.repo_tags.is_empty());
        assert!(parsed.platform.is_empty());

        let parsed: PortSummary =
            serde_json::from_str(r#"{"IP":null,"PrivatePort":80,"PublicPort":null,"Type":"tcp"}"#)
                .unwrap();
        assert_eq!(parsed.public_port, None);
        assert!(parsed.ip.is_empty());
    }

    #[test]
    fn volume_list_tolerates_null() {
        let parsed: VolumeListResponse = serde_json::from_str(r#"{"Volumes": null}"#).unwrap();
        assert!(parsed.volumes.is_empty());
    }

    #[test]
    fn exec_bodies_match_the_documented_shape() {
        let body = ExecCreateBody {
            attach_stdout: true,
            attach_stderr: true,
            cmd: vec!["sh".to_owned(), "-c".to_owned(), "echo hi".to_owned()],
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"AttachStdin":false,"AttachStdout":true,"AttachStderr":true,"Tty":false,"Cmd":["sh","-c","echo hi"]}"#
        );
        assert_eq!(
            serde_json::to_string(&ExecStartBody::default()).unwrap(),
            r#"{"Detach":false,"Tty":false}"#
        );
    }
}
