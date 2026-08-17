// SPDX-License-Identifier: BSD-2-Clause
//! Docker request documents → [`backend::model`](crate::backend::model)
//! types.
//!
//! This is where Docker's wire vocabulary (`Binds`, `PortBindings`,
//! `RestartPolicy`, `X-Registry-Auth`, `?platform=`) becomes SatL's: mounts
//! and port configs from `satl-core`, a task restart policy, a resolved
//! platform. Anything SatL cannot honour is rejected here with
//! [`BackendError::InvalidParameter`] (HTTP 400, Docker's `{"message": …}`
//! shape) rather than silently dropped — a container that quietly ignores
//! `--privileged` or `--cap-add` is worse than one that refuses to start.

pub mod cluster;

use std::collections::BTreeMap;

use base64::Engine as _;
use satl_core::{
    Mount, MountType, Platform, PortProtocol, RestartCondition, RestartPolicy, naming,
};

use crate::backend::model::{
    BackendError, CreateContainerOptions, CreateVolumeOptions, ExecConfig, ExposedPort, LogOptions,
    PortMapping, RegistryAuth, Result, WaitCondition,
};
use crate::timefmt;
use crate::types::{
    ContainerCreateBody, ExecCreateBody, HostConfigBody, PortBindingBody, RestartPolicyBody,
    StringOrList, VolumeCreateBody,
};

/// Network modes SatL accepts on container creation. `bridge` is SatL's
/// node-local bridge network (architecture §11.1).
const SUPPORTED_NETWORK_MODES: [&str; 4] = ["", "default", "bridge", "satl"];

/// The only container runtime SatL drives (invariant #6).
const RUNTIME_NAME: &str = "ocijail";

/// Builds the create-container options from the request body, the `?name=`
/// query parameter and the `?platform=` query parameter.
pub fn create_container_options(
    body: ContainerCreateBody,
    name: Option<&str>,
    platform: Option<&str>,
) -> Result<CreateContainerOptions> {
    let image = body.image.unwrap_or_default();
    if image.trim().is_empty() {
        return Err(BackendError::invalid("no image specified"));
    }

    let name = match name.map(str::trim).filter(|value| !value.is_empty()) {
        None => None,
        Some(name) => {
            naming::validate_service_name(name).map_err(|err| {
                BackendError::invalid(format!("invalid container name {name:?}: {err}"))
            })?;
            Some(name.to_owned())
        }
    };

    let platform = platform
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(parse_platform)
        .transpose()?;

    let host = body.host_config.unwrap_or_default();
    reject_unsupported_host_config(&host)?;

    let restart_policy = restart_policy(host.restart_policy.as_ref())?;
    if host.auto_remove && restart_policy.condition != RestartCondition::None {
        return Err(BackendError::invalid(
            "conflicting options: AutoRemove and RestartPolicy cannot both be set",
        ));
    }

    Ok(CreateContainerOptions {
        name,
        image,
        cmd: body.cmd.map(StringOrList::into_vec).unwrap_or_default(),
        entrypoint: body
            .entrypoint
            .map(StringOrList::into_vec)
            .unwrap_or_default(),
        env: body.env.unwrap_or_default(),
        working_dir: non_empty(body.working_dir),
        user: non_empty(body.user),
        hostname: non_empty(body.hostname),
        tty: body.tty,
        labels: body.labels.unwrap_or_default(),
        exposed_ports: exposed_ports(&body.exposed_ports)?,
        binds: binds(&host.binds)?,
        volumes: anonymous_volumes(&body.volumes)?,
        tmpfs: tmpfs_mounts(&host.tmpfs),
        port_bindings: port_bindings(&host.port_bindings)?,
        memory: positive(host.memory),
        nano_cpus: positive(host.nano_cpus),
        restart_policy,
        platform,
        auto_remove: host.auto_remove,
    })
}

/// `Some(value)` when `value` is a non-empty string.
fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

/// `Some(value)` for strictly positive limits (Docker sends 0 for "unset").
fn positive(value: i64) -> Option<i64> {
    (value > 0).then_some(value)
}

/// Rejects the Docker host options SatL cannot honour on FreeBSD jails
/// (architecture §13: unsupported Linux-only options fail loudly).
fn reject_unsupported_host_config(host: &HostConfigBody) -> Result<()> {
    let unsupported = |option: &str, reason: &str| {
        Err(BackendError::invalid(format!(
            "{option} is not supported by SatL: {reason}"
        )))
    };

    if host.privileged {
        return unsupported("HostConfig.Privileged", "jails have no privileged mode");
    }
    if !host.cap_add.is_empty() || !host.cap_drop.is_empty() {
        return unsupported(
            "HostConfig.CapAdd/CapDrop",
            "Linux capabilities do not exist on FreeBSD",
        );
    }
    if !host.security_opt.is_empty() {
        return unsupported(
            "HostConfig.SecurityOpt",
            "seccomp/apparmor/selinux do not exist on FreeBSD",
        );
    }
    if !host.devices.is_empty() {
        return unsupported(
            "HostConfig.Devices",
            "device mapping is governed by the jail devfs ruleset",
        );
    }
    if !host.cgroup_parent.is_empty() {
        return unsupported(
            "HostConfig.CgroupParent",
            "resource limits are enforced by rctl(8), not cgroups",
        );
    }
    if !host.sysctls.is_empty() {
        return unsupported(
            "HostConfig.Sysctls",
            "per-jail sysctls are not configurable",
        );
    }
    if !host.ulimits.is_empty() {
        return unsupported(
            "HostConfig.Ulimits",
            "use Memory/NanoCpus, which map to rctl(8) rules",
        );
    }
    if !host.pid_mode.is_empty()
        || !host.ipc_mode.is_empty()
        || !host.uts_mode.is_empty()
        || !host.userns_mode.is_empty()
    {
        return unsupported(
            "HostConfig.PidMode/IpcMode/UTSMode/UsernsMode",
            "namespace sharing does not exist on FreeBSD jails",
        );
    }
    if host.shm_size > 0 {
        return unsupported("HostConfig.ShmSize", "jails have no /dev/shm tmpfs");
    }
    if host.cpu_shares > 0 || host.cpu_quota > 0 || !host.cpuset_cpus.is_empty() {
        return unsupported(
            "HostConfig.CpuShares/CpuQuota/CpusetCpus",
            "use NanoCpus, which maps to an rctl(8) pcpu limit",
        );
    }
    if host.memory_swap > 0 {
        return unsupported(
            "HostConfig.MemorySwap",
            "FreeBSD accounts swap separately from memory",
        );
    }
    if !host.mounts.is_empty() {
        return unsupported("HostConfig.Mounts", "use Binds (`src:dst[:ro]`) or Tmpfs");
    }
    if !host.runtime.is_empty() && host.runtime != RUNTIME_NAME {
        return Err(BackendError::invalid(format!(
            "unknown runtime {:?}: SatL only drives {RUNTIME_NAME}",
            host.runtime
        )));
    }
    if !SUPPORTED_NETWORK_MODES.contains(&host.network_mode.as_str()) {
        return Err(BackendError::invalid(format!(
            "network mode {:?} is not supported: SatL attaches containers to \
             its own bridge network",
            host.network_mode
        )));
    }
    Ok(())
}

/// Docker `RestartPolicy` → SatL task restart policy.
///
/// `unless-stopped` maps to `any`: SatL has no notion of "the operator
/// stopped it by hand", because a stopped container is a task with desired
/// state `shutdown` (deviation recorded in `docs/api-compat.md`).
pub fn restart_policy(body: Option<&RestartPolicyBody>) -> Result<RestartPolicy> {
    let Some(body) = body else {
        return Ok(RestartPolicy {
            condition: RestartCondition::None,
            ..RestartPolicy::default()
        });
    };
    let condition = match body.name.as_str() {
        "" | "no" => RestartCondition::None,
        "always" | "unless-stopped" => RestartCondition::Any,
        "on-failure" => RestartCondition::OnFailure,
        other => {
            return Err(BackendError::invalid(format!(
                "invalid restart policy {other:?}: must be one of \
                 no, always, unless-stopped, on-failure"
            )));
        }
    };
    if body.maximum_retry_count > 0 && condition != RestartCondition::OnFailure {
        return Err(BackendError::invalid(
            "maximum retry count can only be used with restart policy \"on-failure\"",
        ));
    }
    Ok(RestartPolicy {
        condition,
        max_attempts: body.maximum_retry_count,
        ..RestartPolicy::default()
    })
}

/// `ExposedPorts` keys (`"80/tcp"`) → declared ports.
pub fn exposed_ports(map: &BTreeMap<String, serde_json::Value>) -> Result<Vec<ExposedPort>> {
    map.keys()
        .map(|key| {
            let (port, protocol) = parse_port_key(key)?;
            Ok(ExposedPort { port, protocol })
        })
        .collect()
}

/// Parses Docker's `<port>[/<proto>]` port key.
pub fn parse_port_key(key: &str) -> Result<(u16, PortProtocol)> {
    let (port, protocol) = key.split_once('/').unwrap_or((key, "tcp"));
    let protocol = match protocol.to_ascii_lowercase().as_str() {
        "tcp" => PortProtocol::Tcp,
        "udp" => PortProtocol::Udp,
        other => {
            return Err(BackendError::invalid(format!(
                "invalid port specification {key:?}: unsupported protocol {other:?} \
                 (SatL supports tcp and udp)"
            )));
        }
    };
    let port: u16 = port.parse().map_err(|_| {
        BackendError::invalid(format!(
            "invalid port specification {key:?}: {port:?} is not a port number \
             (port ranges are not supported)"
        ))
    })?;
    if port == 0 {
        return Err(BackendError::invalid(format!(
            "invalid port specification {key:?}: port 0 is not a valid container port"
        )));
    }
    Ok((port, protocol))
}

/// `HostConfig.PortBindings` → flat host bindings.
pub fn port_bindings(
    map: &BTreeMap<String, Option<Vec<PortBindingBody>>>,
) -> Result<Vec<PortMapping>> {
    let mut bindings = Vec::new();
    for (key, hosts) in map {
        let (container_port, protocol) = parse_port_key(key)?;
        let Some(hosts) = hosts else { continue };
        for host in hosts {
            let host_port = if host.host_port.is_empty() {
                0
            } else {
                host.host_port.parse().map_err(|_| {
                    BackendError::invalid(format!(
                        "invalid host port {:?} for container port {key}: \
                         expected a port number (ranges are not supported)",
                        host.host_port
                    ))
                })?
            };
            bindings.push(PortMapping {
                host_ip: (!host.host_ip.is_empty()).then(|| host.host_ip.clone()),
                host_port,
                container_port,
                protocol,
            });
        }
    }
    Ok(bindings)
}

/// `HostConfig.Binds` (`src:dst[:opts]`) → mounts.
///
/// A source starting with `/` or `.` is a host path (nullfs bind mount);
/// anything else is a named volume. Only the `ro`/`rw` options are
/// understood — `SELinux` relabeling (`z`, `Z`) and mount propagation have no
/// FreeBSD equivalent.
pub fn binds(specs: &[String]) -> Result<Vec<Mount>> {
    specs.iter().map(|spec| parse_bind(spec)).collect()
}

/// Parses one `src:dst[:opts]` bind specification.
pub fn parse_bind(spec: &str) -> Result<Mount> {
    let invalid =
        |reason: &str| BackendError::invalid(format!("invalid bind mount {spec:?}: {reason}"));
    let parts: Vec<&str> = spec.split(':').collect();
    let (source, target, options) = match parts.as_slice() {
        [source, target] => (*source, *target, ""),
        [source, target, options] => (*source, *target, *options),
        _ => {
            return Err(invalid(
                "expected \"source:destination\" or \"source:destination:options\"",
            ));
        }
    };
    if source.is_empty() {
        return Err(invalid("the source is empty"));
    }
    if !target.starts_with('/') {
        return Err(invalid("the destination must be an absolute path"));
    }

    let mut read_only = false;
    for option in options.split(',').filter(|option| !option.is_empty()) {
        match option {
            "ro" => read_only = true,
            "rw" => read_only = false,
            other => {
                return Err(invalid(&format!(
                    "unsupported mount option {other:?} (SatL understands ro and rw)"
                )));
            }
        }
    }

    let kind = if source.starts_with('/') || source.starts_with('.') {
        MountType::Bind
    } else {
        MountType::Volume
    };
    Ok(Mount {
        kind,
        source: Some(source.to_owned()),
        target: target.to_owned(),
        read_only,
    })
}

/// `Config.Volumes` (`{"/data": {}}`) → anonymous volume mounts.
pub fn anonymous_volumes(map: &BTreeMap<String, serde_json::Value>) -> Result<Vec<Mount>> {
    map.keys()
        .map(|target| {
            if !target.starts_with('/') {
                return Err(BackendError::invalid(format!(
                    "invalid volume {target:?}: the destination must be an absolute path"
                )));
            }
            Ok(Mount {
                kind: MountType::Volume,
                source: None,
                target: target.clone(),
                read_only: false,
            })
        })
        .collect()
}

/// `HostConfig.Tmpfs` (`{"/run": "rw,size=64m"}`) → tmpfs mounts.
pub fn tmpfs_mounts(map: &BTreeMap<String, String>) -> Vec<Mount> {
    map.iter()
        .map(|(target, options)| Mount {
            kind: MountType::Tmpfs,
            source: None,
            target: target.clone(),
            read_only: options.split(',').any(|option| option == "ro"),
        })
        .collect()
}

/// Parses `?platform=os/arch[/variant]`; the variant is accepted and ignored
/// (SatL selects on OS and architecture only).
pub fn parse_platform(value: &str) -> Result<Platform> {
    let parts: Vec<&str> = value.split('/').collect();
    match parts.as_slice() {
        [os, arch] | [os, arch, _] if !os.is_empty() && !arch.is_empty() => Ok(Platform {
            os: (*os).to_owned(),
            arch: (*arch).to_owned(),
        }),
        _ => Err(BackendError::invalid(format!(
            "invalid platform {value:?}: expected \"os/arch\", e.g. freebsd/amd64"
        ))),
    }
}

/// Decodes a base64 field the way Docker clients encode them: standard or
/// URL-safe alphabet, padded or not (api-compat #16 accepts all four on
/// `X-Registry-Auth`, and a secret payload is no stricter). `None` when the
/// text is not base64 in any of them.
pub(crate) fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let engines = [
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
    ];
    engines
        .iter()
        .find_map(|engine| engine.decode(value.trim()).ok())
}

/// Docker's `X-Registry-Auth`: base64(url or standard)-encoded JSON
/// `AuthConfig`.
pub fn decode_registry_auth(header: &str) -> Result<RegistryAuth> {
    /// The JSON document Docker clients encode into the header.
    #[derive(serde::Deserialize, Default)]
    struct AuthConfigBody {
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        auth: String,
        #[serde(default)]
        email: String,
        #[serde(default)]
        serveraddress: String,
        #[serde(default)]
        identitytoken: String,
        #[serde(default)]
        registrytoken: String,
    }

    let decoded = decode_base64(header)
        .ok_or_else(|| BackendError::invalid("invalid X-Registry-Auth header: not valid base64"))?;
    let body: AuthConfigBody = serde_json::from_slice(&decoded).map_err(|err| {
        BackendError::invalid(format!(
            "invalid X-Registry-Auth header: not a JSON AuthConfig document ({err})"
        ))
    })?;
    Ok(RegistryAuth {
        username: body.username,
        password: body.password,
        auth: body.auth,
        server_address: body.serveraddress,
        identity_token: body.identitytoken,
        registry_token: body.registrytoken,
        email: body.email,
    })
}

/// Joins `?fromImage=` and `?tag=` into one image reference, the way Docker
/// does: a digest tag is appended with `@`, a plain tag with `:`, and an
/// absent tag means `latest`.
pub fn image_reference(from_image: &str, tag: Option<&str>) -> Result<String> {
    let from_image = from_image.trim();
    if from_image.is_empty() {
        return Err(BackendError::invalid(
            "no image name specified: set the fromImage query parameter",
        ));
    }
    Ok(join_reference(from_image, tag))
}

/// Joins `POST /images/{name}/tag`'s `?repo=` and `?tag=` into the target
/// reference ([`image_reference`]'s join: `repo` may carry its own tag, and
/// an absent `tag` means `latest`).
pub fn tag_target(repo: &str, tag: Option<&str>) -> Result<String> {
    let repo = repo.trim();
    if repo.is_empty() {
        return Err(BackendError::invalid(
            "no repository specified: set the repo query parameter",
        ));
    }
    Ok(join_reference(repo, tag))
}

/// The join both query forms share: `name` may already carry its own tag or
/// digest; a digest tag is appended with `@`, a plain tag with `:`.
fn join_reference(name: &str, tag: Option<&str>) -> String {
    let has_reference = match name.rsplit_once('@') {
        Some(_) => true,
        None => name
            .rsplit_once(':')
            .is_some_and(|(_, tag)| !tag.contains('/')),
    };
    let tag = tag.map(str::trim).filter(|tag| !tag.is_empty());
    match tag {
        Some(tag) if !has_reference && tag.contains(':') => format!("{name}@{tag}"),
        Some(tag) if !has_reference => format!("{name}:{tag}"),
        _ => name.to_owned(),
    }
}

/// `POST /containers/{id}/exec` body → exec configuration.
pub fn exec_config(body: ExecCreateBody) -> Result<ExecConfig> {
    if body.tty {
        return Err(BackendError::invalid("tty not supported yet"));
    }
    if body.privileged {
        return Err(BackendError::invalid(
            "privileged exec is not supported by SatL: jails have no privileged mode",
        ));
    }
    let cmd = body.cmd.map(StringOrList::into_vec).unwrap_or_default();
    if cmd.is_empty() {
        return Err(BackendError::invalid("no command specified"));
    }
    // Docker defaults both output streams on when neither is requested.
    let (attach_stdout, attach_stderr) = if body.attach_stdout || body.attach_stderr {
        (body.attach_stdout, body.attach_stderr)
    } else {
        (true, true)
    };
    Ok(ExecConfig {
        cmd,
        env: body.env.unwrap_or_default(),
        working_dir: non_empty(body.working_dir),
        user: non_empty(body.user),
        attach_stdin: body.attach_stdin,
        attach_stdout,
        attach_stderr,
    })
}

/// `POST /volumes/create` body → volume options.
pub fn volume_options(body: VolumeCreateBody) -> Result<CreateVolumeOptions> {
    let driver = body
        .driver
        .filter(|driver| !driver.is_empty())
        .unwrap_or_else(|| "local".to_owned());
    if driver != "local" {
        return Err(BackendError::invalid(format!(
            "volume driver {driver:?} is not supported: SatL volumes are ZFS \
             datasets served by the local driver"
        )));
    }
    Ok(CreateVolumeOptions {
        name: body.name,
        driver,
        driver_opts: body.driver_opts,
        labels: body.labels,
    })
}

/// `?condition=` of `POST /containers/{id}/wait`.
pub fn wait_condition(value: Option<&str>) -> Result<WaitCondition> {
    match value.unwrap_or("").trim() {
        "" | "not-running" => Ok(WaitCondition::NotRunning),
        "next-exit" => Ok(WaitCondition::NextExit),
        "removed" => Ok(WaitCondition::Removed),
        other => Err(BackendError::invalid(format!(
            "invalid condition {other:?}: must be one of not-running, next-exit, removed"
        ))),
    }
}

/// Builds log options from the already-parsed query parameters.
// The flags mirror Docker's query parameters one-for-one; grouping them into
// a struct here would only move the same booleans one level up.
#[allow(clippy::fn_params_excessive_bools)]
pub fn log_options(
    follow: bool,
    stdout: bool,
    stderr: bool,
    tail: Option<&str>,
    timestamps: bool,
    since: Option<&str>,
) -> Result<LogOptions> {
    if !stdout && !stderr {
        return Err(BackendError::invalid(
            "Bad parameters: you must choose at least one stream",
        ));
    }
    let tail = match tail.map(str::trim).filter(|tail| !tail.is_empty()) {
        None | Some("all") => None,
        Some(value) => Some(value.parse::<u64>().map_err(|_| {
            BackendError::invalid(format!(
                "invalid tail {value:?}: expected a line count or \"all\""
            ))
        })?),
    };
    let since = match since {
        None => None,
        Some(value) => timefmt::parse_timestamp(value).map_err(BackendError::invalid)?,
    };
    Ok(LogOptions {
        follow,
        stdout,
        stderr,
        tail,
        timestamps,
        since,
    })
}

#[cfg(test)]
mod tests {
    use satl_core::PortProtocol;

    use super::*;

    fn body(json: serde_json::Value) -> ContainerCreateBody {
        serde_json::from_value(json).expect("test body must deserialize")
    }

    // One request body exercising every conversion at once; splitting it
    // would only hide which field broke.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn full_create_body_maps_to_backend_options() {
        let options = create_container_options(
            body(serde_json::json!({
                "Hostname": "web-1",
                "User": "www",
                "Env": ["RUST_LOG=info", "PORT=80"],
                "Cmd": ["nginx", "-g", "daemon off;"],
                "Entrypoint": "/usr/local/bin/entry",
                "Image": "registry.example.com/nginx:1.27",
                "WorkingDir": "/srv",
                "Tty": false,
                "Labels": {"tier": "web"},
                "ExposedPorts": {"80/tcp": {}, "53/udp": {}},
                "Volumes": {"/var/cache": {}},
                "HostConfig": {
                    "Binds": ["/host/data:/data:ro", "assets:/srv/assets"],
                    "Tmpfs": {"/run": "rw,size=64m", "/secrets": "ro"},
                    "PortBindings": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]},
                    "Memory": 536_870_912_i64,
                    "NanoCpus": 1_500_000_000_i64,
                    "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
                    "AutoRemove": false
                }
            })),
            Some("web"),
            Some("freebsd/amd64"),
        )
        .expect("valid body");

        assert_eq!(options.name.as_deref(), Some("web"));
        assert_eq!(options.image, "registry.example.com/nginx:1.27");
        assert_eq!(options.cmd, ["nginx", "-g", "daemon off;"]);
        assert_eq!(options.entrypoint, ["/usr/local/bin/entry"]);
        assert_eq!(options.env, ["RUST_LOG=info", "PORT=80"]);
        assert_eq!(options.working_dir.as_deref(), Some("/srv"));
        assert_eq!(options.user.as_deref(), Some("www"));
        assert_eq!(options.hostname.as_deref(), Some("web-1"));
        assert_eq!(options.labels["tier"], "web");
        assert_eq!(
            options.exposed_ports,
            [
                ExposedPort {
                    port: 53,
                    protocol: PortProtocol::Udp
                },
                ExposedPort {
                    port: 80,
                    protocol: PortProtocol::Tcp
                },
            ]
        );
        assert_eq!(options.memory, Some(536_870_912));
        assert_eq!(options.nano_cpus, Some(1_500_000_000));
        assert_eq!(
            options.restart_policy.condition,
            RestartCondition::OnFailure
        );
        assert_eq!(options.restart_policy.max_attempts, 3);
        assert_eq!(
            options.platform,
            Some(Platform {
                os: "freebsd".to_owned(),
                arch: "amd64".to_owned()
            })
        );
        assert!(!options.auto_remove);

        // Mounts keep their kind and order: binds, anonymous volumes, tmpfs.
        let mounts = options.mounts();
        assert_eq!(mounts.len(), 5);
        assert_eq!(
            mounts[0],
            Mount {
                kind: MountType::Bind,
                source: Some("/host/data".to_owned()),
                target: "/data".to_owned(),
                read_only: true,
            }
        );
        assert_eq!(
            mounts[1],
            Mount {
                kind: MountType::Volume,
                source: Some("assets".to_owned()),
                target: "/srv/assets".to_owned(),
                read_only: false,
            }
        );
        assert_eq!(
            mounts[2],
            Mount {
                kind: MountType::Volume,
                source: None,
                target: "/var/cache".to_owned(),
                read_only: false,
            }
        );
        assert_eq!(mounts[3].kind, MountType::Tmpfs);
        assert_eq!(mounts[3].target, "/run");
        assert!(!mounts[3].read_only);
        assert_eq!(mounts[4].target, "/secrets");
        assert!(mounts[4].read_only);

        assert_eq!(
            options.port_bindings,
            [PortMapping {
                host_ip: Some("127.0.0.1".to_owned()),
                host_port: 8080,
                container_port: 80,
                protocol: PortProtocol::Tcp,
            }]
        );
        let ports = options.port_configs();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].target_port, 80);
        assert_eq!(ports[0].published_port, 8080);
        assert_eq!(ports[0].publish_mode, satl_core::PublishMode::Host);
    }

    #[test]
    fn minimal_create_body_uses_defaults() {
        let options =
            create_container_options(body(serde_json::json!({"Image": "nginx"})), None, None)
                .expect("valid body");
        assert_eq!(options.image, "nginx");
        assert!(options.name.is_none());
        assert!(options.cmd.is_empty());
        assert!(options.entrypoint.is_empty());
        assert!(options.mounts().is_empty());
        assert_eq!(options.memory, None);
        assert_eq!(options.nano_cpus, None);
        assert_eq!(options.restart_policy.condition, RestartCondition::None);
        assert_eq!(options.platform, None);
    }

    #[test]
    fn cmd_and_entrypoint_accept_string_or_list() {
        assert_eq!(
            StringOrList::One("sh".to_owned()).into_vec(),
            vec!["sh".to_owned()]
        );
        let options = create_container_options(
            body(serde_json::json!({"Image": "nginx", "Cmd": "sleep 1"})),
            None,
            None,
        )
        .expect("valid body");
        assert_eq!(options.cmd, ["sleep 1"]);
    }

    #[test]
    fn invalid_create_bodies_are_rejected_with_docker_messages() {
        let cases: [(serde_json::Value, &str); 12] = [
            (serde_json::json!({}), "no image specified"),
            (
                serde_json::json!({"Image": "n", "HostConfig": {"Binds": ["only-one-part"]}}),
                "invalid bind mount",
            ),
            (
                serde_json::json!({"Image": "n", "HostConfig": {"Binds": ["/a:b"]}}),
                "destination must be an absolute path",
            ),
            (
                serde_json::json!({"Image": "n", "HostConfig": {"Binds": ["/a:/b:Z"]}}),
                "unsupported mount option",
            ),
            (
                serde_json::json!({"Image": "n", "ExposedPorts": {"80/sctp": {}}}),
                "unsupported protocol",
            ),
            (
                serde_json::json!({"Image": "n", "ExposedPorts": {"8000-8010/tcp": {}}}),
                "port ranges are not supported",
            ),
            (
                serde_json::json!({"Image": "n", "HostConfig": {
                    "PortBindings": {"80/tcp": [{"HostPort": "8080-8090"}]}}}),
                "invalid host port",
            ),
            (
                serde_json::json!({"Image": "n", "HostConfig": {"Privileged": true}}),
                "Privileged is not supported",
            ),
            (
                serde_json::json!({"Image": "n", "HostConfig": {"CapAdd": ["NET_ADMIN"]}}),
                "CapAdd/CapDrop is not supported",
            ),
            (
                serde_json::json!({"Image": "n", "HostConfig": {"NetworkMode": "host"}}),
                "network mode \"host\" is not supported",
            ),
            (
                serde_json::json!({"Image": "n", "HostConfig": {
                    "AutoRemove": true, "RestartPolicy": {"Name": "always"}}}),
                "conflicting options",
            ),
            (
                serde_json::json!({"Image": "n", "HostConfig": {
                    "RestartPolicy": {"Name": "sometimes"}}}),
                "invalid restart policy",
            ),
        ];
        for (json, expected) in cases {
            let err = create_container_options(body(json.clone()), None, None)
                .expect_err(&format!("must reject {json}"));
            let BackendError::InvalidParameter(message) = err else {
                panic!("expected InvalidParameter for {json}, got {err:?}");
            };
            assert!(
                message.contains(expected),
                "for {json}: message {message:?} must contain {expected:?}"
            );
        }
    }

    #[test]
    fn container_names_follow_satl_service_naming() {
        for name in ["web", "web-1", "a"] {
            assert!(
                create_container_options(body(serde_json::json!({"Image": "n"})), Some(name), None)
                    .is_ok(),
                "{name} must be accepted"
            );
        }
        for name in ["my.app", "-web", "web/1", ""] {
            let result =
                create_container_options(body(serde_json::json!({"Image": "n"})), Some(name), None);
            if name.is_empty() {
                // An empty ?name= is "no name at all", not an error.
                assert_eq!(result.expect("empty name is ignored").name, None);
            } else {
                let err = result.expect_err("must be rejected");
                assert!(
                    err.to_string().contains("invalid container name"),
                    "{name}: {err}"
                );
            }
        }
    }

    #[test]
    fn restart_policies_map_to_task_conditions() {
        let cases = [
            ("", 0, RestartCondition::None, 0),
            ("no", 0, RestartCondition::None, 0),
            ("always", 0, RestartCondition::Any, 0),
            ("unless-stopped", 0, RestartCondition::Any, 0),
            ("on-failure", 0, RestartCondition::OnFailure, 0),
            ("on-failure", 5, RestartCondition::OnFailure, 5),
        ];
        for (name, retries, condition, attempts) in cases {
            let policy = restart_policy(Some(&RestartPolicyBody {
                name: name.to_owned(),
                maximum_retry_count: retries,
            }))
            .unwrap_or_else(|err| panic!("{name} must be accepted: {err}"));
            assert_eq!(policy.condition, condition, "for {name}");
            assert_eq!(policy.max_attempts, attempts, "for {name}");
        }
        assert!(restart_policy(None).is_ok());
        let err = restart_policy(Some(&RestartPolicyBody {
            name: "always".to_owned(),
            maximum_retry_count: 2,
        }))
        .expect_err("retry count needs on-failure");
        assert!(err.to_string().contains("maximum retry count"), "{err}");
    }

    #[test]
    fn port_keys_and_bindings_parse() {
        assert_eq!(parse_port_key("80"), Ok((80, PortProtocol::Tcp)));
        assert_eq!(parse_port_key("53/udp"), Ok((53, PortProtocol::Udp)));
        assert_eq!(parse_port_key("443/TCP"), Ok((443, PortProtocol::Tcp)));
        assert!(parse_port_key("0/tcp").is_err());
        assert!(parse_port_key("http/tcp").is_err());

        let mut map = BTreeMap::new();
        map.insert("80/tcp".to_owned(), None);
        map.insert(
            "53/udp".to_owned(),
            Some(vec![PortBindingBody {
                host_ip: String::new(),
                host_port: String::new(),
            }]),
        );
        let bindings = port_bindings(&map).expect("valid bindings");
        assert_eq!(
            bindings,
            [PortMapping {
                host_ip: None,
                host_port: 0,
                container_port: 53,
                protocol: PortProtocol::Udp,
            }],
            "a null binding list declares nothing to publish"
        );
    }

    #[test]
    fn platforms_parse_and_reject() {
        assert_eq!(
            parse_platform("freebsd/amd64"),
            Ok(Platform {
                os: "freebsd".to_owned(),
                arch: "amd64".to_owned()
            })
        );
        assert_eq!(
            parse_platform("linux/arm64/v8"),
            Ok(Platform {
                os: "linux".to_owned(),
                arch: "arm64".to_owned()
            }),
            "the variant is accepted and ignored"
        );
        for bad in ["", "linux", "/amd64", "linux/", "a/b/c/d"] {
            assert!(parse_platform(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn image_references_join_from_image_and_tag() {
        let cases = [
            ("nginx", None, "nginx"),
            ("nginx", Some("1.27"), "nginx:1.27"),
            ("nginx", Some(""), "nginx"),
            ("nginx:1.27", Some("latest"), "nginx:1.27"),
            ("registry:5000/app", Some("v1"), "registry:5000/app:v1"),
            ("nginx", Some("sha256:abc"), "nginx@sha256:abc"),
            ("nginx@sha256:abc", None, "nginx@sha256:abc"),
        ];
        for (from_image, tag, expected) in cases {
            assert_eq!(
                image_reference(from_image, tag).as_deref(),
                Ok(expected),
                "for {from_image:?} + {tag:?}"
            );
        }
        assert!(image_reference("", None).is_err());
    }

    #[test]
    fn tag_target_joins_repo_and_tag() {
        let cases = [
            (
                "registry.example.com/app",
                Some("v1"),
                "registry.example.com/app:v1",
            ),
            ("127.0.0.1:5000/app", Some("v1"), "127.0.0.1:5000/app:v1"),
            ("nginx", Some("1.27"), "nginx:1.27"),
            ("nginx", None, "nginx"),
            ("nginx", Some(""), "nginx"),
            ("nginx:1.27", Some("ignored"), "nginx:1.27"),
        ];
        for (repo, tag, expected) in cases {
            assert_eq!(
                tag_target(repo, tag).as_deref(),
                Ok(expected),
                "for {repo:?} + {tag:?}"
            );
        }
        assert!(tag_target("", None).is_err());
        assert!(tag_target("  ", Some("v1")).is_err());
    }

    #[test]
    fn registry_auth_decodes_both_base64_alphabets() {
        let json = serde_json::json!({
            "username": "frédéric",
            "password": "hunter2?/+",
            "serveraddress": "registry.example.com",
            "identitytoken": "id-token"
        })
        .to_string();
        for engine in [
            base64::engine::general_purpose::URL_SAFE,
            base64::engine::general_purpose::STANDARD,
            base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ] {
            let header = engine.encode(&json);
            let auth = decode_registry_auth(&header).expect("valid header");
            assert_eq!(auth.username, "frédéric");
            assert_eq!(auth.password, "hunter2?/+");
            assert_eq!(auth.server_address, "registry.example.com");
            assert_eq!(auth.identity_token, "id-token");
            assert!(auth.registry_token.is_empty());
        }
    }

    #[test]
    fn registry_auth_rejects_garbage() {
        let err = decode_registry_auth("!!!not base64!!!").expect_err("must reject");
        assert!(err.to_string().contains("not valid base64"), "{err}");
        let header = base64::engine::general_purpose::URL_SAFE.encode("not json");
        let err = decode_registry_auth(&header).expect_err("must reject");
        assert!(err.to_string().contains("AuthConfig"), "{err}");
    }

    #[test]
    fn exec_configs_validate_and_default_streams() {
        let config = exec_config(
            serde_json::from_value(serde_json::json!({
                "Cmd": ["sh", "-c", "echo hi"],
                "Env": ["A=1"],
                "WorkingDir": "/srv",
                "User": "root"
            }))
            .expect("body"),
        )
        .expect("valid config");
        assert_eq!(config.cmd, ["sh", "-c", "echo hi"]);
        assert_eq!(config.env, ["A=1"]);
        assert_eq!(config.working_dir.as_deref(), Some("/srv"));
        assert_eq!(config.user.as_deref(), Some("root"));
        assert!(config.attach_stdout && config.attach_stderr);

        let only_stderr = exec_config(
            serde_json::from_value(serde_json::json!({"Cmd": ["ls"], "AttachStderr": true}))
                .expect("body"),
        )
        .expect("valid config");
        assert!(!only_stderr.attach_stdout && only_stderr.attach_stderr);

        for (json, expected) in [
            (
                serde_json::json!({"Cmd": ["sh"], "Tty": true}),
                "tty not supported yet",
            ),
            (serde_json::json!({"Cmd": []}), "no command specified"),
            (
                serde_json::json!({"Cmd": ["sh"], "Privileged": true}),
                "privileged exec is not supported",
            ),
        ] {
            let err = exec_config(serde_json::from_value(json).expect("body"))
                .expect_err("must be rejected");
            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    #[test]
    fn volume_options_default_to_the_local_driver() {
        let options = volume_options(
            serde_json::from_value(serde_json::json!({"Name": "data", "Labels": {"a": "b"}}))
                .expect("body"),
        )
        .expect("valid options");
        assert_eq!(options.name, "data");
        assert_eq!(options.driver, "local");
        assert_eq!(options.labels["a"], "b");

        let err = volume_options(
            serde_json::from_value(serde_json::json!({"Name": "d", "Driver": "nfs"}))
                .expect("body"),
        )
        .expect_err("must reject foreign drivers");
        assert!(err.to_string().contains("not supported"), "{err}");
    }

    #[test]
    fn wait_conditions_parse() {
        assert_eq!(wait_condition(None), Ok(WaitCondition::NotRunning));
        assert_eq!(wait_condition(Some("")), Ok(WaitCondition::NotRunning));
        assert_eq!(
            wait_condition(Some("not-running")),
            Ok(WaitCondition::NotRunning)
        );
        assert_eq!(
            wait_condition(Some("next-exit")),
            Ok(WaitCondition::NextExit)
        );
        assert_eq!(wait_condition(Some("removed")), Ok(WaitCondition::Removed));
        assert!(wait_condition(Some("whenever")).is_err());
    }

    #[test]
    fn log_options_validate_streams_and_tail() {
        let options = log_options(true, true, false, Some("20"), true, Some("1770000000"))
            .expect("valid options");
        assert!(options.follow && options.stdout && !options.stderr && options.timestamps);
        assert_eq!(options.tail, Some(20));
        assert!(options.since.is_some());

        assert_eq!(
            log_options(false, true, true, Some("all"), false, None)
                .expect("valid")
                .tail,
            None
        );
        let err = log_options(false, false, false, None, false, None).expect_err("no streams");
        assert!(err.to_string().contains("at least one stream"), "{err}");
        assert!(log_options(false, true, true, Some("many"), false, None).is_err());
        assert!(log_options(false, true, true, None, false, Some("nope")).is_err());
    }
}
