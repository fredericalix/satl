// SPDX-License-Identifier: BSD-2-Clause
//! Parsers for docker's compound flag values: `-p`, `-v`, `--tmpfs`, `-e`,
//! `--env-file`, `--memory`, `--cpus`, `--restart`, `--label`, image
//! references.
//!
//! Every parser is pure and total (no environment access, no I/O) so the flag
//! matrix can be tested exhaustively; environment lookups are injected.

use std::collections::BTreeMap;

use crate::api::{Empty, PortBinding, RestartPolicy};

/// One `-p/--publish` mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    /// Host IP, when the operator gave one. Not honored yet: the CLI warns
    /// and publishes on every address.
    pub ignored_ip: Option<String>,
    /// Host port; `None` asks the daemon to pick a free one.
    pub host_port: Option<u16>,
    /// Container-side port.
    pub container_port: u16,
    /// `tcp` or `udp`.
    pub protocol: String,
}

impl PortSpec {
    /// The `"80/tcp"` key used by `ExposedPorts` and `PortBindings`.
    pub fn key(&self) -> String {
        format!("{}/{}", self.container_port, self.protocol)
    }

    /// The `PortBindings` value docker sends.
    pub fn binding(&self) -> PortBinding {
        PortBinding {
            host_ip: String::new(),
            host_port: self.host_port.map(|p| p.to_string()).unwrap_or_default(),
        }
    }
}

/// Parse `-p`: `container`, `host:container`, `ip:host:container`,
/// `ip::container`, each optionally suffixed with `/tcp` or `/udp`.
pub fn parse_publish(value: &str) -> anyhow::Result<PortSpec> {
    let (rest, protocol) = match value.rsplit_once('/') {
        Some((rest, proto)) => {
            let proto = proto.to_ascii_lowercase();
            if proto != "tcp" && proto != "udp" {
                anyhow::bail!("invalid publish spec {value:?}: protocol must be tcp or udp");
            }
            (rest, proto)
        }
        None => (value, "tcp".to_owned()),
    };
    if rest.is_empty() {
        anyhow::bail!("invalid publish spec {value:?}: no port given");
    }

    let (ip, remainder) = split_host_ip(rest);
    let parts: Vec<&str> = remainder.split(':').collect();
    let (host, container) = match parts.as_slice() {
        [container] => (None, *container),
        [host, container] => (Some(*host), *container),
        _ => anyhow::bail!(
            "invalid publish spec {value:?}: expected [ip:][hostPort:]containerPort[/protocol]"
        ),
    };
    if ip.is_some() && host.is_none() {
        anyhow::bail!(
            "invalid publish spec {value:?}: expected [ip:][hostPort:]containerPort[/protocol]"
        );
    }

    let container_port = parse_port(container, value)?;
    let host_port = match host {
        None | Some("") => None,
        Some(port) => Some(parse_port(port, value)?),
    };
    Ok(PortSpec {
        ignored_ip: ip.map(str::to_owned),
        host_port,
        container_port,
        protocol,
    })
}

/// Split a leading IP off `ip:host:container` / `[::1]:host:container`.
fn split_host_ip(value: &str) -> (Option<&str>, &str) {
    if let Some(rest) = value.strip_prefix('[') {
        // Bracketed IPv6 literal.
        if let Some((ip, rest)) = rest.split_once(']') {
            return (Some(ip), rest.strip_prefix(':').unwrap_or(rest));
        }
        return (None, value);
    }
    let colons = value.matches(':').count();
    if colons >= 2
        && let Some((ip, rest)) = value.split_once(':')
    {
        return (Some(ip), rest);
    }
    (None, value)
}

fn parse_port(value: &str, spec: &str) -> anyhow::Result<u16> {
    if value.contains('-') {
        anyhow::bail!("invalid publish spec {spec:?}: port ranges are not supported yet");
    }
    let port: u16 = value
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid publish spec {spec:?}: {value:?} is not a port"))?;
    if port == 0 {
        anyhow::bail!("invalid publish spec {spec:?}: port 0 is not valid");
    }
    Ok(port)
}

/// Fold parsed `-p` values into the create body's two maps.
// `ExposedPorts` has zero-sized values on the wire (`{"80/tcp": {}}`).
#[allow(clippy::zero_sized_map_values)]
pub fn port_maps(
    specs: &[PortSpec],
) -> (BTreeMap<String, Empty>, BTreeMap<String, Vec<PortBinding>>) {
    let mut exposed = BTreeMap::new();
    let mut bindings: BTreeMap<String, Vec<PortBinding>> = BTreeMap::new();
    for spec in specs {
        exposed.insert(spec.key(), Empty {});
        bindings.entry(spec.key()).or_default().push(spec.binding());
    }
    (exposed, bindings)
}

/// One `-v/--volume` mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSpec {
    /// Host path or volume name; `None` for an anonymous volume.
    pub source: Option<String>,
    /// Mount point inside the container.
    pub target: String,
    /// `:ro`.
    pub read_only: bool,
}

impl VolumeSpec {
    /// The `HostConfig.Binds` string docker sends.
    pub fn bind(&self) -> String {
        let mut out = match &self.source {
            Some(source) => format!("{source}:{}", self.target),
            None => self.target.clone(),
        };
        if self.read_only {
            out.push_str(":ro");
        }
        out
    }
}

/// Parse `-v`: `target`, `source:target` or `source:target:ro|rw`.
pub fn parse_volume(value: &str) -> anyhow::Result<VolumeSpec> {
    let parts: Vec<&str> = value.split(':').collect();
    let (source, target, mode) = match parts.as_slice() {
        [target] => (None, *target, None),
        [source, target] => (Some(*source), *target, None),
        [source, target, mode] => (Some(*source), *target, Some(*mode)),
        _ => anyhow::bail!("invalid volume spec {value:?}: expected [source:]target[:ro|:rw]"),
    };
    if !target.starts_with('/') {
        anyhow::bail!("invalid volume spec {value:?}: the mount point must be an absolute path");
    }
    if source.is_some_and(str::is_empty) {
        anyhow::bail!("invalid volume spec {value:?}: empty source");
    }
    let read_only = match mode {
        None | Some("rw") => false,
        Some("ro") => true,
        Some(other) => anyhow::bail!(
            "invalid volume spec {value:?}: unsupported mount option {other:?} (only ro and rw)"
        ),
    };
    Ok(VolumeSpec {
        source: source.map(str::to_owned),
        target: target.to_owned(),
        read_only,
    })
}

/// Parse `--tmpfs`: `/path` or `/path:options`.
pub fn parse_tmpfs(value: &str) -> anyhow::Result<(String, String)> {
    let (path, options) = value
        .split_once(':')
        .map_or((value, String::new()), |(path, options)| {
            (path, options.to_owned())
        });
    if !path.starts_with('/') {
        anyhow::bail!("invalid tmpfs spec {value:?}: the mount point must be an absolute path");
    }
    Ok((path.to_owned(), options))
}

/// Parse `-e`: `KEY=VALUE`, or bare `KEY` meaning "inherit from the
/// environment" (docker's behavior — an unset name is dropped entirely).
pub fn parse_env<F>(value: &str, lookup: &F) -> anyhow::Result<Option<String>>
where
    F: Fn(&str) -> Option<String>,
{
    match value.split_once('=') {
        Some(("", _)) => {
            anyhow::bail!("invalid environment variable {value:?}: empty name")
        }
        Some(_) => Ok(Some(value.to_owned())),
        None => {
            validate_env_name(value)?;
            Ok(lookup(value).map(|resolved| format!("{value}={resolved}")))
        }
    }
}

fn validate_env_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("invalid environment variable: empty name");
    }
    if name.chars().any(char::is_whitespace) {
        anyhow::bail!("poorly formatted environment: variable {name:?} contains whitespace");
    }
    Ok(())
}

/// Parse the contents of an `--env-file`: one `KEY=VALUE` per line, `#`
/// comments and blank lines skipped, a bare `KEY` inherited from the
/// environment. Values are taken verbatim (docker does not trim or unquote).
pub fn parse_env_file<F>(contents: &str, lookup: &F) -> anyhow::Result<Vec<String>>
where
    F: Fn(&str) -> Option<String>,
{
    let mut out = Vec::new();
    for line in contents.lines() {
        let line = line.strip_prefix('\u{feff}').unwrap_or(line);
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim_end();
            validate_env_name(key)?;
            out.push(format!("{key}={value}"));
        } else {
            // A bare name inherits the value from our own environment.
            let key = trimmed.trim_end();
            validate_env_name(key)?;
            if let Some(resolved) = lookup(key) {
                out.push(format!("{key}={resolved}"));
            }
        }
    }
    Ok(out)
}

/// Parse `--memory`: docker's `units.RAMInBytes` (binary units, optional
/// `b`/`k`/`m`/`g`/`t`/`p` suffix, optional `i`/`b` tail, fractions allowed).
pub fn parse_memory(value: &str) -> anyhow::Result<i64> {
    let raw = value.trim();
    let invalid =
        || anyhow::anyhow!("invalid memory value {value:?}: expected e.g. 512m, 1g, 2.5g");
    if raw.is_empty() {
        return Err(invalid());
    }
    let digits_end = raw
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(raw.len());
    let (number, suffix) = raw.split_at(digits_end);
    let number: f64 = number.parse().map_err(|_| invalid())?;
    let suffix = suffix.trim_start().to_ascii_lowercase();
    let multiplier: f64 = match suffix.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" | "tib" => 1024.0_f64.powi(4),
        "p" | "pb" | "pib" => 1024.0_f64.powi(5),
        _ => return Err(invalid()),
    };
    let bytes = number * multiplier;
    if bytes < 0.0 || !bytes.is_finite() {
        return Err(invalid());
    }
    #[allow(clippy::cast_possible_truncation)] // byte counts fit i64 well below 2^63
    let bytes = bytes as i64;
    if bytes == 0 {
        anyhow::bail!("invalid memory value {value:?}: must be greater than 0");
    }
    Ok(bytes)
}

/// Parse `--cpus` into `NanoCpus`. Decimal arithmetic on the digits, not
/// floating point: `0.1` must be exactly 100000000.
pub fn parse_nano_cpus(value: &str) -> anyhow::Result<i64> {
    let invalid = || anyhow::anyhow!("invalid cpu value {value:?}: expected e.g. 1, 0.5, 2.25");
    let raw = value.trim();
    let (whole, fraction) = match raw.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (raw, ""),
    };
    if whole.is_empty() && fraction.is_empty() {
        return Err(invalid());
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !fraction.chars().all(|c| c.is_ascii_digit()) {
        return Err(invalid());
    }
    if fraction.len() > 9 {
        anyhow::bail!("invalid cpu value {value:?}: at most 9 decimal places");
    }
    let whole: i64 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| invalid())?
    };
    let mut nanos = whole
        .checked_mul(1_000_000_000)
        .ok_or_else(|| anyhow::anyhow!("invalid cpu value {value:?}: too large"))?;
    if !fraction.is_empty() {
        let padded = format!("{fraction:0<9}");
        let fraction: i64 = padded.parse().map_err(|_| invalid())?;
        nanos += fraction;
    }
    if nanos <= 0 {
        anyhow::bail!("invalid cpu value {value:?}: must be greater than 0");
    }
    Ok(nanos)
}

/// Parse `--restart`: `no`, `always`, `on-failure` or `on-failure:N`.
pub fn parse_restart(value: &str) -> anyhow::Result<RestartPolicy> {
    let (name, count) = match value.split_once(':') {
        Some((name, count)) => (name, Some(count)),
        None => (value, None),
    };
    let maximum_retry_count = match count {
        None => 0,
        Some(count) => count.parse::<u32>().map_err(|_| {
            anyhow::anyhow!("invalid restart policy {value:?}: {count:?} is not a retry count")
        })?,
    };
    match name {
        "no" | "always" | "on-failure" => {}
        "unless-stopped" => anyhow::bail!(
            "invalid restart policy {value:?}: unless-stopped has no equivalent in SatL's \
             restart supervisor (use always or on-failure)"
        ),
        other => anyhow::bail!(
            "invalid restart policy {other:?}: supported policies are no, on-failure[:max] and always"
        ),
    }
    if maximum_retry_count > 0 && name != "on-failure" {
        anyhow::bail!("maximum retry count cannot be used with restart policy {name:?}");
    }
    Ok(RestartPolicy {
        name: name.to_owned(),
        maximum_retry_count,
    })
}

/// Parse `--label`: `key=value`, or bare `key` for an empty value.
pub fn parse_label(value: &str) -> anyhow::Result<(String, String)> {
    let (key, value) = match value.split_once('=') {
        Some((key, value)) => (key, value.to_owned()),
        None => (value, String::new()),
    };
    if key.is_empty() {
        anyhow::bail!("invalid label: empty key");
    }
    Ok((key.to_owned(), value))
}

/// One `--secret` / `--config` reference: which stored object, and the file it
/// becomes inside the task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRef {
    /// Secret/config name in the cluster store.
    pub source: String,
    /// File name inside the task; defaults to `source`.
    pub target: String,
    /// Owning user inside the task.
    pub uid: String,
    /// Owning group inside the task.
    pub gid: String,
    /// Permission bits, as an octal mode was written on the command line.
    pub mode: u32,
}

/// Default permissions of a delivered secret/config file, as docker's.
pub const DEFAULT_FILE_MODE: u32 = 0o444;

/// Parse `--secret`: a bare `NAME`, or docker's CSV form
/// `source=NAME[,target=FILE][,uid=UID][,gid=GID][,mode=0444]` (`src=` is an
/// accepted alias of `source=`).
pub fn parse_secret_ref(value: &str) -> anyhow::Result<FileRef> {
    parse_file_ref(value, "secret")
}

/// Parse `--config`, in exactly the same forms as [`parse_secret_ref`]. The
/// target of a config is rooted at `/` by the daemon, a secret's at
/// `/run/secrets`; that difference is the daemon's, not this parser's.
pub fn parse_config_ref(value: &str) -> anyhow::Result<FileRef> {
    parse_file_ref(value, "config")
}

/// The shared parser behind `--secret` and `--config`; `kind` only shapes the
/// error messages.
fn parse_file_ref(value: &str, kind: &str) -> anyhow::Result<FileRef> {
    let invalid = |detail: String| anyhow::anyhow!("invalid {kind} reference {value:?}: {detail}");
    if value.is_empty() {
        return Err(invalid("empty".to_owned()));
    }

    // Docker's rule: no '=' anywhere means the whole value is the name.
    if !value.contains('=') {
        if value.contains(',') {
            return Err(invalid(format!(
                "expected NAME or source=NAME[,target=FILE][,uid=UID][,gid=GID]\
                 [,mode=0{DEFAULT_FILE_MODE:o}]"
            )));
        }
        return Ok(FileRef {
            source: value.to_owned(),
            target: value.to_owned(),
            uid: "0".to_owned(),
            gid: "0".to_owned(),
            mode: DEFAULT_FILE_MODE,
        });
    }

    let mut source = String::new();
    let mut target = String::new();
    let mut uid = "0".to_owned();
    let mut gid = "0".to_owned();
    let mut mode = DEFAULT_FILE_MODE;
    for field in value.split(',') {
        let (key, option) = field
            .split_once('=')
            .ok_or_else(|| invalid(format!("expected KEY=VALUE, got {field:?}")))?;
        // Docker matches the keys case-insensitively.
        match key.to_ascii_lowercase().as_str() {
            "source" | "src" => option.clone_into(&mut source),
            "target" => option.clone_into(&mut target),
            "uid" => option.clone_into(&mut uid),
            "gid" => option.clone_into(&mut gid),
            "mode" => {
                mode = u32::from_str_radix(option, 8).map_err(|_| {
                    invalid(format!(
                        "invalid mode {option:?}: expected an octal file mode such as 0444"
                    ))
                })?;
                if mode > 0o7777 {
                    return Err(invalid(format!(
                        "invalid mode {option:?}: at most 7777 (octal)"
                    )));
                }
            }
            _ => return Err(invalid(format!("unknown option {key:?}"))),
        }
    }
    if source.is_empty() {
        return Err(invalid(format!("no {kind} name given (source=NAME)")));
    }
    if target.is_empty() {
        // Docker's default: the file is named after the object.
        target.clone_from(&source);
    }
    Ok(FileRef {
        source,
        target,
        uid,
        gid,
        mode,
    })
}

/// An image reference split the way `POST /images/create` wants it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// Repository, registry host included when the operator gave one.
    pub name: String,
    /// Tag or `sha256:…` digest; `latest` when unspecified.
    pub tag: String,
    /// True when `tag` is a digest (`name@sha256:…`).
    pub is_digest: bool,
}

impl ImageRef {
    /// Render back to the reference the operator typed.
    pub fn canonical(&self) -> String {
        if self.is_digest {
            format!("{}@{}", self.name, self.tag)
        } else {
            format!("{}:{}", self.name, self.tag)
        }
    }
}

/// Split `name[:tag]` / `name@digest`. A colon inside a registry host with a
/// port (`localhost:5000/nginx`) is not a tag.
pub fn parse_image_ref(value: &str) -> anyhow::Result<ImageRef> {
    if value.is_empty() {
        anyhow::bail!("invalid image reference: empty");
    }
    if let Some((name, digest)) = value.split_once('@') {
        if name.is_empty() || digest.is_empty() {
            anyhow::bail!("invalid image reference {value:?}");
        }
        return Ok(ImageRef {
            name: name.to_owned(),
            tag: digest.to_owned(),
            is_digest: true,
        });
    }
    let tag_start = value.rfind(':').filter(|index| {
        // A colon before the last '/' belongs to a registry host:port.
        value[*index..].find('/').is_none()
    });
    match tag_start {
        Some(index) => {
            let (name, tag) = value.split_at(index);
            let tag = &tag[1..];
            if name.is_empty() || tag.is_empty() {
                anyhow::bail!("invalid image reference {value:?}");
            }
            Ok(ImageRef {
                name: name.to_owned(),
                tag: tag.to_owned(),
                is_digest: false,
            })
        }
        None => Ok(ImageRef {
            name: value.to_owned(),
            tag: "latest".to_owned(),
            is_digest: false,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn fake_env(name: &str) -> Option<String> {
        match name {
            "HOME" => Some("/root".to_owned()),
            "EMPTY" => Some(String::new()),
            _ => None,
        }
    }

    #[test]
    fn publish_forms() {
        let spec = parse_publish("8080:80").unwrap();
        assert_eq!(
            spec,
            PortSpec {
                ignored_ip: None,
                host_port: Some(8080),
                container_port: 80,
                protocol: "tcp".to_owned(),
            }
        );
        assert_eq!(spec.key(), "80/tcp");
        assert_eq!(spec.binding().host_port, "8080");

        assert_eq!(
            parse_publish("53:53/udp").unwrap().protocol,
            "udp".to_owned()
        );
        // Container port only: the daemon picks the host port.
        let spec = parse_publish("80").unwrap();
        assert_eq!(spec.host_port, None);
        assert_eq!(spec.container_port, 80);
        assert_eq!(spec.binding().host_port, "");

        // ip:host:container — the ip is remembered so the caller can warn.
        let spec = parse_publish("127.0.0.1:8080:80").unwrap();
        assert_eq!(spec.ignored_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(spec.host_port, Some(8080));
        assert_eq!(spec.binding().host_ip, "");

        // ip::container leaves the host port to the daemon.
        let spec = parse_publish("127.0.0.1::80").unwrap();
        assert_eq!(spec.ignored_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(spec.host_port, None);

        // Bracketed IPv6.
        let spec = parse_publish("[::1]:8080:80/udp").unwrap();
        assert_eq!(spec.ignored_ip.as_deref(), Some("::1"));
        assert_eq!(spec.host_port, Some(8080));
        assert_eq!(spec.protocol, "udp");
    }

    #[test]
    fn publish_rejections() {
        for (value, needle) in [
            ("8080:80/sctp", "tcp or udp"),
            ("8080:80:70:60", "expected [ip:]"),
            ("8000-8005:80", "ranges are not supported"),
            ("http:80", "is not a port"),
            ("0:80", "port 0"),
            ("", "no port given"),
        ] {
            let err = parse_publish(value).unwrap_err();
            assert!(err.to_string().contains(needle), "{value}: {err}");
        }
    }

    #[test]
    fn publish_maps_group_by_container_port() {
        let specs = vec![
            parse_publish("8080:80").unwrap(),
            parse_publish("8081:80").unwrap(),
            parse_publish("53:53/udp").unwrap(),
        ];
        let (exposed, bindings) = port_maps(&specs);
        assert_eq!(exposed.keys().collect::<Vec<_>>(), vec!["53/udp", "80/tcp"]);
        assert_eq!(bindings["80/tcp"].len(), 2);
        assert_eq!(bindings["80/tcp"][1].host_port, "8081");
    }

    #[test]
    fn volume_forms() {
        assert_eq!(
            parse_volume("/data").unwrap(),
            VolumeSpec {
                source: None,
                target: "/data".to_owned(),
                read_only: false
            }
        );
        let spec = parse_volume("web-data:/usr/share/nginx/html:ro").unwrap();
        assert!(spec.read_only);
        assert_eq!(spec.bind(), "web-data:/usr/share/nginx/html:ro");
        assert_eq!(
            parse_volume("/host:/container").unwrap().bind(),
            "/host:/container"
        );
        assert_eq!(
            parse_volume("/host:/container:rw").unwrap().bind(),
            "/host:/container"
        );
        assert_eq!(parse_volume("/data").unwrap().bind(), "/data");

        for (value, needle) in [
            ("data:relative", "absolute path"),
            (":/data", "empty source"),
            ("/a:/b:z", "unsupported mount option"),
            ("/a:/b:ro:extra", "expected [source:]"),
        ] {
            let err = parse_volume(value).unwrap_err();
            assert!(err.to_string().contains(needle), "{value}: {err}");
        }
    }

    #[test]
    fn tmpfs_forms() {
        assert_eq!(
            parse_tmpfs("/run").unwrap(),
            ("/run".to_owned(), String::new())
        );
        assert_eq!(
            parse_tmpfs("/run:rw,size=64m").unwrap(),
            ("/run".to_owned(), "rw,size=64m".to_owned())
        );
        assert!(parse_tmpfs("run").is_err());
    }

    #[test]
    fn env_forms() {
        assert_eq!(
            parse_env("KEY=value", &no_env).unwrap(),
            Some("KEY=value".to_owned())
        );
        // Values keep their spaces and '=' signs.
        assert_eq!(
            parse_env("KEY=a=b c", &no_env).unwrap(),
            Some("KEY=a=b c".to_owned())
        );
        // Empty value is preserved.
        assert_eq!(parse_env("KEY=", &no_env).unwrap(), Some("KEY=".to_owned()));
        // Bare name resolves from the environment, or is dropped.
        assert_eq!(
            parse_env("HOME", &fake_env).unwrap(),
            Some("HOME=/root".to_owned())
        );
        assert_eq!(parse_env("NOPE", &fake_env).unwrap(), None);
        assert!(parse_env("=value", &no_env).is_err());
        assert!(parse_env("BAD NAME", &no_env).is_err());
    }

    #[test]
    fn env_file_parsing() {
        let file = "\
# a comment
   # indented comment

FOO=bar
SPACED=  keeps leading space
EQUALS=a=b
KEY_WITH_TRAILING_SPACE  =value
HOME
MISSING
EMPTY
";
        let parsed = parse_env_file(file, &fake_env).unwrap();
        assert_eq!(
            parsed,
            vec![
                "FOO=bar".to_owned(),
                "SPACED=  keeps leading space".to_owned(),
                "EQUALS=a=b".to_owned(),
                "KEY_WITH_TRAILING_SPACE=value".to_owned(),
                "HOME=/root".to_owned(),
                "EMPTY=".to_owned(),
            ]
        );
    }

    #[test]
    fn env_file_rejects_bad_names() {
        let err = parse_env_file("BAD NAME=1\n", &no_env).unwrap_err();
        assert!(err.to_string().contains("contains whitespace"), "{err}");
    }

    #[test]
    fn memory_units() {
        assert_eq!(parse_memory("512m").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_memory("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_memory("512mb").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_memory("512MiB").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_memory("1g").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_memory("1.5g").unwrap(), 1_610_612_736);
        assert_eq!(parse_memory("2k").unwrap(), 2048);
        assert_eq!(parse_memory("1048576").unwrap(), 1_048_576);
        assert_eq!(parse_memory("64b").unwrap(), 64);
        for value in ["", "abc", "-1g", "12x", "0", "0m"] {
            assert!(parse_memory(value).is_err(), "{value} should be rejected");
        }
    }

    #[test]
    fn cpu_values_are_exact() {
        assert_eq!(parse_nano_cpus("1").unwrap(), 1_000_000_000);
        assert_eq!(parse_nano_cpus("0.5").unwrap(), 500_000_000);
        assert_eq!(parse_nano_cpus("0.1").unwrap(), 100_000_000);
        assert_eq!(parse_nano_cpus("2.25").unwrap(), 2_250_000_000);
        assert_eq!(parse_nano_cpus(".5").unwrap(), 500_000_000);
        assert_eq!(parse_nano_cpus("0.000000001").unwrap(), 1);
        for value in ["", "-1", "abc", "1.2.3", "0", "0.0000000001"] {
            assert!(
                parse_nano_cpus(value).is_err(),
                "{value} should be rejected"
            );
        }
    }

    #[test]
    fn restart_policies() {
        assert_eq!(
            parse_restart("no").unwrap(),
            RestartPolicy {
                name: "no".to_owned(),
                maximum_retry_count: 0
            }
        );
        assert_eq!(
            parse_restart("on-failure:5").unwrap(),
            RestartPolicy {
                name: "on-failure".to_owned(),
                maximum_retry_count: 5
            }
        );
        assert_eq!(parse_restart("on-failure").unwrap().maximum_retry_count, 0);
        assert_eq!(parse_restart("always").unwrap().name, "always");

        let err = parse_restart("always:3").unwrap_err();
        assert!(err.to_string().contains("maximum retry count"), "{err}");
        let err = parse_restart("unless-stopped").unwrap_err();
        assert!(err.to_string().contains("no equivalent"), "{err}");
        let err = parse_restart("sometimes").unwrap_err();
        assert!(err.to_string().contains("supported policies"), "{err}");
        assert!(parse_restart("on-failure:many").is_err());
    }

    #[test]
    fn labels() {
        assert_eq!(
            parse_label("role=web").unwrap(),
            ("role".to_owned(), "web".to_owned())
        );
        assert_eq!(
            parse_label("marker").unwrap(),
            ("marker".to_owned(), String::new())
        );
        assert!(parse_label("=x").is_err());
    }

    #[test]
    fn a_bare_secret_name_is_the_source_and_the_target() {
        assert_eq!(
            parse_secret_ref("site-cert").unwrap(),
            FileRef {
                source: "site-cert".to_owned(),
                target: "site-cert".to_owned(),
                uid: "0".to_owned(),
                gid: "0".to_owned(),
                mode: 0o444,
            }
        );
        // A config reference defaults the same way.
        assert_eq!(
            parse_config_ref("nginx-conf").unwrap(),
            FileRef {
                source: "nginx-conf".to_owned(),
                target: "nginx-conf".to_owned(),
                uid: "0".to_owned(),
                gid: "0".to_owned(),
                mode: 0o444,
            }
        );
    }

    #[test]
    fn the_csv_form_names_every_field_and_mode_is_octal() {
        assert_eq!(
            parse_secret_ref("source=site-cert,target=site.pem,uid=80,gid=80,mode=0400").unwrap(),
            FileRef {
                source: "site-cert".to_owned(),
                target: "site.pem".to_owned(),
                uid: "80".to_owned(),
                gid: "80".to_owned(),
                mode: 0o400,
            }
        );
        // `src=` is docker's alias, keys are case-insensitive, and a mode
        // without its leading zero is still octal.
        let reference = parse_config_ref("src=nginx-conf,TARGET=/etc/nginx/nginx.conf,mode=644")
            .expect("valid");
        assert_eq!(reference.source, "nginx-conf");
        assert_eq!(reference.target, "/etc/nginx/nginx.conf");
        assert_eq!(reference.mode, 0o644, "644 is octal, not decimal");
        // An unnamed target is the object's own name.
        assert_eq!(
            parse_secret_ref("source=site-cert,mode=0400")
                .unwrap()
                .target,
            "site-cert"
        );
    }

    #[test]
    fn bad_secret_and_config_references_are_refused() {
        for (value, needle) in [
            ("", "empty"),
            ("target=site.pem", "no secret name given"),
            ("source=site-cert,owner=root", "unknown option \"owner\""),
            ("source=site-cert,mode=0999", "expected an octal file mode"),
            ("source=site-cert,mode=17777", "at most 7777"),
            ("source=site-cert,site.pem", "expected KEY=VALUE"),
            ("a,b", "expected NAME or source=NAME"),
        ] {
            let err = parse_secret_ref(value).unwrap_err();
            assert!(err.to_string().contains(needle), "{value}: {err}");
            assert!(
                err.to_string().contains("invalid secret reference"),
                "{value}: {err}"
            );
        }
        let err = parse_config_ref("target=x").unwrap_err();
        assert!(err.to_string().contains("no config name given"), "{err}");
    }

    #[test]
    fn image_references() {
        assert_eq!(
            parse_image_ref("nginx").unwrap(),
            ImageRef {
                name: "nginx".to_owned(),
                tag: "latest".to_owned(),
                is_digest: false
            }
        );
        assert_eq!(parse_image_ref("nginx:1.25").unwrap().tag, "1.25");
        let reference = parse_image_ref("127.0.0.1:5000/freebsd-nginx").unwrap();
        assert_eq!(reference.name, "127.0.0.1:5000/freebsd-nginx");
        assert_eq!(reference.tag, "latest");
        let reference = parse_image_ref("127.0.0.1:5000/freebsd-nginx:v1").unwrap();
        assert_eq!(reference.name, "127.0.0.1:5000/freebsd-nginx");
        assert_eq!(reference.tag, "v1");
        let reference = parse_image_ref("nginx@sha256:abc").unwrap();
        assert!(reference.is_digest);
        assert_eq!(reference.canonical(), "nginx@sha256:abc");
        assert_eq!(
            parse_image_ref("nginx:1.25").unwrap().canonical(),
            "nginx:1.25"
        );
        assert!(parse_image_ref("").is_err());
        assert!(parse_image_ref("nginx:").is_err());
    }
}
