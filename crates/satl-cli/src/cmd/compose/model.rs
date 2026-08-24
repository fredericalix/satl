// SPDX-License-Identifier: BSD-2-Clause
//! The Compose file as `satl compose` reads it: the supported subset, typed.
//!
//! Two rules shape every type here.
//!
//! **Nothing is silently dropped.** Every struct ends in a `rest` catch-all, so
//! a key SatL does not implement survives deserialization and is refused by
//! name in [`super::plan`] with a reason. `#[serde(deny_unknown_fields)]` would
//! have been shorter, but it cannot say *why* a key is refused and it cannot
//! make an exception for the `x-` extension keys the Compose Spec reserves.
//!
//! **The YAML crate stops here.** `rest` holds [`serde_json::Value`], not the
//! YAML crate's own value type, so this file — the parser's whole surface —
//! depends on `serde` alone. Only [`super::plan::parse`] names the YAML crate.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};

/// Every key of a mapping SatL did not name, kept so it can be refused.
pub type Rest = BTreeMap<String, serde_json::Value>;

/// A YAML scalar as the Compose Spec means it: text, whatever the node's type.
///
/// `environment: { REPLICAS: 3 }` and `user: 1000` are integers to any YAML
/// parser and strings to Compose. Deserializing them straight into `String`
/// fails ("invalid type: integer"), which would be a refusal an operator cannot
/// act on, so the number is rendered instead — exactly as compose-go does.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Scalar(pub String);

impl Scalar {
    /// The text of the scalar.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ScalarVisitor;

        impl Visitor<'_> for ScalarVisitor {
            type Value = Scalar;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string, number or boolean")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Scalar, E> {
                Ok(Scalar(value.to_owned()))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Scalar, E> {
                Ok(Scalar(value.to_string()))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Scalar, E> {
                Ok(Scalar(value.to_string()))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Scalar, E> {
                Ok(Scalar(value.to_string()))
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Scalar, E> {
                // Compose renders booleans lowercase, as YAML wrote them.
                Ok(Scalar(value.to_string()))
            }
        }

        deserializer.deserialize_any(ScalarVisitor)
    }
}

/// One value or a list of them — Compose's `command`, `entrypoint`, `env_file`,
/// `dns`, … all accept both spellings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalarList(pub Vec<Scalar>);

impl<'de> Deserialize<'de> for ScalarList {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ListVisitor;

        impl<'de> Visitor<'de> for ListVisitor {
            type Value = ScalarList;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string or a list of strings")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<ScalarList, E> {
                Ok(ScalarList(vec![Scalar(value.to_owned())]))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<ScalarList, E> {
                Ok(ScalarList(vec![Scalar(value.to_string())]))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<ScalarList, E> {
                Ok(ScalarList(vec![Scalar(value.to_string())]))
            }

            fn visit_unit<E: de::Error>(self) -> Result<ScalarList, E> {
                Ok(ScalarList(Vec::new()))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ScalarList, A::Error> {
                let mut out = Vec::new();
                while let Some(item) = seq.next_element::<Scalar>()? {
                    out.push(item);
                }
                Ok(ScalarList(out))
            }
        }

        deserializer.deserialize_any(ListVisitor)
    }
}

/// `environment:` and `labels:`, in either of Compose's two spellings: a
/// mapping (`KEY: value`, a null value meaning "inherit") or a list of
/// `KEY=value` / bare `KEY` strings.
///
/// Both are normalized here into ordered `(key, Option<value>)` pairs, `None`
/// standing for "take it from the environment `satl` itself runs in", which is
/// what `-e KEY` does (`crate::parse::parse_env`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyValues(pub Vec<(String, Option<String>)>);

impl<'de> Deserialize<'de> for KeyValues {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyValuesVisitor;

        impl<'de> Visitor<'de> for KeyValuesVisitor {
            type Value = KeyValues;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a mapping of KEY: value, or a list of KEY=value strings")
            }

            fn visit_unit<E: de::Error>(self) -> Result<KeyValues, E> {
                Ok(KeyValues::default())
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<KeyValues, A::Error> {
                let mut out = Vec::new();
                while let Some(item) = seq.next_element::<Scalar>()? {
                    match item.0.split_once('=') {
                        Some((key, value)) => out.push((key.to_owned(), Some(value.to_owned()))),
                        None => out.push((item.0, None)),
                    }
                }
                Ok(KeyValues(out))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<KeyValues, A::Error> {
                let mut out = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Option<Scalar>>()? {
                    out.push((key, value.map(|scalar| scalar.0)));
                }
                Ok(KeyValues(out))
            }
        }

        deserializer.deserialize_any(KeyValuesVisitor)
    }
}

/// `external: true`, or the legacy `external: { name: … }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum External {
    /// The plain boolean form.
    Flag(bool),
    /// The legacy mapping form; `name` renames the object.
    Named(Rest),
}

impl External {
    /// Whether the object is declared as living outside this project.
    pub fn is_external(&self) -> bool {
        match self {
            Self::Flag(flag) => *flag,
            Self::Named(_) => true,
        }
    }
}

impl<'de> Deserialize<'de> for External {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ExternalVisitor;

        impl<'de> Visitor<'de> for ExternalVisitor {
            type Value = External;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("true, false, or a mapping with a name")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<External, E> {
                Ok(External::Flag(value))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<External, A::Error> {
                let mut rest = Rest::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    rest.insert(key, value);
                }
                Ok(External::Named(rest))
            }
        }

        deserializer.deserialize_any(ExternalVisitor)
    }
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// A whole compose file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ComposeFile {
    /// The obsolete `version:` key. Accepted, warned about, ignored — as the
    /// Compose Spec and docker itself now do.
    #[serde(default)]
    pub version: Option<Scalar>,
    /// Project name declared in the file (Compose Spec `name:`).
    #[serde(default)]
    pub name: Option<String>,
    /// The services to deploy.
    #[serde(default)]
    pub services: BTreeMap<String, Service>,
    /// Networks the stack declares. A null body means "all defaults".
    #[serde(default)]
    pub networks: BTreeMap<String, Option<Network>>,
    /// Named volumes the stack declares.
    #[serde(default)]
    pub volumes: BTreeMap<String, Option<Volume>>,
    /// Secrets the stack refers to.
    #[serde(default)]
    pub secrets: BTreeMap<String, Option<Dependency>>,
    /// Configs the stack refers to.
    #[serde(default)]
    pub configs: BTreeMap<String, Option<Dependency>>,
    /// Every other top-level key, refused by name in [`super::plan`].
    #[serde(flatten)]
    pub rest: Rest,
}

/// One service of a compose file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Service {
    /// Image reference. Required unless the service declares `build:`, which
    /// names the image it produces.
    #[serde(default)]
    pub image: Option<String>,
    /// Build this service's image from a `Satlfile` before deploying it
    /// (`satl compose` only, M11e).
    #[serde(default)]
    pub build: Option<Build>,
    /// `command:` overrides the image's `CMD`.
    #[serde(default)]
    pub command: Option<ScalarList>,
    /// `entrypoint:` overrides the image's `ENTRYPOINT`.
    #[serde(default)]
    pub entrypoint: Option<ScalarList>,
    /// Environment for the task.
    #[serde(default)]
    pub environment: Option<KeyValues>,
    /// Files of `KEY=VALUE` lines, read relative to the project directory.
    #[serde(default)]
    pub env_file: Option<ScalarList>,
    /// Published ports.
    #[serde(default)]
    pub ports: Option<Vec<Port>>,
    /// Volumes and bind mounts.
    #[serde(default)]
    pub volumes: Option<Vec<VolumeMount>>,
    /// Secrets delivered into the task.
    #[serde(default)]
    pub secrets: Option<Vec<FileRef>>,
    /// Configs delivered into the task.
    #[serde(default)]
    pub configs: Option<Vec<FileRef>>,
    /// Container healthcheck.
    #[serde(default)]
    pub healthcheck: Option<Healthcheck>,
    /// Container labels (the service's own labels come from `deploy.labels`).
    #[serde(default)]
    pub labels: Option<KeyValues>,
    /// User to run as; numeric (api-compat 102).
    #[serde(default)]
    pub user: Option<Scalar>,
    /// Working directory inside the jail.
    #[serde(default)]
    pub working_dir: Option<String>,
    /// Hostname inside the jail.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Signal sent to stop the container.
    #[serde(default)]
    pub stop_signal: Option<String>,
    /// Grace period before SIGKILL.
    #[serde(default)]
    pub stop_grace_period: Option<Scalar>,
    /// Restart policy, in `docker run`'s spelling.
    #[serde(default)]
    pub restart: Option<Scalar>,
    /// Networks to attach to.
    #[serde(default)]
    pub networks: Option<Attachments>,
    /// Startup ordering, which SatL cannot guarantee.
    #[serde(default)]
    pub depends_on: Option<DependsOn>,
    /// The swarm half of the spec.
    #[serde(default)]
    pub deploy: Option<Deploy>,
    /// Every other service key, refused by name in [`super::plan`].
    #[serde(flatten)]
    pub rest: Rest,
}

/// Collect a mapping into its long form.
///
/// Compose spells half its members two ways — `"8080:80"` or
/// `{target: 80, published: 8080}` — and the long form needs a `rest`
/// catch-all like every other struct here. `#[serde(untagged)]` cannot carry
/// one (serde's content buffering and `flatten` do not compose), so the map is
/// collected into JSON first and the typed form read out of that. The value
/// types survive the hop: [`Scalar`] accepts JSON numbers exactly as it accepts
/// YAML ones.
fn long_form<'de, T, A>(mut map: A) -> Result<T, A::Error>
where
    T: serde::de::DeserializeOwned,
    A: MapAccess<'de>,
{
    let mut object = serde_json::Map::new();
    while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
        object.insert(key, value);
    }
    serde_json::from_value(serde_json::Value::Object(object)).map_err(de::Error::custom)
}

/// One `ports:` entry.
#[derive(Debug, Clone)]
pub enum Port {
    /// `"8080:80/tcp"`, docker's own short syntax.
    Short(Scalar),
    /// The long syntax.
    Long(PortLong),
}

/// The long form of a `ports:` entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PortLong {
    /// Container-side port.
    #[serde(default)]
    pub target: Option<Scalar>,
    /// Host-side port.
    #[serde(default)]
    pub published: Option<Scalar>,
    /// `tcp` or `udp`.
    #[serde(default)]
    pub protocol: Option<String>,
    /// `ingress` or `host`.
    #[serde(default)]
    pub mode: Option<String>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PortVisitor;

        impl<'de> Visitor<'de> for PortVisitor {
            type Value = Port;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a port string such as \"8080:80\", or a mapping")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Port, E> {
                Ok(Port::Short(Scalar(value.to_owned())))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Port, E> {
                Ok(Port::Short(Scalar(value.to_string())))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Port, E> {
                Ok(Port::Short(Scalar(value.to_string())))
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Port, A::Error> {
                long_form(map).map(Port::Long)
            }
        }

        deserializer.deserialize_any(PortVisitor)
    }
}

/// One `volumes:` entry of a service.
#[derive(Debug, Clone)]
pub enum VolumeMount {
    /// `"data:/var/db/redis:ro"`, docker's own short syntax.
    Short(String),
    /// The long syntax.
    Long(VolumeMountLong),
}

/// The long form of a service `volumes:` entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VolumeMountLong {
    /// `volume`, `bind` or `tmpfs`.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    /// Volume name or host path.
    #[serde(default)]
    pub source: Option<String>,
    /// Mount point inside the jail.
    #[serde(default)]
    pub target: Option<String>,
    /// Mount read-only.
    #[serde(default)]
    pub read_only: Option<bool>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

impl<'de> Deserialize<'de> for VolumeMount {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MountVisitor;

        impl<'de> Visitor<'de> for MountVisitor {
            type Value = VolumeMount;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a mount string such as \"data:/var/db\", or a mapping")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<VolumeMount, E> {
                Ok(VolumeMount::Short(value.to_owned()))
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<VolumeMount, A::Error> {
                long_form(map).map(VolumeMount::Long)
            }
        }

        deserializer.deserialize_any(MountVisitor)
    }
}

/// A service's `build:`, in either of compose's two spellings.
///
/// The long form's keys are deliberately few: what SatL's builder can honour
/// is a context and a build file, and the rest of compose's `build:` describes
/// a Dockerfile build that this builder is not (api-compat 181). Everything
/// else lands in `rest` and is refused by name.
#[derive(Debug, Clone)]
pub enum Build {
    /// A bare context path.
    Short(String),
    /// The mapping form.
    Long(BuildLong),
}

/// The long form of a service's `build:`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BuildLong {
    /// Directory the build reads from, relative to the project directory.
    #[serde(default)]
    pub context: Option<String>,
    /// Build file to read, relative to the context. Compose's key name; the
    /// file it points at is a `Satlfile`, which is what the refusal below
    /// explains when it is not.
    #[serde(default)]
    pub dockerfile: Option<String>,
    /// Everything else, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

impl<'de> Deserialize<'de> for Build {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BuildVisitor;

        impl<'de> Visitor<'de> for BuildVisitor {
            type Value = Build;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a build context path, or a mapping with a context")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Build, E> {
                Ok(Build::Short(value.to_owned()))
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Build, A::Error> {
                long_form(map).map(Build::Long)
            }
        }

        deserializer.deserialize_any(BuildVisitor)
    }
}

/// One `secrets:`/`configs:` entry of a service.
#[derive(Debug, Clone)]
pub enum FileRef {
    /// A bare object name.
    Short(String),
    /// The long syntax.
    Long(FileRefLong),
}

/// The long form of a service `secrets:`/`configs:` entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FileRefLong {
    /// Name of the stored secret/config.
    #[serde(default)]
    pub source: Option<String>,
    /// File the payload becomes inside the task.
    #[serde(default)]
    pub target: Option<String>,
    /// Owning user, numeric.
    #[serde(default)]
    pub uid: Option<Scalar>,
    /// Owning group, numeric.
    #[serde(default)]
    pub gid: Option<Scalar>,
    /// Permission bits, octal.
    #[serde(default)]
    pub mode: Option<Scalar>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

impl<'de> Deserialize<'de> for FileRef {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FileRefVisitor;

        impl<'de> Visitor<'de> for FileRefVisitor {
            type Value = FileRef;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a secret/config name, or a mapping with a source")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<FileRef, E> {
                Ok(FileRef::Short(value.to_owned()))
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<FileRef, A::Error> {
                long_form(map).map(FileRef::Long)
            }
        }

        deserializer.deserialize_any(FileRefVisitor)
    }
}

/// A service's `networks:`, in either spelling.
#[derive(Debug, Clone)]
pub enum Attachments {
    /// A list of network names.
    List(Vec<String>),
    /// A mapping of network name to options; a null body means "no options".
    Map(BTreeMap<String, Option<Attachment>>),
}

/// Per-network attachment options.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Attachment {
    /// Extra DNS names for the task on that network.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

impl Attachments {
    /// The declared networks, in declaration order, with their options.
    ///
    /// Order is load-bearing: a task resolves names on its networks in the
    /// order its spec lists them (api-compat 73).
    pub fn entries(&self) -> Vec<(String, Option<&Attachment>)> {
        match self {
            Self::List(names) => names.iter().map(|name| (name.clone(), None)).collect(),
            Self::Map(map) => map
                .iter()
                .map(|(name, options)| (name.clone(), options.as_ref()))
                .collect(),
        }
    }
}

impl<'de> Deserialize<'de> for Attachments {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AttachmentsVisitor;

        impl<'de> Visitor<'de> for AttachmentsVisitor {
            type Value = Attachments;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list of network names, or a mapping of them")
            }

            fn visit_unit<E: de::Error>(self) -> Result<Attachments, E> {
                Ok(Attachments::List(Vec::new()))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Attachments, A::Error> {
                let mut out = Vec::new();
                while let Some(name) = seq.next_element::<String>()? {
                    out.push(name);
                }
                Ok(Attachments::List(out))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Attachments, A::Error> {
                let mut out = BTreeMap::new();
                while let Some((name, options)) = map.next_entry::<String, Option<Attachment>>()? {
                    out.insert(name, options);
                }
                Ok(Attachments::Map(out))
            }
        }

        deserializer.deserialize_any(AttachmentsVisitor)
    }
}

/// `depends_on:`, in either spelling.
#[derive(Debug, Clone)]
pub enum DependsOn {
    /// A list of service names.
    List(Vec<String>),
    /// A mapping of service name to conditions.
    Map(BTreeMap<String, Option<Dependence>>),
}

/// The long form of one `depends_on:` entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Dependence {
    /// `service_started`, `service_healthy`, `service_completed_successfully`.
    #[serde(default)]
    pub condition: Option<String>,
    /// Whether the dependency must exist at all.
    #[serde(default)]
    pub required: Option<bool>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

impl DependsOn {
    /// The declared dependencies with their conditions.
    pub fn entries(&self) -> Vec<(String, Option<&Dependence>)> {
        match self {
            Self::List(names) => names.iter().map(|name| (name.clone(), None)).collect(),
            Self::Map(map) => map
                .iter()
                .map(|(name, options)| (name.clone(), options.as_ref()))
                .collect(),
        }
    }
}

impl<'de> Deserialize<'de> for DependsOn {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DependsOnVisitor;

        impl<'de> Visitor<'de> for DependsOnVisitor {
            type Value = DependsOn;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list of service names, or a mapping of them")
            }

            fn visit_unit<E: de::Error>(self) -> Result<DependsOn, E> {
                Ok(DependsOn::List(Vec::new()))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<DependsOn, A::Error> {
                let mut out = Vec::new();
                while let Some(name) = seq.next_element::<String>()? {
                    out.push(name);
                }
                Ok(DependsOn::List(out))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<DependsOn, A::Error> {
                let mut out = BTreeMap::new();
                while let Some((name, options)) = map.next_entry::<String, Option<Dependence>>()? {
                    out.insert(name, options);
                }
                Ok(DependsOn::Map(out))
            }
        }

        deserializer.deserialize_any(DependsOnVisitor)
    }
}

/// `healthcheck:` of a service.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Healthcheck {
    /// The probe: a shell string, or `["CMD", …]` / `["CMD-SHELL", …]` /
    /// `["NONE"]`.
    #[serde(default)]
    pub test: Option<ScalarList>,
    /// Time between probes.
    #[serde(default)]
    pub interval: Option<Scalar>,
    /// Per-probe timeout.
    #[serde(default)]
    pub timeout: Option<Scalar>,
    /// Consecutive failures before the task is unhealthy.
    #[serde(default)]
    pub retries: Option<u32>,
    /// Grace period during which failures do not count.
    #[serde(default)]
    pub start_period: Option<Scalar>,
    /// Turn the image's probe off.
    #[serde(default)]
    pub disable: Option<bool>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

/// `deploy:` of a service — the swarm half of the spec.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Deploy {
    /// `replicated` or `global`.
    #[serde(default)]
    pub mode: Option<String>,
    /// Replica count (replicated mode only).
    #[serde(default)]
    pub replicas: Option<u64>,
    /// Labels for the *service* object (the service's `labels:` are the
    /// container's, as in docker stack deploy).
    #[serde(default)]
    pub labels: Option<KeyValues>,
    /// Resource limits and reservations.
    #[serde(default)]
    pub resources: Option<Resources>,
    /// Placement constraints.
    #[serde(default)]
    pub placement: Option<Placement>,
    /// Restart policy, in swarm's spelling.
    #[serde(default)]
    pub restart_policy: Option<RestartPolicy>,
    /// `dnsrr` only (api-compat 50).
    #[serde(default)]
    pub endpoint_mode: Option<String>,
    /// Rolling-update policy.
    #[serde(default)]
    pub update_config: Option<UpdatePolicy>,
    /// Rollback policy.
    #[serde(default)]
    pub rollback_config: Option<UpdatePolicy>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

/// `deploy.resources:`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Resources {
    /// Hard caps, enforced through rctl(8).
    #[serde(default)]
    pub limits: Option<Quantities>,
    /// Scheduler-side reservations.
    #[serde(default)]
    pub reservations: Option<Quantities>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

/// One side of `deploy.resources`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Quantities {
    /// CPUs, as a decimal fraction of a core.
    #[serde(default)]
    pub cpus: Option<Scalar>,
    /// Memory, with docker's byte units.
    #[serde(default)]
    pub memory: Option<Scalar>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

/// `deploy.placement:`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Placement {
    /// Constraint expressions, in SatL's (and swarm's) own language.
    #[serde(default)]
    pub constraints: Vec<String>,
    /// Per-node cap on tasks of this service.
    #[serde(default)]
    pub max_replicas_per_node: Option<u64>,
    /// Soft preferences; only `spread: <descriptor>` (M7d).
    #[serde(default)]
    pub preferences: Vec<PlacementPreference>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

/// One `deploy.placement.preferences[]` entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PlacementPreference {
    /// The descriptor to spread across, e.g. `node.labels.zone`.
    #[serde(default)]
    pub spread: Option<String>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

/// `deploy.restart_policy:`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RestartPolicy {
    /// `none`, `on-failure` or `any`.
    #[serde(default)]
    pub condition: Option<String>,
    /// Delay before a replacement starts.
    #[serde(default)]
    pub delay: Option<Scalar>,
    /// Attempt budget; 0 means unlimited.
    #[serde(default)]
    pub max_attempts: Option<u64>,
    /// Window the attempts are counted in.
    #[serde(default)]
    pub window: Option<Scalar>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

/// `deploy.update_config:` / `deploy.rollback_config:`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UpdatePolicy {
    /// Slots moved at once; 0 means all of them.
    #[serde(default)]
    pub parallelism: Option<u64>,
    /// Delay between batches.
    #[serde(default)]
    pub delay: Option<Scalar>,
    /// `pause`, `continue` or `rollback`.
    #[serde(default)]
    pub failure_action: Option<String>,
    /// How long a new task is watched before the batch is called good.
    #[serde(default)]
    pub monitor: Option<Scalar>,
    /// Tolerated failure ratio, 0 to 1.
    #[serde(default)]
    pub max_failure_ratio: Option<f32>,
    /// `start-first` or `stop-first`.
    #[serde(default)]
    pub order: Option<String>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

/// A top-level `networks:` entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Network {
    /// Driver; `overlay` is the only one a stack can span the cluster with.
    #[serde(default)]
    pub driver: Option<String>,
    /// Explicit name, used unprefixed.
    #[serde(default)]
    pub name: Option<String>,
    /// The network already exists and this project neither creates nor removes it.
    #[serde(default)]
    pub external: Option<External>,
    /// Network labels.
    #[serde(default)]
    pub labels: Option<KeyValues>,
    /// Addressing.
    #[serde(default)]
    pub ipam: Option<Ipam>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

/// `networks.<name>.ipam:`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Ipam {
    /// IPAM driver; only `default`.
    #[serde(default)]
    pub driver: Option<String>,
    /// Subnets; SatL networks have exactly one (api-compat 63).
    #[serde(default)]
    pub config: Vec<IpamConfig>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

/// One `ipam.config` entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IpamConfig {
    /// Subnet in CIDR form.
    #[serde(default)]
    pub subnet: Option<String>,
    /// Requested gateway.
    #[serde(default)]
    pub gateway: Option<String>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

/// A top-level `volumes:` entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Volume {
    /// Driver; `local` only (invariant 5: volumes are ZFS datasets).
    #[serde(default)]
    pub driver: Option<String>,
    /// Explicit name, used unprefixed.
    #[serde(default)]
    pub name: Option<String>,
    /// The volume already exists on the nodes.
    #[serde(default)]
    pub external: Option<External>,
    /// Volume labels.
    #[serde(default)]
    pub labels: Option<KeyValues>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}

/// A top-level `secrets:`/`configs:` entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Dependency {
    /// Payload read from a file at deploy time.
    #[serde(default)]
    pub file: Option<String>,
    /// Payload read from an environment variable.
    #[serde(default)]
    pub environment: Option<String>,
    /// The object already exists in the cluster store.
    #[serde(default)]
    pub external: Option<External>,
    /// Explicit name, used unprefixed.
    #[serde(default)]
    pub name: Option<String>,
    /// Every other key, refused by name.
    #[serde(flatten)]
    pub rest: Rest,
}
