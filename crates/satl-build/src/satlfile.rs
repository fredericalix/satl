// SPDX-License-Identifier: BSD-2-Clause
//! The `Satlfile`: the build-file format `satl build` reads (M6f, extended in
//! M7b; `FROM scratch` and multi-stage builds in M8c).
//!
//! A line-based subset of Dockerfile verbs, because a FreeBSD image here is a
//! base rootfs plus pkg packages, not a filesystem diff stream:
//!
//! ```text
//! # comment
//! FROM <image ref> [AS <name>]      (one or more; each starts a new stage.
//!                                   The literal `scratch` is the empty base:
//!                                   no pull, no layers)
//! PKG <pkg> [pkg ...]               (repeatable; all of a stage's PKG steps
//!                                   run together, before its first COPY/RUN)
//! COPY [--from=<stage>] <src> [src ...] <dst>
//!                                   (repeatable; sources relative to the
//!                                   build context — the Satlfile's directory —
//!                                   or, with --from, absolute paths inside an
//!                                   earlier stage's finished rootfs)
//! RUN <shell command>               (repeatable; /bin/sh -c in a chroot of
//!                                   the assembled rootfs)
//! ENV KEY=value                     (repeatable)
//! LABEL KEY=value                   (repeatable)
//! WORKDIR /path
//! EXPOSE 80/tcp                     (repeatable)
//! ENTRYPOINT ["/json", "array"]     (exec form only)
//! CMD ["/json", "array"]            (exec form only)
//! ```
//!
//! `COPY` and `RUN` execute in file order, after every `PKG` (a package must
//! be installed before a step can use it — `PKG node24` then `RUN npm …`).
//!
//! With several `FROM` lines the file is a multi-stage build (M8c), Docker's
//! shape: every stage builds fully, but only the *last* stage's rootfs and
//! metadata (ENTRYPOINT/CMD/ENV/LABEL/WORKDIR/EXPOSE) become the image. The
//! earlier stages exist so `COPY --from` can lift artifacts out of them. A
//! stage is addressable by its `AS <name>` alias (case-insensitive) or by
//! index (`--from=0` is the first stage); only *earlier* stages resolve — a
//! stage's rootfs is final only once the build has moved past it. Docker's
//! other reading of `--from`, copying out of a registry image, is refused:
//! pulling and unpacking a whole image to copy a file is a registry
//! round-trip a build file should not hide, and a stage covers the workflow.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// A parsed build file: one or more stages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Satlfile {
    /// The stages, in file order; never empty after a successful parse.
    pub stages: Vec<Stage>,
}

/// One stage of the build: a base, its steps, and its image metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stage {
    /// The base image reference (`FROM`), or the literal `scratch`.
    pub from: String,
    /// The `AS <name>` alias, lowercased (stage names are case-insensitive).
    pub name: Option<String>,
    /// pkg packages to install into the rootfs (`PKG`).
    pub packages: Vec<String>,
    /// `COPY` and `RUN` steps, in file order.
    pub steps: Vec<Step>,
    /// `ENV` pairs.
    pub env: BTreeMap<String, String>,
    /// `LABEL` pairs.
    pub labels: BTreeMap<String, String>,
    /// `WORKDIR`.
    pub workdir: Option<String>,
    /// `EXPOSE` entries as `<port>/<proto>`.
    pub expose: Vec<String>,
    /// `ENTRYPOINT`, exec form.
    pub entrypoint: Option<Vec<String>>,
    /// `CMD`, exec form.
    pub cmd: Option<Vec<String>>,
}

impl Stage {
    /// Whether this stage starts from the empty base (`FROM scratch`).
    #[must_use]
    pub fn is_scratch(&self) -> bool {
        self.from.eq_ignore_ascii_case("scratch")
    }
}

/// One content or command step of the build (M7b; `--from` in M8c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// `COPY`: sources into `dest` (image-absolute, or relative to
    /// `WORKDIR`). A directory source copies its *contents*, as Docker's
    /// COPY does.
    Copy {
        /// The earlier stage the sources read from (`COPY --from`), as its
        /// index in [`Satlfile::stages`]; `None` = the build context.
        from: Option<usize>,
        /// Context-relative source paths, or stage-absolute ones with
        /// `--from`.
        sources: Vec<PathBuf>,
        /// Destination path inside the image.
        dest: PathBuf,
    },
    /// `RUN`: a shell command for `/bin/sh -c`, executed in a chroot of the
    /// assembled rootfs on the build host.
    Run(String),
}

impl Step {
    /// Resolve `dest` against the stage's `WORKDIR` (Docker's rule: a
    /// relative destination is workdir-relative, defaulting to `/`). The
    /// result is normalized (`/srv/.` → `/srv`), because a trailing `/.`
    /// must still read as a directory destination.
    pub fn resolve_dest(dest: &str, workdir: Option<&str>) -> Result<PathBuf, String> {
        let dest = Path::new(dest);
        let joined = if dest.is_absolute() {
            dest.to_path_buf()
        } else {
            Path::new(workdir.unwrap_or("/")).join(dest)
        };
        let mut normalized = PathBuf::new();
        for component in joined.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    // A `..` would climb out of the image rootfs — refuse
                    // lexically; the rootfs is real host storage during the
                    // build.
                    return Err(format!(
                        "destination {} escapes the image",
                        joined.display()
                    ));
                }
                other => normalized.push(other.as_os_str()),
            }
        }
        // A trailing `/` or `/.` marks a directory destination (Docker's
        // rule); `components()` normalizes the `.` away, so the marker is
        // read off the raw string and put back after normalization.
        let raw = joined.to_string_lossy();
        let directory_marker = raw.ends_with('/') || raw.ends_with("/.");
        if directory_marker {
            normalized.push("");
        }
        Ok(normalized)
    }
}

/// A malformed build file, with the line number.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("Satlfile line {line}: {reason}")]
pub struct SatlfileError {
    /// The 1-based line number.
    pub line: usize,
    /// What is wrong with it.
    pub reason: String,
}

impl Satlfile {
    /// Parse a build file. `ENTRYPOINT`/`CMD` take the JSON exec form only:
    /// the shell form would promise a shell the image may not have.
    pub fn parse(text: &str) -> Result<Self, SatlfileError> {
        let mut stages: Vec<Stage> = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let err = |reason: &str| SatlfileError {
                line,
                reason: reason.to_owned(),
            };
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (verb, rest) = trimmed
                .split_once(char::is_whitespace)
                .ok_or_else(|| err("expected `<VERB> <args>`"))?;
            let rest = rest.trim();
            if verb.eq_ignore_ascii_case("from") {
                stages.push(parse_from(rest, &stages).map_err(|e| err(&e))?);
                continue;
            }
            if stages.is_empty() {
                return Err(err("a stage starts with FROM"));
            }
            let last = stages.len() - 1;
            let (prior, [current]) = stages.split_at_mut(last) else {
                unreachable!("checked non-empty above");
            };
            parse_directive(current, verb, rest, prior).map_err(|e| err(&e))?;
        }
        if stages.is_empty() {
            return Err(SatlfileError {
                line: 0,
                reason: "no FROM line — a base image is mandatory".to_owned(),
            });
        }
        Ok(Self { stages })
    }

    /// The stage whose rootfs and metadata become the image: the last one.
    #[must_use]
    pub fn last_stage(&self) -> &Stage {
        self.stages.last().expect("parse requires a FROM")
    }
}

/// One `FROM` line: `<image> [AS <name>]`, starting a stage. `stages` holds
/// the stages already parsed, so a duplicate alias fails here, where the
/// line number is known.
fn parse_from(rest: &str, stages: &[Stage]) -> Result<Stage, String> {
    let words: Vec<&str> = rest.split_whitespace().collect();
    let (from, name) = match words.as_slice() {
        [] => return Err("FROM needs an image reference".to_owned()),
        [image] => ((*image).to_owned(), None),
        [image, keyword, alias] if keyword.eq_ignore_ascii_case("as") => {
            ((*image).to_owned(), Some(alias.to_ascii_lowercase()))
        }
        _ => return Err("FROM wants `<image> [AS <name>]`".to_owned()),
    };
    if let Some(name) = &name
        && stages
            .iter()
            .any(|stage| stage.name.as_deref() == Some(name))
    {
        return Err(format!("duplicate stage name {name:?}"));
    }
    Ok(Stage {
        from,
        name,
        ..Stage::default()
    })
}

/// One non-FROM directive, applied to the current stage. `prior` holds the
/// stages before it, for `COPY --from` resolution.
fn parse_directive(
    stage: &mut Stage,
    verb: &str,
    rest: &str,
    prior: &[Stage],
) -> Result<(), String> {
    match verb.to_ascii_uppercase().as_str() {
        "PKG" => {
            if rest.is_empty() {
                return Err("PKG needs at least one package name".to_owned());
            }
            stage
                .packages
                .extend(rest.split_whitespace().map(str::to_owned));
        }
        "COPY" => {
            let step = parse_copy(rest, stage.workdir.as_deref(), prior)?;
            stage.steps.push(step);
        }
        "RUN" => {
            if rest.is_empty() {
                return Err("RUN needs a command".to_owned());
            }
            stage.steps.push(Step::Run(rest.to_owned()));
        }
        "ENV" => {
            let (key, value) = rest
                .split_once('=')
                .ok_or_else(|| "ENV wants KEY=value".to_owned())?;
            stage.env.insert(key.to_owned(), value.to_owned());
        }
        "LABEL" => {
            let (key, value) = rest
                .split_once('=')
                .ok_or_else(|| "LABEL wants KEY=value".to_owned())?;
            stage.labels.insert(key.to_owned(), value.to_owned());
        }
        "WORKDIR" => {
            if rest.is_empty() {
                return Err("WORKDIR needs a path".to_owned());
            }
            stage.workdir = Some(rest.to_owned());
        }
        "EXPOSE" => {
            if !rest.contains('/') {
                return Err("EXPOSE wants <port>/<proto>, like 80/tcp".to_owned());
            }
            stage.expose.push(rest.to_owned());
        }
        "ENTRYPOINT" => {
            stage.entrypoint = Some(
                parse_exec_form(rest)
                    .map_err(|e| format!("ENTRYPOINT takes a JSON array (exec form): {e}"))?,
            );
        }
        "CMD" => {
            stage.cmd = Some(
                parse_exec_form(rest)
                    .map_err(|e| format!("CMD takes a JSON array (exec form): {e}"))?,
            );
        }
        other => {
            return Err(format!(
                "unknown verb {other:?} (FROM, PKG, COPY, RUN, ENV, LABEL, WORKDIR, \
                 EXPOSE, ENTRYPOINT, CMD)"
            ));
        }
    }
    Ok(())
}

/// One `COPY` line: `[--from=<stage>] <src> [src ...] <dst>`. Without
/// `--from` the sources are context-relative; with it they are absolute
/// paths inside an earlier stage's rootfs. The destination resolves against
/// the stage's workdir either way.
fn parse_copy(rest: &str, workdir: Option<&str>, prior: &[Stage]) -> Result<Step, String> {
    let mut words: Vec<&str> = rest.split_whitespace().collect();
    let mut from = None;
    while let Some(flag) = words.first().and_then(|word| word.strip_prefix("--")) {
        match flag.strip_prefix("from=") {
            Some(reference) if from.is_none() => {
                from = Some(resolve_stage_ref(reference, prior)?);
            }
            Some(_) => return Err("COPY: --from given twice".to_owned()),
            None => {
                return Err(format!(
                    "COPY: unknown flag --{flag} (only --from is supported)"
                ));
            }
        }
        words.remove(0);
    }
    if words.len() < 2 {
        return Err("COPY wants <src> [src ...] <dst>".to_owned());
    }
    let (sources, [dest]) = words.split_at(words.len() - 1) else {
        unreachable!("len checked above");
    };
    let mut checked = Vec::with_capacity(sources.len());
    for source in sources {
        let path = Path::new(source);
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            let root = if from.is_some() {
                "the source stage"
            } else {
                "the build context"
            };
            return Err(format!("COPY source {source:?} must stay inside {root}"));
        }
        if from.is_some() {
            if !path.is_absolute() {
                return Err(format!(
                    "COPY --from source {source:?} must be absolute inside the stage"
                ));
            }
        } else if path.is_absolute() {
            return Err(format!(
                "COPY source {source:?} must stay inside the build context"
            ));
        }
        checked.push(path.to_path_buf());
    }
    Ok(Step::Copy {
        from,
        sources: checked,
        dest: Step::resolve_dest(dest, workdir)?,
    })
}

/// The stage a `COPY --from` reads: a name (case-insensitive) or an index,
/// of an *earlier* stage only. A reference shaped like an image
/// (`registry/repo:tag`) gets the honest refusal — see the module docs.
fn resolve_stage_ref(reference: &str, prior: &[Stage]) -> Result<usize, String> {
    if let Ok(index) = reference.parse::<usize>() {
        return prior
            .get(index)
            .map(|_| index)
            .ok_or_else(|| format!("COPY --from={reference}: no such stage"));
    }
    let lowered = reference.to_ascii_lowercase();
    if let Some(index) = prior
        .iter()
        .position(|stage| stage.name.as_deref() == Some(lowered.as_str()))
    {
        return Ok(index);
    }
    if reference.contains(['/', ':']) {
        return Err(format!(
            "COPY --from={reference}: copying out of an image is not supported; \
             name or index an earlier stage instead"
        ));
    }
    Err(format!("COPY --from={reference}: no such stage"))
}

/// The exec form of ENTRYPOINT/CMD: a JSON array of strings.
fn parse_exec_form(text: &str) -> Result<Vec<String>, String> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|error| error.to_string())?;
    let array = value.as_array().ok_or_else(|| "not an array".to_owned())?;
    array
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "array items must be strings".to_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nginx_shape_parses() {
        let file = Satlfile::parse(
            "# the test web image\n\
             FROM 127.0.0.1:5000/satl-test/freebsd-runtime:15.1\n\
             PKG nginx pcre2\n\
             EXPOSE 80/tcp\n\
             ENV PATH=/usr/local/bin:/usr/bin:/bin\n\
             LABEL satl.role=web\n\
             ENTRYPOINT [\"/usr/local/sbin/nginx\", \"-g\", \"daemon off;\"]\n",
        )
        .unwrap();
        assert_eq!(file.stages.len(), 1);
        let stage = file.last_stage();
        assert_eq!(stage.from, "127.0.0.1:5000/satl-test/freebsd-runtime:15.1");
        assert!(!stage.is_scratch());
        assert_eq!(stage.packages, ["nginx", "pcre2"]);
        assert_eq!(stage.expose, ["80/tcp"]);
        assert_eq!(
            stage.entrypoint.as_deref(),
            Some(
                [
                    "/usr/local/sbin/nginx".to_owned(),
                    "-g".to_owned(),
                    "daemon off;".to_owned()
                ]
                .as_slice()
            )
        );
        assert_eq!(
            stage.labels.get("satl.role").map(String::as_str),
            Some("web")
        );
    }

    #[test]
    fn from_is_mandatory_and_every_from_starts_a_stage() {
        let err = Satlfile::parse("PKG nginx\n").unwrap_err();
        assert!(err.reason.contains("FROM"), "{err}");
        assert_eq!(err.line, 1);

        let file = Satlfile::parse("FROM a\nFROM b\n").unwrap();
        assert_eq!(file.stages.len(), 2);
        assert_eq!(file.stages[0].from, "a");
        assert_eq!(file.stages[1].from, "b");
    }

    #[test]
    fn scratch_is_the_empty_base_named_or_not() {
        let file = Satlfile::parse("FROM scratch AS empty\nCOPY x /x\n").unwrap();
        let stage = file.last_stage();
        assert!(stage.is_scratch());
        assert_eq!(stage.name.as_deref(), Some("empty"));
    }

    #[test]
    fn verbs_are_checked_and_exec_forms_must_be_json() {
        let err = Satlfile::parse("FROM a\nADD x y\n").unwrap_err();
        assert!(err.reason.contains("unknown verb"), "{err}");
        let err = Satlfile::parse("FROM a\nCMD nginx -g 'daemon off;'\n").unwrap_err();
        assert!(err.reason.contains("JSON"), "{err}");
        let err = Satlfile::parse("FROM a\nENV NOEQUALS\n").unwrap_err();
        assert!(err.reason.contains("KEY=value"), "{err}");
    }

    #[test]
    fn copy_and_run_parse_in_order() {
        let file = Satlfile::parse(
            "FROM a\n\
             WORKDIR /srv\n\
             COPY app/ /srv/app\n\
             RUN npm --prefix /srv/app install --omit=dev\n\
             COPY package.json .\n",
        )
        .unwrap();
        assert_eq!(
            file.last_stage().steps,
            [
                Step::Copy {
                    from: None,
                    sources: vec![PathBuf::from("app/")],
                    dest: PathBuf::from("/srv/app"),
                },
                Step::Run("npm --prefix /srv/app install --omit=dev".to_owned()),
                // A relative destination is WORKDIR-relative (and a
                // directory, marked by the `.`), as Docker's.
                Step::Copy {
                    from: None,
                    sources: vec![PathBuf::from("package.json")],
                    dest: PathBuf::from("/srv/"),
                },
            ]
        );
    }

    #[test]
    fn copy_rejects_escapes_and_absolute_sources() {
        for line in ["COPY ../secret /x", "COPY /etc/passwd /x", "COPY ok /../x"] {
            let err = Satlfile::parse(&format!("FROM a\n{line}\n")).unwrap_err();
            assert!(
                err.reason.contains("context") || err.reason.contains("escapes"),
                "{line}: {err}"
            );
        }
        let err = Satlfile::parse("FROM a\nCOPY onlyone\n").unwrap_err();
        assert!(err.reason.contains("<src>"), "{err}");
    }

    #[test]
    fn a_two_stage_build_parses_and_from_resolves() {
        let file = Satlfile::parse(
            "FROM freebsd-runtime:15.1 AS Builder\n\
             PKG llvm\n\
             COPY src/ /src/\n\
             RUN make -C /src\n\
             FROM scratch\n\
             COPY --from=builder /src/out /usr/local/bin/out\n\
             COPY --from=0 /src/manifest /usr/local/share/\n\
             ENTRYPOINT [\"/usr/local/bin/out\"]\n",
        )
        .unwrap();
        assert_eq!(file.stages.len(), 2);
        // Stage names are case-insensitive; the alias is stored lowercased.
        assert_eq!(file.stages[0].name.as_deref(), Some("builder"));
        let last = file.last_stage();
        assert!(last.is_scratch());
        assert_eq!(
            last.steps,
            [
                Step::Copy {
                    from: Some(0),
                    sources: vec![PathBuf::from("/src/out")],
                    dest: PathBuf::from("/usr/local/bin/out"),
                },
                Step::Copy {
                    from: Some(0),
                    sources: vec![PathBuf::from("/src/manifest")],
                    dest: PathBuf::from("/usr/local/share/"),
                },
            ]
        );
        assert_eq!(
            last.entrypoint.as_deref(),
            Some(["/usr/local/bin/out".to_owned()].as_slice())
        );
    }

    #[test]
    fn copy_from_an_unknown_or_later_stage_is_an_error() {
        let err = Satlfile::parse("FROM a\nCOPY --from=missing /x /y\n").unwrap_err();
        assert_eq!(err.line, 2);
        assert!(err.reason.contains("no such stage"), "{err}");

        // Out of range by index, and a reference to the *current* stage:
        // both are unknown, because only earlier stages have a final rootfs.
        let err = Satlfile::parse("FROM a\nCOPY --from=0 /x /y\n").unwrap_err();
        assert!(err.reason.contains("no such stage"), "{err}");
        let err = Satlfile::parse("FROM a AS self\nCOPY --from=self /x /y\n").unwrap_err();
        assert!(err.reason.contains("no such stage"), "{err}");
    }

    #[test]
    fn duplicate_stage_names_are_an_error() {
        let err = Satlfile::parse("FROM a AS base\nFROM b AS BASE\n").unwrap_err();
        assert_eq!(err.line, 2);
        assert!(err.reason.contains("duplicate stage name"), "{err}");
    }

    #[test]
    fn copy_from_still_refuses_escapes_and_bad_flags() {
        let text = "FROM a AS b\nFROM scratch\n";
        let err = Satlfile::parse(&format!("{text}COPY --from=b /../secret /x\n")).unwrap_err();
        assert_eq!(err.line, 3);
        assert!(err.reason.contains("source stage"), "{err}");
        let err = Satlfile::parse(&format!("{text}COPY --from=b relative /x\n")).unwrap_err();
        assert!(err.reason.contains("absolute"), "{err}");
        let err = Satlfile::parse(&format!("{text}COPY --chown=root /x /y\n")).unwrap_err();
        assert!(err.reason.contains("unknown flag"), "{err}");
    }

    #[test]
    fn copy_from_an_image_is_refused_plainly() {
        let err = Satlfile::parse("FROM a\nFROM b\nCOPY --from=docker.io/library/alpine:3 /x /y\n")
            .unwrap_err();
        assert_eq!(err.line, 3);
        assert!(err.reason.contains("not supported"), "{err}");
    }
}
