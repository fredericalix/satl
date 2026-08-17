// SPDX-License-Identifier: BSD-2-Clause
//! Workspace lint: operator-facing strings are plain ASCII.
//!
//! `satld` runs under `daemon(8)` with its stderr forwarded to syslog, so
//! `/var/log/messages` is the only place a diagnosis comes from. `syslogd` is
//! not 8-bit clean: it rewrites bytes `0x80`-`0x9f` as literal `M-^X` text, and
//! a UTF-8 punctuation character is two or three bytes with one of them
//! usually in that range. An em dash logged from a message arrives as
//! `M-^@M-^T`, which destroys the line and makes the message ungreppable.
//! Measured on FreeBSD 15.1 with `od -c` on the log file; see
//! `docs/operations.md`, "The log is plain ASCII, on purpose".
//!
//! This test walks every crate in the workspace and fails on a non-ASCII
//! character inside anything whose text can reach a log line: a `#[error(...)]`
//! attribute, a `tracing` macro, `anyhow!`, `bail!`, or `.context(...)`. Doc
//! comments, ordinary comments, test names and assertion messages are outside
//! the rule and are not scanned.
//!
//! It lives here, in the crate every other crate depends on, because the rule
//! is a workspace-wide convention rather than one crate's concern.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Openers whose arguments end up in an operator-facing message. A region
/// starts at the opener and ends when its parentheses balance again.
///
/// The qualified `tracing::` forms come first so that they win over the bare
/// ones; a bare opener only matches when it is not part of a longer path or
/// identifier.
const OPENERS: &[&str] = &[
    "#[error(",
    "tracing::trace!(",
    "tracing::debug!(",
    "tracing::info!(",
    "tracing::warn!(",
    "tracing::error!(",
    "trace!(",
    "debug!(",
    "info!(",
    "warn!(",
    "error!(",
    "anyhow!(",
    "bail!(",
    ".context(",
];

/// One non-ASCII character found inside a message region.
struct Offence {
    path: PathBuf,
    line: usize,
    column: usize,
    ch: char,
    opener: &'static str,
}

#[test]
fn operator_facing_strings_are_plain_ascii() {
    let Some(crates) = crates_dir() else {
        // Not a workspace checkout (vendored build); nothing to lint.
        return;
    };

    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(&crates) else {
        panic!("cannot read {}", crates.display());
    };
    for entry in entries.flatten() {
        let krate = entry.path();
        for sub in ["src", "tests"] {
            collect_rust_files(&krate.join(sub), &mut files);
        }
    }
    assert!(
        !files.is_empty(),
        "found no Rust sources under {}",
        crates.display()
    );
    files.sort();

    let mut offences = Vec::new();
    for path in &files {
        let Ok(src) = fs::read_to_string(path) else {
            continue;
        };
        scan(path, &src, &mut offences);
    }

    assert!(offences.is_empty(), "{}", report(&crates, &offences));
}

/// The workspace's `crates/` directory, from this crate's manifest path.
fn crates_dir() -> Option<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?;
    if crates.file_name()? == "crates" && crates.is_dir() {
        Some(crates.to_path_buf())
    } else {
        None
    }
}

/// Every `.rs` file under `dir`, recursively.
fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// What the operator is told when the lint fires.
fn report(crates: &Path, offences: &[Offence]) -> String {
    let root = crates.parent().unwrap_or(crates);
    let mut out = format!(
        "{} non-ASCII character(s) in operator-facing message(s):\n\n",
        offences.len()
    );
    for offence in offences {
        let shown = offence.path.strip_prefix(root).unwrap_or(&offence.path);
        let _ = writeln!(
            out,
            "  {}:{}:{}: U+{:04X} {:?} inside `{}`",
            shown.display(),
            offence.line,
            offence.column,
            u32::from(offence.ch),
            offence.ch,
            offence.opener,
        );
    }
    out.push_str(
        "\nsyslogd rewrites bytes 0x80-0x9f as literal `M-^X` text, so these characters\n\
         reach /var/log/messages mangled and the message becomes ungreppable. Every\n\
         string that can reach a log line must be plain ASCII: use `-`, `->`, `x`,\n\
         `...`, `section N` and straight quotes, or reword the sentence so it does not\n\
         need the character. Doc comments, test names and assertion messages are\n\
         exempt. See CLAUDE.md (coding standards) and docs/operations.md.\n",
    );
    out
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// A cursor over one file that knows where it is, so an offence can name a
/// line and a column.
struct Cursor<'a> {
    src: &'a str,
    at: usize,
    line: usize,
    column: usize,
}

impl<'a> Cursor<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            at: 0,
            line: 1,
            column: 1,
        }
    }

    fn rest(&self) -> &'a str {
        &self.src[self.at..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    /// Advances one character, returning it with the position it was at.
    fn bump(&mut self) -> Option<(usize, usize, char)> {
        let ch = self.peek()?;
        let at = (self.line, self.column);
        self.at += ch.len_utf8();
        if ch == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some((at.0, at.1, ch))
    }
}

/// Scans one file, appending every non-ASCII character that sits inside a
/// message region.
///
/// String and comment bodies are lexed rather than pattern-matched: the
/// messages themselves are full of parentheses, and a region has to end where
/// its own parentheses balance, not where a `)` inside a sentence appears.
fn scan(path: &Path, src: &str, out: &mut Vec<Offence>) {
    let mut cur = Cursor::new(src);
    // The opener whose region we are inside, and its parenthesis depth.
    let mut region: Option<(&'static str, usize)> = None;

    while let Some(ch) = cur.peek() {
        if cur.rest().starts_with("//") {
            skip_line_comment(&mut cur);
            continue;
        }
        if cur.rest().starts_with("/*") {
            skip_block_comment(&mut cur);
            continue;
        }
        let opener = region.map(|(opener, _)| opener);
        if let Some(hashes) = raw_string_hashes(cur.rest()) {
            consume_raw_string(&mut cur, hashes, opener, path, out);
            continue;
        }
        if ch == '"' {
            consume_string(&mut cur, opener, path, out);
            continue;
        }
        if ch == '\''
            && let Some(len) = char_literal_len(cur.rest())
        {
            for _ in 0..len {
                cur.bump();
            }
            continue;
        }
        if region.is_none() {
            // The opener's own `(` is counted by the walk below, which takes
            // the depth from 0 to 1.
            region = opener_at(src, cur.at).map(|opener| (opener, 0));
        }

        let Some((line, column, ch)) = cur.bump() else {
            break;
        };
        if let Some((opener, depth)) = region.as_mut() {
            record(Some(opener), path, line, column, ch, out);
            match ch {
                '(' => *depth += 1,
                ')' => {
                    *depth -= 1;
                    if *depth == 0 {
                        region = None;
                    }
                }
                _ => {}
            }
        }
    }
}

/// The opener starting at `at`, if any. A bare macro name only counts when it
/// is not the tail of a longer path or identifier.
fn opener_at(src: &str, at: usize) -> Option<&'static str> {
    let rest = &src[at..];
    OPENERS.iter().copied().find(|opener| {
        if !rest.starts_with(opener) {
            return false;
        }
        if !opener.starts_with(|c: char| c.is_ascii_alphabetic()) {
            return true;
        }
        let before = src[..at].chars().next_back();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == ':')
    })
}

fn skip_line_comment(cur: &mut Cursor) {
    while let Some((_, _, ch)) = cur.bump() {
        if ch == '\n' {
            return;
        }
    }
}

fn skip_block_comment(cur: &mut Cursor) {
    let mut depth = 0usize;
    while cur.peek().is_some() {
        if cur.rest().starts_with("/*") {
            depth += 1;
            cur.bump();
            cur.bump();
        } else if cur.rest().starts_with("*/") {
            depth -= 1;
            cur.bump();
            cur.bump();
            if depth == 0 {
                return;
            }
        } else {
            cur.bump();
        }
    }
}

/// Consumes a `"..."` literal, reporting non-ASCII when inside a region.
fn consume_string(
    cur: &mut Cursor,
    opener: Option<&'static str>,
    path: &Path,
    out: &mut Vec<Offence>,
) {
    cur.bump(); // opening quote
    while let Some((line, column, ch)) = cur.bump() {
        match ch {
            '\\' => {
                cur.bump();
            }
            '"' => return,
            _ => record(opener, path, line, column, ch, out),
        }
    }
}

/// Consumes an `r"..."` / `r#"..."#` literal, reporting non-ASCII when inside
/// a region. Raw strings have no escapes, so only the terminator ends them.
fn consume_raw_string(
    cur: &mut Cursor,
    hashes: usize,
    opener: Option<&'static str>,
    path: &Path,
    out: &mut Vec<Offence>,
) {
    let mut terminator = String::from('"');
    for _ in 0..hashes {
        terminator.push('#');
    }
    for _ in 0..hashes + 2 {
        cur.bump(); // `r`, the hashes, and the opening quote
    }
    while cur.peek().is_some() {
        if cur.rest().starts_with(&terminator) {
            for _ in 0..terminator.chars().count() {
                cur.bump();
            }
            return;
        }
        let Some((line, column, ch)) = cur.bump() else {
            return;
        };
        record(opener, path, line, column, ch, out);
    }
}

/// Records `ch` when it is non-ASCII and the cursor is inside a region opened
/// by `opener`.
fn record(
    opener: Option<&'static str>,
    path: &Path,
    line: usize,
    column: usize,
    ch: char,
    out: &mut Vec<Offence>,
) {
    if let Some(opener) = opener
        && !ch.is_ascii()
    {
        out.push(Offence {
            path: path.to_path_buf(),
            line,
            column,
            ch,
            opener,
        });
    }
}

/// The number of `#` in a raw-string opener at the start of `rest`, or `None`
/// when `rest` does not open one.
fn raw_string_hashes(rest: &str) -> Option<usize> {
    let mut chars = rest.chars();
    if chars.next()? != 'r' {
        return None;
    }
    let mut hashes = 0usize;
    for ch in chars {
        match ch {
            '#' => hashes += 1,
            '"' => return Some(hashes),
            _ => return None,
        }
    }
    None
}

/// The byte length of a char literal at the start of `rest`, or `None` when
/// this `'` is a lifetime instead.
fn char_literal_len(rest: &str) -> Option<usize> {
    let mut chars = rest.char_indices();
    if chars.next()?.1 != '\'' {
        return None;
    }
    let (_, first) = chars.next()?;
    if first == '\\' {
        let (_, escape) = chars.next()?;
        if escape == 'u' {
            // `'\u{...}'`
            for (idx, ch) in chars {
                if ch == '\'' {
                    return Some(idx + 1);
                }
            }
            return None;
        }
        let (idx, ch) = chars.next()?;
        return if ch == '\'' { Some(idx + 1) } else { None };
    }
    let (idx, ch) = chars.next()?;
    if ch == '\'' { Some(idx + 1) } else { None }
}

// ---------------------------------------------------------------------------
// The scanner's own tests: the lint is only worth having if it fires.
// ---------------------------------------------------------------------------

#[test]
fn it_flags_an_em_dash_in_an_error_attribute() {
    let src = "#[error(\"jail '{id}' is gone \\u{2014} it was destroyed\")]\n";
    let mut out = Vec::new();
    scan(
        Path::new("x.rs"),
        &src.replace("\\u{2014}", "\u{2014}"),
        &mut out,
    );
    assert_eq!(out.len(), 1, "the em dash must be found");
    assert_eq!(out[0].ch, '\u{2014}');
    assert_eq!(out[0].opener, "#[error(");
}

#[test]
fn it_flags_an_arrow_in_a_tracing_field_and_message() {
    let src = "tracing::info!(from = \"a\u{2192}b\", \"moved \u{2192} done\");\n";
    let mut out = Vec::new();
    scan(Path::new("x.rs"), src, &mut out);
    assert_eq!(out.len(), 2, "both the field value and the message count");
    assert!(out.iter().all(|o| o.opener == "tracing::info!("));
}

#[test]
fn a_region_ends_where_its_own_parentheses_balance() {
    // The `)` inside the message must not close the region early, and the
    // comment after it is outside the rule.
    let src = "tracing::warn!(\"mtu (bad) here\");\nlet x = \"\u{2014}\"; // \u{2014}\n";
    let mut out = Vec::new();
    scan(Path::new("x.rs"), src, &mut out);
    assert!(
        out.is_empty(),
        "flagged something outside a message: {}",
        out.len()
    );
}

#[test]
fn comments_test_assertions_and_cli_output_are_exempt() {
    let src = concat!(
        "/// A doc comment with an em dash \u{2014} fine.\n",
        "// An ordinary comment \u{2014} fine.\n",
        "/* a block \u{2014} comment */\n",
        "assert_eq!(a, b, \"capacity \u{2212} reservations\");\n",
        "out.push('\u{2026}');\n",
        "let unit = \"\u{00B5}s\";\n",
    );
    let mut out = Vec::new();
    scan(Path::new("x.rs"), src, &mut out);
    assert!(out.is_empty(), "flagged an exempt string: {}", out.len());
}

#[test]
fn a_qualified_tracing_macro_is_not_double_counted() {
    let src = "tracing::error!(\"a \u{2014} b\");\n";
    let mut out = Vec::new();
    scan(Path::new("x.rs"), src, &mut out);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].opener, "tracing::error!(");
}

#[test]
fn an_unrelated_macro_ending_in_error_is_not_a_region() {
    let src = "my_error!(\"a \u{2014} b\");\nns::other!(\"c \u{2014} d\");\n";
    let mut out = Vec::new();
    scan(Path::new("x.rs"), src, &mut out);
    assert!(out.is_empty(), "matched a foreign macro: {}", out.len());
}
