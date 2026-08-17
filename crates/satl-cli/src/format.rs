// SPDX-License-Identifier: BSD-2-Clause
//! Docker's output conventions: humanized durations and sizes, truncated
//! IDs, port lists and the padded column layout `ps`/`images` print.
//!
//! Everything here is pure so the column goldens can pin the layout with an
//! injected clock instead of `SystemTime::now`.

use std::fmt::Write as _;

use crate::api::PortSummary;

/// Width of a truncated container/image ID, as docker prints it.
pub const TRUNC_ID_LEN: usize = 12;

/// Width the `COMMAND` column is truncated to (docker's `Ellipsis(cmd, 20)`).
const COMMAND_ELLIPSIS: usize = 20;

/// Spaces between columns (docker's tabwriter padding).
const COLUMN_PADDING: usize = 3;

/// Truncate an ID to docker's 12 hex characters, dropping any `sha256:`
/// algorithm prefix first (docker's `TruncateID`).
pub fn truncate_id(id: &str) -> String {
    let id = id.strip_prefix("sha256:").unwrap_or(id);
    id.chars().take(TRUNC_ID_LEN).collect()
}

/// Strip the algorithm prefix without truncating (`--no-trunc`).
pub fn strip_digest_prefix(id: &str) -> String {
    id.strip_prefix("sha256:").unwrap_or(id).to_owned()
}

/// Shorten to `max` characters, the last one being an ellipsis (docker's
/// `Ellipsis`). Strings that already fit are returned unchanged.
pub fn ellipsis(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_owned();
    }
    let mut out: String = value.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Render the `COMMAND` cell: quoted like docker does, truncated unless
/// `--no-trunc`.
pub fn command_cell(command: &str, no_trunc: bool) -> String {
    let shown = if no_trunc {
        command.to_owned()
    } else {
        ellipsis(command, COMMAND_ELLIPSIS)
    };
    quote(&shown)
}

/// Go's `strconv.Quote` for the subset of characters we can see in a command
/// line: double quotes around the value, escaping `"` and `\`.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Docker's `units.HumanDuration`, used by the `CREATED` column (which
/// appends ` ago`) and by relative timestamps in `STATUS`.
pub fn human_duration(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let minutes = seconds / 60;
    // Go rounds hours to nearest before comparing.
    let hours = (seconds + 1800) / 3600;
    if seconds < 1 {
        "Less than a second".to_owned()
    } else if seconds == 1 {
        "1 second".to_owned()
    } else if seconds < 60 {
        format!("{seconds} seconds")
    } else if minutes == 1 {
        "About a minute".to_owned()
    } else if minutes < 60 {
        format!("{minutes} minutes")
    } else if hours == 1 {
        "About an hour".to_owned()
    } else if hours < 48 {
        format!("{hours} hours")
    } else if hours < 24 * 7 * 2 {
        format!("{} days", hours / 24)
    } else if hours < 24 * 30 * 2 {
        format!("{} weeks", hours / (24 * 7))
    } else if hours < 24 * 365 * 2 {
        format!("{} months", hours / (24 * 30))
    } else {
        format!("{} years", hours / (24 * 365))
    }
}

/// The wall clock, as unix seconds. The renderers take it as an argument so
/// the column goldens can pin a fixed "now".
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The `CREATED` cell: `<human duration> ago`, from two unix timestamps.
pub fn created_ago(created_unix: i64, now_unix: i64) -> String {
    format!(
        "{} ago",
        human_duration(now_unix.saturating_sub(created_unix))
    )
}

/// Unix seconds from the RFC 3339 timestamp the daemon sends. Deliberately
/// minimal: the CLI only needs "how long ago", never a calendar date.
pub(crate) fn parse_rfc3339_seconds(value: &str) -> Option<i64> {
    let (date, rest) = value.split_once('T')?;
    let time = rest.split(['.', 'Z', '+']).next()?;
    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    let mut time = time.split(':');
    let hour: i64 = time.next()?.parse().ok()?;
    let minute: i64 = time.next()?.parse().ok()?;
    let second: i64 = time.next()?.parse().ok()?;

    // Howard Hinnant's days-from-civil algorithm.
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// A `CREATED`/`UPDATED` cell built from an RFC 3339 timestamp: humanized when
/// it parses, empty when the daemon sent nothing.
pub(crate) fn timestamp_cell(value: &str, now_unix: i64) -> String {
    match parse_rfc3339_seconds(value) {
        Some(seconds) => created_ago(seconds, now_unix),
        None => String::new(),
    }
}

/// Docker's `units.HumanSize`: decimal (1000-based) units, 4 significant
/// digits, no space before the unit.
pub fn human_size(bytes: i64) -> String {
    const UNITS: [&str; 7] = ["B", "kB", "MB", "GB", "TB", "PB", "EB"];
    #[allow(clippy::cast_precision_loss)] // display only; 4 significant digits
    let mut size = bytes as f64;
    let negative = size < 0.0;
    size = size.abs();
    let mut unit = 0;
    while size >= 1000.0 && unit < UNITS.len() - 1 {
        size /= 1000.0;
        unit += 1;
    }
    let rendered = four_significant_digits(size);
    if negative {
        format!("-{rendered}{}", UNITS[unit])
    } else {
        format!("{rendered}{}", UNITS[unit])
    }
}

/// Go's `%.4g` for the `0.0..1000.0` values `human_size` produces: fixed
/// notation with trailing zeros trimmed.
fn four_significant_digits(value: f64) -> String {
    let decimals = if value >= 100.0 {
        1
    } else if value >= 10.0 {
        2
    } else {
        3
    };
    let rendered = format!("{value:.decimals$}");
    if rendered.contains('.') {
        rendered
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_owned()
    } else {
        rendered
    }
}

/// The `PORTS` cell: docker's `DisplayablePorts`, minus the range folding.
pub fn display_ports(ports: &[PortSummary]) -> String {
    let mut rendered: Vec<(u16, u16, String)> = ports
        .iter()
        .map(|port| {
            let proto = if port.typ.is_empty() {
                "tcp"
            } else {
                &port.typ
            };
            let text = match port.public_port {
                Some(public) if public != 0 => {
                    let ip = if port.ip.is_empty() {
                        "0.0.0.0"
                    } else {
                        &port.ip
                    };
                    format!("{ip}:{public}->{}/{proto}", port.private_port)
                }
                _ => format!("{}/{proto}", port.private_port),
            };
            (port.private_port, port.public_port.unwrap_or(0), text)
        })
        .collect();
    rendered.sort();
    rendered.dedup_by(|a, b| a.2 == b.2);
    rendered
        .into_iter()
        .map(|(_, _, text)| text)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Upper-case the first character, as docker does for the cluster columns
/// (`ready` → `Ready`, `stop-first` stays untouched after the first letter).
pub fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// The `NAMES` cell: names joined with `,`, each stripped of its leading `/`.
pub fn display_names(names: &[String]) -> String {
    names
        .iter()
        .map(|name| name.trim_start_matches('/'))
        .collect::<Vec<_>>()
        .join(",")
}

/// A left-aligned column layout matching docker's tabwriter output: every
/// column padded to its widest cell plus three spaces, the last column left
/// unpadded so lines carry no trailing whitespace.
#[derive(Debug)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// A table with the given header cells.
    pub fn new(headers: &[&str]) -> Self {
        Self {
            headers: headers.iter().map(|h| (*h).to_owned()).collect(),
            rows: Vec::new(),
        }
    }

    /// Append a row; it must have as many cells as there are headers.
    pub fn push(&mut self, row: Vec<String>) {
        debug_assert_eq!(row.len(), self.headers.len(), "row/header width mismatch");
        self.rows.push(row);
    }

    /// Render the table, header included. Always ends with a newline.
    pub fn render(&self) -> String {
        let widths: Vec<usize> = (0..self.headers.len())
            .map(|column| {
                std::iter::once(&self.headers[column])
                    .chain(self.rows.iter().filter_map(|row| row.get(column)))
                    .map(|cell| cell.chars().count())
                    .max()
                    .unwrap_or(0)
            })
            .collect();

        let mut out = String::new();
        for row in std::iter::once(&self.headers).chain(self.rows.iter()) {
            let last = row.len().saturating_sub(1);
            for (index, cell) in row.iter().enumerate() {
                if index == last {
                    out.push_str(cell);
                } else {
                    let pad = widths[index].saturating_sub(cell.chars().count()) + COLUMN_PADDING;
                    let _ = write!(out, "{cell}{:pad$}", "");
                }
            }
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_ids_like_docker() {
        assert_eq!(truncate_id("0123456789abcdef0123"), "0123456789ab");
        assert_eq!(truncate_id("sha256:0123456789abcdef0123"), "0123456789ab");
        assert_eq!(truncate_id("abc"), "abc");
        assert_eq!(
            strip_digest_prefix("sha256:0123456789abcdef"),
            "0123456789abcdef"
        );
    }

    #[test]
    fn command_cell_quotes_and_truncates() {
        assert_eq!(
            command_cell("nginx -g daemon off;", false),
            "\"nginx -g daemon off;\""
        );
        assert_eq!(
            command_cell("/docker-entrypoint.sh nginx", false),
            "\"/docker-entrypoint.…\""
        );
        assert_eq!(
            command_cell("/docker-entrypoint.sh nginx", true),
            "\"/docker-entrypoint.sh nginx\""
        );
        assert_eq!(
            command_cell("sh -c \"echo hi\"", true),
            "\"sh -c \\\"echo hi\\\"\""
        );
    }

    #[test]
    fn human_duration_matches_docker_units() {
        assert_eq!(human_duration(0), "Less than a second");
        assert_eq!(human_duration(1), "1 second");
        assert_eq!(human_duration(45), "45 seconds");
        assert_eq!(human_duration(60), "About a minute");
        assert_eq!(human_duration(119), "About a minute");
        assert_eq!(human_duration(120), "2 minutes");
        assert_eq!(human_duration(45 * 60), "45 minutes");
        assert_eq!(human_duration(60 * 60), "About an hour");
        assert_eq!(human_duration(3 * 3600), "3 hours");
        assert_eq!(human_duration(47 * 3600), "47 hours");
        assert_eq!(human_duration(50 * 3600), "2 days");
        assert_eq!(human_duration(20 * 24 * 3600), "2 weeks");
        assert_eq!(human_duration(70 * 24 * 3600), "2 months");
        assert_eq!(human_duration(800 * 24 * 3600), "2 years");
    }

    #[test]
    fn created_column_appends_ago() {
        assert_eq!(created_ago(1_000_000, 1_000_180), "3 minutes ago");
        // Clock skew must not produce a negative duration.
        assert_eq!(created_ago(1_000_180, 1_000_000), "Less than a second ago");
    }

    #[test]
    fn rfc3339_timestamps_become_unix_seconds() {
        assert_eq!(
            parse_rfc3339_seconds("2026-02-02T02:40:00Z"),
            Some(1_770_000_000)
        );
        assert_eq!(
            parse_rfc3339_seconds("2026-02-02T02:40:00.123456789Z"),
            Some(1_770_000_000)
        );
        assert_eq!(parse_rfc3339_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_seconds(""), None);
        assert_eq!(parse_rfc3339_seconds("nope"), None);
    }

    #[test]
    fn timestamp_cells_are_humanized_or_empty() {
        assert_eq!(
            timestamp_cell("2026-02-02T02:40:00Z", 1_770_000_180),
            "3 minutes ago"
        );
        assert_eq!(timestamp_cell("", 1_770_000_180), "");
    }

    #[test]
    fn human_size_matches_docker_units() {
        assert_eq!(human_size(0), "0B");
        assert_eq!(human_size(999), "999B");
        assert_eq!(human_size(1000), "1kB");
        assert_eq!(human_size(1024), "1.024kB");
        assert_eq!(human_size(187_000_000), "187MB");
        assert_eq!(human_size(1_093_000_000), "1.093GB");
        assert_eq!(human_size(142_800_000), "142.8MB");
        assert_eq!(human_size(2_000_000_000_000), "2TB");
    }

    #[test]
    fn ports_are_sorted_deduped_and_rendered() {
        let ports = vec![
            PortSummary {
                ip: String::new(),
                private_port: 443,
                public_port: None,
                typ: "tcp".to_owned(),
            },
            PortSummary {
                ip: "0.0.0.0".to_owned(),
                private_port: 80,
                public_port: Some(8080),
                typ: "tcp".to_owned(),
            },
            PortSummary {
                ip: "0.0.0.0".to_owned(),
                private_port: 80,
                public_port: Some(8080),
                typ: "tcp".to_owned(),
            },
            PortSummary {
                ip: String::new(),
                private_port: 53,
                public_port: Some(5353),
                typ: "udp".to_owned(),
            },
        ];
        assert_eq!(
            display_ports(&ports),
            "0.0.0.0:5353->53/udp, 0.0.0.0:8080->80/tcp, 443/tcp"
        );
        assert_eq!(display_ports(&[]), "");
    }

    #[test]
    fn capitalize_matches_dockers_cluster_columns() {
        assert_eq!(capitalize("ready"), "Ready");
        assert_eq!(capitalize("drain"), "Drain");
        assert_eq!(capitalize("reachable"), "Reachable");
        assert_eq!(capitalize(""), "");
        assert_eq!(capitalize("Ready"), "Ready");
    }

    #[test]
    fn names_drop_the_leading_slash() {
        assert_eq!(
            display_names(&["/web".to_owned(), "/db".to_owned()]),
            "web,db"
        );
    }

    #[test]
    fn table_pads_columns_and_leaves_no_trailing_space() {
        let mut table = Table::new(&["CONTAINER ID", "IMAGE", "NAMES"]);
        table.push(vec![
            "0123456789ab".to_owned(),
            "nginx:1.25".to_owned(),
            "web".to_owned(),
        ]);
        table.push(vec![
            "cafebabe0000".to_owned(),
            "freebsd/base".to_owned(),
            "db".to_owned(),
        ]);
        let expected = "\
CONTAINER ID   IMAGE          NAMES
0123456789ab   nginx:1.25     web
cafebabe0000   freebsd/base   db
";
        assert_eq!(table.render(), expected);
        for line in table.render().lines() {
            assert_eq!(line.trim_end(), line, "trailing whitespace in {line:?}");
        }
    }

    #[test]
    fn table_with_no_rows_still_prints_the_header() {
        let table = Table::new(&["DRIVER", "VOLUME NAME"]);
        assert_eq!(table.render(), "DRIVER   VOLUME NAME\n");
    }
}
