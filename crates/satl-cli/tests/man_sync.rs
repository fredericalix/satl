// SPDX-License-Identifier: BSD-2-Clause
//! man/satl.1 is pinned to the clap surface: the COMMANDS list must be
//! set-equal to the top-level subcommands, each verb's one-line about must
//! appear in its entry, and the `swarm` alias must be on the swarm line.
//!
//! There is deliberately no rewrite gate here (no `UPDATE_MAN=1`): the page
//! is hand-written mdoc, unlike docs/openapi.yaml whose drift test in
//! crates/satl-api/src/openapi.rs regenerates the file. This halves that
//! precedent on purpose -- the tests only prove the page cannot drift
//! silently, they never write it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use clap::CommandFactory as _;
use satl_cli::cli::Cli;

fn page_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../man/satl.1")
}

fn page() -> String {
    let path = page_path();
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

/// The text between the `.Sh COMMANDS` line and the next `.Sh ` line.
fn commands_slice(page: &str) -> String {
    let mut lines = page.lines();
    for line in lines.by_ref() {
        if line == ".Sh COMMANDS" {
            let slice: Vec<&str> = lines.take_while(|l| !l.starts_with(".Sh ")).collect();
            assert!(
                !slice.is_empty(),
                "man/satl.1: the .Sh COMMANDS section is empty or unterminated \
                 (no following .Sh line)"
            );
            return slice.join("\n");
        }
    }
    panic!("man/satl.1 has no `.Sh COMMANDS` line; the drift tests anchor on it");
}

/// Strip mdoc escapes and typography so page text and clap abouts compare:
/// `\-` -> `-`, `\&` -> nothing, backticks dropped, whitespace collapsed.
fn normalize(text: &str) -> String {
    let text = text.replace("\\-", "-").replace("\\&", "").replace('`', "");
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A verb's one-line about: the normalized text up to and including the
/// first sentence boundary (multi-sentence abouts document the rest in
/// `--help`, the man page only carries the first sentence).
fn first_sentence(about: &str) -> String {
    let about = normalize(about);
    match about.find(". ") {
        Some(dot) => about[..=dot].to_owned(),
        None => about,
    }
}

/// The verbs the page documents: the first word after each `.It Cm `.
fn documented_verbs(slice: &str) -> BTreeSet<String> {
    slice
        .lines()
        .filter_map(|line| line.strip_prefix(".It Cm "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_commands_list_is_set_equal_to_the_clap_subcommands() {
    let page = page();
    let documented = documented_verbs(&commands_slice(&page));
    let truth: BTreeSet<String> = Cli::command()
        .get_subcommands()
        .map(|sub| sub.get_name().to_owned())
        .collect();

    let missing: Vec<&String> = truth.difference(&documented).collect();
    let extra: Vec<&String> = documented.difference(&truth).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "man/satl.1 COMMANDS drifted from the clap surface.\n\
         verbs missing from the page: {missing:?}\n\
         verbs on the page that clap does not have: {extra:?}\n\
         Update man/satl.1's COMMANDS list to match crates/satl-cli/src/cli.rs."
    );
}

#[test]
fn every_verbs_about_appears_in_its_commands_entry() {
    let slice = normalize(&commands_slice(&page()));
    for sub in Cli::command().get_subcommands() {
        let about = sub
            .get_about()
            .unwrap_or_else(|| panic!("subcommand {} has no about in cli.rs", sub.get_name()))
            .to_string();
        let wanted = first_sentence(&about);
        assert!(
            slice.contains(&wanted),
            "man/satl.1: the COMMANDS entry for `{}` does not carry its about.\n\
             expected to find (normalized): {wanted:?}\n\
             Update the entry in man/satl.1 to match cli.rs.",
            sub.get_name()
        );
    }
}

#[test]
fn the_swarm_entry_names_its_cluster_alias() {
    // The alias itself is clap's truth; the page must repeat it on the
    // `.It` line so a reader scanning the list finds `cluster`.
    let swarm = Cli::command()
        .get_subcommands()
        .find(|sub| sub.get_name() == "swarm")
        .expect("the swarm subcommand exists")
        .clone();
    assert!(
        swarm.get_visible_aliases().any(|alias| alias == "cluster"),
        "swarm lost its visible `cluster` alias in cli.rs"
    );
    let page = page();
    let item = commands_slice(&page)
        .lines()
        .find(|line| line.starts_with(".It Cm swarm"))
        .map(str::to_owned)
        .expect("man/satl.1 has an `.It Cm swarm` entry");
    assert!(
        item.contains("cluster"),
        "man/satl.1: the swarm `.It` line must name the `cluster` alias \
         (e.g. `.It Cm swarm , cluster`); found: {item:?}"
    );
}
