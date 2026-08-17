// SPDX-License-Identifier: BSD-2-Clause
//! Root-only end-to-end test of the orphan rctl rule purge (`make integration`).
//!
//! Reproduces audit finding N4 against the real kernel and then proves the
//! fix: rules installed for a jail survive the jail's death, and
//! [`Rctl::purge_orphan_rules`] removes exactly the SatL-shaped orphans —
//! a third-party jail's rules must be left byte-for-byte alone.
//!
//! Conventions (CLAUDE.md): the third-party artifacts are `rptest`-prefixed;
//! the SatL jail is a generated task id, because the pinned M1 contract is
//! *jail name = task ID*. A drop guard tears everything down even on panic.
//!
//! Skips (does not fail) when `kern.racct.enable` is not `1`: no rule can
//! exist then, so there is nothing to measure — the dev host runs racct off
//! and is never rebooted.

use std::collections::BTreeSet;
use std::process::Command;

use satl_agent::{LimitsOutcome, Rctl};
use satl_core::Id;
use satl_runtime::Jails;

const JAIL: &str = "/usr/sbin/jail";
const RCTL: &str = "/usr/bin/rctl";
const SYSCTL: &str = "/sbin/sysctl";

/// The third-party jail: not SatL-shaped, so the purge must never touch it.
const THIRD_PARTY: &str = "rptest3p";

fn run(program: &str, args: &[&str]) -> (bool, String) {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to spawn `{program} {}`: {err}", args.join(" ")));
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

fn assert_root() {
    let (_, uid) = run("/usr/bin/id", &["-u"]);
    assert_eq!(
        uid.trim(),
        "0",
        "this #[ignore] test must run as root (make integration)"
    );
}

fn racct_enabled() -> bool {
    let (_, value) = run(SYSCTL, &["-n", "kern.racct.enable"]);
    value.trim() == "1"
}

/// The subjects of every installed rule, as `rctl` prints them.
fn installed_rules() -> String {
    let (ok, stdout) = run(RCTL, &[]);
    assert!(ok, "rctl listing failed");
    stdout
}

/// Removes rules and jail, in both orders' worth of care, for every name it
/// holds — on success and on panic alike.
struct Guard {
    names: Vec<String>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = Command::new(RCTL)
                .args(["-r", &format!("jail:{name}")])
                .output();
            let _ = Command::new(JAIL).args(["-r", name]).output();
        }
    }
}

#[tokio::test]
#[ignore = "requires root and kern.racct.enable=1 (run via make integration)"]
async fn purge_removes_a_dead_jails_rules_and_leaves_third_partys() {
    assert_root();
    if !racct_enabled() {
        eprintln!("skipping: kern.racct.enable != 1 (no rctl rules can exist)");
        return;
    }

    let dead_satl = Id::generate().to_string();
    let live_satl = Id::generate().to_string();
    let _guard = Guard {
        names: vec![dead_satl.clone(), live_satl.clone(), THIRD_PARTY.to_owned()],
    };
    let rctl = Rctl::system(true);

    // Three jails with a rule each: a SatL one that dies, a SatL one that
    // lives, and a third-party one that dies.
    for name in [&dead_satl, &live_satl, THIRD_PARTY] {
        let (ok, _) = run(JAIL, &["-c", &format!("name={name}"), "persist", "path=/"]);
        assert!(ok, "jail -c {name} failed");
        let outcome = rctl
            .apply_limits(name, Some(64 << 20), None)
            .await
            .expect("apply_limits");
        assert!(
            matches!(outcome, LimitsOutcome::Applied { .. }),
            "rule not applied for {name}: {outcome:?}"
        );
    }
    for name in [&dead_satl, THIRD_PARTY] {
        let (ok, _) = run(JAIL, &["-r", name]);
        assert!(ok, "jail -r {name} failed");
    }

    // N4's premise, verified against this kernel: both dead jails' rules
    // survived the jails' death.
    let rules = installed_rules();
    assert!(
        rules.contains(&format!("jail:{dead_satl}:")),
        "the dead SatL jail's rule did not survive its jail:\n{rules}"
    );
    assert!(
        rules.contains(&format!("jail:{THIRD_PARTY}:")),
        "the dead third-party jail's rule did not survive its jail:\n{rules}"
    );

    // The live set is jls's, exactly as the reconciliation pass builds it.
    let live: BTreeSet<String> = Jails::system()
        .list()
        .await
        .expect("jls list")
        .into_iter()
        .map(|(name, _state)| name)
        .collect();
    assert!(live.contains(&live_satl), "live jail missing from jls");
    assert!(!live.contains(&dead_satl), "dead jail still in jls");

    let purged = rctl.purge_orphan_rules(&live).await.expect("purge");
    assert_eq!(purged, std::slice::from_ref(&dead_satl), "purged subjects");

    let rules = installed_rules();
    assert!(
        !rules.contains(&format!("jail:{dead_satl}:")),
        "the orphan's rules survived the purge:\n{rules}"
    );
    assert!(
        rules.contains(&format!("jail:{live_satl}:")),
        "the live jail's rules were purged:\n{rules}"
    );
    assert!(
        rules.contains(&format!("jail:{THIRD_PARTY}:")),
        "the third-party jail's rules were purged:\n{rules}"
    );
}
