//! §11 known issues in the reference rule set, locked as regressions.
//!
//! These assert the engine faithfully applies the *authored* rules — even where
//! the rules do not express the operator's likely intent. If the reference file
//! is later corrected (§11 backlog), these expectations change with it.

use permcheck::{RuleSet, Tier, evaluate};
use serde_json::json;

fn reference() -> RuleSet {
    RuleSet::load_str(include_str!("../rules/permcheck.json")).unwrap()
}

fn bash(cmd: &str) -> Tier {
    evaluate(
        &reference(),
        "Bash",
        &json!({ "command": cmd }),
        Some("/work"),
    )
    .tier
}

#[test]
fn issue1_python_dash_c_bypasses_deny_list() {
    // `Bash(python3 *)` allows arbitrary `-c` execution; no `-c` deny exists.
    assert_eq!(bash(r#"python3 -c "import os""#), Tier::Allow);
}

#[test]
fn issue2_shell_operator_specifier_never_fires() {
    // `Bash([ ! -d * ] && gh repo clone *)` contains `&&`; §8 splits before
    // matching, so the rule can never match a single unit. The `[ ... ]` unit
    // falls to the `Bash([ *)` allow, and `gh repo clone` to `Bash(gh:*)`.
    assert_eq!(bash("[ ! -d foo ] && gh repo clone x"), Tier::Allow);
}

#[test]
fn issue3_rm_flag_variants_slip_through() {
    // `rm -rf` / `rm -f` are denied, but `rm -fr` is not, so it hits `rm:*` ask.
    assert_eq!(bash("rm -rf /tmp/x"), Tier::Deny);
    assert_eq!(bash("rm -fr /tmp/x"), Tier::Ask);
}

#[test]
fn issue4_gcp_deny_matches_nothing_real() {
    // `Bash(gcp:*)` denies a command named `gcp`, but the real CLI is `gcloud`,
    // which no rule covers -> the `defaultMode: "ask"` fall-back (not the gcp
    // deny). So the deny is real but never fires on the real CLI, which now asks.
    assert_eq!(bash("gcp compute instances list"), Tier::Deny);
    assert_eq!(bash("gcloud compute instances list"), Tier::Ask);
}

#[test]
fn issue5_bare_path_tools_default_to_allow() {
    let rs = reference();
    assert_eq!(
        evaluate(
            &rs,
            "Read",
            &json!({"file_path":"/tmp/anything"}),
            Some("/work")
        )
        .tier,
        Tier::Allow
    );
}
