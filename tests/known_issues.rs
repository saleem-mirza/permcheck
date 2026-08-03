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
fn issue1_python_dash_c_is_now_denied() {
    // §11.1 fixed: `Bash(python3 -c:*)` (specificity 10) outscores the broad
    // `Bash(python3 *)` allow (8), so arbitrary `-c` execution is denied.
    assert_eq!(bash(r#"python3 -c "import os""#), Tier::Deny);
    // A plain script run stays on the broad allow.
    assert_eq!(bash("python3 script.py"), Tier::Allow);
}

#[test]
fn issue2_shell_operator_specifier_never_fires() {
    // `Bash([ ! -d * ] && gh repo clone *)` contains `&&`; §8 splits before
    // matching, so the rule can never match a single unit. The `[ ... ]` unit
    // falls to the `Bash([ *)` allow, and `gh repo clone` to `Bash(gh:*)`.
    assert_eq!(bash("[ ! -d foo ] && gh repo clone x"), Tier::Allow);
}

#[test]
fn issue3_rm_short_flag_variants_are_now_denied() {
    // §11.3 fixed for short flags: the leading short-flag bundle is split, so any
    // force flag matches the `rm -f` deny regardless of clustering or order.
    assert_eq!(bash("rm -rf /tmp/x"), Tier::Deny);
    assert_eq!(bash("rm -fr /tmp/x"), Tier::Deny);
    assert_eq!(bash("rm -Rf /tmp/x"), Tier::Deny);
    assert_eq!(bash("rm -r -f /tmp/x"), Tier::Deny);
    // Recursive-only rm (no force) stays on the ask-tier `rm:*`.
    assert_eq!(bash("rm -r /tmp/x"), Tier::Ask);
    // §11.3 fixed at the rule level: the engine still does not map a long flag
    // onto its short equivalent, so the reference set carries an explicit
    // `rm *--force*` deny that matches the flag at any argument position.
    assert_eq!(bash("rm --recursive --force /tmp/x"), Tier::Deny);
    assert_eq!(bash("rm --force /tmp/x"), Tier::Deny);
    // Recursive-only stays symmetric with its short spelling: both ask.
    assert_eq!(bash("rm --recursive /tmp/x"), Tier::Ask);
}

#[test]
fn issue4_gcp_clis_are_now_denied() {
    // §11.4 fixed: the dead `Bash(gcp:*)` rule is joined by denies for the real
    // Google Cloud CLIs (`gcloud`, `gsutil`, `bq`), so a cloud mutation no longer
    // slips to the `ask` fall-back.
    assert_eq!(bash("gcp compute instances list"), Tier::Deny);
    assert_eq!(bash("gcloud compute instances list"), Tier::Deny);
    assert_eq!(bash("gsutil rm gs://b/obj"), Tier::Deny);
    assert_eq!(bash("bq rm -t dataset.table"), Tier::Deny);
    // A path-qualified invocation is denied the same as the bare name.
    assert_eq!(bash("/usr/bin/gcloud compute instances list"), Tier::Deny);
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
