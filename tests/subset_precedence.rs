//! Subset-guarded precedence (§6.3a).
//!
//! Phase 1 picks the specificity/tier winner; phase 2 lets a less-restrictive
//! winner override a more-restrictive matching rule only when it is a proven
//! subset of it. These tests lock both the fix (a longer-but-broader allow no
//! longer defeats a deny) and the preserved feature (a genuine narrow exception
//! still punches through).

use permcheck::engine::decide_payload;
use permcheck::{RuleSet, Tier, evaluate};
use serde_json::json;

fn bash(rules: &str, cmd: &str) -> Tier {
    let rs = RuleSet::load_str(rules).unwrap();
    evaluate(&rs, "Bash", &json!({ "command": cmd }), Some("/work")).tier
}

fn read(rules: &str, path: &str) -> Tier {
    let rs = RuleSet::load_str(rules).unwrap();
    decide_payload(&rs, "Read", path, Some("/work")).tier
}

fn web(rules: &str, url: &str) -> Tier {
    let rs = RuleSet::load_str(rules).unwrap();
    decide_payload(&rs, "WebFetch", url, None).tier
}

// --- The inversion is fixed --------------------------------------------------

#[test]
fn longer_but_broader_allow_no_longer_defeats_a_deny() {
    // `kubectl * --namespace prod` (score 25) outscores `kubectl delete:*`
    // (score 14), but it is not a subset of the deny, so the deny holds.
    let rules = r#"{
        "deny":  ["Bash(kubectl delete:*)"],
        "allow": ["Bash(kubectl * --namespace prod)"]
    }"#;
    assert_eq!(
        bash(rules, "kubectl delete pod x --namespace prod"),
        Tier::Deny
    );
    // A delete with no namespace matches only the deny.
    assert_eq!(bash(rules, "kubectl delete pod x"), Tier::Deny);
    // A non-delete in the namespace is a real allow (deny does not match).
    assert_eq!(
        bash(rules, "kubectl get pods --namespace prod"),
        Tier::Allow
    );
}

#[test]
fn path_longer_but_broader_allow_no_longer_defeats_a_deny() {
    // `/**/passwd` (score 8) outscores `/etc/**` (score 5) but also matches
    // `/home/passwd`, so it is not a subset: the deny holds on `/etc/passwd`.
    let rules = r#"{
        "deny":  ["Read(/etc/**)"],
        "allow": ["Read(/**/passwd)"]
    }"#;
    assert_eq!(read(rules, "/etc/passwd"), Tier::Deny);
    // Outside the denied tree the allow is a genuine match.
    assert_eq!(read(rules, "/home/user/passwd"), Tier::Allow);
}

#[test]
fn narrow_deny_over_broad_allow_by_specificity_is_unaffected() {
    // Tightening never needs the guard: a narrow deny already outscores a broad
    // allow, and the guard only ever raises restrictiveness.
    let rules = r#"{
        "allow": ["Read(/repo/**)"],
        "deny":  ["Read(/repo/**/.env)"]
    }"#;
    assert_eq!(read(rules, "/repo/src/.env"), Tier::Deny);
    assert_eq!(read(rules, "/repo/src/main.rs"), Tier::Allow);
}

// --- The narrow-exception feature is preserved -------------------------------

#[test]
fn genuine_subset_allow_still_punches_through_broad_deny() {
    // `aws * describe-*` is a proven subset of `aws:*`, so the read-only policy
    // the post opens on still works.
    let rules = r#"{
        "deny":  ["Bash(aws:*)"],
        "allow": ["Bash(aws * describe-*)"]
    }"#;
    assert_eq!(bash(rules, "aws ec2 describe-instances"), Tier::Allow);
    assert_eq!(bash(rules, "aws ec2 terminate-instances"), Tier::Deny);
    assert_eq!(bash(rules, "aws s3api list-buckets"), Tier::Deny);
}

#[test]
fn subset_allow_punches_through_across_paths() {
    // A narrow path allow that is contained in the broad deny wins.
    let rules = r#"{
        "deny":  ["Read(/**/*)"],
        "allow": ["Read(/tmp/**)"]
    }"#;
    assert_eq!(read(rules, "/tmp/sub/file.txt"), Tier::Allow);
    assert_eq!(read(rules, "/etc/passwd"), Tier::Deny);
}

#[test]
fn generic_domain_allow_punches_through_bare_deny() {
    // The `WebFetch(domain:...)` example: a literal host is a subset of the bare
    // `*`/deny-everything rule, so it is allowed while other hosts are denied.
    let rules = r#"{
        "deny":  ["WebFetch(*)"],
        "allow": ["WebFetch(docs.internal.co)"]
    }"#;
    assert_eq!(web(rules, "https://docs.internal.co/x"), Tier::Allow);
    assert_eq!(web(rules, "https://evil.io/x"), Tier::Deny);
}

#[test]
fn double_star_collapse_allow_is_a_subset() {
    // `/**/.env` matches `/.env` (zero directories), so a literal `/.env` allow
    // is a proven subset of the deny and would be over-denied without the
    // collapse being modeled. Here the allow legitimately wins.
    let rules = r#"{
        "deny":  ["Read(/srv/**)"],
        "allow": ["Read(/**/.env)"]
    }"#;
    // `/.env` is matched by the allow and not by the `/srv/**` deny -> allow.
    assert_eq!(read(rules, "/.env"), Tier::Allow);
}

// --- Ties and defaults still behave -----------------------------------------

#[test]
fn equal_specifier_still_resolves_most_restrictive() {
    let rules = r#"{
        "allow": ["Read(/x)"],
        "deny":  ["Read(/x)"]
    }"#;
    assert_eq!(read(rules, "/x"), Tier::Deny);
}
