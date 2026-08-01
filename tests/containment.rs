//! Carve-out / containment precedence (§6.3).
//!
//! A matching deny holds unless a matching allow/ask is a *strict* subset
//! carve-out of it. These cases pin the cross-tier outcomes that a character-count
//! specificity score got wrong: a longer allow that merely overlaps a deny must
//! not override it, while a genuine refinement still does.

use permcheck::bash::decide_bash;
use permcheck::engine::decide_payload;
use permcheck::rules::RuleSet;
use permcheck::types::Tier;

// A wider allow that is not a subset of the deny must not override it. This is the
// `/etc/passwd` case: `Read(/**/passwd)` (allow) overlaps `Read(/etc/**)` (deny)
// without refining it.
#[test]
fn wider_allow_does_not_override_overlapping_deny() {
    let rs =
        RuleSet::load_str(r#"{"allow":["Read(/**/passwd)"],"deny":["Read(/etc/**)"]}"#).unwrap();
    // Both rules match -> deny survives (allow is not a carve-out).
    assert_eq!(
        decide_payload(&rs, "Read", "/etc/passwd", None).tier,
        Tier::Deny
    );
    // Only the allow matches here -> allow.
    assert_eq!(
        decide_payload(&rs, "Read", "/home/u/passwd", None).tier,
        Tier::Allow
    );
}

// An allow that is a strict subset of the deny is a real carve-out and wins.
#[test]
fn exact_allow_carves_out_broad_deny() {
    let rs =
        RuleSet::load_str(r#"{"allow":["Read(/etc/passwd)"],"deny":["Read(/etc/**)"]}"#).unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", "/etc/passwd", None).tier,
        Tier::Allow
    );
    assert_eq!(
        decide_payload(&rs, "Read", "/etc/shadow", None).tier,
        Tier::Deny
    );
}

// Two globs that overlap but where neither contains the other: the deny wins at
// the shared payload (the safe default).
#[test]
fn incomparable_overlap_resolves_to_deny() {
    let rs = RuleSet::load_str(r#"{"allow":["Read(/etc/*.conf)"],"deny":["Read(/etc/secret*)"]}"#)
        .unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", "/etc/secret.conf", None).tier,
        Tier::Deny
    );
    // Each rule still governs the region the other does not reach.
    assert_eq!(
        decide_payload(&rs, "Read", "/etc/app.conf", None).tier,
        Tier::Allow
    );
    assert_eq!(
        decide_payload(&rs, "Read", "/etc/secret.key", None).tier,
        Tier::Deny
    );
}

// Bash carve-out: `aws * describe-*` is a strict subset of the `aws:*` deny.
#[test]
fn bash_narrow_allow_carves_out_broad_deny() {
    let rs = RuleSet::load_str(r#"{"allow":["Bash(aws * describe-*)"],"deny":["Bash(aws:*)"]}"#)
        .unwrap();
    assert_eq!(
        decide_bash("aws ec2 describe-instances", &rs, None).tier,
        Tier::Allow
    );
    assert_eq!(
        decide_bash("aws s3 rm s3://b --recursive", &rs, None).tier,
        Tier::Deny
    );
}

// A narrow allow carves out a bare (match-everything) deny.
#[test]
fn narrow_allow_carves_out_bare_deny() {
    let rs =
        RuleSet::load_str(r#"{"allow":["WebFetch(https://api.example.com)"],"deny":["WebFetch"]}"#)
            .unwrap();
    assert_eq!(
        decide_payload(&rs, "WebFetch", "https://api.example.com", None).tier,
        Tier::Allow
    );
    assert_eq!(
        decide_payload(&rs, "WebFetch", "https://evil.example.org", None).tier,
        Tier::Deny
    );
}

// A bare allow does not carve out a narrow deny: the deny wins where it matches.
#[test]
fn bare_allow_does_not_override_narrow_deny() {
    let rs = RuleSet::load_str(r#"{"allow":["Read"],"deny":["Read(/etc/**)"]}"#).unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", "/etc/passwd", None).tier,
        Tier::Deny
    );
    assert_eq!(
        decide_payload(&rs, "Read", "/tmp/ok.txt", None).tier,
        Tier::Allow
    );
}
