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
    // The carve-out survives the single-token service slot: a mutating call does
    // not ride in on a later `describe-` substring or a value that contains one.
    assert_eq!(
        decide_bash("aws s3 rm s3://prod-bucket/describe-report.json", &rs, None).tier,
        Tier::Deny
    );
    assert_eq!(
        decide_bash("aws iam delete-user --user-name describe-me", &rs, None).tier,
        Tier::Deny
    );
    // A describe across any single-token service still carves out.
    assert_eq!(
        decide_bash("aws rds describe-db-instances", &rs, None).tier,
        Tier::Allow
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

#[test]
fn every_matching_deny_must_be_carved() {
    // `/etc/*` refines `/etc/**`, but it does not refine `/**/passwd`. The engine
    // may resolve denies incrementally, but it must continue past a carved deny
    // and reject as soon as it reaches the uncarved one.
    let rs = RuleSet::load_str(
        r#"{"allow":["Read(/etc/*)"],"deny":["Read(/etc/**)","Read(/**/passwd)"]}"#,
    )
    .unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", "/etc/passwd", None).tier,
        Tier::Deny
    );

    // A literal exception is a strict subset of both denies, so it survives.
    let rs = RuleSet::load_str(
        r#"{"allow":["Read(/etc/passwd)"],"deny":["Read(/etc/**)","Read(/**/passwd)"]}"#,
    )
    .unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", "/etc/passwd", None).tier,
        Tier::Allow
    );
}

// A carve-out is a claim about which *paths* the exception covers, so it has to
// survive a respelling of the path. `Bash(rm -rf /w/.scratch/*)` is a strict
// subset of `Bash(rm -rf /*)` and legitimately carves it, but the carve-out must
// not extend to a command whose operand only looks like it is inside the scratch
// directory. The path-operand form (§8 step 2) is decided on its own precisely so
// that a raw-text match cannot carve it away.
#[test]
fn a_carve_out_does_not_cover_a_traversal_out_of_its_directory() {
    let rs = RuleSet::load_str(
        r#"{"defaultMode":"ask","allow":["Bash(rm -rf /w/.scratch/*)"],"deny":["Bash(rm -rf /*)"]}"#,
    )
    .unwrap();
    assert_eq!(
        decide_bash("rm -rf /w/.scratch/build", &rs, Some("/w")).tier,
        Tier::Allow
    );
    assert_eq!(
        decide_bash("rm -rf /w/.scratch/../src", &rs, Some("/w")).tier,
        Tier::Deny
    );
}

// Windows-only: `\` is the separator a real Windows caller writes, so the same
// carve-out has to hold for the backslash spelling and the mixed spelling. Not
// compiled on POSIX, where `\` is a shell escape and the test above covers it.
#[cfg(windows)]
#[test]
fn windows_carve_out_survives_backslash_traversal() {
    let rs = RuleSet::load_str(
        r#"{"defaultMode":"ask","allow":["Bash(rm -rf /C:/w/.scratch/*)"],"deny":["Bash(rm -rf /C:/*)"]}"#,
    )
    .unwrap();
    assert_eq!(
        decide_bash(r"rm -rf C:\w\.scratch\..\src", &rs, Some(r"C:\w")).tier,
        Tier::Deny
    );
    assert_eq!(
        decide_bash("rm -rf C:/w/.scratch/../src", &rs, Some(r"C:\w")).tier,
        Tier::Deny
    );
}
