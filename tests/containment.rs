//! Carve-out / containment precedence (§6.3). A deny holds unless an allow/ask is
//! a strict subset carve-out of it. These pin the outcomes a character-count
//! specificity score got wrong: overlap must not override, refinement must.

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

// A carve-out claims which paths the exception covers, so it must survive a
// respelling. It must not extend to an operand that only looks like it is inside
// the scratch directory, which is why the path-operand form is decided on its own.
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

// The containment test rejects most pairs with a cheap pre-pass before its
// automaton runs. That pass is an optimization and must never cost a carve-out,
// so these pin the shapes where it comes closest to rejecting a real one.
#[test]
fn containment_prepass_keeps_every_genuine_carve_out() {
    // Each pair is `(allow, deny, payload)` where the allow is a true subset of
    // the deny, so the payload must come back `Allow`.
    let carve_outs = [
        // `**` matching empty at both ends, which is the witness the pre-pass builds.
        ("Read(/a/b)", "Read(/**/b)", "/a/b"),
        ("Read(/a/b)", "Read(/a/**)", "/a/b"),
        ("Read(/a/b)", "Read(/**)", "/a/b"),
        // Wildcard on the allow side, so the witness drops characters the deny
        // still has to match.
        ("Read(/a/*)", "Read(/a/**)", "/a/z"),
        ("Read(/a/**)", "Read(/**)", "/a/b/c"),
        // `?` on the allow side turns the pre-pass off entirely.
        ("Read(/a/?)", "Read(/a/**)", "/a/z"),
        ("Read(/a/?/c)", "Read(/a/**)", "/a/z/c"),
        // Bash family: space is the separator, and the pre-pass runs there too.
        (
            "Bash(git push origin)",
            "Bash(git push *)",
            "git push origin",
        ),
        ("Bash(git push *)", "Bash(git *)", "git push origin"),
    ];
    for (allow, deny, payload) in carve_outs {
        let rs = RuleSet::load_str(&format!(
            r#"{{"defaultMode":"ask","allow":["{allow}"],"deny":["{deny}"]}}"#
        ))
        .unwrap();
        let tier = if allow.starts_with("Bash") {
            decide_bash(payload, &rs, None).tier
        } else {
            decide_payload(&rs, "Read", payload, None).tier
        };
        assert_eq!(tier, Tier::Allow, "carve-out lost: {allow} inside {deny}");
    }
}

// The mirror: pairs that merely overlap must still leave the deny standing. A
// pre-pass that accepted too much would show up here as a lost deny.
#[test]
fn containment_prepass_does_not_invent_carve_outs() {
    let overlaps = [
        ("Read(/**/passwd)", "Read(/etc/**)", "/etc/passwd"),
        (
            "Read(/etc/*.conf)",
            "Read(/etc/secret*)",
            "/etc/secret.conf",
        ),
        ("Read(/a/**)", "Read(/a/*)", "/a/b"),
        ("Bash(git *)", "Bash(git push *)", "git push origin"),
        // Pre-existing incompleteness, asserted so it stays visible: the check
        // models the deny without the `**/`-collapses rule, so `/b` is not proven
        // inside `/**/b`. Unproven containment keeps the deny, the safe direction.
        ("Read(/b)", "Read(/**/b)", "/b"),
        ("Read(x)", "Read(**/x)", "x"),
    ];
    for (allow, deny, payload) in overlaps {
        let rs = RuleSet::load_str(&format!(
            r#"{{"defaultMode":"ask","allow":["{allow}"],"deny":["{deny}"]}}"#
        ))
        .unwrap();
        let tier = if allow.starts_with("Bash") {
            decide_bash(payload, &rs, None).tier
        } else {
            decide_payload(&rs, "Read", payload, None).tier
        };
        assert_eq!(tier, Tier::Deny, "deny lost: {allow} against {deny}");
    }
}
