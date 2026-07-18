//! Winner-selection + candidate-form unit tests (§6.3, §7).

use crate::engine::{decide_payload, url_host};
use crate::rules::RuleSet;
use crate::types::Tier;

#[test]
fn more_specific_allow_beats_broad_deny() {
    let rs = RuleSet::load_str(r#"{"deny":["Bash(aws:*)"],"allow":["Bash(aws * describe-*)"]}"#)
        .unwrap();
    // Bash routes through decide_bash, but the winner selection is shared; here
    // we exercise the Path/Generic path directly.
    let rs2 = RuleSet::load_str(r#"{"deny":["Read(/**/*)"],"allow":["Read(/tmp/*)"]}"#).unwrap();
    let _ = rs;
    assert_eq!(
        decide_payload(&rs2, "Read", "/tmp/x", None).tier,
        Tier::Allow
    );
    assert_eq!(
        decide_payload(&rs2, "Read", "/etc/x", None).tier,
        Tier::Deny
    );
}

#[test]
fn same_specifier_most_restrictive_tier_wins() {
    let rs = RuleSet::load_str(r#"{"allow":["Read(/x)"],"ask":["Read(/x)"],"deny":["Read(/x)"]}"#)
        .unwrap();
    assert_eq!(decide_payload(&rs, "Read", "/x", None).tier, Tier::Deny);
}

#[test]
fn default_deny_when_nothing_matches() {
    let rs = RuleSet::load_str(r#"{"allow":["Read(/tmp/*)"]}"#).unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", "/etc/passwd", None).tier,
        Tier::Deny
    );
}

#[test]
fn relative_path_absolutized_against_cwd() {
    let rs = RuleSet::load_str(r#"{"deny":["Read(/**/.env*)"]}"#).unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", ".env", Some("/home/user")).tier,
        Tier::Deny
    );
}

#[test]
fn empty_payload_reason_uses_tool_name() {
    // A tool that takes no string payload (empty extracted payload) must report
    // the tool name, not a trailing-space `<label>: ` (§2.1). This is the
    // canonical reason the binary emits, built once in the library.
    let rs = RuleSet::load_str(r#"{"allow":["TodoWrite"]}"#).unwrap();
    let decision = decide_payload(&rs, "TodoWrite", "", None);
    assert_eq!(decision.tier, Tier::Allow);
    assert_eq!(decision.reason, "allow: TodoWrite");
}

#[test]
fn url_host_extraction() {
    assert_eq!(
        url_host("https://example.com/path").as_deref(),
        Some("example.com")
    );
    assert_eq!(
        url_host("https://user@Example.com:8443/x").as_deref(),
        Some("Example.com")
    );
    assert_eq!(url_host("example.com"), None);
}

#[test]
fn generic_matches_host_not_substring() {
    let rs = RuleSet::load_str(r#"{"allow":["WebFetch(example.com)"]}"#).unwrap();
    assert_eq!(
        decide_payload(&rs, "WebFetch", "https://example.com/path", None).tier,
        Tier::Allow
    );
    assert_eq!(
        decide_payload(&rs, "WebFetch", "https://example.com.evil.com/x", None).tier,
        Tier::Deny
    );
}
