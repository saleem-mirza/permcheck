//! Winner-selection + candidate-form unit tests (§6.3, §7).

use permcheck::engine::{decide_payload, url_host};
use permcheck::rules::RuleSet;
use permcheck::types::Tier;

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

// Windows-only: a drive-letter CWD with backslashes must be normalized to a
// POSIX-anchored form (`/D:/proj`) so the `/`-based Path globs still match the
// absolutized relative payload. Not compiled on POSIX, where the CWD is already
// `/`-rooted and `relative_path_absolutized_against_cwd` above covers the case.
#[cfg(windows)]
#[test]
fn windows_cwd_is_normalized_before_matching() {
    let rs = RuleSet::load_str(r#"{"deny":["Read(/**/.env*)"]}"#).unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", ".env", Some(r"D:\proj\permcheck")).tier,
        Tier::Deny
    );
}

// Windows-only: the real hook payload for Read/Write/Edit is an *absolute*
// path. A drive-letter payload (`D:\proj\.env`, or its forward-slash form) must
// normalize to `/D:/proj/.env` so a `/`-anchored deny rule fires — and it must
// NOT be mis-classified as relative and joined onto the (unrelated) cwd.
#[cfg(windows)]
#[test]
fn windows_absolute_drive_payload_is_normalized() {
    let rs = RuleSet::load_str(r#"{"deny":["Read(/**/.env*)"]}"#).unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", r"D:\proj\.env", Some(r"D:\other")).tier,
        Tier::Deny
    );
    assert_eq!(
        decide_payload(&rs, "Read", "D:/proj/.env", Some(r"D:\other")).tier,
        Tier::Deny
    );
}

// Windows-only: the filesystem is case-insensitive, so a differently-cased
// payload opens the same file and must not slip past a deny. A literal deny
// (`id_rsa`) must fire on `ID_RSA`/`Id_Rsa`, and the drive letter's case must
// not matter either. Not compiled on POSIX, which is case-sensitive by design.
#[cfg(windows)]
#[test]
fn windows_path_matching_is_case_insensitive() {
    let rs = RuleSet::load_str(r#"{"deny":["Read(/**/id_rsa)"]}"#).unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", r"D:\proj\ID_RSA", None).tier,
        Tier::Deny
    );
    assert_eq!(
        decide_payload(&rs, "Read", r"D:\proj\Id_Rsa", None).tier,
        Tier::Deny
    );
    assert_eq!(
        decide_payload(&rs, "Read", r"d:\proj\id_rsa", None).tier,
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
