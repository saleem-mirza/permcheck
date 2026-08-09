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

// Windows-only: a drive-letter CWD must be POSIX-anchored (`/D:/proj`) so the
// `/`-based Path globs still match the absolutized relative payload. POSIX is
// already `/`-rooted and covered above.
#[cfg(windows)]
#[test]
fn windows_cwd_is_normalized_before_matching() {
    let rs = RuleSet::load_str(r#"{"deny":["Read(/**/.env*)"]}"#).unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", ".env", Some(r"D:\proj\permcheck")).tier,
        Tier::Deny
    );
}

// Windows-only: a drive-letter payload must normalize to `/D:/proj/.env` so a
// `/`-anchored deny fires, and must not be mis-classified as relative and joined
// onto an unrelated cwd.
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

// Windows-only: the filesystem is case-insensitive, so a differently-cased payload
// opens the same file and must not slip past a deny. The drive letter's case must
// not matter either. POSIX is case-sensitive by design.
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

// Windows-only: `C:notes.txt` is drive-relative, read under the current directory
// on drive C. Anchoring it as `/C:notes.txt` matched no `/C:/**` rule at all, so a
// deny on the drive missed it. It must anchor under `/C:/`.
#[cfg(windows)]
#[test]
fn windows_drive_relative_payload_anchors_under_the_drive() {
    let rs = RuleSet::load_str(r#"{"deny":["Read(/C:/**)"]}"#).unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", "C:notes.txt", None).tier,
        Tier::Deny
    );
    // The drive-rooted spellings were already covered and must not regress.
    assert_eq!(
        decide_payload(&rs, "Read", r"C:\notes.txt", None).tier,
        Tier::Deny
    );
    assert_eq!(
        decide_payload(&rs, "Read", "C:/notes.txt", None).tier,
        Tier::Deny
    );
}

// Windows-only: the drive root is a fallback. A cwd on the same drive supplies the
// real current directory, so a deny anchored deeper still fires; a cwd on another
// drive says nothing, so no candidate is invented.
#[cfg(windows)]
#[test]
fn windows_drive_relative_payload_resolves_against_a_same_drive_cwd() {
    // `defaultMode` is explicit here so the last case pins "no candidate matched"
    // rather than colliding with the missing-key fall-back, which is also deny.
    let rs = RuleSet::load_str(r#"{"defaultMode":"ask","deny":["Read(/C:/work/**)"]}"#).unwrap();
    assert_eq!(
        decide_payload(&rs, "Read", "C:secret.txt", Some(r"C:\work")).tier,
        Tier::Deny
    );
    // Same drive, different case on the letter: the filesystem does not care.
    assert_eq!(
        decide_payload(&rs, "Read", "c:secret.txt", Some(r"C:\work")).tier,
        Tier::Deny
    );
    // A different drive says nothing about where `C:secret.txt` lands, so no
    // candidate is invented from it and only the drive-root form survives.
    assert_eq!(
        decide_payload(&rs, "Read", "C:secret.txt", Some(r"D:\work")).tier,
        Tier::Ask
    );
}
