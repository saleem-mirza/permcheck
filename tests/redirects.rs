//! §8 redirection cross-checks, driven through the public library API.

use permcheck::{RuleSet, Tier, evaluate};
use serde_json::json;

const RULES: &str = r#"{
  "allow": ["Bash(echo:*)", "Bash(cat:*)", "Bash(tee:*)"],
  "deny":  ["Read(/**/.env*)", "Write(/**/secret*)", "Edit(/**/secret*)"]
}"#;

fn tier(cmd: &str) -> Tier {
    let rs = RuleSet::load_str(RULES).unwrap();
    evaluate(&rs, "Bash", &json!({ "command": cmd }), Some("/work")).tier
}

#[test]
fn write_redirect_to_denied_path() {
    assert_eq!(tier("echo hi > /work/secret.txt"), Tier::Deny);
    assert_eq!(tier("echo hi >> /work/secret.txt"), Tier::Deny);
    assert_eq!(tier("echo hi &> /work/secret.txt"), Tier::Deny);
}

#[test]
fn read_redirect_from_denied_path() {
    assert_eq!(tier("cat < /work/.env"), Tier::Deny);
}

#[test]
fn clobber_override_is_a_write() {
    // `>|` overrides `noclobber` and writes exactly as `>` does. Its `|` must not
    // reach the splitter's pipe handling, which would cut the unit before the
    // target and leave the write with no cross-check at all.
    assert_eq!(tier("echo hi >| /work/secret.txt"), Tier::Deny);
    assert_eq!(tier("echo hi >|/work/secret.txt"), Tier::Deny);
    assert_eq!(tier("echo hi 1>| /work/secret.txt"), Tier::Deny);
    assert_eq!(tier("echo hi >| /work/out.txt"), Tier::Allow);
}

#[test]
fn fd_dup_is_not_a_write() {
    assert_eq!(tier("echo hi 2>&1"), Tier::Allow);
    assert_eq!(tier("echo hi >&2"), Tier::Allow);
}

#[test]
fn benign_redirect_is_allowed() {
    assert_eq!(tier("echo hi > /work/out.txt"), Tier::Allow);
}
