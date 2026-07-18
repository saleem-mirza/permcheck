//! Configurable unmatched-command fall-back via `defaultMode` (§6.4).
//!
//! `defaultMode: "ask"` makes a call that matches no rule decide `ask`; any other
//! value (including `"deny"`, the native `"default"`, garbage, or a missing key)
//! stays fail-closed at `deny`. The Bash cross-check and explicit denies are
//! unaffected — they still win over the fall-back.

use permcheck::rules::RuleSet;
use permcheck::types::Tier;
use permcheck::{evaluate, load_rules_str};
use serde_json::json;

fn tier(rules: &str, tool: &str, payload: &str) -> Tier {
    let rs = load_rules_str(rules).unwrap();
    let input = match tool {
        "Bash" => json!({ "command": payload }),
        "Read" | "Write" | "Edit" => json!({ "file_path": payload }),
        _ => json!({ "input": payload }),
    };
    evaluate(&rs, tool, &input, Some("/work")).tier
}

#[test]
fn ask_mode_makes_unmatched_calls_ask_across_families() {
    let rules = r#"{"permissions":{"defaultMode":"ask","allow":["Bash(ls:*)"]}}"#;
    // Bash unit with no matching rule.
    assert_eq!(tier(rules, "Bash", "some-tool foo"), Tier::Ask);
    // Path family, no Read rule at all.
    assert_eq!(tier(rules, "Read", "/etc/hosts"), Tier::Ask);
    // Generic family (MCP tool), no rule names it.
    assert_eq!(tier(rules, "mcp__db__query", "SELECT 1"), Tier::Ask);
}

#[test]
fn deny_mode_keeps_unmatched_calls_denied() {
    let rules = r#"{"permissions":{"defaultMode":"deny","allow":["Bash(ls:*)"]}}"#;
    assert_eq!(tier(rules, "Bash", "some-tool foo"), Tier::Deny);
    assert_eq!(tier(rules, "Read", "/etc/hosts"), Tier::Deny);
}

#[test]
fn missing_and_other_values_default_to_deny() {
    // Missing defaultMode.
    assert_eq!(
        tier(r#"{"allow":["Bash(ls:*)"]}"#, "Bash", "some-tool foo"),
        Tier::Deny
    );
    // Native Claude Code value "default".
    assert_eq!(
        tier(
            r#"{"permissions":{"defaultMode":"default"}}"#,
            "Bash",
            "some-tool foo"
        ),
        Tier::Deny
    );
    // Garbage value → fail-closed.
    assert_eq!(
        tier(
            r#"{"permissions":{"defaultMode":"whatever"}}"#,
            "Bash",
            "some-tool foo"
        ),
        Tier::Deny
    );
}

#[test]
fn ask_mode_does_not_loosen_explicit_deny_or_crosscheck() {
    let rules = r#"{"permissions":{"defaultMode":"ask","deny":["Bash(sudo:*)","Read(/**/.env*)"]}}"#;
    // Explicit deny still wins over the ask fall-back.
    assert_eq!(tier(rules, "Bash", "sudo rm -rf /"), Tier::Deny);
    // Bash file-access cross-check still raises to deny (a path IS denied).
    assert_eq!(tier(rules, "Bash", "cat .env"), Tier::Deny);
    // A genuinely unlisted command still asks.
    assert_eq!(tier(rules, "Bash", "some-tool foo"), Tier::Ask);
}

#[test]
fn ask_mode_honored_in_top_level_form() {
    // No `permissions` wrapper — top-level tier arrays + defaultMode.
    let rules = r#"{"defaultMode":"ask","allow":["Bash(ls:*)"]}"#;
    let rs = RuleSet::load_str(rules).unwrap();
    assert_eq!(rs.default_tier, Tier::Ask);
    assert_eq!(tier(rules, "Bash", "some-tool foo"), Tier::Ask);
}

#[test]
fn empty_bash_command_uses_fallback_tier() {
    assert_eq!(
        tier(r#"{"permissions":{"defaultMode":"ask"}}"#, "Bash", "   "),
        Tier::Ask
    );
    assert_eq!(
        tier(r#"{"permissions":{"defaultMode":"deny"}}"#, "Bash", "   "),
        Tier::Deny
    );
}
