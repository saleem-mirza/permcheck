//! Configurable unmatched-call fall-back via `defaultMode` (§6.4). `"ask"` decides
//! `ask`; any other value, including a missing key, stays fail-closed at `deny`.
//! Explicit denies and the cross-check still win over the fall-back.

use permcheck::rules::RuleSet;
use permcheck::types::Tier;
use permcheck::{evaluate, load_rules_str};
use serde_json::json;

fn tier(rules: &str, tool: &str, payload: &str) -> Tier {
    let rs = load_rules_str(rules).unwrap();
    let input = match tool {
        "Bash" => json!({ "command": payload }),
        "Read" | "Write" | "Edit" => json!({ "file_path": payload }),
        "WebSearch" => json!({ "query": payload }),
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
    let rules =
        r#"{"permissions":{"defaultMode":"ask","deny":["Bash(sudo:*)","Read(/**/.env*)"]}}"#;
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
fn a_bash_command_that_runs_nothing_is_allowed() {
    // The fall-back is for a command no rule named, not one with no command in it,
    // so the answer must not depend on `defaultMode`.
    for command in ["   ", "", "\n", ";", ";;", "# just a comment", "( )"] {
        for mode in ["ask", "deny"] {
            let rules = format!(r#"{{"permissions":{{"defaultMode":"{mode}"}}}}"#);
            assert_eq!(
                tier(&rules, "Bash", command),
                Tier::Allow,
                "{mode}-default: {command:?}"
            );
        }
    }
}

#[test]
fn a_comment_cannot_swallow_the_command_after_it() {
    // Why the case above is safe: a comment ends at its newline, so a command on
    // the next line is still its own unit.
    let rules = r#"{"permissions":{"defaultMode":"ask","deny":["Bash(sudo:*)"]}}"#;
    for command in [
        "# c\nsudo whoami",
        "ls # c\nsudo whoami",
        "ls; # c\nsudo whoami",
        "# $(sudo whoami)\nsudo whoami",
    ] {
        assert_eq!(tier(rules, "Bash", command), Tier::Deny, "{command:?}");
    }
    // A substitution that only ever appears inside a comment runs nothing.
    assert_eq!(tier(rules, "Bash", "# $(sudo whoami)"), Tier::Allow);
}

#[test]
fn wildcard_tool_rule_covers_mcp_tools_but_not_other_prefixes() {
    let rules = r#"{"defaultMode":"ask","deny":["mcp__serena__*"]}"#;
    assert_eq!(tier(rules, "mcp__serena__read_file", "x"), Tier::Deny);
    assert_eq!(tier(rules, "mcp__github__read_file", "x"), Tier::Ask);
}

#[test]
fn exact_tool_rule_carves_out_wildcard_tool_deny() {
    let rules = r#"{
        "allow":["mcp__serena__read_file"],
        "deny":["mcp__serena__*"]
    }"#;
    assert_eq!(tier(rules, "mcp__serena__read_file", "x"), Tier::Allow);
    assert_eq!(tier(rules, "mcp__serena__delete_file", "x"), Tier::Deny);
}

#[test]
fn universal_tool_ask_yields_to_exact_tool_allow() {
    let rules = r#"{"allow":["TodoWrite"],"ask":["*"]}"#;
    assert_eq!(tier(rules, "TodoWrite", ""), Tier::Allow);
    assert_eq!(tier(rules, "ExitPlanMode", ""), Tier::Ask);
}

#[test]
fn oversized_payload_fails_closed() {
    let rules = r#"{"allow":["*"]}"#;
    assert_eq!(
        tier(rules, "mcp__db__query", &"x".repeat(32_769)),
        Tier::Deny
    );
    assert_eq!(tier(rules, "Bash", &"x".repeat(32_769)), Tier::Deny);
}

#[test]
fn matcher_work_budget_fails_closed() {
    let pattern = format!("{}*", "x".repeat(1_000));
    let rules = serde_json::json!({"allow": [format!("WebSearch({pattern})")]}).to_string();
    assert_eq!(tier(&rules, "WebSearch", &"x".repeat(3_000)), Tier::Deny);
}

#[test]
fn aggregate_matcher_work_budget_fails_closed() {
    // Every match is individually below the two-million-state limit, but the
    // repeated worst-case misses exceed the complete decision's budget.
    let pattern = format!("*{}b", "a".repeat(59));
    let rules = serde_json::json!({
        "allow": vec![format!("WebSearch({pattern})"); 12],
        "defaultMode": "ask",
    })
    .to_string();
    assert_eq!(tier(&rules, "WebSearch", &"a".repeat(32_000)), Tier::Deny);
}
