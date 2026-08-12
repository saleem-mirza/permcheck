//! Decision reasons name what stopped a call (§2.1). `permissionDecisionReason`
//! is the only field Claude Code reads back, so these lock the clause separating
//! a missing allow entry from a policy stopping an escalation.

use permcheck::{RuleSet, Tier, evaluate, load_rules_str};
use serde_json::json;

const RULES: &str = r#"{
  "defaultMode": "%MODE%",
  "allow": ["Bash(ls:*)", "Bash(cat:*)", "Read"],
  "ask": ["Bash(git push:*)"],
  "deny": ["Bash(sudo:*)", "Read(/**/.env*)", "Read(//**/.ssh/**)"]
}"#;

fn rules(mode: &str) -> RuleSet {
    load_rules_str(&RULES.replace("%MODE%", mode)).expect("crafted rules load")
}

fn bash(cmd: &str) -> String {
    reason("ask", "Bash", json!({ "command": cmd }))
}

fn reason(mode: &str, tool: &str, input: serde_json::Value) -> String {
    evaluate(&rules(mode), tool, &input, Some("/work")).reason
}

fn tier(mode: &str, cmd: &str) -> Tier {
    evaluate(
        &rules(mode),
        "Bash",
        &json!({ "command": cmd }),
        Some("/work"),
    )
    .tier
}

#[test]
fn a_blocked_compound_names_the_statement_and_the_rule() {
    // Which of several statements did it, and on what rule.
    assert_eq!(
        bash("ls; sudo whoami"),
        r#"deny: ls; sudo whoami (statement 2 of 2: "sudo whoami" matched Bash(sudo:*))"#
    );
    // Counting is over the statements as split.
    assert_eq!(
        bash("ls; cat a; sudo whoami"),
        r#"deny: ls; cat a; sudo whoami (statement 3 of 3: "sudo whoami" matched Bash(sudo:*))"#
    );
}

#[test]
fn a_policy_hole_reads_differently_from_a_policy_decision() {
    // Both used to read `deny: <whole command>`. One means the allow list is short
    // an entry, the other means a rule fired.
    let hole = reason("deny", "Bash", json!({ "command": "ls | frobnicate" }));
    let block = reason("deny", "Bash", json!({ "command": "ls | sudo whoami" }));
    assert!(hole.contains("no rule matched, defaultMode=deny"), "{hole}");
    assert!(hole.contains(r#""frobnicate""#), "{hole}");
    assert!(block.contains("matched Bash(sudo:*)"), "{block}");
    assert_ne!(hole, block);
}

#[test]
fn the_fall_back_clause_reports_the_configured_mode() {
    // The reader should not need to know which mode is configured.
    assert!(
        reason("ask", "Bash", json!({ "command": "frobnicate" }))
            .contains("no rule matched, defaultMode=ask")
    );
    assert!(
        reason("deny", "Bash", json!({ "command": "frobnicate" }))
            .contains("no rule matched, defaultMode=deny")
    );
}

#[test]
fn a_wrapper_stage_says_which_stage_matched() {
    // The unit matches nothing; the rule fired one peel in.
    assert_eq!(
        bash("command sudo whoami"),
        r#"deny: command sudo whoami (wrapper stage "sudo whoami" matched Bash(sudo:*))"#
    );
}

#[test]
fn the_cross_check_names_the_path_it_stopped() {
    // `cat` is allowed, so the operand is the whole reason.
    let why = bash("cat .env");
    assert!(why.contains(r#"reaches denied path ".env""#), "{why}");
    assert!(why.contains("Read(/**/.env*)"), "{why}");
}

#[test]
fn an_exhausted_cross_check_names_the_limit_and_no_rule() {
    // Twenty 1000-token globs against an 1100-byte operand: each match is legal
    // on its own (1.1M states, under the 2M per-match bound) and together they
    // pass the 20M decision bound, so the scan runs out mid-way. It must deny,
    // and it must not pin that deny on whichever rule it happened to reach.
    let glob = "a".repeat(1000);
    let deny: Vec<String> = (0..20).map(|_| format!("Read(/{glob}*)")).collect();
    let policy = json!({
        "defaultMode": "allow",
        "allow": ["Bash(cat:*)"],
        "deny": deny,
    });
    let rs = load_rules_str(&policy.to_string()).expect("crafted rules load");
    let operand = "b".repeat(1100);
    let decision = evaluate(
        &rs,
        "Bash",
        &json!({ "command": format!("cat /{operand}") }),
        Some("/work"),
    );

    assert_eq!(decision.tier, Tier::Deny, "{}", decision.reason);
    assert!(
        decision.reason.contains("blocked by a safety limit"),
        "{}",
        decision.reason
    );
    // The giveaway for the bug this locks: no `Read(...)` rule is named, since
    // none of them matched.
    assert!(!decision.reason.contains("Read("), "{}", decision.reason);
}

#[test]
fn a_single_statement_drops_the_statement_prefix() {
    // The payload is already the statement, so repeating it would be noise.
    assert_eq!(
        bash("sudo whoami"),
        "deny: sudo whoami (matched Bash(sudo:*))"
    );
    assert_eq!(
        bash("git push origin main"),
        "ask: git push origin main (matched Bash(git push:*))"
    );
}

#[test]
fn allow_carries_no_clause() {
    // Nothing to explain, and the worked examples assert these verbatim.
    assert_eq!(bash("ls -la"), "allow: ls -la");
    assert_eq!(bash("ls; cat a"), "allow: ls; cat a");
    assert_eq!(
        reason("ask", "Read", json!({ "file_path": "/tmp/notes.txt" })),
        "allow: /tmp/notes.txt"
    );
}

#[test]
fn a_single_tool_call_is_attributed_the_same_way() {
    // A non-Bash call is a one-statement list, taking the same path.
    assert_eq!(
        reason("ask", "Read", json!({ "file_path": "/home/u/.ssh/id_rsa" })),
        "deny: /home/u/.ssh/id_rsa (matched Read(//**/.ssh/**))"
    );
    assert!(
        reason("deny", "Glob", json!({ "pattern": "src/**/*.rs" }))
            .contains("no rule matched, defaultMode=deny")
    );
}

#[test]
fn a_quoted_statement_is_bounded() {
    // The reason enters the model's context, so a 32KB payload must not produce a
    // 32KB reason.
    let long = "a".repeat(4_000);
    let cmd = format!("ls; sudo {long}");
    let why = bash(&cmd);
    assert_eq!(tier("ask", &cmd), Tier::Deny);
    assert!(why.contains('…'), "expected an ellipsis in: {why}");
    // The echoed payload predates this change; the clause must stay small.
    let clause = why.rsplit_once('(').expect("a clause").1;
    assert!(clause.len() < 200, "clause not bounded: {clause}");
}

#[test]
fn attribution_does_not_disturb_the_verdict() {
    // The clause reports, it does not decide.
    assert_eq!(tier("ask", "ls -la"), Tier::Allow);
    assert_eq!(tier("ask", "ls; sudo whoami"), Tier::Deny);
    assert_eq!(tier("ask", "git push origin main"), Tier::Ask);
    assert_eq!(tier("ask", "frobnicate"), Tier::Ask);
    assert_eq!(tier("deny", "frobnicate"), Tier::Deny);
}
