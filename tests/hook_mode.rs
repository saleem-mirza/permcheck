//! Hook-mode behavior (§2.1, §9.1): decision JSON on stdout, **always exit 0**,
//! and fail-closed to `deny` on every error path.

use assert_cmd::Command;
use std::io::Write;
use std::path::Path;

fn rules_file(json: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    write!(f, "{json}").unwrap();
    f
}

const RULES: &str = r#"{"allow":["Bash(ls:*)","Read"],"deny":["Bash(aws:*)","Read(/**/.env*)"]}"#;

fn hook(rules: &Path, stdin: &str) -> assert_cmd::assert::Assert {
    Command::cargo_bin("permcheck")
        .unwrap()
        .arg("--hook")
        .arg("--rules")
        .arg(rules)
        .write_stdin(stdin)
        .assert()
}

#[test]
fn valid_event_emits_decision_and_exits_zero() {
    let f = rules_file(RULES);
    hook(
        f.path(),
        r#"{"tool_name":"Bash","tool_input":{"command":"aws s3 ls"},"cwd":"/repo"}"#,
    )
    .success()
    .stdout(predicates::str::contains(r#""hookEventName":"PreToolUse""#))
    .stdout(predicates::str::contains(r#""permissionDecision":"deny""#));
}

#[test]
fn unparseable_stdin_fails_closed() {
    let f = rules_file(RULES);
    hook(f.path(), "not json")
        .success()
        .stdout(predicates::str::contains(r#""permissionDecision":"deny""#));
}

#[test]
fn missing_tool_name_fails_closed() {
    let f = rules_file(RULES);
    hook(f.path(), r#"{"tool_input":{"command":"ls"}}"#)
        .success()
        .stdout(predicates::str::contains(r#""permissionDecision":"deny""#));
}

#[test]
fn missing_rules_arg_denies_but_exits_zero() {
    Command::cargo_bin("permcheck")
        .unwrap()
        .arg("--hook")
        .write_stdin(r#"{"tool_name":"Read","tool_input":{"file_path":"/x"}}"#)
        .assert()
        .success()
        .stdout(predicates::str::contains(r#""permissionDecision":"deny""#));
}

#[test]
fn cwd_absolutizes_relative_path_to_deny() {
    // `.env` is relative; the event `cwd` absolutizes it into the `.env` deny.
    let f = rules_file(RULES);
    hook(
        f.path(),
        r#"{"tool_name":"Read","tool_input":{"file_path":".env"},"cwd":"/home/user"}"#,
    )
    .success()
    .stdout(predicates::str::contains(r#""permissionDecision":"deny""#));
}

#[test]
fn empty_payload_tool_reports_tool_name_in_reason() {
    // A tool with no string payload: the reason uses the tool name, not a
    // trailing-space `allow: ` (§2.1).
    let f = rules_file(r#"{"allow":["TodoWrite"]}"#);
    hook(f.path(), r#"{"tool_name":"TodoWrite","tool_input":{}}"#)
        .success()
        .stdout(predicates::str::contains(
            r#""permissionDecisionReason":"allow: TodoWrite""#,
        ));
}

#[test]
fn unknown_mcp_tool_defaults_to_deny() {
    let f = rules_file(RULES);
    hook(
        f.path(),
        r#"{"tool_name":"mcp__db__query","tool_input":{"query":"SELECT 1"}}"#,
    )
    .success()
    .stdout(predicates::str::contains(r#""permissionDecision":"deny""#));
}

#[test]
fn extra_event_fields_are_tolerated() {
    // session_id / transcript_path / hook_event_name and friends are ignored.
    let f = rules_file(RULES);
    hook(
        f.path(),
        r#"{"session_id":"abc","transcript_path":"/t","hook_event_name":"PreToolUse",
            "tool_name":"Bash","tool_input":{"command":"ls -la"}}"#,
    )
    .success()
    .stdout(predicates::str::contains(r#""permissionDecision":"allow""#));
}
