//! §10 worked examples, executed as CLI exit-code checks against the reference
//! rule set. This is the acceptance test for the whole engine.

use assert_cmd::Command;

const RULES: &str = "rules/permissions.json";

const ALLOW: i32 = 0;
const ASK: i32 = 1;
const DENY: i32 = 2;

fn check(tool: &str, payload: &str, expected: i32) {
    let assert = Command::cargo_bin("permcheck")
        .unwrap()
        .args([tool, payload, "--rules", RULES])
        .assert();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, expected,
        "{tool}({payload}): expected exit {expected}, got {code}"
    );
}

#[test]
fn worked_examples_table() {
    // The reference set denies `aws:*` / `kubectl:*` with no narrower allow, so
    // read-only forms are denied by the broad rule (not the ask fall-back).
    check("Bash", "aws ec2 describe-instances", DENY);
    check("Bash", "aws s3api list-buckets", DENY);
    check("Bash", "aws ec2 terminate-instances", DENY);
    check("Bash", "kubectl get pods", DENY);
    check("Bash", "kubectl delete pod x", DENY);
    check("Bash", "git push origin main", ASK);
    check("Bash", "git push --force origin", DENY);
    check("Bash", "cat .env", DENY);
    check("Read", "/tmp/notes.txt", ALLOW);
    check("WebFetch", "https://x.io", DENY);
    check("WebSearch", "anything", DENY);
    // Unmatched calls take the `defaultMode: "ask"` fall-back (§6.4).
    check("mcp__db__query", "SELECT 1", ASK);
    check("NotebookEdit", "/repo/nb.ipynb", ASK);
    check("Bash", "some-tool foo", ASK);
    check("Bash", r#"python3 -c "import os""#, ALLOW);
}

#[test]
fn rules_arg_accepts_equals_form() {
    // `--rules=<path>` is equivalent to `--rules <path>`.
    let assert = Command::cargo_bin("permcheck")
        .unwrap()
        .args([
            "Bash",
            "aws ec2 terminate-instances",
            &format!("--rules={RULES}"),
        ])
        .assert();
    assert_eq!(assert.get_output().status.code().unwrap(), DENY);
}

#[test]
fn hook_mode_emits_decision_json_and_exits_zero() {
    Command::cargo_bin("permcheck")
        .unwrap()
        .args(["--hook", "--rules", RULES])
        .write_stdin(
            r#"{"tool_name":"Bash","tool_input":{"command":"aws ec2 terminate-instances"},"cwd":"/tmp"}"#,
        )
        .assert()
        .success()
        .stdout(predicates::str::contains(r#""permissionDecision":"deny""#));
}

#[test]
fn hook_mode_fails_closed_on_bad_stdin() {
    Command::cargo_bin("permcheck")
        .unwrap()
        .args(["--hook", "--rules", RULES])
        .write_stdin("not json")
        .assert()
        .success()
        .stdout(predicates::str::contains(r#""permissionDecision":"deny""#));
}
