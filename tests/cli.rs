//! CLI-mode behavior of the `permcheck` binary (§2.2): exit codes, `--json`,
//! help, and process-CWD path absolutization.

use assert_cmd::Command;
use std::io::Write;

fn rules_file(json: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    write!(f, "{json}").unwrap();
    f
}

const RULES: &str =
    r#"{"allow":["Bash(ls:*)","Read"],"ask":["Bash(rm:*)"],"deny":["Bash(aws:*)"]}"#;

fn exit_code(args: &[&str], rules: &std::path::Path) -> i32 {
    let mut cmd = Command::cargo_bin("permcheck").unwrap();
    cmd.args(args).arg("--rules").arg(rules);
    cmd.assert().get_output().status.code().unwrap()
}

#[test]
fn exit_codes_map_to_tiers() {
    let f = rules_file(RULES);
    assert_eq!(exit_code(&["Bash", "ls -la"], f.path()), 0); // allow
    assert_eq!(exit_code(&["Bash", "rm foo"], f.path()), 1); // ask
    assert_eq!(exit_code(&["Bash", "aws s3 ls"], f.path()), 2); // deny
}

#[test]
fn json_mode_prints_decision_object_and_exits_zero() {
    let f = rules_file(RULES);
    Command::cargo_bin("permcheck")
        .unwrap()
        .args(["Bash", "aws s3 ls", "--json", "--rules"])
        .arg(f.path())
        .assert()
        .code(0) // --json always exits 0, even for deny
        .stdout(predicates::str::contains(r#""permissionDecision": "deny""#));
}

#[test]
fn help_and_no_args_exit_zero() {
    Command::cargo_bin("permcheck")
        .unwrap()
        .arg("--help")
        .assert()
        .code(0);
    Command::cargo_bin("permcheck").unwrap().assert().code(0); // no args -> help
}

#[test]
fn missing_tool_arg_is_config_error() {
    let f = rules_file(RULES);
    Command::cargo_bin("permcheck")
        .unwrap()
        .arg("--rules")
        .arg(f.path())
        .assert()
        .code(3);
}

#[test]
fn relative_path_absolutizes_against_process_cwd() {
    // `.env` is relative; it absolutizes against the process CWD and hits the
    // Read `.env` deny, while an unrelated absolute path stays allowed.
    let f = rules_file(r#"{"allow":["Read"],"deny":["Read(/**/.env*)"]}"#);
    assert_eq!(exit_code(&["Read", ".env"], f.path()), 2);
    assert_eq!(exit_code(&["Read", "/tmp/notes.txt"], f.path()), 0);
}
