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
fn explicit_help_goes_to_stdout_and_succeeds() {
    // Help is requested output, so it belongs on stdout.
    for flag in ["--help", "-h"] {
        Command::cargo_bin("permcheck")
            .unwrap()
            .arg(flag)
            .assert()
            .code(0)
            .stdout(predicates::str::contains("USAGE"));
    }
}

#[test]
fn no_args_is_a_usage_error() {
    // Exiting 0 here would read as an `allow` to anything checking exit codes.
    Command::cargo_bin("permcheck")
        .unwrap()
        .assert()
        .code(3)
        .stderr(predicates::str::contains("USAGE"));
}

#[test]
fn unknown_long_flag_is_a_usage_error() {
    // `--jsn` used to fall through to exit-code mode with no diagnostic.
    let f = rules_file(RULES);
    Command::cargo_bin("permcheck")
        .unwrap()
        .args(["Bash", "ls", "--rules"])
        .arg(f.path())
        .arg("--jsn")
        .assert()
        .code(3)
        .stderr(predicates::str::contains("unrecognized option `--jsn`"));
}

#[test]
fn version_flag_prints_version_and_exits_zero() {
    let expected = format!("permcheck {}\n", env!("CARGO_PKG_VERSION"));
    for flag in ["--version", "-V"] {
        Command::cargo_bin("permcheck")
            .unwrap()
            .arg(flag)
            .assert()
            .code(0)
            .stdout(expected.clone());
    }
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
fn dead_rule_prints_a_lint_warning_to_stderr() {
    // A `cmd:*` specifier with an interior `*` is inert; the checker warns on
    // stderr (never stdout) so the operator catches it before shipping.
    let f = rules_file(r#"{"deny":["Bash(aws * --region east:*)"]}"#);
    Command::cargo_bin("permcheck")
        .unwrap()
        .args(["Bash", "ls", "--rules"])
        .arg(f.path())
        .assert()
        .stderr(predicates::str::contains("matches nothing"));
}

#[test]
fn clean_rules_emit_no_lint_warning() {
    let f = rules_file(RULES);
    Command::cargo_bin("permcheck")
        .unwrap()
        .args(["Bash", "ls -la", "--rules"])
        .arg(f.path())
        .assert()
        .stderr(predicates::str::is_empty());
}

#[test]
fn relative_path_absolutizes_against_process_cwd() {
    // `.env` is relative; it absolutizes against the process CWD and hits the
    // Read `.env` deny, while an unrelated absolute path stays allowed. This
    // holds cross-platform: a Windows drive-letter CWD (e.g. `D:\proj`) is
    // normalized to a POSIX-anchored form (`/D:/proj`) before Path matching.
    let f = rules_file(r#"{"allow":["Read"],"deny":["Read(/**/.env*)"]}"#);
    assert_eq!(exit_code(&["Read", ".env"], f.path()), 2);
    assert_eq!(exit_code(&["Read", "/tmp/notes.txt"], f.path()), 0);
}
