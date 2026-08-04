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

#[test]
fn a_payload_that_looks_like_a_mode_flag_never_changes_mode() {
    // Mode selection reads only the flags before the first positional (§2.2).
    // It used to scan the whole argument vector, so checking the literal command
    // string `--install` performed a real install: wiring the PreToolUse hook and
    // seeding a policy file under the user's home, while the caller believed it
    // was checking a payload. The CLI exists to check hostile strings, so this
    // must never reach a state-changing path.
    //
    // Asserting on the exit code alone would be weak, so each case also asserts
    // that nothing was written where an install or a seed would land.
    let f = rules_file(RULES);
    let home = tempfile::tempdir().unwrap();

    for payload in ["--install", "--uninstall", "--init-rules", "--hook"] {
        let assertion = Command::cargo_bin("permcheck")
            .unwrap()
            .args(["Bash", payload, "--rules"])
            .arg(f.path())
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .current_dir(home.path())
            .assert();
        // An unrecognized option is a usage error, never a mode switch.
        assertion.code(3);
        assert!(
            !home.path().join(".claude").exists(),
            "{payload:?} as a payload must not write settings or a policy file"
        );
        assert!(
            !home.path().join("permcheck.json").exists(),
            "{payload:?} as a payload must not seed a rules file"
        );
    }
}

#[test]
fn a_double_dash_ends_option_parsing_so_any_payload_is_checkable() {
    // With `--`, a payload that starts with dashes is checked as a payload
    // instead of being rejected as an unknown option, so an operator testing a
    // hostile string is not stuck. Options come before `--`, as everywhere else.
    let f = rules_file(RULES);
    let check = |payload: &str| {
        Command::cargo_bin("permcheck")
            .unwrap()
            .arg("Bash")
            .arg("--rules")
            .arg(f.path())
            .arg("--")
            .arg(payload)
            .assert()
            .get_output()
            .status
            .code()
            .unwrap()
    };
    // Unlisted commands, mode-flag-shaped or not, take the deny fall-back.
    assert_eq!(check("--install"), 2);
    assert_eq!(check("--hook"), 2);
    assert_eq!(check("-V"), 2);
    // And the ordinary verdicts still come through unchanged.
    assert_eq!(check("ls -la"), 0);
    assert_eq!(check("rm foo"), 1);
    assert_eq!(check("aws s3 ls"), 2);
}

#[test]
fn mode_flags_are_still_recognized_in_every_leading_position() {
    // Narrowing where a mode flag counts must not break the real invocations:
    // a mode flag anywhere among the leading options is still a mode flag.
    let f = rules_file(RULES);
    for args in [
        vec!["--version"],
        vec!["-V"],
        vec!["--rules", "IGNORED", "--version"],
    ] {
        let mut cmd = Command::cargo_bin("permcheck").unwrap();
        for arg in &args {
            if *arg == "IGNORED" {
                cmd.arg(f.path());
            } else {
                cmd.arg(arg);
            }
        }
        cmd.assert()
            .success()
            .stdout(predicates::str::starts_with("permcheck "));
    }
    // `--hook` after `--rules <path>` still enters hook mode: the value of a
    // value-taking flag is not the first positional.
    Command::cargo_bin("permcheck")
        .unwrap()
        .arg("--rules")
        .arg(f.path())
        .arg("--hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"aws s3 ls"}}"#)
        .assert()
        .success()
        .stdout(predicates::str::contains(r#""permissionDecision":"deny""#));
}
