//! §3–§4 load-error handling: bad rule files fail closed.

use assert_cmd::Command;
use permcheck::{RuleLoadError, load_rules_str};
use std::io::Write;

#[test]
fn library_surfaces_typed_load_errors() {
    assert!(matches!(
        load_rules_str("nope"),
        Err(RuleLoadError::Json(_))
    ));
    assert!(matches!(
        load_rules_str("[]"),
        Err(RuleLoadError::NotObject)
    ));
    assert!(matches!(
        load_rules_str("{}"),
        Err(RuleLoadError::NoPermissions)
    ));
    assert!(matches!(
        load_rules_str(r#"{"deny":["Bash()"]}"#),
        Err(RuleLoadError::EmptySpecifier(_))
    ));
    assert!(matches!(
        load_rules_str(r#"{"deny":[123]}"#),
        Err(RuleLoadError::RuleNotString)
    ));
}

#[test]
fn cli_returns_exit_3_on_bad_rules_file() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    write!(f, "this is not json").unwrap();
    Command::cargo_bin("permcheck")
        .unwrap()
        .args(["Read", "/tmp/x", "--rules"])
        .arg(f.path())
        .assert()
        .code(3);
}

#[test]
fn cli_returns_exit_3_when_rules_missing() {
    Command::cargo_bin("permcheck")
        .unwrap()
        .args(["Read", "/tmp/x"])
        .assert()
        .code(3);
}

#[test]
fn hook_fails_closed_to_deny_on_bad_rules_file() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    write!(f, "not json").unwrap();
    Command::cargo_bin("permcheck")
        .unwrap()
        .arg("--hook")
        .arg("--rules")
        .arg(f.path())
        .write_stdin(r#"{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}"#)
        .assert()
        .success()
        .stdout(predicates::str::contains(r#""permissionDecision":"deny""#));
}
