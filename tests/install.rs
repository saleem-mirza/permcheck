//! End-to-end behavior of `permcheck --install` / `--uninstall`: settings.json
//! injection/removal, idempotency, scope selection, and error posture.

use assert_cmd::Command;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const RULES: &str = r#"{"allow":["Bash(ls:*)","Read"],"deny":["Bash(aws:*)"]}"#;

fn rules_file(dir: &Path) -> PathBuf {
    let p = dir.join("permissions.json");
    let mut f = fs::File::create(&p).unwrap();
    write!(f, "{RULES}").unwrap();
    p
}

/// A `permcheck` invocation with `HOME`/`USERPROFILE` pinned to `home` and the
/// working directory set to `cwd`, so `--user` and `--project`/`--local` resolve
/// into the sandbox instead of the real machine.
fn cmd(home: &Path, cwd: &Path) -> Command {
    let mut c = Command::cargo_bin("permcheck").unwrap();
    c.env("HOME", home)
        .env("USERPROFILE", home) // native-Windows home
        .env_remove("HOMEDRIVE")
        .env_remove("HOMEPATH")
        .current_dir(cwd);
    c
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn has_permcheck_hook(v: &serde_json::Value) -> bool {
    v["hooks"]["PreToolUse"]
        .as_array()
        .map(|groups| {
            groups.iter().any(|g| {
                g["hooks"].as_array().is_some_and(|inner| {
                    inner.iter().any(|h| {
                        h.get("command")
                            .and_then(|c| c.as_str())
                            .is_some_and(|c| c.contains("permcheck") && c.contains("--hook"))
                    })
                })
            })
        })
        .unwrap_or(false)
}

#[test]
fn install_user_creates_settings_and_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let rules = rules_file(home);

    cmd(home, home)
        .args(["--install", "--rules"])
        .arg(&rules)
        .assert()
        .code(0);

    let settings = home.join(".claude").join("settings.json");
    assert!(settings.exists());
    let v = read_json(&settings);
    assert!(has_permcheck_hook(&v));
    // rules path baked in, absolute and double-quoted
    let s = fs::read_to_string(&settings).unwrap();
    assert!(s.contains(&format!("--rules \\\"{}\\\"", rules.display())));

    // Second install is a no-op: byte-identical file, "already up to date".
    let before = fs::read_to_string(&settings).unwrap();
    cmd(home, home)
        .args(["--install", "--rules"])
        .arg(&rules)
        .assert()
        .code(0)
        .stdout(predicates::str::contains("already up to date"));
    assert_eq!(before, fs::read_to_string(&settings).unwrap());
}

#[test]
fn install_project_and_local_scopes() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let proj = tempfile::tempdir().unwrap();
    let rules = rules_file(proj.path());

    cmd(home, proj.path())
        .args(["--install", "--project", "--rules"])
        .arg(&rules)
        .assert()
        .code(0);
    assert!(has_permcheck_hook(&read_json(
        &proj.path().join(".claude").join("settings.json")
    )));

    cmd(home, proj.path())
        .args(["--install", "--local", "--rules"])
        .arg(&rules)
        .assert()
        .code(0);
    assert!(has_permcheck_hook(&read_json(
        &proj.path().join(".claude").join("settings.local.json")
    )));
}

#[test]
fn install_without_rules_is_config_error() {
    let tmp = tempfile::tempdir().unwrap();
    cmd(tmp.path(), tmp.path())
        .arg("--install")
        .assert()
        .code(3)
        .stderr(predicates::str::contains("--rules"));
}

#[test]
fn install_with_bad_rules_is_config_error() {
    let tmp = tempfile::tempdir().unwrap();
    cmd(tmp.path(), tmp.path())
        .args(["--install", "--rules", "/does/not/exist.json"])
        .assert()
        .code(3);
}

#[test]
fn install_and_uninstall_preserve_unrelated_content() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let rules = rules_file(home);

    // Pre-existing settings with an unrelated key and a foreign PreToolUse hook.
    let claude = home.join(".claude");
    fs::create_dir_all(&claude).unwrap();
    let settings = claude.join("settings.json");
    fs::write(
        &settings,
        r#"{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-own-linter"}]}]}}"#,
    )
    .unwrap();

    cmd(home, home)
        .args(["--install", "--rules"])
        .arg(&rules)
        .assert()
        .code(0);
    let v = read_json(&settings);
    assert_eq!(v["model"], "opus");
    assert!(has_permcheck_hook(&v));
    assert!(
        fs::read_to_string(&settings)
            .unwrap()
            .contains("my-own-linter")
    );

    // Uninstall drops only the permcheck hook; the linter and model survive.
    cmd(home, home).arg("--uninstall").assert().code(0);
    let v = read_json(&settings);
    assert!(!has_permcheck_hook(&v));
    assert_eq!(v["model"], "opus");
    assert!(
        fs::read_to_string(&settings)
            .unwrap()
            .contains("my-own-linter")
    );
}

#[test]
fn uninstall_on_missing_file_is_noop_success() {
    let tmp = tempfile::tempdir().unwrap();
    cmd(tmp.path(), tmp.path())
        .arg("--uninstall")
        .assert()
        .code(0)
        .stdout(predicates::str::contains("nothing to uninstall"));
}

#[test]
fn install_and_uninstall_are_mutually_exclusive() {
    let tmp = tempfile::tempdir().unwrap();
    cmd(tmp.path(), tmp.path())
        .args(["--install", "--uninstall"])
        .assert()
        .code(3);
}

#[test]
fn installed_hook_command_actually_decides() {
    // The baked command should run permcheck in hook mode and produce a decision.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let rules = rules_file(home);

    cmd(home, home)
        .args(["--install", "--rules"])
        .arg(&rules)
        .assert()
        .code(0);

    // Drive `--hook` directly with the same rules the install baked in.
    let event = r#"{"tool_name":"Bash","tool_input":{"command":"aws s3 rm s3://x"}}"#;
    cmd(home, home)
        .args(["--hook", "--rules"])
        .arg(&rules)
        .write_stdin(event)
        .assert()
        .code(0)
        .stdout(predicates::str::contains(r#""permissionDecision":"deny""#));
}
