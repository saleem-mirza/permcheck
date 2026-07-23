//! End-to-end behavior of `permcheck --install` / `--uninstall`: settings.json
//! injection/removal, idempotency, scope selection, and error posture.

use assert_cmd::Command;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const RULES: &str = r#"{"allow":["Bash(ls:*)","Read"],"deny":["Bash(aws:*)"]}"#;

fn rules_file(dir: &Path) -> PathBuf {
    let p = dir.join("permcheck.json");
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

/// The `command` string of the first permcheck PreToolUse hook, if present.
/// Windows-only: used to assert against the decoded command rather than raw JSON.
#[cfg(windows)]
fn permcheck_command(v: &serde_json::Value) -> Option<String> {
    v["hooks"]["PreToolUse"].as_array()?.iter().find_map(|g| {
        g["hooks"].as_array()?.iter().find_map(|h| {
            let c = h.get("command").and_then(|c| c.as_str())?;
            (c.contains("permcheck") && c.contains("--hook")).then(|| c.to_string())
        })
    })
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

    // The rules file is copied to the canonical location under .claude/, and the
    // hook references THAT path (not the user's source path).
    let dest = home.join(".claude").join("permcheck.json");
    assert!(dest.exists());
    assert_eq!(fs::read(&dest).unwrap(), fs::read(&rules).unwrap());
    #[cfg(not(windows))]
    {
        // POSIX paths have no backslashes, so the escaped-quote substring appears
        // verbatim in the raw JSON text.
        let s = fs::read_to_string(&settings).unwrap();
        assert!(s.contains(&format!("--rules \\\"{}\\\"", dest.display())));
    }
    #[cfg(windows)]
    {
        // The JSON escapes each path backslash (`\` -> `\\`), so scanning raw text
        // for the single-backslash path fails. Assert against the decoded command.
        let command = permcheck_command(&v).expect("permcheck hook command present");
        assert!(command.contains(&format!("--rules \"{}\"", dest.display())));
    }

    // Second install is a no-op: identical dest + wired hook → "already configured".
    let before = fs::read_to_string(&settings).unwrap();
    cmd(home, home)
        .args(["--install", "--rules"])
        .arg(&rules)
        .assert()
        .code(0)
        .stdout(predicates::str::contains("already configured"));
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
    // Project scope seeds ./.claude/permcheck.json.
    assert!(proj.path().join(".claude").join("permcheck.json").exists());

    cmd(home, proj.path())
        .args(["--install", "--local", "--rules"])
        .arg(&rules)
        .assert()
        .code(0);
    assert!(has_permcheck_hook(&read_json(
        &proj.path().join(".claude").join("settings.local.json")
    )));
    // Local scope uses the .local variant, distinct from the project file above.
    assert!(
        proj.path()
            .join(".claude")
            .join("permcheck.local.json")
            .exists()
    );
}

#[test]
fn install_without_rules_seeds_starter() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();

    cmd(home, home)
        .arg("--install")
        .assert()
        .code(0)
        .stdout(predicates::str::contains("starter"));

    // A starter rules file lands at the canonical location and the hook wires to it.
    let dest = home.join(".claude").join("permcheck.json");
    assert!(dest.exists());
    assert!(has_permcheck_hook(&read_json(
        &home.join(".claude").join("settings.json")
    )));

    // The seeded starter loads and enforces the canonical deny list.
    let event = r#"{"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /"}}"#;
    cmd(home, home)
        .args(["--hook", "--rules"])
        .arg(&dest)
        .write_stdin(event)
        .assert()
        .code(0)
        .stdout(predicates::str::contains(r#""permissionDecision":"deny""#));
}

#[test]
fn install_refuses_to_overwrite_differing_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let rules = rules_file(home);

    // First install copies the rules to the canonical dest.
    cmd(home, home)
        .args(["--install", "--rules"])
        .arg(&rules)
        .assert()
        .code(0);
    let dest = home.join(".claude").join("permcheck.json");
    let settings = home.join(".claude").join("settings.json");
    let dest_before = fs::read(&dest).unwrap();
    let settings_before = fs::read_to_string(&settings).unwrap();

    // Change the source and re-install: must refuse and touch nothing.
    let mut f = fs::File::create(&rules).unwrap();
    write!(f, r#"{{"allow":["Bash(ls:*)"]}}"#).unwrap();
    cmd(home, home)
        .args(["--install", "--rules"])
        .arg(&rules)
        .assert()
        .code(3)
        .stderr(predicates::str::contains("differs"));
    assert_eq!(dest_before, fs::read(&dest).unwrap());
    assert_eq!(settings_before, fs::read_to_string(&settings).unwrap());
}

#[test]
fn install_seed_reuses_existing_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let dest = home.join(".claude").join("permcheck.json");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    fs::write(&dest, RULES).unwrap();
    let before = fs::read(&dest).unwrap();

    // Auto-seed with an existing canonical file reuses it, never overwriting.
    cmd(home, home)
        .arg("--install")
        .assert()
        .code(0)
        .stdout(predicates::str::contains("Using existing rules"));
    assert_eq!(before, fs::read(&dest).unwrap());
    assert!(has_permcheck_hook(&read_json(
        &home.join(".claude").join("settings.json")
    )));
}

#[test]
fn install_rules_pointing_at_dest_is_safe() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let dest = home.join(".claude").join("permcheck.json");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    fs::write(&dest, RULES).unwrap();

    // Passing --rules pointing at the canonical file itself must not corrupt it.
    cmd(home, home)
        .args(["--install", "--rules"])
        .arg(&dest)
        .assert()
        .code(0);
    assert_eq!(fs::read_to_string(&dest).unwrap(), RULES);
    assert!(has_permcheck_hook(&read_json(
        &home.join(".claude").join("settings.json")
    )));
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

#[test]
fn install_refuses_to_repoint_noncanonical_hook() {
    // Simulate a legacy install whose hook points at a non-canonical rules path
    // (the pre-canonical-dest behavior). A bare `--install` must refuse rather
    // than silently re-point the hook and abandon that policy file.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let rules = rules_file(home);

    cmd(home, home)
        .args(["--install", "--rules"])
        .arg(&rules)
        .assert()
        .code(0);

    let settings = home.join(".claude").join("settings.json");
    let dest = home.join(".claude").join("permcheck.json");
    // Rewrite the baked command to reference a bogus, non-canonical path. Mutate
    // the parsed JSON (not the raw text) so this is independent of how the path is
    // escaped on the platform — on Windows the stored path is drive-lettered with
    // escaped backslashes, which a raw `dest.display()` replace would miss.
    let mut v = read_json(&settings);
    for group in v["hooks"]["PreToolUse"].as_array_mut().unwrap() {
        for h in group["hooks"].as_array_mut().unwrap() {
            let c = h["command"].as_str().unwrap();
            if c.contains("permcheck") && c.contains("--hook") {
                h["command"] =
                    serde_json::json!("permcheck --hook --rules \"/custom/policy.json\"");
            }
        }
    }
    let rewired = serde_json::to_string_pretty(&v).unwrap();
    fs::write(&settings, &rewired).unwrap();
    let dest_before = fs::read(&dest).unwrap();

    cmd(home, home)
        .arg("--install")
        .assert()
        .code(3)
        .stderr(predicates::str::contains("re-point"));

    // Nothing touched: the settings and canonical rules file are byte-identical.
    assert_eq!(rewired, fs::read_to_string(&settings).unwrap());
    assert_eq!(dest_before, fs::read(&dest).unwrap());
}

#[test]
fn install_rules_flag_without_value_errors() {
    // A dangling `--rules` (no path) is a usage error, not a request to seed.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();

    cmd(home, home)
        .args(["--install", "--rules"])
        .assert()
        .code(3)
        .stderr(predicates::str::contains("requires a path"));

    // No starter was seeded and no hook was wired.
    assert!(!home.join(".claude").join("permcheck.json").exists());
    assert!(!home.join(".claude").join("settings.json").exists());
}

#[test]
fn install_rules_does_not_swallow_flag() {
    // `--rules` followed by a flag must not treat the flag as the path; it is a
    // dangling `--rules` → clean usage error, not a "cannot load --user" failure.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();

    cmd(home, home)
        .args(["--install", "--rules", "--user"])
        .assert()
        .code(3)
        .stderr(predicates::str::contains("requires a path"));
}
