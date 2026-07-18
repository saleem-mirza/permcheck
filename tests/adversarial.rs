//! Adversarial / evasion tests driving the public engine API end to end.
//!
//! These lock the security posture: obfuscated or wrapped commands that reach a
//! denied file, compound-command hiding, and traversal paths must still resolve
//! to `deny`, while legitimate look-alikes must NOT be over-denied. A crafted
//! rule set (not the reference file) keeps the expectations self-contained.

use permcheck::{Tier, evaluate, load_rules_str};
use serde_json::json;

const RULES: &str = r#"{
  "allow": [
    "Bash(cat:*)", "Bash(ls:*)", "Bash(echo:*)", "Bash(grep:*)", "Bash(tee:*)",
    "Bash(python3 *)", "Bash(git push:*)",
    "Bash(sudo:*)", "Bash(env:*)", "Bash(timeout:*)", "Bash(nice:*)",
    "Read", "Write"
  ],
  "ask": ["Bash(rm:*)"],
  "deny": [
    "Read(/**/.env*)",
    "Read(//**/.ssh/**)",
    "Write(//**/.ssh/**)",
    "Edit(//**/.ssh/**)",
    "Bash(git push --force:*)",
    "Bash(curl:*)"
  ]
}"#;

const CWD: &str = "/home/user";

fn tier(tool: &str, input: serde_json::Value) -> Tier {
    let rs = load_rules_str(RULES).expect("crafted rules load");
    evaluate(&rs, tool, &input, Some(CWD)).tier
}
fn bash(cmd: &str) -> Tier {
    tier("Bash", json!({ "command": cmd }))
}
fn read(path: &str) -> Tier {
    tier("Read", json!({ "file_path": path }))
}
fn write(path: &str) -> Tier {
    tier("Write", json!({ "file_path": path }))
}

#[test]
fn bash_evasion_to_denied_file_is_denied() {
    // Every one of these reaches `.env` or an `.ssh` file and must deny, whether
    // via the file-access cross-check, wrapper peeling, or default-deny.
    let denied = [
        "cat .env",                                  // direct reader
        "cat /home/user/.env",                       // absolute
        "cat .env.local",                            // .env* glob
        "echo $(cat .env)",                          // command substitution
        "echo $(echo $(cat .env))",                  // nested substitution
        "echo `cat .env`",                           // backticks
        "echo <(cat .env)",                          // process substitution
        "FOO=bar cat .env",                          // env-assignment prefix
        "sudo cat .env",                             // wrapper peel
        "env cat .env",                              // wrapper peel
        "timeout 5 cat .env",                        // wrapper + numeric arg
        "nice -n 10 cat .env",                       // wrapper + option + numeric
        "cat < .env",                                // input redirection
        "grep secret .env",                          // pattern-first reader
        "tee /home/user/.ssh/authorized_keys",       // writer operand
        "echo hi > /home/user/.ssh/authorized_keys", // output redirection
        "ls && cat .env",                            // compound &&
        "ls; cat .env",                              // compound ;
        "ls | cat .env",                             // pipeline
        "ls\ncat .env",                              // newline
        "c\"\"at .env",                              // quote-obfuscated command
    ];
    for cmd in denied {
        assert_eq!(bash(cmd), Tier::Deny, "expected deny for: {cmd:?}");
    }
}

#[test]
fn specific_deny_beats_broad_allow() {
    assert_eq!(bash("git push --force origin main"), Tier::Deny);
    assert_eq!(bash("curl http://example.com"), Tier::Deny);
}

#[test]
fn legitimate_lookalikes_are_not_over_denied() {
    // Hardening must not block benign commands that merely resemble evasions.
    assert_eq!(bash("cat notes.txt"), Tier::Allow);
    // `.env` here is grep's PATTERN, not a file operand.
    assert_eq!(bash("grep .env notes.txt"), Tier::Allow);
    // Quoted text is an argument to echo, not an executed command.
    assert_eq!(bash("echo 'cat .env'"), Tier::Allow);
    // A pure fd dup is not a file write.
    assert_eq!(bash("echo hi 2>&1"), Tier::Allow);
    // Interpreter exec is allowed by `python3 *` (a documented rule-set gap).
    assert_eq!(bash(r#"python3 -c "import os""#), Tier::Allow);
    assert_eq!(bash("git push origin main"), Tier::Allow);
    assert_eq!(bash("rm scratch.txt"), Tier::Ask);
}

#[test]
fn path_traversal_and_forms_resolve_to_deny() {
    assert_eq!(read(".env"), Tier::Deny); // relative -> cwd-absolutized
    assert_eq!(read("../../.env"), Tier::Deny); // traversal segments
    assert_eq!(read("/home/user/.ssh/id_rsa"), Tier::Deny);
    assert_eq!(write("/home/user/.ssh/authorized_keys"), Tier::Deny);
}

#[test]
fn benign_paths_are_allowed() {
    assert_eq!(read("/tmp/notes.txt"), Tier::Allow);
    assert_eq!(write("/home/user/project/out.txt"), Tier::Allow);
}
