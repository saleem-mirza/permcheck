//! Bash file-access cross-check unit tests (§8.3).
//!
//! The cross-check only ever raises a unit to `deny`; these assert it catches
//! reads/writes to denied paths even when the base command is allowed.

use permcheck::bash::decide_bash;
use permcheck::rules::RuleSet;
use permcheck::types::Tier;

const RULES: &str = r#"{
  "allow": ["Bash(cat:*)", "Bash(ls:*)", "Bash(grep:*)", "Bash(tee:*)", "Bash(echo:*)"],
  "deny":  ["Read(/**/.env*)", "Write(/**/.ssh/**)", "Edit(/**/.ssh/**)"]
}"#;

fn rs() -> RuleSet {
    RuleSet::load_str(RULES).unwrap()
}

fn tier(cmd: &str) -> Tier {
    decide_bash(cmd, &rs(), Some("/home/user")).tier
}

#[test]
fn reader_operand_hits_read_deny() {
    assert_eq!(tier("cat .env"), Tier::Deny);
    assert_eq!(tier("cat /home/user/.env"), Tier::Deny);
    assert_eq!(tier("cat notes.txt"), Tier::Allow);
}

#[test]
fn pattern_first_reader_skips_first_operand() {
    // `.env` here is the file, `secret` is the pattern.
    assert_eq!(tier("grep secret .env"), Tier::Deny);
    // A pattern that merely looks like a path is not treated as a file.
    assert_eq!(tier("grep .env notes.txt"), Tier::Allow);
}

#[test]
fn redirect_write_hits_write_deny() {
    assert_eq!(
        tier("echo hi > /home/user/.ssh/authorized_keys"),
        Tier::Deny
    );
}

#[test]
fn wrapper_is_peeled() {
    assert_eq!(tier("sudo cat .env"), Tier::Deny);
}

#[test]
fn compound_is_most_restrictive() {
    assert_eq!(tier("ls && cat .env"), Tier::Deny);
    assert_eq!(tier("ls && cat notes.txt"), Tier::Allow);
}

#[test]
fn wrapper_cannot_launder_a_denied_command() {
    // `env` is allowed, but it executes its argument command, so a denied wrapped
    // command must still deny (§8.2). Legitimate wrapper use stays allowed.
    let rs = RuleSet::load_str(r#"{"allow":["Bash(env:*)","Bash(ls:*)"],"deny":["Bash(aws:*)"]}"#)
        .unwrap();
    let t = |c: &str| decide_bash(c, &rs, None).tier;
    assert_eq!(t("env aws s3 rm s3://b/k"), Tier::Deny);
    assert_eq!(t("env FOO=bar aws s3 rm s3://b/k"), Tier::Deny);
    assert_eq!(t("env -i aws s3 rm s3://b/k"), Tier::Deny);
    assert_eq!(t("env ls -la"), Tier::Allow); // benign wrapped command
    assert_eq!(t("env"), Tier::Allow); // bare wrapper, nothing wrapped
}

// --- dd if=/of= cross-check (A1) ---------------------------------------------

fn dd_rs() -> RuleSet {
    RuleSet::load_str(
        r#"{
          "allow": ["Bash(dd:*)"],
          "deny":  ["Read(/**/.env*)", "Write(/**/.ssh/**)"]
        }"#,
    )
    .unwrap()
}

#[test]
fn dd_input_file_hits_read_deny() {
    let t = |c: &str| decide_bash(c, &dd_rs(), Some("/home/user")).tier;
    // `if=` names a file dd reads; `of=` a file it writes — both cross-checked.
    assert_eq!(t("dd if=/home/user/.env of=/tmp/x"), Tier::Deny);
    assert_eq!(
        t("dd if=/tmp/x of=/home/user/.ssh/authorized_keys"),
        Tier::Deny
    );
    // Benign copy stays allowed.
    assert_eq!(t("dd if=/tmp/a of=/tmp/b"), Tier::Allow);
    // Bare `dd` with no file operands is fine.
    assert_eq!(t("dd"), Tier::Allow);
}

// --- pattern-first reader option handling (A2) -------------------------------

fn grep_rs() -> RuleSet {
    RuleSet::load_str(
        r#"{
          "allow": ["Bash(grep:*)", "Bash(awk:*)"],
          "deny":  ["Read(/**/.env*)"]
        }"#,
    )
    .unwrap()
}

#[test]
fn attached_short_option_does_not_eat_the_file() {
    let t = |c: &str| decide_bash(c, &grep_rs(), Some("/home/user")).tier;
    // Pattern supplied via -e (attached), so `.env` is a file, not the pattern.
    assert_eq!(t("grep -efoo .env"), Tier::Deny);
    // Space-separated -e form too.
    assert_eq!(t("grep -e foo .env"), Tier::Deny);
}

#[test]
fn pattern_file_option_is_read_checked() {
    let t = |c: &str| decide_bash(c, &grep_rs(), Some("/home/user")).tier;
    // `-f <file>` / `-f<file>` / `--file=<file>` name a file grep reads.
    assert_eq!(t("grep -f /home/user/.env input.txt"), Tier::Deny);
    assert_eq!(t("grep -f/home/user/.env input.txt"), Tier::Deny);
    assert_eq!(t("grep --file=/home/user/.env input.txt"), Tier::Deny);
    // awk -f (program file) likewise.
    assert_eq!(t("awk -f /home/user/.env"), Tier::Deny);
}

#[test]
fn double_dash_ends_options() {
    let t = |c: &str| decide_bash(c, &grep_rs(), Some("/home/user")).tier;
    // After `--`, the pattern is the first operand and `.env` the file.
    assert_eq!(t("grep -- -pat .env"), Tier::Deny);
}
