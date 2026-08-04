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
    "Read(/etc/**)",
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
        "timeout 5s cat .env",                       // wrapper + duration-suffix arg
        "timeout 1.5h cat .env",                     // wrapper + fractional duration
        "nice -n 10 cat .env",                       // wrapper + option + numeric
        "cat < .env",                                // input redirection
        "cat .\\env",                                // backslash escape -> .env
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
    // Extra interior whitespace must not evade a prefix deny.
    assert_eq!(bash("git  push --force origin main"), Tier::Deny);
    assert_eq!(bash("git   push   --force"), Tier::Deny);
    assert_eq!(bash("curl http://example.com"), Tier::Deny);
}

#[test]
fn identity_normalizations_compose() {
    // §8 step 2: each stage runs on the previous stage's output, so a command
    // wearing several disguises still reduces to the spelling the deny names.
    // Isolated on a crafted rule set: only `Bash(git push --force:*)` and
    // `Bash(curl:*)` deny here, so a hit proves the pipeline reached the rule.
    let denied = [
        "git push --force",                      // no disguise, the baseline
        "/usr/bin/git push --force",             // basename alone
        "git  push --force",                     // whitespace alone
        r#"git push "--force""#,                 // quoting alone
        "/usr/bin/git  push --force",            // basename + whitespace
        r#"/usr/bin/git push "--force""#,        // basename + quoting
        r#"git  push "--force""#,                // whitespace + quoting
        r#"/usr/bin/git  push "--force""#,       // all three
        r#""/usr/bin/git"  push '--force'"#,     // all three, binary quoted too
        r"\git push --force",                    // escape instead of quotes
        r#"/usr/bin/cu"rl" http://example.com"#, // basename + split name
    ];
    for cmd in denied {
        assert_eq!(bash(cmd), Tier::Deny, "expected deny for: {cmd:?}");
    }
}

#[test]
fn quoted_wrapper_is_still_peeled() {
    // `sudo`/`env` are broadly allowed here, so laundering only fails if the
    // wrapper is recognized through its disguise and the wrapped command is
    // decided on its own. `curl` is the denied payload.
    let denied = [
        "env curl http://example.com",
        r#""env" curl http://example.com"#,
        r#"en"v" curl http://example.com"#,
        r"\env curl http://example.com",
        r#""sudo" "env" curl http://example.com"#,
        r#""/usr/bin/env" curl http://example.com"#,
        r#""FOO=bar" env curl http://example.com"#,
        r#""timeout" 5 curl http://example.com"#,
    ];
    for cmd in denied {
        assert_eq!(bash(cmd), Tier::Deny, "expected deny for: {cmd:?}");
    }
}

#[test]
fn quoted_flags_reach_the_escalation_forms() {
    // The clustered-short-flag and interpreter candidates read the canonical
    // spelling, so quoting a flag no longer takes it out of their reach. `rm` is
    // ask-tier here and `python3 *` is allowed, so these assert the canonical
    // form is what gets built, not that a deny fires.
    assert_eq!(bash(r#"rm "-rf" scratch"#), Tier::Ask);
    assert_eq!(bash(r#"python3 "-c" "import os""#), Tier::Allow);
}

#[test]
fn quoting_strip_stays_anchored_at_the_command_word() {
    // Stripping quotes merges quoted text into the matched string. Matching is
    // anchored (§6.5), so denied text sitting inside an argument must not turn a
    // benign command into a deny.
    assert_eq!(bash(r#"echo "git push --force""#), Tier::Allow);
    assert_eq!(bash(r#"echo "curl http://example.com""#), Tier::Allow);
    assert_eq!(bash(r#"grep "curl" access.log"#), Tier::Allow);
    // A quoted argument that is a denied *path* is still caught, because the
    // cross-check tokenizes and reads operands regardless of quoting (§8.3).
    assert_eq!(bash(r#"cat ".env""#), Tier::Deny);
}

#[test]
fn legitimate_lookalikes_are_not_over_denied() {
    // Hardening must not block benign commands that merely resemble evasions.
    assert_eq!(bash("cat notes.txt"), Tier::Allow);
    // `.env` here is grep's PATTERN, not a file operand.
    assert_eq!(bash("grep .env notes.txt"), Tier::Allow);
    // Quoted text is an argument to echo, not an executed command.
    assert_eq!(bash("echo 'cat .env'"), Tier::Allow);
    // Whitespace collapse must not over-deny: a benign command with runs of
    // spaces stays allowed when no deny prefix covers it.
    assert_eq!(bash("echo 'a  b'"), Tier::Allow);
    assert_eq!(bash("git  push origin main"), Tier::Allow);
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
fn parent_traversal_evades_directory_anchored_deny() {
    // A `..` segment routes an absolute path out of and back into a denied
    // directory. `path_candidates` collapses `.`/`..` lexically, so
    // `/tmp/../etc/shadow` resolves to `/etc/shadow` and hits `Read(/etc/**)`.
    // Filename-anchored denies (`.env*`) are immune anyway because `**` catches
    // any suffix; directory-prefix denies rely on this collapse.
    assert_eq!(read("/tmp/../etc/shadow"), Tier::Deny);
    assert_eq!(bash("cat /tmp/../etc/shadow"), Tier::Deny);
}

#[test]
fn benign_paths_are_allowed() {
    assert_eq!(read("/tmp/notes.txt"), Tier::Allow);
    assert_eq!(write("/home/user/project/out.txt"), Tier::Allow);
}

// The `aws * describe-*` carve-out must admit only genuine read-only calls. Two
// bypasses used to promote a mutating `aws` call to allow: (1) an interior `*`
// that spanned whitespace let a later `describe-` substring satisfy the allow
// while the executed operation stayed destructive; (2) a trailing `# describe-…`
// comment fed the allow glob but bash discarded it at runtime. The single-token
// service slot closes (1); comment stripping closes (2).
#[test]
fn describe_carveout_admits_only_read_only_calls() {
    const CARVEOUT: &str = r#"{
      "allow": ["Bash(aws * describe-*)"],
      "deny": ["Bash(aws:*)"]
    }"#;
    let rs = load_rules_str(CARVEOUT).expect("carve-out rules load");
    let d = |cmd: &str| evaluate(&rs, "Bash", &json!({ "command": cmd }), Some(CWD)).tier;

    // Genuine read-only calls across any single-token service still carve out.
    assert_eq!(d("aws ec2 describe-instances"), Tier::Allow);
    assert_eq!(d("aws rds describe-db-instances"), Tier::Allow);
    assert_eq!(d("aws ec2 describe-instances --output json"), Tier::Allow);

    // Mutating calls stay denied through every injection shape.
    assert_eq!(d("aws ec2 terminate-instances"), Tier::Deny);
    assert_eq!(
        d("aws s3 rm s3://prod-bucket/describe-report.json"),
        Tier::Deny
    );
    assert_eq!(d("aws iam delete-user --user-name describe-me"), Tier::Deny);
    assert_eq!(
        d("aws ec2 terminate-instances # describe-instances"),
        Tier::Deny
    );
    assert_eq!(
        d("aws iam delete-user --user-name x # describe-me"),
        Tier::Deny
    );
}
