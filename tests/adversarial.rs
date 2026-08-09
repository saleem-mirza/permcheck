//! Adversarial / evasion tests driving the public engine API end to end. Wrapped
//! or obfuscated commands reaching a denied file must resolve to `deny`, and
//! look-alikes must not over-deny. A crafted rule set keeps these self-contained.

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
    // §8 step 2: each stage runs on the previous stage's output, so several
    // disguises still reduce to the spelling the deny names. Only two rules deny
    // here, so a hit proves the pipeline reached the rule.
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
fn reserved_word_prefix_is_still_peeled() {
    // Shell reserved words that introduce a command. `curl` is the denied payload
    // and every other word is allowed, so a deny proves the word was peeled.
    let denied = [
        "{ curl http://example.com; }",
        "! curl http://example.com",
        "time curl http://example.com",
        "time -p curl http://example.com",
        "if curl http://example.com; then echo y; fi",
        "while true; do curl http://example.com; done",
        "until curl http://example.com; do echo y; done",
        "{ FOO=bar curl http://example.com; }",
        "! time sudo curl http://example.com", // reserved words and wrappers interleave
        // Quoting strips a word's reserved meaning in the shell, so bash would run
        // a command named `{` here. Peeling only raises a verdict, so reading it
        // as a group opener over-denies rather than letting `curl` through.
        r#"'{' curl http://example.com"#,
    ];
    for cmd in denied {
        assert_eq!(bash(cmd), Tier::Deny, "expected deny for: {cmd:?}");
    }
    // The file-access cross-check peels the same words: `cat` is allowed, `.env`
    // is a denied Read.
    assert_eq!(bash("{ cat .env; }"), Tier::Deny);
    assert_eq!(bash("if true; then cat .env; fi"), Tier::Deny);
}

#[test]
fn reserved_words_do_not_over_deny_ordinary_commands() {
    // A reserved word is peeled only in command position; anywhere else it is an
    // ordinary operand and the command keeps its own verdict.
    assert_eq!(bash("echo if then do while"), Tier::Allow);
    assert_eq!(bash("grep -n while src/main.rs"), Tier::Allow);
    assert_eq!(bash("cat do"), Tier::Allow);
    // Peeling raises and never lowers, so a wrapped `ask` stays an ask rather
    // than inheriting the inner command's allow.
    assert_eq!(bash("sudo rm notes.txt"), Tier::Ask);

    // This rule set names no rule for `time` or `!`, so a unit led by one denies
    // under §6.4 either way. The shipped ask-default policy is where a benign
    // `time ls` is observable, so `reference_evasion.rs` asserts that.
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
    // The flag and interpreter candidates read the canonical spelling, so quoting
    // a flag no longer puts it out of reach. These assert the canonical form is
    // built, not that a deny fires.
    assert_eq!(bash(r#"rm "-rf" scratch"#), Tier::Ask);
    assert_eq!(bash(r#"python3 "-c" "import os""#), Tier::Allow);
}

#[test]
fn single_flag_escalation_preserves_operands() {
    let rs = load_rules_str(r#"{"allow":["Bash(rm:*)"],"deny":["Bash(rm -f /:*)"]}"#).unwrap();
    for cmd in ["rm -rf /", "rm -fr /", "rm -r -f /"] {
        assert_eq!(
            evaluate(&rs, "Bash", &json!({"command": cmd}), Some(CWD)).tier,
            Tier::Deny,
            "operand-bearing flag form should deny: {cmd}"
        );
    }
    // No `-f` means no escalation to the force rule.
    assert_eq!(
        evaluate(&rs, "Bash", &json!({"command": "rm -r /"}), Some(CWD)).tier,
        Tier::Allow
    );
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
    // A `..` routes an absolute path back into a denied directory.
    // `path_candidates` collapses it lexically, so `/tmp/../etc/shadow` hits
    // `Read(/etc/**)`. Directory-prefix denies rely on this collapse.
    assert_eq!(read("/tmp/../etc/shadow"), Tier::Deny);
    assert_eq!(bash("cat /tmp/../etc/shadow"), Tier::Deny);
}

// A `..` spelling used to ride a narrow allow out of the directory it names, the
// raw text matching the allow that carved the deny away. The path-operand form is
// decided on its own, so the allow cannot carve it out (claude-code#79756).
#[test]
fn traversal_cannot_ride_a_narrow_allow_out_of_its_directory() {
    const SCRATCH: &str = r#"{
      "defaultMode": "ask",
      "allow": ["Bash(rm -rf /w/.scratch/*)", "Bash(rm -rf .scratch/*)"],
      "deny": ["Bash(rm -rf /*)"]
    }"#;
    let rs = load_rules_str(SCRATCH).expect("scratch rules load");
    let d = |cmd: &str| evaluate(&rs, "Bash", &json!({ "command": cmd }), Some("/w")).tier;

    // The carve-out still does its job: these are the calls the policy exists to
    // permit, and over-denying them would defeat the whole point.
    assert_eq!(d("rm -rf /w/.scratch/checks.log"), Tier::Allow);
    assert_eq!(d("rm -rf .scratch/checks.log"), Tier::Allow);

    // Every spelling whose real target leaves the scratch directory resolves onto
    // the deny, absolute and relative alike.
    assert_eq!(d("rm -rf /w/.scratch/../src"), Tier::Deny);
    assert_eq!(d("rm -rf /w/.scratch/../../etc"), Tier::Deny);
    assert_eq!(d("rm -rf .scratch/../src"), Tier::Deny);
    assert_eq!(d("rm -rf ./.scratch/../src"), Tier::Deny);
    assert_eq!(d("rm -rf /w/./.scratch/../src"), Tier::Deny);
    // And the plain spelling of the same target was never in doubt.
    assert_eq!(d("rm -rf /w/src"), Tier::Deny);
}

// A Bash specifier matches command text, so `Bash(rm -rf .scratch/*)` used to
// grant deletion of every `.scratch` on the machine. Absolutizing against the
// call's cwd allows it inside the project and denies it outside.
#[test]
fn a_relative_allow_grants_only_inside_the_directory_it_names() {
    const SCRATCH: &str = r#"{
      "defaultMode": "ask",
      "allow": ["Bash(rm -rf /w/.scratch/*)", "Bash(rm -rf .scratch/*)"],
      "deny": ["Bash(rm -rf /*)"]
    }"#;
    let rs = load_rules_str(SCRATCH).expect("scratch rules load");
    let at =
        |cwd: &str, cmd: &str| evaluate(&rs, "Bash", &json!({ "command": cmd }), Some(cwd)).tier;

    // Inside the project the relative rule means what its author meant.
    assert_eq!(at("/w", "rm -rf .scratch/x"), Tier::Allow);
    // Anywhere else the same text names a different directory, and the deny on
    // the tree catches it.
    for cwd in ["/tmp", "/etc", "/", "/home/other"] {
        assert_eq!(
            at(cwd, "rm -rf .scratch/x"),
            Tier::Deny,
            "relative allow must not reach {cwd}"
        );
    }
    // The absolute spelling names one directory and works from anywhere.
    assert_eq!(at("/tmp", "rm -rf /w/.scratch/x"), Tier::Allow);
}

// The path-operand form raises only on a real rule match, so an ordinary command
// carrying a `.` or `..` keeps whatever verdict it already had. This is the fence
// that stops the traversal fix from turning into a blanket over-deny.
#[test]
fn dot_segments_in_benign_commands_are_not_over_denied() {
    assert_eq!(bash("cat ./notes.txt"), Tier::Allow);
    assert_eq!(bash("cat ../project/notes.txt"), Tier::Allow);
    assert_eq!(bash("ls ./src/.."), Tier::Allow);
    assert_eq!(bash("echo ../README.md"), Tier::Allow);
    // A lone `.` collapses to itself, so no extra form is produced at all.
    assert_eq!(bash("ls ."), Tier::Allow);
}

// A `~user` operand names a home the engine cannot learn, so it stays literal
// rather than joining onto the cwd (§7.2). Joining would invent
// `/w/~alice/notes.txt` and deny a command the Path family leaves at ask.
#[test]
fn a_tilde_user_operand_is_not_joined_onto_the_cwd() {
    let rs = load_rules_str(r#"{"defaultMode":"ask","deny":["Bash(cat /w/*)"]}"#).unwrap();
    let d = |cmd: &str| evaluate(&rs, "Bash", &json!({ "command": cmd }), Some("/w")).tier;

    assert_eq!(d("cat ~alice/notes.txt"), Tier::Ask);
    // The join itself still works: a relative operand lands under the cwd.
    assert_eq!(d("cat sub/notes.txt"), Tier::Deny);
}

// The resolved form must reach a Bash rule without the cross-check, which only
// covers its reader/writer tables. `curl` is denied as a Bash rule and is not a
// reader, so the path form alone catches a traversal spelling.
#[test]
fn traversal_reaches_a_bash_rule_without_the_cross_check() {
    assert_eq!(bash("/usr/bin/../bin/curl https://x.example"), Tier::Deny);
}

#[test]
fn benign_paths_are_allowed() {
    assert_eq!(read("/tmp/notes.txt"), Tier::Allow);
    assert_eq!(write("/home/user/project/out.txt"), Tier::Allow);
}

// The `aws * describe-*` carve-out must admit only read-only calls. Two bypasses
// promoted a mutating call to allow: an interior `*` spanning whitespace, and a
// trailing `# describe-…` comment bash discards. Slot and comment stripping close both.
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

// A quoted spaced executable path is one word only because of the quotes, so
// stripping them first left the basename `Program` and a rule naming the real
// binary matched nothing (claude-code#27688). Both readings must stay available.
#[test]
fn a_quoted_command_path_with_spaces_reaches_both_its_spellings() {
    const P: &str = r#"{
      "defaultMode": "ask",
      "allow": ["Bash", "Bash(clang.exe:*)"],
      "deny": ["Bash(/opt/my tool/bin/danger:*)"]
    }"#;
    let rs = load_rules_str(P).expect("rules load");
    let d = |cmd: &str| evaluate(&rs, "Bash", &json!({ "command": cmd }), Some(CWD)).tier;

    // The basename reading: the rule names the binary, not the path.
    assert_eq!(
        d(r#""C:/Program Files/LLVM/bin/clang.exe" -c x.c"#),
        Tier::Allow
    );
    assert_eq!(d(r#"'/opt/my tool/bin/clang.exe' -c x.c"#), Tier::Allow);

    // The full-path reading: a deny naming the spaced path holds through quoting.
    assert_eq!(d(r#""/opt/my tool/bin/danger" --now"#), Tier::Deny);
    assert_eq!(d(r#"'/opt/my tool/bin/danger' --now"#), Tier::Deny);
    assert_eq!(d("/opt/my tool/bin/danger --now"), Tier::Deny);
}

// Residual, locked deliberately: the pipeline still produces the mangled reading,
// so a rule naming the path's first segment matches an unrelated command. Removing
// it needs quote-awareness inside the chain, a larger change.
#[test]
fn a_spaced_path_still_also_reads_as_its_first_segment() {
    let rs = load_rules_str(r#"{"defaultMode":"ask","allow":["Bash(Program:*)"]}"#).unwrap();
    let d = |cmd: &str| evaluate(&rs, "Bash", &json!({ "command": cmd }), Some(CWD)).tier;
    assert_eq!(
        d(r#""C:/Program Files/LLVM/bin/clang.exe" -c x.c"#),
        Tier::Allow
    );
}

// Quote-stripping a spaced path was a deny-bypass: `"/tmp/git evil/bin/rm" -rf x`
// mangled to `git evil/bin/rm -rf x` and satisfied `Bash(git:*)` while the real
// executable was `rm`. The basename form now also produces `rm -rf x`.
#[test]
fn a_quoted_path_cannot_launder_a_denied_binary_through_an_allowed_name() {
    let rs =
        load_rules_str(r#"{"defaultMode":"ask","allow":["Bash(git:*)"],"deny":["Bash(rm:*)"]}"#)
            .unwrap();
    let d = |cmd: &str| evaluate(&rs, "Bash", &json!({ "command": cmd }), Some(CWD)).tier;

    assert_eq!(d("rm -rf /tmp/data"), Tier::Deny, "baseline");
    assert_eq!(d(r#""/tmp/git evil/bin/rm" -rf /tmp/data"#), Tier::Deny);
    assert_eq!(d(r#""/tmp/git x/rm" -rf /tmp/data"#), Tier::Deny);
    assert_eq!(d(r#"'/tmp/git evil/bin/rm' -rf /tmp/data"#), Tier::Deny);
    // The allow it tried to ride still works for real git.
    assert_eq!(d("git status"), Tier::Allow);
}

// ANSI-C quoting is still one shell word. It bypassed the parsed-basename form,
// which only recognized a literal quote in byte zero, inventing the allowed
// basename `my` while the real executable was `rm`.
#[test]
fn ansi_c_quoted_path_cannot_launder_a_denied_binary() {
    let rs =
        load_rules_str(r#"{"defaultMode":"ask","allow":["Bash(my:*)"],"deny":["Bash(rm:*)"]}"#)
            .unwrap();
    let d = |cmd: &str| evaluate(&rs, "Bash", &json!({ "command": cmd }), Some(CWD)).tier;

    assert_eq!(d(r#"$'/tmp/my tool/bin/rm' -rf x"#), Tier::Deny);
}

// A backslash inside single quotes is a literal POSIX filename character, not a
// separator. Treating it as `/` invented the allowed basename `git` and hid the
// actual basename `bin\git` from its deny.
#[cfg(not(windows))]
#[test]
fn posix_quoted_backslash_does_not_invent_a_basename() {
    let rs = load_rules_str(
        r#"{"defaultMode":"ask","allow":["Bash(git:*)"],"deny":["Bash(bin\\git:*)"]}"#,
    )
    .unwrap();
    let d = |cmd: &str| evaluate(&rs, "Bash", &json!({ "command": cmd }), Some(CWD)).tier;

    assert_eq!(d(r#"'/tmp/foo evil/bin\git' status"#), Tier::Deny);
}

// Path rewriting must use shell words, not whitespace runs. The quoted directory
// is one operand; collapsing `..` lands it on `/w/src`, where the broad deny holds.
// Wrapper peeling must keep the same raw word boundary.
#[test]
fn quoted_spaced_operand_resolves_as_one_word() {
    const POLICY: &str = r#"{
      "defaultMode": "ask",
      "allow": [
        "Bash(rm -rf \"scratch dir\"/*)",
        "Bash(rm -rf /w/scratch dir/*)",
        "Bash(sudo:*)"
      ],
      "deny": ["Bash(rm -rf /*)"]
    }"#;
    let rs = load_rules_str(POLICY).unwrap();
    let d = |cmd: &str| evaluate(&rs, "Bash", &json!({ "command": cmd }), Some("/w")).tier;

    assert_eq!(d(r#"rm -rf "scratch dir"/file"#), Tier::Allow);
    assert_eq!(d(r#"rm -rf "scratch dir"/../src"#), Tier::Deny);
    assert_eq!(d(r#"sudo rm -rf "scratch dir"/../src"#), Tier::Deny);
}

// A long option can carry a path in the same word. Resolve the value after `=`
// while preserving the option name, so traversal cannot ride a relative allow
// past the equivalent absolute deny.
#[test]
fn attached_long_option_path_is_resolved() {
    const POLICY: &str = r#"{
      "defaultMode": "ask",
      "allow": [
        "Bash(tar --directory=.scratch/*)",
        "Bash(tar --directory=/w/.scratch/*)"
      ],
      "deny": ["Bash(tar --directory=/*)"]
    }"#;
    let rs = load_rules_str(POLICY).unwrap();
    let d = |cmd: &str| evaluate(&rs, "Bash", &json!({ "command": cmd }), Some("/w")).tier;

    assert_eq!(d("tar --directory=.scratch/build archive.tar"), Tier::Allow);
    assert_eq!(d("tar --directory=.scratch/../src archive.tar"), Tier::Deny);
}

// --- Displaced wrappers (§8.2) ------------------------------------------------

/// The denied command is itself a *wrapper*, with allowed words either side, so
/// every spelling matches an explicit rule at every stage and any `deny` came from
/// the `sudo` rule. `defaultMode` is `deny`: the loader accepts nothing else.
const WRAPPER_RULES: &str = r#"{
  "defaultMode": "deny",
  "allow": ["Bash(command:*)", "Bash(xargs:*)", "Bash(whoami:*)", "Bash(ls:*)"],
  "deny": ["Bash(sudo:*)"]
}"#;

fn wrapper_bash(cmd: &str) -> Tier {
    let rs = load_rules_str(WRAPPER_RULES).expect("crafted rules load");
    evaluate(&rs, "Bash", &json!({ "command": cmd }), Some(CWD)).tier
}

#[test]
fn a_denied_wrapper_outranks_an_allow_at_both_ends_of_the_peel() {
    // A rule naming a wrapper only fires while that wrapper is the first word. A
    // one-step peel decided the two ends only, so the allowed outer and inner words
    // let the `sudo` between them run on an allow.
    assert_eq!(wrapper_bash("command sudo whoami"), Tier::Deny);
    assert_eq!(wrapper_bash("xargs sudo whoami"), Tier::Deny);
    assert_eq!(wrapper_bash("command xargs sudo whoami"), Tier::Deny);
    // Head and innermost position already worked; lock them against a regression.
    assert_eq!(wrapper_bash("sudo whoami"), Tier::Deny);
    // An allowed command behind the same wrappers keeps its allow, so the stages
    // raise a verdict only on a real match.
    assert_eq!(wrapper_bash("command whoami"), Tier::Allow);
    assert_eq!(wrapper_bash("command xargs ls"), Tier::Allow);
}

#[test]
fn an_unmatched_stage_does_not_stop_the_peel() {
    // A stage matching nothing reports the fall-back tier, indistinguishable from
    // a rule that says `ask`. Only `deny`, which nothing outranks, is safe to stop on.
    let rs = load_rules_str(
        r#"{"defaultMode":"ask","allow":["Bash(whoami:*)"],"deny":["Bash(sudo:*)"]}"#,
    )
    .expect("crafted rules load");
    let tier = |cmd: &str| evaluate(&rs, "Bash", &json!({ "command": cmd }), Some(CWD)).tier;

    // No rule names `timeout`, so the first stage reports the fall-back `ask`.
    assert_eq!(tier("timeout 5 whoami"), Tier::Ask);
    // Stopping at that `ask` would return `ask` for this, not `deny`.
    assert_eq!(tier("timeout 5 sudo whoami"), Tier::Deny);
    assert_eq!(tier("nice timeout 5 sudo whoami"), Tier::Deny);
}

#[test]
fn a_wrapper_chain_past_the_stage_bound_fails_closed() {
    // Each stage re-decides a suffix, so an unbounded chain is quadratic. Past the
    // bound the unit is denied rather than decided on the stages that fit (§9.1).
    let chain = |n: usize| format!("{}whoami", "command ".repeat(n));

    assert_eq!(wrapper_bash(&chain(32)), Tier::Allow); // at the bound
    assert_eq!(wrapper_bash(&chain(33)), Tier::Deny); // one past it
    assert_eq!(wrapper_bash(&chain(500)), Tier::Deny);
    // A denied wrapper inside a chain short of the bound is still found.
    assert_eq!(
        wrapper_bash(&format!("{}sudo whoami", "command ".repeat(20))),
        Tier::Deny
    );
}

// --- Statements that run nothing (§8.1) ---------------------------------------

/// The same rules at both fall-back settings. The `deny` side is where a stray
/// verdict matters: there the fall-back is a block, not a prompt.
const STRUCTURE_RULES: &str = r#"{
  "defaultMode": "%MODE%",
  "allow": ["Bash(ls:*)", "Bash(whoami:*)"],
  "deny": ["Bash(sudo:*)"]
}"#;

fn structure_bash(cmd: &str, mode: &str) -> Tier {
    let rs = load_rules_str(&STRUCTURE_RULES.replace("%MODE%", mode)).expect("crafted rules load");
    evaluate(&rs, "Bash", &json!({ "command": cmd }), Some(CWD)).tier
}

/// Assert a command resolves to `ask` under ask-default and `deny` under
/// deny-default, i.e. it is being decided by the fall-back and nothing else.
fn assert_takes_fall_back(cmd: &str) {
    assert_eq!(
        structure_bash(cmd, "ask"),
        Tier::Ask,
        "ask-default: {cmd:?}"
    );
    assert_eq!(
        structure_bash(cmd, "deny"),
        Tier::Deny,
        "deny-default: {cmd:?}"
    );
}

#[test]
fn a_statement_that_runs_nothing_carries_no_verdict() {
    // A closer left by §8.1, or an assignment with no command, must not take the
    // fall-back: no rule set can repair that, since nobody writes `Bash(fi:*)`.
    for cmd in [
        "ls; fi",
        "ls; done",
        "ls; esac",
        "ls; }",
        "FOO=bar; ls",
        "ls; if",
        "ls; then",
        "FOO=bar BAZ=qux; ls",
    ] {
        assert_eq!(
            structure_bash(cmd, "ask"),
            Tier::Allow,
            "ask-default: {cmd:?}"
        );
        assert_eq!(
            structure_bash(cmd, "deny"),
            Tier::Allow,
            "deny-default: {cmd:?}"
        );
    }
}

#[test]
fn a_quoted_or_qualified_closer_is_still_a_command() {
    // The skip reads the raw slice: these all normalize to the word `fi`, and
    // `./fi` runs a program.
    for cmd in ["'fi'", "\"fi\"", "\\fi", "./fi", "/usr/bin/fi", "fi x"] {
        assert_takes_fall_back(cmd);
    }
}

#[test]
fn a_wrapper_alone_is_still_a_command() {
    // Wrappers are executables, so one alone is a real invocation.
    assert_eq!(structure_bash("sudo", "ask"), Tier::Deny);
    assert_eq!(structure_bash("ls; sudo", "ask"), Tier::Deny);
    assert_eq!(structure_bash("sudo; ls", "deny"), Tier::Deny);
    // One that no rule names still reaches the fall-back rather than being skipped.
    assert_takes_fall_back("xargs");
}

#[test]
fn a_command_hidden_in_an_assignment_value_still_decides() {
    // Dropping an assignment husk is safe only because §8.1 lifts a substitution
    // in the value into its own unit. Locked here: if that stops, so does the deny.
    for cmd in [
        "FOO=$(sudo whoami)",
        "FOO=`sudo whoami`",
        "A=1 B=$(sudo -i) C=3",
        "FOO=$(sudo whoami); ls",
    ] {
        assert_eq!(
            structure_bash(cmd, "ask"),
            Tier::Deny,
            "ask-default: {cmd:?}"
        );
        assert_eq!(
            structure_bash(cmd, "deny"),
            Tier::Deny,
            "deny-default: {cmd:?}"
        );
    }
}

#[test]
fn a_command_made_only_of_structure_is_allowed() {
    // The fall-back is for a command no rule named, not one containing no command,
    // so the answer must not depend on `defaultMode`.
    for cmd in ["fi", "done", "esac", "}", "FOO=bar", "FOO=", "if", "{", "!"] {
        assert_eq!(
            structure_bash(cmd, "ask"),
            Tier::Allow,
            "ask-default: {cmd:?}"
        );
        assert_eq!(
            structure_bash(cmd, "deny"),
            Tier::Allow,
            "deny-default: {cmd:?}"
        );
    }
    // Anything that could run keeps its verdict, so this never generalizes.
    assert_takes_fall_back("./fi");
    assert_takes_fall_back("'fi'");
    assert_eq!(structure_bash("sudo", "ask"), Tier::Deny);
}

// Windows drive-relative words have no separator (`C:secret.txt`) but still name
// a path. The Bash operand gate must let them reach the same same-drive resolution
// already used by Path payloads.
#[cfg(windows)]
#[test]
fn windows_drive_relative_bash_operand_uses_the_cwd() {
    let rs = load_rules_str(
        r#"{"defaultMode":"ask","allow":["Bash(cat:*)"],"deny":["Bash(cat /C:/work/**)"]}"#,
    )
    .unwrap();
    let at = |cwd: &str| {
        evaluate(
            &rs,
            "Bash",
            &json!({ "command": "cat C:secret.txt" }),
            Some(cwd),
        )
        .tier
    };

    assert_eq!(at(r"C:\work"), Tier::Deny);
    assert_eq!(at(r"D:\work"), Tier::Allow);
}
