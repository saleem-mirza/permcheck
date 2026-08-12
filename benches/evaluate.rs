//! Criterion benchmarks for the hot path: load once, then evaluate many calls
//! against the reference rule set, grouped by matcher family, plus the one-time
//! load. Every case pins inputs and result with `black_box`.

use criterion::{Criterion, criterion_group, criterion_main};
use permcheck::types::Tier;
use permcheck::{RuleSet, evaluate};
use serde_json::{Value, json};
use std::hint::black_box;

const RULES_JSON: &str = include_str!("../rules/permcheck.json");

fn ruleset() -> RuleSet {
    RuleSet::load_str(RULES_JSON).expect("reference rules load")
}

/// Benchmark a list of `(name, tool, tool_input)` calls under one group.
fn bench_cases(c: &mut Criterion, group: &str, cwd: Option<&str>, cases: &[(&str, &str, Value)]) {
    let rules = ruleset();
    let mut g = c.benchmark_group(group);
    for (name, tool, input) in cases {
        g.bench_function(*name, |b| {
            b.iter(|| black_box(evaluate(black_box(&rules), tool, black_box(input), cwd)));
        });
    }
    g.finish();
}

/// One-time cost of loading + compiling the entire reference rule set.
fn bench_load(c: &mut Criterion) {
    c.bench_function("load/reference_set", |b| {
        b.iter(|| black_box(ruleset()));
    });
}

/// Bash family: winner selection per unit, the file-access cross-check, wrapper
/// re-decision, and compound splitting (§6.3, §8).
fn bench_bash(c: &mut Criterion) {
    let cmd = |s: &str| json!({ "command": s });
    bench_cases(
        c,
        "bash",
        Some("/repo"),
        &[
            // Specificity and fall-back: broad `aws:*` / `kubectl:*` denies, git
            // reads with no rule, and `git push --force` deny beating the ask.
            (
                "deny_aws_describe",
                "Bash",
                cmd("aws ec2 describe-instances"),
            ),
            ("deny_kubectl_get", "Bash", cmd("kubectl get pods")),
            ("ask_git_status", "Bash", cmd("git status")),
            ("ask_git_push", "Bash", cmd("git push origin main")),
            (
                "deny_aws_terminate",
                "Bash",
                cmd("aws ec2 terminate-instances"),
            ),
            ("deny_kubectl_delete", "Bash", cmd("kubectl delete pod x")),
            (
                "deny_git_push_force",
                "Bash",
                cmd("git push --force origin main"),
            ),
            ("ask_unknown", "Bash", cmd("some-tool --flag")),
            // File-access cross-check and wrapper re-decision (§8).
            ("crosscheck_cat_env", "Bash", cmd("cat .env")),
            ("crosscheck_cat_glob", "Bash", cmd("cat .en?")),
            (
                "crosscheck_redirect",
                "Bash",
                cmd("echo hi > /home/user/.ssh/authorized_keys"),
            ),
            (
                "wrapper_env_aws",
                "Bash",
                cmd("env aws ec2 terminate-instances"),
            ),
            // Staged peel (§8 step 2): the denied wrapper sits behind another
            // peelable word, so it is found on the second stage, not the first.
            ("wrapper_displaced_sudo", "Bash", cmd("command sudo whoami")),
            // Worst realistic shape for the walk: several stages and no deny to
            // short-circuit on, so every stage is decided.
            (
                "wrapper_stack_no_deny",
                "Bash",
                cmd("! time command nice whoami"),
            ),
            // Compound splitting: substitution, pipe, and chaining.
            ("compound_and", "Bash", cmd("cd /tmp && ls -la")),
            (
                "compound_pipe",
                "Bash",
                cmd("cat file.txt | grep something"),
            ),
            (
                "compound_subshell",
                "Bash",
                cmd("echo $(kubectl delete pod x)"),
            ),
        ],
    );
}

/// Path family: candidate forms (raw, `~`-expanded, cwd-absolutized) against the
/// ~30 path deny globs (§6.5, §7).
fn bench_path(c: &mut Criterion) {
    bench_cases(
        c,
        "path",
        Some("/home/user"),
        &[
            (
                "read_allow_tmp",
                "Read",
                json!({ "file_path": "/tmp/notes.txt" }),
            ),
            (
                "read_deny_ssh",
                "Read",
                json!({ "file_path": "/home/user/.ssh/id_rsa" }),
            ),
            (
                "read_deny_env",
                "Read",
                json!({ "file_path": "/home/user/.env" }),
            ),
            ("read_relative_env", "Read", json!({ "file_path": ".env" })), // cwd-absolutized
            (
                "read_traversal_env",
                "Read",
                json!({ "file_path": "/tmp/../repo/.env" }),
            ),
            (
                "write_deny_bashrc",
                "Write",
                json!({ "file_path": "/home/user/.bashrc" }),
            ),
            (
                "glob_allow_skills",
                "Glob",
                json!({ "path": "~/.claude/skills/x" }),
            ), // ~ expansion
        ],
    );
}

/// Generic family: URL/host extraction and the `defaultMode` fall-back for
/// unnamed MCP tools.
fn bench_generic(c: &mut Criterion) {
    bench_cases(
        c,
        "generic",
        None,
        &[
            (
                "webfetch_deny",
                "WebFetch",
                json!({ "url": "https://example.com/x" }),
            ),
            (
                "websearch_deny",
                "WebSearch",
                json!({ "query": "rust async" }),
            ),
            (
                "mcp_default_ask",
                "mcp__db__query",
                json!({ "query": "SELECT 1" }),
            ),
        ],
    );
}

/// A policy whose individually legal worst-case misses approach or exhaust the
/// complete decision's matcher-work budget. At 32,000 payload bytes, each
/// 61-token pattern costs 1,952,000 states: ten fit under 20 million and eleven
/// fail closed on the aggregate limit.
fn matcher_budget_rules(rule_count: usize) -> RuleSet {
    let pattern = format!("*{}b", "a".repeat(59));
    let rules = json!({
        "allow": vec![format!("WebSearch({pattern})"); rule_count],
        "defaultMode": "ask",
    });
    RuleSet::load_str(&rules.to_string()).expect("matcher budget rules load")
}

fn bench_matcher_budget(c: &mut Criterion) {
    let input = json!({ "query": "a".repeat(32_000) });
    let cases = [
        ("near_limit_ask", matcher_budget_rules(10), Tier::Ask),
        ("exhausted_deny", matcher_budget_rules(11), Tier::Deny),
    ];
    let mut group = c.benchmark_group("matcher_budget");
    for (name, rules, expected) in &cases {
        assert_eq!(evaluate(rules, "WebSearch", &input, None).tier, *expected);
        group.bench_function(*name, |b| {
            b.iter(|| {
                black_box(evaluate(
                    black_box(rules),
                    "WebSearch",
                    black_box(&input),
                    None,
                ))
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_load,
    bench_bash,
    bench_path,
    bench_generic,
    bench_matcher_budget
);
criterion_main!(benches);
