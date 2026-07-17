//! Criterion benchmarks for the hot path: load once, then evaluate many calls.
//!
//! The production cost model is a fresh short-lived process per tool call, so
//! these measure steady-state `evaluate` latency against the reference rule set
//! (`rules/permissions.json`), grouped by matcher family, plus the one-time cost
//! of loading and compiling the whole rule set. Every case pins its inputs and
//! result with `black_box` so the optimizer can't fold the work away.

use criterion::{Criterion, criterion_group, criterion_main};
use permcheck::{RuleSet, evaluate};
use serde_json::{Value, json};
use std::hint::black_box;

const RULES_JSON: &str = include_str!("../rules/permissions.json");

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
            // Specificity: narrow allow/ask beats broad deny, and vice versa.
            (
                "allow_aws_describe",
                "Bash",
                cmd("aws ec2 describe-instances"),
            ),
            ("allow_kubectl_get", "Bash", cmd("kubectl get pods")),
            ("allow_git_status", "Bash", cmd("git status")),
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
            ("deny_unknown", "Bash", cmd("some-tool --flag")),
            // File-access cross-check and wrapper re-decision (§8).
            ("crosscheck_cat_env", "Bash", cmd("cat .env")),
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

/// Generic family: URL/host extraction and default-deny for unnamed MCP tools.
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
                "mcp_default_deny",
                "mcp__db__query",
                json!({ "query": "SELECT 1" }),
            ),
        ],
    );
}

criterion_group!(benches, bench_load, bench_bash, bench_path, bench_generic);
criterion_main!(benches);
