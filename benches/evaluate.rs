//! Criterion benchmark for the hot path: load once, then evaluate many calls.
//!
//! The production cost model is a fresh short-lived process per tool call, so
//! this measures steady-state `evaluate` latency against the reference rule set.

use criterion::{Criterion, criterion_group, criterion_main};
use permcheck::{RuleSet, evaluate};
use serde_json::json;
use std::hint::black_box;

const RULES_JSON: &str = include_str!("../rules/permissions.json");

fn make_ruleset() -> permcheck::rules::RuleSet {
    RuleSet::load_str(RULES_JSON).expect("reference rules load")
}

fn bench_load(c: &mut Criterion) {
    c.bench_function("load_rules_set", |b| {
        b.iter(|| make_ruleset())
    });
}

fn bench_bash(c: &mut Criterion) {
    let rules = make_ruleset();
    let mut g = c.benchmark_group("bash");

    let cases: &[(&str, &str)] = &[
        ("allow_aws_describe", "aws ec2 describe-instance"),
        ("deny_aws_terminate", "aws ec2 terminate-instances"),
        ("allow_kubectl_get", "kubectl get pods"),
        ("deny_kubectl_delete", "kubectl delete pod x"),
        ("ask_git_push", "git push origin main"),
        ("deny_git_push_force", "git push --force origin main"),
        ("deny_cat_env", "cat .env"),
        ("deny_unknown", "unknown command"),
        ("compound_and", "cd /tmp && ls -la"),
        ("compound_subshell", "echo $(ls -la)"),
        ("compound_pipe", "cat file.txt | grep something"),
    ];

    for (name, cmd) in cases {
        let input = json!({"command": cmd});

        g.bench_function(*name, |b| {
            b.iter(|| 

                evaluate(
                    &rules,
                    "Bash",
                    &input,
                    None,
                ));
        });
    }

    g.finish();
}

fn bench_path(c: &mut Criterion) {
    let rules = make_ruleset();
    let mut g = c.benchmark_group("path");
 
    let cases = &[
        (
            "read_allow_tmp",
            "Read",
            "/tmp/notes.txt",
        ),
        (
            "read_deny_ssh",
            "Read",
            "/home/user/.ssh/id_rsa",
        ),
                (
            "read_deny_env",
            "Read",
            "/home/user/.env",
        ),
                (
            "edit_allow",
            "Read",
            "/tmp/notes.txt",
        ),
    ];

    for (name, tool, path) in cases {
        let input = json!({"file_path": path});
        g.bench_function(*name, |b| {
            b.iter(|| {
                black_box(evaluate(
                    &rules,
                    tool,
                    &input,
                    None,
                ))
            })
        });
    }

    g.finish();
}

criterion_group!(benches, bench_load, bench_bash, bench_path);
criterion_main!(benches);
