//! Criterion benchmark for the hot path: load once, then evaluate many calls.
//!
//! The production cost model is a fresh short-lived process per tool call, so
//! this measures steady-state `evaluate` latency against the reference rule set.

use criterion::{Criterion, criterion_group, criterion_main};
use permcheck::{RuleSet, evaluate};
use serde_json::json;
use std::hint::black_box;

const RULES: &str = include_str!("../rules/permissions.json");

fn bench_evaluate(c: &mut Criterion) {
    let rules = RuleSet::load_str(RULES).expect("reference rules load");
    let cwd = Some("/home/user/project");

    let cases = [
        (
            "bash_allow",
            "Bash",
            json!({"command": "aws ec2 describe-instances"}),
        ),
        (
            "bash_deny",
            "Bash",
            json!({"command": "aws ec2 terminate-instances"}),
        ),
        (
            "bash_compound",
            "Bash",
            json!({"command": "ls && cat .env | grep x"}),
        ),
        ("path_allow", "Read", json!({"file_path": "/tmp/notes.txt"})),
        (
            "path_deny",
            "Read",
            json!({"file_path": "/home/user/.ssh/id_rsa"}),
        ),
        (
            "generic_deny",
            "WebFetch",
            json!({"url": "https://example.com/x"}),
        ),
    ];

    for (name, tool, input) in &cases {
        c.bench_function(name, |b| {
            b.iter(|| {
                black_box(evaluate(
                    black_box(&rules),
                    black_box(tool),
                    black_box(input),
                    cwd,
                ))
            })
        });
    }

    c.bench_function("load_str", |b| {
        b.iter(|| black_box(RuleSet::load_str(black_box(RULES))).unwrap())
    });
}

criterion_group!(benches, bench_evaluate);
criterion_main!(benches);
