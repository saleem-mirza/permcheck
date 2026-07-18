//! Bash matcher + specificity unit tests (§6.1, §6.5).

use crate::matcher::{Matcher, compile};
use crate::types::Family;

fn m(spec: &str) -> (Matcher, u32) {
    compile(Family::Bash, spec).expect("compiles")
}

#[test]
fn trailing_form_matches_command_and_args() {
    let (matcher, _) = m("git push:*");
    assert!(matcher.matches("git push"));
    assert!(matcher.matches("git push origin main"));
    assert!(!matcher.matches("git pushx"));
    assert!(!matcher.matches("git pus"));
}

#[test]
fn trailing_specificity_excludes_star_marker() {
    assert_eq!(m("aws:*").1, 3);
    assert_eq!(m("git push:*").1, 8);
    assert_eq!(m("git push --force:*").1, 16);
}

#[test]
fn general_glob_star_spans_any_run() {
    let (matcher, spec) = m("aws * describe-*");
    assert_eq!(spec, 14);
    assert!(matcher.matches("aws ec2 describe-instances"));
    assert!(matcher.matches("aws s3api describe-buckets"));
    assert!(!matcher.matches("aws ec2 list-instances"));
}

#[test]
fn anchored_full_string_no_substring() {
    let (matcher, _) = m("mkdir *");
    assert!(matcher.matches("mkdir foo"));
    assert!(!matcher.matches("sudo mkdir foo"));
    assert!(!matcher.matches("mkdir")); // literal space is required
}
