//! Bash matcher + specificity unit tests (§6.1, §6.5).

use permcheck::matcher::{Matcher, compile};
use permcheck::types::Family;

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
fn interior_space_fenced_star_is_a_single_token() {
    // ` * ` fenced by spaces on both sides matches one whitespace-delimited token,
    // so the service slot cannot swallow spaces and admit a later operation.
    let (matcher, spec) = m("aws * describe-*");
    assert_eq!(spec, 14);
    assert!(matcher.matches("aws ec2 describe-instances"));
    assert!(matcher.matches("aws rds describe-db-instances"));
    assert!(!matcher.matches("aws ec2 list-instances"));
    // The service slot is one token: an operation before a later `describe-`
    // substring does not match.
    assert!(!matcher.matches("aws s3 rm s3://prod-bucket/describe-report.json"));
    assert!(!matcher.matches("aws iam delete-user --user-name describe-me"));
}

#[test]
fn word_attached_and_trailing_stars_still_span() {
    // A `*` attached to a word (`describe-*`) spans the rest of that argument.
    let (matcher, _) = m("aws * describe-*");
    assert!(matcher.matches("aws ec2 describe-instances --output json"));
    // A trailing `cmd *` still spans all arguments, including spaces.
    let (trailing, _) = m("python3 *");
    assert!(trailing.matches("python3 a b c"));
    assert!(trailing.matches("python3 script.py --flag x"));
}

#[test]
fn anchored_full_string_no_substring() {
    let (matcher, _) = m("mkdir *");
    assert!(matcher.matches("mkdir foo"));
    assert!(!matcher.matches("sudo mkdir foo"));
    assert!(!matcher.matches("mkdir")); // literal space is required
}
