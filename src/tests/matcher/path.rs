//! Path matcher unit tests (§6.5).

use crate::matcher::{Matcher, compile};
use crate::types::Family;

fn m(spec: &str) -> Matcher {
    compile(Family::Path, spec).expect("compiles").0
}

#[test]
fn star_does_not_cross_separator() {
    let matcher = m("/a/*/c");
    assert!(matcher.matches("/a/b/c"));
    assert!(!matcher.matches("/a/b/x/c"));
}

#[test]
fn double_star_crosses_separators() {
    let matcher = m("/**/.env");
    assert!(matcher.matches("/home/user/.env"));
    assert!(matcher.matches("/.env"));
    assert!(!matcher.matches("/home/user/.envrc"));
}

#[test]
fn question_matches_single_non_separator() {
    let matcher = m("/a?c");
    assert!(matcher.matches("/abc"));
    assert!(!matcher.matches("/a/c"));
    assert!(!matcher.matches("/ac"));
}

#[test]
fn root_marker_strips_one_slash() {
    // `//**/.env` normalizes to `/**/.env`, an absolute-rooted glob.
    let matcher = m("//**/.env");
    assert!(matcher.matches("/etc/.env"));
    assert!(!matcher.matches("etc/.env"));
}

#[test]
fn brackets_are_literal() {
    let matcher = m("/a[b]c");
    assert!(matcher.matches("/a[b]c"));
    assert!(!matcher.matches("/abc"));
}

/// Tricky (spec, text, expected) cases spanning the glob semantics (§6.5).
const CORPUS: &[(&str, &str, bool)] = &[
    // Multiple `**`, separator crossing, and the `**/` zero-directory collapse.
    ("/**/**/**/x", "/a/b/c/x", true),
    ("/**/**/**/x", "/a/b/c/y", false),
    ("/**/.env", "/.env", true),
    ("/**/.env", "/a/b/c/.env", true),
    ("/**/.env", "/a/.envrc", false),
    ("**/x", "x", true),
    ("**/x", "a/b/x", true),
    // `*` must not cross a separator; `?` is a single non-separator byte.
    ("/a/*/c", "/a/b/c", true),
    ("/a/*/c", "/a/b/x/c", false),
    ("/a?c", "/abc", true),
    ("/a?c", "/a/c", false),
    // Metacharacters are literal in the Path family.
    ("/a[b]c", "/a[b]c", true),
    ("/a[b]c", "/abc", false),
    // Adjacent stars and empty runs.
    ("/**/*", "/a/b/c", true),
    ("/**", "/", true),
    ("**", "", true),
    ("/*", "/", true),
    // Long matching path against a spanning pattern.
    ("/**/secret", "/a/b/c/d/e/f/g/secret", true),
];

#[test]
fn matches_tricky_cases_correctly() {
    for &(spec, text, expected) in CORPUS {
        assert_eq!(
            m(spec).matches(text),
            expected,
            "spec={spec:?} text={text:?}"
        );
    }
}

#[test]
fn tilde_expands_to_home() {
    // The pattern's `~` expands via the process $HOME; a candidate carrying the
    // same expansion must match.
    let matcher = m("~/.npmrc");
    let home = std::env::var("HOME").unwrap_or_default();
    assert!(matcher.matches(&format!("{home}/.npmrc")));
    assert!(!matcher.matches(&format!("{home}/.other")));
}
