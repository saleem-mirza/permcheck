//! Path matcher unit tests (§6.5).

use permcheck::matcher::{Matcher, compile, normalize_root};
use permcheck::types::Family;

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
    // The pattern's `~` expands via the process home dir; a candidate carrying
    // the same expansion must match. `test_home` mirrors `home_dir`'s resolution
    // on each platform so this holds on Windows too (drive-letter home).
    let matcher = m("~/.npmrc");
    let home = test_home();
    assert!(matcher.matches(&format!("{home}/.npmrc")));
    assert!(!matcher.matches(&format!("{home}/.other")));
}

#[test]
fn tilde_expansion_uses_the_shared_home_resolution() {
    // `--install` and `~` expansion must resolve the same directory; if they
    // diverged, a `Read(~/.npmrc)` deny could expand where the file is not. Assert
    // against `raw_home` rather than any env var.
    let Some(raw) = permcheck::matcher::raw_home() else {
        return; // no home in this environment: nothing to pin
    };
    assert!(!raw.is_empty(), "raw_home must never yield an empty path");
    let expanded = normalize_root(&raw);
    assert!(m("~/.npmrc").matches(&format!("{expanded}/.npmrc")));
}

/// The home dir as the engine resolves it. Calls `raw_home` rather than
/// restating the per-platform chain, so it cannot drift.
fn test_home() -> String {
    normalize_root(&permcheck::matcher::raw_home().unwrap_or_default())
}
