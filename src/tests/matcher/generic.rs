//! Generic (URL/string) matcher unit tests (§6.5).

use crate::matcher::{Matcher, compile};
use crate::types::Family;

fn m(spec: &str) -> (Matcher, u32) {
    compile(Family::Generic, spec).expect("compiles")
}

#[test]
fn domain_prefix_is_stripped() {
    let (matcher, _) = m("domain:example.com");
    assert!(matcher.matches("example.com"));
}

#[test]
fn anchored_full_match_against_host() {
    let (matcher, _) = m("example.com");
    assert!(matcher.matches("example.com"));
    assert!(!matcher.matches("example.com.evil.com"));
    assert!(!matcher.matches("https://example.com/path"));
}

#[test]
fn star_spans_slashes() {
    let (matcher, _) = m("https://example.com/*");
    assert!(matcher.matches("https://example.com/a/b/c"));
}

#[test]
fn literal_specifier_gets_exact_bonus() {
    assert!(m("example.com").1 >= 1000);
    assert!(m("*.example.com").1 < 1000);
}
