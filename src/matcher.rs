//! Per-family matchers and specificity scoring (§6.1, §6.5).
//!
//! [`compile`] turns a specifier string into a [`Matcher`] plus its specificity
//! score. All globbing is hand-written (no `regex`) so cold-start cost stays in
//! microseconds — the binary is a fresh short-lived process per tool call.

use crate::types::Family;
use std::sync::OnceLock;

/// Bonus added to a specifier's literal-character count when it contains no
/// wildcard at all, so a literal specifier outranks any wildcard one (§6.1).
pub const EXACT_MATCH_BONUS: u32 = 1000;

/// `$HOME`, read once and cached for the process lifetime.
pub(crate) fn home_dir() -> &'static str {
    static HOME: OnceLock<String> = OnceLock::new();
    HOME.get_or_init(|| std::env::var("HOME").unwrap_or_default())
}

/// Why a specifier could not be compiled into a matcher (§4).
///
/// The matchers below are **total** for any non-empty specifier, so `Empty` is
/// the only way `compile` can fail — and callers already reject empty specifiers
/// earlier (see [`crate::rules::parse_rule`]). This enum exists so that a future
/// fallible matcher has a typed failure that surfaces as a load error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    /// Empty specifier (`Tool()`), caught before reaching a matcher.
    Empty,
}

/// A compiled matcher for one rule.
#[derive(Debug, Clone)]
pub enum Matcher {
    /// Bare rule: matches any payload for the tool (specificity 0).
    Bare,
    Bash(BashMatcher),
    Path(PathMatcher),
    Generic(GenericMatcher),
}

impl Matcher {
    /// Test one candidate form of the payload against this matcher.
    pub fn matches(&self, candidate: &str) -> bool {
        match self {
            Matcher::Bare => true,
            Matcher::Bash(m) => m.matches(candidate),
            Matcher::Path(m) => m.matches(candidate),
            Matcher::Generic(m) => m.matches(candidate),
        }
    }
}

/// Compile a specifier for the given family into a `(matcher, specificity)`
/// pair (§6.1, §6.5).
pub fn compile(family: Family, spec: &str) -> Result<(Matcher, u32), CompileError> {
    if spec.is_empty() {
        return Err(CompileError::Empty);
    }
    Ok(match family {
        Family::Bash => {
            if let Some(prefix) = spec.strip_suffix(":*") {
                // Trailing `cmd:*` form: the `:*` is a wildcard marker, so its
                // own characters are not counted and no exact-match bonus is
                // awarded — `aws:*` scores 3, not 1005.
                let specificity = literal_count(prefix, &['*']);
                (
                    Matcher::Bash(BashMatcher::Prefix(prefix.to_string())),
                    specificity,
                )
            } else {
                let specificity = score(spec, &['*']);
                (
                    Matcher::Bash(BashMatcher::Glob(spec.to_string())),
                    specificity,
                )
            }
        }
        Family::Path => {
            let specificity = score(spec, &['*', '?']);
            (Matcher::Path(PathMatcher::compile(spec)), specificity)
        }
        Family::Generic => {
            let pattern = spec.strip_prefix("domain:").unwrap_or(spec);
            let specificity = score(pattern, &['*']);
            (
                Matcher::Generic(GenericMatcher(pattern.to_string())),
                specificity,
            )
        }
    })
}

/// Literal char count + exact-match bonus when no wildcard is present (§6.1).
fn score(spec: &str, wildcards: &[char]) -> u32 {
    let mut literal = 0u32;
    let mut has_wildcard = false;
    for c in spec.chars() {
        if wildcards.contains(&c) {
            has_wildcard = true;
        } else {
            literal += 1;
        }
    }
    literal + if has_wildcard { 0 } else { EXACT_MATCH_BONUS }
}

/// Count of non-wildcard characters, with no exact-match bonus.
fn literal_count(spec: &str, wildcards: &[char]) -> u32 {
    spec.chars().filter(|c| !wildcards.contains(c)).count() as u32
}

// --- Bash --------------------------------------------------------------------

/// A Bash specifier, anchored to the whole (trimmed) command (§6.5).
#[derive(Debug, Clone)]
pub enum BashMatcher {
    /// Trailing `cmd:*` form: matches `cmd` alone or `cmd` + whitespace + args.
    Prefix(String),
    /// General glob where `*` matches any run of characters.
    Glob(String),
}

impl BashMatcher {
    fn matches(&self, cmd: &str) -> bool {
        match self {
            BashMatcher::Prefix(prefix) => {
                if cmd == prefix {
                    return true;
                }
                cmd.len() > prefix.len()
                    && cmd.starts_with(prefix.as_str())
                    && cmd.as_bytes()[prefix.len()].is_ascii_whitespace()
            }
            BashMatcher::Glob(pattern) => glob_star_match(cmd.as_bytes(), pattern.as_bytes()),
        }
    }
}

// --- Generic (URL/string) ----------------------------------------------------

/// A Generic specifier: a domain/URL pattern where `*` is the only wildcard and
/// spans any characters, `/` included (§6.5).
#[derive(Debug, Clone)]
pub struct GenericMatcher(String);

impl GenericMatcher {
    fn matches(&self, candidate: &str) -> bool {
        glob_star_match(candidate.as_bytes(), self.0.as_bytes())
    }
}

/// Anchored full-string wildcard match where only `*` is special and matches any
/// run of bytes (including empty). Iterative with backtracking — O(n·m) worst
/// case, linear in practice.
pub(crate) fn glob_star_match(text: &[u8], pat: &[u8]) -> bool {
    let (mut t, mut p) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while t < text.len() {
        if p < pat.len() && pat[p] == b'*' {
            star = p;
            p += 1;
            mark = t;
        } else if p < pat.len() && pat[p] == text[t] {
            p += 1;
            t += 1;
        } else if star != usize::MAX {
            p = star + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

// --- Path --------------------------------------------------------------------

/// One token of a compiled path glob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PToken {
    Lit(u8),
    /// `*` — any run of non-separator bytes.
    Star,
    /// `?` — a single non-separator byte.
    Ques,
    /// `**` — any run of bytes, separators included.
    DStar,
}

/// A Path specifier compiled to a glob token sequence (§6.5).
#[derive(Debug, Clone)]
pub struct PathMatcher(Vec<PToken>);

impl PathMatcher {
    fn compile(spec: &str) -> PathMatcher {
        // Root markers and `~` expansion happen before tokenizing.
        let owned;
        let normalized: &str = if spec == "~" {
            owned = home_dir().to_string();
            &owned
        } else if let Some(rest) = spec.strip_prefix("~/") {
            owned = format!("{}/{}", home_dir(), rest);
            &owned
        } else if let Some(rest) = spec.strip_prefix("//") {
            // Leading `//` root marker: strip one slash, leaving an
            // absolute-rooted glob.
            owned = format!("/{rest}");
            &owned
        } else {
            spec
        };

        let bytes = normalized.as_bytes();
        let mut tokens = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'*' => {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                        tokens.push(PToken::DStar);
                        i += 2;
                    } else {
                        tokens.push(PToken::Star);
                        i += 1;
                    }
                }
                b'?' => {
                    tokens.push(PToken::Ques);
                    i += 1;
                }
                // `[`, `]`, `{`, `}`, `\` and everything else are literal.
                c => {
                    tokens.push(PToken::Lit(c));
                    i += 1;
                }
            }
        }
        PathMatcher(tokens)
    }

    fn matches(&self, candidate: &str) -> bool {
        path_match(&self.0, candidate.as_bytes())
    }
}

/// Anchored, full-string glob match with `/`-aware wildcards (§6.5).
///
/// Plain recursive backtracking. Path specifiers come from the operator-authored
/// rule set (`permissions.json` is the source of truth), so they are trusted and
/// short — at most a few spanning wildcards — and paths are bounded, making this
/// fast in practice. It is deliberately **not** hardened against adversarial
/// patterns with many interacting wildcards; that is a documented non-goal
/// (§9.2), since the rules are trusted config, not attacker input. Semantics:
/// `*` spans a run of non-`/` bytes, `?` one non-`/` byte, `**` any run including
/// `/`, and `**/` collapses to zero directories (so `/**/.env` matches `/.env`
/// and `**/x` matches a bare `x`).
fn path_match(pat: &[PToken], text: &[u8]) -> bool {
    match pat.first() {
        None => text.is_empty(),
        Some(PToken::DStar) => {
            let rest = &pat[1..];
            // `**` matches any suffix boundary, separators included.
            if (0..=text.len()).any(|i| path_match(rest, &text[i..])) {
                return true;
            }
            // Collapse `**/` to zero directories, so `/**/.env` matches `/.env`
            // and `**/x` matches a bare `x`.
            if let Some(PToken::Lit(b'/')) = rest.first() {
                return path_match(&rest[1..], text);
            }
            false
        }
        Some(PToken::Star) => {
            let rest = &pat[1..];
            // `*` matches a run of non-separator bytes (including empty).
            let mut i = 0;
            loop {
                if path_match(rest, &text[i..]) {
                    return true;
                }
                if i < text.len() && text[i] != b'/' {
                    i += 1;
                } else {
                    return false;
                }
            }
        }
        Some(PToken::Ques) => {
            !text.is_empty() && text[0] != b'/' && path_match(&pat[1..], &text[1..])
        }
        Some(PToken::Lit(c)) => {
            !text.is_empty() && text[0] == *c && path_match(&pat[1..], &text[1..])
        }
    }
}
