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

/// The home directory, read once and cached for the process lifetime, in a
/// POSIX-anchored form (see [`normalize_root`]).
pub(crate) fn home_dir() -> &'static str {
    static HOME: OnceLock<String> = OnceLock::new();
    HOME.get_or_init(|| normalize_root(&raw_home()))
}

/// The raw home directory from the environment, before normalization.
#[cfg(not(windows))]
fn raw_home() -> String {
    std::env::var("HOME").unwrap_or_default()
}

/// On Windows, fall back to `%USERPROFILE%` when `$HOME` is unset (native,
/// non-MSYS shells set only the former).
#[cfg(windows)]
fn raw_home() -> String {
    std::env::var("HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("USERPROFILE").ok())
        .unwrap_or_default()
}

/// Normalize an absolute base path (a CWD or home dir) into a POSIX-anchored form
/// so the `/`-based Path globs match.
///
/// Path specifiers are written POSIX-style (leading `/`, `/` separators), so a
/// POSIX base is already anchored: on non-Windows targets this is the identity
/// function and the whole transform compiles out. The Windows implementation
/// below is the only platform-specific behavior.
#[cfg(not(windows))]
#[inline]
pub fn normalize_root(dir: &str) -> String {
    dir.to_string()
}

/// A Windows base is a drive-letter path with backslashes (e.g. `D:\proj`); we
/// convert `\` to `/` and prepend a `/` to the drive-letter root, so `D:\proj`
/// becomes `/D:/proj` — an absolute-rooted candidate a rule like `/**/.env*`
/// matches. A path already starting with `/` (an MSYS-style form) is left as is.
#[cfg(windows)]
pub fn normalize_root(dir: &str) -> String {
    if dir.starts_with('/') {
        return dir.to_string();
    }
    let slashed = dir.replace('\\', "/");
    let b = slashed.as_bytes();
    // A Windows drive-letter root (`X:/…`) needs a leading `/` to anchor.
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        format!("/{slashed}")
    } else {
        slashed
    }
}

/// True if `path` is already absolute and so must not be joined onto a CWD
/// (§7.2). POSIX (and MSYS) absolute paths are `/`-rooted.
#[cfg(not(windows))]
#[inline]
pub(crate) fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// On Windows a payload is also absolute when it is drive-letter-rooted
/// (`X:\…` or `X:/…`); such a path is normalized by [`normalize_root`], not
/// absolutized against the CWD.
#[cfg(windows)]
pub(crate) fn is_absolute(path: &str) -> bool {
    if path.starts_with('/') {
        return true;
    }
    let b = path.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
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

        // Windows paths are case-insensitive, so fold the pattern to
        // ASCII-lowercase; candidates are folded the same way in `matches`, and
        // the byte-exact `path_match` then compares like cases. POSIX is
        // case-sensitive and left untouched. (ASCII folding only — it covers
        // drive letters and the common file names this tool matches on.)
        #[cfg(windows)]
        let normalized = normalized.to_ascii_lowercase();

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
        // On Windows the candidate is ASCII-lowercased to match the pattern,
        // which was folded the same way at compile time (case-insensitive FS).
        // POSIX stays byte-exact and allocation-free on this hot path.
        #[cfg(windows)]
        let candidate = candidate.to_ascii_lowercase();
        path_match(&self.0, candidate.as_bytes())
    }
}

// --- Subset test (§6.3a) -----------------------------------------------------

/// Sound (but deliberately incomplete) language-containment test: returns `true`
/// only when every payload matcher `a` accepts is also accepted by matcher `b`
/// (`L(a) ⊆ L(b)`). A `true` result is a proof; a `false` result means "not
/// proven", never "disproven". The winner-selection guard in
/// [`crate::engine::best_match`] relies on that direction: an unproven subset
/// falls back to the more-restrictive rule, so incompleteness only ever fails
/// closed (§6.3a).
pub(crate) fn matcher_subset(a: &Matcher, b: &Matcher) -> bool {
    // `b` accepts every payload, so anything is a subset of it.
    if let Matcher::Bare = b {
        return true;
    }
    match (a, b) {
        // `a` accepts everything but `b` does not (handled above), so not a subset.
        (Matcher::Bare, _) => false,

        (Matcher::Bash(am), Matcher::Bash(bm)) => match (am, bm) {
            // A `cmd:*` container matches `p` or `p` + boundary + args, so proving
            // containment is structural: `a`'s guaranteed leading text must extend
            // `b`'s prefix at a word boundary.
            (BashMatcher::Prefix(ap), BashMatcher::Prefix(bp)) => {
                ap == bp || starts_at_boundary(ap, bp)
            }
            (BashMatcher::Glob(ag), BashMatcher::Prefix(bp)) => {
                starts_at_boundary(glob_leading_literal(ag), bp)
            }
            // A `Glob` container is a plain `*`-glob (no boundary rule), so the
            // token engine decides it exactly. A `Prefix` on the `a` side is
            // over-approximated to `lit·**`, which is sound: proving the larger
            // set is contained proves the real one is.
            (BashMatcher::Glob(ag), BashMatcher::Glob(bg)) => {
                tokens_contain(&glob_str_to_tokens(bg), &glob_str_to_tokens(ag), false)
            }
            (BashMatcher::Prefix(ap), BashMatcher::Glob(bg)) => {
                let mut approx = str_to_lit_tokens(ap);
                approx.push(PToken::DStar);
                tokens_contain(&glob_str_to_tokens(bg), &approx, false)
            }
        },

        // Both path globs compile to the same token vocabulary; the token engine
        // decides containment exactly over it, with path `**/`-collapse semantics.
        (Matcher::Path(am), Matcher::Path(bm)) => tokens_contain(&bm.0, &am.0, true),

        // URL/string globs use `*` as an any-run wildcard with no path structure,
        // so no `**/`-collapse (matches [`glob_star_match`]).
        (Matcher::Generic(am), Matcher::Generic(bm)) => tokens_contain(
            &glob_str_to_tokens(&bm.0),
            &glob_str_to_tokens(&am.0),
            false,
        ),

        // Different families never share a payload space here.
        _ => false,
    }
}

/// Do matchers `a` and `b` share at least one payload (`L(a) ∩ L(b) ≠ ∅`)? Used
/// by the author-time conflict lint (§6.3a) to tell a genuine overlap from two
/// unrelated rules. Under-approximates (a Bash prefix is over-approximated to
/// `lit·**`, and the path `**/`-collapse is not modeled), so it errs toward
/// *fewer* conflict warnings, never a false alarm from a non-overlap.
pub(crate) fn matchers_intersect(a: &Matcher, b: &Matcher) -> bool {
    match (a, b) {
        // Bare matches everything, so it intersects any non-empty language.
        (Matcher::Bare, _) | (_, Matcher::Bare) => true,

        (Matcher::Bash(am), Matcher::Bash(bm)) => match (am, bm) {
            // Two prefix languages share a command only when one prefix extends
            // the other at a word boundary (a command cannot start with both
            // `git push` and `git pull`).
            (BashMatcher::Prefix(ap), BashMatcher::Prefix(bp)) => {
                ap == bp || starts_at_boundary(ap, bp) || starts_at_boundary(bp, ap)
            }
            (BashMatcher::Glob(g), BashMatcher::Prefix(p))
            | (BashMatcher::Prefix(p), BashMatcher::Glob(g)) => prefix_glob_intersect(p, g),
            (BashMatcher::Glob(g1), BashMatcher::Glob(g2)) => {
                globs_can_intersect(&glob_str_to_tokens(g1), &glob_str_to_tokens(g2))
            }
        },

        (Matcher::Path(am), Matcher::Path(bm)) => globs_can_intersect(&am.0, &bm.0),

        (Matcher::Generic(am), Matcher::Generic(bm)) => {
            globs_can_intersect(&glob_str_to_tokens(&am.0), &glob_str_to_tokens(&bm.0))
        }

        _ => false,
    }
}

/// Does a Bash glob `g` share a command with a `cmd:*` prefix `p`? A prefix
/// matches `p` exactly or `p` + whitespace + args, so the two alternatives are
/// tested separately: `g` matching the bare `p`, or `g` intersecting
/// `p`·space·`**`. Modeling the boundary (rather than over-approximating `p` to
/// `p·**`) is what stops a false overlap like `Bash(.:*)` vs
/// `Bash(.venv/bin/python *)`.
fn prefix_glob_intersect(p: &str, g: &str) -> bool {
    if glob_star_match(p.as_bytes(), g.as_bytes()) {
        return true; // the glob matches the bare prefix command
    }
    let mut pt = str_to_lit_tokens(p);
    pt.push(PToken::Lit(b' '));
    pt.push(PToken::DStar);
    globs_can_intersect(&glob_str_to_tokens(g), &pt)
}

/// True when every string beginning with `s` also begins with `prefix` followed
/// by a word boundary, i.e. `s` strictly extends `prefix` at a whitespace break.
/// This is the containment rule for the Bash `cmd:*` prefix form.
fn starts_at_boundary(s: &str, prefix: &str) -> bool {
    s.len() > prefix.len()
        && s.starts_with(prefix)
        && s.as_bytes()[prefix.len()].is_ascii_whitespace()
}

/// The literal run of a Bash glob up to its first `*` (every matched string
/// begins with this text).
fn glob_leading_literal(g: &str) -> &str {
    g.split('*').next().unwrap_or(g)
}

/// Compile a Bash/Generic glob string into path-glob tokens. Their `*` spans any
/// run of any byte (separators included), so it maps to [`PToken::DStar`]; runs
/// of `*` collapse to one. Every other byte is literal.
fn glob_str_to_tokens(s: &str) -> Vec<PToken> {
    let b = s.as_bytes();
    let mut t = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'*' {
            t.push(PToken::DStar);
            while i < b.len() && b[i] == b'*' {
                i += 1;
            }
        } else {
            t.push(PToken::Lit(b[i]));
            i += 1;
        }
    }
    t
}

/// Every byte of `s` as a literal token (no wildcards).
fn str_to_lit_tokens(s: &str) -> Vec<PToken> {
    s.bytes().map(PToken::Lit).collect()
}

/// Byte-class an NFA transition consumes: a concrete byte, or `Other` standing
/// for every non-`/` byte not named by any `Lit` in the two patterns. Two bytes
/// in the same class are indistinguishable to `Lit`/`?`/`*`/`**`, so testing one
/// representative per class decides containment exactly (§6.3a).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cls {
    Byte(u8),
    Other,
}

/// How a token consumes one input class.
enum Step {
    /// Advance past the token (it matched exactly one char).
    Advance,
    /// Stay on the token (a spanning wildcard consumed one char, more may follow).
    Stay,
    /// The token rejects this class.
    No,
}

fn token_step(tok: PToken, cls: Cls) -> Step {
    match tok {
        PToken::Lit(c) => match cls {
            Cls::Byte(x) if x == c => Step::Advance,
            _ => Step::No,
        },
        // `?` and `*` span non-separator bytes; `?` consumes exactly one, `*`
        // may consume more.
        PToken::Ques => match cls {
            Cls::Byte(b'/') => Step::No,
            _ => Step::Advance,
        },
        PToken::Star => match cls {
            Cls::Byte(b'/') => Step::No,
            _ => Step::Stay,
        },
        // `**` spans any byte, separators included.
        PToken::DStar => Step::Stay,
    }
}

/// Epsilon-closure: a `*`/`**` position also reaches the next position by matching
/// the empty string. With `collapse` (path semantics), a `**/` pair also reaches
/// the position past the `/`, so `/**/.env` matches `/.env` -- the zero-directory
/// case [`path_match`] handles specially. Positions are bits (`1 << p`); bit `len`
/// is the accepting (fully-consumed) position.
fn eclose(pat: &[PToken], mut set: u64, collapse: bool) -> u64 {
    loop {
        let mut next = set;
        for (p, &tok) in pat.iter().enumerate() {
            if set & (1 << p) == 0 {
                continue;
            }
            if matches!(tok, PToken::Star | PToken::DStar) {
                next |= 1 << (p + 1);
            }
            if collapse
                && matches!(tok, PToken::DStar)
                && matches!(pat.get(p + 1), Some(PToken::Lit(b'/')))
            {
                next |= 1 << (p + 2);
            }
        }
        if next == set {
            return set;
        }
        set = next;
    }
}

/// Move an NFA position set over one input class, then epsilon-close.
fn step_set(pat: &[PToken], set: u64, cls: Cls, collapse: bool) -> u64 {
    let mut out = 0u64;
    for (p, &tok) in pat.iter().enumerate() {
        if set & (1 << p) == 0 {
            continue;
        }
        match token_step(tok, cls) {
            Step::Advance => out |= 1 << (p + 1),
            Step::Stay => out |= 1 << p,
            Step::No => {}
        }
    }
    eclose(pat, out, collapse)
}

/// Does pattern `b` match every string pattern `a` matches (`L(a) ⊆ L(b)`)?
///
/// Product search over `(a-positions, b-positions)` NFA state sets: if a reachable
/// state has `a` accepting while `b` does not, the string read so far witnesses
/// `L(a) \ L(b)` and containment fails. Exact over the token vocabulary. Bounded:
/// patterns longer than 62 tokens, or a search that exceeds the visited cap, fail
/// closed (return `false`), matching the trusted-rules stance in §9.2.
///
/// `collapse` selects path (`**/`-collapsing) vs plain-glob semantics, so the
/// model matches the family's real matcher exactly on both sides.
fn tokens_contain(b: &[PToken], a: &[PToken], collapse: bool) -> bool {
    if a.len() > 62 || b.len() > 62 {
        return false;
    }
    let (la, lb) = (a.len(), b.len());
    let a_acc = 1u64 << la;
    let b_acc = 1u64 << lb;

    // Alphabet: one representative per class -- every `Lit` byte, `/`, and `Other`.
    let mut classes: Vec<Cls> = vec![Cls::Byte(b'/'), Cls::Other];
    for &tok in a.iter().chain(b.iter()) {
        if let PToken::Lit(c) = tok
            && c != b'/'
            && !classes.iter().any(|k| matches!(k, Cls::Byte(x) if *x == c))
        {
            classes.push(Cls::Byte(c));
        }
    }

    let start = (eclose(a, 1, collapse), eclose(b, 1, collapse));
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![start];
    while let Some((sa, sb)) = stack.pop() {
        if !visited.insert((sa, sb)) {
            continue;
        }
        if visited.len() > 20_000 {
            return false; // sound bail: unproven -> caller fails closed
        }
        if sa & a_acc != 0 && sb & b_acc == 0 {
            return false; // witness in L(a) \ L(b)
        }
        for &cls in &classes {
            let na = step_set(a, sa, cls, collapse);
            if na == 0 {
                continue; // no a-string continues with this class
            }
            let nb = step_set(b, sb, cls, collapse);
            stack.push((na, nb));
        }
    }
    true
}

// --- Glob-operand cross-check (§8.3) -----------------------------------------

/// Does `candidate` carry a shell glob metacharacter (`*`, `?`, `[`)?
fn has_glob_meta(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, b'*' | b'?' | b'['))
}

/// True if any path segment of `s` begins with a glob metacharacter. A shell
/// leaves such a wildcard from matching a leading `.` (hidden files), so a
/// segment-leading wildcard cannot resolve to a dotfile like `.env`; we defer
/// those to the literal check and never escalate them (avoids over-denying
/// ordinary globs such as `cat *.rs`).
fn has_segment_leading_wildcard(s: &str) -> bool {
    let mut seg_start = true;
    for &c in s.as_bytes() {
        if seg_start && matches!(c, b'*' | b'?' | b'[') {
            return true;
        }
        seg_start = c == b'/';
    }
    false
}

/// Compile a Bash reader operand into path-glob tokens. Shell semantics: `*` and
/// `?` span non-`/` runs, `[…]` a single char (over-approximated to `?`). Any
/// `**` run collapses to a single `*` (shell globstar is off by default).
fn compile_operand_glob(s: &str) -> Vec<PToken> {
    let b = s.as_bytes();
    let mut t = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'*' => {
                t.push(PToken::Star);
                i += 1;
                while i < b.len() && b[i] == b'*' {
                    i += 1;
                }
            }
            b'?' => {
                t.push(PToken::Ques);
                i += 1;
            }
            b'[' => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b']' {
                    j += 1;
                }
                if j < b.len() {
                    t.push(PToken::Ques); // a class matches one char
                    i = j + 1;
                } else {
                    t.push(PToken::Lit(b'[')); // unterminated: literal
                    i += 1;
                }
            }
            c => {
                t.push(PToken::Lit(c));
                i += 1;
            }
        }
    }
    t
}

/// True if a `Read`/`Write` deny rule matches `candidate`, extended to catch a
/// glob operand that could expand onto a denied path (§8.3). Escalation is
/// monotone: it only ever adds a hit, and only for glob operands whose every
/// segment begins with a literal (see [`has_segment_leading_wildcard`]), so
/// ordinary reads and non-glob operands keep their exact behavior.
pub(crate) fn path_glob_hits(m: &Matcher, candidate: &str) -> bool {
    if m.matches(candidate) {
        return true;
    }
    if !has_glob_meta(candidate) || has_segment_leading_wildcard(candidate) {
        return false;
    }
    match m {
        Matcher::Path(pm) => globs_can_intersect(&pm.0, &compile_operand_glob(candidate)),
        Matcher::Bare => true,
        _ => false,
    }
}

/// Can two path globs share a concrete string? Product-automaton reachability
/// over token positions `(i, j)`, where a wildcard either matches one shared
/// character (staying put) or matches empty (advancing). Both inputs are short
/// operator/operand globs, so the `(len+1)²` state space is tiny.
fn globs_can_intersect(a: &[PToken], b: &[PToken]) -> bool {
    let (la, lb) = (a.len(), b.len());
    let width = lb + 1;
    let mut visited = vec![false; (la + 1) * width];
    let mut stack = vec![(0usize, 0usize)];
    visited[0] = true;
    while let Some((i, j)) = stack.pop() {
        if i == la && j == lb {
            return true;
        }
        let ta = a.get(i).copied();
        let tb = b.get(j).copied();
        // A wildcard on either side may match the empty string and advance.
        if matches!(ta, Some(PToken::Star) | Some(PToken::DStar)) && !visited[(i + 1) * width + j] {
            visited[(i + 1) * width + j] = true;
            stack.push((i + 1, j));
        }
        if matches!(tb, Some(PToken::Star) | Some(PToken::DStar)) && !visited[i * width + j + 1] {
            visited[i * width + j + 1] = true;
            stack.push((i, j + 1));
        }
        // Consume one character both sides accept.
        if let (Some(ta), Some(tb)) = (ta, tb)
            && tokens_share_char(ta, tb)
        {
            let ni = if matches!(ta, PToken::Star | PToken::DStar) {
                i
            } else {
                i + 1
            };
            let nj = if matches!(tb, PToken::Star | PToken::DStar) {
                j
            } else {
                j + 1
            };
            if (ni, nj) != (i, j) && !visited[ni * width + nj] {
                visited[ni * width + nj] = true;
                stack.push((ni, nj));
            }
        }
    }
    false
}

/// Do two glob tokens accept a common single character?
fn tokens_share_char(a: PToken, b: PToken) -> bool {
    use PToken::*;
    match (a, b) {
        (Lit(x), Lit(y)) => x == y,
        // A `?`/`*` spans one non-separator byte; a literal `/` cannot fill it.
        (Lit(c), Ques | Star) | (Ques | Star, Lit(c)) => c != b'/',
        // `**` spans any byte, separators included.
        (Lit(_), DStar) | (DStar, Lit(_)) => true,
        // Any two wildcards agree on an ordinary character.
        _ => true,
    }
}

/// Anchored, full-string glob match with `/`-aware wildcards (§6.5).
///
/// Plain recursive backtracking. Path specifiers come from the operator-authored
/// rule set (`permcheck.json` is the source of truth), so they are trusted and
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

#[cfg(test)]
mod subset_tests {
    use super::*;
    use crate::types::Family;

    fn m(family: Family, spec: &str) -> Matcher {
        compile(family, spec).expect("spec compiles").0
    }

    fn subset(family: Family, a: &str, b: &str) -> bool {
        matcher_subset(&m(family, a), &m(family, b))
    }

    #[test]
    fn bash_glob_subset_of_broad_prefix() {
        // `aws * describe-*` only ever matches `aws`-prefixed commands, so it is a
        // proven subset of the broad `aws:*` deny. The reverse is false.
        assert!(subset(Family::Bash, "aws * describe-*", "aws:*"));
        assert!(!subset(Family::Bash, "aws:*", "aws * describe-*"));
    }

    #[test]
    fn bash_longer_but_broader_is_not_a_subset() {
        // The inversion case: a longer allow that is not a subset of a shorter
        // deny. `kubectl * --namespace prod` also matches `kubectl get ...`, so it
        // is NOT contained in `kubectl delete:*`, in either direction.
        assert!(!subset(
            Family::Bash,
            "kubectl * --namespace prod",
            "kubectl delete:*"
        ));
        assert!(!subset(
            Family::Bash,
            "kubectl delete:*",
            "kubectl * --namespace prod"
        ));
    }

    #[test]
    fn bash_prefix_extends_prefix_at_boundary() {
        assert!(subset(Family::Bash, "git push --force:*", "git push:*"));
        assert!(!subset(Family::Bash, "git push:*", "git push --force:*"));
        // A prefix that shares leading bytes without a word boundary is not a
        // subset: `gitfoo` is not a `git ...` command.
        assert!(!subset(Family::Bash, "gitfoo:*", "git:*"));
    }

    #[test]
    fn path_narrow_glob_subset_of_broad() {
        assert!(subset(Family::Path, "/tmp/**", "/**/*"));
        assert!(!subset(Family::Path, "/**/*", "/tmp/**"));
        // Longer-but-not-contained: `/**/passwd` also matches `/home/passwd`.
        assert!(!subset(Family::Path, "/**/passwd", "/etc/**"));
        // A literal path is a subset of a glob that matches it.
        assert!(subset(Family::Path, "/etc/passwd", "/etc/**"));
    }

    #[test]
    fn path_double_star_collapse_is_modeled() {
        // `/**/.env` matches `/.env` (zero directories). A literal `/.env` allow
        // is therefore a proven subset of the `/**/.env` deny.
        assert!(subset(Family::Path, "/.env", "/**/.env"));
    }

    #[test]
    fn generic_literal_subset_of_star() {
        assert!(subset(Family::Generic, "docs.internal.co", "*"));
        assert!(!subset(Family::Generic, "*", "docs.internal.co"));
    }

    #[test]
    fn bare_is_top_and_only_subset_of_bare() {
        let bare = Matcher::Bare;
        let glob = m(Family::Path, "/etc/**");
        assert!(matcher_subset(&glob, &bare)); // anything ⊆ Bare
        assert!(!matcher_subset(&bare, &glob)); // Bare ⊄ a restrictive glob
        assert!(matcher_subset(&bare, &Matcher::Bare));
    }

    #[test]
    fn ques_and_star_containment() {
        // `?` matches one non-`/`, contained in `*`; `*` is not contained in `?`.
        assert!(subset(Family::Path, "/foo?", "/foo*"));
        assert!(!subset(Family::Path, "/foo*", "/foo?"));
    }

    /// Brute-force soundness: whenever `matcher_subset(a, b)` reports true, every
    /// string `a` matches must also be matched by `b`. This is the safety-critical
    /// direction -- a false positive here would let a less-restrictive rule
    /// override a deny it does not actually refine. We enumerate all strings up to
    /// length 6 over a small alphabet that includes the separator and the literal
    /// bytes used in the patterns, and check the guarantee for every ordered pair.
    #[test]
    fn subset_true_implies_real_containment() {
        let specs = [
            "/**/*",
            "/tmp/**",
            "/tmp/*",
            "/**/.env",
            "/etc/**",
            "/etc/passwd",
            "/a/b",
            "/a?b",
            "/a*",
            "/**/x",
            "/x",
        ];
        let matchers: Vec<Matcher> = specs.iter().map(|s| m(Family::Path, s)).collect();
        let alphabet = b"/abx.envp";

        let mut buf = Vec::new();
        for a in &matchers {
            for b in &matchers {
                if !matcher_subset(a, b) {
                    continue;
                }
                enumerate(alphabet, 6, &mut buf, &mut |s| {
                    if let Ok(text) = std::str::from_utf8(s) {
                        assert!(
                            !a.matches(text) || b.matches(text),
                            "unsound: subset claimed but {text:?} matches a, not b"
                        );
                    }
                });
            }
        }
    }

    /// Enumerate every byte string of length `0..=max` over `alphabet`, calling
    /// `f` on each. Used by the brute-force soundness check.
    fn enumerate(alphabet: &[u8], max: usize, buf: &mut Vec<u8>, f: &mut impl FnMut(&[u8])) {
        f(buf);
        if buf.len() == max {
            return;
        }
        for &c in alphabet {
            buf.push(c);
            enumerate(alphabet, max, buf, f);
            buf.pop();
        }
    }
}
