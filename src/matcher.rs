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
            BashMatcher::Prefix(prefix) => prefix_covers(prefix, cmd),
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

// --- Containment / carve-out subset test (§6.3) ------------------------------

/// True when every payload `a` matches is also matched by `d`, i.e.
/// `L(a) ⊆ L(d)`. Used by the engine to decide whether an allow/ask rule is a
/// genuine *carve-out* of a deny (a strict refinement) and so overrides it; on
/// any other overlap the deny wins (§6.3).
///
/// The test is **sound but deliberately incomplete**: it returns `true` only when
/// containment is proven, and falls back to `false` otherwise. A false negative
/// keeps the deny, biasing toward `deny`, which matches the fail-closed posture
/// (§9.2). A false positive would neutralize a deny that should hold, so the
/// procedure never guesses.
pub(crate) fn matcher_subset(a: &Matcher, d: &Matcher) -> bool {
    match (a, d) {
        // A bare deny matches everything, so any allow is a subset of it.
        (_, Matcher::Bare) => true,
        // A bare allow (matches everything) refines only a universal deny.
        (Matcher::Bare, _) => is_universal(d),
        (Matcher::Path(pa), Matcher::Path(pd)) => tokens_subset(&pa.0, &pd.0),
        (Matcher::Generic(ga), Matcher::Generic(gd)) => tokens_subset(
            &glob_to_tokens(ga.0.as_bytes()),
            &glob_to_tokens(gd.0.as_bytes()),
        ),
        (Matcher::Bash(ba), Matcher::Bash(bd)) => bash_subset(ba, bd),
        // Cross-family rules never share a tool, so this is unreachable in
        // practice; conservatively not a subset.
        _ => false,
    }
}

/// Does this matcher accept every possible payload?
fn is_universal(m: &Matcher) -> bool {
    match m {
        Matcher::Bare => true,
        Matcher::Path(p) => matches!(p.0.as_slice(), [PToken::DStar]),
        Matcher::Generic(g) => g.0 == "*",
        Matcher::Bash(BashMatcher::Glob(s)) => s == "*",
        Matcher::Bash(BashMatcher::Prefix(_)) => false,
    }
}

/// Compile a `*`-only glob (Bash `Glob`, Generic) into path tokens: `*` becomes
/// `**` (it spans separators in these families) and every other byte is literal.
fn glob_to_tokens(bytes: &[u8]) -> Vec<PToken> {
    let mut t = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'*' {
            t.push(PToken::DStar);
            i += 1;
            while i < bytes.len() && bytes[i] == b'*' {
                i += 1;
            }
        } else {
            t.push(PToken::Lit(bytes[i]));
            i += 1;
        }
    }
    t
}

/// True if command `cmd` is accepted by the trailing-`:*` prefix specifier `pre`
/// (matches `pre` exactly, or `pre` followed by whitespace then anything). The
/// single definition of prefix matching, used both by [`BashMatcher::matches`] and
/// by the prefix-containment subset test.
fn prefix_covers(pre: &str, cmd: &str) -> bool {
    cmd == pre
        || (cmd.len() > pre.len()
            && cmd.starts_with(pre)
            && cmd.as_bytes()[pre.len()].is_ascii_whitespace())
}

/// Subset test between two Bash specifiers.
fn bash_subset(a: &BashMatcher, d: &BashMatcher) -> bool {
    match (a, d) {
        // `L(a-prefix) ⊆ L(d-prefix)` when `d` commits before `a` varies, i.e. `a`
        // (the shortest string `a` accepts) is itself accepted by `d`.
        (BashMatcher::Prefix(pa), BashMatcher::Prefix(pd)) => prefix_covers(pd, pa),
        // A glob whose fixed leading literal already clears `d`'s prefix boundary
        // is contained in the prefix (`aws * describe-* ⊆ aws:*`).
        (BashMatcher::Glob(ga), BashMatcher::Prefix(pd)) => {
            let lit = ga.split('*').next().unwrap_or(ga);
            if !ga.contains('*') {
                return prefix_covers(pd, ga);
            }
            lit.len() > pd.len()
                && lit.starts_with(pd)
                && lit.as_bytes()[pd.len()].is_ascii_whitespace()
        }
        (BashMatcher::Glob(ga), BashMatcher::Glob(gd)) => tokens_subset(
            &glob_to_tokens(ga.as_bytes()),
            &glob_to_tokens(gd.as_bytes()),
        ),
        // A prefix's language is `pre` or `pre` + whitespace + anything. Over-
        // approximate it as `pre` + `**` (more strings, so proving subset stays
        // sound) and test against the glob.
        (BashMatcher::Prefix(pa), BashMatcher::Glob(gd)) => {
            let mut toks = glob_to_tokens(pa.as_bytes());
            toks.push(PToken::DStar);
            tokens_subset(&toks, &glob_to_tokens(gd.as_bytes()))
        }
    }
}

/// Sound, incomplete decision of `L(a) ⊆ L(d)` over path-glob tokens.
///
/// `d` is treated as a DFA via on-the-fly subset construction (`dstate` is the set
/// of live `d` positions), so the deny side is deterministic and `dstate`'s
/// accepting test is exact. `a` is then walked with its wildcards universally
/// quantified over representative characters; containment holds only when every
/// branch keeps `d` alive and accepting. Revisiting a `(position, dstate)` pair is
/// treated as success (greatest-fixpoint over the safety property). Returns `false`
/// for oversized or budget-exceeding inputs — always the safe direction.
fn tokens_subset(a: &[PToken], d: &[PToken]) -> bool {
    // `dstate` is a bitset over positions `0..=d.len()`, so `d.len()` must index
    // into a u128. Oversized patterns (never real rules) fail closed.
    if d.len() >= 127 || a.len() >= 127 {
        return false;
    }
    let lits = d_literals(d);
    let fresh = fresh_byte(&lits);
    // Representative characters an `a`-wildcard adversary may pick. `/` is kept
    // separate because `?`/`*` reject it while `**` accepts it.
    let mut reps_nonsep: Vec<u8> = lits.iter().copied().filter(|&b| b != b'/').collect();
    reps_nonsep.push(fresh);
    let mut reps_all = reps_nonsep.clone();
    reps_all.push(b'/');

    let start = closure_d(d, 1u128);
    let mut ctx = InclCtx {
        d,
        reps_nonsep: &reps_nonsep,
        reps_all: &reps_all,
        seen: std::collections::HashSet::new(),
        budget: 100_000,
    };
    incl(a, 0, start, &mut ctx)
}

struct InclCtx<'a> {
    d: &'a [PToken],
    reps_nonsep: &'a [u8],
    reps_all: &'a [u8],
    seen: std::collections::HashSet<(usize, u128)>,
    budget: usize,
}

fn incl(a: &[PToken], i: usize, dstate: u128, ctx: &mut InclCtx) -> bool {
    // `d` has died: a string `a` produces is rejected by `d`, so not a subset.
    if dstate == 0 {
        return false;
    }
    if ctx.budget == 0 {
        return false; // ran out of exploration budget: fail closed.
    }
    if !ctx.seen.insert((i, dstate)) {
        return true; // already under evaluation: no new violation on this cycle.
    }
    ctx.budget -= 1;
    let accepting = dstate & (1u128 << ctx.d.len()) != 0;
    if i == a.len() {
        return accepting; // `a` ends; `d` must accept the empty continuation.
    }
    match a[i] {
        PToken::Lit(c) => {
            let ns = step_d(ctx.d, dstate, c);
            incl(a, i + 1, ns, ctx)
        }
        // A single non-`/` char: advance past `?`, requiring every representative.
        PToken::Ques => all_reps(a, i + 1, dstate, ctx.reps_nonsep.to_vec(), ctx),
        // Star ends now (advance), or consumes one non-`/` char and stays at `i`.
        PToken::Star => {
            incl(a, i + 1, dstate, ctx) && all_reps(a, i, dstate, ctx.reps_nonsep.to_vec(), ctx)
        }
        // `**` ends now, or consumes any char (separators included) and stays.
        PToken::DStar => {
            incl(a, i + 1, dstate, ctx) && all_reps(a, i, dstate, ctx.reps_all.to_vec(), ctx)
        }
    }
}

/// Require containment for every representative character, stepping `d` on each
/// and continuing `a` from `next_i` (the caller passes `i` to stay on a spanning
/// wildcard, or `i + 1` to advance past a single-character one).
fn all_reps(a: &[PToken], next_i: usize, dstate: u128, reps: Vec<u8>, ctx: &mut InclCtx) -> bool {
    reps.iter().all(|&ch| {
        let ns = step_d(ctx.d, dstate, ch);
        incl(a, next_i, ns, ctx)
    })
}

/// Distinct literal bytes appearing in `d`.
fn d_literals(d: &[PToken]) -> Vec<u8> {
    let mut v: Vec<u8> = d
        .iter()
        .filter_map(|t| {
            if let PToken::Lit(c) = t {
                Some(*c)
            } else {
                None
            }
        })
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// A byte that is neither `/` nor any of `d`'s literals — one representative for
/// "every other character", which all of `d`'s tokens treat identically.
fn fresh_byte(lits: &[u8]) -> u8 {
    (1u8..=255)
        .find(|b| *b != b'/' && !lits.contains(b))
        .unwrap_or(0)
}

/// Epsilon-closure of a `d` state: nullable tokens (`*`, `**`) let a live position
/// advance without consuming a character.
fn closure_d(d: &[PToken], mut bits: u128) -> u128 {
    loop {
        let mut nb = bits;
        for (j, tok) in d.iter().enumerate() {
            if bits & (1u128 << j) != 0 && matches!(tok, PToken::Star | PToken::DStar) {
                nb |= 1u128 << (j + 1);
            }
        }
        if nb == bits {
            return bits;
        }
        bits = nb;
    }
}

/// Transition of a (closed) `d` state on one concrete character.
fn step_d(d: &[PToken], bits: u128, ch: u8) -> u128 {
    let sep = ch == b'/';
    let mut nb = 0u128;
    for (j, tok) in d.iter().enumerate() {
        if bits & (1u128 << j) == 0 {
            continue;
        }
        match *tok {
            PToken::Lit(c) => {
                if ch == c {
                    nb |= 1u128 << (j + 1);
                }
            }
            PToken::Ques => {
                if !sep {
                    nb |= 1u128 << (j + 1);
                }
            }
            PToken::Star => {
                if !sep {
                    nb |= 1u128 << j; // stay inside the star; ending is a closure move
                }
            }
            PToken::DStar => {
                nb |= 1u128 << j; // spans any character, separators included
            }
        }
    }
    closure_d(d, nb)
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
        compile(family, spec).unwrap().0
    }

    fn path_subset(a: &str, d: &str) -> bool {
        matcher_subset(&m(Family::Path, a), &m(Family::Path, d))
    }

    #[test]
    fn literal_is_subset_of_covering_glob() {
        assert!(path_subset("/etc/passwd", "/etc/**"));
        assert!(path_subset("/etc/passwd", "/etc/*"));
        assert!(path_subset("/a/b/c", "/**/c"));
    }

    #[test]
    fn overlapping_but_uncontained_globs_are_not_subsets() {
        // The `/etc/passwd` case: neither refines the other.
        assert!(!path_subset("/**/passwd", "/etc/**"));
        // Incomparable: `*.conf` vs `secret*`.
        assert!(!path_subset("/etc/*.conf", "/etc/secret*"));
        assert!(!path_subset("/etc/secret*", "/etc/*.conf"));
    }

    #[test]
    fn star_and_dstar_separator_semantics() {
        // `*` stays within one segment, so it is contained in `**`.
        assert!(path_subset("/a/*", "/a/**"));
        // `**` crosses separators, so it is not contained in a single-segment `*`.
        assert!(!path_subset("/a/**", "/a/*"));
        // `**` matches everything.
        assert!(path_subset("/etc/passwd", "**"));
    }

    #[test]
    fn equal_patterns_are_mutual_subsets() {
        // Used by the engine's strict-carve-out test: equal match-sets are subsets
        // both ways, so an identical allow never carves out a deny.
        assert!(path_subset("/etc/**", "/etc/**"));
    }

    #[test]
    fn bash_glob_is_subset_of_prefix() {
        let a = m(Family::Bash, "aws * describe-*");
        let d = m(Family::Bash, "aws:*");
        assert!(matcher_subset(&a, &d));
        // The prefix is not a subset of the narrower glob.
        assert!(!matcher_subset(&d, &a));
    }

    #[test]
    fn anything_is_subset_of_bare_only_universal_covers_bare() {
        let narrow = m(Family::Path, "/etc/passwd");
        assert!(matcher_subset(&narrow, &Matcher::Bare));
        // A bare allow refines only a universal deny, not a narrow one.
        assert!(!matcher_subset(&Matcher::Bare, &narrow));
        assert!(matcher_subset(&Matcher::Bare, &m(Family::Path, "**")));
    }
}
