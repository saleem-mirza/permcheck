//! Per-family matchers and specificity scoring (§6.1, §6.5). [`compile`] turns a
//! specifier into a [`Matcher`] plus its specificity score; globbing is
//! hand-written (no `regex`) to keep cold start in microseconds.

use crate::types::Family;
use std::borrow::Cow;
use std::sync::OnceLock;

/// Bonus added to a specifier's literal-character count when it contains no
/// wildcard at all, so a literal specifier outranks any wildcard one (§6.1).
pub const EXACT_MATCH_BONUS: u32 = 1000;

/// Maximum dynamic-programming/NFA state visits for one matcher invocation.
/// The engine turns exhaustion into `deny`; the public boolean compatibility
/// method returns `false`, which never grants a match on its own.
const MAX_MATCH_STATES: usize = 2_000_000;

/// Maximum aggregate matcher work for one tool-call decision. Individual
/// matches retain the tighter bound above; this second limit prevents thousands
/// of individually valid misses from accumulating into seconds of hook latency.
const MAX_DECISION_MATCH_STATES: usize = 20_000_000;

/// Remaining matcher work for one complete decision. Created at the family
/// boundary and threaded through every normalized form and cross-check.
pub(crate) struct WorkBudget {
    remaining: usize,
}

impl WorkBudget {
    pub(crate) fn new() -> Self {
        Self {
            remaining: MAX_DECISION_MATCH_STATES,
        }
    }

    fn single_match() -> Self {
        Self {
            remaining: MAX_MATCH_STATES,
        }
    }

    fn consume(&mut self, work: usize) -> Result<(), ()> {
        self.remaining = self.remaining.checked_sub(work).ok_or(())?;
        Ok(())
    }
}

/// The home directory, read once and cached for the process lifetime, in a
/// POSIX-anchored form (see [`normalize_root`]).
pub(crate) fn home_dir() -> &'static str {
    static HOME: OnceLock<String> = OnceLock::new();
    HOME.get_or_init(|| normalize_root(&raw_home().unwrap_or_default()))
}

/// Expand a leading `~` naming the caller's own home: `~` alone and `~/rest`.
/// `~user` stays literal, another user's home being unknowable (§7.2). Shared by
/// specifier compilation and both payload resolvers, so they agree.
pub(crate) fn expand_tilde(path: &str) -> Option<String> {
    if path == "~" {
        return Some(home_dir().to_string());
    }
    path.strip_prefix("~/")
        .map(|rest| format!("{}/{}", home_dir(), rest))
}

/// The home directory as the environment reports it, before normalization. Single
/// source of truth for `~` expansion ([`home_dir`]) and `--install` path
/// resolution, so they cannot disagree. POSIX has only `$HOME`.
#[cfg(not(windows))]
pub fn raw_home() -> Option<String> {
    std::env::var("HOME").ok().filter(|s| !s.is_empty())
}

/// MSYS/Git-Bash sets `$HOME`, native shells `%USERPROFILE%`, older ones only
/// `%HOMEDRIVE%%HOMEPATH%`.
#[cfg(windows)]
pub fn raw_home() -> Option<String> {
    if let Some(home) = std::env::var("HOME").ok().filter(|s| !s.is_empty()) {
        return Some(home);
    }
    if let Some(profile) = std::env::var("USERPROFILE").ok().filter(|s| !s.is_empty()) {
        return Some(profile);
    }
    match (std::env::var("HOMEDRIVE"), std::env::var("HOMEPATH")) {
        (Ok(drive), Ok(path)) if !drive.is_empty() && !path.is_empty() => {
            Some(format!("{drive}{path}"))
        }
        _ => None,
    }
}

/// Normalize an absolute base path (a CWD or home dir) into a POSIX-anchored form
/// so the `/`-based Path globs match. Identity on POSIX, where it compiles out;
/// the Windows twin below is the only platform-specific behavior.
#[cfg(not(windows))]
#[inline]
pub fn normalize_root(dir: &str) -> String {
    dir.to_string()
}

/// A Windows base is a drive-letter path with backslashes (`D:\proj`); fold `\` to
/// `/` and prepend `/` to the drive root, so `D:\proj` becomes `/D:/proj`, which a
/// rule like `/**/.env*` matches. An already-`/`-rooted MSYS form is left alone.
#[cfg(windows)]
pub fn normalize_root(dir: &str) -> String {
    if dir.starts_with('/') {
        return dir.to_string();
    }
    let slashed = fold_separators(dir);
    let b = slashed.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        // `X:/…` is drive-rooted and only needs the leading `/`. `X:rest` is
        // drive-relative, and anchoring it as `/X:rest` matches no `/X:/**` rule at
        // all, so anchor at the drive root; [`drive_relative_join`] refines it.
        if b.get(2) == Some(&b'/') {
            format!("/{slashed}")
        } else {
            format!("/{}/{}", &slashed[..2], &slashed[2..])
        }
    } else {
        slashed.into_owned()
    }
}

/// Resolve a Windows drive-relative payload (`C:notes.txt`) against `cwd`, the only
/// way to learn that drive's current directory. `None` unless `cwd` names the same
/// drive. Purely additive on the drive-root form, so it can only add a match.
#[cfg(windows)]
pub(crate) fn drive_relative_join(payload: &str, cwd: &str) -> Option<String> {
    let p = payload.as_bytes();
    let is_drive_relative = p.len() >= 2
        && p[0].is_ascii_alphabetic()
        && p[1] == b':'
        && !matches!(p.get(2), Some(b'/' | b'\\'));
    if !is_drive_relative {
        return None;
    }
    // `normalize_root` anchors the cwd as `/C:/work`, so the drive letter sits
    // between the leading slash and the colon.
    let base = normalize_root(cwd);
    let same_drive =
        matches!(base.as_bytes(), [b'/', drive, b':', ..] if drive.eq_ignore_ascii_case(&p[0]));
    if !same_drive {
        return None;
    }
    let rest = fold_separators(&payload[2..]);
    Some(format!("{}/{}", base.trim_end_matches('/'), rest))
}

/// Fold platform path separators onto `/`, the separator every specifier uses.
/// Identity on POSIX, where it compiles out. Runs with [`normalize_root`]: fold
/// first, then anchor the drive root.
#[cfg(not(windows))]
#[inline]
pub(crate) fn fold_separators(path: &str) -> Cow<'_, str> {
    Cow::Borrowed(path)
}

/// Windows separates with `\`, often mixed with `/`. Fold `\` onto `/` so segment
/// splitting sees real segments. A UNC root becomes `//server/share` and `\\?\C:\…`
/// becomes `//?/C:/…`; both stay `/`-rooted for [`normalize_root`].
#[cfg(windows)]
pub(crate) fn fold_separators(path: &str) -> Cow<'_, str> {
    if path.contains('\\') {
        Cow::Owned(path.replace('\\', "/"))
    } else {
        Cow::Borrowed(path)
    }
}

/// True if `path` is already absolute and so must not be joined onto a CWD
/// (§7.2). POSIX (and MSYS) absolute paths are `/`-rooted.
#[cfg(not(windows))]
#[inline]
pub(crate) fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// On Windows any drive-qualified payload answers `true`, rooted (`X:\…`) or
/// relative (`X:rest`): the predicate means "do not join onto the CWD", and the CWD
/// may name another drive. [`normalize_root`] anchors both.
#[cfg(windows)]
pub(crate) fn is_absolute(path: &str) -> bool {
    if path.starts_with('/') {
        return true;
    }
    let b = path.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Why a specifier could not be compiled into a matcher (§4). The matchers are
/// total for any non-empty specifier and callers reject empty ones earlier, so this
/// exists to give a future fallible matcher a typed load failure.
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
        self.matches_checked(candidate).unwrap_or(false)
    }

    /// Matcher test with explicit resource exhaustion for the decision engine.
    pub(crate) fn matches_checked(&self, candidate: &str) -> Result<bool, ()> {
        self.matches_checked_with_budget(candidate, &mut WorkBudget::single_match())
    }

    /// Matcher test charged against the complete decision's remaining work.
    pub(crate) fn matches_checked_with_budget(
        &self,
        candidate: &str,
        budget: &mut WorkBudget,
    ) -> Result<bool, ()> {
        let work = match self {
            Matcher::Bare => 1,
            // A prefix test is one `starts_with`, so it costs the prefix length
            // and has no state space to bound. Charging the payload length as
            // well denied ordinary large commands: 162 prefix rules over a
            // 15 KB command reached the decision limit on nominal work alone.
            Matcher::Bash(BashMatcher::Prefix(prefix)) => prefix.len().max(1),
            Matcher::Bash(BashMatcher::Glob(glob)) => {
                bounded_work(candidate.len(), glob.toks.len())?
            }
            Matcher::Path(path) => bounded_work(candidate.len(), path.0.len())?,
            Matcher::Generic(generic) => bounded_work(candidate.len(), generic.0.len())?,
        };
        budget.consume(work)?;
        match self {
            Matcher::Bare => Ok(true),
            Matcher::Bash(BashMatcher::Prefix(prefix)) => Ok(prefix_covers(prefix, candidate)),
            Matcher::Bash(BashMatcher::Glob(glob)) => {
                Ok(tokens_match(candidate.as_bytes(), &glob.toks, b' '))
            }
            Matcher::Path(path) => Ok(path.matches(candidate)),
            Matcher::Generic(generic) => Ok(generic.matches(candidate)),
        }
    }
}

fn bounded_work(text_len: usize, pattern_len: usize) -> Result<usize, ()> {
    let work = text_len.saturating_mul(pattern_len).max(1);
    (work <= MAX_MATCH_STATES).then_some(work).ok_or(())
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
                    Matcher::Bash(BashMatcher::Glob(BashGlob {
                        raw: spec.to_string(),
                        toks: bash_glob_tokens(spec),
                    })),
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
    /// General glob. A trailing or word-attached `*` spans any run of characters;
    /// an interior `*` fenced by spaces on both sides matches a single
    /// whitespace-delimited token (§6.5).
    Glob(BashGlob),
}

/// A compiled Bash glob: the raw specifier plus its token sequence, so matching
/// and the containment check share one compilation and the hot path allocates
/// nothing per call.
#[derive(Debug, Clone)]
pub struct BashGlob {
    raw: String,
    toks: Vec<PToken>,
}

/// Compile a Bash glob specifier into tokens. A `*` fenced by spaces on both sides
/// becomes a single-token `Star` (the `aws * describe-*` slot idiom) so it cannot
/// swallow whitespace; trailing and word-attached `*` stay spanning `DStar`.
fn bash_glob_tokens(spec: &str) -> Vec<PToken> {
    let b = spec.as_bytes();
    let mut t = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'*' {
            let prev = (i > 0).then(|| b[i - 1]);
            let mut j = i + 1;
            while j < b.len() && b[j] == b'*' {
                j += 1;
            }
            let next = (j < b.len()).then(|| b[j]);
            let fenced = |c: Option<u8>| matches!(c, Some(b' ') | Some(b'\t'));
            t.push(if fenced(prev) && fenced(next) {
                PToken::Star
            } else {
                PToken::DStar
            });
            i = j;
        } else {
            t.push(PToken::Lit(b[i]));
            i += 1;
        }
    }
    t
}

/// Anchored full-command match over Bash glob tokens with `sep` as separator.
/// Mirrors [`glob_star_match`] for spanning `DStar`, adding the single-token `Star`
/// that stops at `sep`. Plain backtracking over short trusted patterns (§9.2).
fn tokens_match(text: &[u8], toks: &[PToken], sep: u8) -> bool {
    nfa_match(text, toks, sep)
}

/// Stackless glob evaluation by NFA state propagation. Each `(text, token)`
/// state is visited at most once per input byte, eliminating the recursive
/// backtracking blow-up formerly reachable through interacting wildcards.
fn nfa_match(text: &[u8], toks: &[PToken], sep: u8) -> bool {
    if let Some(matches) = literal_tokens_match(toks, text) {
        return matches;
    }
    if toks.len() < MAX_BITSET_TOKENS {
        nfa_match_bits(text, toks, sep)
    } else {
        nfa_match_vec(text, toks, sep)
    }
}

/// [`nfa_match`] for a pattern too long for the bitset, callable on its own for
/// the differential test.
fn nfa_match_vec(text: &[u8], toks: &[PToken], sep: u8) -> bool {
    let mut current = vec![false; toks.len() + 1];
    let mut next = vec![false; toks.len() + 1];
    current[0] = true;
    epsilon_closure(&mut current, toks);

    for &ch in text {
        next.fill(false);
        for (i, tok) in toks.iter().copied().enumerate() {
            if !current[i] {
                continue;
            }
            match tok {
                PToken::Lit(expected) if expected == ch => next[i + 1] = true,
                PToken::Ques if ch != sep => next[i + 1] = true,
                PToken::Star if ch != sep => next[i] = true,
                PToken::DStar => next[i] = true,
                PToken::Lit(_) | PToken::Ques | PToken::Star => {}
            }
        }
        epsilon_closure(&mut next, toks);
        if !next.iter().any(|state| *state) {
            return false;
        }
        std::mem::swap(&mut current, &mut next);
    }
    current[toks.len()]
}

/// Longest token sequence the `u128` state sets below can hold. A state set
/// spans positions `0..=len`, and [`path_epsilon_closure`] reaches `i + 2`, so
/// the bound leaves both inside 128 bits. Patterns past it (never real rules,
/// but `MAX_RULE_BYTES` permits them) take the `Vec` path.
const MAX_BITSET_TOKENS: usize = 125;

/// [`nfa_match`] with the state sets held in registers rather than two heap
/// allocations per call, visiting only the live states. Same transitions, same
/// answer.
fn nfa_match_bits(text: &[u8], toks: &[PToken], sep: u8) -> bool {
    let mut current: u128 = 1;
    epsilon_closure_bits(&mut current, toks);

    for &ch in text {
        let mut next: u128 = 0;
        let mut live = current;
        while live != 0 {
            let i = live.trailing_zeros() as usize;
            live &= live - 1;
            // The accepting position past the last token carries no transition.
            let Some(tok) = toks.get(i) else { continue };
            match *tok {
                PToken::Lit(expected) if expected == ch => next |= 1u128 << (i + 1),
                PToken::Ques if ch != sep => next |= 1u128 << (i + 1),
                PToken::Star if ch != sep => next |= 1u128 << i,
                PToken::DStar => next |= 1u128 << i,
                PToken::Lit(_) | PToken::Ques | PToken::Star => {}
            }
        }
        epsilon_closure_bits(&mut next, toks);
        if next == 0 {
            return false;
        }
        current = next;
    }
    current & (1u128 << toks.len()) != 0
}

/// [`epsilon_closure`] over a bitset, walking set positions rather than every
/// token. The single forward pass is enough: it only ever sets a later position,
/// which the same scan then reaches.
fn epsilon_closure_bits(states: &mut u128, toks: &[PToken]) {
    let mut i = 0usize;
    loop {
        let live = *states >> i;
        if live == 0 {
            return;
        }
        i += live.trailing_zeros() as usize;
        let Some(tok) = toks.get(i) else { return };
        if matches!(tok, PToken::Star | PToken::DStar) {
            *states |= 1u128 << (i + 1);
        }
        i += 1;
    }
}

/// Add transitions that consume no input: either wildcard may end immediately.
fn epsilon_closure(states: &mut [bool], toks: &[PToken]) {
    for i in 0..toks.len() {
        if !states[i] {
            continue;
        }
        if matches!(toks[i], PToken::Star | PToken::DStar) {
            states[i + 1] = true;
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
        let normalized: &str = if let Some(expanded) = expand_tilde(spec) {
            owned = expanded;
            &owned
        } else if let Some(rest) = spec.strip_prefix("//") {
            // Leading `//` root marker: strip one slash, leaving an
            // absolute-rooted glob.
            owned = format!("/{rest}");
            &owned
        } else {
            spec
        };

        // Windows paths are case-insensitive, so fold the pattern to ASCII
        // lowercase; `matches` folds candidates the same way. POSIX is left
        // untouched. ASCII only, which covers drive letters and common names.
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
/// wildcard does not match a leading `.`, so such a segment cannot resolve to a
/// dotfile; deferring these avoids over-denying ordinary globs like `cat *.rs`.
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

/// A path candidate prepared once for matching against several deny rules, so a
/// shell-glob operand is tokenized once rather than per rule (§8.3).
/// [`PathProbe::hits`] is monotone: it only ever adds hits.
pub(crate) struct PathProbe<'a> {
    raw: &'a str,
    operand_glob: Option<Vec<PToken>>,
}

impl<'a> PathProbe<'a> {
    /// A glob operand is prepared only when every path segment starts with a
    /// literal, mirroring shell expansion: a segment-leading wildcard matches no
    /// dotfile, so preparing one would over-deny ordinary globs (`cat *.rs`).
    pub(crate) fn new(raw: &'a str) -> Self {
        let prepare = has_glob_meta(raw) && !has_segment_leading_wildcard(raw);
        let operand_glob = prepare.then(|| compile_operand_glob(raw));
        Self { raw, operand_glob }
    }

    pub(crate) fn hits(&self, matcher: &Matcher, budget: &mut WorkBudget) -> Result<bool, ()> {
        if matcher.matches_checked_with_budget(self.raw, budget)? {
            return Ok(true);
        }
        match (matcher, self.operand_glob.as_deref()) {
            (Matcher::Path(path), Some(operand)) => {
                let work = bounded_work(path.0.len(), operand.len())?;
                budget.consume(work)?;
                Ok(globs_can_intersect(&path.0, operand))
            }
            (Matcher::Bare, Some(_)) => Ok(true),
            _ => Ok(false),
        }
    }
}

/// Can two path globs share a concrete string? Product-automaton reachability over
/// token positions, where a wildcard matches one shared character or empty. Both
/// inputs are short operator globs, so the `(len+1)²` state space is tiny.
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

/// True when every payload `a` matches is also matched by `d` (`L(a) ⊆ L(d)`), so
/// an allow/ask rule is a genuine carve-out of a deny and overrides it (§6.3).
/// Sound but incomplete: it proves `true` or answers `false`, never guessing.
pub(crate) fn matcher_subset(a: &Matcher, d: &Matcher) -> bool {
    match (a, d) {
        // A bare deny matches everything, so any allow is a subset of it.
        (_, Matcher::Bare) => true,
        // A bare allow (matches everything) refines only a universal deny.
        (Matcher::Bare, _) => is_universal(d),
        (Matcher::Path(pa), Matcher::Path(pd)) => tokens_subset(&pa.0, &pd.0, b'/'),
        (Matcher::Generic(ga), Matcher::Generic(gd)) => tokens_subset(
            &glob_to_tokens(ga.0.as_bytes()),
            &glob_to_tokens(gd.0.as_bytes()),
            b'/',
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
        Matcher::Bash(BashMatcher::Glob(g)) => g.toks.as_slice() == [PToken::DStar],
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

/// True if `cmd` is accepted by the trailing-`:*` prefix specifier `pre`: equal to
/// `pre`, or `pre` then whitespace then anything. The single definition, used by
/// [`BashMatcher::matches`] and by the prefix-containment subset test.
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
            if !ga.raw.contains('*') {
                return prefix_covers(pd, &ga.raw);
            }
            let lit = ga.raw.split('*').next().unwrap_or(&ga.raw);
            lit.len() > pd.len()
                && lit.starts_with(pd)
                && lit.as_bytes()[pd.len()].is_ascii_whitespace()
        }
        // Space is the token separator for both Bash globs.
        (BashMatcher::Glob(ga), BashMatcher::Glob(gd)) => tokens_subset(&ga.toks, &gd.toks, b' '),
        // A prefix's language is `pre`, or `pre` + whitespace + anything.
        // Over-approximate as `pre` + `**` (more strings, so subset stays sound).
        // The prefix side keeps every `*` spanning, the safe reading for `cmd:*`.
        (BashMatcher::Prefix(pa), BashMatcher::Glob(gd)) => {
            let mut toks = glob_to_tokens(pa.as_bytes());
            toks.push(PToken::DStar);
            tokens_subset(&toks, &gd.toks, b' ')
        }
    }
}

/// Sound, incomplete decision of `L(a) ⊆ L(d)` over path-glob tokens. `d` becomes a
/// DFA by on-the-fly subset construction; `a` is walked with its wildcards
/// universally quantified. Oversized or over-budget input answers `false`.
fn tokens_subset(a: &[PToken], d: &[PToken], sep: u8) -> bool {
    // `dstate` is a bitset over positions `0..=d.len()`, so `d.len()` must index
    // into a u128. Oversized patterns (never real rules) fail closed.
    if d.len() >= 127 || a.len() >= 127 {
        return false;
    }
    if shortest_witness_rejected(a, d, sep) {
        return false;
    }
    let lits = d_literals(d);
    let Some(fresh) = fresh_byte(&lits, sep) else {
        return false;
    };
    // Representative characters an `a`-wildcard adversary may pick. The separator
    // (`/` for paths, space for Bash) is kept separate because `?`/`*` reject it
    // while `**` accepts it.
    let mut reps_nonsep: Vec<u8> = lits.iter().copied().filter(|&b| b != sep).collect();
    reps_nonsep.push(fresh);
    let mut reps_all = reps_nonsep.clone();
    reps_all.push(sep);

    let start = closure_d(d, 1u128);
    let mut ctx = InclCtx {
        d,
        sep,
        reps_nonsep: &reps_nonsep,
        reps_all: &reps_all,
        seen: std::collections::HashSet::new(),
        budget: 100_000,
    };
    incl(a, 0, start, &mut ctx)
}

/// Reject a pair before [`incl`] allocates its representative sets and visit table.
/// Sound because it tries exactly `incl`'s first branch, every `a` wildcard matching
/// empty, through the same model. Skipped when `a` has a `?`, which must consume.
fn shortest_witness_rejected(a: &[PToken], d: &[PToken], sep: u8) -> bool {
    if a.iter().any(|token| matches!(token, PToken::Ques)) {
        return false;
    }
    // Cheap gate first: every `d` literal must be consumed by that exact character,
    // so any string `d` accepts carries `d`'s literals in order. Two pointers, where
    // the walk below is a `u128` transition per `d` position per character.
    if !d_literals_are_subsequence(a, d) {
        return true;
    }
    let mut dstate = closure_d(d, 1u128);
    for token in a {
        if let PToken::Lit(c) = token {
            dstate = step_d(d, dstate, *c, sep);
            if dstate == 0 {
                return true; // `d` is dead: it rejects a string `a` accepts.
            }
        }
    }
    dstate & (1u128 << d.len()) == 0
}

/// Are `d`'s literal bytes an ordered subsequence of `a`'s? Necessary for `d` to
/// accept the witness above, and so for `L(a) ⊆ L(d)`.
fn d_literals_are_subsequence(a: &[PToken], d: &[PToken]) -> bool {
    let mut wanted = d.iter().filter_map(|token| match token {
        PToken::Lit(c) => Some(*c),
        _ => None,
    });
    let mut next = wanted.next();
    for token in a {
        let Some(c) = next else {
            return true;
        };
        if *token == PToken::Lit(c) {
            next = wanted.next();
        }
    }
    next.is_none()
}

struct InclCtx<'a> {
    d: &'a [PToken],
    sep: u8,
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
            let ns = step_d(ctx.d, dstate, c, ctx.sep);
            incl(a, i + 1, ns, ctx)
        }
        // A single non-`/` char: advance past `?`, requiring every representative.
        PToken::Ques => all_reps(a, i + 1, dstate, RepSet::NonSeparator, ctx),
        // Star ends now (advance), or consumes one non-`/` char and stays at `i`.
        PToken::Star => {
            incl(a, i + 1, dstate, ctx) && all_reps(a, i, dstate, RepSet::NonSeparator, ctx)
        }
        // `**` ends now, or consumes any char (separators included) and stays.
        PToken::DStar => incl(a, i + 1, dstate, ctx) && all_reps(a, i, dstate, RepSet::All, ctx),
    }
}

/// Require containment for every representative character, stepping `d` on each
/// and continuing `a` from `next_i` (the caller passes `i` to stay on a spanning
/// wildcard, or `i + 1` to advance past a single-character one).
#[derive(Clone, Copy)]
enum RepSet {
    NonSeparator,
    All,
}

fn all_reps(a: &[PToken], next_i: usize, dstate: u128, reps: RepSet, ctx: &mut InclCtx) -> bool {
    let len = match reps {
        RepSet::NonSeparator => ctx.reps_nonsep.len(),
        RepSet::All => ctx.reps_all.len(),
    };
    (0..len).all(|index| {
        // Copy the byte before recursively borrowing `ctx` mutably.
        let ch = match reps {
            RepSet::NonSeparator => ctx.reps_nonsep[index],
            RepSet::All => ctx.reps_all[index],
        };
        let ns = step_d(ctx.d, dstate, ch, ctx.sep);
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

/// A byte that is neither the separator nor any of `d`'s literals: one
/// representative for "every other character". `None` when none is left, and
/// [`tokens_subset`] then fails closed rather than shrink the adversary's alphabet.
fn fresh_byte(lits: &[u8], sep: u8) -> Option<u8> {
    (0u8..=255).find(|b| *b != sep && !lits.contains(b))
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

/// Transition of a (closed) `d` state on one concrete character. `sep_byte` is the
/// token separator (`/` for paths, space for Bash): a non-spanning `*` stays live
/// on any character except it.
fn step_d(d: &[PToken], bits: u128, ch: u8, sep_byte: u8) -> u128 {
    let sep = ch == sep_byte;
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

/// Anchored, full-string glob match with `/`-aware wildcards (§6.5). Stackless
/// state propagation, so no recursive backtracking. `*` spans non-`/` bytes, `?`
/// one, `**` any run, and `**/` collapses to zero directories.
fn path_match(pat: &[PToken], text: &[u8]) -> bool {
    if let Some(matches) = literal_tokens_match(pat, text) {
        return matches;
    }
    if pat.len() < MAX_BITSET_TOKENS {
        path_match_bits(pat, text)
    } else {
        path_match_vec(pat, text)
    }
}

/// [`path_match`] for a pattern too long for the bitset. Kept callable on its
/// own so the differential test can hold it against the bitset on every case,
/// not only on the oversized patterns that reach it in practice.
fn path_match_vec(pat: &[PToken], text: &[u8]) -> bool {
    let mut current = vec![false; pat.len() + 1];
    let mut looped = vec![false; pat.len() + 1];
    let mut next = vec![false; pat.len() + 1];
    let mut next_looped = vec![false; pat.len() + 1];
    current[0] = true;
    path_epsilon_closure(&mut current, &looped, pat);

    for &ch in text {
        next.fill(false);
        next_looped.fill(false);
        for (i, tok) in pat.iter().copied().enumerate() {
            if current[i] {
                match tok {
                    PToken::Lit(expected) if expected == ch => next[i + 1] = true,
                    PToken::Ques if ch != b'/' => next[i + 1] = true,
                    PToken::Star if ch != b'/' => next[i] = true,
                    PToken::DStar => next_looped[i] = true,
                    PToken::Lit(_) | PToken::Ques | PToken::Star => {}
                }
            }
            if looped[i] && tok == PToken::DStar {
                next_looped[i] = true;
            }
        }
        path_epsilon_closure(&mut next, &next_looped, pat);
        if !next.iter().any(|state| *state) && !next_looped.iter().any(|state| *state) {
            return false;
        }
        std::mem::swap(&mut current, &mut next);
        std::mem::swap(&mut looped, &mut next_looped);
    }
    path_epsilon_closure(&mut current, &looped, pat);
    current[pat.len()]
}

fn literal_tokens_match(toks: &[PToken], text: &[u8]) -> Option<bool> {
    toks.iter()
        .all(|tok| matches!(tok, PToken::Lit(_)))
        .then(|| {
            toks.len() == text.len()
                && toks
                    .iter()
                    .zip(text)
                    .all(|(tok, byte)| matches!(tok, PToken::Lit(expected) if expected == byte))
        })
}

/// [`path_match`] with the four state sets held in registers rather than four
/// heap allocations per call, visiting only the live states. Same transitions,
/// same answer.
fn path_match_bits(pat: &[PToken], text: &[u8]) -> bool {
    let mut current: u128 = 1;
    let mut looped: u128 = 0;
    path_epsilon_closure_bits(&mut current, looped, pat);

    for &ch in text {
        let mut next: u128 = 0;
        let mut next_looped: u128 = 0;
        let mut live = current;
        while live != 0 {
            let i = live.trailing_zeros() as usize;
            live &= live - 1;
            // The accepting position past the last token carries no transition.
            let Some(tok) = pat.get(i) else { continue };
            match *tok {
                PToken::Lit(expected) if expected == ch => next |= 1u128 << (i + 1),
                PToken::Ques if ch != b'/' => next |= 1u128 << (i + 1),
                PToken::Star if ch != b'/' => next |= 1u128 << i,
                PToken::DStar => next_looped |= 1u128 << i,
                PToken::Lit(_) | PToken::Ques | PToken::Star => {}
            }
        }
        // A `**` that has already consumed a character stays consumed.
        let mut live = looped;
        while live != 0 {
            let i = live.trailing_zeros() as usize;
            live &= live - 1;
            if pat.get(i) == Some(&PToken::DStar) {
                next_looped |= 1u128 << i;
            }
        }
        path_epsilon_closure_bits(&mut next, next_looped, pat);
        if next == 0 && next_looped == 0 {
            return false;
        }
        current = next;
        looped = next_looped;
    }
    path_epsilon_closure_bits(&mut current, looped, pat);
    current & (1u128 << pat.len()) != 0
}

/// [`path_epsilon_closure`] over bitsets, walking set positions rather than
/// every token. Both sets are scanned together, since either can open a move.
fn path_epsilon_closure_bits(states: &mut u128, looped: u128, toks: &[PToken]) {
    let mut i = 0usize;
    loop {
        let live = (*states | looped) >> i;
        if live == 0 {
            return;
        }
        i += live.trailing_zeros() as usize;
        let Some(tok) = toks.get(i) else { return };
        if looped & (1u128 << i) != 0 && *tok == PToken::DStar {
            *states |= 1u128 << (i + 1);
        }
        if *states & (1u128 << i) != 0 {
            if matches!(tok, PToken::Star | PToken::DStar) {
                *states |= 1u128 << (i + 1);
            }
            if *tok == PToken::DStar && toks.get(i + 1) == Some(&PToken::Lit(b'/')) {
                *states |= 1u128 << (i + 2);
            }
        }
        i += 1;
    }
}

/// Path `**/` has one extra epsilon transition, but only before that `**` has
/// consumed a character. Keeping consumed `**` states separate lets the slash
/// collapse for zero directories without matching midway through a segment.
fn path_epsilon_closure(states: &mut [bool], looped: &[bool], toks: &[PToken]) {
    for i in 0..toks.len() {
        if looped[i] && toks[i] == PToken::DStar {
            states[i + 1] = true;
        }
        if !states[i] {
            continue;
        }
        if matches!(toks[i], PToken::Star | PToken::DStar) {
            states[i + 1] = true;
        }
        if toks[i] == PToken::DStar && toks.get(i + 1) == Some(&PToken::Lit(b'/')) {
            states[i + 2] = true;
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
    fn fresh_byte_is_absent_only_when_the_alphabet_is_exhausted() {
        // The representative for "every other character". Present for any ordinary
        // deny pattern, including one whose literals cover the whole of ASCII.
        assert!(fresh_byte(&[], b'/').is_some());
        assert!(fresh_byte(&b"/etc/passwd"[..], b'/').is_some());
        let ascii: Vec<u8> = (0u8..128).collect();
        assert!(fresh_byte(&ascii, b'/').is_some());

        // Absent only when every byte but the separator is already a literal. A
        // rule file cannot reach this, since a specifier arrives as `&str` and its
        // literals are valid UTF-8, so the bound is asserted on the helper.
        let all_but_sep: Vec<u8> = (0u8..=255).filter(|&b| b != b'/').collect();
        assert_eq!(fresh_byte(&all_but_sep, b'/'), None);
        // The separator itself is never offered as the fresh byte.
        assert_eq!(fresh_byte(&all_but_sep, b' '), Some(b'/'));
    }

    #[test]
    fn exhausted_alphabet_keeps_the_deny() {
        // With no fresh representative, containment is unprovable and the subset
        // test answers `false`, which leaves the deny standing (§6.3).
        let a = [PToken::Star];
        let d: Vec<PToken> = (0u8..=255)
            .filter(|&b| b != b'/')
            .map(PToken::Lit)
            .collect();
        assert!(!tokens_subset(&a, &d, b'/'));
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

#[cfg(test)]
mod glob_engine_tests {
    use super::*;

    /// Patterns and texts covering every token kind, separator behaviour, and the
    /// `**/` zero-directory collapse, plus the shapes that used to backtrack.
    const CASES: &[(&str, &[&str])] = &[
        ("/etc/passwd", &["/etc/passwd", "/etc/passwdx", "/etc", ""]),
        ("/etc/*", &["/etc/x", "/etc/", "/etc/x/y", "/etc"]),
        ("/etc/**", &["/etc/x", "/etc/x/y", "/etc/", "/etcx"]),
        ("/**/.env", &["/a/.env", "/a/b/.env", "/.env", "/a/.envx"]),
        ("/a/**/b", &["/a/b", "/a/x/b", "/a/x/y/b", "/a/bx"]),
        ("/?/x", &["/a/x", "/ab/x", "//x"]),
        ("/a*b*c", &["/abc", "/axbyc", "/ab/c", "/abcx"]),
        ("**", &["", "/", "/a/b/c", "x"]),
        ("/**/*.rs", &["/a.rs", "/a/b.rs", "/a/b/c.rs", "/a.rsx"]),
        ("/a/**/**/b", &["/a/b", "/a/x/b", "/a/x/y/z/b"]),
    ];

    #[test]
    fn the_bitset_and_vec_engines_agree_on_every_case() {
        // Both are reachable in production, the `Vec` one only for a pattern past
        // MAX_BITSET_TOKENS. Holding them against each other on ordinary patterns
        // is what keeps the rarely-taken path honest.
        for (spec, texts) in CASES {
            let pat = PathMatcher::compile(spec).0;
            for text in *texts {
                assert_eq!(
                    path_match_bits(&pat, text.as_bytes()),
                    path_match_vec(&pat, text.as_bytes()),
                    "path {spec:?} vs {text:?}"
                );
            }
        }
        for (spec, texts) in CASES {
            let toks = bash_glob_tokens(spec);
            for text in *texts {
                assert_eq!(
                    nfa_match_bits(text.as_bytes(), &toks, b' '),
                    nfa_match_vec(text.as_bytes(), &toks, b' '),
                    "bash {spec:?} vs {text:?}"
                );
            }
        }
    }

    #[test]
    fn a_pattern_past_the_bitset_bound_still_matches() {
        // The `Vec` path is only reachable here, and `MAX_RULE_BYTES` permits a
        // specifier this long even though no real rule is one.
        let segment = "a".repeat(MAX_BITSET_TOKENS + 10);
        let matcher = PathMatcher::compile(&format!("/{segment}/**"));
        assert!(matcher.0.len() > MAX_BITSET_TOKENS);
        assert!(matcher.matches(&format!("/{segment}/x/y")));
        assert!(!matcher.matches("/elsewhere/x"));
    }
}
