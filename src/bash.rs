//! Compound-Bash decision pipeline (§8).
//!
//! A single Bash `command` may contain several commands. [`decide_bash`] splits
//! it into units, decides each against the Bash matchers, applies a file-access
//! cross-check that can only raise a unit to `deny`, and aggregates the
//! most-restrictive verdict. The splitter is total: it never errors.

use crate::engine;
use crate::rules::RuleSet;
use crate::types::{Decision, Tier};

/// Decide a Bash command by aggregating per-unit verdicts (§8).
pub fn decide_bash(command: &str, rs: &RuleSet, cwd: Option<&str>) -> Decision {
    let units = split(command);
    if units.is_empty() {
        // Empty / whitespace-only command matches no Bash rule -> fall-back tier.
        return Decision::for_call(rs.default_tier, "Bash", command);
    }

    let mut worst = Tier::Allow;
    for unit in &units {
        let cmd = strip_env_assignments(unit);
        let mut tier = unit_tier(rs, cmd);
        // A leading wrapper (`env`, `sudo`, `timeout`, …) executes the command
        // that follows it, so the wrapped command's own decision must apply too.
        // Otherwise `env aws …` would ride in on the wrapper's allow rule and
        // bypass an `aws` deny. This can only raise the verdict (§8.3).
        if let Some(inner) = strip_leading_wrappers(cmd) {
            let inner_tier = unit_tier(rs, inner);
            if inner_tier > tier {
                tier = inner_tier;
            }
        }
        // Cross-check can only raise; skip it once we are already at deny.
        if tier != Tier::Deny && cross_check(rs, cmd, cwd) {
            tier = Tier::Deny;
        }
        if tier > worst {
            worst = tier;
        }
    }

    Decision::for_call(worst, "Bash", command)
}

/// The tier of a single (already env-stripped) command string against the Bash
/// matchers, taking the rule set's `defaultMode` fall-back when nothing matches
/// (§6.3, §6.4).
fn unit_tier(rs: &RuleSet, cmd: &str) -> Tier {
    match engine::best_match(rs, "Bash", &[cmd]) {
        Some(rule) => rule.tier,
        None => rs.default_tier,
    }
}

// --- Splitter (§8.1) ---------------------------------------------------------

/// Split a command into units on shell operators outside quotes, pulling inner
/// commands out of `$(…)`, backticks, and `<(…)` / `>(…)` substitutions. Never
/// errors; unterminated constructs are consumed to end of input.
pub fn split(input: &str) -> Vec<String> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    scan(input, 0, input.len(), &mut ranges);
    ranges
        .into_iter()
        .filter_map(|(a, b)| {
            let t = input[a..b].trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        })
        .collect()
}

fn scan(s: &str, start: usize, end: usize, out: &mut Vec<(usize, usize)>) {
    let b = s.as_bytes();
    let mut i = start;
    let mut unit_start = start;
    while i < end {
        match b[i] {
            b'\'' => i = skip_single(b, i + 1, end),
            b'"' => i = skip_double(s, i + 1, end, out),
            b'`' => i = handle_backtick(s, i + 1, end, out),
            b'$' if i + 1 < end && b[i + 1] == b'(' => {
                if i + 2 < end && b[i + 2] == b'(' {
                    i = skip_arith(b, i + 3, end); // $(( … )) is literal
                } else {
                    i = handle_paren(s, i + 2, end, out); // command substitution
                }
            }
            b'<' | b'>' if i + 1 < end && b[i + 1] == b'(' => {
                i = handle_paren(s, i + 2, end, out); // process substitution
            }
            b'<' => {
                // Redirection, not a split point.
                i += 1;
                if i < end && b[i] == b'&' {
                    i += 1;
                }
            }
            b'>' => {
                i += 1;
                if i < end && b[i] == b'>' {
                    i += 1;
                }
                if i < end && b[i] == b'&' {
                    i += 1;
                }
            }
            b'&' => {
                if i + 1 < end && b[i + 1] == b'&' {
                    out.push((unit_start, i));
                    i += 2;
                    unit_start = i;
                } else if i + 1 < end && b[i + 1] == b'>' {
                    // `&>` / `&>>` redirection; the `>` is consumed next pass.
                    i += 1;
                } else {
                    out.push((unit_start, i));
                    i += 1;
                    unit_start = i;
                }
            }
            b'|' => {
                out.push((unit_start, i));
                if i + 1 < end && b[i + 1] == b'|' {
                    i += 2;
                } else {
                    i += 1;
                }
                unit_start = i;
            }
            b';' | b'\n' => {
                out.push((unit_start, i));
                i += 1;
                unit_start = i;
            }
            _ => i += 1,
        }
    }
    if unit_start < end {
        out.push((unit_start, end));
    }
}

fn skip_single(b: &[u8], mut i: usize, end: usize) -> usize {
    while i < end && b[i] != b'\'' {
        i += 1;
    }
    if i < end { i + 1 } else { end }
}

fn skip_double(s: &str, mut i: usize, end: usize, out: &mut Vec<(usize, usize)>) -> usize {
    let b = s.as_bytes();
    while i < end && b[i] != b'"' {
        if b[i] == b'$' && i + 1 < end && b[i + 1] == b'(' {
            if i + 2 < end && b[i + 2] == b'(' {
                i = skip_arith(b, i + 3, end);
            } else {
                i = handle_paren(s, i + 2, end, out);
            }
        } else if b[i] == b'`' {
            i = handle_backtick(s, i + 1, end, out);
        } else {
            i += 1;
        }
    }
    if i < end { i + 1 } else { end }
}

fn handle_paren(s: &str, inner: usize, end: usize, out: &mut Vec<(usize, usize)>) -> usize {
    let close = find_close_paren(s, inner, end);
    scan(s, inner, close, out);
    if close < end { close + 1 } else { end }
}

fn find_close_paren(s: &str, mut i: usize, end: usize) -> usize {
    let b = s.as_bytes();
    let mut depth = 1usize;
    while i < end {
        match b[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            b'\'' => {
                i = skip_single(b, i + 1, end);
                continue;
            }
            b'"' => {
                i = skip_quoted(b, i + 1, end, b'"');
                continue;
            }
            b'`' => {
                i = skip_quoted(b, i + 1, end, b'`');
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    end
}

fn handle_backtick(s: &str, inner: usize, end: usize, out: &mut Vec<(usize, usize)>) -> usize {
    let b = s.as_bytes();
    let mut j = inner;
    while j < end && b[j] != b'`' {
        j += 1;
    }
    scan(s, inner, j, out);
    if j < end { j + 1 } else { end }
}

fn skip_quoted(b: &[u8], mut i: usize, end: usize, close: u8) -> usize {
    while i < end && b[i] != close {
        i += 1;
    }
    if i < end { i + 1 } else { end }
}

fn skip_arith(b: &[u8], mut i: usize, end: usize) -> usize {
    while i < end {
        if b[i] == b')' && i + 1 < end && b[i + 1] == b')' {
            return i + 2;
        }
        i += 1;
    }
    end
}

// --- Env-assignment stripping (§8.2) -----------------------------------------

/// Strip leading `NAME=value` environment assignments from a unit.
pub fn strip_env_assignments(unit: &str) -> &str {
    let mut s = unit.trim_start();
    loop {
        let b = s.as_bytes();
        let mut i = 0;
        if i < b.len() && (b[i].is_ascii_alphabetic() || b[i] == b'_') {
            i += 1;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            if i < b.len() && b[i] == b'=' {
                let value_end = skip_word(b, i + 1);
                s = s[value_end..].trim_start();
                continue;
            }
        }
        break;
    }
    s
}

/// Advance past a single shell word starting at `i`, honoring simple quoting.
fn skip_word(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && !b[i].is_ascii_whitespace() {
        match b[i] {
            b'\'' => i = skip_single(b, i + 1, b.len()),
            b'"' => i = skip_quoted(b, i + 1, b.len(), b'"'),
            _ => i += 1,
        }
    }
    i
}

// --- File-access cross-check (§8.3) ------------------------------------------

/// The kind of a redirection operator (§8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectKind {
    In,
    Out,
    Append,
    AmpOut,
    AmpAppend,
}

/// A tokenized element of a simple command: a word or a redirection to a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Word(String),
    Redirect(RedirectKind, String),
}

/// Wrapper commands whose leading options are peeled to reach the real command.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "timeout", "nice", "ionice", "nohup", "stdbuf", "setsid", "command",
];

/// Readers whose file operands are checked against `Read` deny rules.
const READERS: &[&str] = &[
    "cat",
    "tac",
    "nl",
    "head",
    "tail",
    "less",
    "more",
    "most",
    "view",
    "grep",
    "egrep",
    "fgrep",
    "zgrep",
    "rgrep",
    "sed",
    "awk",
    "gawk",
    "cut",
    "sort",
    "uniq",
    "xxd",
    "od",
    "hexdump",
    "strings",
    "wc",
    "rev",
    "column",
    "comm",
    "base64",
    "md5",
    "md5sum",
    "shasum",
    "sha1sum",
    "sha256sum",
    "cksum",
    "paste",
    "fold",
    "expand",
    "look",
    "join",
];

/// Readers whose first non-option operand is a pattern, not a file (§8.3).
const PATTERN_FIRST: &[&str] = &[
    "grep", "egrep", "fgrep", "zgrep", "rgrep", "sed", "awk", "gawk",
];

/// Writers whose file operands are checked against `Write`/`Edit` deny rules.
const WRITERS: &[&str] = &["tee", "dd", "truncate"];

/// Cross-check a single simple command for reads/writes to denied paths, raising
/// the verdict to `deny` on a hit (§8.3). Never loosens.
fn cross_check(rs: &RuleSet, cmd: &str, cwd: Option<&str>) -> bool {
    let tokens = tokenize(cmd);

    // Redirection targets, regardless of the command.
    for tok in &tokens {
        if let Token::Redirect(kind, target) = tok {
            let hit = match kind {
                RedirectKind::In => engine::path_hits_deny(rs, &["Read"], target, cwd),
                _ => engine::path_hits_deny(rs, &["Write", "Edit"], target, cwd),
            };
            if hit {
                return true;
            }
        }
    }

    // Reader/writer operands, after peeling wrapper commands.
    let mut words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();
    peel_wrappers(&mut words);
    let Some(&cmd0) = words.first() else {
        return false;
    };
    let name = basename(cmd0);
    let operands = &words[1..];

    if READERS.contains(&name) {
        let pattern_first = PATTERN_FIRST.contains(&name);
        let mut skipped_pattern = false;
        for op in operands {
            if op.starts_with('-') {
                continue;
            }
            if pattern_first && !skipped_pattern {
                skipped_pattern = true;
                continue;
            }
            if engine::path_hits_deny(rs, &["Read"], op, cwd) {
                return true;
            }
        }
    } else if WRITERS.contains(&name) {
        for op in operands {
            if op.starts_with('-') || op.contains('=') {
                continue; // options and dd's if=/of= key-values (§9.2)
            }
            if engine::path_hits_deny(rs, &["Write", "Edit"], op, cwd) {
                return true;
            }
        }
    }
    false
}

/// Drop leading wrapper commands (and their options / assignments / numeric
/// args) so the cross-check sees the real command.
fn peel_wrappers(words: &mut Vec<&str>) {
    while let Some(&head) = words.first() {
        if !WRAPPERS.contains(&basename(head)) {
            return;
        }
        words.remove(0);
        while let Some(&w) = words.first() {
            let is_option = w.starts_with('-');
            let is_assignment = w.contains('=');
            let is_numeric = !w.is_empty() && w.bytes().all(|b| b.is_ascii_digit());
            if is_option || is_assignment || is_numeric {
                words.remove(0);
            } else {
                break;
            }
        }
    }
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// Strip leading wrapper commands and their options / assignments / numeric args
/// from `cmd`, returning the wrapped command string when any wrapper was peeled
/// (else `None`). String-level counterpart to [`peel_wrappers`], so the wrapped
/// command can be re-decided against the Bash matchers (§8.3). Handles nested
/// wrappers (`sudo env aws …`) and quoted args (`env FOO="a b" cmd`).
fn strip_leading_wrappers(cmd: &str) -> Option<&str> {
    let b = cmd.as_bytes();
    let skip_ws = |mut i: usize| {
        while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
            i += 1;
        }
        i
    };

    let mut i = skip_ws(0);
    let mut peeled = false;
    loop {
        let start = i;
        let end = skip_word(b, start);
        if end == start || !WRAPPERS.contains(&basename(&cmd[start..end])) {
            break;
        }
        // Consume the wrapper word, then its options / assignments / numeric args.
        i = end;
        peeled = true;
        loop {
            let ws = skip_ws(i);
            let we = skip_word(b, ws);
            if we == ws {
                i = ws;
                break;
            }
            let w = &cmd[ws..we];
            let is_option = w.starts_with('-');
            let is_assignment = w.as_bytes().contains(&b'=');
            let is_numeric = w.bytes().all(|c| c.is_ascii_digit());
            if is_option || is_assignment || is_numeric {
                i = we;
            } else {
                i = ws;
                break;
            }
        }
    }

    let rest = cmd[skip_ws(i)..].trim_end();
    (peeled && !rest.is_empty()).then_some(rest)
}

/// Tokenize a simple command into words and redirections (§8.3).
pub fn tokenize(s: &str) -> Vec<Token> {
    let b = s.as_bytes();
    let n = b.len();
    let mut i = 0;
    let mut out = Vec::new();
    while i < n {
        while i < n && (b[i] == b' ' || b[i] == b'\t') {
            i += 1;
        }
        if i >= n {
            break;
        }

        // Redirection with an optional leading fd number: `2>`, `>`, `<`, `>>`.
        let mut j = i;
        while j < n && b[j].is_ascii_digit() {
            j += 1;
        }
        if j < n && (b[j] == b'<' || b[j] == b'>') {
            let is_out = b[j] == b'>';
            j += 1;
            let mut append = false;
            if is_out && j < n && b[j] == b'>' {
                append = true;
                j += 1;
            }
            let mut amp = false;
            if is_out && j < n && b[j] == b'&' {
                amp = true;
                j += 1;
            }
            let (target, next) = read_target(s, j);
            i = next;
            if amp {
                // `>&1`, `>&-` etc. are fd dups/closes, not file writes.
                if !target.is_empty() && target.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
                    continue;
                }
                out.push(Token::Redirect(
                    if append {
                        RedirectKind::AmpAppend
                    } else {
                        RedirectKind::AmpOut
                    },
                    target,
                ));
            } else if is_out {
                out.push(Token::Redirect(
                    if append {
                        RedirectKind::Append
                    } else {
                        RedirectKind::Out
                    },
                    target,
                ));
            } else {
                out.push(Token::Redirect(RedirectKind::In, target));
            }
            continue;
        }

        // `&>` / `&>>` redirection.
        if j < n && b[j] == b'&' && j + 1 < n && b[j + 1] == b'>' {
            let mut k = j + 2;
            let mut append = false;
            if k < n && b[k] == b'>' {
                append = true;
                k += 1;
            }
            let (target, next) = read_target(s, k);
            i = next;
            out.push(Token::Redirect(
                if append {
                    RedirectKind::AmpAppend
                } else {
                    RedirectKind::AmpOut
                },
                target,
            ));
            continue;
        }

        // Ordinary word.
        let (word, next) = read_word(s, i);
        if word.is_empty() {
            i = next.max(i + 1);
        } else {
            out.push(Token::Word(word));
            i = next;
        }
    }
    out
}

/// Read a redirection target: attached chars, or the next whitespace-delimited
/// word when the operator stands alone.
fn read_target(s: &str, start: usize) -> (String, usize) {
    let (attached, next) = read_word(s, start);
    if !attached.is_empty() {
        return (attached, next);
    }
    let b = s.as_bytes();
    let mut k = next;
    while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
        k += 1;
    }
    read_word(s, k)
}

/// Read one word (unquoted), stopping at whitespace or a redirection metachar.
fn read_word(s: &str, start: usize) -> (String, usize) {
    let b = s.as_bytes();
    let n = b.len();
    let mut i = start;
    let mut out = String::new();
    while i < n {
        match b[i] {
            b' ' | b'\t' | b'<' | b'>' => break,
            b'\'' => {
                i += 1;
                let st = i;
                while i < n && b[i] != b'\'' {
                    i += 1;
                }
                out.push_str(&s[st..i]);
                if i < n {
                    i += 1;
                }
            }
            b'"' => {
                i += 1;
                let st = i;
                while i < n && b[i] != b'"' {
                    i += 1;
                }
                out.push_str(&s[st..i]);
                if i < n {
                    i += 1;
                }
            }
            _ => {
                let st = i;
                while i < n && !matches!(b[i], b' ' | b'\t' | b'<' | b'>' | b'\'' | b'"') {
                    i += 1;
                }
                out.push_str(&s[st..i]);
            }
        }
    }
    (out, i)
}
