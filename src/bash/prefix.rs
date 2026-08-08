//! Environment-assignment, wrapper, and reserved-word prefix handling (§8.2).

use super::split::{skip_quoted, skip_single};
use super::tokenize::shell_words;

/// Wrapper commands whose leading options are peeled to reach the real command.
///
/// `time` earns its place here rather than in [`RESERVED`] because it takes its
/// own options (`time -p cmd`), which the argument peeling below already drops.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "timeout", "nice", "ionice", "nohup", "stdbuf", "setsid", "command",
    "xargs", "time",
];

/// Shell reserved words that introduce a command without changing which command
/// runs, so the command after one has to be decided on its own. Splitting on `;`
/// (§8.1) already leaves a conditional or loop body as a unit like `then cat .env`
/// or `do sudo …`, one word short of the rule that names it.
///
/// Unlike a [`WRAPPERS`] entry these take no options, so only the word itself is
/// dropped: peeling arguments after `if` would eat the condition's own operands.
/// The list stops at words a command follows. `for`, `case`, and `in` are left out
/// because a variable or pattern follows them, not a command, and `fi`, `done`,
/// `esac`, and `}` because nothing follows them at all.
///
/// Matching is exact, against the word the lexical pass produced, which has had
/// its quoting removed. Quoting does strip a word's reserved meaning in the shell
/// (`'{' cmd` runs a command named `{`, it does not open a group), so that
/// spelling is peeled here when the shell would not peel it. Both callers only
/// ever raise a verdict, so the cost is an over-deny on a command the shell would
/// have failed to find anyway.
const RESERVED: &[&str] = &[
    "{", "!", "if", "then", "elif", "else", "while", "until", "do",
];

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

fn is_wrapper_arg(w: &str) -> bool {
    w.starts_with('-') || w.contains('=') || is_duration(w)
}

/// A bare numeric wrapper argument, including `timeout`'s duration forms
/// (`5`, `5s`, `1m`, `1.5h`, `2d`). Recognizing these lets wrapper peeling reach
/// the wrapped command: without it, `timeout 5s sudo rm -rf /` stops at `5s` and
/// launders the `sudo` deny down to the fall-back tier. Peeling only ever raises a
/// verdict, so widening what counts as a wrapper argument cannot loosen a decision.
fn is_duration(w: &str) -> bool {
    // An optional single unit suffix (`timeout` accepts one, e.g. `5s`, not `1h30m`).
    let num = match w.as_bytes().last() {
        Some(b's' | b'm' | b'h' | b'd') => &w[..w.len() - 1],
        _ => w,
    };
    // The remaining number is digits with at most one decimal point.
    !num.is_empty()
        && num.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && num.bytes().filter(|&b| b == b'.').count() <= 1
        && num.bytes().any(|b| b.is_ascii_digit())
}

/// Return the words remaining after leading wrappers and their arguments.
pub(super) fn peel_wrappers<'a, 'b>(mut words: &'a [&'b str]) -> &'a [&'b str] {
    while let Some((&head, rest)) = words.split_first() {
        // A reserved word carries no options of its own, so only it is dropped.
        if RESERVED.contains(&head) {
            words = rest;
            continue;
        }
        if !WRAPPERS.contains(&basename(head)) {
            break;
        }
        words = rest;
        while let Some(&word) = words.first() {
            if is_wrapper_arg(word) {
                words = &words[1..];
            } else {
                break;
            }
        }
    }
    words
}

#[cfg(not(windows))]
pub(super) fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

#[cfg(windows)]
pub(super) fn basename(word: &str) -> &str {
    word.rsplit(['/', '\\']).next().unwrap_or(word)
}

/// Strip leading wrapper commands and shell reserved words, returning the command
/// string behind them.
pub(super) fn strip_leading_wrappers(cmd: &str) -> Option<&str> {
    let words: Vec<_> = shell_words(cmd)
        .into_iter()
        .filter(|word| word.redirect.is_none())
        .collect();
    let mut i = 0;
    while words.get(i).is_some_and(|word| is_assignment(&word.value)) {
        i += 1;
    }
    let mut peeled = false;
    while let Some(word) = words.get(i) {
        // A reserved word carries no options of its own, so only it is dropped;
        // peeling arguments after `if` would eat the condition's own operands.
        if RESERVED.contains(&word.value.as_str()) {
            peeled = true;
            i += 1;
            continue;
        }
        if !WRAPPERS.contains(&basename(&word.value)) {
            break;
        }
        peeled = true;
        i += 1;
        while words.get(i).is_some_and(|word| is_wrapper_arg(&word.value)) {
            i += 1;
        }
    }

    let rest = words
        .get(i)
        .map(|word| cmd[word.range.start..].trim_end())
        .unwrap_or("");
    (peeled && !rest.is_empty()).then_some(rest)
}

pub(super) fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
