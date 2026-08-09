//! Environment-assignment, wrapper, and reserved-word prefix handling (§8.2).

use super::split::{skip_quoted, skip_single};
use super::tokenize::shell_words;

/// Wrapper commands whose leading options are peeled to reach the real command.
/// `time` belongs here rather than in [`RESERVED`] because it takes its own
/// options (`time -p cmd`), which the argument peeling below drops.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "timeout", "nice", "ionice", "nohup", "stdbuf", "setsid", "command",
    "xargs", "time",
];

/// Shell reserved words a command follows, so the command after one is decided on
/// its own. Only the word is dropped, never arguments, which would eat a
/// condition's operands. Matched after quote removal, which over-denies `'{' cmd`.
const RESERVED: &[&str] = &[
    "{", "!", "if", "then", "elif", "else", "while", "until", "do",
];

/// Reserved words that *close* a construct, so §8.1 leaves each as a unit of its
/// own: `fi`, `done`, `}`. They run no command.
const CLOSERS: &[&str] = &["fi", "done", "esac", "}", ";;"];

/// True when a unit runs no command, so it carries no verdict (§8 step 4). The
/// only place the engine lowers one, so it reads the **raw** slice: `'fi'` and
/// `./fi` normalize to `fi`, and `./fi` runs a program. Wrappers never skip.
pub(super) fn executes_nothing(unit: &str) -> bool {
    let trimmed = unit.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed
        .split_ascii_whitespace()
        .all(|word| RESERVED.contains(&word) || CLOSERS.contains(&word))
    {
        return true;
    }
    strip_env_assignments(trimmed).trim().is_empty()
}

/// Most peel stages per unit, past which it is denied. Each stage re-decides a
/// suffix, so an unbounded chain is quadratic in the unit's length. Real commands
/// stack a handful (`! time env sudo timeout 5 nice cmd` is six).
const MAX_STAGES: usize = 32;

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

/// A bare numeric wrapper argument, including `timeout` durations (`5s`, `1.5h`).
/// Without these, `timeout 5s sudo …` stops at `5s` and launders the `sudo` deny.
/// Peeling only raises, so widening this cannot loosen a decision.
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

/// The command behind **each** leading wrapper or reserved word, outermost first,
/// plus whether [`MAX_STAGES`] truncated it (caller fails closed, §9.1). Every
/// stage, because a rule naming a wrapper only matches in head position.
pub(super) fn strip_leading_wrappers(cmd: &str) -> (Vec<&str>, bool) {
    let words: Vec<_> = shell_words(cmd)
        .into_iter()
        .filter(|word| word.redirect.is_none())
        .collect();
    let mut i = 0;
    while words.get(i).is_some_and(|word| is_assignment(&word.value)) {
        i += 1;
    }
    let mut stages = Vec::new();
    while let Some(word) = words.get(i) {
        // A reserved word carries no options of its own, so only it is dropped;
        // peeling arguments after `if` would eat the condition's own operands.
        if RESERVED.contains(&word.value.as_str()) {
            i += 1;
        } else if WRAPPERS.contains(&basename(&word.value)) {
            i += 1;
            while words.get(i).is_some_and(|word| is_wrapper_arg(&word.value)) {
                i += 1;
            }
        } else {
            break;
        }
        // Nothing follows, so there is no command to decide.
        let Some(next) = words.get(i) else { break };
        let rest = cmd[next.range.start..].trim_end();
        if rest.is_empty() {
            break;
        }
        if stages.len() == MAX_STAGES {
            return (stages, true);
        }
        stages.push(rest);
    }
    (stages, false)
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
