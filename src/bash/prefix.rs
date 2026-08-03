//! Environment-assignment and wrapper-prefix handling (§8.2).

use super::split::{skip_quoted, skip_single};

/// Wrapper commands whose leading options are peeled to reach the real command.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "timeout", "nice", "ionice", "nohup", "stdbuf", "setsid", "command",
    "xargs",
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

pub(super) fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// Strip leading wrapper commands and return the wrapped command string.
pub(super) fn strip_leading_wrappers(cmd: &str) -> Option<&str> {
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
        i = end;
        peeled = true;
        loop {
            let ws = skip_ws(i);
            let we = skip_word(b, ws);
            if we == ws {
                i = ws;
                break;
            }
            if is_wrapper_arg(&cmd[ws..we]) {
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
