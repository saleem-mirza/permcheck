//! Lightweight simple-command tokenization for file-access checks (§8.3).

use std::ops::Range;

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

/// One shell word as both the raw source range and the value after the limited
/// quote/escape removal this analyzer models. Keeping the range is what lets
/// callers rewrite a word without losing quoted whitespace boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ShellWord {
    pub(super) value: String,
    pub(super) range: Range<usize>,
    pub(super) redirect: Option<RedirectKind>,
}

/// Tokenize a simple command into words and redirections (§8.3).
pub fn tokenize(s: &str) -> Vec<Token> {
    shell_words(s)
        .into_iter()
        .map(|word| match word.redirect {
            Some(kind) => Token::Redirect(kind, word.value),
            None => Token::Word(word.value),
        })
        .collect()
}

/// Tokenize a simple command while retaining each word's source range. This is
/// the shared lexical layer for the public tokenizer and Bash normalization.
pub(super) fn shell_words(s: &str) -> Vec<ShellWord> {
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
            // `>|` is `>` with `noclobber` overridden: same target, same kind.
            if is_out && !append && j < n && b[j] == b'|' {
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
                if !target.value.is_empty()
                    && target
                        .value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || b == b'-')
                {
                    continue;
                }
                out.push(ShellWord {
                    redirect: Some(if append {
                        RedirectKind::AmpAppend
                    } else {
                        RedirectKind::AmpOut
                    }),
                    ..target
                });
            } else if is_out {
                out.push(ShellWord {
                    redirect: Some(if append {
                        RedirectKind::Append
                    } else {
                        RedirectKind::Out
                    }),
                    ..target
                });
            } else {
                out.push(ShellWord {
                    redirect: Some(RedirectKind::In),
                    ..target
                });
            }
            continue;
        }

        if j < n && b[j] == b'&' && j + 1 < n && b[j + 1] == b'>' {
            let mut k = j + 2;
            let mut append = false;
            if k < n && b[k] == b'>' {
                append = true;
                k += 1;
            }
            let (target, next) = read_target(s, k);
            i = next;
            out.push(ShellWord {
                redirect: Some(if append {
                    RedirectKind::AmpAppend
                } else {
                    RedirectKind::AmpOut
                }),
                ..target
            });
            continue;
        }

        let word = read_word(s, i);
        if word.range.end > i {
            i = word.range.end;
            out.push(word);
        } else {
            i += 1;
        }
    }
    out
}

/// Remove quoting from every parsed word while leaving whitespace and
/// redirection operators exactly where they were. Returns `None` when no parsed
/// word changes.
pub(super) fn dequote_words(s: &str) -> Option<String> {
    let words = shell_words(s);
    let changed = words
        .iter()
        .any(|word| s.get(word.range.clone()) != Some(word.value.as_str()));
    if !changed {
        return None;
    }

    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;
    for word in words {
        out.push_str(&s[cursor..word.range.start]);
        out.push_str(&word.value);
        cursor = word.range.end;
    }
    out.push_str(&s[cursor..]);
    Some(out)
}

fn read_target(s: &str, start: usize) -> (ShellWord, usize) {
    let attached = read_word(s, start);
    if attached.range.end > start {
        let next = attached.range.end;
        return (attached, next);
    }
    let b = s.as_bytes();
    let mut k = attached.range.end;
    while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
        k += 1;
    }
    let target = read_word(s, k);
    let next = target.range.end;
    (target, next)
}

fn read_word(s: &str, start: usize) -> ShellWord {
    let b = s.as_bytes();
    let n = b.len();
    let mut i = start;
    let mut out = String::new();
    while i < n {
        match b[i] {
            b' ' | b'\t' | b'<' | b'>' => break,
            b'\\' => {
                // An unquoted backslash escapes the next character (`.\env` ->
                // `.env`), so the cross-check tests the real path. Advance a full
                // UTF-8 char; a trailing backslash is dropped.
                i += 1;
                if let Some(ch) = s[i..].chars().next() {
                    out.push(ch);
                    i += ch.len_utf8();
                }
            }
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
                append_double_quoted(s, &mut i, &mut out);
            }
            b'$' if b.get(i + 1) == Some(&b'\'') => {
                // ANSI-C escape decoding remains outside the analyzer's scope,
                // but an escaped quote must not end the word early.
                i += 2;
                append_ansi_c_quoted(s, &mut i, &mut out);
            }
            b'$' if b.get(i + 1) == Some(&b'"') => {
                // Locale quoting has the same word boundaries as double quoting;
                // the leading `$` and delimiters are syntax, not word content.
                i += 2;
                append_double_quoted(s, &mut i, &mut out);
            }
            _ => {
                let st = i;
                while i < n
                    && !matches!(
                        b[i],
                        b' ' | b'\t' | b'<' | b'>' | b'\'' | b'"' | b'\\' | b'$'
                    )
                {
                    i += 1;
                }
                if i == st {
                    // A `$` not opening a quoted run is ordinary word content.
                    out.push('$');
                    i += 1;
                } else {
                    out.push_str(&s[st..i]);
                }
            }
        }
    }
    ShellWord {
        value: out,
        range: start..i,
        redirect: None,
    }
}

/// Append a double-quoted run. Backslashes remain literal under the analyzer's
/// documented approximation except when they escape the closing quote; handling
/// that boundary is necessary to keep the rest of the executable in one word.
fn append_double_quoted(s: &str, i: &mut usize, out: &mut String) {
    let b = s.as_bytes();
    let mut start = *i;
    while *i < b.len() {
        match b[*i] {
            b'"' => {
                out.push_str(&s[start..*i]);
                *i += 1;
                return;
            }
            b'\\' if b.get(*i + 1) == Some(&b'"') => {
                out.push_str(&s[start..*i]);
                out.push('"');
                *i += 2;
                start = *i;
            }
            _ => *i += 1,
        }
    }
    out.push_str(&s[start..*i]);
}

/// Append an ANSI-C-quoted run without decoding general escape sequences. The
/// quote/backslash escapes are enough to find the real closing delimiter and
/// therefore preserve the correct shell word boundary.
fn append_ansi_c_quoted(s: &str, i: &mut usize, out: &mut String) {
    let b = s.as_bytes();
    let mut start = *i;
    while *i < b.len() {
        match b[*i] {
            b'\'' => {
                out.push_str(&s[start..*i]);
                *i += 1;
                return;
            }
            b'\\' if matches!(b.get(*i + 1), Some(b'\'') | Some(b'\\')) => {
                out.push_str(&s[start..*i]);
                out.push(b[*i + 1] as char);
                *i += 2;
                start = *i;
            }
            _ => *i += 1,
        }
    }
    out.push_str(&s[start..*i]);
}
