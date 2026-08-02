//! Lightweight simple-command tokenization for file-access checks (§8.3).

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
