//! Best-effort compound-command splitting (§8.1).

/// Split a command into borrowed units for the decision hot path.
pub(super) fn units(input: &str) -> Vec<&str> {
    let mut ranges = Vec::new();
    scan(input, 0, input.len(), &mut ranges);
    ranges
        .into_iter()
        .map(|(a, b)| input[a..b].trim())
        .filter(|unit| !unit.is_empty())
        .collect()
}

/// Owned compatibility wrapper exposed by [`super::split`].
pub(super) fn owned_units(input: &str) -> Vec<String> {
    units(input).into_iter().map(str::to_owned).collect()
}

fn scan(s: &str, start: usize, end: usize, out: &mut Vec<(usize, usize)>) {
    let b = s.as_bytes();
    let mut i = start;
    let mut unit_start = start;
    while i < end {
        match b[i] {
            b'\\' => i += 2,
            b'\'' => i = skip_single(b, i + 1, end),
            b'"' => i = skip_double(s, i + 1, end, out),
            b'`' => i = handle_backtick(s, i + 1, end, out),
            b'$' if i + 1 < end && b[i + 1] == b'(' => {
                if i + 2 < end && b[i + 2] == b'(' {
                    i = skip_arith(b, i + 3, end);
                } else {
                    i = handle_paren(s, i + 2, end, out);
                }
            }
            b'<' | b'>' if i + 1 < end && b[i + 1] == b'(' => {
                i = handle_paren(s, i + 2, end, out);
            }
            b'<' => {
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
                    i += 1;
                } else {
                    out.push((unit_start, i));
                    i += 1;
                    unit_start = i;
                }
            }
            b'|' => {
                out.push((unit_start, i));
                i += if i + 1 < end && b[i + 1] == b'|' {
                    2
                } else {
                    1
                };
                unit_start = i;
            }
            b';' | b'\n' => {
                out.push((unit_start, i));
                i += 1;
                unit_start = i;
            }
            // An unquoted `#` opening a word starts a comment that bash discards
            // through end-of-line, so the matched text must exclude it too:
            // otherwise `aws … # describe-instances` smuggles the substring a glob allow
            // needs into a command whose executed part stays destructive. A `#`
            // right after a redirection operator (`>#file`) is a target word, not a
            // comment, so `<`/`>` are excluded to keep that target visible to the
            // file-access cross-check.
            b'#' if i == start
                || matches!(b[i - 1], b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(') =>
            {
                out.push((unit_start, i));
                while i < end && b[i] != b'\n' {
                    i += 1;
                }
                unit_start = i;
            }
            _ => i += 1,
        }
    }
    if unit_start < end {
        out.push((unit_start, end));
    }
}

pub(super) fn skip_single(b: &[u8], mut i: usize, end: usize) -> usize {
    while i < end && b[i] != b'\'' {
        i += 1;
    }
    if i < end { i + 1 } else { end }
}

fn skip_double(s: &str, mut i: usize, end: usize, out: &mut Vec<(usize, usize)>) -> usize {
    let b = s.as_bytes();
    while i < end && b[i] != b'"' {
        if b[i] == b'\\' {
            i += 2;
        } else if b[i] == b'$' && i + 1 < end && b[i + 1] == b'(' {
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

pub(super) fn skip_quoted(b: &[u8], mut i: usize, end: usize, close: u8) -> usize {
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
