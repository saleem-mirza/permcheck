//! Best-effort compound-command splitting (§8.1).

/// Nesting depth cap for substitutions (§9.1). `scan` recurses once per level,
/// and a stack overflow aborts instead of unwinding, so `catch_unwind` could not
/// turn it into `deny`. Well above any real command, well below the 1 MiB
/// main-thread stack on Windows.
const MAX_SUBST_DEPTH: u32 = 64;

/// Unit ranges collected so far, current substitution depth, and whether the cap
/// was hit.
struct ScanCtx {
    out: Vec<(usize, usize)>,
    depth: u32,
    too_deep: bool,
}

/// Split a command into borrowed units for the decision hot path. The flag is
/// `true` when nesting exceeded [`MAX_SUBST_DEPTH`]: the units are incomplete, so
/// the caller must fail closed rather than decide on them.
pub(super) fn units(input: &str) -> (Vec<&str>, bool) {
    let mut ctx = ScanCtx {
        out: Vec::new(),
        depth: 0,
        too_deep: false,
    };
    scan(input, 0, input.len(), &mut ctx);
    let units = ctx
        .out
        .into_iter()
        .map(|(a, b)| input[a..b].trim())
        .filter(|unit| !unit.is_empty())
        .collect();
    (units, ctx.too_deep)
}

/// Owned compatibility wrapper exposed by [`super::split`]. The decision path
/// uses [`units`], which reports truncation.
pub(super) fn owned_units(input: &str) -> Vec<String> {
    units(input).0.into_iter().map(str::to_owned).collect()
}

fn scan(s: &str, start: usize, end: usize, ctx: &mut ScanCtx) {
    let b = s.as_bytes();
    let mut i = start;
    let mut unit_start = start;
    while i < end {
        match b[i] {
            b'\\' => i += 2,
            b'\'' => i = skip_single(b, i + 1, end),
            b'"' => i = skip_double(s, i + 1, end, ctx),
            b'`' => i = handle_backtick(s, i + 1, end, ctx),
            b'$' if i + 1 < end && b[i + 1] == b'(' => {
                if i + 2 < end && b[i + 2] == b'(' {
                    i = skip_arith(b, i + 3, end);
                } else {
                    i = handle_paren(s, i + 2, end, ctx);
                }
            }
            b'<' | b'>' if i + 1 < end && b[i + 1] == b'(' => {
                i = handle_paren(s, i + 2, end, ctx);
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
                    ctx.out.push((unit_start, i));
                    i += 2;
                    unit_start = i;
                } else if i + 1 < end && b[i + 1] == b'>' {
                    i += 1;
                } else {
                    ctx.out.push((unit_start, i));
                    i += 1;
                    unit_start = i;
                }
            }
            b'|' => {
                ctx.out.push((unit_start, i));
                i += if i + 1 < end && b[i + 1] == b'|' {
                    2
                } else {
                    1
                };
                unit_start = i;
            }
            b';' | b'\n' => {
                ctx.out.push((unit_start, i));
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
                ctx.out.push((unit_start, i));
                while i < end && b[i] != b'\n' {
                    i += 1;
                }
                unit_start = i;
            }
            _ => i += 1,
        }
    }
    if unit_start < end {
        ctx.out.push((unit_start, end));
    }
}

pub(super) fn skip_single(b: &[u8], mut i: usize, end: usize) -> usize {
    while i < end && b[i] != b'\'' {
        i += 1;
    }
    if i < end { i + 1 } else { end }
}

fn skip_double(s: &str, mut i: usize, end: usize, ctx: &mut ScanCtx) -> usize {
    let b = s.as_bytes();
    while i < end && b[i] != b'"' {
        if b[i] == b'\\' {
            i += 2;
        } else if b[i] == b'$' && i + 1 < end && b[i + 1] == b'(' {
            if i + 2 < end && b[i + 2] == b'(' {
                i = skip_arith(b, i + 3, end);
            } else {
                i = handle_paren(s, i + 2, end, ctx);
            }
        } else if b[i] == b'`' {
            i = handle_backtick(s, i + 1, end, ctx);
        } else {
            i += 1;
        }
    }
    if i < end { i + 1 } else { end }
}

fn handle_paren(s: &str, inner: usize, end: usize, ctx: &mut ScanCtx) -> usize {
    let close = find_close_paren(s, inner, end);
    scan_nested(s, inner, close, ctx);
    if close < end { close + 1 } else { end }
}

/// Scan a substitution's interior one level deeper. Past [`MAX_SUBST_DEPTH`] this
/// sets `too_deep` instead of descending, so the caller fails closed.
fn scan_nested(s: &str, start: usize, end: usize, ctx: &mut ScanCtx) {
    if ctx.depth >= MAX_SUBST_DEPTH {
        ctx.too_deep = true;
        return;
    }
    ctx.depth += 1;
    scan(s, start, end, ctx);
    ctx.depth -= 1;
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

fn handle_backtick(s: &str, inner: usize, end: usize, ctx: &mut ScanCtx) -> usize {
    let b = s.as_bytes();
    let mut j = inner;
    while j < end && b[j] != b'`' {
        j += 1;
    }
    scan_nested(s, inner, j, ctx);
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
