//! File-access cross-checking for simple Bash commands (§8.3).

use crate::engine;
use crate::rules::RuleSet;

use super::prefix::{basename, peel_wrappers};
use super::tokenize::{RedirectKind, Token, tokenize};

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
    "openssl",
    "zcat",
    "xzcat",
    "bzcat",
    "gpg",
];

const PATTERN_FIRST: &[&str] = &[
    "grep", "egrep", "fgrep", "zgrep", "rgrep", "sed", "awk", "gawk",
];

const WRITERS: &[&str] = &["tee", "truncate"];

enum ReaderOpt<'a> {
    /// Supplies the pattern inline (`-e`, `--regexp`), so the first positional
    /// is a file rather than the pattern.
    Pattern(Option<&'a str>),
    /// Names a file that supplies the pattern (`-f`, `--file`): the file is
    /// read, and the first positional is a file too.
    PatternFile(Option<&'a str>),
    /// Names a file the reader opens without supplying the pattern
    /// (`--exclude-from`), so the pattern operand is still to come.
    AuxFile(Option<&'a str>),
}

/// Options taking a **separate** value that names neither a pattern nor a file.
/// The value must be consumed or it is misread as an operand. Deliberately short:
/// skipping a real file operand under-denies, so varying-arity options are left out.
struct ValueOpts {
    short: &'static [u8],
    long: &'static [&'static str],
}

const GREP_VALUE_OPTS: ValueOpts = ValueOpts {
    short: b"mABCdD",
    long: &[
        "--max-count",
        "--after-context",
        "--before-context",
        "--context",
        "--directories",
        "--devices",
        "--binary-files",
        "--label",
        "--include",
        "--exclude",
        "--exclude-dir",
    ],
};

const AWK_VALUE_OPTS: ValueOpts = ValueOpts {
    short: b"vF",
    long: &[],
};

const NO_VALUE_OPTS: ValueOpts = ValueOpts {
    short: b"",
    long: &[],
};

fn value_opts(name: &str) -> &'static ValueOpts {
    match name {
        "grep" | "egrep" | "fgrep" | "zgrep" | "rgrep" => &GREP_VALUE_OPTS,
        "awk" | "gawk" => &AWK_VALUE_OPTS,
        _ => &NO_VALUE_OPTS,
    }
}

/// Does `option` consume the **next** token as its value for reader `name`? Only
/// the separated spelling does; an attached value is self-contained, and in a
/// cluster the value-taking letter ends the token (`-im` consumes, `-mi` does not).
fn consumes_next_value(name: &str, option: &str) -> bool {
    let opts = value_opts(name);
    if option.starts_with("--") {
        return opts.long.contains(&option);
    }
    let Some(cluster) = option.strip_prefix('-') else {
        return false;
    };
    cluster.bytes().all(|c| c.is_ascii_alphanumeric())
        && cluster
            .bytes()
            .next_back()
            .is_some_and(|last| opts.short.contains(&last))
}

fn reader_option(op: &str) -> Option<ReaderOpt<'_>> {
    if op == "--file" {
        return Some(ReaderOpt::PatternFile(None));
    }
    if let Some(value) = op.strip_prefix("--file=") {
        return Some(ReaderOpt::PatternFile(Some(value)));
    }
    // `--exclude-from` names a file grep reads, so its value is checked rather
    // than skipped. It does not supply the pattern, so the pattern operand is
    // still to come.
    if op == "--exclude-from" {
        return Some(ReaderOpt::AuxFile(None));
    }
    if let Some(value) = op.strip_prefix("--exclude-from=") {
        return Some(ReaderOpt::AuxFile(Some(value)));
    }
    if op == "--regexp" {
        return Some(ReaderOpt::Pattern(None));
    }
    if let Some(value) = op.strip_prefix("--regexp=") {
        return Some(ReaderOpt::Pattern(Some(value)));
    }
    let b = op.as_bytes();
    if b.len() >= 2 && b[0] == b'-' && b[1] != b'-' {
        let attached = (op.len() > 2).then(|| &op[2..]);
        return match b[1] {
            b'f' => Some(ReaderOpt::PatternFile(attached)),
            b'e' => Some(ReaderOpt::Pattern(attached)),
            _ => None,
        };
    }
    None
}

/// Which file operand tripped the cross-check and the deny rule that stopped it,
/// so a decision can name the path rather than echo the command (§2.1).
pub(super) struct CrossHit {
    pub(super) operand: String,
    pub(super) rule: Option<usize>,
}

/// Check one operand against the deny rules for `tools`. The only place a
/// [`CrossHit`] is built, so every call site reports the operand it tested.
fn hits(rs: &RuleSet, tools: &[&str], path: &str, cwd: Option<&str>) -> Option<CrossHit> {
    engine::path_deny_hit(rs, tools, path, cwd).map(|rule| CrossHit {
        operand: path.to_string(),
        rule,
    })
}

/// Return the file operand by which a simple command reads or writes a denied path.
pub(super) fn cross_check(rs: &RuleSet, cmd: &str, cwd: Option<&str>) -> Option<CrossHit> {
    let tokens = tokenize(cmd);

    for token in &tokens {
        if let Token::Redirect(kind, target) = token {
            let hit = match kind {
                RedirectKind::In => hits(rs, &["Read"], target, cwd),
                _ => hits(rs, &["Write", "Edit"], target, cwd),
            };
            if hit.is_some() {
                return hit;
            }
        }
    }

    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|token| match token {
            Token::Word(word) => Some(word.as_str()),
            Token::Redirect(..) => None,
        })
        .collect();
    let words = peel_wrappers(&words);
    let &command = words.first()?;
    let name = basename(command);
    let operands = &words[1..];

    if name == "dd" {
        for operand in operands {
            if let Some(path) = operand.strip_prefix("if=")
                && !path.is_empty()
                && let Some(hit) = hits(rs, &["Read"], path, cwd)
            {
                return Some(hit);
            }
            if let Some(path) = operand.strip_prefix("of=")
                && !path.is_empty()
                && let Some(hit) = hits(rs, &["Write", "Edit"], path, cwd)
            {
                return Some(hit);
            }
        }
    } else if READERS.contains(&name) {
        if let Some(hit) = reader_reads_denied(rs, name, operands, cwd) {
            return Some(hit);
        }
    } else if WRITERS.contains(&name) {
        for operand in operands {
            if operand.starts_with('-') || operand.contains('=') {
                continue;
            }
            if let Some(hit) = hits(rs, &["Write", "Edit"], operand, cwd) {
                return Some(hit);
            }
        }
    } else if name == "cp" || name == "mv" {
        return cp_mv_denied(rs, operands, cwd);
    } else if name == "curl" {
        return curl_reads_denied(rs, operands, cwd);
    } else if name == "wget" {
        return wget_reads_denied(rs, operands, cwd);
    }
    None
}

fn reader_reads_denied(
    rs: &RuleSet,
    name: &str,
    operands: &[&str],
    cwd: Option<&str>,
) -> Option<CrossHit> {
    let pattern_first = PATTERN_FIRST.contains(&name);
    let mut pattern_consumed = false;
    let mut end_of_options = false;
    let mut i = 0;
    while i < operands.len() {
        let operand = operands[i];
        i += 1;
        if !end_of_options && operand == "--" {
            end_of_options = true;
            continue;
        }
        if !end_of_options && operand.len() > 1 && operand.starts_with('-') {
            if pattern_first && let Some(kind) = reader_option(operand) {
                let (checks_file, supplies_pattern, attached) = match kind {
                    ReaderOpt::Pattern(value) => (false, true, value),
                    ReaderOpt::PatternFile(value) => (true, true, value),
                    ReaderOpt::AuxFile(value) => (true, false, value),
                };
                pattern_consumed |= supplies_pattern;
                let value = attached.or_else(|| operands.get(i).copied().inspect(|_| i += 1));
                if checks_file
                    && let Some(value) = value
                    && !value.is_empty()
                    && let Some(hit) = hits(rs, &["Read"], value, cwd)
                {
                    return Some(hit);
                }
            } else if consumes_next_value(name, operand) {
                // The option's value is a separate token. Leaving it in place
                // shifts every later operand by one, so the pattern is read as a
                // file and a benign command is denied (§8.3).
                i += 1;
            }
            continue;
        }
        if pattern_first && !pattern_consumed {
            pattern_consumed = true;
            continue;
        }
        if let Some(hit) = hits(rs, &["Read"], operand, cwd) {
            return Some(hit);
        }
    }
    None
}

/// `cp` and `mv` touch two sides and both are checked. Sources go against `Read`
/// deny, since `cp .env /tmp/leak` exposes a secret exactly as `cat` does; the
/// destination goes against `Write`/`Edit`, since that is how a policy is swapped.
fn cp_mv_denied(rs: &RuleSet, operands: &[&str], cwd: Option<&str>) -> Option<CrossHit> {
    let mut target_dir = None;
    let mut positionals = Vec::new();
    let mut end_options = false;
    let mut i = 0;
    while i < operands.len() {
        let operand = operands[i];
        i += 1;
        if end_options {
            positionals.push(operand);
        } else if operand == "--" {
            end_options = true;
        } else if operand == "-t" || operand == "--target-directory" {
            if let Some(value) = operands.get(i) {
                target_dir = Some(*value);
                i += 1;
            }
        } else if let Some(value) = operand.strip_prefix("--target-directory=") {
            target_dir = Some(value);
        } else if let Some(value) = operand.strip_prefix("-t").filter(|value| !value.is_empty()) {
            target_dir = Some(value);
        } else if !(operand.starts_with('-') && operand.len() > 1) {
            positionals.push(operand);
        }
    }

    let reads = |path: &str| {
        (!path.is_empty())
            .then(|| hits(rs, &["Read"], path, cwd))
            .flatten()
    };
    let writes = |path: &str| {
        (!path.is_empty())
            .then(|| hits(rs, &["Write", "Edit"], path, cwd))
            .flatten()
    };

    // With `-t <dir>` every positional is a source; otherwise the last operand is
    // the destination and the rest are sources.
    let sources = match target_dir {
        Some(_) => positionals.as_slice(),
        None => positionals.split_last().map_or(&[][..], |(_, rest)| rest),
    };
    if let Some(hit) = sources.iter().find_map(|source| reads(source)) {
        return Some(hit);
    }

    if let Some(directory) = target_dir {
        if let Some(hit) = writes(directory) {
            return Some(hit);
        }
        let base = directory.trim_end_matches('/');
        return positionals
            .iter()
            .find_map(|source| writes(&format!("{base}/{}", basename(source))));
    }
    positionals
        .split_last()
        .and_then(|(destination, _)| writes(destination))
}

fn long_value<'a>(
    operand: &'a str,
    flag: &str,
    operands: &[&'a str],
    i: &mut usize,
) -> Option<&'a str> {
    let rest = operand.strip_prefix(flag)?;
    if rest.is_empty() {
        let value = operands.get(*i).copied();
        if value.is_some() {
            *i += 1;
        }
        value
    } else if let Some(value) = rest.strip_prefix('=') {
        Some(value)
    } else {
        None
    }
}

fn short_value<'a>(
    operand: &'a str,
    flag: u8,
    operands: &[&'a str],
    i: &mut usize,
) -> Option<&'a str> {
    let b = operand.as_bytes();
    if b.len() < 2 || b[0] != b'-' || b[1] == b'-' || b[1] != flag {
        return None;
    }
    if operand.len() == 2 {
        let value = operands.get(*i).copied();
        if value.is_some() {
            *i += 1;
        }
        value
    } else {
        Some(&operand[2..])
    }
}

fn curl_file_ref(value: &str) -> Option<&str> {
    if let Some(rest) = value.strip_prefix('@') {
        return Some(rest);
    }
    if let Some(position) = value.find('@') {
        return Some(&value[position + 1..]);
    }
    value.find('<').map(|position| &value[position + 1..])
}

fn curl_reads_denied(rs: &RuleSet, operands: &[&str], cwd: Option<&str>) -> Option<CrossHit> {
    let mut i = 0;
    while i < operands.len() {
        let operand = operands[i];
        i += 1;
        if let Some(path) = long_value(operand, "--upload-file", operands, &mut i)
            .or_else(|| short_value(operand, b'T', operands, &mut i))
        {
            if !path.is_empty()
                && let Some(hit) = hits(rs, &["Read"], path, cwd)
            {
                return Some(hit);
            }
            continue;
        }

        let data = long_value(operand, "--data-binary", operands, &mut i)
            .or_else(|| long_value(operand, "--data-ascii", operands, &mut i))
            .or_else(|| long_value(operand, "--data-urlencode", operands, &mut i))
            .or_else(|| long_value(operand, "--data", operands, &mut i))
            .or_else(|| long_value(operand, "--form", operands, &mut i))
            .or_else(|| short_value(operand, b'd', operands, &mut i))
            .or_else(|| short_value(operand, b'F', operands, &mut i));
        if let Some(value) = data
            && let Some(path) = curl_file_ref(value)
            && !path.is_empty()
            && let Some(hit) = hits(rs, &["Read"], path, cwd)
        {
            return Some(hit);
        }
    }
    None
}

fn wget_reads_denied(rs: &RuleSet, operands: &[&str], cwd: Option<&str>) -> Option<CrossHit> {
    let mut i = 0;
    while i < operands.len() {
        let operand = operands[i];
        i += 1;
        if let Some(path) = long_value(operand, "--post-file", operands, &mut i)
            .or_else(|| long_value(operand, "--body-file", operands, &mut i))
            && !path.is_empty()
            && let Some(hit) = hits(rs, &["Read"], path, cwd)
        {
            return Some(hit);
        }
    }
    None
}
