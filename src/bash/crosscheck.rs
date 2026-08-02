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
    Pattern(Option<&'a str>),
    File(Option<&'a str>),
}

fn reader_option(op: &str) -> Option<ReaderOpt<'_>> {
    if op == "--file" {
        return Some(ReaderOpt::File(None));
    }
    if let Some(value) = op.strip_prefix("--file=") {
        return Some(ReaderOpt::File(Some(value)));
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
            b'f' => Some(ReaderOpt::File(attached)),
            b'e' => Some(ReaderOpt::Pattern(attached)),
            _ => None,
        };
    }
    None
}

/// Return whether a simple command reads or writes a denied path.
pub(super) fn cross_check(rs: &RuleSet, cmd: &str, cwd: Option<&str>) -> bool {
    let tokens = tokenize(cmd);

    for token in &tokens {
        if let Token::Redirect(kind, target) = token {
            let hit = match kind {
                RedirectKind::In => engine::path_hits_deny(rs, &["Read"], target, cwd),
                _ => engine::path_hits_deny(rs, &["Write", "Edit"], target, cwd),
            };
            if hit {
                return true;
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
    let Some(&command) = words.first() else {
        return false;
    };
    let name = basename(command);
    let operands = &words[1..];

    if name == "dd" {
        for operand in operands {
            if let Some(path) = operand.strip_prefix("if=")
                && !path.is_empty()
                && engine::path_hits_deny(rs, &["Read"], path, cwd)
            {
                return true;
            }
            if let Some(path) = operand.strip_prefix("of=")
                && !path.is_empty()
                && engine::path_hits_deny(rs, &["Write", "Edit"], path, cwd)
            {
                return true;
            }
        }
    } else if READERS.contains(&name) {
        if reader_reads_denied(rs, name, operands, cwd) {
            return true;
        }
    } else if WRITERS.contains(&name) {
        for operand in operands {
            if operand.starts_with('-') || operand.contains('=') {
                continue;
            }
            if engine::path_hits_deny(rs, &["Write", "Edit"], operand, cwd) {
                return true;
            }
        }
    } else if ((name == "cp" || name == "mv") && cp_mv_writes_denied(rs, operands, cwd))
        || (name == "curl" && curl_reads_denied(rs, operands, cwd))
        || (name == "wget" && wget_reads_denied(rs, operands, cwd))
    {
        return true;
    }
    false
}

fn reader_reads_denied(rs: &RuleSet, name: &str, operands: &[&str], cwd: Option<&str>) -> bool {
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
                pattern_consumed = true;
                let (is_file, attached) = match kind {
                    ReaderOpt::File(value) => (true, value),
                    ReaderOpt::Pattern(value) => (false, value),
                };
                let value = attached.or_else(|| operands.get(i).copied().inspect(|_| i += 1));
                if is_file
                    && let Some(value) = value
                    && !value.is_empty()
                    && engine::path_hits_deny(rs, &["Read"], value, cwd)
                {
                    return true;
                }
            }
            continue;
        }
        if pattern_first && !pattern_consumed {
            pattern_consumed = true;
            continue;
        }
        if engine::path_hits_deny(rs, &["Read"], operand, cwd) {
            return true;
        }
    }
    false
}

fn cp_mv_writes_denied(rs: &RuleSet, operands: &[&str], cwd: Option<&str>) -> bool {
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

    let hits =
        |path: &str| !path.is_empty() && engine::path_hits_deny(rs, &["Write", "Edit"], path, cwd);
    if let Some(directory) = target_dir {
        if hits(directory) {
            return true;
        }
        let base = directory.trim_end_matches('/');
        return positionals
            .iter()
            .any(|source| hits(&format!("{base}/{}", basename(source))));
    }
    positionals
        .split_last()
        .is_some_and(|(destination, _)| hits(destination))
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

fn curl_reads_denied(rs: &RuleSet, operands: &[&str], cwd: Option<&str>) -> bool {
    let mut i = 0;
    while i < operands.len() {
        let operand = operands[i];
        i += 1;
        if let Some(path) = long_value(operand, "--upload-file", operands, &mut i)
            .or_else(|| short_value(operand, b'T', operands, &mut i))
        {
            if !path.is_empty() && engine::path_hits_deny(rs, &["Read"], path, cwd) {
                return true;
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
            && engine::path_hits_deny(rs, &["Read"], path, cwd)
        {
            return true;
        }
    }
    false
}

fn wget_reads_denied(rs: &RuleSet, operands: &[&str], cwd: Option<&str>) -> bool {
    let mut i = 0;
    while i < operands.len() {
        let operand = operands[i];
        i += 1;
        if let Some(path) = long_value(operand, "--post-file", operands, &mut i)
            .or_else(|| long_value(operand, "--body-file", operands, &mut i))
            && !path.is_empty()
            && engine::path_hits_deny(rs, &["Read"], path, cwd)
        {
            return true;
        }
    }
    false
}
