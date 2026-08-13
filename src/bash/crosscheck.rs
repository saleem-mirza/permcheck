//! File-access cross-checking for simple Bash commands (§8.3).

use crate::engine;
use crate::matcher::WorkBudget;
use crate::rules::RuleSet;

use super::prefix::{
    ValueOpts, basename, command_name, consumes_next_value, name_eq, name_in, peel_wrappers,
    short_value_option,
};
use super::tokenize::{RedirectKind, shell_words};

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

/// Commands whose every positional operand is a file they overwrite or destroy,
/// so each is checked against the `Write`/`Edit` deny. Deleting a protected path
/// ends it as thoroughly as writing over it, so `rm` and `shred` belong here.
const WRITERS: &[&str] = &["tee", "truncate", "rm", "shred"];

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

/// Reader options taking a **separate** value that names neither a pattern nor a
/// file. Deliberately short: skipping a real file operand under-denies, so
/// varying-arity options are left out.
const GREP_VALUE_OPTS: ValueOpts = ValueOpts {
    short: b"mABCdDef",
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
    short: b"vFef",
    long: &[],
};

const SED_VALUE_OPTS: ValueOpts = ValueOpts {
    short: b"ef",
    long: &[],
};

/// `sort` reads its inputs, but `-o`/`--output` names a file it writes. Consuming
/// the value here keeps [`reader_reads_denied`] from treating the output path as
/// an input operand and checking it against `Read` instead of `Write`.
const SORT_VALUE_OPTS: ValueOpts = ValueOpts {
    short: b"koStT",
    long: &["--output"],
};

const NO_VALUE_OPTS: ValueOpts = ValueOpts {
    short: b"",
    long: &[],
};

/// Curl short options with mandatory values. The first one in a cluster owns
/// every byte after it, so an apparent `d`, `F`, or `T` later in that value is
/// not a file-reading flag. Kept beside the curl parser rather than in the
/// wrapper table because these options describe curl itself.
const CURL_VALUE_OPTS: &[u8] = b"AbcCdDEeFhHKmoPQrTtUuwxXyYz";

fn value_opts(name: &str) -> &'static ValueOpts {
    if name_in(name, &["grep", "egrep", "fgrep", "zgrep", "rgrep"]) {
        &GREP_VALUE_OPTS
    } else if name_in(name, &["awk", "gawk"]) {
        &AWK_VALUE_OPTS
    } else if name_eq(name, "sed") {
        &SED_VALUE_OPTS
    } else if name_eq(name, "sort") {
        &SORT_VALUE_OPTS
    } else {
        &NO_VALUE_OPTS
    }
}

fn reader_option<'a>(name: &str, op: &'a str) -> Option<ReaderOpt<'a>> {
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
    // The first value-taking flag decides the rest of a short-option bundle. In
    // `grep -if FILE`, `f` is first and consumes FILE; in `grep -mf`, `m` owns
    // the attached value `f`, so that byte must not be re-read as a file flag.
    let (flag, attached) = short_value_option(op, value_opts(name).short)?;
    Some(match flag {
        b'f' => ReaderOpt::PatternFile(attached),
        b'e' => ReaderOpt::Pattern(attached),
        _ => return None,
    })
}

/// Which file operand tripped the cross-check and the deny rule that stopped it,
/// so a decision can name the path rather than echo the command (§2.1).
pub(super) struct CrossHit {
    pub(super) operand: String,
    pub(super) rule: Option<usize>,
}

/// Check one operand against the deny rules for `tools`. The only place a
/// [`CrossHit`] is built, so every call site reports the operand it tested.
fn hits(
    rs: &RuleSet,
    tools: &[&str],
    path: &str,
    cwd: Option<&str>,
    budget: &mut WorkBudget,
) -> Option<CrossHit> {
    engine::path_deny_hit(rs, tools, path, cwd, budget).map(|rule| CrossHit {
        operand: path.to_string(),
        rule,
    })
}

/// Return the file operand by which a simple command reads or writes a denied path.
pub(super) fn cross_check(
    rs: &RuleSet,
    cmd: &str,
    cwd: Option<&str>,
    budget: &mut WorkBudget,
) -> Option<CrossHit> {
    // The shared lexical layer, not the owned `tokenize` wrapper: every word is
    // borrowed straight back out below, so building a `Token` per word only to
    // discard the ownership cost one `String` per word per unit.
    let parsed = shell_words(cmd);

    for word in &parsed {
        if let Some(kind) = word.redirect {
            let hit = match kind {
                RedirectKind::In => hits(rs, &["Read"], &word.value, cwd, budget),
                _ => hits(rs, &["Write", "Edit"], &word.value, cwd, budget),
            };
            if hit.is_some() {
                return hit;
            }
        }
    }

    let words: Vec<&str> = parsed
        .iter()
        .filter(|word| word.redirect.is_none())
        .map(|word| word.value.as_str())
        .collect();
    // A wrapper option of unknown arity leaves more than one candidate command
    // word (§8.2); the most-peeled reading comes first, so the hit it names is
    // the accurate one whenever it fires.
    peel_wrappers(&words)
        .into_iter()
        .find_map(|reading| simple_command_hit(rs, reading, cwd, budget))
}

/// Return the file operand by which one reading of a simple command reads or
/// writes a denied path.
fn simple_command_hit(
    rs: &RuleSet,
    words: &[&str],
    cwd: Option<&str>,
    budget: &mut WorkBudget,
) -> Option<CrossHit> {
    let &command = words.first()?;
    let name = command_name(command);
    let operands = &words[1..];

    if name_eq(name, "dd") {
        for operand in operands {
            if let Some(path) = operand.strip_prefix("if=")
                && !path.is_empty()
                && let Some(hit) = hits(rs, &["Read"], path, cwd, budget)
            {
                return Some(hit);
            }
            if let Some(path) = operand.strip_prefix("of=")
                && !path.is_empty()
                && let Some(hit) = hits(rs, &["Write", "Edit"], path, cwd, budget)
            {
                return Some(hit);
            }
        }
    } else if name_in(name, READERS) {
        // `sort -o FILE` writes FILE, unlike every other reader; check it against
        // the write deny before the read-operand scan.
        if name_eq(name, "sort")
            && let Some(hit) = sort_writes_denied(rs, operands, cwd, budget)
        {
            return Some(hit);
        }
        if let Some(hit) = reader_reads_denied(rs, name, operands, cwd, budget) {
            return Some(hit);
        }
    } else if name_in(name, WRITERS) {
        let mut end_of_options = false;
        for operand in operands {
            if !end_of_options && *operand == "--" {
                end_of_options = true;
                continue;
            }
            if !end_of_options && operand.len() > 1 && operand.starts_with('-') {
                continue;
            }
            if let Some(hit) = hits(rs, &["Write", "Edit"], operand, cwd, budget) {
                return Some(hit);
            }
        }
    } else if name_in(name, &["cp", "mv"]) {
        return cp_mv_denied(rs, operands, cwd, budget);
    } else if name_eq(name, "curl") {
        return curl_reads_denied(rs, operands, cwd, budget);
    } else if name_eq(name, "wget") {
        return wget_reads_denied(rs, operands, cwd, budget);
    }
    None
}

fn reader_reads_denied(
    rs: &RuleSet,
    name: &str,
    operands: &[&str],
    cwd: Option<&str>,
    budget: &mut WorkBudget,
) -> Option<CrossHit> {
    let pattern_first = name_in(name, PATTERN_FIRST);
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
            if pattern_first && let Some(kind) = reader_option(name, operand) {
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
                    && let Some(hit) = hits(rs, &["Read"], value, cwd, budget)
                {
                    return Some(hit);
                }
            } else if consumes_next_value(value_opts(name), operand) {
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
        if let Some(hit) = hits(rs, &["Read"], operand, cwd, budget) {
            return Some(hit);
        }
    }
    None
}

/// `cp` and `mv` touch two sides and both are checked. Sources go against `Read`
/// deny, since `cp .env /tmp/leak` exposes a secret exactly as `cat` does; the
/// destination goes against `Write`/`Edit`, since that is how a policy is swapped.
fn cp_mv_denied(
    rs: &RuleSet,
    operands: &[&str],
    cwd: Option<&str>,
    budget: &mut WorkBudget,
) -> Option<CrossHit> {
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
        } else if operand == "--target-directory" {
            if let Some(value) = operands.get(i) {
                target_dir = Some(*value);
                i += 1;
            }
        } else if let Some(value) = operand.strip_prefix("--target-directory=") {
            target_dir = Some(value);
        } else if let Some(value) = short_value(operand, b't', b"St", operands, &mut i) {
            // `-t DIR`, `-tDIR`, and the bundled `-rt DIR`, which is how a copy
            // into a denied directory otherwise reached no check at all.
            target_dir = Some(value);
        } else if !(operand.starts_with('-') && operand.len() > 1) {
            positionals.push(operand);
        }
    }

    let reads = |path: &str, budget: &mut WorkBudget| {
        (!path.is_empty())
            .then(|| hits(rs, &["Read"], path, cwd, budget))
            .flatten()
    };
    let writes = |path: &str, budget: &mut WorkBudget| {
        (!path.is_empty())
            .then(|| hits(rs, &["Write", "Edit"], path, cwd, budget))
            .flatten()
    };

    // Resolve the destination directory when the operands name one: an explicit
    // `-t`/`--target-directory`, a trailing-slash last operand, or 3+ operands
    // (cp/mv then require the last to be an existing directory). Every source
    // lands inside it under its basename, so each landing path is a write — the
    // same effect the `-t` form has, which denied while the trailing-slash and
    // multi-operand spellings of the identical copy used to slip through.
    let (directory, sources) = match target_dir {
        Some(dir) => (Some(dir), positionals.as_slice()),
        None => match positionals.split_last() {
            Some((&last, rest)) if last.ends_with('/') || positionals.len() >= 3 => {
                (Some(last), rest)
            }
            _ => (
                None,
                positionals.split_last().map_or(&[][..], |(_, rest)| rest),
            ),
        },
    };
    if let Some(hit) = sources.iter().find_map(|source| reads(source, budget)) {
        return Some(hit);
    }

    if let Some(directory) = directory {
        if let Some(hit) = writes(directory, budget) {
            return Some(hit);
        }
        let base = directory.trim_end_matches('/');
        return sources
            .iter()
            .find_map(|source| writes(&format!("{base}/{}", basename(source)), budget));
    }
    positionals
        .split_last()
        .and_then(|(destination, _)| writes(destination, budget))
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
    value_flags: &[u8],
    operands: &[&'a str],
    i: &mut usize,
) -> Option<&'a str> {
    let (found, attached) = short_value_option(operand, value_flags)?;
    if found != flag {
        return None;
    }
    if let Some(attached) = attached {
        return Some(attached);
    }
    // `-T FILE`, and the bundled `-sT FILE`: the value is the next token.
    let value = operands.get(*i).copied();
    if value.is_some() {
        *i += 1;
    }
    value
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

fn curl_reads_denied(
    rs: &RuleSet,
    operands: &[&str],
    cwd: Option<&str>,
    budget: &mut WorkBudget,
) -> Option<CrossHit> {
    let mut i = 0;
    while i < operands.len() {
        let operand = operands[i];
        i += 1;
        if let Some(path) = long_value(operand, "--upload-file", operands, &mut i)
            .or_else(|| short_value(operand, b'T', CURL_VALUE_OPTS, operands, &mut i))
        {
            if !path.is_empty()
                && let Some(hit) = hits(rs, &["Read"], path, cwd, budget)
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
            .or_else(|| short_value(operand, b'd', CURL_VALUE_OPTS, operands, &mut i))
            .or_else(|| short_value(operand, b'F', CURL_VALUE_OPTS, operands, &mut i));
        if let Some(value) = data
            && let Some(path) = curl_file_ref(value)
            && !path.is_empty()
            && let Some(hit) = hits(rs, &["Read"], path, cwd, budget)
        {
            return Some(hit);
        }
    }
    None
}

/// Return the file operand by which `sort -o FILE` / `sort --output=FILE` writes a
/// denied path. `sort` reads its inputs like any reader; this covers the one flag
/// that turns it into a writer.
fn sort_writes_denied(
    rs: &RuleSet,
    operands: &[&str],
    cwd: Option<&str>,
    budget: &mut WorkBudget,
) -> Option<CrossHit> {
    let mut i = 0;
    while i < operands.len() {
        let operand = operands[i];
        i += 1;
        if let Some(path) = long_value(operand, "--output", operands, &mut i)
            .or_else(|| short_value(operand, b'o', SORT_VALUE_OPTS.short, operands, &mut i))
            && !path.is_empty()
            && let Some(hit) = hits(rs, &["Write", "Edit"], path, cwd, budget)
        {
            return Some(hit);
        }
    }
    None
}

fn wget_reads_denied(
    rs: &RuleSet,
    operands: &[&str],
    cwd: Option<&str>,
    budget: &mut WorkBudget,
) -> Option<CrossHit> {
    let mut i = 0;
    while i < operands.len() {
        let operand = operands[i];
        i += 1;
        if let Some(path) = long_value(operand, "--post-file", operands, &mut i)
            .or_else(|| long_value(operand, "--body-file", operands, &mut i))
            && !path.is_empty()
            && let Some(hit) = hits(rs, &["Read"], path, cwd, budget)
        {
            return Some(hit);
        }
    }
    None
}
