//! Compound-Bash decision pipeline (§8).
//!
//! A single Bash `command` may contain several commands. [`decide_bash`] splits
//! it into units, decides each against the Bash matchers, applies a file-access
//! cross-check that can only raise a unit to `deny`, and aggregates the
//! most-restrictive verdict. The splitter is total: it never errors.

use crate::engine;
use crate::rules::RuleSet;
use crate::types::{Decision, Tier};

/// Decide a Bash command by aggregating per-unit verdicts (§8).
pub fn decide_bash(command: &str, rs: &RuleSet, cwd: Option<&str>) -> Decision {
    let units = split(command);
    if units.is_empty() {
        // Empty / whitespace-only command matches no Bash rule -> fall-back tier.
        return Decision::for_call(rs.default_tier, "Bash", command);
    }

    let mut worst = Tier::Allow;
    for unit in &units {
        let cmd = strip_env_assignments(unit);
        let mut tier = unit_tier(rs, cmd);
        // A leading wrapper (`env`, `sudo`, `timeout`, …) executes the command
        // that follows it, so the wrapped command's own decision must apply too.
        // Otherwise `env aws …` would ride in on the wrapper's allow rule and
        // bypass an `aws` deny. This can only raise the verdict (§8.3).
        if let Some(inner) = strip_leading_wrappers(cmd) {
            let inner_tier = unit_tier(rs, inner);
            if inner_tier > tier {
                tier = inner_tier;
            }
        }
        // The file-access cross-check raises a unit to deny only; skip it once we
        // are already at deny. Flag-variant and interpreter-inline normalization
        // are handled inside `unit_tier` (for the command and the wrapped inner).
        if tier != Tier::Deny && cross_check(rs, cmd, cwd) {
            tier = Tier::Deny;
        }
        if tier > worst {
            worst = tier;
        }
    }

    Decision::for_call(worst, "Bash", command)
}

/// The tier of a single (already env-stripped) command string against the Bash
/// matchers, taking the rule set's `defaultMode` fall-back when nothing matches
/// (§6.3, §6.4).
///
/// The command is matched in normalized forms as well as verbatim, so an
/// invocation cannot dodge a rule by dressing up the command line. Two kinds:
///
/// - **Identity** forms — the same command spelled with a path or global
///   options: a **path-qualified** executable (`/usr/bin/aws …`) matches by
///   basename, and a **git** invocation with global options before the
///   subcommand (`git -c x config …`) matches the subcommand-exposed form. These
///   decide together with the raw command, so an allow can still win (a
///   path-qualified allowed binary stays allowed).
///
/// - **Escalation** forms — a clustered/split short-flag set (`rm -Rf` -> `rm -f`)
///   and an interpreter inline-code invocation (`perl -we` -> `perl -e`,
///   `node --eval` -> `node -e`). Each is decided on its own and can only RAISE
///   the verdict, and only on a real rule match — so an interpreter the rules do
///   not mention keeps the base verdict (its `defaultMode`), never a hard-coded
///   deny. The policy stays in the rules; the engine only normalizes the form.
fn unit_tier(rs: &RuleSet, cmd: &str) -> Tier {
    let base_owned = basename_command(cmd);
    let base: &str = base_owned.as_deref().unwrap_or(cmd);
    let git_owned = git_subcommand_form(base);

    let mut identity: Vec<&str> = vec![cmd];
    identity.extend(base_owned.as_deref());
    identity.extend(git_owned.as_deref());
    let mut tier = engine::decide_tier(rs, "Bash", &identity).unwrap_or(rs.default_tier);

    let mut esc: Vec<String> = flag_split_candidates(base);
    esc.extend(inline_exec_candidate(base));
    for e in &esc {
        if let Some(t) = engine::decide_tier(rs, "Bash", &[e.as_str()])
            && t > tier
        {
            tier = t;
        }
    }
    tier
}

/// Git global options placed *before* the subcommand that consume the following
/// token as their value, so it is not mistaken for the subcommand.
const GIT_VALUE_OPTS: &[&str] = &[
    "-c",
    "-C",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
    "--exec-path",
];

/// If `cmd` is a `git` invocation with global options before the subcommand
/// (`git -c core.pager=cat config …`, `git -C /repo push --force`), return the
/// command with those options dropped so the subcommand is exposed to the
/// `Bash(git <sub>:*)` rules. Returns `None` when `cmd` is not `git`, has no
/// leading global options, or leaves no subcommand.
fn git_subcommand_form(cmd: &str) -> Option<String> {
    let after = cmd
        .trim_start()
        .strip_prefix("git")?
        .strip_prefix([' ', '\t'])?;
    let tokens: Vec<&str> = after.split_ascii_whitespace().collect();
    let mut i = 0;
    let mut peeled = false;
    while let Some(&tok) = tokens.get(i) {
        if !tok.starts_with('-') {
            break; // the subcommand
        }
        peeled = true;
        // `-c name=value` / `-C path` consume the next token; `--opt=value` and
        // bare flags are self-contained.
        i += if GIT_VALUE_OPTS.contains(&tok) { 2 } else { 1 };
    }
    if !peeled || i >= tokens.len() {
        return None;
    }
    Some(format!("git {}", tokens[i..].join(" ")))
}

/// An interpreter and the option forms that make it run inline code from the
/// command line (rather than a script file). The inline flag is interpreter-
/// specific — `perl -c` is a *syntax check*, `python -c` *executes* — so this is
/// a per-interpreter table, not a shared flag set: `short` lists short flags
/// (each canonicalized to `-<flag>`), `long` maps a long option to its canonical
/// short form, and `subcommand` lists an inline subcommand (`deno eval`). Adding
/// a language is one row. The table normalizes the *form* only; whether an
/// interpreter's inline exec is denied stays in the rules.
struct Interp {
    name: &'static str,
    short: &'static [u8],
    long: &'static [(&'static str, &'static str)],
    subcommand: &'static [&'static str],
}

const INTERPRETERS: &[Interp] = &[
    Interp { name: "python", short: b"c", long: &[], subcommand: &[] },
    Interp { name: "python2", short: b"c", long: &[], subcommand: &[] },
    Interp { name: "python3", short: b"c", long: &[], subcommand: &[] },
    Interp { name: "pypy", short: b"c", long: &[], subcommand: &[] },
    Interp { name: "pypy3", short: b"c", long: &[], subcommand: &[] },
    Interp { name: "perl", short: b"eE", long: &[], subcommand: &[] },
    Interp { name: "perl5", short: b"eE", long: &[], subcommand: &[] },
    Interp { name: "ruby", short: b"e", long: &[], subcommand: &[] },
    Interp { name: "node", short: b"ep", long: &[("--eval", "-e"), ("--print", "-p")], subcommand: &[] },
    Interp { name: "nodejs", short: b"ep", long: &[("--eval", "-e"), ("--print", "-p")], subcommand: &[] },
    Interp { name: "bun", short: b"e", long: &[("--eval", "-e")], subcommand: &[] },
    Interp { name: "deno", short: b"", long: &[], subcommand: &["eval"] },
    Interp { name: "php", short: b"r", long: &[], subcommand: &[] },
    Interp { name: "lua", short: b"e", long: &[], subcommand: &[] },
    Interp { name: "luajit", short: b"e", long: &[], subcommand: &[] },
    Interp { name: "Rscript", short: b"e", long: &[], subcommand: &[] },
];

/// If `cmd` invokes a known interpreter with an inline-code option in any form
/// (`python3 -cimport`, `python3 -W ignore -c`, `perl -we`, `node --eval`,
/// `deno eval`, `bun -e`), return the canonical `<basename> <flag>` form
/// (`python3 -c`, `perl -e`, `node -e`, `deno eval`) so every spelling matches
/// whatever the rules say about that interpreter. Returns `None` for a plain
/// script/module run (`python3 app.py`, `perl -c`) — no inline option present.
fn inline_exec_candidate(cmd: &str) -> Option<String> {
    let mut toks = cmd.split_ascii_whitespace();
    let name = basename(toks.next()?);
    let interp = INTERPRETERS.iter().find(|i| i.name == name)?;
    for tok in toks {
        if tok == "--" {
            break; // end of options; the rest are operands
        }
        let b = tok.as_bytes();
        if b.first() != Some(&b'-') {
            // A non-option token: an inline subcommand (`deno eval`), else a
            // script/operand — keep scanning for a later inline flag.
            if interp.subcommand.contains(&tok) {
                return Some(format!("{name} {tok}"));
            }
            continue;
        }
        if let Some(rest) = tok.strip_prefix("--") {
            let head = rest.split('=').next().unwrap_or(rest);
            for &(long, canon) in interp.long {
                if long.strip_prefix("--") == Some(head) {
                    return Some(format!("{name} {canon}"));
                }
            }
            continue;
        }
        // Short bundle: an inline flag anywhere in the run, before an attached
        // value (`-cimport`, `-we`). A value-taking flag can misread here, but
        // over-approximating toward the deny is the safe direction.
        for &c in &b[1..] {
            if interp.short.contains(&c) {
                return Some(format!("{name} -{}", c as char));
            }
            if !c.is_ascii_alphanumeric() {
                break; // attached value begins
            }
        }
    }
    None
}

/// Split the leading short-flag bundles of `cmd` into individual `<cmd> -<flag>`
/// candidate strings, so a reordered / clustered / split flag set can match a
/// single-flag deny rule. Returns empty when fewer than two distinct flags lead
/// the command — a lone `-x` already matches its prefix rule verbatim, and a
/// bare command has no flags. Only leading option tokens are scanned; a long
/// option (`--force`) or the first operand ends the scan, and a bundle carrying
/// an attached value (`-e'code'`, `--x=y`) is left intact.
fn flag_split_candidates(cmd: &str) -> Vec<String> {
    let mut toks = cmd.split_ascii_whitespace();
    let Some(cmd_word) = toks.next() else {
        return Vec::new();
    };
    let mut flags: Vec<u8> = Vec::new();
    for tok in toks {
        let b = tok.as_bytes();
        // Stop at an operand or a long option; a short bundle is `-` + alnums.
        if b.len() < 2 || b[0] != b'-' || b[1] == b'-' {
            break;
        }
        if !b[1..].iter().all(|&c| c.is_ascii_alphanumeric()) {
            break; // attached value / `=` — not a plain flag bundle
        }
        for &f in &b[1..] {
            if !flags.contains(&f) {
                flags.push(f);
            }
        }
    }
    if flags.len() < 2 {
        return Vec::new();
    }
    flags
        .iter()
        .map(|&f| format!("{cmd_word} -{}", f as char))
        .collect()
}

/// If the command's leading executable token is path-qualified (`/usr/bin/aws`,
/// `./aws`, `../bin/rm`), return the command with that token reduced to its
/// basename (`aws …`, `rm …`). Returns `None` when the leading token carries no
/// `/` (nothing to strip) or reduces to empty (a bare `/`, or a trailing-slash
/// token), so a bare-name command allocates nothing.
fn basename_command(cmd: &str) -> Option<String> {
    let trimmed = cmd.trim_start();
    let end = trimmed
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(trimmed.len());
    let exe = &trimmed[..end];
    if !exe.contains('/') {
        return None;
    }
    let base = basename(exe);
    if base.is_empty() || base == exe {
        return None;
    }
    Some(format!("{base}{}", &trimmed[end..]))
}

// --- Splitter (§8.1) ---------------------------------------------------------

/// Split a command into units on shell operators outside quotes, pulling inner
/// commands out of `$(…)`, backticks, and `<(…)` / `>(…)` substitutions. Never
/// errors; unterminated constructs are consumed to end of input.
pub fn split(input: &str) -> Vec<String> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    scan(input, 0, input.len(), &mut ranges);
    ranges
        .into_iter()
        .filter_map(|(a, b)| {
            let t = input[a..b].trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        })
        .collect()
}

fn scan(s: &str, start: usize, end: usize, out: &mut Vec<(usize, usize)>) {
    let b = s.as_bytes();
    let mut i = start;
    let mut unit_start = start;
    while i < end {
        match b[i] {
            // Outside quotes a backslash escapes the next byte, making it
            // literal: `\"` is a literal quote (not a quote opener), `\;` a
            // literal semicolon, etc. Skip both bytes so an escaped metachar
            // never opens a quoted region or a split point.
            b'\\' => i += 2,
            b'\'' => i = skip_single(b, i + 1, end),
            b'"' => i = skip_double(s, i + 1, end, out),
            b'`' => i = handle_backtick(s, i + 1, end, out),
            b'$' if i + 1 < end && b[i + 1] == b'(' => {
                if i + 2 < end && b[i + 2] == b'(' {
                    i = skip_arith(b, i + 3, end); // $(( … )) is literal
                } else {
                    i = handle_paren(s, i + 2, end, out); // command substitution
                }
            }
            b'<' | b'>' if i + 1 < end && b[i + 1] == b'(' => {
                i = handle_paren(s, i + 2, end, out); // process substitution
            }
            b'<' => {
                // Redirection, not a split point.
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
                    // `&>` / `&>>` redirection; the `>` is consumed next pass.
                    i += 1;
                } else {
                    out.push((unit_start, i));
                    i += 1;
                    unit_start = i;
                }
            }
            b'|' => {
                out.push((unit_start, i));
                if i + 1 < end && b[i + 1] == b'|' {
                    i += 2;
                } else {
                    i += 1;
                }
                unit_start = i;
            }
            b';' | b'\n' => {
                out.push((unit_start, i));
                i += 1;
                unit_start = i;
            }
            _ => i += 1,
        }
    }
    if unit_start < end {
        out.push((unit_start, end));
    }
}

fn skip_single(b: &[u8], mut i: usize, end: usize) -> usize {
    while i < end && b[i] != b'\'' {
        i += 1;
    }
    if i < end { i + 1 } else { end }
}

fn skip_double(s: &str, mut i: usize, end: usize, out: &mut Vec<(usize, usize)>) -> usize {
    let b = s.as_bytes();
    while i < end && b[i] != b'"' {
        if b[i] == b'\\' {
            // Inside double quotes a backslash escapes `"`, `` ` ``, `$` and
            // `\`; skip the escaped byte so `\"` does not close the string and
            // `\$(`, `` \` `` do not open a substitution.
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

fn skip_quoted(b: &[u8], mut i: usize, end: usize, close: u8) -> usize {
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

// --- Env-assignment stripping (§8.2) -----------------------------------------

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

/// Advance past a single shell word starting at `i`, honoring simple quoting.
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

// --- File-access cross-check (§8.3) ------------------------------------------

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

/// Wrapper commands whose leading options are peeled to reach the real command.
/// `xargs` builds its command line by appending stdin items to the command that
/// follows it, so the wrapped command (`xargs cat …`, `xargs rm -rf …`) is the
/// one that must be decided and cross-checked.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "timeout", "nice", "ionice", "nohup", "stdbuf", "setsid", "command",
    "xargs",
];

/// Readers whose file operands are checked against `Read` deny rules.
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

/// Readers whose first non-option operand is a pattern, not a file (§8.3).
const PATTERN_FIRST: &[&str] = &[
    "grep", "egrep", "fgrep", "zgrep", "rgrep", "sed", "awk", "gawk",
];

/// Writers whose plain file operands are checked against `Write`/`Edit` deny
/// rules. (`dd` is handled separately: its files arrive as `if=`/`of=` operands.)
const WRITERS: &[&str] = &["tee", "truncate"];

/// A value-bearing option of a pattern-first reader (`grep`/`sed`/`awk` family):
/// `-e`/`--regexp` supplies the pattern, `-f`/`--file` names a file the tool
/// *reads*. Carries any value attached in the same token (`-fFILE`, `--file=X`).
enum ReaderOpt<'a> {
    /// Pattern supplied via option — no leading operand is the pattern.
    Pattern(Option<&'a str>),
    /// A pattern *file* the reader opens — check it against `Read` deny rules.
    File(Option<&'a str>),
}

/// Classify a pattern-first reader's option token, or `None` if it is a plain
/// flag. Recognizes `-e`/`-f` (bare or attached) and `--regexp`/`--file`.
fn reader_option(op: &str) -> Option<ReaderOpt<'_>> {
    if op == "--file" {
        return Some(ReaderOpt::File(None));
    }
    if let Some(v) = op.strip_prefix("--file=") {
        return Some(ReaderOpt::File(Some(v)));
    }
    if op == "--regexp" {
        return Some(ReaderOpt::Pattern(None));
    }
    if let Some(v) = op.strip_prefix("--regexp=") {
        return Some(ReaderOpt::Pattern(Some(v)));
    }
    let b = op.as_bytes();
    if b.len() >= 2 && b[0] == b'-' && b[1] != b'-' {
        let attached = (op.len() > 2).then(|| &op[2..]);
        match b[1] {
            b'f' => return Some(ReaderOpt::File(attached)),
            b'e' => return Some(ReaderOpt::Pattern(attached)),
            _ => {}
        }
    }
    None
}

/// Cross-check a single simple command for reads/writes to denied paths, raising
/// the verdict to `deny` on a hit (§8.3). Never loosens.
fn cross_check(rs: &RuleSet, cmd: &str, cwd: Option<&str>) -> bool {
    let tokens = tokenize(cmd);

    // Redirection targets, regardless of the command.
    for tok in &tokens {
        if let Token::Redirect(kind, target) = tok {
            let hit = match kind {
                RedirectKind::In => engine::path_hits_deny(rs, &["Read"], target, cwd),
                _ => engine::path_hits_deny(rs, &["Write", "Edit"], target, cwd),
            };
            if hit {
                return true;
            }
        }
    }

    // Reader/writer operands, after peeling wrapper commands.
    let mut words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();
    peel_wrappers(&mut words);
    let Some(&cmd0) = words.first() else {
        return false;
    };
    let name = basename(cmd0);
    let operands = &words[1..];

    if name == "dd" {
        // `dd` names its files as `if=<path>` (read) and `of=<path>` (write),
        // not as bare operands, so it needs its own operand shape.
        for op in operands {
            if let Some(path) = op.strip_prefix("if=")
                && !path.is_empty()
                && engine::path_hits_deny(rs, &["Read"], path, cwd)
            {
                return true;
            }
            if let Some(path) = op.strip_prefix("of=")
                && !path.is_empty()
                && engine::path_hits_deny(rs, &["Write", "Edit"], path, cwd)
            {
                return true;
            }
        }
    } else if READERS.contains(&name) {
        let pattern_first = PATTERN_FIRST.contains(&name);
        let mut pattern_consumed = false;
        let mut end_of_options = false;
        let mut k = 0;
        while k < operands.len() {
            let op = operands[k];
            k += 1;
            if !end_of_options && op == "--" {
                end_of_options = true;
                continue;
            }
            if !end_of_options && op.len() > 1 && op.starts_with('-') {
                // On pattern-first readers, `-e`/`-f` supply the pattern via the
                // option (so no leading operand is the pattern); `-f` additionally
                // names a file the tool reads, checked here. Its value may be
                // attached (`-fFILE`, `--file=X`) or the next operand.
                if pattern_first && let Some(kind) = reader_option(op) {
                    pattern_consumed = true;
                    let (is_file, attached) = match kind {
                        ReaderOpt::File(a) => (true, a),
                        ReaderOpt::Pattern(a) => (false, a),
                    };
                    let value = attached.or_else(|| operands.get(k).copied().inspect(|_| k += 1));
                    if is_file
                        && let Some(v) = value
                        && !v.is_empty()
                        && engine::path_hits_deny(rs, &["Read"], v, cwd)
                    {
                        return true;
                    }
                }
                continue;
            }
            // A pattern-first reader's first bare operand is the regex, not a file.
            if pattern_first && !pattern_consumed {
                pattern_consumed = true;
                continue;
            }
            if engine::path_hits_deny(rs, &["Read"], op, cwd) {
                return true;
            }
        }
    } else if WRITERS.contains(&name) {
        for op in operands {
            if op.starts_with('-') || op.contains('=') {
                continue; // skip options and any key=value operand
            }
            if engine::path_hits_deny(rs, &["Write", "Edit"], op, cwd) {
                return true;
            }
        }
    } else if (name == "cp" || name == "mv") && cp_mv_writes_denied(rs, operands, cwd) {
        return true;
    } else if (name == "curl" && curl_reads_denied(rs, operands, cwd))
        || (name == "wget" && wget_reads_denied(rs, operands, cwd))
    {
        return true;
    }
    false
}

/// True if a `cp`/`mv` invocation writes to a `Write`/`Edit`-denied destination
/// (§8.3). Shape: `cp [opts] SRC… DEST`, where the last path operand is the
/// destination, or `-t DIR` / `--target-directory[=DIR]`, where DIR is the
/// destination directory and each source lands at `DIR/<basename>`. Only the
/// write side is modeled, so overwriting a protected file (the policy/settings
/// file, a shell-rc, `.env`, an ssh file) denies; following the source reads is
/// a documented non-goal (§9.2). The cross-check only ever raises to `deny`.
fn cp_mv_writes_denied(rs: &RuleSet, operands: &[&str], cwd: Option<&str>) -> bool {
    let mut target_dir: Option<&str> = None;
    let mut positionals: Vec<&str> = Vec::new();
    let mut end_opts = false;
    let mut i = 0;
    while i < operands.len() {
        let op = operands[i];
        i += 1;
        if end_opts {
            positionals.push(op);
        } else if op == "--" {
            end_opts = true;
        } else if op == "-t" || op == "--target-directory" {
            // The directory is the next operand.
            if let Some(v) = operands.get(i) {
                target_dir = Some(v);
                i += 1;
            }
        } else if let Some(v) = op.strip_prefix("--target-directory=") {
            target_dir = Some(v);
        } else if let Some(v) = op.strip_prefix("-t").filter(|v| !v.is_empty()) {
            target_dir = Some(v); // attached: -tDIR
        } else if op.starts_with('-') && op.len() > 1 {
            // Any other option flag; not a path operand.
        } else {
            positionals.push(op);
        }
    }

    let hits = |p: &str| !p.is_empty() && engine::path_hits_deny(rs, &["Write", "Edit"], p, cwd);

    if let Some(dir) = target_dir {
        // `-t DIR SRC…`: DIR is the destination, and each source lands at
        // `DIR/<basename>` — check both so `cp -t .claude settings.json` denies.
        if hits(dir) {
            return true;
        }
        let base = dir.trim_end_matches('/');
        return positionals
            .iter()
            .any(|src| hits(&format!("{base}/{}", basename(src))));
    }
    // Plain form: the last path operand is the destination.
    match positionals.split_last() {
        Some((dest, _)) => hits(dest),
        None => false,
    }
}

/// The value of an option in `--flag val` or `--flag=val` form. Returns `None`
/// when `op` is not `flag` (so a prefix like `--data` does not swallow
/// `--data-binary`). Consumes the next operand only for the space-separated form.
fn long_value<'a>(op: &'a str, flag: &str, operands: &[&'a str], i: &mut usize) -> Option<&'a str> {
    let rest = op.strip_prefix(flag)?;
    if rest.is_empty() {
        // `--flag val`: the value is the next operand, if any.
        let v = operands.get(*i).copied();
        if v.is_some() {
            *i += 1;
        }
        v
    } else if let Some(v) = rest.strip_prefix('=') {
        Some(v) // `--flag=val`
    } else {
        None // `--flag` is a prefix of a longer flag, not a match
    }
}

/// The value of a single-letter short option `-x val` or `-xval`. Rejects long
/// options (`--…`). Consumes the next operand only for the space-separated form.
fn short_value<'a>(op: &'a str, ch: u8, operands: &[&'a str], i: &mut usize) -> Option<&'a str> {
    let b = op.as_bytes();
    if b.len() < 2 || b[0] != b'-' || b[1] == b'-' || b[1] != ch {
        return None;
    }
    if op.len() == 2 {
        let v = operands.get(*i).copied();
        if v.is_some() {
            *i += 1;
        }
        v
    } else {
        Some(&op[2..]) // attached value: `-d@file`, `-Tfile`
    }
}

/// The file path a curl data/form value reads, or `None` for a literal value.
/// `@file` (data options) and `field=@file` / `field=<file` (`--form`) name a
/// file curl opens. The scan for any `@`/`<` biases toward over-deny, which is
/// the safe direction: the cross-check only ever raises to `deny`, and only when
/// the extracted path matches a `Read` deny rule.
fn curl_file_ref(val: &str) -> Option<&str> {
    if let Some(rest) = val.strip_prefix('@') {
        return Some(rest);
    }
    if let Some(pos) = val.find('@') {
        return Some(&val[pos + 1..]);
    }
    if let Some(pos) = val.find('<') {
        return Some(&val[pos + 1..]);
    }
    None
}

/// True if a `curl` invocation reads a `Read`-denied file through a data option
/// (`-d`/`--data`/`--data-binary`/`--data-ascii`/`--data-urlencode`,
/// `-F`/`--form` with `@file`) or an upload option (`-T`/`--upload-file`).
fn curl_reads_denied(rs: &RuleSet, operands: &[&str], cwd: Option<&str>) -> bool {
    let mut i = 0;
    while i < operands.len() {
        let op = operands[i];
        i += 1;

        // Upload flags: the value is a direct path.
        if let Some(path) = long_value(op, "--upload-file", operands, &mut i)
            .or_else(|| short_value(op, b'T', operands, &mut i))
        {
            if !path.is_empty() && engine::path_hits_deny(rs, &["Read"], path, cwd) {
                return true;
            }
            continue;
        }

        // Data/form flags: a value of the form `@file` reads a file.
        let data_val = long_value(op, "--data-binary", operands, &mut i)
            .or_else(|| long_value(op, "--data-ascii", operands, &mut i))
            .or_else(|| long_value(op, "--data-urlencode", operands, &mut i))
            .or_else(|| long_value(op, "--data", operands, &mut i))
            .or_else(|| long_value(op, "--form", operands, &mut i))
            .or_else(|| short_value(op, b'd', operands, &mut i))
            .or_else(|| short_value(op, b'F', operands, &mut i));
        if let Some(val) = data_val
            && let Some(path) = curl_file_ref(val)
            && !path.is_empty()
            && engine::path_hits_deny(rs, &["Read"], path, cwd)
        {
            return true;
        }
    }
    false
}

/// True if a `wget` invocation reads a `Read`-denied file through `--post-file`
/// or `--body-file` (both `=` and space-separated forms).
fn wget_reads_denied(rs: &RuleSet, operands: &[&str], cwd: Option<&str>) -> bool {
    let mut i = 0;
    while i < operands.len() {
        let op = operands[i];
        i += 1;
        if let Some(path) = long_value(op, "--post-file", operands, &mut i)
            .or_else(|| long_value(op, "--body-file", operands, &mut i))
            && !path.is_empty()
            && engine::path_hits_deny(rs, &["Read"], path, cwd)
        {
            return true;
        }
    }
    false
}

/// A wrapper's own trailing argument that is peeled to reach the wrapped command:
/// an option (`-n`), a `NAME=value` assignment (`env FOO=bar`), or a numeric arg
/// (`timeout 5`). Shared by the token-level [`peel_wrappers`] and the string-level
/// [`strip_leading_wrappers`] so the two stay in lockstep.
fn is_wrapper_arg(w: &str) -> bool {
    w.starts_with('-')
        || w.contains('=')
        || (!w.is_empty() && w.bytes().all(|b| b.is_ascii_digit()))
}

/// Drop leading wrapper commands (and their options / assignments / numeric
/// args) so the cross-check sees the real command.
fn peel_wrappers(words: &mut Vec<&str>) {
    while let Some(&head) = words.first() {
        if !WRAPPERS.contains(&basename(head)) {
            return;
        }
        words.remove(0);
        while let Some(&w) = words.first() {
            if is_wrapper_arg(w) {
                words.remove(0);
            } else {
                break;
            }
        }
    }
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// Strip leading wrapper commands and their options / assignments / numeric args
/// from `cmd`, returning the wrapped command string when any wrapper was peeled
/// (else `None`). String-level counterpart to [`peel_wrappers`], so the wrapped
/// command can be re-decided against the Bash matchers (§8.3). Handles nested
/// wrappers (`sudo env aws …`) and quoted args (`env FOO="a b" cmd`).
fn strip_leading_wrappers(cmd: &str) -> Option<&str> {
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
        // Consume the wrapper word, then its options / assignments / numeric args.
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

        // Redirection with an optional leading fd number: `2>`, `>`, `<`, `>>`.
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
                // `>&1`, `>&-` etc. are fd dups/closes, not file writes.
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

        // `&>` / `&>>` redirection.
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

        // Ordinary word.
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

/// Read a redirection target: attached chars, or the next whitespace-delimited
/// word when the operator stands alone.
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

/// Read one word (unquoted), stopping at whitespace or a redirection metachar.
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
