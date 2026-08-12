//! Environment-assignment, wrapper, and reserved-word prefix handling (§8.2).

use super::split::{skip_quoted, skip_single};
use super::tokenize::{ShellWord, shell_words};

/// Options taking a **separate** value, which must be consumed or the value is
/// misread as an operand. Shared by wrapper peeling (§8.2) and the reader
/// cross-check (§8.3), so one definition of option arity serves both.
pub(super) struct ValueOpts {
    pub(super) short: &'static [u8],
    pub(super) long: &'static [&'static str],
}

/// Does `option` consume the **next** token as its value? Only the separated
/// spelling does; an attached value is self-contained, and in a cluster the
/// value-taking letter ends the token (`-im` consumes, `-mi` does not).
pub(super) fn consumes_next_value(opts: &ValueOpts, option: &str) -> bool {
    if option.starts_with("--") {
        return opts.long.contains(&option);
    }
    last_cluster_flag(option).is_some_and(|last| opts.short.contains(&last))
}

/// The flag a bundle of short options ends with, whose value is therefore the
/// next token. `None` when `option` is not such a bundle. The one definition of
/// cluster arity, shared by wrapper peeling (§8.2) and the reader option parsers
/// (§8.3); one pass over the token however many flags the caller tests.
fn last_cluster_flag(option: &str) -> Option<u8> {
    let cluster = option.strip_prefix('-')?;
    cluster
        .bytes()
        .all(|c| c.is_ascii_alphanumeric())
        .then(|| cluster.bytes().next_back())?
}

/// Does `option` bundle short flags and end with `flag`? `-o` and `-uo` do; `-ou`
/// does not, since there the value would be attached.
pub(super) fn cluster_ends_with(option: &str, flag: u8) -> bool {
    last_cluster_flag(option) == Some(flag)
}

/// A wrapper command whose leading options are peeled to reach the real command,
/// with the options whose value is a separate token. `time` belongs here rather
/// than in [`RESERVED`] because it takes its own options (`time -p cmd`).
struct Wrapper {
    name: &'static str,
    opts: ValueOpts,
}

const fn wrapper(
    name: &'static str,
    short: &'static [u8],
    long: &'static [&'static str],
) -> Wrapper {
    Wrapper {
        name,
        opts: ValueOpts { short, long },
    }
}

/// Arity comes from each command's own synopsis. Options whose value is
/// *optional* (GNU `xargs -e`, `-i`) are left out: the reading that consumes
/// nothing already reaches the command, so listing them would only add a stage.
const WRAPPERS: &[Wrapper] = &[
    wrapper(
        "sudo",
        b"CDghpRTUu",
        &[
            "--close-from",
            "--chdir",
            "--group",
            "--host",
            "--prompt",
            "--chroot",
            "--command-timeout",
            "--other-user",
            "--user",
        ],
    ),
    wrapper("doas", b"aCu", &[]),
    wrapper("env", b"uCPS", &["--unset", "--chdir", "--split-string"]),
    wrapper("timeout", b"sk", &["--signal", "--kill-after"]),
    wrapper("nice", b"n", &["--adjustment"]),
    wrapper(
        "ionice",
        b"cnpPu",
        &["--class", "--classdata", "--pid", "--pgid", "--uid"],
    ),
    wrapper("nohup", b"", &[]),
    wrapper("stdbuf", b"eio", &["--input", "--output", "--error"]),
    wrapper("setsid", b"", &[]),
    wrapper("command", b"", &[]),
    wrapper("builtin", b"", &[]),
    wrapper(
        "xargs",
        b"EIRSJLnPsad",
        &[
            "--arg-file",
            "--delimiter",
            "--max-lines",
            "--max-args",
            "--max-procs",
            "--max-chars",
            "--replace",
        ],
    ),
    wrapper("time", b"fo", &["--format", "--output"]),
];

fn wrapper_for(name: &str) -> Option<&'static Wrapper> {
    WRAPPERS.iter().find(|wrapper| name_eq(wrapper.name, name))
}

/// Shell reserved words a command follows, so the command after one is decided on
/// its own. Only the word is dropped, never arguments, which would eat a
/// condition's operands. Matched after quote removal, which over-denies `'{' cmd`.
const RESERVED: &[&str] = &[
    "{", "!", "if", "then", "elif", "else", "while", "until", "do", "coproc",
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

/// The words after leading wrappers and their arguments, as every reading the
/// wrappers' option arity allows: the fully peeled one first, then one per
/// option whose value could instead be the command word.
pub(super) fn peel_wrappers<'a, 'b>(words: &'a [&'b str]) -> Vec<&'a [&'b str]> {
    let mut alternates = Vec::new();
    let mut rest = words;
    while let Some((&head, tail)) = rest.split_first() {
        // A reserved word carries no options of its own, so only it is dropped.
        if RESERVED.contains(&head) {
            rest = tail;
            continue;
        }
        let Some(wrapper) = wrapper_for(command_name(head)) else {
            break;
        };
        rest = tail;
        while let Some(&option) = rest.first() {
            if !is_wrapper_arg(option) {
                break;
            }
            rest = &rest[1..];
            if consumes_next_value(&wrapper.opts, option)
                && let Some((&value, after)) = rest.split_first()
            {
                // A value the argument peel already absorbs never headed a
                // command, so it contributes no second reading.
                if !is_wrapper_arg(value) {
                    alternates.push(rest);
                }
                rest = after;
            }
        }
    }
    let mut readings = Vec::with_capacity(alternates.len() + 1);
    readings.push(rest);
    readings.extend(alternates);
    readings
}

#[cfg(not(windows))]
pub(super) fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

#[cfg(windows)]
pub(super) fn basename(word: &str) -> &str {
    word.rsplit(['/', '\\']).next().unwrap_or(word)
}

/// Suffixes Windows resolves as part of an executable's name (`PATHEXT`), so
/// `rm` and `rm.exe` invoke the same program there.
const EXEC_SUFFIXES: &[&str] = &[".exe", ".com", ".bat", ".cmd"];

/// The command name a word invokes: its basename, and on Windows without the
/// executable suffix. POSIX keeps the name byte-exact, where `rm.exe` is a
/// different file from `rm`, so the strip is behind [`cfg!`] rather than applied.
pub(super) fn command_name(word: &str) -> &str {
    let base = basename(word);
    if cfg!(windows) {
        strip_exec_suffix(base)
    } else {
        base
    }
}

/// Do two command names invoke the same program? Windows resolves executables
/// case-insensitively, so `RM.EXE`, `rm.exe`, and `rm` are one program there.
/// POSIX names are byte-exact. Shell **keywords** are case-sensitive on every
/// platform, so [`RESERVED`] and [`CLOSERS`] deliberately do not use this.
pub(super) fn name_eq(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// Is `name` one of `names`, by [`name_eq`]?
pub(super) fn name_in(name: &str, names: &[&str]) -> bool {
    names.iter().any(|known| name_eq(known, name))
}

/// Remove one trailing [`EXEC_SUFFIXES`] entry, matched case-insensitively
/// because the filesystem is. Compiled on every platform so the suffix logic is
/// testable there; [`command_name`] decides whether it applies.
fn strip_exec_suffix(base: &str) -> &str {
    for suffix in EXEC_SUFFIXES {
        let Some(idx) = base.len().checked_sub(suffix.len()) else {
            continue;
        };
        // `is_char_boundary` first: a name ending in a multibyte character
        // would otherwise panic on the slice, and in hook mode a panic denies
        // every call (§9.1).
        if idx > 0 && base.is_char_boundary(idx) && base[idx..].eq_ignore_ascii_case(suffix) {
            return &base[..idx];
        }
    }
    base
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
        } else if let Some(wrapper) = wrapper_for(command_name(&word.value)) {
            i += 1;
            while let Some(option) = words.get(i) {
                if !is_wrapper_arg(&option.value) {
                    break;
                }
                i += 1;
                // Two readings: the value belongs to the option, or the option
                // took none and the value heads the command. Both are decided,
                // since either alone hides a command some spelling puts there.
                if consumes_next_value(&wrapper.opts, &option.value) {
                    if words
                        .get(i)
                        .is_some_and(|value| !is_wrapper_arg(&value.value))
                    {
                        match push_stage(cmd, &words, i, &mut stages) {
                            Staged::Full => return (stages, true),
                            Staged::Kept | Staged::Nothing => {}
                        }
                    }
                    i += 1;
                }
            }
        } else {
            break;
        }
        match push_stage(cmd, &words, i, &mut stages) {
            Staged::Kept => {}
            // Nothing follows, so there is no command to decide.
            Staged::Nothing => break,
            Staged::Full => return (stages, true),
        }
    }
    (stages, false)
}

/// Outcome of recording one peel stage.
enum Staged {
    /// Recorded; the walk continues.
    Kept,
    /// No command follows the peeled prefix.
    Nothing,
    /// [`MAX_STAGES`] is full, so the caller fails closed (§9.1).
    Full,
}

/// Record the command starting at word `at` as a peel stage.
fn push_stage<'a>(
    cmd: &'a str,
    words: &[ShellWord],
    at: usize,
    stages: &mut Vec<&'a str>,
) -> Staged {
    let Some(next) = words.get(at) else {
        return Staged::Nothing;
    };
    let rest = cmd[next.range.start..].trim_end();
    if rest.is_empty() {
        return Staged::Nothing;
    }
    if stages.len() == MAX_STAGES {
        return Staged::Full;
    }
    stages.push(rest);
    Staged::Kept
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

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn executable_suffixes_are_stripped_case_insensitively() {
        // Compiled on every platform, so the suffix logic is proven here rather
        // than only on a Windows runner.
        for (input, want) in [
            ("rm.exe", "rm"),
            ("RM.EXE", "RM"),
            ("run.bat", "run"),
            ("run.cmd", "run"),
            ("run.com", "run"),
            // No suffix, an unknown one, and a name that is only a suffix.
            ("rm", "rm"),
            ("archive.tar", "archive.tar"),
            (".exe", ".exe"),
            ("", ""),
        ] {
            assert_eq!(strip_exec_suffix(input), want, "input: {input:?}");
        }
    }

    #[test]
    fn a_multibyte_name_does_not_panic_on_the_suffix_slice() {
        // The byte length can land mid-character; in hook mode a panic denies
        // every call, so the boundary check is load-bearing (§9.1).
        for input in ["ré.exe", "日本語", "ü.cmd", "…"] {
            let _ = strip_exec_suffix(input);
            let _ = command_name(input);
        }
        assert_eq!(strip_exec_suffix("ré.exe"), "ré");
    }

    #[test]
    fn name_comparison_follows_the_platform() {
        // Same program on Windows, different files on POSIX.
        assert_eq!(name_eq("rm", "RM"), cfg!(windows));
        assert_eq!(name_in("CAT", &["cat", "tac"]), cfg!(windows));
        // Equality and non-membership hold on both.
        assert!(name_eq("rm", "rm"));
        assert!(name_in("cat", &["cat", "tac"]));
        assert!(!name_eq("rm", "cp"));
        assert!(!name_in("cp", &["cat", "tac"]));
    }

    #[test]
    #[cfg(not(windows))]
    fn posix_keeps_the_name_byte_exact() {
        // `rm.exe` is a different file from `rm` here, so nothing is stripped.
        assert_eq!(command_name("rm.exe"), "rm.exe");
        assert_eq!(command_name("/usr/bin/rm.exe"), "rm.exe");
        assert_eq!(command_name("/usr/bin/rm"), "rm");
        // A backslash is an ordinary filename character on POSIX.
        assert_eq!(command_name(r"a\b"), r"a\b");
    }

    #[test]
    #[cfg(windows)]
    fn windows_resolves_both_spellings_to_one_name() {
        assert_eq!(command_name("rm.exe"), "rm");
        assert_eq!(command_name(r"C:\tools\sudo.exe"), "sudo");
        assert_eq!(command_name("C:/tools/sudo.exe"), "sudo");
        assert_eq!(command_name("rm"), "rm");
    }
}
