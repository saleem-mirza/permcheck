//! Rule-driven command-form normalization (§8.2).

use crate::engine;
use crate::rules::RuleSet;
use crate::types::Tier;

use super::prefix::basename;

/// The tier of a single (already env-stripped) command string against the Bash
/// matchers, taking the rule set's `defaultMode` fall-back when nothing matches.
pub(super) fn unit_tier(rs: &RuleSet, cmd: &str) -> Tier {
    let base_owned = basename_command(cmd);
    let base = base_owned.as_deref().unwrap_or(cmd);
    let git_owned = git_subcommand_form(base);
    // Collapse runs of whitespace to single spaces so a prefix/glob rule
    // (`git push --force:*`) is not evaded by `git  push --force`. Only added when
    // it changes the string. Collapsing inside a quoted argument can only add a
    // match (raise the verdict), the safe direction, matching the additive-candidate
    // pattern in `engine::path_candidates`.
    let collapsed_owned = collapse_whitespace(cmd);

    // Identity forms: raw, basename-normalized, git-subcommand, and the
    // whitespace-collapsed spelling. Keep this capacity in sync when adding one.
    const IDENTITY_CAP: usize = 4;
    let mut identity = [""; IDENTITY_CAP];
    identity[0] = cmd;
    let mut identity_len = 1;
    if let Some(base) = base_owned.as_deref() {
        debug_assert!(identity_len < IDENTITY_CAP);
        identity[identity_len] = base;
        identity_len += 1;
    }
    if let Some(git) = git_owned.as_deref() {
        debug_assert!(identity_len < IDENTITY_CAP);
        identity[identity_len] = git;
        identity_len += 1;
    }
    if let Some(collapsed) = collapsed_owned.as_deref() {
        debug_assert!(identity_len < IDENTITY_CAP);
        identity[identity_len] = collapsed;
        identity_len += 1;
    }
    let mut tier =
        engine::decide_tier(rs, "Bash", &identity[..identity_len]).unwrap_or(rs.default_tier);

    for_each_flag_candidate(base, |candidate| {
        if tier != Tier::Deny
            && let Some(candidate_tier) = engine::decide_tier(rs, "Bash", &[candidate])
        {
            tier = tier.max(candidate_tier);
        }
        tier != Tier::Deny
    });
    if tier != Tier::Deny
        && let Some(candidate) = inline_exec_candidate(base)
        && let Some(candidate_tier) = engine::decide_tier(rs, "Bash", &[&candidate])
    {
        tier = tier.max(candidate_tier);
    }
    tier
}

/// Git global options placed before the subcommand that consume a value.
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

/// Expose a git subcommand hidden behind leading global options.
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
            break;
        }
        peeled = true;
        i += if GIT_VALUE_OPTS.contains(&tok) { 2 } else { 1 };
    }
    if !peeled || i >= tokens.len() {
        return None;
    }
    Some(format!("git {}", tokens[i..].join(" ")))
}

/// An interpreter and the option forms that make it run inline code.
struct Interp {
    name: &'static str,
    short: &'static [u8],
    long: &'static [(&'static str, &'static str)],
    subcommand: &'static [&'static str],
}

const INTERPRETERS: &[Interp] = &[
    Interp {
        name: "python",
        short: b"c",
        long: &[],
        subcommand: &[],
    },
    Interp {
        name: "python2",
        short: b"c",
        long: &[],
        subcommand: &[],
    },
    Interp {
        name: "python3",
        short: b"c",
        long: &[],
        subcommand: &[],
    },
    Interp {
        name: "pypy",
        short: b"c",
        long: &[],
        subcommand: &[],
    },
    Interp {
        name: "pypy3",
        short: b"c",
        long: &[],
        subcommand: &[],
    },
    Interp {
        name: "perl",
        short: b"eE",
        long: &[],
        subcommand: &[],
    },
    Interp {
        name: "perl5",
        short: b"eE",
        long: &[],
        subcommand: &[],
    },
    Interp {
        name: "ruby",
        short: b"e",
        long: &[],
        subcommand: &[],
    },
    Interp {
        name: "node",
        short: b"ep",
        long: &[("--eval", "-e"), ("--print", "-p")],
        subcommand: &[],
    },
    Interp {
        name: "nodejs",
        short: b"ep",
        long: &[("--eval", "-e"), ("--print", "-p")],
        subcommand: &[],
    },
    Interp {
        name: "bun",
        short: b"e",
        long: &[("--eval", "-e")],
        subcommand: &[],
    },
    Interp {
        name: "deno",
        short: b"",
        long: &[],
        subcommand: &["eval"],
    },
    Interp {
        name: "php",
        short: b"r",
        long: &[],
        subcommand: &[],
    },
    Interp {
        name: "lua",
        short: b"e",
        long: &[],
        subcommand: &[],
    },
    Interp {
        name: "luajit",
        short: b"e",
        long: &[],
        subcommand: &[],
    },
    Interp {
        name: "Rscript",
        short: b"e",
        long: &[],
        subcommand: &[],
    },
];

/// Return the canonical inline-code form for a known interpreter invocation.
fn inline_exec_candidate(cmd: &str) -> Option<String> {
    let mut toks = cmd.split_ascii_whitespace();
    let name = basename(toks.next()?);
    let interp = INTERPRETERS.iter().find(|i| i.name == name)?;
    for tok in toks {
        if tok == "--" {
            break;
        }
        let b = tok.as_bytes();
        if b.first() != Some(&b'-') {
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
        for &c in &b[1..] {
            if interp.short.contains(&c) {
                return Some(format!("{name} -{}", c as char));
            }
            if !c.is_ascii_alphanumeric() {
                break;
            }
        }
    }
    None
}

/// Visit the canonical candidates for a clustered or reordered short-flag set.
fn for_each_flag_candidate(cmd: &str, mut visit: impl FnMut(&str) -> bool) {
    let mut toks = cmd.split_ascii_whitespace();
    let Some(cmd_word) = toks.next() else {
        return;
    };
    let mut flags = Vec::new();
    for tok in toks {
        let b = tok.as_bytes();
        if b.len() < 2 || b[0] != b'-' || b[1] == b'-' {
            break;
        }
        if !b[1..].iter().all(|&c| c.is_ascii_alphanumeric()) {
            break;
        }
        for &flag in &b[1..] {
            if !flags.contains(&flag) {
                flags.push(flag);
            }
        }
    }
    if flags.len() < 2 {
        return;
    }
    for flag in flags {
        let candidate = format!("{cmd_word} -{}", flag as char);
        if !visit(&candidate) {
            break;
        }
    }
}

/// Collapse every run of ASCII whitespace to a single space, returning the result
/// only when it differs from `cmd`. `None` means `cmd` was already single-spaced,
/// so no extra candidate is needed.
fn collapse_whitespace(cmd: &str) -> Option<String> {
    let collapsed = cmd.split_ascii_whitespace().collect::<Vec<_>>().join(" ");
    (collapsed != cmd).then_some(collapsed)
}

/// Reduce a path-qualified executable token to its basename.
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
