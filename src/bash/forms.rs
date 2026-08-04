//! Rule-driven command-form normalization (§8.2).

use std::borrow::Cow;

use crate::engine;
use crate::rules::RuleSet;
use crate::types::Tier;

use super::prefix::{basename, strip_env_assignments};

/// The normalization pipeline behind the identity forms (§8 step 2), in order.
/// Each stage runs on the **previous stage's output**, and every intermediate
/// spelling is kept as a candidate, so a command wearing several disguises at
/// once still reduces to the spelling a rule names.
///
/// The order is load-bearing, and so is composing the stages instead of applying
/// each to the raw command: quoting hides every later stage's marker (a quoted
/// `"/usr/bin/git"` shows no `/` to reduce), and irregular whitespace hides the
/// rest. Applied independently, as this did before, `/usr/bin/git  push --force`
/// produced `git  push --force` and `/usr/bin/git push --force` and so matched
/// neither the deny rule nor anything else.
///
/// A stage returns `None` when it changes nothing, which is the common case, so
/// a plain command yields a single borrowed form and allocates nothing.
const STAGES: [fn(&str) -> Option<String>; 5] = [
    strip_shell_quoting,
    assignment_stripped_form,
    collapse_whitespace,
    basename_command,
    git_subcommand_form,
];

/// Upper bound on identity forms: the raw unit plus one per pipeline stage.
const MAX_FORMS: usize = STAGES.len() + 1;

/// The identity forms of one unit (§8 step 2): every spelling decided together
/// with the raw command, plus the index of the fully-normalized one.
pub(super) struct Forms<'a> {
    forms: [Cow<'a, str>; MAX_FORMS],
    len: usize,
    canonical: usize,
}

impl<'a> Forms<'a> {
    /// The spellings to decide together, so a matching allow still wins (§6.3).
    fn candidates(&self) -> &[Cow<'a, str>] {
        &self.forms[..self.len]
    }

    /// The end of the pipeline: the unit with every disguise this engine knows
    /// how to remove taken off. Escalation forms and wrapper peeling read this,
    /// so they see through a disguise the raw string still wears.
    pub(super) fn canonical(&self) -> &str {
        self.forms[self.canonical].as_ref()
    }

    /// Record a stage's output and make it the spelling the next stage reads. A
    /// form already present is reused rather than duplicated, which keeps the
    /// candidate list free of repeats when two stages converge.
    fn push(&mut self, form: String) {
        if let Some(existing) = self.forms[..self.len]
            .iter()
            .position(|known| known.as_ref() == form.as_str())
        {
            self.canonical = existing;
            return;
        }
        debug_assert!(self.len < MAX_FORMS, "one form per stage plus the raw unit");
        if self.len < MAX_FORMS {
            self.forms[self.len] = Cow::Owned(form);
            self.canonical = self.len;
            self.len += 1;
        }
    }
}

/// Run the normalization pipeline over one (already env-stripped) unit.
pub(super) fn identity_forms(cmd: &str) -> Forms<'_> {
    let mut forms = Forms {
        forms: std::array::from_fn(|_| Cow::Borrowed("")),
        len: 1,
        canonical: 0,
    };
    forms.forms[0] = Cow::Borrowed(cmd);
    for stage in STAGES {
        let next = stage(forms.canonical());
        if let Some(next) = next {
            forms.push(next);
        }
    }
    forms
}

/// The tier of a single unit against the Bash matchers, taking the rule set's
/// `defaultMode` fall-back when nothing matches.
pub(super) fn unit_tier(rs: &RuleSet, forms: &Forms<'_>) -> Tier {
    let mut tier = engine::decide_tier(rs, "Bash", forms.candidates()).unwrap_or(rs.default_tier);

    // Escalation forms (§8 step 2) are each decided on their own and only ever
    // raise the verdict. They read the canonical spelling, so a quoted or padded
    // command reaches its flag and interpreter rules the same as a bare one.
    let canonical = forms.canonical();
    for_each_flag_candidate(canonical, |candidate| {
        if tier != Tier::Deny
            && let Some(candidate_tier) = engine::decide_tier(rs, "Bash", &[candidate])
        {
            tier = tier.max(candidate_tier);
        }
        tier != Tier::Deny
    });
    if tier != Tier::Deny
        && let Some(candidate) = inline_exec_candidate(canonical)
        && let Some(candidate_tier) = engine::decide_tier(rs, "Bash", &[&candidate])
    {
        tier = tier.max(candidate_tier);
    }
    tier
}

/// Remove shell quoting and escaping, leaving the characters the shell passes to
/// the command: `"sudo" rm`, `su"do" rm`, `\sudo rm`, and `$'sudo' rm` all reduce
/// to `sudo rm`. Returns `None` when the unit carries no quote or escape
/// character, which is the common case.
///
/// Stripping covers the whole unit, not only the command word, because a rule
/// names argument text too (`Bash(git push --force:*)` against
/// `git push "--force"`). Operators, redirections, and spacing survive; the
/// whitespace stage collapses those.
///
/// The escape sequences inside `$'…'` are not decoded (§9.2), and a backslash
/// inside double quotes stays literal, matching what `super::tokenize` does.
fn strip_shell_quoting(cmd: &str) -> Option<String> {
    if !cmd.bytes().any(|b| matches!(b, b'\'' | b'"' | b'\\')) {
        return None;
    }
    let b = cmd.as_bytes();
    let mut out = String::with_capacity(cmd.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            // An unquoted backslash escapes the next character; append it
            // verbatim and advance a whole UTF-8 char. A trailing one is dropped.
            b'\\' => {
                i += 1;
                if let Some(ch) = cmd[i..].chars().next() {
                    out.push(ch);
                    i += ch.len_utf8();
                }
            }
            // `$'…'` (ANSI-C) and `$"…"` (locale) quoting: the `$` is part of the
            // quoting, not of the word, so drop it and let the quote arm run.
            b'$' if matches!(b.get(i + 1), Some(b'\'') | Some(b'"')) => i += 1,
            // A quoted run is copied verbatim up to its close; an unterminated
            // one runs to the end of the unit, as the splitter also assumes.
            quote @ (b'\'' | b'"') => {
                i += 1;
                let start = i;
                while i < b.len() && b[i] != quote {
                    i += 1;
                }
                out.push_str(&cmd[start..i]);
                if i < b.len() {
                    i += 1;
                }
            }
            _ => {
                let start = i;
                while i < b.len() && !matches!(b[i], b'\'' | b'"' | b'\\' | b'$') {
                    i += 1;
                }
                if i == start {
                    // A `$` not opening a quoted run: keep it and move on.
                    out.push('$');
                    i += 1;
                } else {
                    out.push_str(&cmd[start..i]);
                }
            }
        }
    }
    (out != cmd).then_some(out)
}

/// The unit with leading `NAME=value` environment assignments removed, for the
/// ones that were hidden behind quoting (`"FOO=bar" sudo …`) and so survived the
/// strip [`super::decide_bash`] applies to the raw unit.
fn assignment_stripped_form(cmd: &str) -> Option<String> {
    let stripped = strip_env_assignments(cmd);
    (stripped != cmd).then(|| stripped.to_string())
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

/// An interpreter and the option forms that make it execute caller-supplied
/// code: inline source (`-c`, `-e`) or a named module (`-m`).
struct Interp {
    name: &'static str,
    /// Flags whose canonical form is the flag alone (`python -c`).
    short: &'static [u8],
    /// Flags whose value belongs in the canonical form, because the rule names
    /// it (`python -m http.server`).
    value_short: &'static [u8],
    long: &'static [(&'static str, &'static str)],
    subcommand: &'static [&'static str],
}

impl Interp {
    const fn new(name: &'static str, short: &'static [u8]) -> Self {
        Interp {
            name,
            short,
            value_short: b"",
            long: &[],
            subcommand: &[],
        }
    }

    const fn value_short(mut self, flags: &'static [u8]) -> Self {
        self.value_short = flags;
        self
    }

    const fn long(mut self, forms: &'static [(&'static str, &'static str)]) -> Self {
        self.long = forms;
        self
    }

    const fn subcommand(mut self, names: &'static [&'static str]) -> Self {
        self.subcommand = names;
        self
    }
}

const NODE_LONG: &[(&str, &str)] = &[("--eval", "-e"), ("--print", "-p")];

const INTERPRETERS: &[Interp] = &[
    Interp::new("python", b"c").value_short(b"m"),
    Interp::new("python2", b"c").value_short(b"m"),
    Interp::new("python3", b"c").value_short(b"m"),
    Interp::new("pypy", b"c").value_short(b"m"),
    Interp::new("pypy3", b"c").value_short(b"m"),
    Interp::new("perl", b"eE"),
    Interp::new("perl5", b"eE"),
    Interp::new("ruby", b"e"),
    Interp::new("node", b"ep").long(NODE_LONG),
    Interp::new("nodejs", b"ep").long(NODE_LONG),
    Interp::new("bun", b"e").long(&[("--eval", "-e")]),
    Interp::new("deno", b"").subcommand(&["eval"]),
    Interp::new("php", b"r"),
    Interp::new("lua", b"e"),
    Interp::new("luajit", b"e"),
    Interp::new("Rscript", b"e"),
];

/// The canonical inline-code form for a known interpreter invocation. A
/// value-taking flag keeps its value, so `python3 -mhttp.server` and
/// `python3 -m http.server` both reach `python3 -m http.server`.
fn inline_exec_candidate(cmd: &str) -> Option<String> {
    let mut toks = cmd.split_ascii_whitespace().peekable();
    let name = basename(toks.next()?);
    let interp = INTERPRETERS.iter().find(|i| i.name == name)?;
    while let Some(tok) = toks.next() {
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
        // The first code-executing flag in the cluster decides the canonical
        // form, bundled (`-We`) or with an attached value (`-mhttp.server`).
        for (offset, &c) in b[1..].iter().enumerate() {
            if interp.short.contains(&c) {
                return Some(format!("{name} -{}", c as char));
            }
            if interp.value_short.contains(&c) {
                // The value follows the flag in this token, or is the next token.
                let attached = &tok[2 + offset..];
                let value = if attached.is_empty() {
                    toks.peek().copied()
                } else {
                    Some(attached)
                };
                return value.map(|value| format!("{name} -{} {value}", c as char));
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

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    fn stripped(cmd: &str) -> Option<String> {
        strip_shell_quoting(cmd)
    }

    #[test]
    fn quoting_is_removed_in_every_spelling() {
        for (input, want) in [
            (r#""sudo" rm"#, "sudo rm"),
            (r#"su"do" rm"#, "sudo rm"),
            ("'sudo' rm", "sudo rm"),
            (r"\sudo rm", "sudo rm"),
            (r#"sudo"" rm"#, "sudo rm"),
            // `$'…'` / `$"…"`: the `$` belongs to the quoting.
            (r"$'sudo' rm", "sudo rm"),
            (r#"$"sudo" rm"#, "sudo rm"),
            // Quoting an argument, not the command word.
            (r#"git push "--force""#, "git push --force"),
            // Whitespace inside quotes survives; the collapse stage handles it.
            ("echo 'a  b'", "echo a  b"),
        ] {
            assert_eq!(stripped(input).as_deref(), Some(want), "input: {input:?}");
        }
    }

    #[test]
    fn unclosed_and_trailing_forms_are_total() {
        // The splitter already consumes unterminated constructs to end of input,
        // so stripping must agree rather than panic or drop the tail.
        assert_eq!(stripped(r#""sudo rm"#).as_deref(), Some("sudo rm"));
        assert_eq!(stripped("'sudo rm").as_deref(), Some("sudo rm"));
        assert_eq!(stripped(r"sudo rm\").as_deref(), Some("sudo rm"));
        assert_eq!(stripped(r"\").as_deref(), Some(""));
    }

    #[test]
    fn unquoted_text_is_left_alone() {
        // No quote or escape byte means no work and no allocation.
        assert_eq!(stripped("git push --force"), None);
        assert_eq!(stripped("echo $HOME"), None);
        assert_eq!(stripped(""), None);
        // A `$` that opens nothing is kept.
        assert_eq!(stripped(r#"echo "$HOME""#).as_deref(), Some("echo $HOME"));
        assert_eq!(stripped(r#"echo $ "x""#).as_deref(), Some("echo $ x"));
    }

    #[test]
    fn multibyte_characters_survive_stripping() {
        // Byte indexing must stay on char boundaries: a panic here is a denial of
        // service on the hook, and `catch_unwind` would turn every such call into
        // a deny.
        assert_eq!(stripped(r#"echo "héllo""#).as_deref(), Some("echo héllo"));
        assert_eq!(stripped(r"echo \é").as_deref(), Some("echo é"));
        assert_eq!(stripped("echo 'ünïcødé'").as_deref(), Some("echo ünïcødé"));
    }

    #[test]
    fn stages_compose_into_one_canonical_form() {
        // The regression this pipeline exists for: applied independently, these
        // produce `git  push --force` and `/usr/bin/git push --force` and never
        // the spelling a rule names.
        for input in [
            "/usr/bin/git  push --force",
            r#"/usr/bin/git push "--force""#,
            r#""/usr/bin/git"  push '--force'"#,
            r#"/usr/bin/git   push   "--force""#,
        ] {
            assert_eq!(
                identity_forms(input).canonical(),
                "git push --force",
                "input: {input:?}"
            );
        }
    }

    #[test]
    fn canonical_form_is_the_raw_unit_when_nothing_normalizes() {
        let forms = identity_forms("git push --force");
        assert_eq!(forms.canonical(), "git push --force");
        assert_eq!(forms.candidates().len(), 1);
    }

    #[test]
    fn every_intermediate_spelling_stays_a_candidate() {
        // Intermediates matter: a rule written against a partly-normalized form
        // must still match, and an allow among them must still be able to win.
        let forms = identity_forms(r#""/usr/bin/git"  push --force"#);
        let seen: Vec<&str> = forms.candidates().iter().map(|c| c.as_ref()).collect();
        assert!(seen.contains(&r#""/usr/bin/git"  push --force"#)); // raw
        assert!(seen.contains(&"/usr/bin/git  push --force")); // quoting stripped
        assert!(seen.contains(&"/usr/bin/git push --force")); // + collapsed
        assert!(seen.contains(&"git push --force")); // + basename
        assert_eq!(forms.canonical(), "git push --force");
    }

    #[test]
    fn converging_stages_do_not_duplicate_candidates() {
        // A stage that reproduces an earlier form reuses it, so the candidate
        // list never carries repeats into `decide_tier`.
        let forms = identity_forms("git push --force");
        assert_eq!(forms.candidates().len(), 1);
        let forms = identity_forms("git  push --force");
        assert_eq!(forms.candidates().len(), 2);
        assert_eq!(forms.canonical(), "git push --force");
    }

    #[test]
    fn quoted_assignments_are_stripped_after_unquoting() {
        // `decide_bash` strips assignments from the raw unit; a quoted one only
        // becomes visible once the quoting comes off, so the pipeline repeats it.
        assert_eq!(
            identity_forms(r#""FOO=bar" sudo rm"#).canonical(),
            "sudo rm"
        );
        assert_eq!(
            identity_forms(r#"FOO="bar" sudo rm"#).canonical(),
            "sudo rm"
        );
    }

    #[test]
    fn git_subcommand_exposure_runs_last() {
        // The git stage reads the basename-reduced, collapsed spelling, so global
        // options plus a path prefix plus padding still expose the subcommand.
        assert_eq!(
            identity_forms("/usr/bin/git  -c x=y  config --global a b").canonical(),
            "git config --global a b"
        );
    }
}
