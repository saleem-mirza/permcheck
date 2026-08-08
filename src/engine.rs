//! Winner selection and candidate forms (§6.3, §7).
//!
//! [`decide_tier`] is the carve-out-aware selection used by every family: a deny
//! holds unless a matching allow/ask is a subset carve-out of it. [`decide_payload`]
//! is the whole decision for Path and Generic tools; Bash adds the compound step
//! in [`crate::bash`].

use crate::matcher::is_absolute;
#[cfg(windows)]
use crate::matcher::normalize_root;
use crate::rules::{CompiledRule, MAX_PAYLOAD_BYTES, RuleSet};
use crate::types::{Decision, Family, Tier};
use std::borrow::Cow;

/// Decide the tier for `tool` given the payload's candidate forms (§6.3).
///
/// A matching deny holds unless some matching allow/ask rule is a **carve-out** of
/// it, i.e. its match-set is a strict subset of that deny
/// ([`crate::matcher::is_strict_carve_out`]). If any matching deny is left
/// un-carved, the decision is `deny`. Otherwise the winner is chosen among the
/// matching allow/ask rules by [`selection_key`].
///
/// Returns `None` when nothing matches (caller applies the `defaultMode`
/// fall-back, §6.4).
pub(crate) fn decide_tier<S: AsRef<str>>(
    rs: &RuleSet,
    tool: &str,
    candidates: &[S],
) -> Option<Tier> {
    if candidates
        .iter()
        .any(|candidate| candidate.as_ref().len() > MAX_PAYLOAD_BYTES)
    {
        return Some(Tier::Deny);
    }
    // Loaded rule indices are tier-ordered Allow -> Ask -> Deny. Record only the
    // matching non-denies; when a deny matches, every possible carve-out has
    // already been seen, so an uncarved deny can terminate immediately.
    // The inline array plus a lazy spill keeps the common case off the heap:
    // `Vec::new` allocates nothing until the first push.
    const CAP: usize = 8;
    let mut buf: [Option<&CompiledRule>; CAP] = [None; CAP];
    let mut n = 0usize;
    let mut spill: Vec<&CompiledRule> = Vec::new();
    let mut best_carve: Option<&CompiledRule> = None;
    let mut last_tier = Tier::Allow;
    for idx in rs.matching_rule_indices(tool) {
        let rule = &rs.rules[idx];
        debug_assert!(
            last_tier <= rule.tier,
            "rule index must remain tier-ordered"
        );
        last_tier = rule.tier;
        let mut matched = false;
        for candidate in candidates {
            match rule.matcher.matches_checked(candidate.as_ref()) {
                Ok(true) => {
                    matched = true;
                    break;
                }
                Ok(false) => {}
                Err(()) => return Some(Tier::Deny),
            }
        }
        if !matched {
            continue;
        }
        if rule.tier == Tier::Deny {
            let carved = buf[..n]
                .iter()
                .flatten()
                .copied()
                .chain(spill.iter().copied())
                .any(|carve| rs.is_strict_carve_out(carve, rule));
            if !carved {
                return Some(Tier::Deny);
            }
            continue;
        }
        if n < CAP {
            buf[n] = Some(rule);
            n += 1;
        } else {
            spill.push(rule);
        }
        best_carve = Some(match best_carve {
            None => rule,
            Some(current) if selection_key(rule) > selection_key(current) => rule,
            Some(current) => current,
        });
    }
    best_carve.map(|rule| rule.tier)
}

/// Winner-selection ordering (§6.3): maximize specificity, then tier (`ask` over
/// `allow`), then earliest in file order — `Reverse` puts that last field in the
/// same maximize direction.
fn selection_key(rule: &CompiledRule) -> (u32, u32, Tier, std::cmp::Reverse<usize>) {
    crate::rules::selection_key(rule)
}

/// The complete decision for a Path or Generic tool (§6.3, §7).
pub fn decide_payload(rs: &RuleSet, tool: &str, payload: &str, cwd: Option<&str>) -> Decision {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Decision::deny_msg("payload exceeds the 32768-byte safety limit");
    }
    let candidates = match Family::from_tool(tool) {
        Family::Path => path_candidates(payload, cwd),
        _ => generic_candidates(payload),
    };
    let tier = decide_tier(rs, tool, &candidates).unwrap_or(rs.default_tier); // fall-back §6.4
    Decision::for_call(tier, tool, payload)
}

/// Candidate forms for a Path payload (§7.1, §7.2): the raw payload, its
/// `~`-expanded and `cwd`-absolutized forms, the Windows drive-root and
/// drive-relative anchorings, and each of those with `.`/`..` collapsed.
pub(crate) fn path_candidates<'a>(payload: &'a str, cwd: Option<&str>) -> Vec<Cow<'a, str>> {
    let mut v = Vec::with_capacity(4);
    v.push(Cow::Borrowed(payload));
    for form in resolve_path(payload, cwd).forms {
        push_unique(&mut v, form);
    }
    v
}

/// Resolve one Bash command operand to the path it really names (§7.2), for the
/// path-operand escalation form (§8 step 2).
///
/// Returns `None` for a token that names no path, so an ordinary word is left
/// exactly as written and produces no extra form. The gate opens for a token that
/// carries a `.` or `..` segment, that is relative and contains a separator, or
/// that starts with `~`.
///
/// The relative case is why a rule anchored at a real directory means what it
/// says. A Bash specifier matches command text, so `Bash(rm -rf .scratch/*)`
/// otherwise matches `rm -rf .scratch/x` from *any* directory, granting deletion
/// of every `.scratch` on the machine rather than the project's. Absolutizing the
/// operand against the call's `cwd` puts the real target in front of the rules,
/// where a deny on the tree can see it.
///
/// When the gate opens, the token is put through the same resolution a Path
/// payload gets: separators folded, `~` expanded, a relative token absolutized
/// against `cwd`, and `.`/`..` collapsed. Resolution is lexical only, so a
/// wildcard in the token is carried through untouched — sound because a shell `*`
/// matches within one segment, so `dir/*/../x` really does name `dir/x`.
pub(crate) fn resolve_operand(token: &str, cwd: Option<&str>) -> Option<String> {
    let folded = crate::matcher::fold_separators(token);
    if !names_a_path(&folded) {
        return None;
    }
    resolve_path(token, cwd).resolved
}

/// Every additive path spelling shared by Path payloads and Bash operands, in
/// resolution order: Windows root anchoring, same-drive joining, tilde expansion,
/// CWD absolutization, then lexical `.`/`..` collapse of each prior form. The raw
/// spelling is used as the seed but omitted from `forms`; `resolved` explicitly
/// carries the real final spelling so callers never depend on candidate order.
struct PathResolution<'a> {
    forms: Vec<Cow<'a, str>>,
    resolved: Option<String>,
}

fn resolve_path<'a>(path: &'a str, cwd: Option<&str>) -> PathResolution<'a> {
    let mut forms = vec![Cow::Borrowed(path)];
    let folded = crate::matcher::fold_separators(path);
    if folded.as_ref() != path {
        push_unique(&mut forms, folded.clone());
    }
    let mut primary = folded;

    #[cfg(windows)]
    {
        let drive_joined =
            cwd.and_then(|dir| crate::matcher::drive_relative_join(primary.as_ref(), dir));
        let rooted = normalize_root(primary.as_ref());
        push_unique(&mut forms, Cow::Owned(rooted.clone()));
        primary = Cow::Owned(rooted);
        if let Some(joined) = drive_joined {
            push_unique(&mut forms, Cow::Owned(joined.clone()));
            primary = Cow::Owned(joined);
        }
    }

    if let Some(expanded) = crate::matcher::expand_tilde(primary.as_ref()) {
        push_unique(&mut forms, Cow::Owned(expanded.clone()));
        primary = Cow::Owned(expanded);
    } else if !is_absolute(primary.as_ref())
        && !primary.starts_with('~')
        && let Some(dir) = cwd
    {
        #[cfg(windows)]
        let dir = normalize_root(dir);
        let rel = primary.strip_prefix("./").unwrap_or(primary.as_ref());
        let joined = format!("{}/{}", dir.trim_end_matches('/'), rel);
        push_unique(&mut forms, Cow::Owned(joined.clone()));
        primary = Cow::Owned(joined);
    }

    let unnormalized = forms.len();
    for i in 0..unnormalized {
        if let Some(normalized) = lexical_normalize(forms[i].as_ref()) {
            push_unique(&mut forms, Cow::Owned(normalized));
        }
    }

    let resolved = lexical_normalize(primary.as_ref()).unwrap_or_else(|| primary.into_owned());
    let resolved = (resolved != path).then_some(resolved);
    forms.remove(0);
    PathResolution { forms, resolved }
}

/// Could this command word name a file, and is it worth resolving?
///
/// Conservative on both sides. A word must start like a filename, which drops
/// options (`-rf`, `--exclude=x`), redirections (`>out`, `2>&1`), and operators.
/// It must then name a directory (`~`, a separator) or be a bare `.`/`..`, which
/// drops ordinary arguments (`push`, `main`, `fix`). A `scheme://host/path` URL is
/// excluded: its slashes are not a filesystem path, and the Generic family
/// already matches it by host.
///
/// Being wrong in the permissive direction only costs a wasted candidate, because
/// the form it feeds can only raise a verdict and only on a real rule match.
pub(crate) fn names_a_path(word: &str) -> bool {
    let starts_like_a_name = word
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || matches!(c, '.' | '/' | '~' | '_'));
    if !starts_like_a_name {
        return false;
    }
    // A word with no separator can only be a dot segment: splitting it on `/` would
    // yield the word itself, so the general scan reduces to these two equalities.
    // The `://` scan runs last so an ordinary argument never pays for it.
    (word.starts_with('~')
        || word.contains('/')
        || word == "."
        || word == ".."
        || (cfg!(windows) && is_absolute(word)))
        && !word.contains("://")
}

/// Does `path` carry a `.` or `..` segment, i.e. is there anything for
/// [`lexical_normalize`] to collapse? The gate for every caller that wants to skip
/// the work when there is none.
fn has_dot_segment(path: &str) -> bool {
    path.split('/').any(|s| s == "." || s == "..")
}

/// Lexically resolve `.` and `..` segments of `path` without touching the
/// filesystem (no symlink following, §9.2). Returns the collapsed form only when
/// it differs from `path`; `None` when there is nothing to collapse. An absolute
/// path stays rooted and a `..` at the root is dropped; a relative path keeps a
/// leading `..` it cannot cancel.
fn lexical_normalize(path: &str) -> Option<String> {
    if !has_dot_segment(path) {
        return None;
    }
    let absolute = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => match out.last() {
                Some(&s) if s != ".." => {
                    out.pop();
                }
                // A relative path keeps a leading `..` it cannot cancel; an
                // absolute path drops a `..` at the root.
                _ if !absolute => out.push(".."),
                _ => {}
            },
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    let result = if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    };
    (result != path).then_some(result)
}

/// Candidate forms for a Generic payload: raw, the extracted host, and its
/// lowercased form (§7.1).
pub(crate) fn generic_candidates(payload: &str) -> Vec<Cow<'_, str>> {
    let mut v = vec![Cow::Borrowed(payload)];
    if let Some(host) = url_host_ref(payload) {
        let lower = host.to_ascii_lowercase();
        push_unique(&mut v, Cow::Borrowed(host));
        if lower != host {
            push_unique(&mut v, Cow::Owned(lower));
        }
    }
    v
}

/// Extract the host from a `scheme://[user@]host[:port]/…` URL (§7.1). Public so
/// it can be exercised directly by the integration tests.
pub fn url_host(s: &str) -> Option<String> {
    url_host_ref(s).map(str::to_owned)
}

fn url_host_ref(s: &str) -> Option<&str> {
    let idx = s.find("://")?;
    let after = &s[idx + 3..];
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..end];
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = match host_port.rfind(':') {
        Some(colon) if colon > 0 && host_port[colon + 1..].bytes().all(|b| b.is_ascii_digit()) => {
            &host_port[..colon]
        }
        _ => host_port,
    };
    if host.is_empty() { None } else { Some(host) }
}

/// True if any **deny**-tier rule for one of `tools` matches `path` (§8). Used by
/// the Bash file-access cross-check, which only ever raises to `deny`.
///
/// Candidates are prepared once into [`PathProbe`]s and reused across rules; a
/// candidate with no glob metacharacter reduces to a plain matcher test.
pub(crate) fn path_hits_deny(rs: &RuleSet, tools: &[&str], path: &str, cwd: Option<&str>) -> bool {
    if path.len() > MAX_PAYLOAD_BYTES {
        return true;
    }
    let candidates = path_candidates(path, cwd);
    let probes: Vec<_> = candidates
        .iter()
        .map(|candidate| crate::matcher::PathProbe::new(candidate.as_ref()))
        .collect();
    tools.iter().any(|&tool| {
        rs.matching_rule_indices(tool).iter().any(|&idx| {
            let rule = &rs.rules[idx];
            rule.tier == Tier::Deny
                && probes
                    .iter()
                    .any(|probe| probe.hits(&rule.matcher).unwrap_or(true))
        })
    })
}

fn push_unique<'a>(v: &mut Vec<Cow<'a, str>>, s: Cow<'a, str>) {
    if !v.contains(&s) {
        v.push(s);
    }
}
