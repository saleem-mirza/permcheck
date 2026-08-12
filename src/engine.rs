//! Winner selection and candidate forms (§6.3, §7). [`decide_hit`] is the
//! carve-out-aware selection every family uses; [`decide_payload`] is the whole
//! decision for Path and Generic tools, and Bash adds its compound step.

#[cfg(windows)]
use crate::matcher::normalize_root;
use crate::matcher::{WorkBudget, is_absolute};
use crate::rules::{CompiledRule, MAX_PAYLOAD_BYTES, RuleSet};
use crate::types::{Decision, Family, Tier};
use std::borrow::Cow;

/// Decide the tier for `tool`, plus the rule that set it as an index into
/// `rs.rules` (§6.3, §2.1). A matching deny holds unless an allow/ask is a strict
/// carve-out of it. `None` means nothing matched, so the caller falls back (§6.4).
pub(crate) fn decide_hit<S: AsRef<str>>(
    rs: &RuleSet,
    tool: &str,
    candidates: &[S],
    budget: &mut WorkBudget,
) -> Option<(Tier, Option<usize>)> {
    if candidates
        .iter()
        .any(|candidate| candidate.as_ref().len() > MAX_PAYLOAD_BYTES)
    {
        return Some((Tier::Deny, None));
    }
    // Rule indices are tier-ordered Allow -> Ask -> Deny, so by the time a deny
    // matches every possible carve-out has been seen and an uncarved deny can
    // return at once. The inline array plus lazy spill keeps that off the heap.
    const CAP: usize = 8;
    let mut buf: [Option<&CompiledRule>; CAP] = [None; CAP];
    let mut n = 0usize;
    let mut spill: Vec<&CompiledRule> = Vec::new();
    let mut best_carve: Option<(usize, &CompiledRule)> = None;
    let mut last_tier = Tier::Allow;
    for &idx in rs.matching_rule_indices(tool).iter() {
        let rule = &rs.rules[idx];
        debug_assert!(
            last_tier <= rule.tier,
            "rule index must remain tier-ordered"
        );
        last_tier = rule.tier;
        let mut matched = false;
        for candidate in candidates {
            match rule
                .matcher
                .matches_checked_with_budget(candidate.as_ref(), budget)
            {
                Ok(true) => {
                    matched = true;
                    break;
                }
                Ok(false) => {}
                Err(()) => return Some((Tier::Deny, None)),
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
                return Some((Tier::Deny, Some(idx)));
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
            None => (idx, rule),
            Some((_, current)) if selection_key(rule) > selection_key(current) => (idx, rule),
            Some(current) => current,
        });
    }
    best_carve.map(|(idx, rule)| (rule.tier, Some(idx)))
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
    let mut budget = WorkBudget::new();
    // Fall-back §6.4. A single call is a one-statement list, attributed like a
    // Bash unit (§2.1).
    let hit = decide_hit(rs, tool, &candidates, &mut budget);
    let tier = hit.map_or(rs.default_tier, |(tier, _)| tier);
    Decision::for_call_because(tier, tool, payload, || match hit {
        Some((_, Some(idx))) => Some(Clause::Rule(&rs.rules[idx].source)),
        Some((_, None)) => None,
        None => Some(Clause::FallBack(rs.default_tier)),
    })
}

/// Why a call got its tier, rendered into the reason (§2.1). A `Display` rather
/// than a `String`, so a decision costs one allocation either way.
pub(crate) enum Clause<'a> {
    /// The rule that decided it, as the operator wrote it.
    Rule(&'a str),
    /// Nothing matched. Naming the configured mode is what separates a policy
    /// hole from a policy decision (§6.4).
    FallBack(Tier),
}

impl std::fmt::Display for Clause<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Clause::Rule(source) => write!(f, "matched {source}"),
            Clause::FallBack(tier) => write!(f, "no rule matched, defaultMode={}", tier.label()),
        }
    }
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

/// Resolve one Bash operand to the path it really names (§7.2, §8 step 2), or
/// `None` for a token naming no path. Absolutizing against `cwd` is what stops
/// `Bash(rm -rf .scratch/*)` matching a `.scratch` in any directory at all.
pub(crate) fn resolve_operand(token: &str, cwd: Option<&str>) -> Option<String> {
    let folded = crate::matcher::fold_separators(token);
    if !names_a_path(&folded) {
        return None;
    }
    resolve_path(token, cwd).resolved
}

/// Every additive path spelling shared by Path payloads and Bash operands, in
/// resolution order: root anchoring, drive join, `~`, CWD, then `.`/`..` collapse.
/// `resolved` carries the final spelling, so callers never depend on form order.
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

/// Could this command word name a file, and is it worth resolving? A word must
/// start like a filename and then name a directory or be a bare `.`/`..`, which
/// drops options, redirections, ordinary arguments, and URLs.
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

/// Lexically resolve `.` and `..` in `path`, never touching the filesystem (§9.2).
/// `None` when there is nothing to collapse. An absolute path stays rooted and a
/// root `..` is dropped; a relative path keeps a leading `..` it cannot cancel.
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

/// Whether a deny-tier rule for one of `tools` matches `path`, and which rule did
/// (§8.3). The inner `None` means a §9.1 limit denied before any rule matched, so
/// there is no rule to name: an oversized path, or matcher work exhausted
/// mid-scan. Candidates are prepared once into [`PathProbe`]s and reused.
pub(crate) fn path_deny_hit(
    rs: &RuleSet,
    tools: &[&str],
    path: &str,
    cwd: Option<&str>,
    budget: &mut WorkBudget,
) -> Option<Option<usize>> {
    // Unreachable from the one caller today: a cross-check operand is bounded by
    // its command, which `decide_bash` already caps. The invariant lives in
    // another function, so the assert fails the tests the day a caller stops
    // honouring it, and the fail-closed return still covers a release build.
    debug_assert!(
        path.len() <= MAX_PAYLOAD_BYTES,
        "path_deny_hit got a {}-byte path; every caller is bounded by the command cap",
        path.len()
    );
    if path.len() > MAX_PAYLOAD_BYTES {
        return Some(None);
    }
    let candidates = path_candidates(path, cwd);
    let probes: Vec<_> = candidates
        .iter()
        .map(|candidate| crate::matcher::PathProbe::new(candidate.as_ref()))
        .collect();
    for &tool in tools {
        for &idx in rs.matching_rule_indices(tool).iter() {
            let rule = &rs.rules[idx];
            if rule.tier != Tier::Deny {
                continue;
            }
            for probe in &probes {
                match probe.hits(&rule.matcher, budget) {
                    Ok(true) => return Some(Some(idx)),
                    Ok(false) => {}
                    // Out of matcher work: fail closed, naming no rule. This one
                    // did not match, and the scan never reached the rest, so
                    // attributing the deny to it would send the operator to a
                    // rule that has nothing to do with the block.
                    Err(()) => return Some(None),
                }
            }
        }
    }
    None
}

fn push_unique<'a>(v: &mut Vec<Cow<'a, str>>, s: Cow<'a, str>) {
    if !v.contains(&s) {
        v.push(s);
    }
}
