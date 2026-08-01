//! Winner selection and candidate forms (§6.3, §7).
//!
//! [`decide_tier`] is the carve-out-aware selection used by every family: a deny
//! holds unless a matching allow/ask is a subset carve-out of it. [`decide_payload`]
//! is the whole decision for Path and Generic tools; Bash adds the compound step
//! in [`crate::bash`].

#[cfg(windows)]
use crate::matcher::normalize_root;
use crate::matcher::{home_dir, is_absolute};
use crate::rules::{CompiledRule, RuleSet};
use crate::types::{Decision, Family, Tier};

/// Decide the tier for `tool` given the payload's candidate forms (§6.3).
///
/// A matching deny holds unless some matching allow/ask rule is a **carve-out** of
/// it, i.e. its match-set is a subset of that deny ([`matcher_subset`]). If any
/// matching deny is left un-carved, the decision is `deny`. Otherwise the winner
/// is chosen among the matching allow/ask rules, maximizing `(specificity, tier)`
/// lexicographically with a full tie broken by the lowest `order_index` (first in
/// file order).
///
/// Returns `None` when nothing matches (caller applies the `defaultMode`
/// fall-back, §6.4).
pub(crate) fn decide_tier(rs: &RuleSet, tool: &str, candidates: &[&str]) -> Option<Tier> {
    // One pass: match each rule once, recording the (few) hits, the best allow/ask
    // winner, and whether any deny matched. A single payload matches only a handful
    // of rules, so a small stack buffer holds them with no heap allocation; an
    // unusually large match set spills to a `Vec` (empty `Vec::new()` allocates
    // nothing until the first push). Recording during the match pass lets the
    // subset check reuse the hits instead of matching a second time.
    const CAP: usize = 8;
    let mut buf: [Option<&CompiledRule>; CAP] = [None; CAP];
    let mut n = 0usize;
    let mut spill: Vec<&CompiledRule> = Vec::new();
    let mut best_carve: Option<&CompiledRule> = None;
    let mut any_deny = false;
    for &idx in rs.rules_for(tool) {
        let rule = &rs.rules[idx];
        if !candidates.iter().any(|c| rule.matcher.matches(c)) {
            continue;
        }
        if n < CAP {
            buf[n] = Some(rule);
            n += 1;
        } else {
            spill.push(rule);
        }
        if rule.tier == Tier::Deny {
            any_deny = true;
        } else {
            best_carve = Some(match best_carve {
                None => rule,
                Some(cur) => {
                    let cur_key = (cur.specificity, cur.tier);
                    let new_key = (rule.specificity, rule.tier);
                    if new_key > cur_key
                        || (new_key == cur_key && rule.order_index < cur.order_index)
                    {
                        rule
                    } else {
                        cur
                    }
                }
            });
        }
    }
    if !any_deny {
        return best_carve.map(|r| r.tier); // allow/ask winner, or `None` -> fall-back
    }
    if best_carve.is_none() {
        return Some(Tier::Deny); // deny matched, nothing could carve it out
    }

    // A deny and a carve candidate both matched. A deny survives unless every
    // matching deny is carved out by a matching allow/ask that is its *strict*
    // subset (`a ⊆ d` and `d ⊄ a`). Equal match-sets are not carve-outs, so an
    // identical specifier in a lower tier never overrides the deny (§6.6). This
    // double loop runs over the recorded hits only, doing no further matching.
    let total = n + spill.len();
    let get = |i: usize| -> &CompiledRule { if i < n { buf[i].unwrap() } else { spill[i - n] } };
    let all_carved = (0..total).all(|i| {
        let d = get(i);
        if d.tier != Tier::Deny {
            return true;
        }
        (0..total).any(|j| {
            let a = get(j);
            a.tier != Tier::Deny
                && crate::matcher::matcher_subset(&a.matcher, &d.matcher)
                && !crate::matcher::matcher_subset(&d.matcher, &a.matcher)
        })
    });
    if all_carved {
        best_carve.map(|r| r.tier) // every deny carved; the allow/ask winner takes it
    } else {
        Some(Tier::Deny)
    }
}

/// The complete decision for a Path or Generic tool (§6.3, §7).
pub fn decide_payload(rs: &RuleSet, tool: &str, payload: &str, cwd: Option<&str>) -> Decision {
    let candidates = match Family::from_tool(tool) {
        Family::Path => path_candidates(payload, cwd),
        _ => generic_candidates(payload),
    };
    let refs: Vec<&str> = candidates.iter().map(String::as_str).collect();
    let tier = decide_tier(rs, tool, &refs).unwrap_or(rs.default_tier); // fall-back §6.4
    Decision::for_call(tier, tool, payload)
}

/// Candidate forms for a Path payload: raw, `~`-expanded, and `cwd`-absolutized
/// (§7.1, §7.2).
pub(crate) fn path_candidates(payload: &str, cwd: Option<&str>) -> Vec<String> {
    let mut v = Vec::with_capacity(4);
    v.push(payload.to_string());

    // A Windows payload arrives drive-letter-rooted with backslashes
    // (`D:\proj\.env`); its POSIX-anchored form (`/D:/proj/.env`) is what the
    // `/`-based Path globs match. POSIX needs no such candidate — the raw
    // payload above is already anchored — so this whole step compiles out there.
    #[cfg(windows)]
    push_unique(&mut v, normalize_root(payload));

    if payload == "~" {
        push_unique(&mut v, home_dir().to_string());
    } else if let Some(rest) = payload.strip_prefix("~/") {
        push_unique(&mut v, format!("{}/{}", home_dir(), rest));
    }

    // Relative payloads are absolutized against cwd (§7.2). An already-absolute
    // payload (`/`-rooted, or a Windows drive-letter root) is left to its
    // normalized form above and must not be joined onto cwd.
    if !is_absolute(payload)
        && !payload.starts_with('~')
        && let Some(dir) = cwd
    {
        // Only the cwd base needs Windows normalization (`D:\proj` -> `/D:/proj`);
        // on POSIX `dir` is already `/`-rooted and is used as-is, allocation-free.
        #[cfg(windows)]
        let dir = normalize_root(dir);
        let rel = payload.strip_prefix("./").unwrap_or(payload);
        push_unique(&mut v, format!("{}/{}", dir.trim_end_matches('/'), rel));
    }

    // Lexically collapse `.`/`..` in each candidate so a traversal spelling cannot
    // route around a directory-anchored deny (`/tmp/../etc/shadow` -> `/etc/shadow`
    // still hits `Read(/etc/**)`, §7.2). Resolution is purely lexical: no symlink
    // following, which stays a non-goal (§9.2). Additive — a new candidate only
    // ever adds a match, preserving the fail-closed bias. The bound is the length
    // captured before the loop, so the pushes below are not re-scanned.
    for i in 0..v.len() {
        if let Some(norm) = lexical_normalize(&v[i]) {
            push_unique(&mut v, norm);
        }
    }
    v
}

/// Lexically resolve `.` and `..` segments of `path` without touching the
/// filesystem (no symlink following, §9.2). Returns the collapsed form only when
/// it differs from `path`; `None` when there is nothing to collapse. An absolute
/// path stays rooted and a `..` at the root is dropped; a relative path keeps a
/// leading `..` it cannot cancel.
fn lexical_normalize(path: &str) -> Option<String> {
    if !path.split('/').any(|s| s == "." || s == "..") {
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
pub(crate) fn generic_candidates(payload: &str) -> Vec<String> {
    let mut v = vec![payload.to_string()];
    if let Some(host) = url_host(payload) {
        let lower = host.to_ascii_lowercase();
        push_unique(&mut v, host);
        push_unique(&mut v, lower);
    }
    v
}

/// Extract the host from a `scheme://[user@]host[:port]/…` URL (§7.1). Public so
/// it can be exercised directly by the integration tests.
pub fn url_host(s: &str) -> Option<String> {
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
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// True if any **deny**-tier rule for one of `tools` matches `path` (§8). Used by
/// the Bash file-access cross-check, which only ever raises to `deny`.
pub(crate) fn path_hits_deny(rs: &RuleSet, tools: &[&str], path: &str, cwd: Option<&str>) -> bool {
    let candidates = path_candidates(path, cwd);
    let refs: Vec<&str> = candidates.iter().map(String::as_str).collect();
    for &tool in tools {
        for &idx in rs.rules_for(tool) {
            let rule = &rs.rules[idx];
            if rule.tier == Tier::Deny
                && refs
                    .iter()
                    .any(|c| crate::matcher::path_glob_hits(&rule.matcher, c))
            {
                return true;
            }
        }
    }
    false
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}
