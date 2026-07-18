//! Winner selection and candidate forms (§6.3, §7).
//!
//! [`best_match`] is the single-pass `(specificity, tier)` selection used by
//! every family. [`decide_payload`] is the whole decision for Path and Generic
//! tools; Bash adds the compound step in [`crate::bash`].

use crate::matcher::home_dir;
use crate::rules::{CompiledRule, RuleSet};
use crate::types::{Decision, Family, Tier};

/// Select the winning rule for `tool` given the payload's candidate forms.
///
/// The winner maximizes `(specificity, tier)` lexicographically; a full tie is
/// broken by the lowest `order_index` (first in file order) for determinism
/// (§6.3). Returns `None` when nothing matches (caller applies the `defaultMode`
/// fall-back, §6.4).
pub(crate) fn best_match<'a>(
    rs: &'a RuleSet,
    tool: &str,
    candidates: &[&str],
) -> Option<&'a CompiledRule> {
    let mut best: Option<&CompiledRule> = None;
    for &idx in rs.rules_for(tool) {
        let rule = &rs.rules[idx];
        if !candidates.iter().any(|c| rule.matcher.matches(c)) {
            continue;
        }
        best = Some(match best {
            None => rule,
            Some(current) => {
                let cur_key = (current.specificity, current.tier);
                let new_key = (rule.specificity, rule.tier);
                if new_key > cur_key
                    || (new_key == cur_key && rule.order_index < current.order_index)
                {
                    rule
                } else {
                    current
                }
            }
        });
    }
    best
}

/// The complete decision for a Path or Generic tool (§6.3, §7).
pub fn decide_payload(rs: &RuleSet, tool: &str, payload: &str, cwd: Option<&str>) -> Decision {
    let candidates = match Family::from_tool(tool) {
        Family::Path => path_candidates(payload, cwd),
        _ => generic_candidates(payload),
    };
    let refs: Vec<&str> = candidates.iter().map(String::as_str).collect();
    let tier = match best_match(rs, tool, &refs) {
        Some(rule) => rule.tier,
        None => rs.default_tier, // configurable fall-back (§6.4)
    };
    Decision::for_call(tier, tool, payload)
}

/// Candidate forms for a Path payload: raw, `~`-expanded, and `cwd`-absolutized
/// (§7.1, §7.2).
pub(crate) fn path_candidates(payload: &str, cwd: Option<&str>) -> Vec<String> {
    let mut v = Vec::with_capacity(3);
    v.push(payload.to_string());

    if payload == "~" {
        push_unique(&mut v, home_dir().to_string());
    } else if let Some(rest) = payload.strip_prefix("~/") {
        push_unique(&mut v, format!("{}/{}", home_dir(), rest));
    }

    // Relative payloads are absolutized against cwd (§7.2).
    if !payload.starts_with('/')
        && !payload.starts_with('~')
        && let Some(dir) = cwd
    {
        let rel = payload.strip_prefix("./").unwrap_or(payload);
        push_unique(&mut v, format!("{}/{}", dir.trim_end_matches('/'), rel));
    }
    v
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
            if rule.tier == Tier::Deny && refs.iter().any(|c| rule.matcher.matches(c)) {
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
