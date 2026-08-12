//! Rule grammar, loading, and the compiled rule set (§3, §4). Bad rules fail at
//! **load**, never at decision time: [`load`] returns a fully valid [`RuleSet`] or
//! a [`LoadError`] the caller turns into `deny` (hook) or exit 3 (CLI).

use crate::matcher::{self, Matcher};
use crate::types::{Family, Tier};
use serde_json::{Map, Value};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::Path;

/// Hard bounds on trusted policy input and untrusted call payloads. These keep
/// configuration mistakes and hostile hook input from turning one short-lived
/// checker invocation into unbounded work (§9.1).
pub(crate) const MAX_RULE_FILE_BYTES: usize = 1_048_576;
pub(crate) const MAX_RULES: usize = 4_096;
pub(crate) const MAX_RULE_BYTES: usize = 1_024;
pub(crate) const MAX_PAYLOAD_BYTES: usize = 32_768;

/// Carve-out warnings reported before [`RuleSet::lint_warnings`] stops scanning
/// pairs. An author fixes these a few at a time, and the pair scan is quadratic,
/// so the cap is what keeps a repeated mistake from costing seconds of search and
/// millions of lines of stderr.
const MAX_CARVE_OUT_WARNINGS: usize = 50;

/// Everything that can go wrong loading a rule file (§3, §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// The file could not be read.
    Io(String),
    /// The file is not valid JSON.
    Json(String),
    /// Top-level JSON is not an object.
    NotObject,
    /// No `permissions` object and no top-level tier arrays.
    NoPermissions,
    /// A tier array contained a non-string entry.
    RuleNotString,
    /// A rule string is not `Tool` or `Tool(specifier)`.
    MalformedRule(String),
    /// `Tool()` with an empty specifier.
    EmptySpecifier(String),
    /// A specifier that could not be compiled into a matcher. Unreachable today,
    /// since the matchers are total for any non-empty specifier and empty ones are
    /// rejected earlier; kept so a future fallible matcher fails at load (§4).
    BadSpecifier(String),
    /// A policy exceeded a documented resource bound.
    LimitExceeded(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "cannot read rules file: {e}"),
            LoadError::Json(e) => write!(f, "invalid JSON in rules file: {e}"),
            LoadError::NotObject => write!(f, "rules file is not a JSON object"),
            LoadError::NoPermissions => write!(f, "rules file has no permissions object"),
            LoadError::RuleNotString => write!(f, "a rule entry is not a string"),
            LoadError::MalformedRule(r) => write!(f, "malformed rule: {r}"),
            LoadError::EmptySpecifier(r) => write!(f, "empty specifier in rule: {r}"),
            LoadError::BadSpecifier(r) => write!(f, "uncompilable specifier in rule: {r}"),
            LoadError::LimitExceeded(detail) => write!(f, "policy limit exceeded: {detail}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// One compiled rule: the tool it applies to, its matcher, specificity, tier,
/// file-order index for stable tie-breaking (§6.3), and the original rule string
/// as written (for lint messages).
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub tool: String,
    pub matcher: Matcher,
    pub specificity: u32,
    pub tier: Tier,
    pub order_index: usize,
    pub source: String,
    selector: ToolSelector,
    tool_specificity: u32,
}

/// The deliberately narrow tool-name glob grammar: exact names, a terminal `*`
/// prefix selector, or `*` itself. Wildcard selectors are bare rules, so one
/// payload matcher can never straddle several tool families.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ToolSelector {
    Exact(String),
    Prefix(String),
}

impl ToolSelector {
    fn matches(&self, tool: &str) -> bool {
        match self {
            Self::Exact(exact) => tool == exact,
            Self::Prefix(prefix) => tool.starts_with(prefix),
        }
    }

    fn is_subset_of(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact(a), Self::Exact(b)) => a == b,
            (Self::Exact(a), Self::Prefix(b)) => a.starts_with(b),
            (Self::Prefix(a), Self::Prefix(b)) => a.starts_with(b),
            (Self::Prefix(_), Self::Exact(_)) => false,
        }
    }

    fn specificity(&self) -> u32 {
        match self {
            Self::Exact(name) => matcher::EXACT_MATCH_BONUS + name.len() as u32,
            Self::Prefix(prefix) => prefix.len() as u32,
        }
    }
}

/// A loaded rule set with an exact-name index plus a small wildcard-selector list.
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub rules: Vec<CompiledRule>,
    index: HashMap<String, Vec<usize>>,
    wildcard_indices: Vec<usize>,
    /// Tier applied when a call matches **no** rule (§6.4). Configured by the
    /// `defaultMode` field: `"ask"` → [`Tier::Ask`], otherwise (`"deny"`,
    /// missing, or any other value) → [`Tier::Deny`], fail-closed.
    pub default_tier: Tier,
    /// The `defaultMode` value as written, when it is neither `"ask"` nor
    /// `"deny"`. Held only so [`RuleSet::lint_warnings`] can name it (§11.2);
    /// the tier above is already resolved fail-closed.
    unknown_default_mode: Option<String>,
}

impl RuleSet {
    /// Indices of the rules whose tool name equals `tool`, ordered by tier
    /// (`Allow`, `Ask`, `Deny`) and then file order within the tier. Winner
    /// selection relies on every possible carve-out preceding the denies.
    pub fn rules_for(&self, tool: &str) -> &[usize] {
        self.index.get(tool).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Indices of exact and wildcard selectors matching `tool`, in global
    /// tier/file order. Borrows the exact list when no wildcard selector matches
    /// (the common case: a policy with no `Tool*`/`*` selectors never allocates
    /// or sorts here), since each tool's exact list is already ascending by
    /// `order_index`.
    pub(crate) fn matching_rule_indices(&self, tool: &str) -> Cow<'_, [usize]> {
        let exact = self.index.get(tool).map(Vec::as_slice).unwrap_or(&[]);
        if self.wildcard_indices.is_empty()
            || !self
                .wildcard_indices
                .iter()
                .any(|&idx| self.rules[idx].selector.matches(tool))
        {
            return Cow::Borrowed(exact);
        }
        let mut out = Vec::with_capacity(exact.len() + self.wildcard_indices.len());
        out.extend_from_slice(exact);
        out.extend(
            self.wildcard_indices
                .iter()
                .copied()
                .filter(|&idx| self.rules[idx].selector.matches(tool)),
        );
        out.sort_unstable();
        Cow::Owned(out)
    }

    /// Rule-language containment includes both the tool selector and payload
    /// matcher, so exact-tool exceptions can refine broader selectors safely.
    pub(crate) fn is_strict_carve_out(&self, narrow: &CompiledRule, broad: &CompiledRule) -> bool {
        rule_subset(narrow, broad) && !rule_subset(broad, narrow)
    }

    /// Author-time lint warnings that do not block loading, printed to stderr in
    /// the CLI-check and `--install` paths only. Two kinds: a narrower rule that
    /// loosens a broader one, and an unrecognized `defaultMode` (§11.2). The
    /// carve-out scan stops at [`MAX_CARVE_OUT_WARNINGS`].
    pub fn lint_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();

        // Policy-wide warnings first, so the list reads top-down.
        if let Some(value) = &self.unknown_default_mode {
            out.push(format!(
                "`defaultMode` is `{value}`, which is neither `ask` nor `deny`, so unmatched calls fall back to `deny`. Claude Code's `permissions.defaultMode` accepts session modes such as `dontAsk` under the same key name; this file is a permcheck policy, not `settings.json`.",
            ));
        }

        // Unusual but valid `cmd:*` prefixes retain literal semantics. Warn about
        // likely authoring mistakes without changing or rejecting the rule.
        for rule in &self.rules {
            let Matcher::Bash(matcher::BashMatcher::Prefix(prefix)) = &rule.matcher else {
                continue;
            };
            if prefix.contains('*') {
                out.push(format!(
                    "rule `{}` has `*` before `:*`; prefix form treats it as a literal asterisk. If wildcard matching was intended, use the Bash glob form (no `:*`).",
                    rule.source,
                ));
            }
            let leading = prefix.starts_with(char::is_whitespace);
            if leading || prefix.ends_with(char::is_whitespace) {
                let trimmed = prefix.trim();
                let detail = if leading {
                    "a unit is trimmed before matching, so the leading whitespace makes this rule match nothing"
                        .to_string()
                } else {
                    format!(
                        "the trailing whitespace requires another boundary (`{trimmed} x` does not match, `{trimmed}  x` does)"
                    )
                };
                out.push(format!(
                    "rule `{}` has edge whitespace in its `cmd:*` prefix: {detail}. If that was unintended, write `Bash({trimmed}:*)`.",
                    rule.source,
                ));
            }
        }

        // Wildcard selectors can interact with exact names, so compare all pairs.
        // The cheap selector-containment gate rejects unrelated tools before the
        // matcher work, and file order keeps warnings deterministic.
        //
        // The cap bounds the search as well as the output, since reaching it ends
        // the scan: a policy repeating one mistake across N rules has N² carving
        // pairs, and every one of them clears the cheap gate and runs the full
        // containment test. 1000 asks inside 1000 denies took 7.7s and a million
        // identical lines before the cap.
        let carve_outs = out.len();
        'pairs: for narrow in &self.rules {
            for broad in &self.rules {
                if out.len() - carve_outs >= MAX_CARVE_OUT_WARNINGS {
                    out.push(format!(
                        "stopped after {MAX_CARVE_OUT_WARNINGS} carve-out warnings; fix these and re-run to see the rest."
                    ));
                    break 'pairs;
                }
                // An `ask` inside a `deny` downgrades a hard block to a prompt.
                if narrow.tier == Tier::Ask
                    && broad.tier == Tier::Deny
                    && self.is_strict_carve_out(narrow, broad)
                {
                    out.push(format!(
                        "ask rule `{}` is a subset of deny rule `{}`, so it carves out the deny: matching calls prompt instead of being blocked, and a prompt can be approved. Drop the ask, or narrow the deny, if the block was intended.",
                        narrow.source, broad.source,
                    ));
                }
                // A more-specific `allow` inside a broader `ask` wins on
                // specificity and drops the prompt for that subset.
                if narrow.tier == Tier::Allow
                    && broad.tier == Tier::Ask
                    && specificity_key(narrow) > specificity_key(broad)
                    && self.is_strict_carve_out(narrow, broad)
                {
                    out.push(format!(
                        "allow rule `{}` is a subset of ask rule `{}` and outranks it on specificity, so matching calls are allowed without the prompt. Confirm the prompt was not meant to cover them.",
                        narrow.source, broad.source,
                    ));
                }
            }
        }

        out
    }

    /// Load and compile a rule set from a file path.
    pub fn load(path: &Path) -> Result<RuleSet, LoadError> {
        let file = std::fs::File::open(path).map_err(|e| LoadError::Io(e.to_string()))?;
        let mut text = String::new();
        file.take((MAX_RULE_FILE_BYTES + 1) as u64)
            .read_to_string(&mut text)
            .map_err(|e| LoadError::Io(e.to_string()))?;
        RuleSet::load_str(&text)
    }

    /// Load and compile a rule set from an in-memory JSON string.
    pub fn load_str(text: &str) -> Result<RuleSet, LoadError> {
        if text.len() > MAX_RULE_FILE_BYTES {
            return Err(LoadError::LimitExceeded(format!(
                "rules file is {} bytes; maximum is {MAX_RULE_FILE_BYTES}",
                text.len()
            )));
        }
        let value: Value =
            serde_json::from_str(text).map_err(|e| LoadError::Json(e.to_string()))?;
        let obj = value.as_object().ok_or(LoadError::NotObject)?;

        let permissions: &Map<String, Value> = if let Some(p) = obj.get("permissions") {
            p.as_object().ok_or(LoadError::NotObject)?
        } else if obj.contains_key("allow") || obj.contains_key("ask") || obj.contains_key("deny") {
            obj
        } else {
            return Err(LoadError::NoPermissions);
        };

        let mut rules = Vec::new();
        let mut index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut wildcard_indices = Vec::new();
        // Fixed tier order gives a deterministic file order for tie-breaking,
        // independent of JSON object key ordering.
        for (key, tier) in [
            ("allow", Tier::Allow),
            ("ask", Tier::Ask),
            ("deny", Tier::Deny),
        ] {
            let Some(entry) = permissions.get(key) else {
                continue; // missing array is treated as empty
            };
            let arr = entry.as_array().ok_or(LoadError::NotObject)?;
            rules.reserve(arr.len().min(MAX_RULES.saturating_sub(rules.len())));
            for item in arr {
                if rules.len() >= MAX_RULES {
                    return Err(LoadError::LimitExceeded(format!(
                        "more than {MAX_RULES} rules"
                    )));
                }
                let s = item.as_str().ok_or(LoadError::RuleNotString)?;
                let (tool, selector, m, specificity) = parse_rule(s)?;
                let order_index = rules.len();
                match &selector {
                    ToolSelector::Exact(exact) => {
                        index.entry(exact.clone()).or_default().push(order_index);
                    }
                    ToolSelector::Prefix(_) => wildcard_indices.push(order_index),
                }
                let tool_specificity = selector.specificity();
                rules.push(CompiledRule {
                    tool,
                    matcher: m,
                    specificity,
                    tier,
                    order_index,
                    source: s.to_string(),
                    selector,
                    tool_specificity,
                });
            }
        }

        // Fall-back tier for unmatched calls (§6.4). `"ask"` opts into
        // asking; "deny", missing, or any other value stays fail-closed.
        let configured = permissions.get("defaultMode");
        let default_tier = match configured.and_then(Value::as_str) {
            Some("ask") => Tier::Ask,
            _ => Tier::Deny,
        };
        // A present-but-unrecognized value is fail-closed above and linted below
        // (§11.2). Non-string JSON is rendered so the warning quotes what was
        // written rather than an empty string.
        let unknown_default_mode = match configured {
            None => None,
            Some(Value::String(s)) if s == "ask" || s == "deny" => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(other) => Some(other.to_string()),
        };

        Ok(RuleSet {
            rules,
            index,
            wildcard_indices,
            default_tier,
            unknown_default_mode,
        })
    }
}

/// The canonical reference rule set, embedded only in test builds so the suite can
/// assert it loads and lints clean. Not a decision-time default (`--rules` is
/// always required) and not the `--init-rules` seed, which is [`starter_rules`].
#[cfg(test)]
const DEFAULT_RULES: &str = include_str!("../rules/permcheck.json");

/// The minimal `deny` list `--init-rules` seeds, a safe default the user grows.
/// The policy denies cover every location a decision is read from: miss one and a
/// `Write` swaps the policy out from under the next call.
const STARTER_DENY: &[&str] = &[
    "Bash(sudo:*)",
    "Bash(rm -f:*)",
    "Bash(git push --force:*)",
    "Read(//**/.env*)",
    "Read(//**/id_rsa*)",
    "Read(//**/.ssh/**)",
    "Edit(//**/.claude/permcheck.json)",
    "Write(//**/.claude/permcheck.json)",
    "Edit(//**/.claude/permcheck.local.json)",
    "Write(//**/.claude/permcheck.local.json)",
    "Edit(//**/.claude/settings.json)",
    "Write(//**/.claude/settings.json)",
    "Edit(//**/.claude/settings.local.json)",
    "Write(//**/.claude/settings.local.json)",
    "Edit(//**/.permcheck/**)",
    "Write(//**/.permcheck/**)",
];

/// A starter rules value for `permcheck --init-rules`: the minimal safe [`STARTER_DENY`]
/// list, `defaultMode: "ask"`, and empty `allow`/`ask` for the user to grow.
pub fn starter_rules() -> Value {
    serde_json::json!({
        "permissions": {
            "allow": [],
            "ask": [],
            "deny": STARTER_DENY,
            "defaultMode": "ask",
        }
    })
}

/// Parse one rule string into `(tool, matcher, specificity)` (§4).
fn parse_rule(s: &str) -> Result<(String, ToolSelector, Matcher, u32), LoadError> {
    if s.len() > MAX_RULE_BYTES {
        return Err(LoadError::LimitExceeded(format!(
            "rule is {} bytes; maximum is {MAX_RULE_BYTES}: {s}",
            s.len()
        )));
    }
    let bytes = s.as_bytes();
    if bytes == b"*" {
        return Ok((
            s.to_string(),
            ToolSelector::Prefix(String::new()),
            Matcher::Bare,
            0,
        ));
    }
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return Err(LoadError::MalformedRule(s.to_string()));
    }
    let mut i = 1;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    let tool = &s[..i];

    // Tool-name globs are terminal-star, bare selectors. Keeping specifiers off
    // wildcard names prevents one payload matcher from crossing tool families.
    if bytes.get(i) == Some(&b'*') {
        if i + 1 != s.len() {
            return Err(LoadError::MalformedRule(s.to_string()));
        }
        return Ok((
            s.to_string(),
            ToolSelector::Prefix(tool.to_string()),
            Matcher::Bare,
            0,
        ));
    }
    let selector = ToolSelector::Exact(tool.to_string());

    // Bare rule: the whole string is a valid tool name.
    if i == s.len() {
        return Ok((tool.to_string(), selector, Matcher::Bare, 0));
    }

    // Otherwise it must be `Tool(specifier)`.
    if bytes[i] != b'(' || !s.ends_with(')') {
        return Err(LoadError::MalformedRule(s.to_string()));
    }
    let spec = &s[i + 1..s.len() - 1];
    if spec.is_empty() {
        return Err(LoadError::EmptySpecifier(s.to_string()));
    }

    let family = Family::from_tool(tool);
    let (m, specificity) =
        matcher::compile(family, spec).map_err(|_| LoadError::BadSpecifier(s.to_string()))?;
    Ok((tool.to_string(), selector, m, specificity))
}

fn rule_subset(a: &CompiledRule, d: &CompiledRule) -> bool {
    a.selector.is_subset_of(&d.selector) && matcher::matcher_subset(&a.matcher, &d.matcher)
}

pub(crate) fn selection_key(rule: &CompiledRule) -> (u32, u32, Tier, std::cmp::Reverse<usize>) {
    (
        rule.tool_specificity,
        rule.specificity,
        rule.tier,
        std::cmp::Reverse(rule.order_index),
    )
}

fn specificity_key(rule: &CompiledRule) -> (u32, u32) {
    (rule.tool_specificity, rule.specificity)
}

#[cfg(test)]
mod starter_tests {
    use super::*;

    #[test]
    fn starter_rules_is_secure_skeleton() {
        let v = starter_rules();
        let perms = &v["permissions"];
        assert!(perms["allow"].as_array().unwrap().is_empty());
        assert!(perms["ask"].as_array().unwrap().is_empty());
        assert_eq!(perms["defaultMode"], "ask");

        // A minimal but non-empty deny list covering the safe-default categories.
        let deny = perms["deny"].as_array().unwrap();
        assert!(!deny.is_empty(), "starter deny list must be non-empty");
        for needle in ["Bash(sudo:*)", "Bash(rm -f:*)", "Bash(git push --force:*)"] {
            assert!(
                deny.iter().any(|r| r == needle),
                "starter deny missing {needle}"
            );
        }

        // Every location a decision can be read from must be write-protected.
        for path in [
            "//**/.claude/permcheck.json",
            "//**/.claude/permcheck.local.json",
            "//**/.claude/settings.json",
            "//**/.claude/settings.local.json",
            "//**/.permcheck/**",
        ] {
            for tool in ["Edit", "Write"] {
                let needle = format!("{tool}({path})");
                assert!(
                    deny.iter().any(|r| r == &needle),
                    "starter deny missing {needle}"
                );
            }
        }

        // The written form loads, lints clean, and falls back to ask.
        let text = serde_json::to_string(&v).unwrap();
        let rs = RuleSet::load_str(&text).unwrap();
        assert_eq!(rs.default_tier, Tier::Ask);
        assert!(
            rs.lint_warnings().is_empty(),
            "starter has lint warnings: {:?}",
            rs.lint_warnings()
        );
    }
}

#[cfg(test)]
mod lint_tests {
    use super::*;

    #[test]
    fn unusual_prefix_rules_load_and_warn_without_changing_semantics() {
        for rule in [
            "Bash(aws * --region east:*)",
            "Bash(curl :*)",
            "Bash( curl:*)",
        ] {
            let rs = RuleSet::load_str(&format!(r#"{{"deny":["{rule}"]}}"#)).unwrap();
            assert_eq!(rs.lint_warnings().len(), 1, "rule: {rule}");
        }
    }

    #[test]
    fn session_mode_as_default_mode_warns() {
        // `dontAsk` is a Claude Code session mode, not a permcheck fall-back
        // tier. It resolves to deny (fail-closed) and the lint names it (§6.4).
        let rs =
            RuleSet::load_str(r#"{"permissions":{"defaultMode":"dontAsk","allow":[]}}"#).unwrap();
        assert_eq!(rs.default_tier, Tier::Deny);
        let w = rs.lint_warnings();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("dontAsk"));
        assert!(w[0].contains("fall back to `deny`"));
    }

    #[test]
    fn non_string_default_mode_warns_with_its_value() {
        // A non-string value also misses both tiers; the warning quotes what was
        // written rather than an empty string.
        let rs = RuleSet::load_str(r#"{"permissions":{"defaultMode":true,"allow":[]}}"#).unwrap();
        assert_eq!(rs.default_tier, Tier::Deny);
        let w = rs.lint_warnings();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("`true`"));
    }

    #[test]
    fn recognized_and_missing_default_modes_do_not_warn() {
        for text in [
            r#"{"permissions":{"defaultMode":"ask","allow":[]}}"#,
            r#"{"permissions":{"defaultMode":"deny","allow":[]}}"#,
            r#"{"permissions":{"allow":[]}}"#,
        ] {
            let rs = RuleSet::load_str(text).unwrap();
            assert!(rs.lint_warnings().is_empty(), "warned on {text}");
        }
    }

    #[test]
    fn legitimate_forms_do_not_warn() {
        // Glob form (no `:*`), a plain prefix (no `*`), and a path rule with `*`.
        let rs = RuleSet::load_str(
            r#"{"allow":["Bash(aws * describe-*)","Bash(aws:*)","Bash(git push --force:*)"],"deny":["Read(/**/.env*)"]}"#,
        )
        .unwrap();
        assert!(rs.lint_warnings().is_empty());
    }

    #[test]
    fn reference_set_has_no_lint_warnings() {
        // The shipped policy has no weakening carve-outs or other warnings.
        let rs = RuleSet::load_str(DEFAULT_RULES).unwrap();
        assert!(
            rs.lint_warnings().is_empty(),
            "reference rules have lint warnings: {:?}",
            rs.lint_warnings()
        );
    }

    #[test]
    fn ask_inside_deny_warns_block_becomes_prompt() {
        // `git push --force` is denied, but an ask carves it back to a prompt.
        let rs = RuleSet::load_str(
            r#"{"ask":["Bash(git push --force:*)"],"deny":["Bash(git push:*)"]}"#,
        )
        .unwrap();
        let w = rs.lint_warnings();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("prompt instead of being blocked"));
    }

    #[test]
    fn allow_inside_ask_warns_prompt_dropped() {
        // `git push:*` prompts, but the narrower, more-specific allow drops it.
        let rs = RuleSet::load_str(
            r#"{"allow":["Bash(git push origin:*)"],"ask":["Bash(git push:*)"]}"#,
        )
        .unwrap();
        let w = rs.lint_warnings();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("allowed without the prompt"));
    }

    #[test]
    fn exact_tool_allow_inside_wildcard_ask_warns() {
        let rs =
            RuleSet::load_str(r#"{"allow":["mcp__serena__read_file"],"ask":["mcp__serena__*"]}"#)
                .unwrap();
        let warnings = rs.lint_warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("mcp__serena__read_file"));
        assert!(warnings[0].contains("mcp__serena__*"));
    }

    #[test]
    fn the_carve_out_scan_stops_at_the_cap() {
        // One mistake repeated across N rules has N² carving pairs, each running
        // the full containment test. Unbounded, 1000 asks inside 1000 denies took
        // 7.7s and a million identical lines.
        let rules = |tier: &str, spec: &str| {
            let one = format!(r#""Read({spec})""#);
            format!(r#""{tier}":[{}]"#, vec![one; 200].join(","))
        };
        let rs = RuleSet::load_str(&format!(
            "{{{},{}}}",
            rules("ask", "/srv/app/**/*.conf"),
            rules("deny", "/srv/app/**")
        ))
        .unwrap();
        let w = rs.lint_warnings();
        assert_eq!(w.len(), MAX_CARVE_OUT_WARNINGS + 1);
        assert!(w.last().unwrap().contains("stopped after"));
    }

    #[test]
    fn allow_inside_deny_is_not_flagged() {
        // The intended read-only carve-out must stay silent.
        let rs =
            RuleSet::load_str(r#"{"allow":["Bash(aws * describe-*)"],"deny":["Bash(aws:*)"]}"#)
                .unwrap();
        assert!(rs.lint_warnings().is_empty(), "{:?}", rs.lint_warnings());
    }
}
