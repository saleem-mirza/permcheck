//! Rule grammar, loading, and the compiled rule set (§3, §4).
//!
//! Bad rules fail at **load**, never at decision time: every specifier is
//! compiled up front, so [`load`] either returns a fully valid [`RuleSet`] or a
//! [`LoadError`] the caller turns into `deny` (hook) / exit 3 (CLI).

use crate::matcher::{self, Matcher};
use crate::types::{Family, Tier};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;

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
    /// A specifier that could not be compiled into a matcher.
    ///
    /// Currently **unreachable**: the matchers in [`crate::matcher`] are total
    /// for any non-empty specifier, and [`parse_rule`] already rejects the empty
    /// specifier as [`LoadError::EmptySpecifier`] before calling `compile`. This
    /// variant is a deliberate, forward-compatible placeholder so that adding a
    /// fallible matcher later fails at **load**, never at decision time (§4).
    BadSpecifier(String),
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
}

/// A loaded rule set with a tool-name index for O(1) candidate lookup.
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub rules: Vec<CompiledRule>,
    index: HashMap<String, Vec<usize>>,
    /// Tier applied when a call matches **no** rule (§6.4). Configured by the
    /// `defaultMode` field: `"ask"` → [`Tier::Ask`], otherwise (`"deny"`,
    /// missing, or any other value) → [`Tier::Deny`], fail-closed.
    pub default_tier: Tier,
}

impl RuleSet {
    /// Indices of the rules whose tool name equals `tool`, ordered by tier
    /// (`Allow`, `Ask`, `Deny`) and then file order within the tier. Winner
    /// selection relies on every possible carve-out preceding the denies.
    pub fn rules_for(&self, tool: &str) -> &[usize] {
        self.index.get(tool).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Author-time lint warnings that do **not** block loading (a flagged rule is
    /// inert, not dangerous). The binary prints these to stderr in the CLI-check
    /// and `--install` paths, never in hook mode.
    ///
    /// **Dead rule.** A Bash `cmd:*` specifier whose prefix contains `*`. The
    /// `cmd:*` form matches `cmd` literally, so an interior `*` is a literal
    /// asterisk and the rule matches nothing (§11.2).
    pub fn lint_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();

        // Dead `cmd:*` rules with an interior `*`.
        for rule in &self.rules {
            if let Matcher::Bash(matcher::BashMatcher::Prefix(prefix)) = &rule.matcher
                && prefix.contains('*')
            {
                out.push(format!(
                    "rule `{}` has `*` before `:*`; the `cmd:*` form matches `cmd` literally, so the `*` is a literal asterisk and this rule matches nothing. For a mid-command wildcard use the glob form (no `:*`).",
                    rule.source,
                ));
            }
        }

        out
    }

    /// Load and compile a rule set from a file path.
    pub fn load(path: &Path) -> Result<RuleSet, LoadError> {
        let text = std::fs::read_to_string(path).map_err(|e| LoadError::Io(e.to_string()))?;
        RuleSet::load_str(&text)
    }

    /// Load and compile a rule set from an in-memory JSON string.
    pub fn load_str(text: &str) -> Result<RuleSet, LoadError> {
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
            rules.reserve(arr.len());
            for item in arr {
                let s = item.as_str().ok_or(LoadError::RuleNotString)?;
                let (tool, m, specificity) = parse_rule(s)?;
                let order_index = rules.len();
                index.entry(tool.clone()).or_default().push(order_index);
                rules.push(CompiledRule {
                    tool,
                    matcher: m,
                    specificity,
                    tier,
                    order_index,
                    source: s.to_string(),
                });
            }
        }

        // Fall-back tier for unmatched calls (§6.4). `"ask"` opts into
        // asking; "deny", missing, or any other value stays fail-closed.
        let default_tier = match permissions.get("defaultMode").and_then(Value::as_str) {
            Some("ask") => Tier::Ask,
            _ => Tier::Deny,
        };

        Ok(RuleSet {
            rules,
            index,
            default_tier,
        })
    }
}

/// The canonical reference rule set (`rules/permcheck.json`), embedded only in
/// test builds so the suite can assert it loads and lints clean. It is **not** a
/// decision-time default (the hook and CLI always require an explicit `--rules`),
/// and it is **not** the `--init-rules` seed: that is [`starter_rules`], a
/// minimal list. The full set stays the reference fixture for the spec and tests.
#[cfg(test)]
const DEFAULT_RULES: &str = include_str!("../rules/permcheck.json");

/// The minimal but functional `deny` list `permcheck --init-rules` seeds. It is a
/// safe default the user grows, not the full reference set: privilege escalation,
/// destructive removes, secret reads (which also gate shell readers through the
/// file-access cross-check), history-rewriting push, and edits to permcheck's own
/// policy and its wiring.
const STARTER_DENY: &[&str] = &[
    "Bash(sudo:*)",
    "Bash(rm -f:*)",
    "Bash(git push --force:*)",
    "Read(//**/.env*)",
    "Read(//**/id_rsa*)",
    "Read(//**/.ssh/**)",
    "Edit(//**/.claude/permcheck.json)",
    "Write(//**/.claude/permcheck.json)",
    "Edit(//**/.claude/settings.json)",
    "Write(//**/.claude/settings.json)",
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
pub(crate) fn parse_rule(s: &str) -> Result<(String, Matcher, u32), LoadError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return Err(LoadError::MalformedRule(s.to_string()));
    }
    let mut i = 1;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    let tool = &s[..i];

    // Bare rule: the whole string is a valid tool name.
    if i == s.len() {
        return Ok((tool.to_string(), Matcher::Bare, 0));
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
    Ok((tool.to_string(), m, specificity))
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
    fn dead_prefix_rule_with_interior_star_warns() {
        // `Bash(aws * --region east:*)` compiles to a literal-asterisk prefix, so
        // it matches nothing -- a silently dead rule the lint must flag.
        let rs = RuleSet::load_str(r#"{"deny":["Bash(aws * --region east:*)"]}"#).unwrap();
        let w = rs.lint_warnings();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("aws * --region east"));
        assert!(w[0].contains("matches nothing"));
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
        // The shipped policy has no dead rules.
        let rs = RuleSet::load_str(DEFAULT_RULES).unwrap();
        assert!(
            rs.lint_warnings().is_empty(),
            "reference rules have lint warnings: {:?}",
            rs.lint_warnings()
        );
    }
}
