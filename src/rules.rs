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
/// and file-order index for stable tie-breaking (§6.3).
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub tool: String,
    pub matcher: Matcher,
    pub specificity: u32,
    pub tier: Tier,
    pub order_index: usize,
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
    /// Indices of the rules whose tool name equals `tool`, in file order.
    pub fn rules_for(&self, tool: &str) -> &[usize] {
        self.index.get(tool).map(Vec::as_slice).unwrap_or(&[])
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
            for item in arr {
                let s = item.as_str().ok_or(LoadError::RuleNotString)?;
                let (tool, m, specificity) = parse_rule(s)?;
                let order_index = rules.len();
                rules.push(CompiledRule {
                    tool,
                    matcher: m,
                    specificity,
                    tier,
                    order_index,
                });
            }
        }

        // Fall-back tier for unmatched calls (§6.4). `"ask"` opts into
        // asking; "deny", missing, or any other value stays fail-closed.
        let default_tier = match permissions.get("defaultMode").and_then(Value::as_str) {
            Some("ask") => Tier::Ask,
            _ => Tier::Deny,
        };

        let mut index: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, rule) in rules.iter().enumerate() {
            index.entry(rule.tool.clone()).or_default().push(idx);
        }

        Ok(RuleSet {
            rules,
            index,
            default_tier,
        })
    }
}

/// The canonical secure rule set, embedded at build time. It is the single
/// source of truth for the `deny` list that [`starter_rules`] seeds a fresh file
/// with. It is **not** a decision-time default: the hook and CLI always require
/// an explicit `--rules` path.
const DEFAULT_RULES: &str = include_str!("../rules/permissions.json");

/// A starter rules value for `permcheck --init-rules`: the canonical `deny` list,
/// `defaultMode: "ask"`, and empty `allow`/`ask` for the user to grow.
pub fn starter_rules() -> Value {
    let canonical: Value =
        serde_json::from_str(DEFAULT_RULES).expect("embedded rules/permissions.json is valid JSON");
    let deny = canonical
        .get("permissions")
        .and_then(|p| p.get("deny"))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    serde_json::json!({
        "permissions": {
            "allow": [],
            "ask": [],
            "deny": deny,
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

        // deny is copied verbatim from the canonical set (non-empty, same length).
        let canonical: Value = serde_json::from_str(DEFAULT_RULES).unwrap();
        let canon_deny = canonical["permissions"]["deny"].as_array().unwrap().len();
        assert!(canon_deny > 0, "canonical deny list must be non-empty");
        assert_eq!(perms["deny"].as_array().unwrap().len(), canon_deny);

        // The written form loads and falls back to ask.
        let text = serde_json::to_string(&v).unwrap();
        let rs = RuleSet::load_str(&text).unwrap();
        assert_eq!(rs.default_tier, Tier::Ask);
    }
}
