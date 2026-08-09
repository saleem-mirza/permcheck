//! permcheck: a specificity-aware permission engine for Claude Code. Given a tool
//! call and a [`RuleSet`], [`evaluate`] returns one [`Decision`] with a reason,
//! never executing the call. `specs/SPEC.md` is the source of truth.

pub mod bash;
pub mod engine;
pub mod matcher;
pub mod rules;
pub mod settings;
pub mod types;

use serde_json::Value;

pub use rules::LoadError as RuleLoadError;
pub use rules::RuleSet;
pub use types::{Decision, Family, Tier};

/// Load and compile a rule set from a file path (`rules::load`).
pub fn load_rules(path: &std::path::Path) -> Result<RuleSet, RuleLoadError> {
    RuleSet::load(path)
}

/// Load and compile a rule set from an in-memory JSON string (`rules::load_str`).
pub fn load_rules_str(text: &str) -> Result<RuleSet, RuleLoadError> {
    RuleSet::load_str(text)
}

/// Decide a single tool call. The payload is extracted from `tool_input`
/// (§5) and routed by family: Bash runs the compound pipeline (§8), Path and
/// Generic run single-pass winner selection (§6.3).
pub fn evaluate(rules: &RuleSet, tool: &str, tool_input: &Value, cwd: Option<&str>) -> Decision {
    let payload = types::extract_payload_ref(tool, tool_input);
    evaluate_payload(rules, tool, payload, cwd)
}

/// Decide a call whose family-specific payload has already been extracted. This
/// avoids constructing a temporary `tool_input` object in manual CLI mode.
pub fn evaluate_payload(rules: &RuleSet, tool: &str, payload: &str, cwd: Option<&str>) -> Decision {
    match Family::from_tool(tool) {
        Family::Bash => bash::decide_bash(payload, rules, cwd),
        Family::Path | Family::Generic => engine::decide_payload(rules, tool, payload, cwd),
    }
}
