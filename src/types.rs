//! Core data types and payload extraction (§5, §6.2). [`Tier`] is the decision
//! lattice, [`Decision`] the engine's output, [`Family`] routes a tool to a matcher
//! family, and [`extract_payload`] pulls the matched string from `tool_input`.

use std::fmt;

use serde_json::{Value, json};

/// The three permission tiers, ordered `Allow < Ask < Deny` so that the derived
/// [`Ord`] gives "most restrictive wins" for free (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Allow,
    Ask,
    Deny,
}

impl Tier {
    /// Lowercase label used in both the hook JSON and the reason string.
    pub fn label(self) -> &'static str {
        match self {
            Tier::Allow => "allow",
            Tier::Ask => "ask",
            Tier::Deny => "deny",
        }
    }
}

/// A finished decision: a tier plus a human-readable reason (§2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub tier: Tier,
    pub reason: String,
}

impl Decision {
    /// The canonical decision for a tool call (§2.1): the reason is
    /// `<label>: <payload>`, or `<label>: <tool>` for a tool with no payload. The
    /// single place that form is built, so library and binary cannot diverge.
    pub fn for_call(tier: Tier, tool: &str, payload: &str) -> Self {
        let what = if payload.is_empty() { tool } else { payload };
        Decision {
            tier,
            reason: format!("{}: {}", tier.label(), what),
        }
    }

    /// [`Decision::for_call`] plus a clause naming what produced the tier, keeping
    /// the §2.1 prefix. `permissionDecisionReason` is the only field Claude Code
    /// reads back, so it is the sole channel for explaining a block.
    pub(crate) fn for_call_because<D, F>(tier: Tier, tool: &str, payload: &str, clause: F) -> Self
    where
        D: fmt::Display,
        F: FnOnce() -> Option<D>,
    {
        let what = if payload.is_empty() { tool } else { payload };
        // Written straight into the one format that builds the reason: building the
        // clause separately, or appending it, costs an extra allocation per
        // decision and measured 30-70% slower on the smallest ones.
        let reason = match (tier != Tier::Allow).then(clause).flatten() {
            Some(clause) => format!("{}: {what} ({clause})", tier.label()),
            None => format!("{}: {what}", tier.label()),
        };
        Decision { tier, reason }
    }

    /// A fail-closed `deny` carrying a descriptive reason instead of the uniform
    /// `<label>: <payload>` form (§2.1, §9.1).
    pub fn deny_msg(msg: &str) -> Self {
        Decision {
            tier: Tier::Deny,
            reason: msg.to_string(),
        }
    }

    /// The Claude Code PreToolUse hook output object (§2.1), as a [`Value`].
    fn hook_value(&self) -> Value {
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": self.tier.label(),
                "permissionDecisionReason": self.reason,
            }
        })
    }

    /// Serialize as the Claude Code PreToolUse hook output object (§2.1).
    pub fn to_hook_json(&self) -> String {
        self.hook_value().to_string()
    }

    /// Pretty variant of [`Decision::to_hook_json`].
    pub fn to_hook_json_pretty(&self) -> String {
        serde_json::to_string_pretty(&self.hook_value()).unwrap_or_default()
    }

    /// CLI exit code: `0` allow, `1` ask, `2` deny (§2.2).
    pub fn to_exit_code(&self) -> i32 {
        match self.tier {
            Tier::Allow => 0,
            Tier::Ask => 1,
            Tier::Deny => 2,
        }
    }
}

/// The matcher family a tool routes to (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Bash,
    Path,
    Generic,
}

impl Family {
    /// Route a tool name to its family. Any tool not named explicitly falls into
    /// [`Family::Generic`] and is still evaluated — the taxonomy has no gaps.
    pub fn from_tool(tool: &str) -> Family {
        match tool {
            "Bash" => Family::Bash,
            "Read" | "Write" | "Edit" | "Glob" | "Grep" | "NotebookEdit" => Family::Path,
            _ => Family::Generic,
        }
    }
}

/// Extract the primary payload string from a tool's `tool_input` (§5). Empty when
/// the field is missing or the tool takes no string payload (`TodoWrite`), in which
/// case only a bare rule can match it.
pub fn extract_payload(tool: &str, input: &Value) -> String {
    extract_payload_ref(tool, input).to_owned()
}

/// Borrow the primary payload directly from `tool_input` for the evaluation hot
/// path. [`extract_payload`] remains the owned public compatibility wrapper.
pub(crate) fn extract_payload_ref<'a>(tool: &str, input: &'a Value) -> &'a str {
    let field = |key: &str| input.get(key).and_then(Value::as_str);

    let extracted: Option<&str> = match tool {
        "Bash" => field("command"),
        "Read" | "Write" | "Edit" => field("file_path"),
        "NotebookEdit" => field("notebook_path"),
        "Glob" | "Grep" => field("path").or_else(|| field("pattern")),
        "WebFetch" => field("url"),
        "WebSearch" => field("query"),
        "SlashCommand" => field("command"),
        // The lexicographically-first non-empty string field, per SPEC §5. Key
        // order is computed here, not inherited: `preserve_order` would otherwise
        // silently redefine this as "first inserted field".
        _ => input.as_object().and_then(|map| {
            map.iter()
                .filter(|(_, value)| value.as_str().is_some_and(|s| !s.is_empty()))
                .min_by(|(a, _), (b, _)| a.cmp(b))
                .and_then(|(_, value)| value.as_str())
        }),
    };

    extracted.unwrap_or("")
}
