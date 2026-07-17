//! Core data types + payload extraction (§5, §6.2).
//!
//! [`Tier`] is the three-way decision lattice, [`Decision`] is the engine's
//! output, and [`Family`] routes a tool to one of three matcher families.
//! [`extract_payload`] pulls the string that gets matched out of `tool_input`.

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
    /// Build the canonical decision for a tool call (§2.1): the reason is
    /// `<label>: <payload>`, or `<label>: <tool>` when the tool takes no payload
    /// (the extracted payload is empty). This is the single place the §2.1 reason
    /// form is constructed, so the library and the binary never diverge.
    pub fn for_call(tier: Tier, tool: &str, payload: &str) -> Self {
        let what = if payload.is_empty() { tool } else { payload };
        Decision {
            tier,
            reason: format!("{}: {}", tier.label(), what),
        }
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

/// Extract the primary payload string from a tool's `tool_input` (§5).
///
/// Returns the empty string when the expected field is missing or the tool
/// takes no string payload (e.g. `TodoWrite`), in which case only a bare rule
/// can match it.
pub fn extract_payload(tool: &str, input: &Value) -> String {
    let field = |key: &str| input.get(key).and_then(Value::as_str);

    let extracted: Option<&str> = match tool {
        "Bash" => field("command"),
        "Read" | "Write" | "Edit" => field("file_path"),
        "NotebookEdit" => field("notebook_path"),
        "Glob" | "Grep" => field("path").or_else(|| field("pattern")),
        "WebFetch" => field("url"),
        "WebSearch" => field("query"),
        "SlashCommand" => field("command"),
        // Generic fallback: the lexicographically-first (by field name)
        // non-empty string field of tool_input. `serde_json::Map` is a
        // `BTreeMap` (no `preserve_order` feature), so `.values()` visits keys
        // in sorted order — deterministic, and the behavior SPEC §5 pins.
        _ => input.as_object().and_then(|map| {
            map.values()
                .find_map(|v| v.as_str().filter(|s| !s.is_empty()))
        }),
    };

    extracted.unwrap_or("").to_string()
}
