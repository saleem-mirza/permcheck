//! Compound-Bash decision pipeline (§8). [`decide_bash`] splits a command into
//! units, decides each against the Bash matchers, applies a file-access
//! cross-check that only raises, and takes the most restrictive verdict.

use std::fmt::{self, Write as _};

use crate::engine::Clause;
use crate::matcher::WorkBudget;
use crate::rules::MAX_PAYLOAD_BYTES;
use crate::rules::RuleSet;
use crate::types::{Decision, Tier};

mod crosscheck;
mod forms;
mod prefix;
mod split;
mod tokenize;
use crosscheck::{CrossHit, cross_check};
use forms::{identity_forms, unit_tier};
pub use prefix::strip_env_assignments;
use prefix::strip_leading_wrappers;
pub use tokenize::{RedirectKind, Token, tokenize};

/// What set one unit's verdict, so the decision can name it (§2.1). Otherwise a
/// blocked compound echoes the whole command and a missing allow entry looks
/// identical to a real escalation.
struct Why<'a> {
    index: usize,
    total: usize,
    unit: &'a str,
    /// Set when a peel stage, not the unit itself, carried the verdict.
    stage: Option<&'a str>,
    /// Set when the file-access cross-check raised the unit to `deny`.
    cross: Option<CrossHit>,
    /// Index into `rs.rules` of the rule that set the tier.
    rule: Option<usize>,
    tier: Tier,
}

/// A [`Why`] bound to its rule set, so it renders into the reason with no
/// intermediate string.
struct WhyClause<'a> {
    why: &'a Why<'a>,
    rs: &'a RuleSet,
}

impl fmt::Display for WhyClause<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let why = self.why;
        if why.total > 1 {
            write!(
                f,
                "statement {} of {}: \"{}\" ",
                why.index + 1,
                why.total,
                Clipped(why.unit)
            )?;
        }
        let named = why.rule.map(|idx| self.rs.rules[idx].source.as_str());
        match (&why.cross, why.stage, named) {
            (Some(hit), _, Some(rule)) => write!(
                f,
                "reaches denied path \"{}\" via {rule}",
                Clipped(&hit.operand)
            ),
            (Some(hit), _, None) => {
                write!(f, "reaches denied path \"{}\"", Clipped(&hit.operand))
            }
            (None, Some(stage), Some(rule)) => {
                write!(f, "wrapper stage \"{}\" matched {rule}", Clipped(stage))
            }
            (None, _, Some(rule)) => write!(f, "matched {rule}"),
            // No rule to name: the fall-back applied, or a §9.1 limit denied first.
            (None, _, None) if why.tier == self.rs.default_tier => {
                write!(f, "{}", Clause::FallBack(self.rs.default_tier))
            }
            (None, _, None) => write!(f, "blocked by a safety limit"),
        }
    }
}

/// A fragment written with a length bound, so a 32KB payload cannot produce a
/// 32KB reason. Truncates by character, never mid-codepoint.
struct Clipped<'a>(&'a str);

impl fmt::Display for Clipped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX_CHARS: usize = 120;
        let text = self.0.trim();
        for ch in text.chars().take(MAX_CHARS) {
            f.write_char(ch)?;
        }
        if text.chars().nth(MAX_CHARS).is_some() {
            f.write_char('…')?;
        }
        Ok(())
    }
}

/// Decide a Bash command by aggregating per-unit verdicts (§8).
pub fn decide_bash(command: &str, rs: &RuleSet, cwd: Option<&str>) -> Decision {
    const MAX_UNITS: usize = 1_024;
    if command.len() > MAX_PAYLOAD_BYTES {
        return Decision::deny_msg("bash: command exceeds the 32768-byte safety limit");
    }
    let (units, too_deep) = split::units(command);
    // Incomplete units could miss a denied inner command, so fail closed (§9.1).
    if too_deep {
        return Decision::deny_msg("bash: substitution nesting too deep");
    }
    if units.len() > MAX_UNITS {
        return Decision::deny_msg("bash: command contains more than 1024 units");
    }
    if units.is_empty() {
        // Only whitespace, a bare separator, a comment, or an empty subshell get
        // here, and none runs a command (§8 step 4).
        return Decision::for_call(Tier::Allow, "Bash", command);
    }

    let total = units.len();
    let mut budget = WorkBudget::new();
    let mut worst: Option<Why<'_>> = None;
    for (index, unit) in units.into_iter().enumerate() {
        // Structure runs nothing, so it carries no verdict (§8 step 4).
        if prefix::executes_nothing(unit) {
            continue;
        }
        let cmd = strip_env_assignments(unit);
        let forms = identity_forms(cmd);
        let (mut tier, mut rule) = unit_tier(rs, &forms, cwd, &mut budget);
        let mut stage_used = None;
        // Each peel stage is decided too, since a rule naming a wrapper only
        // matches in head position. Raises only, so `deny` ends the walk; `ask`
        // cannot, being indistinguishable from an unmatched stage (§8.3).
        if tier != Tier::Deny {
            let (stages, too_many) = strip_leading_wrappers(cmd);
            // Truncated stages could hide a denied command, so fail closed (§9.1).
            if too_many {
                return Decision::deny_msg("bash: unit has more than 32 leading wrappers");
            }
            for stage in stages {
                let (stage_tier, stage_rule) =
                    unit_tier(rs, &identity_forms(stage), cwd, &mut budget);
                if stage_tier > tier {
                    tier = stage_tier;
                    rule = stage_rule;
                    stage_used = Some(stage);
                }
                if tier == Tier::Deny {
                    break;
                }
            }
        }
        // The cross-check raises to deny only, so skip it once already there.
        let mut cross = None;
        if tier != Tier::Deny
            && let Some(hit) = cross_check(rs, cmd, cwd, &mut budget)
        {
            tier = Tier::Deny;
            rule = hit.rule;
            cross = Some(hit);
        }
        let why = Why {
            index,
            total,
            unit,
            stage: stage_used,
            cross,
            rule,
            tier,
        };
        if tier == Tier::Deny {
            return Decision::for_call_because(Tier::Deny, "Bash", command, || {
                Some(WhyClause { why: &why, rs })
            });
        }
        if worst.as_ref().is_none_or(|current| tier > current.tier) {
            worst = Some(why);
        }
    }

    let Some(why) = worst else {
        // Every unit was structure, so nothing runs (§8 step 4).
        return Decision::for_call(Tier::Allow, "Bash", command);
    };
    Decision::for_call_because(why.tier, "Bash", command, || {
        Some(WhyClause { why: &why, rs })
    })
}

// --- Splitter (§8.1) ---------------------------------------------------------

/// Split a command into units on shell operators outside quotes, lifting inner
/// commands out of substitutions. Never errors. The owned public/test wrapper;
/// the decision path borrows units via `split::units`.
pub fn split(input: &str) -> Vec<String> {
    split::owned_units(input)
}
