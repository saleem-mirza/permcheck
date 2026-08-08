//! Compound-Bash decision pipeline (§8).
//!
//! A single Bash `command` may contain several commands. [`decide_bash`] splits
//! it into units, decides each against the Bash matchers, applies a file-access
//! cross-check that can only raise a unit to `deny`, and aggregates the
//! most-restrictive verdict. The splitter is total: it never errors.

use crate::rules::RuleSet;
use crate::types::{Decision, Tier};

mod crosscheck;
mod forms;
mod prefix;
mod split;
mod tokenize;
use crosscheck::cross_check;
use forms::{identity_forms, unit_tier};
pub use prefix::strip_env_assignments;
use prefix::strip_leading_wrappers;
pub use tokenize::{RedirectKind, Token, tokenize};

/// Decide a Bash command by aggregating per-unit verdicts (§8).
pub fn decide_bash(command: &str, rs: &RuleSet, cwd: Option<&str>) -> Decision {
    let (units, too_deep) = split::units(command);
    // Incomplete units could miss a denied inner command, so fail closed (§9.1).
    if too_deep {
        return Decision::deny_msg("bash: substitution nesting too deep");
    }
    if units.is_empty() {
        // Empty / whitespace-only command matches no Bash rule -> fall-back tier.
        return Decision::for_call(rs.default_tier, "Bash", command);
    }

    let mut worst = Tier::Allow;
    for unit in units {
        let cmd = strip_env_assignments(unit);
        let forms = identity_forms(cmd);
        let mut tier = unit_tier(rs, &forms, cwd);
        // A leading wrapper (`env`, `sudo`, `timeout`, …) executes the command
        // that follows it, so the wrapped command's own decision must apply too.
        // Otherwise `env aws …` would ride in on the wrapper's allow rule and
        // bypass an `aws` deny. This can only raise the verdict (§8.3).
        //
        // Peel from the canonical spelling rather than the raw unit: a disguised
        // wrapper (`"env" aws …`) is invisible to the raw string, and every
        // pipeline stage leaves the leading word easier to recognize, never
        // harder.
        // Skip it once already at deny: the re-decision can only raise, so there is
        // nothing left for it to add, and it would re-resolve every path operand
        // and re-scan the rule index to learn that.
        if tier != Tier::Deny
            && let Some(inner) = strip_leading_wrappers(forms.canonical())
        {
            let inner_tier = unit_tier(rs, &identity_forms(inner), cwd);
            if inner_tier > tier {
                tier = inner_tier;
            }
        }
        // The file-access cross-check raises a unit to deny only; skip it once we
        // are already at deny. Flag-variant and interpreter-inline normalization
        // are handled inside `unit_tier` (for the command and the wrapped inner).
        if tier != Tier::Deny && cross_check(rs, cmd, cwd) {
            tier = Tier::Deny;
        }
        if tier == Tier::Deny {
            return Decision::for_call(Tier::Deny, "Bash", command);
        }
        worst = worst.max(tier);
    }

    Decision::for_call(worst, "Bash", command)
}

// --- Splitter (§8.1) ---------------------------------------------------------

/// Split a command into units on shell operators outside quotes, pulling inner
/// commands out of `$(…)`, backticks, and `<(…)` / `>(…)` substitutions. Never
/// errors; unterminated constructs are consumed to end of input. This is the
/// owned public/test wrapper; the decision path borrows units via `split::units`.
pub fn split(input: &str) -> Vec<String> {
    split::owned_units(input)
}
