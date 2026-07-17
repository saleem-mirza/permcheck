//! Rule grammar + loading tests (§3, §4).
//!
//! `parse_rule` is crate-internal, so these exercise the grammar through the
//! public `RuleSet::load_str` loader and the public `CompiledRule` fields.

use permcheck::RuleSet;
use permcheck::rules::LoadError;
use permcheck::types::Tier;

fn load(src: &str) -> Result<RuleSet, LoadError> {
    RuleSet::load_str(src)
}

#[test]
fn both_shapes_parse_identically() {
    let wrapped = r#"{"permissions":{"allow":["Read"],"deny":["WebFetch"]}}"#;
    let flat = r#"{"allow":["Read"],"deny":["WebFetch"]}"#;
    assert_eq!(
        load(wrapped).unwrap().rules.len(),
        load(flat).unwrap().rules.len()
    );
}

#[test]
fn unknown_keys_are_ignored() {
    let src = r#"{"permissions":{"allow":["Read"],"defaultMode":"default","disableAutoMode":"x"}}"#;
    assert_eq!(load(src).unwrap().rules.len(), 1);
}

#[test]
fn missing_arrays_are_empty() {
    let rs = load(r#"{"allow":["Read"]}"#).unwrap();
    assert_eq!(rs.rules_for("Read").len(), 1);
    assert_eq!(rs.rules_for("Bash").len(), 0);
}

#[test]
fn bare_rule_has_zero_specificity() {
    let rs = load(r#"{"allow":["Read"]}"#).unwrap();
    assert_eq!(rs.rules[0].tool, "Read");
    assert_eq!(rs.rules[0].specificity, 0);
}

#[test]
fn exact_specifier_outranks_any_wildcard() {
    // No wildcard -> +1000 bonus; a wildcard rule scores only its literal chars.
    let rs = load(r#"{"allow":["Read(/etc/hosts)"],"deny":["Read(/etc/*)"]}"#).unwrap();
    assert!(rs.rules[0].specificity >= 1000, "exact rule gets the bonus");
    assert!(rs.rules[1].specificity < 1000, "wildcard rule does not");
}

#[test]
fn empty_specifier_is_load_error() {
    assert!(matches!(
        load(r#"{"deny":["Bash()"]}"#),
        Err(LoadError::EmptySpecifier(_))
    ));
}

#[test]
fn malformed_rules_are_load_errors() {
    assert!(matches!(
        load(r#"{"deny":["9bad"]}"#),
        Err(LoadError::MalformedRule(_))
    ));
    assert!(matches!(
        load(r#"{"deny":["Bash(x"]}"#),
        Err(LoadError::MalformedRule(_))
    ));
    assert!(matches!(
        load(r#"{"deny":[""]}"#),
        Err(LoadError::MalformedRule(_))
    ));
}

#[test]
fn non_string_rule_entry_is_error() {
    assert!(matches!(
        load(r#"{"deny":[123]}"#),
        Err(LoadError::RuleNotString)
    ));
}

#[test]
fn tier_value_must_be_an_array() {
    assert!(matches!(
        load(r#"{"allow":"Read"}"#),
        Err(LoadError::NotObject)
    ));
}

#[test]
fn not_object_and_no_permissions() {
    assert!(matches!(load("[]"), Err(LoadError::NotObject)));
    assert!(matches!(load("not json"), Err(LoadError::Json(_))));
    assert!(matches!(load("{}"), Err(LoadError::NoPermissions)));
}

#[test]
fn mcp_tool_names_parse() {
    let rs = load(r#"{"allow":["mcp__github__create_issue(x)"]}"#).unwrap();
    assert_eq!(rs.rules[0].tool, "mcp__github__create_issue");
}

#[test]
fn order_index_is_file_order_allow_then_ask_then_deny() {
    let rs = load(r#"{"deny":["Bash(a:*)"],"ask":["Bash(b:*)"],"allow":["Bash(c:*)"]}"#).unwrap();
    let idx = |t: Tier| rs.rules.iter().find(|r| r.tier == t).unwrap().order_index;
    // File order is fixed as allow -> ask -> deny, independent of JSON key order.
    assert!(idx(Tier::Allow) < idx(Tier::Ask));
    assert!(idx(Tier::Ask) < idx(Tier::Deny));
}
