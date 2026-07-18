//! Rule grammar + loading unit tests (§3, §4).

use crate::rules::{LoadError, RuleSet, parse_rule};
use crate::types::Tier;

#[test]
fn both_shapes_parse_identically() {
    let wrapped = r#"{"permissions":{"allow":["Read"],"deny":["WebFetch"]}}"#;
    let flat = r#"{"allow":["Read"],"deny":["WebFetch"]}"#;
    let a = RuleSet::load_str(wrapped).unwrap();
    let b = RuleSet::load_str(flat).unwrap();
    assert_eq!(a.rules.len(), b.rules.len());
}

#[test]
fn unknown_keys_are_ignored() {
    let src = r#"{"permissions":{"allow":["Read"],"defaultMode":"default","disableAutoMode":"x"}}"#;
    let rs = RuleSet::load_str(src).unwrap();
    assert_eq!(rs.rules.len(), 1);
}

#[test]
fn missing_arrays_are_empty() {
    let rs = RuleSet::load_str(r#"{"allow":["Read"]}"#).unwrap();
    assert_eq!(rs.rules_for("Read").len(), 1);
    assert_eq!(rs.rules_for("Bash").len(), 0);
}

#[test]
fn bare_rule_has_zero_specificity() {
    let (tool, _m, spec) = parse_rule("Read").unwrap();
    assert_eq!(tool, "Read");
    assert_eq!(spec, 0);
}

#[test]
fn empty_specifier_is_load_error() {
    assert!(matches!(
        parse_rule("Bash()"),
        Err(LoadError::EmptySpecifier(_))
    ));
}

#[test]
fn malformed_rules_are_load_errors() {
    assert!(matches!(
        parse_rule("9bad"),
        Err(LoadError::MalformedRule(_))
    ));
    assert!(matches!(
        parse_rule("Bash(x"),
        Err(LoadError::MalformedRule(_))
    ));
    assert!(matches!(parse_rule(""), Err(LoadError::MalformedRule(_))));
}

#[test]
fn not_object_and_no_permissions() {
    assert!(matches!(RuleSet::load_str("[]"), Err(LoadError::NotObject)));
    assert!(matches!(
        RuleSet::load_str("not json"),
        Err(LoadError::Json(_))
    ));
    assert!(matches!(
        RuleSet::load_str("{}"),
        Err(LoadError::NoPermissions)
    ));
}

#[test]
fn mcp_tool_names_parse() {
    let (tool, _m, _s) = parse_rule("mcp__github__create_issue(x)").unwrap();
    assert_eq!(tool, "mcp__github__create_issue");
}

#[test]
fn order_index_is_file_order_allow_then_ask_then_deny() {
    let rs = RuleSet::load_str(r#"{"deny":["Bash(a:*)"],"allow":["Bash(b:*)"]}"#).unwrap();
    // allow is processed first, so it gets the lower order_index.
    let allow = rs.rules.iter().find(|r| r.tier == Tier::Allow).unwrap();
    let deny = rs.rules.iter().find(|r| r.tier == Tier::Deny).unwrap();
    assert!(allow.order_index < deny.order_index);
}
