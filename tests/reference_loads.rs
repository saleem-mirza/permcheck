//! The full reference rule set loads clean, and every specifier compiles.

use permcheck::RuleSet;

const RULES: &str = include_str!("../rules/permissions.json");

#[test]
fn reference_rule_set_loads() {
    let rs = RuleSet::load_str(RULES).expect("reference rules must load without error");
    assert!(!rs.rules.is_empty());
}

#[test]
fn reference_has_expected_tool_coverage() {
    let rs = RuleSet::load_str(RULES).unwrap();
    assert!(!rs.rules_for("Bash").is_empty());
    assert!(!rs.rules_for("Read").is_empty());
    assert!(!rs.rules_for("Write").is_empty());
    assert!(!rs.rules_for("Edit").is_empty());
    assert!(!rs.rules_for("WebFetch").is_empty());
    assert!(!rs.rules_for("WebSearch").is_empty());
}
