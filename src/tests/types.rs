//! Payload extraction unit tests (§5).

use crate::types::extract_payload;
use serde_json::json;

#[test]
fn named_fields_are_extracted_per_tool() {
    assert_eq!(extract_payload("Bash", &json!({"command": "ls"})), "ls");
    assert_eq!(extract_payload("Read", &json!({"file_path": "/x"})), "/x");
    assert_eq!(
        extract_payload("NotebookEdit", &json!({"notebook_path": "/n.ipynb"})),
        "/n.ipynb"
    );
    assert_eq!(
        extract_payload("WebFetch", &json!({"url": "https://x"})),
        "https://x"
    );
}

#[test]
fn grep_prefers_path_then_falls_back_to_pattern() {
    assert_eq!(
        extract_payload("Grep", &json!({"path": "/src", "pattern": "foo"})),
        "/src"
    );
    assert_eq!(extract_payload("Grep", &json!({"pattern": "foo"})), "foo");
}

#[test]
fn empty_payload_when_no_string_field() {
    // A tool that takes no string payload extracts the empty string, so only a
    // bare rule can match it (§5).
    assert_eq!(extract_payload("TodoWrite", &json!({"todos": []})), "");
    assert_eq!(extract_payload("ExitPlanMode", &json!({})), "");
}

#[test]
fn generic_fallback_is_lexicographically_first_field() {
    // The Generic fallback picks the lexicographically-first (by field name)
    // non-empty string field (§5). `serde_json::Map` is a BTreeMap, so key order
    // is sorted regardless of JSON source order: `database` (d) < `query` (q).
    let input = json!({"query": "SELECT *", "database": "prod"});
    assert_eq!(extract_payload("mcp__db__run", &input), "prod");

    // Source order reversed — same result, because selection is by sorted key.
    let reversed = json!({"database": "prod", "query": "SELECT *"});
    assert_eq!(extract_payload("mcp__db__run", &reversed), "prod");
}

#[test]
fn generic_fallback_skips_empty_and_non_string_fields() {
    // `alpha` sorts first but is empty; `beta` is a bool; `gamma` is the first
    // non-empty string in sorted order.
    let input = json!({"alpha": "", "beta": true, "gamma": "hit", "delta": 3});
    assert_eq!(extract_payload("mcp__x__y", &input), "hit");
}
