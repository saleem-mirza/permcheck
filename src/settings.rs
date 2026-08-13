//! Idempotent install/uninstall of the permcheck PreToolUse hook into a Claude
//! Code `settings.json`. Pure `serde_json::Value` transforms, so [`install`]
//! applied to its own output is a fixed point; `main.rs` owns the file I/O.

use serde_json::{Map, Value, json};

/// Build the hook command string baked into `settings.json`. The binary is bare
/// (PATH-resolved) and the rules path absolute and double-quoted, so a path with
/// spaces works under `sh`, `cmd.exe`, and PowerShell alike. The installer checks
/// that the absolute path contains no character active inside those quotes before
/// it calls this formatter.
pub fn hook_command(abs_rules: &str) -> String {
    format!("permcheck --hook --rules \"{abs_rules}\"")
}

/// Detection marker for a permcheck hook: the command invokes `permcheck` in
/// `--hook` mode, whatever the rules path. A heuristic, not proof of ownership: a
/// user's own `run-permcheck.sh --hook` also matches and would be rewritten.
pub fn is_permcheck_hook(command: &str) -> bool {
    command.contains("permcheck") && command.contains("--hook")
}

/// The `--rules` path in the first installed permcheck hook, used by `--install`
/// to refuse a re-point that would abandon a hook's current policy. Recognizes the
/// quoted form [`hook_command`] writes and the bare form a hand-wired hook uses.
pub fn installed_rules_path(settings: &Value) -> Option<String> {
    let groups = settings["hooks"]["PreToolUse"].as_array()?;
    let command = groups.iter().find_map(|g| {
        g["hooks"].as_array()?.iter().find_map(|h| {
            let c = h.get("command").and_then(Value::as_str)?;
            is_permcheck_hook(c).then_some(c)
        })
    })?;
    // Both spellings the binary itself accepts. Reading only `--rules <path>`
    // left a hook wired with `--rules=<path>` looking pathless, so the refusal
    // below never fired and the install re-pointed it.
    let rest = match command.split_once("--rules=") {
        Some((_, rest)) => rest,
        None => command.split_once("--rules ")?.1.trim_start(),
    };
    let path = match rest.strip_prefix('"') {
        // Quoted: runs to the closing quote, so it may contain spaces.
        Some(quoted) => quoted.split_once('"')?.0,
        // Bare: ends at the next whitespace. Truncating a spaced path is the safe
        // direction, since a mismatch makes `--install` refuse rather than re-point.
        None => rest.split_ascii_whitespace().next()?,
    };
    (!path.is_empty()).then(|| path.to_string())
}

/// Return a new settings object with the permcheck PreToolUse hook present. An
/// existing permcheck hook has its `command` rewritten and duplicates dropped;
/// otherwise a group is appended. Everything else is preserved untouched.
pub fn install(settings: &Value, command: &str) -> Value {
    let mut root = settings.as_object().cloned().unwrap_or_default();

    let hooks = ensure_object(&mut root, "hooks");
    let pretooluse = ensure_array(hooks, "PreToolUse");

    let entry = json!({ "type": "command", "command": command });

    // Rewrite the first permcheck hook in place, dropping any further permcheck
    // duplicates across every matcher group.
    let mut seen = false;
    for group in pretooluse.iter_mut() {
        let Some(inner) = group
            .as_object_mut()
            .and_then(|g| g.get_mut("hooks"))
            .and_then(Value::as_array_mut)
        else {
            continue;
        };
        inner.retain_mut(|h| {
            let is_ours = h
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(is_permcheck_hook);
            if !is_ours {
                return true;
            }
            if seen {
                return false; // drop duplicate permcheck entries
            }
            seen = true;
            h["command"] = json!(command);
            true
        });
    }

    if !seen {
        pretooluse.push(json!({
            "matcher": "*",
            "hooks": [entry],
        }));
    }

    Value::Object(root)
}

/// Return a new settings object with every permcheck PreToolUse hook removed.
/// Containers emptied by the removal are dropped in turn; everything else is
/// preserved, and it is a no-op when no permcheck hook is present.
pub fn uninstall(settings: &Value) -> Value {
    let mut root = match settings.as_object() {
        Some(o) => o.clone(),
        None => return settings.clone(),
    };

    let Some(hooks) = root.get_mut("hooks").and_then(Value::as_object_mut) else {
        return Value::Object(root);
    };

    if let Some(pretooluse) = hooks.get_mut("PreToolUse").and_then(Value::as_array_mut) {
        for group in pretooluse.iter_mut() {
            if let Some(inner) = group
                .as_object_mut()
                .and_then(|g| g.get_mut("hooks"))
                .and_then(Value::as_array_mut)
            {
                inner.retain(|h| {
                    !h.get("command")
                        .and_then(Value::as_str)
                        .is_some_and(is_permcheck_hook)
                });
            }
        }
        // Drop groups whose hooks array is now empty.
        pretooluse.retain(|group| {
            group
                .get("hooks")
                .and_then(Value::as_array)
                .map(|a| !a.is_empty())
                .unwrap_or(true)
        });
        if pretooluse.is_empty() {
            hooks.remove("PreToolUse");
        }
    }

    if hooks.is_empty() {
        root.remove("hooks");
    }

    Value::Object(root)
}

/// Get (or insert an empty) object under `key`, returning it as a mutable map.
fn ensure_object<'a>(parent: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    let slot = parent.entry(key).or_insert_with(|| json!({}));
    if !slot.is_object() {
        *slot = json!({});
    }
    slot.as_object_mut().expect("just ensured object")
}

/// Get (or insert an empty) array under `key`, returning it as a mutable vec.
fn ensure_array<'a>(parent: &'a mut Map<String, Value>, key: &str) -> &'a mut Vec<Value> {
    let slot = parent.entry(key).or_insert_with(|| json!([]));
    if !slot.is_array() {
        *slot = json!([]);
    }
    slot.as_array_mut().expect("just ensured array")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd() -> String {
        hook_command("/abs/permcheck.json")
    }

    #[test]
    fn install_into_empty_creates_block() {
        let out = install(&json!({}), &cmd());
        let hooks = &out["hooks"]["PreToolUse"];
        assert_eq!(hooks.as_array().unwrap().len(), 1);
        assert_eq!(hooks[0]["matcher"], "*");
        assert_eq!(hooks[0]["hooks"][0]["type"], "command");
        assert!(is_permcheck_hook(
            hooks[0]["hooks"][0]["command"].as_str().unwrap()
        ));
    }

    #[test]
    fn install_is_a_fixed_point() {
        let once = install(&json!({}), &cmd());
        let twice = install(&once, &cmd());
        assert_eq!(once, twice);
    }

    #[test]
    fn reinstall_rewrites_changed_rules_path() {
        let first = install(&json!({}), &hook_command("/old.json"));
        let second = install(&first, &hook_command("/new.json"));
        // still exactly one permcheck entry, now pointing at /new.json
        let arr = second["hooks"]["PreToolUse"].as_array().unwrap();
        let count: usize = arr
            .iter()
            .flat_map(|g| g["hooks"].as_array().cloned().unwrap_or_default())
            .filter(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(is_permcheck_hook)
            })
            .count();
        assert_eq!(count, 1);
        assert!(second.to_string().contains("/new.json"));
        assert!(!second.to_string().contains("/old.json"));
    }

    #[test]
    fn installed_rules_path_reads_the_baked_path() {
        let out = install(&json!({}), &hook_command("/abs/permcheck.json"));
        assert_eq!(
            installed_rules_path(&out).as_deref(),
            Some("/abs/permcheck.json")
        );
        // A hand-wired hook writes the path bare; the guard must still see it,
        // otherwise `--install` would silently re-point exactly the hooks the
        // refusal exists to protect.
        assert_eq!(
            installed_rules_path(&json!({
                "hooks": { "PreToolUse": [
                    { "matcher": "*", "hooks": [
                        { "type": "command",
                          "command": "/opt/permcheck --hook --rules /etc/policy.json" }
                    ] }
                ] }
            }))
            .as_deref(),
            Some("/etc/policy.json")
        );
        // No permcheck hook → None.
        assert_eq!(installed_rules_path(&json!({})), None);
        assert_eq!(
            installed_rules_path(&json!({
                "hooks": { "PreToolUse": [
                    { "matcher": "Bash", "hooks": [
                        { "type": "command", "command": "my-own-linter" }
                    ] }
                ] }
            })),
            None
        );
    }

    #[test]
    fn install_preserves_unrelated_hook() {
        let existing = json!({
            "model": "opus",
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash", "hooks": [
                        { "type": "command", "command": "my-own-linter" }
                    ] }
                ]
            }
        });
        let out = install(&existing, &cmd());
        assert_eq!(out["model"], "opus");
        let s = out.to_string();
        assert!(s.contains("my-own-linter"));
        assert!(is_permcheck_present(&out));
    }

    #[test]
    fn uninstall_removes_only_permcheck_and_prunes() {
        let installed = install(&json!({}), &cmd());
        let out = uninstall(&installed);
        assert_eq!(out, json!({})); // hooks/PreToolUse pruned away
    }

    #[test]
    fn uninstall_keeps_unrelated_hook() {
        let existing = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [
                    { "type": "command", "command": "my-own-linter" }
                ] }
            ] }
        });
        let installed = install(&existing, &cmd());
        let out = uninstall(&installed);
        assert!(!is_permcheck_present(&out));
        assert!(out.to_string().contains("my-own-linter"));
    }

    #[test]
    fn uninstall_on_empty_is_noop() {
        assert_eq!(uninstall(&json!({})), json!({}));
    }

    #[test]
    fn command_quotes_rules_path() {
        let c = hook_command("/path with space/permcheck.json");
        assert!(c.contains("--rules \"/path with space/permcheck.json\""));
        // and it round-trips through JSON intact
        let v = json!({ "command": c });
        let s = v.to_string();
        let back: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(back["command"], json!(c));
    }

    #[test]
    fn windows_style_path_round_trips() {
        let c = hook_command(r"C:\Users\Jane Doe\.claude\permcheck.json");
        let v = install(&json!({}), &c);
        let s = serde_json::to_string_pretty(&v).unwrap();
        let back: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
        assert!(is_permcheck_present(&back));
    }

    fn is_permcheck_present(v: &Value) -> bool {
        v["hooks"]["PreToolUse"]
            .as_array()
            .map(|arr| {
                arr.iter().any(|g| {
                    g["hooks"].as_array().is_some_and(|inner| {
                        inner.iter().any(|h| {
                            h.get("command")
                                .and_then(Value::as_str)
                                .is_some_and(is_permcheck_hook)
                        })
                    })
                })
            })
            .unwrap_or(false)
    }
}
