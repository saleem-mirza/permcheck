use std::io::{IsTerminal, Read as IoRead};
use std::panic;
use std::path::PathBuf;
use std::process;

use permcheck::types::{Decision, Tier};
use permcheck::{evaluate, load_rules};

fn main() {
    // Silence backtraces in hook mode
    panic::set_hook(Box::new(|_| {}));

    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        process::exit(0);
    }

    if args.iter().any(|a| a == "--hook") {
        // --json is CLI-only; in hook mode it is silently ignored
        // (hook mode always emits JSON and always exits 0).
        run_hook(&args);
    } else {
        run_cli(&args);
    }
}

fn run_hook(args: &[String]) {
    let result = panic::catch_unwind(|| -> Decision {
        let rules_path = match find_rules_arg(args) {
            Some(p) => p,
            None => return Decision::deny_msg("--rules <path> is required"),
        };

        let rule_set = match load_rules(&rules_path) {
            Ok(rs) => rs,
            Err(e) => {
                return Decision::deny_msg(&format!("rules load error: {e}"));
            }
        };

        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .unwrap_or_default();

        let val: serde_json::Value = match serde_json::from_str(&input) {
            Ok(v) => v,
            Err(_) => return Decision::deny_msg("unparseable stdin"),
        };

        let tool = val.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");
        let empty = serde_json::Value::Object(serde_json::Map::new());
        let tool_input = val.get("tool_input").unwrap_or(&empty);
        let cwd = val.get("cwd").and_then(|v| v.as_str());

        if tool.is_empty() {
            return Decision::deny_msg("missing tool_name");
        }

        // `evaluate` already builds the canonical §2.1 reason.
        evaluate(&rule_set, tool, tool_input, cwd)
    });

    let decision = result.unwrap_or_else(|_| Decision::deny_msg("internal panic"));
    println!("{}", decision.to_hook_json());
    process::exit(0);
}

fn run_cli(args: &[String]) {
    // Usage: permcheck <Tool> [payload] --rules <path> [--json]
    let rules_path = match find_rules_arg(args) {
        Some(p) => p,
        None => {
            eprintln!("error: --rules <path> is required");
            process::exit(3);
        }
    };

    let json_mode = args.contains(&"--json".to_string());

    // Collect positional args (not --rules, its value, or --json)
    let positional: Vec<&str> = {
        let mut pos = Vec::new();
        let mut skip_next = false;
        for arg in args {
            if skip_next {
                skip_next = false;
                continue;
            }
            if arg == "--rules" {
                skip_next = true;
                continue;
            }
            if arg == "--json" {
                continue;
            }
            if arg.starts_with("--") {
                continue;
            }
            pos.push(arg.as_str());
        }
        pos
    };

    if positional.is_empty() {
        eprintln!("error: tool name required");
        process::exit(3);
    }

    let tool = positional[0];
    let payload = positional.get(1).copied().unwrap_or("");

    let rule_set = match load_rules(&rules_path) {
        Ok(rs) => rs,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(3);
        }
    };

    // Relative path payloads are absolutized against the process CWD in CLI mode (§7.2).
    let cwd = std::env::current_dir().ok();
    let cwd_str = cwd.as_deref().and_then(|p| p.to_str());

    // Build a minimal tool_input for the payload
    let tool_input = build_tool_input(tool, payload);
    // `evaluate` already builds the canonical §2.1 reason.
    let decision = evaluate(&rule_set, tool, &tool_input, cwd_str);

    if json_mode {
        println!("{}", decision.to_hook_json_pretty());
        process::exit(0);
    } else {
        match decision.tier {
            Tier::Allow => {} // silent — the caller proceeds to execute
            _ => eprintln!("{}", decision.reason),
        }
        process::exit(decision.to_exit_code());
    }
}

fn print_help() {
    // Respect NO_COLOR (https://no-color.org), require a non-dumb TERM, and only
    // emit ANSI when stderr is an actual terminal (not a pipe or file).
    let color = std::env::var("NO_COLOR").is_err()
        && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(false)
        && std::io::stderr().is_terminal();

    // ANSI helpers — empty strings when color is off.
    let bold = if color { "\x1b[1m" } else { "" };
    let yellow = if color { "\x1b[1;33m" } else { "" };
    let cyan = if color { "\x1b[1;36m" } else { "" };
    let green = if color { "\x1b[1;32m" } else { "" };
    let red = if color { "\x1b[1;31m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };

    eprintln!(
        r#"{bold}permcheck{reset} — permission decision engine for Claude Code PreToolUse hooks

{yellow}USAGE{reset}
  permcheck {green}<Tool>{reset} {green}<payload>{reset} --rules <path> [--json]   check one call (manual)
  permcheck {cyan}--hook{reset} --rules <path>                          hook mode: event JSON on stdin

{yellow}ARGUMENTS{reset}
  {green}<Tool>{reset}      Exact Claude Code tool name: Bash, Read, Write, Edit, WebFetch, WebSearch, mcp__db__query, …
  {green}<payload>{reset}   The tool's real input — {red}not a rule specifier{reset}. By tool:
            {cyan}Bash{reset}              → shell command    {green}"aws s3 ls"{reset}
            {cyan}Read/Write/Edit{reset}   → file path        {green}"/home/user/.env"{reset}
            {cyan}WebFetch{reset}          → URL              {green}"https://example.com"{reset}
            {cyan}WebSearch{reset}         → search query     {green}"rust async"{reset}

{yellow}OPTIONS{reset}
  {cyan}--rules{reset} <path>   Permissions JSON file {bold}(required){reset}. Reference: rules/permissions.json
  {cyan}--json{reset}           {red}(CLI mode only){reset} Print the hook-format JSON decision instead of using the exit code.
  {cyan}--hook{reset}           Read a PreToolUse event on stdin, write decision JSON, always exit 0.
  {cyan}-h, --help{reset}       Show this help.

{yellow}EXIT CODES{reset}  (CLI mode)  {green}0 allow{reset} · {yellow}1 ask{reset} · {red}2 deny{reset} · 3 config error
  Hook mode always exits 0 — the decision travels in the JSON output.

{yellow}EXAMPLES{reset}
  permcheck Bash {green}"aws ec2 describe-instances"{reset} --rules rules/permissions.json    # allow
  permcheck Bash {green}"kubectl delete pod x"{reset}       --rules rules/permissions.json    # deny
  permcheck Read {green}"/home/user/.ssh/id_rsa"{reset}     --rules rules/permissions.json    # deny
  echo '{{…}}' | permcheck {cyan}--hook{reset}               --rules rules/permissions.json    # hook

{yellow}NOTE{reset}  A specifier like {red}"aws:*"{reset} is a rule pattern, not a payload — passing it checks the
      literal command "aws:*" (which default-denies). Pass a real command instead."#,
        bold = bold,
        yellow = yellow,
        cyan = cyan,
        green = green,
        red = red,
        reset = reset,
    );
}

/// Find the `--rules` value in either form: `--rules <path>` or `--rules=<path>`.
fn find_rules_arg(args: &[String]) -> Option<PathBuf> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(path) = arg.strip_prefix("--rules=") {
            return Some(PathBuf::from(path));
        }
        if arg == "--rules" {
            return iter.next().map(PathBuf::from);
        }
    }
    None
}

fn build_tool_input(tool: &str, payload: &str) -> serde_json::Value {
    use serde_json::json;
    match tool {
        "Bash" => json!({"command": payload}),
        "Read" | "Write" | "Edit" => json!({"file_path": payload}),
        "NotebookEdit" => json!({"notebook_path": payload}),
        "Glob" | "Grep" => json!({"path": payload}),
        "WebFetch" => json!({"url": payload}),
        "WebSearch" => json!({"query": payload}),
        "SlashCommand" => json!({"command": payload}),
        _ => {
            // Generic: put payload as first field
            if payload.is_empty() {
                json!({})
            } else {
                json!({"input": payload})
            }
        }
    }
}
