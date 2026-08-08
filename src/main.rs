use std::io::{IsTerminal, Read as IoRead, Write as IoWrite};
use std::panic;
use std::path::{Path, PathBuf};
use std::process;

use permcheck::types::{Decision, Tier};
use permcheck::{evaluate, evaluate_payload, load_rules, settings};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Mode selection reads only the leading flags, never the payload (§2.2).
    let modes = mode_args(&args);

    if modes.iter().any(|a| a == "-V" || a == "--version") {
        println!("permcheck {}", env!("CARGO_PKG_VERSION"));
        process::exit(0);
    }

    // Help is requested output, so stdout and exit 0. No arguments is a usage
    // error: exiting 0 would read as an `allow` to anything checking exit codes.
    if modes.iter().any(|a| a == "-h" || a == "--help") {
        println!("{}", help_text(std::io::stdout().is_terminal()));
        process::exit(0);
    }
    if args.is_empty() {
        eprintln!("{}", help_text(std::io::stderr().is_terminal()));
        process::exit(3);
    }

    let install = modes.iter().any(|a| a == "--install");
    let uninstall = modes.iter().any(|a| a == "--uninstall");
    let init_rules = modes.iter().any(|a| a == "--init-rules");
    if [install, uninstall, init_rules]
        .iter()
        .filter(|b| **b)
        .count()
        > 1
    {
        eprintln!("error: --install, --uninstall, and --init-rules are mutually exclusive");
        process::exit(3);
    }
    if init_rules {
        run_init_rules(&args);
    } else if install {
        run_install(&args);
    } else if uninstall {
        run_uninstall(&args);
    } else if modes.iter().any(|a| a == "--hook") {
        // --json is CLI-only; in hook mode it is silently ignored
        // (hook mode always emits JSON and always exits 0).
        // Silence panic output; `run_hook` converts the panic itself to deny.
        panic::set_hook(Box::new(|_| {}));
        run_hook(&args);
    } else {
        run_cli(&args);
    }
}

/// The leading arguments that select a mode: everything before the first
/// positional (and before an explicit `--`).
///
/// In check mode the first positional is the tool name, so anything after it is
/// the payload being checked, not a request to change what permcheck does.
/// Without that cut, `permcheck Bash "--install" --rules <file>` scanned the
/// whole argument vector, matched `--install`, and performed a real install:
/// wiring the hook and seeding a policy while the caller believed it was
/// checking a command string. The CLI exists to check arbitrary, potentially
/// hostile payloads, which is exactly where such a string arrives.
///
/// A value-taking flag consumes the token after it, so that token is not the
/// first positional. [`flag_value`] uses the same rule, so the two agree on
/// where the flags end.
fn mode_args(args: &[String]) -> &[String] {
    const VALUE_FLAGS: [&str; 2] = ["--rules", "--init-rules"];
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        if arg == "--" || !arg.starts_with('-') {
            break;
        }
        i += 1;
        if VALUE_FLAGS.contains(&arg.as_str())
            && args.get(i).is_some_and(|next| !next.starts_with("--"))
        {
            i += 1;
        }
    }
    &args[..i]
}

/// Where a settings file lives, selected by the scope flags.
#[derive(Clone, Copy)]
enum Scope {
    User,
    Project,
    Local,
}

/// Resolve the scope from `--user` / `--project` / `--local` (default: user).
/// Multiple scope flags are an error.
fn scope_from_args(args: &[String]) -> Scope {
    let user = args.iter().any(|a| a == "--user");
    let project = args.iter().any(|a| a == "--project");
    let local = args.iter().any(|a| a == "--local");
    match (user, project, local) {
        (_, false, false) => Scope::User, // default, or explicit --user
        (false, true, false) => Scope::Project,
        (false, false, true) => Scope::Local,
        _ => {
            eprintln!("error: choose at most one of --user, --project, --local");
            process::exit(3);
        }
    }
}

/// The user's home directory. Resolution is platform-specific and lives in
/// [`permcheck::matcher::raw_home`], shared with `~` expansion so the install
/// path and a `~/…` rule cannot resolve differently.
fn home_dir() -> Option<PathBuf> {
    permcheck::matcher::raw_home().map(PathBuf::from)
}

/// The `settings.json` path for a scope. `.claude/` is joined with `PathBuf` so
/// separators are correct on every OS.
fn settings_path(scope: Scope) -> Option<PathBuf> {
    let (base, file): (PathBuf, &str) = match scope {
        Scope::User => (home_dir()?, "settings.json"),
        Scope::Project => (PathBuf::from("."), "settings.json"),
        Scope::Local => (PathBuf::from("."), "settings.local.json"),
    };
    Some(base.join(".claude").join(file))
}

/// The canonical rules-file path for a scope — next to that scope's settings
/// file, so `--install` can seed/copy the policy into a predictable location.
/// Local uses a `.local` variant, mirroring `settings.local.json`, so it never
/// collides with a project-scope `permcheck.json` in the same repo.
fn rules_dest_path(scope: Scope) -> Option<PathBuf> {
    let (base, file): (PathBuf, &str) = match scope {
        Scope::User => (home_dir()?, "permcheck.json"),
        Scope::Project => (PathBuf::from("."), "permcheck.json"),
        Scope::Local => (PathBuf::from("."), "permcheck.local.json"),
    };
    Some(base.join(".claude").join(file))
}

/// Sibling temp path for an atomic write, unique per process so concurrent
/// `--install` runs cannot clobber each other's scratch file.
fn temp_path(path: &Path) -> PathBuf {
    path.with_extension(format!("json.permcheck-tmp.{}", process::id()))
}

/// Write `bytes` to `path` atomically: temp file, `sync_all`, then `rename`
/// (atomic-replace on Unix and Windows). The flush matters because `rename`
/// orders the directory entry, not the contents. Cleans up the temp on failure.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = temp_path(path);

    let write = || -> std::io::Result<()> {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Serialize `value` as pretty JSON and write it atomically.
fn write_json_atomic(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
    text.push('\n');
    write_atomic(path, text.as_bytes())
}

/// Write `bytes` to `path` only when nothing is there yet, returning
/// [`std::io::ErrorKind::AlreadyExists`] otherwise.
///
/// The policy writers want "create, never replace", and asking `exists()` first
/// and then writing does not give them that: the answer is stale the moment it
/// returns, so a file appearing in the gap gets overwritten by the write that
/// follows. `create_new` puts the test and the creation in one syscall, which is
/// the only way the check binds. Every caller here is a create-if-absent path, so
/// none of them wants [`write_atomic`]'s replacing `rename`; that one stays for
/// `settings.json`, where replacing in place is the point.
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Serialize `value` as pretty JSON and write it only if `path` is free.
fn write_json_new(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
    text.push('\n');
    write_new(path, text.as_bytes())
}

/// Copy `src` to `dest`, refusing to replace an existing `dest`. Policy files are
/// small, so reading into memory keeps this on the single write path.
fn copy_rules_new(src: &Path, dest: &Path) -> std::io::Result<()> {
    let bytes = std::fs::read(src)?;
    write_new(dest, &bytes)
}

fn run_install(args: &[String]) {
    let scope = scope_from_args(args);
    let Some(path) = settings_path(scope) else {
        eprintln!("error: cannot resolve home directory (set HOME or USERPROFILE)");
        process::exit(3);
    };
    let Some(dest) = rules_dest_path(scope) else {
        eprintln!("error: cannot resolve home directory (set HOME or USERPROFILE)");
        process::exit(3);
    };
    // Absolute form baked into the hook command — a path in settings.json must
    // resolve regardless of the hook's working directory.
    let dest_abs = match std::path::absolute(&dest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot resolve rules destination: {e}");
            process::exit(3);
        }
    };
    // Validate the destination is UTF-8 *before* touching the filesystem, so a
    // non-UTF-8 path aborts without orphaning a half-written rules file.
    let Some(dest_str) = dest_abs.to_str() else {
        eprintln!("error: rules path is not valid UTF-8");
        process::exit(3);
    };

    // Resolve the rules source. A bare `--rules` with no value (or one followed
    // by a flag) is a usage error, not a request to auto-seed a starter.
    let rules_arg = find_rules_arg(args);
    if rules_arg.is_none() && args.iter().any(|a| a == "--rules") {
        eprintln!("error: --rules requires a path");
        process::exit(3);
    }

    let existing = match read_settings(&path) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("error: {msg}");
            process::exit(3);
        }
    };

    // Refuse to silently re-point an existing hook away from a non-canonical
    // rules path — completing the install would abandon whatever policy that
    // hook currently references. (A hook already pointing at `dest` is a no-op.)
    if let Some(old) = settings::installed_rules_path(&existing)
        && old != dest_str
    {
        eprintln!(
            "error: an existing permcheck hook points at {old}; refusing to silently re-point it to {dest_str}"
        );
        eprintln!("hint: run `permcheck --uninstall [scope]` first, then re-install");
        process::exit(3);
    }

    // Land the canonical rules file at `dest` *before* touching settings.json,
    // and never overwrite an existing one (avoid clobbering user edits). Each of
    // these aborts the whole install (exit 3) on error or conflict.
    match rules_arg {
        Some(rules_path) => install_copy_rules(&rules_path, &dest_abs),
        None => install_seed_rules(&dest_abs),
    }

    let command = settings::hook_command(dest_str);
    let out = settings::install(&existing, &command);

    if out == existing && path.exists() {
        println!(
            "permcheck already configured → {}  (rules → {})",
            path.display(),
            dest_abs.display()
        );
        process::exit(0);
    }
    if let Err(e) = write_json_atomic(&path, &out) {
        eprintln!("error: cannot write {}: {e}", path.display());
        process::exit(3);
    }
    println!("Installed permcheck PreToolUse hook → {}", path.display());
    process::exit(0);
}

/// Copy mode for `--install --rules <src>`: land the policy file at the canonical
/// `dest`. Validates `src` loads, and refuses to overwrite an existing `dest`
/// whose content differs (an identical `dest` is a no-op). Aborts on error.
fn install_copy_rules(src: &Path, dest: &Path) {
    // Absolutize + validate the source — a broken rules file would deny everything.
    let abs_src = match std::path::absolute(src) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot resolve rules path: {e}");
            process::exit(3);
        }
    };
    match load_rules(&abs_src) {
        Ok(rs) => print_lint_warnings(&rs),
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!(
                "hint: create a starter rules file with `permcheck --init-rules {}`",
                abs_src.display()
            );
            process::exit(3);
        }
    }

    // The source already *is* the canonical file — nothing to copy.
    if abs_src == dest {
        return;
    }

    match std::fs::read(dest) {
        // `dest` already exists: only proceed if it is byte-identical, else refuse
        // — never silently clobber a policy the user may have edited.
        Ok(existing) => {
            let incoming = match std::fs::read(&abs_src) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: cannot read {}: {e}", abs_src.display());
                    process::exit(3);
                }
            };
            if existing == incoming {
                return; // identical — idempotent, no write
            }
            eprintln!(
                "error: {} exists and differs from {}; remove it or edit it in place to change policy",
                dest.display(),
                abs_src.display()
            );
            process::exit(3);
        }
        // `dest` was free a moment ago. The write below still refuses to replace,
        // so a file that lands in between is reported rather than clobbered.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match copy_rules_new(&abs_src, dest) {
                Ok(()) => println!("Copied rules → {}", dest.display()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    eprintln!(
                        "error: {} was created while this install was running; re-run to compare it against {}",
                        dest.display(),
                        abs_src.display()
                    );
                    process::exit(3);
                }
                Err(e) => {
                    eprintln!("error: cannot write {}: {e}", dest.display());
                    process::exit(3);
                }
            }
        }
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", dest.display());
            process::exit(3);
        }
    }
}

/// Auto-seed mode for `--install` with no `--rules`: reuse an existing canonical
/// rules file (never overwrite it), or write a fresh starter. Aborts on error or
/// a broken existing file (a broken policy must not be wired).
fn install_seed_rules(dest: &Path) {
    if dest.exists() {
        match load_rules(dest) {
            Ok(rs) => print_lint_warnings(&rs),
            Err(e) => {
                eprintln!(
                    "error: existing rules file {} does not load: {e}",
                    dest.display()
                );
                process::exit(3);
            }
        }
        println!("Using existing rules → {}", dest.display());
        return;
    }
    // `dest` was free a moment ago; the write still refuses to replace, so a file
    // that lands in between is adopted rather than overwritten.
    let rules = permcheck::rules::starter_rules();
    match write_json_new(dest, &rules) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!(
                "error: {} was created while this install was running; re-run to use it",
                dest.display()
            );
            process::exit(3);
        }
        Err(e) => {
            eprintln!("error: cannot write {}: {e}", dest.display());
            process::exit(3);
        }
    }
    // The file we just wrote must load — a broken starter would deny everything.
    if let Err(e) = load_rules(dest) {
        eprintln!("error: wrote an invalid rules file ({e})");
        process::exit(3);
    }
    println!("Wrote starter rules → {}", dest.display());
}

/// Write a starter rules file: the minimal safe `deny` list, `defaultMode`
/// `ask`, and empty `allow`/`ask`. Refuses to overwrite an existing file.
fn run_init_rules(args: &[String]) {
    // The path is optional; default to `permcheck.json` in the current directory.
    let path = init_rules_path(args).unwrap_or_else(|| PathBuf::from("permcheck.json"));

    // The refusal is the write itself, not a preceding `exists()`: that answer is
    // stale by the time the write runs, and a file created in the gap would be
    // overwritten by the very call meant to protect it.
    let rules = permcheck::rules::starter_rules();
    match write_json_new(&path, &rules) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!(
                "error: refusing to overwrite existing file {}",
                path.display()
            );
            process::exit(3);
        }
        Err(e) => {
            eprintln!("error: cannot write {}: {e}", path.display());
            process::exit(3);
        }
    }
    // The file we just wrote must load — a broken starter would deny everything.
    if let Err(e) = load_rules(&path) {
        eprintln!("error: wrote an invalid rules file ({e})");
        process::exit(3);
    }

    println!("Wrote starter rules → {}", path.display());
    println!("  next: permcheck --install --rules {}", path.display());
    process::exit(0);
}

fn run_uninstall(args: &[String]) {
    let scope = scope_from_args(args);
    let Some(path) = settings_path(scope) else {
        eprintln!("error: cannot resolve home directory (set HOME or USERPROFILE)");
        process::exit(3);
    };

    if !path.exists() {
        println!("nothing to uninstall ({} does not exist)", path.display());
        process::exit(0);
    }

    let existing = match read_settings(&path) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("error: {msg}");
            process::exit(3);
        }
    };

    let out = settings::uninstall(&existing);
    if out == existing {
        println!("no permcheck hook found in {}", path.display());
        process::exit(0);
    }
    if let Err(e) = write_json_atomic(&path, &out) {
        eprintln!("error: cannot write {}: {e}", path.display());
        process::exit(3);
    }
    println!("Removed permcheck PreToolUse hook → {}", path.display());
    process::exit(0);
}

/// Read and parse a settings file into a JSON object. A missing or empty file is
/// an empty object; a present-but-non-object file is refused (so we never clobber
/// an unexpected structure).
fn read_settings(path: &Path) -> Result<serde_json::Value, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(serde_json::json!({})),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    if text.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("invalid JSON in {}: {e}", path.display()))?;
    if !value.is_object() {
        return Err(format!("{} is not a JSON object", path.display()));
    }
    Ok(value)
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

    // Write through a locked handle rather than `println!`: that macro panics on
    // a write error, and this sits outside the `catch_unwind` above, so a stdout
    // whose reader is gone exited 101 with no decision — which Claude Code reads
    // as a non-blocking error and lets the tool call through. That was the one
    // path where the hook failed open. (`std` reports EBADF on stdout as success,
    // so the reachable failure is a broken pipe, not a closed descriptor.)
    //
    // An undeliverable decision falls back to the exit-code channel: exit 2 is a
    // blocking error, so the call is stopped rather than waved through (§9.1).
    // Nothing else is worth attempting here; stderr may be just as broken.
    let mut out = std::io::stdout().lock();
    if writeln!(out, "{}", decision.to_hook_json())
        .and_then(|()| out.flush())
        .is_err()
    {
        process::exit(2);
    }
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

    let json_mode = args.iter().any(|a| a == "--json");

    // Positional args (not --rules, its value, or --json). An unrecognized long
    // flag is a usage error: silently skipping `--jsn` would drop the caller into
    // exit-code mode with no hint. A bare `--` ends option parsing, so a payload
    // that looks like a flag stays checkable (`permcheck Bash --rules r -- --install`).
    let positional: Vec<&str> = {
        let mut pos = Vec::new();
        let mut skip_next = false;
        let mut end_of_options = false;
        for arg in args {
            if skip_next {
                skip_next = false;
                continue;
            }
            if !end_of_options {
                if arg == "--" {
                    end_of_options = true;
                    continue;
                }
                if arg == "--rules" {
                    skip_next = true;
                    continue;
                }
                if arg == "--json" {
                    continue;
                }
                if let Some(flag) = arg.strip_prefix("--") {
                    // `--rules=<path>` is consumed by `find_rules_arg` above.
                    if flag.starts_with("rules=") {
                        continue;
                    }
                    eprintln!("error: unrecognized option `{arg}`");
                    eprintln!("hint: run `permcheck --help` for usage");
                    process::exit(3);
                }
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
    print_lint_warnings(&rule_set);

    // Relative path payloads are absolutized against the process CWD in CLI mode (§7.2).
    let cwd = std::env::current_dir().ok();
    let cwd_str = cwd.as_deref().and_then(|p| p.to_str());

    let decision = evaluate_payload(&rule_set, tool, payload, cwd_str);

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

/// Render the help screen. `is_tty` is whether the stream it is headed for is a
/// terminal, which (with NO_COLOR and TERM) decides whether ANSI is emitted.
fn help_text(is_tty: bool) -> String {
    // Respect NO_COLOR (https://no-color.org), require a non-dumb TERM, and only
    // emit ANSI when the destination is an actual terminal (not a pipe or file).
    let color = std::env::var("NO_COLOR").is_err()
        && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(false)
        && is_tty;

    // ANSI helpers — empty strings when color is off.
    let bold = if color { "\x1b[1m" } else { "" };
    let yellow = if color { "\x1b[1;33m" } else { "" };
    let cyan = if color { "\x1b[1;36m" } else { "" };
    let green = if color { "\x1b[1;32m" } else { "" };
    let red = if color { "\x1b[1;31m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };

    format!(
        r#"{bold}permcheck{reset} — permission decision engine for Claude Code PreToolUse hooks

{yellow}USAGE{reset}
  permcheck {green}<Tool>{reset} {green}<payload>{reset} --rules <path> [--json]   check one call (manual)
  permcheck {cyan}--hook{reset} --rules <path>                          hook mode: event JSON on stdin
  permcheck {cyan}--init-rules{reset} [path]                           write a secure starter rules file (default: permcheck.json)
  permcheck {cyan}--install{reset} [--rules <path>] [scope]            seed/copy rules under .claude and wire the hook
  permcheck {cyan}--uninstall{reset} [scope]                           remove the hook from settings.json

{yellow}ARGUMENTS{reset}
  {green}<Tool>{reset}      Exact Claude Code tool name: Bash, Read, Write, Edit, WebFetch, WebSearch, mcp__db__query, …
  {green}<payload>{reset}   The tool's real input — {red}not a rule specifier{reset}. By tool:
            {cyan}Bash{reset}              → shell command    {green}"aws s3 ls"{reset}
            {cyan}Read/Write/Edit{reset}   → file path        {green}"/home/user/.env"{reset}
            {cyan}WebFetch{reset}          → URL              {green}"https://example.com"{reset}
            {cyan}WebSearch{reset}         → search query     {green}"rust async"{reset}

{yellow}OPTIONS{reset}
  {cyan}--rules{reset} <path>   Permissions JSON file {bold}(required){reset}. Reference: rules/permcheck.json
  {cyan}--json{reset}           {red}(CLI mode only){reset} Print the hook-format JSON decision instead of using the exit code.
  {cyan}--hook{reset}           Read a PreToolUse event on stdin, write decision JSON, always exit 0.
  {cyan}--init-rules{reset} [path]  Write a starter rules file (path defaults to permcheck.json): a minimal safe deny list (sudo, rm -rf, secret reads, force-push) plus self-protection, empty allow/ask, defaultMode ask. Refuses to overwrite.
  {cyan}--install{reset}        Wire the PreToolUse hook into settings.json. With {cyan}--rules{reset} <path>, copies that file to the canonical location under .claude/; without it, writes a starter there. Never overwrites an existing rules file, and refuses to re-point a hook that already targets a different rules path (uninstall first).
  {cyan}--uninstall{reset}      Idempotently remove the permcheck PreToolUse hook from settings.json.
  {cyan}-h, --help{reset}       Show this help.
  {cyan}-V, --version{reset}    Print the version and exit.

{yellow}INSTALL SCOPE{reset}  (for --install / --uninstall; default {green}--user{reset})
  {cyan}--user{reset}      ~/.claude/settings.json          machine-wide (default)
  {cyan}--project{reset}   ./.claude/settings.json          committed, team-shared
  {cyan}--local{reset}     ./.claude/settings.local.json    this checkout only

{yellow}EXIT CODES{reset}  (CLI mode)  {green}0 allow{reset} · {yellow}1 ask{reset} · {red}2 deny{reset} · 3 config error
  Hook mode always exits 0 — the decision travels in the JSON output.

{yellow}EXAMPLES{reset}
  permcheck Bash {green}"aws ec2 describe-instances"{reset} --rules rules/permcheck.json    # allow
  permcheck Bash {green}"kubectl delete pod x"{reset}       --rules rules/permcheck.json    # deny
  permcheck Read {green}"/home/user/.ssh/id_rsa"{reset}     --rules rules/permcheck.json    # deny
  echo '{{…}}' | permcheck {cyan}--hook{reset}               --rules rules/permcheck.json    # hook

{yellow}NOTE{reset}  A specifier like {red}"aws:*"{reset} is a rule pattern, not a payload — passing it checks the
      literal command "aws:*" (which default-denies). Pass a real command instead."#
    )
}

/// The path argument for `--init-rules`, in either form: `--init-rules <path>`
/// or `--init-rules=<path>`.
fn init_rules_path(args: &[String]) -> Option<PathBuf> {
    flag_value(args, "--init-rules")
}

/// Find the `--rules` value in either form: `--rules <path>` or `--rules=<path>`.
fn find_rules_arg(args: &[String]) -> Option<PathBuf> {
    flag_value(args, "--rules")
}

/// The value of a path-taking flag, in either `--flag=<path>` or `--flag <path>`
/// form. A following flag (or nothing) means no value: the next token is not
/// swallowed as the path, so callers see a dangling flag and error rather than
/// silently seeding. Scanning stops at a bare `--`, so a payload after it is
/// never mistaken for a flag.
fn flag_value(args: &[String], flag: &str) -> Option<PathBuf> {
    let eq_prefix = format!("{flag}=");
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            return None;
        }
        if let Some(path) = arg.strip_prefix(&eq_prefix) {
            return Some(PathBuf::from(path));
        }
        if arg == flag {
            return iter
                .next()
                .filter(|a| !a.starts_with("--"))
                .map(PathBuf::from);
        }
    }
    None
}

/// Print author-time lint warnings to stderr (never stdout, which carries the
/// hook JSON). Called from the CLI-check and `--install` paths, never in hook
/// mode, where a per-call warning would spam the logs.
fn print_lint_warnings(rs: &permcheck::RuleSet) {
    for w in rs.lint_warnings() {
        eprintln!("warning: {w}");
    }
}
