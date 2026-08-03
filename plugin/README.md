# permcheck: Claude Code plugin

Runs [permcheck](https://github.com/saleem-mirza/permcheck), a specificity-aware
permission engine, as a **PreToolUse hook**: every tool call (Bash,
Read/Write/Edit, WebFetch/WebSearch, MCP, …) is decided `allow`, `ask`, or `deny`
before it runs. For what permcheck is, how it decides, and use cases, see the
[main README](https://github.com/saleem-mirza/permcheck#readme) and
[SPEC](https://github.com/saleem-mirza/permcheck/blob/main/specs/SPEC.md).

## Install

From the marketplace:

```sh
/plugin marketplace add saleem-mirza/marketplace
/plugin install permcheck@zethian
```

The plugin is served from the dedicated
[`saleem-mirza/marketplace`](https://github.com/saleem-mirza/marketplace) repo, a
source-free bundle of only the catalog, hook, rules, and prebuilt binaries, so nothing
pulls the Rust source onto your machine, and once fetched the plugin runs offline.

For local development, point Claude Code straight at this directory:

```sh
claude --plugin-dir /path/to/permcheck/plugin
```

Then ask Claude to run `python3 -m http.server` (blocked) versus
`python3 script.py` (allowed). `/plugin` confirms it loaded.

## How it activates (no `settings.json` edit)

Enabling the plugin **automatically** makes permcheck your `PreToolUse` permission
engine, functionally identical to a `PreToolUse` hook in `settings.json`, but with
nothing to hand-wire:

- Claude Code loads `hooks/hooks.json` and runs the hook on **every** tool call the
  moment the plugin is enabled. Your `settings.json` is **not** modified, and the
  plugin is only recorded under `enabledPlugins`.
- Run `/hooks` to see it, labeled with source **`Plugin`**.
- It **merges with** (doesn't replace) any existing PreToolUse hooks, and across
  hooks a `deny` wins.
- To turn it off, disable or uninstall the plugin via `/plugin`. There is nothing to
  unpick from `settings.json`.

## Configuring rules

The hook decides against a JSON rule file, resolved first-hit-wins:

1. `$PERMCHECK_RULES`: an absolute path you set.
2. `<project>/.permcheck/rules.json`: per-project rules (via
   `$CLAUDE_PROJECT_DIR`).
3. The bundled default `rules/permcheck.json` (the canonical reference set).

> **Every entry in that list is a policy source, so every entry needs protecting.**
> Whoever can write `.permcheck/rules.json` sets the policy for the next tool
> call, and whoever can set `$PERMCHECK_RULES` in the hook's environment picks the
> file outright. The bundled rules deny `Write`/`Edit` on `.permcheck/**` and on
> the `.claude/` policy and settings files for this reason; if you replace them
> with your own, carry those denies over. The environment is outside what a rule
> can reach, so treat it as trusted input like the rule file itself.

For the rule grammar and matching semantics, see the
[main README](https://github.com/saleem-mirza/permcheck#rules) and
[SPEC](https://github.com/saleem-mirza/permcheck/blob/main/specs/SPEC.md).

## Platforms

`hooks/hooks.json` wires `hooks/permcheck-hook.sh`, which selects a prebuilt
binary from `bin/` by OS/arch. Five binaries ship, matching the release matrix:

| Platform | Binary |
|---|---|
| macOS (Apple silicon / Intel) | `permcheck-darwin-arm64` · `permcheck-darwin-x64` |
| Linux (x64 / arm64, static musl) | `permcheck-linux-x64` · `permcheck-linux-arm64` |
| Windows (x64; ARM runs it emulated) | `permcheck-windows-x64.exe` |

`hooks/permcheck-hook.cmd` mirrors the wrapper for native `cmd.exe`. It is **not**
wired by `hooks.json`, which runs the POSIX wrapper: on Windows that needs a `sh`
on `PATH` (git-bash ships one). Point a hook at the `.cmd` yourself if you have no
`sh`.

If no binary matches the platform, the hook **fails open** (emits no decision, so
Claude Code uses its normal permission flow) rather than blocking every call. To
make a missing binary strict-`deny` instead, change the wrapper's final fallback.
