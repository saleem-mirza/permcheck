# permcheck — Claude Code plugin

Runs [permcheck](https://github.com/saleem-mirza/permcheck) — a specificity-aware
permission engine — as a **PreToolUse hook**: every tool call (Bash,
Read/Write/Edit, WebFetch/WebSearch, MCP, …) is decided `allow`, `ask`, or `deny`
before it runs. For what permcheck is, how it decides, and use cases, see the
[main README](https://github.com/saleem-mirza/permcheck#readme) and
[SPEC](https://github.com/saleem-mirza/permcheck/blob/main/specs/SPEC.md).

## Install

From the marketplace:

```sh
/plugin marketplace add saleem-mirza/permcheck
/plugin install permcheck@zethian
```

The prebuilt binaries are served from the `plugin-dist` branch, so once fetched the
plugin runs offline.

For local development, point Claude Code straight at this directory:

```sh
claude --plugin-dir /path/to/permcheck/plugin
```

Then ask Claude to run `python3 -m http.server` (blocked) versus
`python3 script.py` (allowed); `/plugin` confirms it loaded.

## How it activates (no `settings.json` edit)

Enabling the plugin **automatically** makes permcheck your `PreToolUse` permission
engine — functionally identical to a `PreToolUse` hook in `settings.json`, but with
nothing to hand-wire:

- Claude Code loads `hooks/hooks.json` and runs the hook on **every** tool call the
  moment the plugin is enabled. Your `settings.json` is **not** modified — the
  plugin is only recorded under `enabledPlugins`.
- Run `/hooks` to see it, labeled with source **`Plugin`**.
- It **merges with** (doesn't replace) any existing PreToolUse hooks, and across
  hooks a `deny` wins.
- To turn it off, disable or uninstall the plugin via `/plugin`; there is nothing to
  unpick from `settings.json`.

## Configuring rules

The hook decides against a JSON rule file, resolved first-hit-wins:

1. `$PERMCHECK_RULES` — an absolute path you set.
2. `<project>/.permcheck/permissions.json` — per-project rules (via
   `$CLAUDE_PROJECT_DIR`).
3. The bundled default `rules/permissions.json` (the canonical reference set).

For the rule grammar and matching semantics, see the
[main README](https://github.com/saleem-mirza/permcheck#rules) and
[SPEC](https://github.com/saleem-mirza/permcheck/blob/main/specs/SPEC.md).

## Platforms

`hooks/permcheck-hook.sh` (POSIX) — plus `hooks/permcheck-hook.cmd` for native
Windows `cmd.exe` — selects a prebuilt binary from `bin/` by OS/arch:
`permcheck-{darwin,linux,windows}-{arm64,x64}`. macOS, Linux, and
Windows-under-git-bash are handled by the shell wrapper.

If no binary matches the platform, the hook **fails open** (emits no decision, so
Claude Code uses its normal permission flow) rather than blocking every call. To
make a missing binary strict-`deny` instead, change the wrapper's final fallback.
