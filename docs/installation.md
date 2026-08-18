# Installation

permcheck decides `allow`, `ask`, or `deny` for each Claude Code tool call against a rules file you provide. There are three ways to wire it into Claude Code.

The plugin is the recommended path. The marketplace package includes prebuilt binaries for macOS, Linux, and Windows and registers the hook without editing your `settings.json`.

## Plugin

```sh
/plugin marketplace add saleem-mirza/marketplace
/plugin install permcheck@zethian
```

The plugin is served from [`saleem-mirza/marketplace`](https://github.com/saleem-mirza/marketplace), a distribution repo that contains the catalog, hooks, rules, and prebuilt binaries.

After install:

- The hook runs on every tool call while the plugin is enabled.
- Your `settings.json` is not modified, except for Claude Code recording the enabled plugin.
- The hook appears in `/hooks` with source `Plugin`.
- Existing `PreToolUse` hooks still run. A `deny` from any hook wins.
- To turn it off, disable or uninstall the plugin with `/plugin`.

The marketplace plugin decides against its bundled `rules/permcheck.json`. This source repo keeps the reference copy at [`rules/permcheck.json`](../rules/permcheck.json). See [`plugin/README.md`](../plugin/README.md) for per-project rule overrides, local development with `--plugin-dir`, and platform notes.

## Standalone CLI With `--install`

Install the standalone CLI with Homebrew:

```sh
brew install saleem-mirza/tap/permcheck
```

Or build it yourself:

```sh
cargo build --release
```

Then wire the hook:

```sh
permcheck --install [--rules <path>] [--user|--project|--local]
permcheck --uninstall [--user|--project|--local]
```

Scope controls which Claude Code settings file is updated:

| Scope | Settings file | Rules file |
| --- | --- | --- |
| `--user` (default) | `~/.claude/settings.json` | `~/.claude/permcheck.json` |
| `--project` | `./.claude/settings.json` | `./.claude/permcheck.json` |
| `--local` | `./.claude/settings.local.json` | `./.claude/permcheck.local.json` |

With no `--rules`, `--install` writes a starter policy at the canonical rules path. With `--rules <path>`, it validates that policy and copies it into place. It refuses to overwrite an existing rules file with different content.

Examples:

```sh
permcheck --install
permcheck --install --rules rules/permcheck.json
permcheck --install --project
permcheck --uninstall
```

`--install` is idempotent. Re-running it updates the existing permcheck hook entry instead of duplicating it. If a previous hook points to a non-canonical rules path, `--install` refuses rather than silently abandoning that policy. Run `--uninstall` first, then install again.

`--install` creates the target `.claude/` directory and `settings.json` if needed. If `settings.json` exists but is invalid JSON, it exits with an error instead of writing.

When no settings file exists, the generated file is minimal:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "permcheck --hook --rules \"<abs path to your rules file>\""
          }
        ]
      }
    ]
  }
}
```

Verify the install with `/hooks` in Claude Code. Re-running `permcheck --install` on a completed install prints `permcheck already configured`.

## Manual Hook

Add the hook yourself under `hooks.PreToolUse`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/abs/path/to/permcheck --hook --rules \"/abs/path/to/rules/permcheck.json\""
          }
        ]
      }
    ]
  }
}
```

Use absolute paths for both the binary and `--rules`. After editing, confirm the file is valid JSON:

```sh
jq . ~/.claude/settings.json
```

Then run `/hooks` in Claude Code to confirm the hook loaded. Claude Code ignores malformed settings files.

## Rules Files

Use `--init-rules` to create a starter rules file:

```sh
permcheck --init-rules ~/.claude/permcheck.json
permcheck --init-rules
```

The first command writes the named file. The second writes `./permcheck.json`. Both refuse to overwrite an existing file.

The starter policy is intentionally small: a safe deny list, self-protection for the policy file, `defaultMode: "ask"`, and empty `allow` and `ask` lists to grow.

## Install Safety Details

The rules path is embedded in a shell command. `--install` refuses paths that would remain active inside a quoted command, including substitution, quote, escape, or line-break characters. On Windows, it also refuses environment-expansion characters. It exits before writing rules or settings.

`--uninstall` removes only permcheck hook entries and prunes hook containers that become empty. It leaves unrelated settings and hooks intact.
