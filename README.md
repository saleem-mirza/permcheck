# permcheck

permcheck is a permission layer for [Claude Code](https://claude.com/claude-code). It helps you keep useful agent access without approving broad, risky behavior.

It runs as a `PreToolUse` hook. For each tool call, it checks your rules and returns one decision: `allow`, `ask`, or `deny`.

It is a defense-in-depth layer, not a sandbox. The OS sandbox and Claude Code enterprise settings remain the security boundary. permcheck only tightens permissions.

The behavioral source of truth is [`specs/SPEC.md`](specs/SPEC.md).

## What Problem Does It Solve?

AI coding agents need useful permissions to do real work. The risk is that useful permissions are often broad:

- letting the agent inspect cloud resources also exposes destructive cloud commands
- letting it read project files also exposes secrets such as `.env` and SSH keys
- letting it use Git also exposes force-pushes, hard resets, and cleanup commands
- letting it fetch web pages also exposes domains you do not trust

permcheck lets you keep the useful parts and fence off the dangerous parts with explicit rules. A casual user gets prompts for undecided actions. A team gets a policy file for review, versioning, and sharing.

For example, write a policy that denies all `aws` commands, allows only read-only `aws ... describe-*` calls, and prompts on unlisted commands.

## Quick Start

Install the Claude Code plugin:

```sh
/plugin marketplace add saleem-mirza/marketplace
/plugin install permcheck@zethian
```

Then run `/hooks` in Claude Code. You should see permcheck listed as a `PreToolUse` hook with source `Plugin`.

The marketplace plugin is distributed with prebuilt binaries for macOS, Linux, and Windows. It registers the hook without editing your `settings.json`.

For Homebrew, manual wiring, and `--install` details, see [`docs/installation.md`](docs/installation.md).

## How It Works

Claude Code's native permission model gives broad `deny` rules priority over narrow `allow` rules.

permcheck evaluates every matching rule and lets a narrower rule carve out a broader one when containment is clear.

Example policy:

```json
{
  "defaultMode": "ask",
  "deny": ["Bash(aws:*)"],
  "allow": ["Bash(aws * describe-*)"]
}
```

Result:

| Tool call | Decision |
| --- | --- |
| `aws ec2 describe-instances` | `allow` |
| `aws ec2 terminate-instances` | `deny` |
| unlisted command | `ask` |

The same idea works in the other direction: a narrow `deny` overrides a broader `allow`.

## What It Checks

permcheck supports three matcher families:

| Family | Examples | What it checks |
| --- | --- | --- |
| Bash | `Bash(git push:*)`, `Bash(rm -rf:*)` | Shell command payloads, including many compound commands and wrappers. |
| Path | `Read(//**/.env*)`, `Write(/repo/**)` | File paths from `Read`, `Write`, `Edit`, `Glob`, `Grep`, and `NotebookEdit`. |
| Generic | `WebFetch(domain:docs.example.com)`, `mcp__server__*` | URLs, queries, MCP tools, and unknown tools. |

Bad input, invalid rules, unreadable rules, and internal errors fail closed to `deny` in hook mode.

For full rule syntax and precedence, see [`docs/rules.md`](docs/rules.md).

## Common Policies

Protect secrets:

```json
{
  "defaultMode": "ask",
  "deny": ["Read(//**/.env*)", "Read(//**/.ssh/**)"]
}
```

Guard destructive git operations:

```json
{
  "defaultMode": "ask",
  "allow": ["Bash(git add:*)", "Bash(git commit:*)"],
  "ask": ["Bash(git push:*)"],
  "deny": ["Bash(git push --force:*)", "Bash(git reset --hard:*)"]
}
```

Allow read-only cloud inspection:

```json
{
  "defaultMode": "ask",
  "deny": ["Bash(aws:*)", "Bash(kubectl:*)"],
  "allow": ["Bash(aws * describe-*)", "Bash(kubectl get:*)"]
}
```

Restrict web access:

```json
{
  "defaultMode": "ask",
  "deny": ["WebFetch", "WebSearch"],
  "allow": ["WebFetch(domain:docs.internal.example.com)"]
}
```

## Rules File

Rules are JSON:

```json
{
  "defaultMode": "ask",
  "allow": [],
  "ask": [],
  "deny": []
}
```

The lists also work under a `permissions` key, matching Claude Code's settings shape:

```json
{
  "permissions": {
    "allow": [],
    "ask": [],
    "deny": []
  }
}
```

Create a starter policy:

```sh
permcheck --init-rules ~/.claude/permcheck.json
```

The reference policy used by tests lives at [`rules/permcheck.json`](rules/permcheck.json). The starter policy is smaller and meant to be edited.

## CLI Checks

Use the CLI to test one tool call against a policy:

```sh
permcheck <Tool> [payload] --rules <path> [--json]
```

Examples:

```sh
permcheck Bash "cat notes.txt"          --rules rules/permcheck.json
permcheck Bash "kubectl delete pod x"   --rules rules/permcheck.json
permcheck Read "/home/user/.ssh/id_rsa" --rules rules/permcheck.json
```

Without `--json`, exit codes are `0` for `allow`, `1` for `ask`, `2` for `deny`, and `3` for config or usage errors. With `--json`, the CLI prints the hook-format decision object and exits `0`.

## Safety Notes

permcheck only tightens Claude Code permissions. It cannot loosen a native `deny` or bypass a native `ask` from user, project, or enterprise settings.

It also does not invent policy. If a command, path, or tool is not covered by your rules, `defaultMode` decides.

Bash analysis is best effort. permcheck splits many compound commands, checks known file reads and writes against path deny rules, and re-decides through wrappers such as `env` and `sudo`. It is not a full shell parser.

For the detailed safety model, Bash coverage, flag handling, path normalization, and resource bounds, see [`docs/security-model.md`](docs/security-model.md).

## Build

Requires a recent Rust toolchain for edition 2024.

```sh
cargo build --release
cargo test
cargo bench
```

The runtime dependencies are `serde` and `serde_json`. Packaging and release notes are in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
