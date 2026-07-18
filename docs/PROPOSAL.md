# Proposal: a specificity-aware permission engine for Claude Code

## The problem

Claude Code decides whether to run a tool call (`Bash`, `Read`, `WebFetch`, an
MCP tool, …) by consulting permission rules. The native model matches a call
against `allow`, `ask`, and `deny` lists, but it cannot express the rule shape
that least-privilege policies actually need: **a narrow exception that overrides
a broad rule, in either direction.**

Two concrete cases the native model cannot state cleanly:

- **Narrow allow over broad deny.** "Deny every `aws …` command, *except*
  read-only `describe-*` / `list-*` calls." You want the broad deny as the
  default posture and a small, auditable set of allowed subcommands.
- **Narrow deny over broad allow.** "Allow `cat`, *except* `cat` of a secret
  file like `.env`." The broad allow is convenient; the narrow deny is
  non-negotiable.

Without a precedence model, an operator is forced to choose between a rule set
that is too permissive (broad allows with holes) or too restrictive (broad
denies that block routine work). Neither is least-privilege.

There is a second gap: shell commands are **compound**. A single `Bash` call can
chain `a && b | c; d`, hide a command in `$(…)`, or smuggle a file read past a
command allow (`cat .env`). A rule that inspects only the leading command word
is trivially bypassed.

## What this is (and is not)

permcheck is **defense-in-depth, not a sandbox.** The OS sandbox and enterprise
`managed-settings.json` remain the security boundary. permcheck exists to express
the least-privilege *policy* the native permission model cannot — it decides
`allow` / `ask` / `deny` for a single call and never executes anything, never
mutates state, and never reaches the network. If it is bypassed or buggy, the
underlying sandbox still holds.

## Proposed solution

A single small binary, wired in as a Claude Code **PreToolUse hook**, that reads
one tool call on stdin and returns one decision. Its distinguishing ideas:

1. **Specificity-based precedence.** Every matching rule earns a specificity
   score from how literal (non-wildcard) its pattern is, with a large bonus for
   an exact match. The most specific rule wins; ties break toward the most
   restrictive tier. This is what lets a narrow `allow` beat a broad `deny` and a
   narrow `deny` beat a broad `allow` — both directions, from one mechanism.

2. **Every tool is evaluated, not just Bash.** Tools route into three matcher
   families — **Bash** (command patterns), **Path** (glob over file paths), and
   **Generic** (URL/string patterns for WebFetch, WebSearch, MCP, …) — so the
   taxonomy has no gaps and no tool silently bypasses policy.

3. **Compound-Bash analysis.** A Bash command is decomposed into units on shell
   operators (`&&`, `||`, `|`, `;`, `&`, newlines), with inner commands pulled
   out of `$(…)`, backticks, and process substitutions. Each unit is judged
   independently and the **most restrictive** verdict wins. A file-access
   cross-check catches reads/writes of denied paths even when the command word
   itself is allowed (e.g. `cat .env`).

4. **Fail-closed.** Any error — unparseable input, an unreadable or invalid rule
   file, an unknown tool, even an internal panic — resolves to `deny`. The hook
   always exits 0 so it can never crash a tool call *open*.

## Why it's worth building

- **Expresses real least-privilege policy** that the native lists cannot, in a
  form that stays auditable (a short deny list plus a few explicit exceptions).
- **Closes the compound-command bypass** that makes command-word allow-listing
  unsafe.
- **Cheap and safe to run** on every single tool call: a short-lived process
  with microsecond-scale matching, no regex engine to compile, and a fail-closed
  posture that degrades to the safe direction.

The full behavioral contract is specified in `specs/SPEC.md`; the architecture
that realizes it is in [`DESIGN.md`](DESIGN.md).
