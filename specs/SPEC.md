# Specification: specificity-aware permission engine for Claude Code

Specification of the permcheck decision engine, and the **source of truth for
behavior**: where code and spec disagree, the spec wins. It defines *what* the
engine decides, not *how* it is built. The code and the README carry the
implementation and file layout.

Running as a Claude Code **PreToolUse hook**, permcheck decides whether a tool
call is `allow`, `ask`, or `deny`. It is **defense-in-depth, not a sandbox**:
the OS sandbox and enterprise `managed-settings.json` remain the security
boundary. It exists to express the least-privilege rules the native permission
model cannot: a narrow `allow` overriding a broad `deny`, and vice versa.

This spec is written against `rules/permcheck.json`, the **canonical
reference rule set**. The worked examples (§10) and the known issues (§11) refer
to that file.

---

## 1. Purpose and scope

Given a single tool call (tool name + input payload) and a set of rules,
permcheck returns exactly one decision: `allow`, `ask`, or `deny`, with a
human-readable reason. It never executes the tool call and never mutates state.

In scope: rule loading, rule matching, carve-out (containment) precedence, the
compound-Bash decision, and the fail-closed error posture.

Out of scope: enforcing the decision (Claude Code does that), sandboxing,
network policy, and any statically-undecidable shell construct (§9).

Assumptions. permcheck only tightens the native decision; it never loosens it.
A PreToolUse hook cannot open a native `deny`: Claude Code evaluates its own
`deny` and `ask` rules [regardless of what the hook returns](https://code.claude.com/docs/en/permissions#extend-permissions-with-hooks),
so a native `deny` or `ask` (user or enterprise `settings.json`, or
`managed-settings.json`) still applies even when permcheck returns `allow`. The
carve-out precedence (§6) therefore holds only among the rules inside the
rules file. permcheck assumes the `deny` section of the native `settings.json`
is empty or does not conflict with the rules file, and that the operator is
responsible for a correct, valid policy across all three sources (enterprise,
user, and the rules file).

## 2. Interfaces

The engine is one binary with two **decision** modes plus two **management**
commands. The **hook is the normative interface**, the CLI is a thin wrapper for
testing and manual checks, and `--install` / `--uninstall` wire the hook into a
Claude Code `settings.json` (§2.3).

### 2.1 PreToolUse hook (`--hook`)

Invoked as `permcheck --hook --rules <path>`. Wired into Claude Code
`settings.json` under `hooks.PreToolUse`.

- **Input** (stdin, JSON): the Claude Code PreToolUse event. Fields consumed:
  - `tool_name`: string, the tool being called.
  - `tool_input`: object, the tool's arguments.
  - `cwd`: string, optional, the session working directory (used to absolutize
    relative path payloads, §7.2).

  All other fields (`session_id`, `transcript_path`, `hook_event_name`, …) are
  tolerated and ignored. Missing/unknown fields never error.

- **Output** (stdout, JSON), **always exit 0**:

  ```json
  {
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "allow|ask|deny",
      "permissionDecisionReason": "<reason>"
    }
  }
  ```

  where `<reason>` is a uniform string `<label>: <payload>`. Here `<label>` matches
  `permissionDecision` (`allow`, `ask`, or `deny`), and `<payload>` is the tool's
  input (command, path, URL, query), or the tool name when the tool takes no
  payload. Error decisions (below) use a descriptive reason instead.

- **Fail-closed**: any error (unparseable stdin, unreadable/invalid rules file, a
  missing or empty `tool_name`, or an internal panic) yields `deny` (still exit
  0). An unrecognized non-empty tool name is not an error: it routes to Generic
  (§5) and uses its matching result or the `defaultMode` fall-back (§6.4). The
  hook never crashes the tool call open.

### 2.2 CLI: direct check

Invoked as `permcheck <Tool> [payload] --rules <path> [--json]`.

- `payload` is the tool's primary input string (a Bash command, a file path, a
  URL, …). If omitted, the tool is checked with an empty payload.
- Exit codes: `0` = allow, `1` = ask, `2` = deny, `3` = config/usage error
  (bad arguments, unreadable or invalid rules file). An unrecognized long flag
  is a usage error, and so is invoking with no arguments; `-h`/`--help` prints
  usage to stdout and exits `0`.
- `--json` prints the same decision object as hook mode, pretty-printed for
  readability, instead of using the exit code.
- Config errors surface as exit `3` in CLI mode. In hook mode the same
  conditions fail closed to `deny`.

### 2.3 Install / uninstall

Invoked as `permcheck --install [--rules <path>] [scope]` and
`permcheck --uninstall [scope]`. These **idempotently** add or remove permcheck's
own `PreToolUse` hook entry in a Claude Code `settings.json`, and never touch
unrelated settings or other hooks.

- **Scope** selects the target file (default `--user`): `--user`
  (`~/.claude/settings.json`), `--project` (`./.claude/settings.json`), or
  `--local` (`./.claude/settings.local.json`). At most one scope is allowed.
- **`--install`** lands the policy file at a canonical location next to the
  scope's settings file, `<scope .claude>/permcheck.json` (`permcheck.local.json`
  for `--local`), and bakes that absolute path into the injected command
  `permcheck --hook --rules "<abs>"`. With `--rules <path>` the given file is
  absolutized and validated (it must load), then **copied** into the canonical
  location. With no `--rules` a minimal safe starter (a small `deny` list, not the
  full reference set, plus `defaultMode: "ask"` and empty `allow`/`ask`) is written there. `--rules` **requires
  a value**: a bare `--rules` (no path, or one followed by a flag) is a usage
  error (exit `3`), never a silent auto-seed. An
  existing canonical rules file is **never overwritten**: copy mode refuses (exit
  `3`) when the source differs from it (an identical file is a no-op), and seed
  mode reuses it as-is. A permcheck hook already present is rewritten in place,
  never duplicated. A fresh `{ "matcher": "*", … }` group is appended otherwise,
  **except** when that hook already targets a *non-canonical* rules path (e.g. a
  legacy install): re-pointing it would silently abandon that policy, so
  `--install` refuses (exit `3`) and directs the user to `--uninstall` first.
- **`--uninstall`** removes every permcheck hook entry and prunes emptied
  matcher groups / `PreToolUse` / `hooks` containers.
- Detection is by command marker (contains `permcheck` and `--hook`), so a
  user's other hooks are left untouched (the marker is a heuristic: a command
  naming both `permcheck` and `--hook` matches, including a user's own wrapper
  around it). The baked `--rules` path is recognized quoted or bare, so the
  re-point refusal above also covers a hand-wired hook. Writes are atomic: a
  per-process temp file, flushed with `sync_all`, then `rename` over the target.
  A missing/empty file starts from `{}`, and a present-but-non-object file is
  refused rather than clobbered. Both exit `0` on success (or when already in
  the desired state), `3` on a usage/IO error. These commands are portable across
  Linux, macOS, and Windows. Home resolution is per-platform: POSIX reads `$HOME`
  only, Windows tries `$HOME` → `%USERPROFILE%` → `%HOMEDRIVE%%HOMEPATH%`. The
  same resolution serves `~` expansion in Path specifiers (§6.5), so the
  directory `--install` writes a policy into and the directory a `~/…` rule
  *inside* that policy expands to are always the same.

## 3. Rule file

The rules file is passed explicitly via `--rules <path>`. At **decision time**
there is no hardcoded default location. The hook config or CLI user always names
the file. `--install` (§2.3) is the one place permcheck picks a location for you:
it seeds/copies the policy to a canonical path next to `settings.json` and points
the hook there. The canonical reference rule set ships at `rules/permcheck.json`.

### 3.1 Accepted shapes

Both of these parse identically:

```json
{
  "permissions": {
    "allow": [...],
    "ask": [...],
    "deny": [...]
  }
}
```

```json
{
  "allow": [...],
  "ask": [...],
  "deny": [...]
}
```

- Each of `allow`, `ask`, `deny` is an array of rule strings (§4). A missing
  array is treated as empty.
- `defaultMode` is **honored** as the fall-back decision for calls that match no
  rule (§6.4): `"ask"` → `ask`, while `"deny"`, a missing key, or any other value →
  `deny` (fail-closed). (The native Claude Code value `"default"` therefore maps
  to `deny`.)
- Any other keys in the object (including Claude Code settings such as
  `disableAutoMode`, `disableBypassPermissionsMode`) are **ignored**. The engine
  reads only the three tier arrays and `defaultMode`. (The file doubles as a
  Claude Code settings file when you want, and permcheck simply ignores what it
  does not own.)
- A file that is unreadable, not valid JSON, or does not contain a permissions
  object → **load error → deny** (hook) / exit `3` (CLI).

## 4. Rule grammar

A rule is one string, in one of two forms:

- **Bare rule**: `Tool` matches any payload for that tool.
- **Specifier rule**: `Tool(specifier)` matches payloads of that tool per the
  tool's matching semantics (§6).

Rules:

- **Tool name** matches `[A-Za-z][A-Za-z0-9_]*`. This covers built-in tools
  (`Bash`, `Read`, `WebFetch`, …) and MCP tools (`mcp__server__tool`).
- **Specifier** is everything between the first `(` and the final `)`, and it must be
  at least one character. `Tool()` (empty specifier) is a **load error**: an
  operator who writes a deny that way must be told, not silently ignored.
- A specifier that cannot be compiled into a matcher (§6) is a **load error →
  deny**. Bad rules fail at load, never at decision time.

## 5. Tool taxonomy and payload extraction

**Every tool call is evaluated, not `Bash` alone.** No tool bypasses the engine.
Each tool is routed to one of three matcher families by its name, and the **payload**
(the string that gets matched) is extracted from `tool_input` as below.

| Family | Tools | Payload |
|---|---|---|
| **Bash** | `Bash` | `command` (then split and cross-checked, §8) |
| **Path** | `Read`, `Write`, `Edit`, `Glob`, `Grep`, `NotebookEdit` | `file_path` (`NotebookEdit`→`notebook_path`), `Glob`/`Grep`→`path`, fallback `pattern` |
| **Generic** | **every other tool**: `WebFetch`, `WebSearch`, `SlashCommand`, `Task`, and all MCP `mcp__*` tools | `WebFetch`→`url`, `WebSearch`→`query`, `SlashCommand`→`command`, otherwise the **lexicographically-first** (by field name) non-empty string field of `tool_input`, else the empty string |

Routing rules:

- The **Path** family gets glob semantics (§6.5), and the **Generic** family gets
  URL/string semantics (§6.5). Any built-in or MCP tool the engine does not name
  explicitly falls into **Generic** and is still evaluated, so the taxonomy has no
  gaps.
- A rule's tool name must equal the call's tool name exactly, so
  `mcp__github__create_issue(...)` rules apply only to that MCP tool, and
  `NotebookEdit` is not covered by a bare `Edit` rule (different tool name).
- **Tools with no string payload** (e.g. `TodoWrite`, `ExitPlanMode`) extract the
  empty string, so only a **bare** rule (`TodoWrite`) matches them. Absent one
  they take the **`defaultMode` fall-back** (§6.4). Give always-on benign tools an
  explicit bare `allow` so they are neither blocked nor prompted.

## 6. Specificity, matching, and precedence

### 6.1 Specificity score

Every matched rule carries a specificity score so a narrow rule beats a broad
one:

```
specificity = (count of literal, non-wildcard characters in the specifier)
            + (1000 if the specifier contains no wildcard at all)
```

- Wildcards are `*` for all families, plus `?` for the Path family.
- A **bare rule** has specificity `0`.
- The `+1000` exact-match bonus guarantees a literal specifier outranks any
  wildcard specifier, regardless of length.
- Specificity is a **character count**, a proxy for narrowness. It orders rules
  of the same effect (which allow/ask wins, and the stable tie-break in §6.3), but
  it does **not** decide allow-versus-deny across tiers. Cross-tier precedence
  uses containment (§6.3): an allow/ask overrides a deny only when its match-set
  is a strict subset of that deny. So `allow Read(/**/passwd)` does **not**
  override `deny Read(/etc/**)` — the two overlap without one refining the other —
  and `/etc/passwd` is denied. A literal `allow Read(/etc/passwd)`, a strict
  subset of the deny, does override it. The only load-time check is the
  dead-`cmd:*` lint (§11.2).

### 6.2 Tier ordering

Tiers are ordered `Allow < Ask < Deny`. Deny is the most restrictive and the
highest rank, and this ordering is the tie-break in §6.3.

### 6.3 Winner selection (single unit)

For a given payload, gather **every** matching rule across the tool's matchers
(including any bare rule at specificity `0`), split into denies and allow/ask
rules.

1. **Carve-out test.** An allow/ask rule *carves out* a matching deny when its
   match-set is a **strict subset** of that deny's (`allow ⊆ deny` and
   `deny ⊄ allow`), a genuine narrower exception. An identical specifier in a
   lower tier is not a carve-out (equal sets), so it never overrides the deny.
2. **Deny survives.** If any matching deny is not carved out by some matching
   allow/ask, the decision is `deny`.
3. **Otherwise pick the winner** among the matching allow/ask rules by
   `(specificity, tier)`, maximal lexicographically: higher specificity, then
   higher tier (`ask` over `allow`), then the first rule in file order for a
   stable, deterministic decision.

The subset test is **sound but conservative**: it reports a carve-out only when
containment is proven, and otherwise keeps the deny, so an unprovable case fails
toward `deny` (§9.2).

This selection is the **entire** decision for Path and Generic tools (Read,
Write, Edit, Glob, Grep, NotebookEdit, WebFetch, WebSearch, MCP, …). Only `Bash`
adds a step: it first decomposes the command into units (§8) and applies this
selection per unit.

### 6.4 Default decision

If no rule matches, the decision is the rule set's **fall-back tier**, configured
by `defaultMode`: `"ask"` makes an unlisted call **ask**, and otherwise (`"deny"`,
missing, or any other value) it is **deny** (fail-closed default). This fall-back
governs only the *no rule matched* case. It does **not** loosen the Bash
file-access cross-check (§8), which still raises to `deny` on a hit, nor the
error posture (§9.1): bad rules, unparseable input, a missing/empty tool name, or
a panic are always `deny`, independent of `defaultMode`.

### 6.5 Matching semantics per family

**Bash.** A specifier is an anchored, full-string pattern over the command:

- The trailing form `cmd:*` matches the command `cmd` plus any
  whitespace-delimited arguments (i.e. `cmd` alone, or `cmd <args>`).
- A `*` **fenced by a space on both sides** (` * `) matches a single
  whitespace-delimited token: the "argument slot" idiom. In `aws * describe-*`
  the slot is one service token, so `aws ec2 describe-instances` matches while
  `aws s3 rm s3://bucket/describe-report.json` does **not** — the slot cannot swallow
  the space and let a later `describe-` substring satisfy the suffix. This is what
  makes a `service`-wildcarded read-only carve-out safe against argument
  injection.
- Any other `*` (trailing after a space, or attached to a word such as
  `describe-*`) spans any run of characters, whitespace included.
- Every other character is matched literally.
- Matching is anchored to the whole (trimmed) command string, with no substring
  matches.
- The token boundary is space; the containment check (§6.3) uses the same
  boundary, so the strict-subset relation agrees with the match set.

**Path.** A specifier is a glob over the file path:

- `*` matches any run of characters except the path separator `/`.
- `?` matches a single non-separator character.
- `**` matches across separators (any depth).
- A leading `//` is a root marker: one leading `/` is stripped, leaving an
  absolute-rooted glob.
- A leading `~` or `~/` expands via `$HOME`.
- `[`, `]`, `{`, `}`, `\` are treated as **literal** characters, not
  character-class / alternation metacharacters.

**Generic (URL/string).** A specifier is a domain or URL pattern:

- An optional leading `domain:` prefix is stripped (Claude Code's WebFetch form).
- `*` is the only wildcard and spans any characters, `/` included. Every other
  character (`.`, `?`, `&`, `:`) is literal, so a query string is never treated
  as wildcards.
- Matching is anchored (full match, not substring), so `WebFetch(example.com)`
  matches `https://example.com/path` (via the extracted host, §7.2) but not
  `example.com.evil.com`.

### 6.6 Precedence in plain terms

Denies hold unless an allow/ask carves them out:

- A pattern that appears in **no** list falls back to the `defaultMode` tier:
  `deny` by default, or `ask` when configured (§6.4).
- The **same** specifier in several tiers → the **most restrictive** tier wins.
  `Bash(aws:*)` in `allow`, `ask`, and `deny` → `deny` (an equal set is not a
  carve-out).
- A **carve-out** — an allow/ask whose match-set is a strict subset of a deny —
  overrides that deny; any other overlap leaves the deny in force. With
  `Bash(aws:*)` (deny) and `Bash(aws * describe-*)` (allow, a strict subset), the
  `describe-*` calls are **allowed** and every other `aws …` call is **denied**.
  But `allow Read(/**/passwd)` and `deny Read(/etc/**)` only overlap, so
  `/etc/passwd` is **denied**.

## 7. Evaluation details

### 7.1 Candidate forms (Path and Generic)

To match reliably regardless of how the caller wrote the payload, the engine
matches the specifier against **candidate forms** of the payload, and a hit on
any form counts:

- **Path**: the raw payload, its `~`-expanded form, and its `cwd`-absolutized
  form (so a bare `.env` matches a rule written for an absolute path).
- **Generic/URL**: the raw payload and the host extracted from a
  `scheme://[user@]host[:port]/…` URL (plus a lowercased host, since domains are
  case-insensitive).

### 7.2 Relative paths

A relative path payload is resolved against the hook event's `cwd` (or the
process CWD in CLI mode) before Path matching, so bare filenames are matched via
their absolute form.

## 8. Bash compound decision

A single Bash `tool_input.command` often contains several commands. The engine
decomposes it and takes the **most restrictive** verdict.

1. **Split into units** on shell operators outside quotes: `&&`, `||`, `|`, `;`,
   `&`, and newlines. Pull inner commands out of command substitutions
   `$(…)`, backticks `` `…` ``, and process substitutions `<(…)` / `>(…)`,
   including inside double quotes. `$((…))` arithmetic is literal. Single quotes
   suppress expansion. An unquoted `#` that starts a word (at unit start or after
   whitespace or an operator) opens a comment; it and the rest of the line are
   dropped, as bash does, so a comment cannot feed matched text. A `#` inside a
   word (`feature#123`) or inside quotes is literal. The splitter is total: it
   never errors, and unterminated constructs are consumed to end of input.
   Substitution nesting is bounded: past a fixed depth (far above any real
   command) the splitter stops descending and the command is **denied**, since a
   partial split could miss a denied inner command (§9.1).

2. **Per unit**, strip leading `NAME=value` environment assignments, then decide
   the trimmed unit string against the Bash matchers via §6.3. The unit is also
   matched in normalized forms so a rule cannot be dodged by dressing up the
   command line. Two kinds:

   - **Identity** forms decide together with the raw command, so an allow can
     still win. They come from a normalization **pipeline**: each stage runs on
     the previous stage's output and every intermediate spelling is kept, so a
     command wearing several disguises at once still reaches the rule that names
     it. The stages, in order:

     1. **Quoting and escaping** are removed, leaving the characters the shell
        passes to the command: `"sudo" rm`, `su"do" rm`, `\sudo rm`, `$'sudo' rm`,
        and `git push "--force"` all reduce to their bare spelling. Quoting is
        stripped across the whole unit, not only the command word, because a
        rule names argument text too.
     2. Leading `NAME=value` **environment assignments** that were hidden behind
        quoting (`"FOO=bar" sudo …`) are stripped, as step 2 already does for
        the plain spelling.
     3. Runs of **whitespace** collapse to a single space, so `git  push
        --force` reaches a rule written with single spaces.
     4. A **path-qualified** executable reduces to its basename
        (`/usr/bin/aws …` → `aws …`).
     5. A **git** invocation with global options before the subcommand
        (`git -c x config …`, `git -C /r push --force`) exposes the subcommand.

     The order is load-bearing, and so is composing the stages rather than
     applying them independently: quoting hides every later stage's marker (a
     quoted `"/usr/bin/git"` shows no `/` to reduce), and irregular whitespace
     hides the rest. `/usr/bin/git  push --force` matches only when basename
     reduction runs on the whitespace-collapsed spelling.
   - **Escalation** forms are each decided on their own and can only *raise* the
     verdict, and only on a real rule match — so they respect `defaultMode` and
     never invent a deny. A clustered/reordered/split **short-flag** set maps onto
     its single-flag rule (`rm -Rf` / `rm -fr` / `rm -r -f` → `rm -f`), and an
     **interpreter inline-code** invocation is canonicalized to `<interp> <flag>`
     (`python3 -cimport` / `python3 -W ignore -c` / `perl -we` / `node --eval` /
     `deno eval` → `python3 -c` / `perl -e` / `node -e` / `deno eval`) so every
     spelling matches whatever the rules say about that interpreter. A
     **value-taking** flag keeps its value, because that is what the rule names:
     `python3 -mhttp.server` and `python3 -Bmhttp.server` both canonicalize to
     `python3 -m http.server`, while `python3 -mpytest` stays a different command.
     The interpreter+flag vocabulary is an engine table (`python`, `perl`, `ruby`,
     `node`, `deno`, `php`, `bun`, `lua`, `Rscript`, …); the policy stays in the
     rules.

   Additionally, if the unit begins with a **wrapper command** (`env`, `sudo`,
   `timeout`, `nice`, `xargs`, …), peel the wrapper and its options / assignments
   / numeric args and decide the wrapped command too, taking the most restrictive.
   This runs the wrapped command's own rules, so `env aws …` cannot ride in on a
   broad `Bash(env:*)` allow and bypass an `aws` deny. Peeling reads the
   fully-normalized spelling from the pipeline above, so a disguised wrapper
   (`"env" aws …`) is still recognized as one.

3. **File-access cross-check** (raises to `deny` only, never loosens): tokenize
   the unit, peel wrapper commands (`sudo`, `env`, `timeout`, `nice`, `xargs`,
   …), then:
   - if the command is a known **reader** (`cat`, `grep`, `sed`, `head`, …),
     check each non-option operand against the `Read` **deny** rules
     (pattern-first readers like `grep`/`sed`/`awk` skip their first operand,
     which is a pattern, not a file). An option that takes a **separate value**
     (`grep -m 5`, `-A/-B/-C`, `--max-count 5`, `awk -F ,`) consumes that value,
     so it is not counted as an operand: leaving it in place would shift every
     later operand by one and read the pattern as a file. An attached value
     (`-m5`, `--max-count=5`) is self-contained and consumes nothing further.
     An option that *names a file* is checked rather than skipped: `-f`/`--file`
     supplies the pattern from a file, and `--exclude-from` reads one without
     supplying the pattern. The option vocabulary is a fixed engine table
     (§9.2), and an option whose arity varies by platform (`sed -i`) is left out
     of it, which costs an extra path check but never skips a real operand.
   - if it is a known **writer** (`tee`, `truncate`), check operands against the
     `Write`/`Edit` deny rules.
   - `cp`/`mv` touch both sides, and both are checked. They **overwrite** their
     destination: the last path operand (or the `-t <dir>` /
     `--target-directory=<dir>` target, with each source's landing path) is
     checked against `Write`/`Edit` deny. They also **read** every source: each
     remaining positional (all of them in the `-t` form) is checked against
     `Read` deny, since `cp .env /tmp/leak` exposes the file exactly as
     `cat .env` does.
   - `dd` names files by key-value operand: `if=<path>` is checked against `Read`
     deny, `of=<path>` against `Write`/`Edit` deny.
   - two exfil tools read files by argument: `curl` (`@file` on `-d`/`--data*`/
     `-F`, or `-T`/`--upload-file`) and `wget` (`--post-file`/`--body-file`) are
     checked against `Read` deny. The reader and exfil sets are fixed lists (§9.2).
   - check redirection targets: `<` against `Read` deny, `>` / `>>` / `&>` /
     `&>>` against `Write`/`Edit` deny. `>&word` / `>>&word` where `word` is a
     filename (not an fd number) also count as a write. Pure fd dups/closes like
     `2>&1`, `>&2`, `>&-` are skipped.

   An operand carrying a shell glob metacharacter (`*`, `?`, `[`) is matched by
   glob **intersection**: it hits a deny when it could expand onto a denied
   path, so `cat .en?` and `cat .e*` are caught, not only `cat .env`. This
   escalation applies only when every path segment of the operand begins with a
   literal, mirroring shell expansion (a segment-leading wildcard does not match
   a hidden dotfile), so ordinary globs like `cat *.rs` are not over-denied.

   A cross-check hit raises that unit's verdict to `deny`. This catches
   `cat .env` even though `Bash(cat:*)` is allowed.

4. **Aggregate**: the command's verdict is the most restrictive unit verdict
   (the first unit that reaches the maximal tier). The emitted reason echoes the
   whole command, not the individual unit.

## 9. Fail-closed and non-goals

### 9.1 Fail-closed

- Every fallible load step returns a result, and invalid rules fail at **load →
  deny**. No evaluation-path code panics on runtime input.
- Hook mode wraps evaluation so that any unexpected panic becomes `deny`.
- Recursive analysis is depth-bounded so it cannot exhaust the stack. A stack
  overflow **aborts** the process rather than unwinding, so `catch_unwind` cannot
  convert it to `deny` and the hook would exit non-zero with no decision — which
  Claude Code treats as a non-blocking error, letting the call run. The Bash
  splitter therefore caps substitution nesting and denies past the cap (§8.1).
- Unreadable/invalid rules file, unparseable stdin, or a missing/empty tool name
  → `deny` (hook) or exit `3` (CLI, config errors only). An unrecognized
  non-empty tool name routes to Generic and is not an error (§5).

### 9.2 Non-goals (documented limitations)

The Bash analyzer is a best-effort scanner, not a full shell parser. These are
out of scope and left to the OS sandbox and enterprise denies:

- `eval`, shell aliases/functions, dynamic variable expansion, and commands
  assembled at runtime. Quote and escape *removal* is normalized (§8 step 2),
  but the escape sequences inside `$'…'` are not decoded, so a name spelled
  `$'\x73udo'` is not reduced to `sudo`.
- Non-POSIX shells (PowerShell, `cmd.exe`): the splitter, reader vocabulary, and
  env-stripping model POSIX syntax and do not apply there, though Windows
  binaries ship.
- File reads by tools outside the covered set (readers, `dd`, `curl`, `wget`,
  `cp`/`mv`): `scp`, `tar`, `git`, `rsync`, and editors reading a secret are not
  followed.
- Interpreter inline-exec is form-normalized (§8 step 2): once an interpreter is
  in the engine table, every spelling of its inline flag (clustered, attached,
  reordered, long, spaced, path-qualified) maps onto the rule, so a bundled flag
  no longer slips. The table is still an enumeration — an interpreter not in it
  (`tclsh`, `groovy`, …) is not normalized, but it falls to `defaultMode` (ask),
  never a silent allow. The `curl`/`wget` file-read options remain a blocklist.
- `xargs` is peeled as a wrapper, so the command it runs (`xargs cat …`,
  `xargs rm -rf …`) is decided and cross-checked. A separate-token replace string
  (`xargs -I {} …`) still hides the command; the attached form (`-I{}`) does not.
- The reader **option** vocabulary (§8 step 3) is an enumeration, like the
  interpreter table. An option outside it whose value is a separate token leaves
  that value in the operand stream, where it is checked as if it were a path.
  That direction over-denies rather than under-denies, so an option is added to
  the table only when its value is mandatory and separable on every platform.
- An unquoted `#` starting a word opens a comment, which the splitter strips
  through end of line (§8.1) — matching bash, so a comment cannot smuggle a
  substring into the matched text. Heredoc bodies are not modeled; an unterminated
  or exotic heredoc biases toward over-deny, the safe direction.
- The glob-operand cross-check (§8.3) escalates only operands whose every path
  segment begins with a literal, so ordinary globs (`cat *.rs`) are not
  over-denied. This leaves one gap: a segment-leading wildcard against a
  non-dotfile filename-pattern deny. `cat *rsa` resolves to allow even though a
  shell expands `*rsa` onto `id_rsa`, which `Read(//**/id_rsa*)` denies. A deny
  targeting a directory (`.ssh/**`) still catches it.
- **Path-glob matching is not hardened against catastrophic backtracking.** The
  matcher is a plain recursive backtracker. A specifier with many interacting
  wildcards (e.g. `/*a*a*a*a*a*a*a*b`) grows super-linearly in the path length.
  This is acceptable because rule specifiers are **trusted operator config**, not
  attacker input. The rule file is the source of truth. Payloads (paths) are
  bounded and realistic rules use at most a few wildcards, so matching stays in
  microseconds.

Unsupported constructs receive no special interpretation beyond whatever units
and forms the analyzer can extract. They remain governed by literal rule
matching and `defaultMode`; the gaps above may therefore under- or over-deny.

## 10. Worked examples

Drawn from the reference rule set `rules/permcheck.json`. It denies `Bash(aws:*)`,
`Bash(kubectl:*)`, `Bash(git push --force:*)`, bare `WebFetch`, and bare `WebSearch`.
It allows `Bash(cat:*)`, `Bash(python3 *)`, and bare `Read`. It asks on
`Bash(git push:*)`, and `defaultMode: "ask"` makes a call matching no rule fall back
to `ask` (§6.4). The reference set carries **no** narrow `aws`/`kubectl` read-only
allows, so those commands are governed by the broad deny. Git read commands
(`git status`, `git diff`, …) have no explicit rule and take the ask fall-back.

| Tool call | Decision | Why |
|---|---|---|
| `Bash(aws ec2 describe-instances)` | deny | only `aws:*` deny matches, no narrower allow |
| `Bash(aws s3api list-buckets)` | deny | only `aws:*` deny matches |
| `Bash(aws ec2 terminate-instances)` | deny | only `aws:*` deny matches |
| `Bash(kubectl get pods)` | deny | only `kubectl:*` deny matches |
| `Bash(kubectl delete pod x)` | deny | only `kubectl:*` deny matches |
| `Bash(git push origin main)` | ask | `git push:*` is in `ask` |
| `Bash(git push --force origin)` | deny | `git push --force:*` deny holds; the broader `git push:*` ask does not carve it out |
| `Bash(git status)` | ask | no rule matches → `defaultMode: "ask"` fall-back (§6.4) |
| `Bash(cat .env)` | deny | file-access cross-check hits a `Read` `.env` deny even though `cat:*` is allowed (§8) |
| `Read(/tmp/notes.txt)` | allow | bare `Read` (allow, specificity 0), no secret-path deny matches |
| `WebFetch(https://x.io)` | deny | bare `WebFetch` deny matches, no allow carves it out |
| `WebSearch(anything)` | deny | bare `WebSearch` deny matches (non-Bash tools are evaluated too) |
| `mcp__db__query(SELECT …)` | ask | Generic family, no rule names this MCP tool → ask fall-back |
| `NotebookEdit(/repo/nb.ipynb)` | ask | Path family, but no `NotebookEdit` rule and bare `Edit` does not cover it → ask fall-back |
| `Bash(some-tool foo)` | ask | no Bash rule matches → ask fall-back |
| `Bash(python3 -c "import os")` | deny | `python3 -c:*` deny holds; the broad `python3 *` allow does not carve it out |
| `Bash(python3 script.py)` | allow | broad `python3 *` allow, no narrower deny matches |

Two rows show both directions of the design: an active protection (`cat .env`)
denies regardless of the fall-back, while a broad allow the rules do not narrow
grants more than intended (§11).

## 11. Appendix: known issues in the reference rule set

These are **authoring issues in `rules/permcheck.json`**, not engine defects.
The engine faithfully applies §5-§8. Each item below is a case where the rules
do not express what an operator likely intends: cautionary patterns and a
correction backlog for the reference file.

1. **Arbitrary-execution / secret bypasses.** Interpreter inline-exec is guarded
   with one canonical deny per interpreter (`Bash(python3 -c:*)`, `python -c`,
   `python2 -c`, `pypy -c`, `perl -e`/`-E`, `ruby -e`, `node -e`/`-p`, `deno eval`,
   `php -r`, `bun -e`, `lua -e`, `Rscript -e`) while a plain script run stays
   allowed. The engine normalizes every *form* onto these rules (§8 step 2), so a
   clustered/attached/reordered/long/path-qualified spelling no longer slips, and
   `.venv/bin/python -c` matches by basename — no per-form rules needed. Under
   `Bash(gh:*)`, `gh auth token` is denied and `gh api` is `ask`; the
   arbitrary-package runners under `yarn:*`/`pnpm:*`/`uv:*` (`yarn dlx`, `pnpm dlx`,
   `pnpm exec`, `uv run`, `uvx`, `uv tool run`) are denied. (`Bash(env:*)` is
   denied, and `env` is peeled as a wrapper so `env <cmd>` re-decides `<cmd>`,
   §8.2.) The same pairing now covers utilities whose *subform* runs a command or
   writes in place while the tool itself stays broadly allowed: `find -exec` /
   `-execdir` / `-ok` / `-okdir` (an arbitrary command runner that is invisible to
   the splitter, since it is not a shell operator), `gh secret` and
   `gh extension`, and `sed -i` / `perl -i`. `Bash(printenv:*)` moved from `allow`
   to `ask`. Remaining open: dependency installs (`npm install`, `pip install`,
   `gem install`, …) run package build/lifecycle code by design, which a prefix
   deny cannot separate from a safe install. *Pattern:* pair any broad
   interpreter/tool allow with denies for its exec/secret subforms, or move it to
   `ask`; the install residual is a sandbox concern, not a rule fix. An
   interpreter not in the engine table (§9.2) is not normalized, but it takes the
   `defaultMode` fall-back, not a silent allow.

   A subform deny must use the **glob** form when the flag can appear at any
   argument position (`Bash(find *-exec *)`, `Bash(rm *--force*)`); the `cmd:*`
   prefix form anchors at position 0 only.

2. **Dead / redundant under command-splitting.** *Pattern:* one rule per simple
   command, and never put shell operators in a specifier. A specifier like
   `Bash([ ! -d * ] && gh repo clone *)` contains `&&`, and §8 splits on `&&`
   before matching, so no unit ever contains it and the rule never fires.
   (The reference set previously shipped such rules, since removed.) A second
   dead-rule form: a `Bash(cmd:*)` specifier with a `*` before the `:*` compiles
   to a literal-asterisk prefix and matches nothing (the `cmd:*` form has no
   interior wildcard; use the glob form `Bash(cmd …)` instead).

   `RuleSet::lint_warnings` is the author-time linter, printed to stderr by the
   CLI checker and `--install` (never in hook mode). It reports the dead-rule
   form above, plus two **weakening carve-outs** that loosen a broader restriction
   and are easy to write by accident: an `ask` whose match-set is a strict subset
   of a `deny` (the block silently becomes a prompt), and an `allow` whose match-set
   is a strict subset of a broader `ask` it outranks on specificity (the prompt
   silently becomes auto-allow). A narrow `allow` inside a `deny` is **not**
   flagged: that is the intended read-only carve-out. The shipped reference set is
   clean under the check.

3. **Coverage gaps / asymmetries.** `Bash(cp -R:*)` is allowed but plain
   `cp a b` matches no rule and takes the `defaultMode: "ask"` fall-back. Short
   destructive-flag variants are now normalized onto their single-flag rule
   (§8 step 2), so `rm -fr`, `rm -Rf`, `rm -r -f` all match `Bash(rm -f:*)` and
   deny. The **long-form** flags are still not mapped to their short equivalents
   by the engine (that pairing is per-utility and not standardized), so the
   reference set carries an explicit `Bash(rm *--force*)` deny instead;
   `rm --recursive` without force stays `ask`, symmetric with `rm -r`.
   *Pattern:* when a utility supports both spellings, write a deny for each.

4. **`gcp` vs `gcloud`** (fixed). `Bash(gcp:*)` denied a command named `gcp`, but
   the real GCP CLI is `gcloud` (also `gsutil`, `bq`). The reference now denies
   `Bash(gcloud:*)`, `Bash(gsutil:*)`, `Bash(bq:*)` alongside the (harmless) `gcp`
   rule, mirroring aws/kubectl/az.

5. **Bare path-tool allows shift the default.** Bare `Read` / `Edit` / `Write`
   (specificity 0) are in `allow`, so those tools default to **allow** (minus
   the specific secret-path denies). Unmatched Bash and Generic calls instead
   take the `defaultMode` fall-back, `ask` in this reference set (§6.4). Both
   are intended, but worth stating explicitly.

6. **Hygiene (harmless, noisy).** `Read(/**/.env*)` subsumes `Read(/**/.env.*)`,
   `.bash_history` / `.zsh_history` are denied twice, and path root markers mix
   `//**/`, `/**/`, and `**/`, which changes absolute-vs-relative anchoring.
   Dedupe and standardize markers alongside matcher tests.
