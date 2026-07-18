# Specification: specificity-aware permission engine for Claude Code

Specification of the permcheck decision engine, and the **source of truth for
behavior**: where code and spec disagree, the spec wins. It defines *what* the
engine decides, not *how* it is built — the code and the README carry the
implementation and file layout.

Running as a Claude Code **PreToolUse hook**, permcheck decides whether a tool
call is `allow`, `ask`, or `deny`. It is **defense-in-depth, not a sandbox**:
the OS sandbox and enterprise `managed-settings.json` remain the security
boundary. It exists to express the least-privilege rules the native permission
model cannot: a narrow `allow` overriding a broad `deny`, and vice versa.

This spec is written against `rules/permissions.json`, the **canonical
reference rule set**. The worked examples (§10) and the known issues (§11) refer
to that file.

---

## 1. Purpose and scope

Given a single tool call (tool name + input payload) and a set of rules,
permcheck returns exactly one decision: `allow`, `ask`, or `deny`, with a
human-readable reason. It never executes the tool call and never mutates state.

In scope: rule loading, rule matching, specificity-based precedence, the
compound-Bash decision, and the fail-closed error posture.

Out of scope: enforcing the decision (Claude Code does that), sandboxing,
network policy, and any statically-undecidable shell construct (§9).

## 2. Interfaces

The engine is one binary with two **decision** modes plus two **management**
commands. The **hook is the normative interface**; the CLI is a thin wrapper for
testing and manual checks; `--install` / `--uninstall` wire the hook into a
Claude Code `settings.json` (§2.3).

### 2.1 PreToolUse hook (`--hook`)

Invoked as `permcheck --hook --rules <path>`. Wired into Claude Code
`settings.json` under `hooks.PreToolUse`.

- **Input** (stdin, JSON): the Claude Code PreToolUse event. Fields consumed:
  - `tool_name`: string, the tool being called.
  - `tool_input`: object, the tool's arguments.
  - `cwd`: string, optional; the session working directory (used to absolutize
    relative path payloads, §7.2).

  All other fields (`session_id`, `transcript_path`, `hook_event_name`, …) are
  tolerated and ignored. Missing/unknown fields never error.

- **Output** (stdout, JSON), **always exit 0**:

  ```json
  {"hookSpecificOutput":{
    "hookEventName":"PreToolUse",
    "permissionDecision":"allow|ask|deny",
    "permissionDecisionReason":"<reason>"}}
  ```

  where `<reason>` is a uniform string `<label>: <payload>` — `<label>` matches
  `permissionDecision` (`allow`, `ask`, or `deny`); `<payload>` is the tool's
  input (command, path, URL, query), or the tool name when the tool takes no
  payload. Error decisions (below) use a descriptive reason instead.

- **Fail-closed**: any error (unparseable stdin, unreadable/invalid rules file,
  unknown tool, or an internal panic) yields `deny` (still exit 0). The hook
  never crashes the tool call open.

### 2.2 CLI: direct check

Invoked as `permcheck <Tool> [payload] --rules <path> [--json]`.

- `payload` is the tool's primary input string (a Bash command, a file path, a
  URL, …). If omitted, the tool is checked with an empty payload.
- Exit codes: `0` = allow, `1` = ask, `2` = deny, `3` = config/usage error
  (bad arguments, unreadable or invalid rules file).
- `--json` prints the same decision object as hook mode, pretty-printed for
  readability, instead of using the exit code.
- Config errors surface as exit `3` in CLI mode; in hook mode the same
  conditions fail closed to `deny`.

### 2.3 Install / uninstall

Invoked as `permcheck --install --rules <path> [scope]` and
`permcheck --uninstall [scope]`. These **idempotently** add or remove permcheck's
own `PreToolUse` hook entry in a Claude Code `settings.json`, and never touch
unrelated settings or other hooks.

- **Scope** selects the target file (default `--user`): `--user`
  (`~/.claude/settings.json`), `--project` (`./.claude/settings.json`), or
  `--local` (`./.claude/settings.local.json`). At most one scope may be given.
- **`--install`** requires `--rules <path>`; the path is absolutized and
  validated (it must load) before writing, then baked into the injected command
  `permcheck --hook --rules "<abs>"`. A permcheck hook already present is
  rewritten in place (refreshing a changed rules path), never duplicated; a fresh
  `{ "matcher": "*", … }` group is appended otherwise.
- **`--uninstall`** removes every permcheck hook entry and prunes emptied
  matcher groups / `PreToolUse` / `hooks` containers.
- Detection is by command marker (contains `permcheck` and `--hook`), so a
  user's other hooks are left untouched. Writes are atomic (temp file +
  `rename`). A missing/empty file starts from `{}`; a present-but-non-object file
  is refused rather than clobbered. Both exit `0` on success (or when already in
  the desired state), `3` on a usage/IO error. These commands are portable across
  Linux, macOS, and Windows (`$HOME` → `%USERPROFILE%` → `%HOMEDRIVE%%HOMEPATH%`).

## 3. Rule file

The rules file is passed explicitly via `--rules <path>`. There is no hardcoded
default location; the caller (hook config or CLI user) always names the file.
The canonical reference rule set ships at `rules/permissions.json`.

### 3.1 Accepted shapes

Both of these parse identically:

```json
{ "permissions": { "allow": [...], "ask": [...], "deny": [...] } }
```

```json
{ "allow": [...], "ask": [...], "deny": [...] }
```

- Each of `allow`, `ask`, `deny` is an array of rule strings (§4). A missing
  array is treated as empty.
- `defaultMode` is **honored** as the fall-back decision for calls that match no
  rule (§6.4): `"ask"` → `ask`; `"deny"`, a missing key, or any other value →
  `deny` (fail-closed). (The native Claude Code value `"default"` therefore maps
  to `deny`.)
- Any other keys in the object (including Claude Code settings such as
  `disableAutoMode`, `disableBypassPermissionsMode`) are **ignored**. The engine
  reads only the three tier arrays and `defaultMode`. (The file may double as a
  Claude Code settings file; permcheck simply ignores what it does not own.)
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
- **Specifier** is everything between the first `(` and the final `)`; it must be
  at least one character. `Tool()` (empty specifier) is a **load error**: an
  operator who writes a deny that way must be told, not silently ignored.
- A specifier that cannot be compiled into a matcher (§6) is a **load error →
  deny**. Bad rules fail at load, never at decision time.

## 5. Tool taxonomy and payload extraction

**Every tool call is evaluated, not just `Bash`** — no tool bypasses the engine.
Each tool is routed to one of three matcher families by its name; the **payload**
(the string that gets matched) is extracted from `tool_input` as below.

| Family | Tools | Payload |
|---|---|---|
| **Bash** | `Bash` | `command` (then split and cross-checked, §8) |
| **Path** | `Read`, `Write`, `Edit`, `Glob`, `Grep`, `NotebookEdit` | `file_path` (`NotebookEdit`→`notebook_path`); `Glob`/`Grep`→`path`, fallback `pattern` |
| **Generic** | **every other tool**: `WebFetch`, `WebSearch`, `SlashCommand`, `Task`, and all MCP `mcp__*` tools | `WebFetch`→`url`; `WebSearch`→`query`; `SlashCommand`→`command`; otherwise the **lexicographically-first** (by field name) non-empty string field of `tool_input`, else the empty string |

Routing rules:

- The **Path** family gets glob semantics (§6.5); the **Generic** family gets
  URL/string semantics (§6.5). Any built-in or MCP tool the engine does not name
  explicitly falls into **Generic** and is still evaluated; the taxonomy has no
  gaps.
- A rule's tool name must equal the call's tool name exactly, so
  `mcp__github__create_issue(...)` rules apply only to that MCP tool, and
  `NotebookEdit` is not covered by a bare `Edit` rule (different tool name).
- **Tools with no string payload** (e.g. `TodoWrite`, `ExitPlanMode`) extract the
  empty string, so only a **bare** rule (`TodoWrite`) matches them; absent one
  they take the **`defaultMode` fall-back** (§6.4). Give always-on benign tools an
  explicit bare `allow` so they are neither blocked nor prompted.

## 6. Specificity, matching, and precedence

### 6.1 Specificity score

Every matched rule carries a specificity score so a narrow rule can beat a broad
one:

```
specificity = (count of literal, non-wildcard characters in the specifier)
            + (1000 if the specifier contains no wildcard at all)
```

- Wildcards are `*` for all families, plus `?` for the Path family.
- A **bare rule** has specificity `0`.
- The `+1000` exact-match bonus guarantees a literal specifier outranks any
  wildcard specifier, regardless of length.

### 6.2 Tier ordering

Tiers are ordered `Allow < Ask < Deny`. Deny is the most restrictive and the
highest rank; this ordering is the tie-break in §6.3.

### 6.3 Winner selection (single unit)

For a given payload, gather **every** matching rule across the tool's matchers
(including any bare rule at specificity `0`). Each hit contributes
`(specificity, tier)`. The winner is the rule with the maximal `(specificity,
tier)` pair, compared lexicographically:

1. Higher **specificity** wins.
2. On equal specificity, higher **tier** wins, so `deny` beats `ask` beats
   `allow` (most-restrictive-wins).
3. On a full tie (equal specificity and tier), the **first rule in file order**
   is reported, for a stable, deterministic decision.

This single-pass selection is the **entire** decision for Path and Generic tools
(Read, Write, Edit, Glob, Grep, NotebookEdit, WebFetch, WebSearch, MCP, …). Only
`Bash` adds a step: it first decomposes the command into units (§8) and applies
this selection per unit.

### 6.4 Default decision

If no rule matches, the decision is the rule set's **fall-back tier**, configured
by `defaultMode`: `"ask"` makes an unlisted call **ask**; otherwise (`"deny"`,
missing, or any other value) it is **deny** (fail-closed default). This fall-back
governs only the *no rule matched* case. It does **not** loosen the Bash
file-access cross-check (§8), which still raises to `deny` on a hit, nor the
error posture (§9.1) — bad rules, unparseable input, an unknown tool, or a panic
are always `deny`, independent of `defaultMode`.

### 6.5 Matching semantics per family

**Bash.** A specifier is an anchored, full-string pattern over the command:

- The trailing form `cmd:*` matches the command `cmd` plus any
  whitespace-delimited arguments (i.e. `cmd` alone, or `cmd <args>`).
- `*` anywhere else in the specifier matches any run of characters.
- Every other character is matched literally.
- Matching is anchored to the whole (trimmed) command string, with no substring
  matches.

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

The three tiers interact by specificity first, then tier:

- A pattern that appears in **no** list falls back to the `defaultMode` tier —
  `deny` by default, or `ask` when configured (§6.4).
- The **same** specifier in several tiers → the **most restrictive** tier wins.
  `Bash(aws:*)` in `allow`, `ask`, and `deny` (all specificity 3) → `deny`.
- A **more specific** rule beats a broader one across tiers, in either
  direction: a narrow `allow`/`ask` overrides a broad `deny`, and a narrow
  `deny` overrides a broad `allow`. With `Bash(aws:*)` (deny, 3) and
  `Bash(aws * describe-*)` (allow, 14), the `describe-*` calls are **allowed**
  and every other `aws …` call is **denied**.

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

A single Bash `tool_input.command` may contain several commands. The engine
decomposes it and takes the **most restrictive** verdict.

1. **Split into units** on shell operators outside quotes: `&&`, `||`, `|`, `;`,
   `&`, and newlines. Pull inner commands out of command substitutions
   `$(…)`, backticks `` `…` ``, and process substitutions `<(…)` / `>(…)`,
   including inside double quotes. `$((…))` arithmetic is literal. Single quotes
   suppress expansion. The splitter is total: it never errors; unterminated
   constructs are consumed to end of input.

2. **Per unit**, strip leading `NAME=value` environment assignments, then decide
   the trimmed unit string against the Bash matchers via §6.3. Additionally, if
   the unit begins with a **wrapper command** (`env`, `sudo`, `timeout`, `nice`,
   …), peel the wrapper and its options / assignments / numeric args and decide
   the wrapped command too, taking the most restrictive of the two. This runs
   the wrapped command's own rules, so `env aws …` cannot ride in on a broad
   `Bash(env:*)` allow and bypass an `aws` deny. It only ever raises the verdict.

3. **File-access cross-check** (raises to `deny` only; never loosens): tokenize
   the unit, peel wrapper commands (`sudo`, `env`, `timeout`, `nice`, …), then:
   - if the command is a known **reader** (`cat`, `grep`, `sed`, `head`, …),
     check each non-option operand against the `Read` **deny** rules
     (pattern-first readers like `grep`/`sed`/`awk` skip their first operand,
     which is a pattern, not a file);
   - if it is a known **writer** (`tee`, `dd`, `truncate`, …), check operands
     against the `Write`/`Edit` deny rules;
   - check redirection targets: `<` against `Read` deny, `>` / `>>` / `&>` /
     `&>>` against `Write`/`Edit` deny; `>&word` / `>>&word` where `word` is a
     filename (not an fd number) also count as a write. Pure fd dups/closes like
     `2>&1`, `>&2`, `>&-` are skipped.

   A cross-check hit raises that unit's verdict to `deny`. This catches
   `cat .env` even though `Bash(cat:*)` is allowed.

4. **Aggregate**: the command's verdict is the most restrictive unit verdict
   (the first unit that reaches the maximal tier). The emitted reason echoes the
   whole command, not the individual unit.

## 9. Fail-closed and non-goals

### 9.1 Fail-closed

- Every fallible load step returns a result; invalid rules fail at **load →
  deny**. There is no evaluation-path code that can panic on runtime input.
- Hook mode wraps evaluation so that any unexpected panic becomes `deny`.
- Unreadable/invalid rules file, unparseable stdin, or an unknown/unmapped tool
  → `deny` (hook) or exit `3` (CLI, config errors only).

### 9.2 Non-goals (documented limitations)

The Bash analyzer is a best-effort scanner, not a full shell parser. These are
out of scope and left to the OS sandbox and enterprise denies:

- `eval`, shell aliases/functions, dynamic variable expansion, and commands
  assembled at runtime.
- `dd if=/of=` key-value targets are not unwrapped.
- Commands assembled by `xargs` from stdin are not followed.
- `#` comments and heredoc bodies are not modeled (biases toward over-deny, the
  safe direction).
- **Path-glob matching is not hardened against catastrophic backtracking.** The
  matcher is a plain recursive backtracker; a specifier with many interacting
  wildcards (e.g. `/*a*a*a*a*a*a*a*b`) can be super-linear in the path length.
  This is acceptable because rule specifiers are **trusted operator config**, not
  attacker input — the rule file is the source of truth. Payloads (paths) are
  bounded and realistic rules use at most a few wildcards, so matching stays in
  microseconds.

When the analyzer cannot understand a construct, it errs toward `deny`.

## 10. Worked examples

Drawn from the reference rule set `rules/permissions.json` (deny `Bash(aws:*)`,
`Bash(kubectl:*)`, `Bash(git push --force:*)`, bare `WebFetch`, bare `WebSearch`;
allow `Bash(cat:*)`, `Bash(python3 *)`, bare `Read`; ask `Bash(git push:*)`;
`defaultMode: "ask"`, so a call matching no rule falls back to `ask`, §6.4). The
reference set carries **no** narrow `aws`/`kubectl` read-only allows, so those
commands are governed by the broad deny; git read commands (`git status`,
`git diff`, …) have no explicit rule and take the ask fall-back.

| Tool call | Decision | Why |
|---|---|---|
| `Bash(aws ec2 describe-instances)` | deny | only `aws:*` deny matches; no narrower allow |
| `Bash(aws s3api list-buckets)` | deny | only `aws:*` deny matches |
| `Bash(aws ec2 terminate-instances)` | deny | only `aws:*` deny matches |
| `Bash(kubectl get pods)` | deny | only `kubectl:*` deny matches |
| `Bash(kubectl delete pod x)` | deny | only `kubectl:*` deny matches |
| `Bash(git push origin main)` | ask | `git push:*` is in `ask` |
| `Bash(git push --force origin)` | deny | `git push --force:*` (16) beats `git push:*` ask (8) |
| `Bash(git status)` | ask | no rule matches → `defaultMode: "ask"` fall-back (§6.4) |
| `Bash(cat .env)` | deny | file-access cross-check hits a `Read` `.env` deny even though `cat:*` is allowed (§8) |
| `Read(/tmp/notes.txt)` | allow | bare `Read` (allow, specificity 0); no secret-path deny matches |
| `WebFetch(https://x.io)` | deny | bare `WebFetch` deny matches; nothing more specific allows |
| `WebSearch(anything)` | deny | bare `WebSearch` deny matches (non-Bash tools are evaluated too) |
| `mcp__db__query(SELECT …)` | ask | Generic family; no rule names this MCP tool → ask fall-back |
| `NotebookEdit(/repo/nb.ipynb)` | ask | Path family, but no `NotebookEdit` rule and bare `Edit` does not cover it → ask fall-back |
| `Bash(some-tool foo)` | ask | no Bash rule matches → ask fall-back |
| `Bash(python3 -c "import os")` | allow (see §11) | `python3 *` allows it; no `-c` deny exists |

Two rows show both directions of the design: an active protection (`cat .env`)
denies regardless of the fall-back, while a broad allow the rules do not narrow
(`python3 -c`) lets code through (§11).

## 11. Appendix: known issues in the reference rule set

These are **authoring issues in `rules/permissions.json`**, not engine defects.
The engine faithfully applies §5–§8; each item below is a case where the rules
do not express what an operator likely intends — cautionary patterns and a
correction backlog for the reference file.

1. **Arbitrary-execution / secret bypasses.** `Bash(python3 *)` and
   `Bash(.venv/bin/python *)` allow `python3 -c "<code>"`, which sidesteps the
   whole deny list; only `python3 -m http.server` is denied. `Bash(env:*)` /
   `Bash(printenv:*)` can print secrets from the environment. `Bash(gh:*)` is
   broad (`gh auth token`, `gh extension`). *Pattern:* pair any broad
   interpreter/tool allow with denies for its exec/secret subforms
   (`Bash(python3 -c:*)`, `Bash(gh auth:*)`), or move it to `ask`.

2. **Dead / redundant under command-splitting.** *Pattern:* one rule per simple
   command; never put shell operators in a specifier — a specifier like
   `Bash([ ! -d * ] && gh repo clone *)` contains `&&`, and §8 splits on `&&`
   before matching, so no unit ever contains it and the rule can never fire.
   (The reference set previously shipped such rules; they have since been removed.)

3. **Coverage gaps / asymmetries.** `Bash(cp -R:*)` is allowed but plain
   `cp a b` matches no rule and takes the `defaultMode: "ask"` fall-back.
   `Bash(rm -rf:*)` / `Bash(rm -f:*)` miss `rm -fr`, `rm -Rf`, `rm --force`
   (which then hit the `rm:*` **ask**). *Pattern:* match the base command, then
   add explicit denies for every destructive flag spelling/variant.

4. **`gcp` vs `gcloud`.** `Bash(gcp:*)` denies a command named `gcp`, but the
   real GCP CLI is `gcloud` (also `gsutil`, `bq`), so the deny matches nothing —
   `gcloud …` matches no rule and takes the `ask` fall-back rather than being
   denied. *Pattern:* `Bash(gcloud:*)` deny plus read-only allows
   (`Bash(gcloud * list:*)`, `Bash(gcloud * describe:*)`), mirroring aws/kubectl.

5. **Bare path-tool allows shift the default.** Bare `Read` / `Edit` / `Write`
   (specificity 0) are in `allow`, so those tools default to **allow** (minus
   the specific secret-path denies). Unmatched Bash and Generic calls instead
   take the `defaultMode` fall-back — `ask` in this reference set (§6.4). Both
   are intended, but worth stating explicitly.

6. **Hygiene (harmless, noisy).** `Read(/**/.env*)` subsumes `Read(/**/.env.*)`;
   `.bash_history` / `.zsh_history` are denied twice; path root markers mix
   `//**/`, `/**/`, and `**/`, which changes absolute-vs-relative anchoring.
   Dedupe and standardize markers alongside matcher tests.
