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

- **Output** (stdout, JSON), **exit 0** whenever the decision is written:

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

  An `ask` or `deny` reason additionally carries a parenthesized clause naming what
  produced it, because `permissionDecisionReason` is the only field Claude Code
  reads back and so the only place a block can be explained. Without it, a policy
  hole and a policy decision are indistinguishable: `deny: ls | frobnicate` and
  `deny: ls | sudo whoami` differ only in which one means the allow list is short
  an entry. The clause names the deciding statement when the payload split into
  more than one, and then what decided it:

  ```
  deny: ls; sudo whoami (statement 2 of 2: "sudo whoami" matched Bash(sudo:*))
  deny: ls | frobnicate (statement 2 of 2: "frobnicate" no rule matched, defaultMode=deny)
  deny: command sudo whoami (wrapper stage "sudo whoami" matched Bash(sudo:*))
  deny: cat .env (reaches denied path ".env" via Read(//**/.env))
  ask: figlet hello (no rule matched, defaultMode=ask)
  allow: ls -la
  ```

  `allow` never carries a clause: nothing needs explaining. Quoted fragments are
  clipped, so an oversized payload cannot produce an oversized reason.

- **Fail-closed**: any error (unparseable stdin, unreadable/invalid rules file, a
  missing or empty `tool_name`, or an internal panic) yields `deny` (still exit
  0). An unrecognized non-empty tool name is not an error: it routes to Generic
  (§5) and uses its matching result or the `defaultMode` fall-back (§6.4). The
  hook never crashes the tool call open.

- **Undeliverable decision**: if the decision cannot be written to stdout (a
  broken pipe, for instance), the verdict falls back to the exit-code channel and
  the process exits `2`, which Claude Code treats as a blocking error. Exiting
  `0` there would report a decision that never arrived, and any other non-zero
  code reads as a non-blocking error and lets the call through.

### 2.2 CLI: direct check

Invoked as `permcheck <Tool> [payload] --rules <path> [--json]`.

- `payload` is the tool's primary input string (a Bash command, a file path, a
  URL, …). If omitted, the tool is checked with an empty payload.
- Exit codes: `0` = allow, `1` = ask, `2` = deny, `3` = config/usage error
  (bad arguments, unreadable or invalid rules file). An unrecognized long flag
  is a usage error, and so is invoking with no arguments; `-h`/`--help` prints
  usage to stdout and exits `0`.
- **Mode selection reads only the leading flags**, those before the first
  positional argument. In check mode the first positional is the tool name, so a
  mode flag after it (`permcheck Bash "--install" …`) is payload text, not a
  request to install, uninstall, seed rules, or enter hook mode. A value-taking
  flag (`--rules`, `--init-rules`) consumes the token after it, so that token is
  not the first positional.
- A bare `--` ends option parsing: every later argument is positional, so a
  payload that starts with dashes stays checkable
  (`permcheck Bash --rules <path> -- --install`).
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
  re-point refusal above also covers a hand-wired hook. Writes to `settings.json`
  are atomic: a per-process temp file, flushed with `sync_all`, then `rename` over
  the target. A missing/empty file starts from `{}`, and a present-but-non-object
  file is refused rather than clobbered.

  Writes to a **rules** file never replace, because every one of them is a
  create-if-absent path (`--init-rules`, `--install` seeding, `--install --rules`
  copying) whose whole point is to leave an existing policy alone. The refusal is
  the creation itself rather than a preceding existence check, so a file that
  appears between the two is reported (exit `3`) instead of overwritten. Both exit `0` on success (or when already in
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

- **Bare rule**: `Tool` matches any payload for that tool. `Tool` may be an
  exact name, a terminal-star prefix selector (`mcp__serena__*`), or `*`.
- **Specifier rule**: `Tool(specifier)` matches payloads of that tool per the
  tool's matching semantics (§6).

Rules:

- An exact **tool name** matches `[A-Za-z][A-Za-z0-9_]*`. A bare rule may use
  one terminal `*`, including `*` by itself. Tool wildcards are prefix-only and
  bare: `mcp__*__read` and `mcp__serena__*(path)` are load errors. This narrow
  grammar covers Claude Code's MCP grouping idiom without applying one payload
  matcher across several tool families.
- **Specifier** is everything between the first `(` and the final `)`, and it must be
  at least one character. `Tool()` (empty specifier) is a **load error**: an
  operator who writes a deny that way must be told, not silently ignored.
- A specifier that cannot be compiled into a matcher (§6) is a **load error →
  deny**. Bad rules fail at load, never at decision time.
- A `Bash(cmd:*)` prefix with edge whitespace or an interior `*` remains valid
  and is evaluated literally. The author-time linter warns because those forms
  are often mistakes, but the engine neither rewrites nor rejects valid rules
  based on inferred intent.
- Policies are bounded at 1 MiB, 4,096 rules, and 1,024 bytes per rule. Exceeding
  a bound is a load error.

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
- "Lexicographically-first" is by **byte order of the field name**, computed from
  the names themselves. It is not whichever field a JSON map happens to yield
  first, so the payload a tool call resolves to does not depend on how the JSON
  object is built or ordered.
- An exact selector must equal the call's tool name. A terminal-star selector
  matches names with that prefix, so `mcp__serena__*` covers Serena's tools but
  not `mcp__github__read_file`. `NotebookEdit` is not covered by bare `Edit`.
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
  subset of the deny, does override it. Grammar and resource checks happen at
  load (§4); containment remains conservative at decision time.

Tool selectors carry a separate, leading specificity component: an exact tool
name gets the exact-match bonus and outranks a matching terminal-star selector;
among terminal-star selectors, the longer literal prefix is more specific. This
component matters only when exact and wildcard tool rules overlap. Containment
and carve-outs include both the selector language and payload language, so an
exact MCP-tool rule is a strict subset of a matching `mcp__server__*` bare rule.

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
   `(tool specificity, payload specificity, tier)`, maximal lexicographically:
   a narrower selector first, then higher payload specificity, then
   higher tier (`ask` over `allow`), then the first rule in file order for a
   stable, deterministic decision.

The subset test is **sound but conservative**: it reports a carve-out only when
containment is proven, and otherwise keeps the deny, so an unprovable case fails
toward `deny` (§9.2). One shape reaches that fall-back in practice: the test reads
a deny's `**/` without the collapse-to-zero-directories rule §6.5 gives the
matcher, so `Read(/b)` is not proven to sit inside `Read(/**/b)` even though the
matcher agrees that it does, and the deny stands. Write the allow against the
spelling the deny uses when the carve-out is intended.

This selection is the **entire** decision for Path and Generic tools (Read,
Write, Edit, Glob, Grep, NotebookEdit, WebFetch, WebSearch, MCP, …). Only `Bash`
adds a step: it first decomposes the command into units (§8) and applies this
selection per unit.

### 6.4 Default decision

If no rule matches, the decision is the rule set's **fall-back tier**, configured
by `defaultMode`: `"ask"` makes an unlisted call **ask**, and otherwise (`"deny"`,
missing, or any other value) it is **deny** (fail-closed default). A value that is
present but neither `"ask"` nor `"deny"` still resolves to `deny`, and the
author-time linter reports it (§11.2): Claude Code's `permissions.defaultMode`
accepts session modes such as `"dontAsk"` and `"acceptEdits"` under the same key
name, so a value copied from `settings.json` would otherwise change the fall-back
without saying so. This fall-back
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

### 7.1 Candidate forms

To match reliably regardless of how the caller wrote the payload, the engine
matches the specifier against **candidate forms** of the payload, and a hit on
any form counts:

- **Path**: the raw payload, its `~`-expanded form, its `cwd`-absolutized form
  (so a bare `.env` matches a rule written for an absolute path), and each of
  those with `.` and `..` segments lexically collapsed (§7.2).
- **Generic/URL**: the raw payload and the host extracted from a
  `scheme://[user@]host[:port]/…` URL (plus a lowercased host, since domains are
  case-insensitive).
- **Bash**: the identity and escalation forms of each unit (§8 step 2), which
  include a form with every path operand resolved the same way a Path payload is.

Only the **payload** is resolved. A rule specifier compiles exactly as written,
because a wildcard in a specifier matches arbitrary text, and cancelling a `..`
against text that could be anything is unsound.

### 7.2 Relative paths and traversal

A relative path payload is resolved against the hook event's `cwd` (or the
process CWD in CLI mode) before Path matching, so bare filenames are matched via
their absolute form. A `~`-leading payload is excluded from that join: `~` and
`~/…` expand via `$HOME` (§6.5), and `~user` stays literal, because it names
that user's home, not a file under the `cwd`, and the engine has no way to
learn another user's home. Bash path operands (§8 step 2) follow the same rule.

`.` and `..` segments are then collapsed **lexically**, so a traversal spelling
cannot route around a directory-anchored rule: `/tmp/../etc/shadow` still hits
`Read(/etc/**)`. An absolute path stays rooted and a `..` at the root is dropped;
a relative path keeps a leading `..` it cannot cancel. Resolution never touches
the filesystem, so symlinks are not followed (§9.2).

On Windows, `\` folds onto `/` and a drive-letter root gains a leading `/`, so
`D:\proj\.env` matches a rule written `/**/.env*`. A **drive-relative** payload
(`C:notes.txt`, which Windows reads as `notes.txt` under the current directory on
drive C, not as `C:\notes.txt`) anchors under `/C:/` rather than as `/C:notes.txt`,
which would match no `/C:/**` rule at all. Its exact directory is knowable only
from the call's `cwd`, so when that `cwd` names the same drive it contributes the
resolved form as an additional candidate; a `cwd` on a different drive contributes
nothing.

## 8. Bash compound decision

A single Bash `tool_input.command` often contains several commands. The engine
decomposes it and takes the **most restrictive** verdict.

1. **Split into units** on shell operators outside quotes: `&&`, `||`, `|`, `;`,
   `&`, newlines, and the subshell delimiters `(` and `)`. Pull inner commands out
   of command substitutions
   `$(…)`, backticks `` `…` ``, and process substitutions `<(…)` / `>(…)`,
   including inside double quotes and inside `$((…))` arithmetic expansion, whose
   contents bash expands before evaluating them.

   A `|` immediately after `>` belongs to the **redirection**, not to the pipe:
   `>|` overrides `noclobber` and writes exactly as `>` does. Read as a pipe it
   would cut the unit before the target, leaving the write with no cross-check
   (§8.3) and a reason that does not name the file being overwritten.

   A `(` is a delimiter only in **command position** (at unit start, or after
   whitespace or another operator), which is the only place bash reads one as a
   subshell opener. Elsewhere it is word content, so an array assignment
   (`arr=(a b)`) and a format specifier (`--format=%(refname)`) keep their shape
   instead of fragmenting into units that match no rule. A `)` always closes a
   unit. Without this, a subshell stayed one unit whose first word was `(sudo`,
   and every Bash deny was one paren away from being evaded, while the same
   command written `$(sudo …)` was caught. A bare `((…))` arithmetic *command*
   therefore contributes its interior as a unit, which reaches no rule and lands
   on `defaultMode`, the verdict the undivided spelling already got.

   Single quotes
   suppress expansion. An unquoted `#` that starts a word (at unit start or after
   whitespace or an operator) opens a comment; it and the rest of the line are
   dropped, as bash does, so a comment cannot feed matched text. A `#` inside a
   word (`feature#123`) or inside quotes is literal. The splitter is total: it
   never errors, and unterminated constructs are consumed to end of input.
   Substitution nesting is bounded: past a fixed depth (far above any real
   command) the splitter stops descending and the command is **denied**, since a
   partial split could miss a denied inner command (§9.1). Arithmetic expansion
   counts against that same depth, because scanning its contents means recursing
   on them and nested `$((` recurses directly.

   Splitting a conditional, loop, or group leaves its **closer** as a unit of its
   own (`fi`, `done`, `esac`, `}`), and an assignment with no command (`FOO=bar`)
   is a unit too. Neither runs anything, so neither is decided (§8 step 4).

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
        (`/usr/bin/aws …` → `aws …`). On Windows the name also loses a `PATHEXT`
        suffix (`rm.exe` → `rm`) and gains a case-folded spelling
        (`RM.EXE` → `rm`), because the filesystem resolves an executable by
        either. POSIX keeps the name byte-exact, where `rm.exe` is a different
        file. The fold stops at the command **word**: bash does not fold
        arguments, so `git PUSH` is not `git push` on any platform, and shell
        keywords stay byte-exact too.
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
     its single-flag rule while retaining later operands (`rm -Rf /` / `rm -fr /`
     / `rm -r -f /` → `rm -f /`), and an
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

     A **path-operand** form resolves every operand that names a path to the path
     it really names, exactly as a Path payload is resolved (§7.1, §7.2), and
     re-decides the rebuilt command. The shared shell-word lexer retains raw spans
     alongside dequoted values, so a quoted operand containing whitespace remains
     one path while the command is rebuilt. An operand names a path when it starts
     like a filename, is not a `scheme://host/path` URL, and either carries a
     `.`/`..` segment, a separator, a leading `~`, or (on Windows) a drive prefix.
     A long `--option=value` word resolves a path-like `value` while retaining the
     option name. Other options, redirections, and operators are skipped. Anything
     else is left exactly as written, so an ordinary command produces no extra
     form. The form needs no per-command vocabulary, so it covers `rm`, `tar`, and
     every other command alike.

     It closes two gaps a text-only match leaves open.

     - A **traversal** spelling riding a narrow allow past a broad deny.
       `rm -rf /w/.scratch/../src` matches an allow written for `/w/.scratch/*` as
       raw text, but its resolved form is `rm -rf /w/src`, which the allow does not
       match and a deny on the tree does.
     - A **relative** rule meaning more than it says. A Bash specifier matches
       command text, so `Bash(rm -rf .scratch/*)` matches `rm -rf .scratch/x` from
       any directory, granting deletion of every `.scratch` on the machine rather
       than the project's. Absolutizing the operand against the call's `cwd` puts
       the real target in front of the rules, so the same command resolves to
       `/w/.scratch/x` inside the project and to `/tmp/.scratch/x` outside it,
       where a deny on the tree catches it.

     Because this is an escalation form it only ever raises a verdict, so an
     operand the resolver misjudges costs a wasted candidate, never a false allow.

     That also decides what a specifier's own path spelling covers, which is the
     rule author's choice to make. A deny anchored at an absolute path reaches both
     spellings, because the resolved operand lands on it. An `allow` reaches only
     the spelling it names, because resolution can raise a verdict and never grant
     one: a relative command does not reach an absolute allow. Naming both
     spellings permits both.

   Additionally, if the unit begins with a **wrapper command** (`env`, `sudo`,
   `timeout`, `nice`, `time`, `xargs`, `builtin`, …) or a **shell reserved word**
   (`{`, `!`, `if`, `then`, `elif`, `else`, `while`, `until`, `do`, `coproc`),
   peel it and decide the command behind it too, taking the most restrictive. A
   wrapper's options, assignments, and numeric args are peeled with it; a
   reserved word takes no options, so only the word itself is dropped, which
   leaves a condition's own operands intact. The two interleave
   (`! time env sudo …`).

   A wrapper option whose value is a **separate token** is ambiguous, and both
   readings are peeled: the value belongs to the option, or the option took none
   and the value heads the command. Consuming alone would hide the command behind
   `timeout -s KILL 5 rm -rf /`; consuming nothing hides it behind every such
   option. The engine carries each wrapper's value-taking options as a table, but
   the table cannot be authoritative on its own, since `sudo -h` is both `--help`
   and `--host=host` and GNU `xargs -e`/`-i` take an *optional* value. Deciding
   both readings makes a wrong or missing entry cost one extra stage rather than
   a missed deny. A value the argument peel already absorbs (`-n 5`) never headed
   a command, so it contributes no second reading.

   This runs the wrapped command's own rules, so `env aws …` cannot ride in on a
   broad `Bash(env:*)` allow and bypass an `aws` deny, and `{ sudo …; }` cannot
   escape the `sudo` deny by wearing a group opener. Peeling reads the
   fully-normalized spelling from the pipeline above, so a disguised wrapper
   (`"env" aws …`) is still recognized as one.

   Peeling runs **one stage at a time**, and every stage is decided, not only the
   command left at the end. A Bash specifier matches at the head of a unit, so a
   rule naming a wrapper (`Bash(sudo:*)`) fires only while that wrapper is the
   first word: peeling `command sudo …` straight through to the innermost command
   would leave the `sudo` deny with nothing to match. Deciding each stage puts
   every peeled word back at a head. This matters for ordinary shell, since §8.1
   hands the matcher `then sudo …` and `do sudo …` for the body of any `if` or
   `while`.

   Stages fold in with the same most-restrictive rule, and only `deny` ends the
   walk early. A stage that matches no rule reports the fall-back tier, which is
   indistinguishable from a rule that says `ask`, so stopping at `ask` would skip
   a later stage that denies. `deny` is the one verdict no further stage outranks.

   Each stage re-decides a suffix of the unit, so a unit of nothing but stacked
   wrappers costs work quadratic in its length. Stages are capped at **32** and a
   unit past the cap is denied rather than decided on the stages that fit (§9.1).

   The reserved-word list stops at words a command follows. `for`, `case`, and
   `in` are excluded because a variable or pattern follows them, and `fi`, `done`,
   `esac`, and `}` because nothing follows them. Words are matched after quote
   removal, so `'{' cmd` peels here though the shell would treat the quoted `{` as
   an ordinary command name. Peeling only raises a verdict, so that costs an
   over-deny on a command the shell would fail to find.

3. **File-access cross-check** (raises to `deny` only, never loosens): tokenize
   the unit, peel wrapper commands (`sudo`, `env`, `timeout`, `nice`, `time`,
   `xargs`, …) and leading reserved words, then, for each reading the wrapper
   option arity leaves open (§8 step 2), with the command name resolved the same
   way the identity forms resolve it:
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
   whole command, and names the deciding unit in its clause (§2.1).

   A unit that **runs no command** is not decided and contributes nothing: a
   closer or bare reserved word from §8 step 1, or an assignment husk. Charging
   those the `defaultMode` fall-back blocked a unit that never executes, which is
   invisible while the fall-back is `ask` and unconditional once an operator sets
   it to `deny`. No rule set can repair it, since nobody writes `Bash(fi:*)`.

   When *every* unit runs nothing, the command is **allowed**. The fall-back is
   for a command no rule named, not for a payload containing no command, so it
   does not apply and the answer does not depend on `defaultMode`. The same holds
   when the splitter yields no units at all, which happens only for whitespace, a
   bare separator, a comment, or an empty subshell. A comment ends at its newline,
   so a command on the next line is still a unit of its own and still decided:
   `# c` is allowed, `# c\nsudo …` is not.

   This is the only step that lowers a verdict, so it reads the **raw** spelling.
   `'fi'`, `"fi"`, `\fi`, and `./fi` all normalize to the word `fi` and `./fi`
   runs a program, so a skip keyed on the normalized word would drop a real
   command. Wrappers are never skipped either: `sudo` alone is an executable, and
   a rule naming it has to keep matching. Dropping an assignment husk is sound
   only because §8 step 1 already lifted any substitution in the value into a unit
   of its own, so `FOO=$(curl …)` still decides `curl …`.

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
- Work that grows faster than the input is capped the same way, since a hook that
  takes seconds to answer is a hook an operator turns off: wrapper peel stages are
  bounded at 32 per unit and a unit past the bound is denied (§8 step 2).
- Unreadable/invalid rules file, unparseable stdin, or a missing/empty tool name
  → `deny` (hook) or exit `3` (CLI, config errors only). An unrecognized
  non-empty tool name routes to Generic and is not an error (§5).
- Emitting the decision is itself fallible, so it is not left to a macro that
  panics on failure: a panic there would land outside the `catch_unwind` above
  and exit non-zero with no decision, which reads as a non-blocking error and
  lets the call run. A decision that cannot be written exits `2` instead (§2.1).
- Mode selection never reads the payload (§2.2), so a checked command string
  cannot steer permcheck into a state-changing mode.

### 9.2 Non-goals (documented limitations)

The Bash analyzer is a best-effort scanner, not a full shell parser. These are
out of scope and left to the OS sandbox and enterprise denies:

- `eval`, shell aliases/functions, dynamic variable expansion, and commands
  assembled at runtime. Quote and escape *removal* is normalized (§8 step 2),
  but the escape sequences inside `$'…'` are not decoded, so a name spelled
  `$'\x73udo'` is not reduced to `sudo`.
- Non-POSIX shells (PowerShell, `cmd.exe`): the splitter, reader vocabulary, and
  env-stripping model POSIX syntax and do not apply there, though Windows
  binaries ship. The Bash analyzer itself is **not** compiled out on Windows,
  since Claude Code runs bash there through Git Bash and MSYS; gating it would
  leave that build unable to match any `Bash(…)` rule. What is platform-gated is
  executable **naming** (§8 step 2): the `PATHEXT` suffix strip and the
  case-insensitive name comparison apply on Windows only, because on POSIX
  `rm.exe` is a different file and names are case-sensitive.
- Path resolution (§7.2) is purely **lexical**. Symlinks are not followed, so a
  link pointing out of an allowed directory reaches its target unseen, and a path
  the shell builds at runtime is resolved as the literal text it was written as.
  On Windows a backslash is both a path separator and the shell's escape
  character, and which one it is depends on the shell the command runs under.
  The engine resolves the command under both readings and takes the most
  restrictive, so the ambiguity over-denies rather than under-denies.
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
  `xargs rm -rf …`) is decided and cross-checked, including behind a
  separate-token replace string (`xargs -I {} …`), which is peeled under both
  readings (§8 step 2).
- The named coprocess form `coproc NAME compound-command` is not peeled. After
  the prefix is dropped the next word is the coprocess's name rather than a
  command, and nothing distinguishes the two lexically. The common unnamed form
  (`coproc cmd …`) is peeled.
- The reader **option** vocabulary (§8 step 3) is an enumeration, like the
  interpreter table. An option outside it whose value is a separate token leaves
  that value in the operand stream, where it is checked as if it were a path.
  That direction over-denies rather than under-denies, so an option is added to
  the table only when its value is mandatory and separable on every platform.
- Generic path-operand normalization understands positional path words and long
  `--option=path` forms. A command-specific attached short form such as `-Cpath`
  is not split generically because the same short flag has different arity and
  meaning across programs; use its separate-value or long form in policies that
  rely on path normalization, or cover the attached spelling explicitly.
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
- Matcher execution is bounded: Bash and Path globs use stackless NFA state
  propagation rather than recursive backtracking; tool payloads over 32,768 bytes
  deny before normalization/matching; Bash commands over 1,024 split units deny;
  a glob evaluation over two million text/pattern state visits denies. These
  bounds are intentionally family-agnostic and do not interpret command option
  semantics.

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
   suspect-rule form is a `Bash(cmd:*)` prefix with an interior `*` (literal in
   prefix form) or edge whitespace. `Bash(curl :*)` would fire only on a
   double-spaced `curl  x`, while a leading space cannot match a trimmed unit.
   These forms remain valid and retain their literal behavior; the linter warns
   without changing the result. The policy author chooses whether to use Bash
   glob form for an interior wildcard or remove edge padding.

   `RuleSet::lint_warnings` is the author-time linter, printed to stderr by the
   CLI checker and `--install` (never in hook mode). It reports two
   **weakening carve-outs** that loosen a broader restriction
   and are easy to write by accident: an `ask` whose match-set is a strict subset
   of a `deny` (the block silently becomes a prompt), and an `allow` whose match-set
   is a strict subset of a broader `ask` it outranks on specificity (the prompt
   silently becomes auto-allow). A narrow `allow` inside a `deny` is **not**
   flagged: that is the intended read-only carve-out. It also reports an
   **unrecognized `defaultMode`**: any value other than `"ask"` or `"deny"`, which
   §6.4 resolves to `deny`. The key name and the enclosing `permissions` object are
   the same shape Claude Code's `settings.json` uses, where `defaultMode` accepts
   session modes (`"dontAsk"`, `"acceptEdits"`, `"plan"`, `"auto"`,
   `"bypassPermissions"`, `"default"`). Such a value is fail-closed here but not
   what the author asked for, so the linter names it. The shipped reference set is
   clean under the check.

3. **Coverage gaps / asymmetries.** `Bash(cp -R:*)` is allowed but plain
   `cp a b` matches no rule and takes the `defaultMode: "ask"` fall-back. Short
   destructive-flag variants are normalized onto their single-flag rule while
   retaining operands (§8 step 2), so `rm -fr /`, `rm -Rf /`, and `rm -r -f /`
   all produce `rm -f /`. The **long-form** flags are still not mapped to their short equivalents
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
