# Security Model

permcheck is defense in depth. It is not a sandbox and not the security boundary.

The OS sandbox and Claude Code enterprise `managed-settings.json` remain the security boundary. permcheck runs as a Claude Code `PreToolUse` hook and returns a permission decision for one tool call at a time.

## Native Permissions Still Apply

permcheck only tightens. It does not open a native `deny` or bypass a native `ask` in Claude Code settings.

Claude Code enforces native user and enterprise permission rules regardless of what a hook returns. A permcheck `allow` therefore cannot loosen a native `deny`.

For predictable behavior, keep conflicting native `deny` and `ask` entries out of `settings.json` and `managed-settings.json`, or account for them explicitly. You own the policy across all three sources:

- enterprise `managed-settings.json`
- user or project `settings.json`
- `permcheck.json`

permcheck enforces the rules you write. It does not infer intent or repair an overly broad policy.

## Engine And Ruleset

The engine takes one tool call plus your rules and returns one verdict: `allow`, `ask`, or `deny`. It is deterministic and stateless. It never executes the call, mutates state, or writes policy.

The ruleset holds policy. A command, path, or tool that no rule covers is a policy gap. Close that gap by adding a rule.

For example, to stop in-place edits against protected files, add rules such as:

```json
"deny": ["Bash(sed -i:*)", "Bash(perl -i:*)"]
```

The engine owns path canonicalization because rules cannot express it. It expands `~`, absolutizes relative paths against the call's `cwd`, and collapses `.` and `..` in the incoming call before comparing path rules.

## Bash Compound Safety

A single `Bash` command often contains multiple commands. permcheck applies extra checks:

- It splits shell chains on operators such as `&&`, `||`, `|`, `;`, `&`, newlines, `(`, and `)`.
- It extracts commands inside `$(...)`, backticks, process substitution, and common wrappers.
- It applies the most restrictive verdict across the extracted units.
- It checks known file readers, writers, `dd`, selected `curl` and `wget` file forms, and redirection targets against Path-family deny rules.
- It re-decides through wrappers such as `env`, `sudo`, `timeout`, `nice`, and `time`.

This catches cases such as:

```sh
ls && sudo rm -rf /
cat .env
env aws ec2 terminate-instances ...
```

The Bash analyzer is a best-effort scanner, not a full shell parser. Unsupported constructs still rely on literal rule matching and `defaultMode`. Non-goals such as `eval`, aliases, and `xargs`-assembled commands are documented in [`specs/SPEC.md`](../specs/SPEC.md).

## Flag Spellings

permcheck matches each command in normalized form as well as verbatim. It handles cases such as:

- `/usr/bin/aws` as `aws`
- `git -c x=y config` as `git config`
- `rm -rf /`, `rm -fr /`, and `rm -Rf /` as the same short-flag escalation form
- `perl -we` as `perl -e`
- `node --eval` as `node -e`

It does not treat long and short options as equivalent. `--force` and `-f` are program-specific, so write both forms when needed:

```json
"deny": ["Bash(rm -f:*)", "Bash(rm --force:*)"]
```

The engine does not invent flags you did not write, enumerate flag subsets, or infer which options consume values.

## Path Spellings

The engine normalizes the incoming call, not your rule.

A path operand is expanded, absolutized against the call's `cwd`, and collapsed. That resolved form only raises a verdict to `deny`; it never grants an `allow`.

Consequences:

- An absolute deny covers relative spellings that resolve into it.
- An allow covers only the spelling you wrote.

To allow both absolute and relative spellings for a directory, name both:

```json
"deny":  ["Bash(rm -rf /*)"],
"allow": ["Bash(rm -rf /home/me/src/myproject/.scratch/*)",
          "Bash(rm -rf .scratch/*)"]
```

Use the absolute form when you need one exact directory. Use the relative form when policy should move across checkouts.

## Resource Bounds

Policy files are limited to 1 MiB, 4,096 rules, and 1,024 bytes per rule.

Runtime payloads are limited to 32,768 bytes. A Bash command is limited to 1,024 split units. One glob match is limited to two million text/pattern state visits.

Exceeding a policy bound is a load error. Exceeding a runtime bound returns `deny`.
