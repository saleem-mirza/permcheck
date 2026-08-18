# Rules

Rules are passed explicitly with `--rules <path>`. There is no decision-time default rules file. The hook config or CLI command must name the file.

The canonical reference policy lives at [`rules/permcheck.json`](../rules/permcheck.json). `permcheck --init-rules` writes a separate starter policy, not the full reference set.

## File Shape

These forms parse identically:

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

`defaultMode` sets the fallback for calls that match no rule. Use `"ask"` to prompt. Any other value denies by default.

Unknown keys are ignored, so the rules work inside a Claude Code settings-shaped file.

## Rule Syntax

Each entry is a rule string:

- `Tool`: matches any payload for that tool.
- `Tool(specifier)`: matches according to that tool family's matcher.

Exact tool names match `[A-Za-z][A-Za-z0-9_]*`, including built-in tools such as `Bash` and `Read`, and MCP tools such as `mcp__server__tool`.

A bare selector also works with one trailing `*`, such as `mcp__serena__*`, or as `*` by itself. Tool globs are prefix-only and bare. `mcp__*__read` and `mcp__serena__*(path)` are load errors.

Bad rules fail when the rules file loads. In hook mode, that fails closed to `deny`. In CLI mode, it exits `3`.

## Tool Families

| Family | Tools | Payload | Matching |
| --- | --- | --- | --- |
| Bash | `Bash` | `command` | Anchored command pattern. Trailing `cmd:*` matches `cmd` plus args. `*` spans any run. |
| Path | `Read`, `Write`, `Edit`, `Glob`, `Grep`, `NotebookEdit` | `file_path`, `notebook_path`, or `path` | Glob syntax: `*`, `?`, `**`, `//` root marker, `~` expansion. |
| Generic | `WebFetch`, `WebSearch`, every `mcp__*`, and unknown tools | `url`, `query`, or first string field | Anchored domain or URL glob. `*` is the only wildcard. `domain:` is stripped. |

A leading `//` in a Path specifier is a root marker. `Read(//**/id_rsa*)` means an absolute-rooted glob, equivalent to `/**/id_rsa*`. The doubled slash in the reference policy is intentional.

## Carve-Out Precedence

For a tool call, permcheck gathers every matching rule and decides:

1. A narrower `allow` or `ask` carves out a broader matching `deny` only when its match-set is a strict subset of the deny.
2. Any matching `deny` that was not carved out wins.
3. Otherwise, the most specific matching `allow` or `ask` wins.
4. If nothing matches, `defaultMode` applies.

Identical specifiers do not carve each other out. For the same specifier, `deny` beats `ask`, and `ask` beats `allow`.

Examples:

| Tool call | Decision | Reason |
| --- | --- | --- |
| `aws ec2 describe-instances` | `allow` | `Bash(aws * describe-*)` is a strict subset of `Bash(aws:*)`. |
| `aws ec2 terminate-instances` | `deny` | Only `Bash(aws:*)` matches. |
| `kubectl get pods` | `allow` | `Bash(kubectl get:*)` carves out `Bash(kubectl:*)`. |
| `git push --force origin` | `deny` | `Bash(git push --force:*)` holds over broader `Bash(git push:*)`. |

These rows illustrate the mechanism. The shipped policy does not include the narrow `aws` or `kubectl` read-only allows. Add them to opt into that behavior.

A carve-out requires true containment. `allow Read(/**/passwd)` overlaps with `deny Read(/etc/**)`, but it is not a subset, so `/etc/passwd` stays denied.

## Lint Warnings

The CLI check and `--install` print author-time lint warnings to stderr. Hook mode does not.

A lint warning does not change evaluation. The rule still loads and runs as written.

Warnings include:

- `ask` inside `deny`: a block becomes a prompt, and the prompt is approvable.
- `allow` inside `ask`: a prompt is dropped for that narrower subset.
- Unusual `Bash(cmd:*)` forms: edge whitespace changes the command boundary, and an interior `*` is literal in prefix form.

A narrow `allow` inside `deny` is not warned about because that is the intended read-only carve-out pattern.

## CLI Checks

Use the CLI to test a policy:

```sh
permcheck <Tool> [payload] --rules <path> [--json]
```

Without `--json`, exit codes are:

| Exit | Meaning |
| --- | --- |
| `0` | allow |
| `1` | ask |
| `2` | deny |
| `3` | config or usage error |

With `--json`, the CLI prints the hook-format decision object and exits `0`.

Examples:

```sh
permcheck Bash "cat notes.txt"          --rules rules/permcheck.json
permcheck Bash "gcloud compute ..."     --rules rules/permcheck.json
permcheck Bash "kubectl delete pod x"   --rules rules/permcheck.json
permcheck Read "/home/user/.ssh/id_rsa" --rules rules/permcheck.json
```
