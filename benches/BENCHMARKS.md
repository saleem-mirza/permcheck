# Benchmarks

Measured on 2026-08-01 with `cargo bench` (Criterion) against
`rules/permcheck.json`, the canonical reference rule set, on a **MacBook Pro
(Apple M3 Max)**, macOS 26.5, release profile (`opt-level=z`, LTO, `strip`).
Numbers are rounded medians and are indicative. Re-run locally for your hardware.

Benchmarks are grouped by matcher family, plus the one-time rule-set load. Run
`cargo bench` to reproduce. Each case exercises a distinct decision path.

### Loading (one-time, per process)

| Case | What | Time |
|---|---|---|
| `load/reference_set` | parse + compile the whole reference set (50 allow · 18 ask · 181 deny) | ~81 µs |

### `bash`: winner selection, cross-check, wrapper re-decision, compound split (§6.3, §8)

| Case | Command | Decision | Time |
|---|---|---|---|
| `deny_aws_describe` | `aws ec2 describe-instances` | deny (broad `aws:*`, no narrow allow) | ~1.64 µs |
| `deny_kubectl_get` | `kubectl get pods` | deny (broad `kubectl:*`) | ~1.66 µs |
| `ask_git_status` | `git status` | ask (no rule → `defaultMode` fall-back) | ~2.42 µs |
| `ask_git_push` | `git push origin main` | ask | ~2.75 µs |
| `deny_aws_terminate` | `aws ec2 terminate-instances` | deny | ~1.76 µs |
| `deny_kubectl_delete` | `kubectl delete pod x` | deny | ~1.73 µs |
| `deny_git_push_force` | `git push --force origin main` | deny (narrow deny > broad ask) | ~1.69 µs |
| `ask_unknown` | `some-tool --flag` | ask (`defaultMode` fall-back) | ~2.57 µs |
| `crosscheck_cat_env` | `cat .env` | deny (literal file-access cross-check) | ~2.60 µs |
| `crosscheck_cat_glob` | `cat .en?` | deny (shell-glob intersection) | ~3.26 µs |
| `crosscheck_redirect` | `echo hi > …/.ssh/authorized_keys` | deny (redirect cross-check) | ~5.29 µs |
| `wrapper_env_aws` | `env aws ec2 terminate-instances` | deny (wrapper re-decision) | ~2.66 µs |
| `compound_and` | `cd /tmp && ls -la` | ask (2 units) | ~7.47 µs |
| `compound_pipe` | `cat file.txt \| grep something` | allow (2 units, both cross-checked) | ~8.48 µs |
| `compound_subshell` | `echo $(kubectl delete pod x)` | deny (substitution extracted) | ~1.79 µs |

### `path`: candidate forms vs ~30 path globs (§6.5, §7)

| Case | Call | Decision | Time |
|---|---|---|---|
| `read_allow_tmp` | `Read(/tmp/notes.txt)` | allow | ~3.29 µs |
| `read_deny_ssh` | `Read(/home/user/.ssh/id_rsa)` | deny | ~1.90 µs |
| `read_deny_env` | `Read(/home/user/.env)` | deny | ~0.36 µs |
| `read_relative_env` | `Read(.env)` (cwd-absolutized) | deny | ~0.49 µs |
| `read_traversal_env` | `Read(/tmp/../repo/.env)` (lexically normalized) | deny | ~0.63 µs |
| `write_deny_bashrc` | `Write(/home/user/.bashrc)` | deny | ~0.49 µs |
| `glob_allow_skills` | `Glob(~/.claude/skills/x)` (`~` expansion) | allow | ~0.67 µs |

### `generic`: URL/host extraction and the `defaultMode` fall-back (§6.5)

| Case | Call | Decision | Time |
|---|---|---|---|
| `webfetch_deny` | `WebFetch(https://example.com/x)` | deny | ~0.39 µs |
| `websearch_deny` | `WebSearch(rust async)` | deny | ~0.19 µs |
| `mcp_default_ask` | `mcp__db__query(SELECT 1)` | ask (`defaultMode` fall-back) | ~0.17 µs |

**Reading the numbers.** Simple single-command Bash calls are ~1.6-2.8 µs over
the 165 Bash rules. Cost rises with *work*, not tier: `wrapper_env_aws` decides
the command twice, while `compound_pipe` splits into two units and runs the
file-access cross-check on each. A literal file operand takes the direct matcher
path; an operand such as `.en?` prepares its shell-glob representation once and
reuses it across the `Read` deny rules.

Path costs now depend strongly on where a decisive deny appears in the tier-ordered
index. An uncarved deny returns immediately (`read_deny_env`, ~0.36 µs), while an
allow with no matching deny (`read_allow_tmp`, ~3.29 µs) must establish that no
later deny survives. Raw payload and URL-host candidates are borrowed; allocation
is limited to derived forms such as cwd absolutization, lexical normalization,
`~` expansion, or a lowercased host. Generic cases finish in ~170-390 ns.

Path matching is a plain recursive glob matcher: rule specifiers are trusted
operator config (the rule file is the source of truth) and use at most a few
wildcards, so backtracking stays cheap. It is intentionally **not** hardened
against adversarial many-wildcard patterns, a documented non-goal (SPEC §9.2).
Every figure sits far below the ~1.7 ms fresh-process cost measured below, so it
is immaterial end-to-end.

## Why this is fast (and why the manifest looks the way it does)

The production cost model is **one fresh, short-lived process per tool call**, so
**startup cost dominates**: there is no steady state to amortize against. Three
manifest choices in `Cargo.toml` follow directly:

- **No `regex`, no `clap`.** Every matcher (§6.5) and the argument parser (§2)
  are hand-written. Hand-written globs cost microseconds cold, and compiling a regex
  set would cost milliseconds each launch with nothing to amortize. Loading and
  compiling the entire reference rule set is ~81 µs, cheaper than a single
  regex compilation would be.
- **`opt-level = "z"` + LTO + `strip`.** Size, not steady-state throughput, is
  the lever for a cold-start binary, and a smaller image pages in faster. The
  release binary is ~410 KiB.
- **`panic = "unwind"`** is retained (not `abort`) because hook mode relies on
  `catch_unwind` to convert any unexpected panic into `deny` (§9.1).

End-to-end, a fresh CLI invocation with a warm OS file cache (`hyperfine`, 50
runs) measures ~1.7 ms, almost entirely process creation and dynamic loading.
The engine's own work is the microsecond figures above.
