# Benchmarks

Measured with `cargo bench` (Criterion) against `rules/permissions.json`, the
canonical reference rule set, on a **MacBook Pro (Apple M3 Max)**, macOS 26,
release profile (`opt-level=z`, LTO, `strip`). Numbers are indicative; re-run
locally for your hardware.

Benchmarks are grouped by matcher family, plus the one-time rule-set load. Run
`cargo bench` to reproduce; each case exercises a distinct decision path.

### Loading (one-time, per process)

| Case | What | Time |
|---|---|---|
| `load/reference_set` | parse + compile the whole reference set (51 allow · 17 ask · 142 deny) | ~57 µs |

### `bash` — winner selection, cross-check, wrapper re-decision, compound split (§6.3, §8)

| Case | Command | Decision | Time |
|---|---|---|---|
| `deny_aws_describe` | `aws ec2 describe-instances` | deny (broad `aws:*`, no narrow allow) | ~2.1 µs |
| `deny_kubectl_get` | `kubectl get pods` | deny (broad `kubectl:*`) | ~2.0 µs |
| `ask_git_status` | `git status` | ask (no rule → `defaultMode` fall-back) | ~1.8 µs |
| `ask_git_push` | `git push origin main` | ask | ~2.1 µs |
| `deny_aws_terminate` | `aws ec2 terminate-instances` | deny | ~1.8 µs |
| `deny_kubectl_delete` | `kubectl delete pod x` | deny | ~1.7 µs |
| `deny_git_push_force` | `git push --force origin main` | deny (narrow deny > broad ask) | ~1.8 µs |
| `ask_unknown` | `some-tool --flag` | ask (`defaultMode` fall-back) | ~1.7 µs |
| `crosscheck_cat_env` | `cat .env` | deny (file-access cross-check) | ~2.0 µs |
| `crosscheck_redirect` | `echo hi > …/.ssh/authorized_keys` | deny (redirect cross-check) | ~1.8 µs |
| `wrapper_env_aws` | `env aws ec2 terminate-instances` | deny (wrapper re-decision) | ~3.4 µs |
| `compound_and` | `cd /tmp && ls -la` | (2 units) | ~3.0 µs |
| `compound_pipe` | `cat file.txt \| grep something` | (2 units, both cross-checked) | ~7.1 µs |
| `compound_subshell` | `echo $(kubectl delete pod x)` | deny (substitution extracted) | ~3.4 µs |

### `path` — candidate forms vs ~30 path globs (§6.5, §7)

| Case | Call | Decision | Time |
|---|---|---|---|
| `read_allow_tmp` | `Read(/tmp/notes.txt)` | allow | ~2.9 µs |
| `read_deny_ssh` | `Read(/home/user/.ssh/id_rsa)` | deny | ~4.5 µs |
| `read_deny_env` | `Read(/home/user/.env)` | deny | ~3.2 µs |
| `read_relative_env` | `Read(.env)` (cwd-absolutized) | deny | ~3.5 µs |
| `write_deny_bashrc` | `Write(/home/user/.bashrc)` | deny | ~2.2 µs |
| `glob_allow_skills` | `Glob(~/.claude/skills/x)` (`~` expansion) | allow | ~0.47 µs |

### `generic` — URL/host extraction and the `defaultMode` fall-back (§6.5)

| Case | Call | Decision | Time |
|---|---|---|---|
| `webfetch_deny` | `WebFetch(https://example.com/x)` | deny | ~0.45 µs |
| `websearch_deny` | `WebSearch(rust async)` | deny | ~0.21 µs |
| `mcp_default_ask` | `mcp__db__query(SELECT 1)` | ask (`defaultMode` fall-back) | ~0.20 µs |

**Reading the numbers.** Simple single-command Bash calls are ~1.7–2.1 µs — a few
hundred prefix comparisons over the ~157 Bash rules. Cost rises with *work*, not
tier: `wrapper_env_aws` (~3.4 µs) decides the command twice (the wrapper and the
wrapped command); `compound_pipe` (~7.1 µs) splits into two units and runs the
file-access cross-check on each, matching operands against every `Read` deny glob
× up to three candidate forms. Path cases are naturally pricier than Generic
because there are ~30 path globs to test; Generic has only the two bare
`WebFetch`/`WebSearch` denies, so it finishes in ~200–450 ns.

Path matching is a plain recursive glob matcher: rule specifiers are trusted
operator config (the rule file is the source of truth) and use at most a few
wildcards, so backtracking stays cheap. It is intentionally **not** hardened
against adversarial many-wildcard patterns — a documented non-goal (SPEC §9.2).
Every figure sits far below the ~3 ms process-spawn floor below, so it is
immaterial end-to-end.

## Why this is fast (and why the manifest looks the way it does)

The production cost model is **one fresh, short-lived process per tool call**, so
**startup cost dominates** — there is no steady state to amortize against. Two
manifest choices follow directly (§12.2 of the spec):

- **No `regex`, no `clap`.** Every matcher (§6.5) and the argument parser (§2)
  are hand-written. Hand-written globs cost microseconds cold; compiling a regex
  set would cost milliseconds each launch with nothing to amortize. Loading and
  compiling the entire reference rule set is ~57 µs — cheaper than a single
  regex compilation would be.
- **`opt-level = "z"` + LTO + `strip`.** Size, not steady-state throughput, is
  the lever for a cold-start binary; a smaller image pages in faster. The
  release binary is ~360 KB.
- **`panic = "unwind"`** is retained (not `abort`) because hook mode relies on
  `catch_unwind` to convert any unexpected panic into `deny` (§9.1).

End-to-end, a cold CLI invocation (process spawn + load + evaluate + exit)
measures ~2.9 ms, almost entirely OS process-creation overhead; the engine's own
work is the microsecond figures above. The stripped release binary is ~361 KB.
