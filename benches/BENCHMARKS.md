# Benchmarks

Measured on 2026-08-09 (re-run after the bitset matcher change) with `cargo bench` (Criterion) against
`rules/permcheck.json`, the canonical reference rule set, on a **MacBook Pro
(Apple M3 Max)**, macOS 26.5.2, release profile (`opt-level=z`, LTO, `strip`).
Numbers are rounded medians and are indicative. Re-run locally for your hardware.

The machine carried background load during this run (load average ~1.5), and
repeat runs of untouched code moved by up to 7%. Treat anything inside ±7% as
noise, not signal.

**2026-08-09 update — `matching_rule_indices` borrows instead of allocating.**
When a policy has no `Tool*`/`*` tool selectors (the reference set has none), the
function now returns the already-sorted exact index list by reference rather than
copying it into a fresh `Vec` and re-sorting on every `decide_hit` call. Bash has
174 rules, and that list was re-sorted per unit, per escalation form, per wrapper
stage, and per cross-check operand. Measured against a same-session baseline: the
single-unit Bash denies improved 4-5% (`deny_aws_describe` 2.61→2.49 µs), the
escalation-heavy git/wrapper cases 2-2.5%, and the small generic decisions 2-5%.
Cases dominated by NFA glob matching (heavy `path` reads, `compound_pipe`) were
flat within noise. The table medians below predate this change; the relative
deltas above are the reliable signal.

Benchmarks are grouped by matcher family, plus the one-time rule-set load. Run
`cargo bench` to reproduce. Each case exercises a distinct decision path.

### Loading (one-time, per process)

| Case | What | Time |
|---|---|---|
| `load/reference_set` | parse + compile the whole reference set (49 allow · 19 ask · 193 deny) | ~85.6 µs |

### `bash`: winner selection, cross-check, wrapper stages, compound split (§6.3, §8)

| Case | Command | Decision | Time |
|---|---|---|---|
| `deny_aws_describe` | `aws ec2 describe-instances` | deny (broad `aws:*`, no narrow allow) | ~2.72 µs |
| `deny_kubectl_get` | `kubectl get pods` | deny (broad `kubectl:*`) | ~2.72 µs |
| `ask_git_status` | `git status` | ask (no rule → `defaultMode` fall-back) | ~4.26 µs |
| `ask_git_push` | `git push origin main` | ask | ~4.99 µs |
| `deny_aws_terminate` | `aws ec2 terminate-instances` | deny | ~2.80 µs |
| `deny_kubectl_delete` | `kubectl delete pod x` | deny | ~2.84 µs |
| `deny_git_push_force` | `git push --force origin main` | deny (narrow deny > broad ask) | ~3.10 µs |
| `ask_unknown` | `some-tool --flag` | ask (`defaultMode` fall-back) | ~4.42 µs |
| `crosscheck_cat_env` | `cat .env` | deny (literal file-access cross-check) | ~5.09 µs |
| `crosscheck_cat_glob` | `cat .en?` | deny (shell-glob intersection) | ~5.58 µs |
| `crosscheck_redirect` | `echo hi > …/.ssh/authorized_keys` | deny (redirect cross-check) | ~20.5 µs |
| `wrapper_env_aws` | `env aws ec2 terminate-instances` | deny (denied wrapper in head position) | ~2.21 µs |
| `wrapper_displaced_sudo` | `command sudo whoami` | deny (denied wrapper found on stage 2) | ~6.21 µs |
| `wrapper_stack_no_deny` | `! time command nice whoami` | ask (4 stages, none denies) | ~20.5 µs |
| `compound_and` | `cd /tmp && ls -la` | ask (2 units) | ~13.1 µs |
| `compound_pipe` | `cat file.txt \| grep something` | allow (2 units, both cross-checked) | ~30.3 µs |
| `compound_subshell` | `echo $(kubectl delete pod x)` | deny (substitution extracted) | ~3.07 µs |

### `path`: candidate forms vs the 33 `Read` deny globs (§6.5, §7)

| Case | Call | Decision | Time |
|---|---|---|---|
| `read_allow_tmp` | `Read(/tmp/notes.txt)` | allow | ~19.0 µs |
| `read_deny_ssh` | `Read(/home/user/.ssh/id_rsa)` | deny | ~10.1 µs |
| `read_deny_env` | `Read(/home/user/.env)` | deny | ~0.99 µs |
| `read_relative_env` | `Read(.env)` (cwd-absolutized) | deny | ~1.18 µs |
| `read_traversal_env` | `Read(/tmp/../repo/.env)` (lexically normalized) | deny | ~1.51 µs |
| `write_deny_bashrc` | `Write(/home/user/.bashrc)` | deny | ~1.80 µs |
| `glob_allow_skills` | `Glob(~/.claude/skills/x)` (`~` expansion) | allow | ~3.91 µs |

### `generic`: URL/host extraction and the `defaultMode` fall-back (§6.5)

| Case | Call | Decision | Time |
|---|---|---|---|
| `webfetch_deny` | `WebFetch(https://example.com/x)` | deny | ~0.45 µs |
| `websearch_deny` | `WebSearch(rust async)` | deny | ~0.29 µs |
| `mcp_default_ask` | `mcp__db__query(SELECT 1)` | ask (`defaultMode` fall-back) | ~0.26 µs |

**Reading the numbers.** Simple single-command Bash calls are ~2.7-5.0 µs over
the 174 Bash rules. Cost rises with *work*, not tier: `compound_pipe` splits into
two units and runs the file-access cross-check on each, which is why it is the
most expensive case here. A literal file operand takes the direct matcher path;
an operand such as `.en?` prepares its shell-glob representation once and reuses
it across the `Read` deny rules.

**Wrapper stages.** A unit that starts with a wrapper or a shell reserved word is
decided once per peel stage (§8 step 2), so the two wrapper cases bracket that
cost. `wrapper_displaced_sudo` denies on its second stage and stops there, which
also skips the cross-check, so it lands at ~6 µs. `wrapper_stack_no_deny` stacks
four peelable words with nothing denying, so every stage is decided and none is
skipped: ~21 µs, the worst realistic shape. Stages are capped at 32 per unit and
a unit past the cap is denied outright, which bounds a pathological chain that
would otherwise cost work quadratic in the unit's length (§9.1).

Path costs depend strongly on where a decisive deny appears in the tier-ordered
index. An uncarved deny returns immediately (`read_deny_env`, ~1.0 µs), while an
allow with no matching deny (`read_allow_tmp`, ~19 µs) must establish that no
later deny survives. Raw payload and URL-host candidates are borrowed; allocation
is limited to derived forms such as cwd absolutization, lexical normalization,
`~` expansion, or a lowercased host. Generic cases finish in ~260-440 ns.

**What the reason clause costs.** An `ask` or `deny` reason names what decided the
call (§2.1), which makes the reason string longer and so its one allocation bigger.
Measured against the same suite before the change, with `load/reference_set` as a
drift control at −1.5%, the cost is a near-constant **70-100 ns per non-allow
decision**: `bash` and `path` cases moved +1.5% to +8.5%, mostly inside the ±7%
noise band, while the three `generic` cases moved +18% to +48% because they are
the smallest and a fixed cost dominates them. `allow` pays nothing, since the
clause closure is never called.

Two earlier shapes of this code cost considerably more and were rejected on these
numbers: building the clause as its own `String` (+67% on `mcp_default_ask`), and
appending it to a finished reason, which reallocates a string built to an exact fit.
The clause is a `Display` written straight into the single format that builds the
reason, so a decision still costs one allocation whether or not it carries one.

**What the matcher state costs.** Both glob engines propagate NFA states rather
than backtracking, so an adversarial many-wildcard pattern cannot blow up. The
state sets were two `Vec<bool>` per call for Bash and four for Path, allocated
and dropped on every rule tested against every candidate: answering "no rule
matched" for one `Read` call cost a few hundred small allocations. They are now
two `u128` registers, with the `Vec` form kept for a pattern longer than 125
tokens, which `MAX_RULE_BYTES` permits and no real rule reaches.

Measured against the same suite before the change, every difference far outside
the ±7% noise band and p = 0.00 on each: `path/read_allow_tmp` −52%,
`path/read_deny_ssh` −52%, `path/write_deny_bashrc` −44%, `path/glob_allow_skills`
−40%, `path/read_deny_env` −35%, `bash/compound_pipe` −47%,
`bash/crosscheck_cat_env` −21%. Decisions are unchanged; a differential test
holds the two engines against each other on every case rather than trusting the
rarely-taken one.

Every figure sits far below the fresh-process cost measured below, so it is
immaterial end-to-end.

**Against the 2026-08-01 table.** The `load` family reproduces its earlier figure.
The `bash` and `path` families are still higher, though the matcher-state change
above halved the gap: `read_allow_tmp` was ~3.3 µs then, ~40 µs before that
change, ~19 µs now. Reverting the wrapper-stage change reproduced the high
figures, so the remaining shift predates it and is not explained here. The rule
set also grew over the same period (181 deny rules to 193). Anyone tracking the
rest should start by bisecting the `path` family. The `generic` family reproduced its earlier
figures until the reason clause above, which accounts for its current numbers.

## Why this is fast (and why the manifest looks the way it does)

The production cost model is **one fresh, short-lived process per tool call**, so
**startup cost dominates**: there is no steady state to amortize against. Three
manifest choices in `Cargo.toml` follow directly:

- **No `regex`, no `clap`.** Every matcher (§6.5) and the argument parser (§2)
  are hand-written. Hand-written globs cost microseconds cold, and compiling a regex
  set would cost milliseconds each launch with nothing to amortize. Loading and
  compiling the entire reference rule set is ~85 µs, cheaper than a single
  regex compilation would be.
- **`opt-level = "z"` + LTO + `strip`.** Size, not steady-state throughput, is
  the lever for a cold-start binary, and a smaller image pages in faster. The
  release binary is ~443 KiB.
- **`panic = "unwind"`** is retained (not `abort`) because hook mode relies on
  `catch_unwind` to convert any unexpected panic into `deny` (§9.1).

End-to-end, a fresh CLI invocation with a warm OS file cache (50 runs, spawned
from a Python driver) measures ~2.3 ms, almost entirely process creation and
dynamic loading. That figure includes the driver's own spawn overhead, so it sits
above the ~1.7 ms an earlier `hyperfine` run reported. The engine's own work is
the microsecond figures above.
