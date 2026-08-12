# Benchmarks

Measured on 2026-08-12 (re-run after the live-state NFA change) with `cargo bench` (Criterion) against
`rules/permcheck.json`, the canonical reference rule set, on a **MacBook Pro
(Apple M3 Max)**, macOS 26.5.2, release profile (`opt-level=z`, LTO, `strip`).
Numbers are rounded medians and are indicative. Re-run locally for your hardware.

The machine carried background load during this run (load average ~1.5), and
repeat runs of untouched code moved by up to 7%. Treat anything inside ±7% as
noise, not signal.

**2026-08-12 update: live-state NFA iteration.** Both bitset glob engines walked
every pattern token on every input byte, and each epsilon closure repeated that
full scan. The state sets are `u128` and typically hold 1 to 4 live bits, so 20
to 30 iterations per byte read a zero bit and did nothing. Both engines now
iterate set bits with `trailing_zeros`, costing live states per byte instead of
pattern length. Same transitions, same answers; the differential test holds the
bitset engines against the `Vec` ones on every case.

The same commit stopped charging a Bash `cmd:*` prefix rule
`payload_len × prefix_len` against the decision work budget. `prefix_covers` is
one `starts_with`, so it costs the prefix length and has no state space to
bound. The old charge denied ordinary large commands: 162 prefix rules over a
15,101-byte command reached the 20-million-state limit on nominal work alone,
while the real decision took ~70 µs. Commands are now evaluated across the whole
documented 32,768-byte payload range.

Measured against the same suite before the change, on the same machine in the
same session:

| Case | Before | After | Change |
|---|---|---|---|
| `path/glob_allow_skills` | 3.65 µs | 1.03 µs | −72% |
| `path/read_allow_tmp` | 17.8 µs | 6.42 µs | −64% |
| `path/read_deny_ssh` | 9.61 µs | 4.20 µs | −56% |
| `bash/compound_pipe` | 30.3 µs | 15.3 µs | −49% |
| `bash/crosscheck_redirect` | 20.5 µs | 10.7 µs | −48% |
| `path/write_deny_bashrc` | 1.69 µs | 1.09 µs | −35% |
| `path/read_deny_env` | 892 ns | 752 ns | −16% |

The gain tracks how much glob matching a case does. Cases that scan every rule
to prove no deny survives (`read_allow_tmp`, `glob_allow_skills`) and the
cross-check cases that run path globs per operand (`compound_pipe`,
`crosscheck_redirect`) move the most. Prefix-dominated Bash cases moved 4-10%,
partly at the edge of the noise band: prefix rules never ran an NFA, and their
saving is the dropped work-budget multiply. The three `generic` cases moved +4%
to +6%, inside the noise band.

**2026-08-12 update: decision-wide matcher-work budget.** The
`matcher_budget` group fixes a 32,000-byte WebSearch payload against repeated
61-token worst-case misses. Each match is individually legal at 1,952,000
states. Ten rules total 19,520,000 states and preserve the configured `ask`
fall-back; an eleventh exceeds the 20-million-state decision budget and fails
closed to `deny`. The benchmark asserts both decisions before measuring.

| Case | Decision | Time |
|---|---|---|
| `near_limit_ask` | ask (ten misses, one under the aggregate limit) | ~16.21 ms |
| `exhausted_deny` | deny (the eleventh match exhausts the aggregate limit) | ~16.33 ms |

The nearly identical times are intentional: the exhausted case rejects the
eleventh match before running its NFA, after doing the same ten full misses as
the near-limit case. These are synthetic safety-boundary cases, not normal hook
latency; the reference-policy cases below remain in the microsecond range.

**2026-08-09 update — `matching_rule_indices` borrows instead of allocating.**
When a policy has no `Tool*`/`*` tool selectors (the reference set has none), the
function now returns the already-sorted exact index list by reference rather than
copying it into a fresh `Vec` and re-sorting on every `decide_hit` call. Bash has
174 rules, and that list was re-sorted per unit, per escalation form, per wrapper
stage, and per cross-check operand. Measured against a same-session baseline: the
single-unit Bash denies improved 4-5% (`deny_aws_describe` 2.61→2.49 µs), the
escalation-heavy git/wrapper cases 2-2.5%, and the small generic decisions 2-5%.
Cases dominated by NFA glob matching (heavy `path` reads, `compound_pipe`) were
flat within noise. The tables below have since been re-measured, so they include
this change; the relative deltas above are the reliable signal for it.

Benchmarks are grouped by matcher family, plus the one-time rule-set load. Run
`cargo bench` to reproduce. Each case exercises a distinct decision path.

### Loading (one-time, per process)

| Case | What | Time |
|---|---|---|
| `load/reference_set` | parse + compile the whole reference set (49 allow · 19 ask · 193 deny) | ~82.8 µs |

### `bash`: winner selection, cross-check, wrapper stages, compound split (§6.3, §8)

| Case | Command | Decision | Time |
|---|---|---|---|
| `deny_aws_describe` | `aws ec2 describe-instances` | deny (broad `aws:*`, no narrow allow) | ~2.54 µs |
| `deny_kubectl_get` | `kubectl get pods` | deny (broad `kubectl:*`) | ~2.55 µs |
| `ask_git_status` | `git status` | ask (no rule → `defaultMode` fall-back) | ~3.94 µs |
| `ask_git_push` | `git push origin main` | ask | ~4.62 µs |
| `deny_aws_terminate` | `aws ec2 terminate-instances` | deny | ~2.61 µs |
| `deny_kubectl_delete` | `kubectl delete pod x` | deny | ~2.64 µs |
| `deny_git_push_force` | `git push --force origin main` | deny (narrow deny > broad ask) | ~2.97 µs |
| `ask_unknown` | `some-tool --flag` | ask (`defaultMode` fall-back) | ~4.13 µs |
| `crosscheck_cat_env` | `cat .env` | deny (literal file-access cross-check) | ~4.58 µs |
| `crosscheck_cat_glob` | `cat .en?` | deny (shell-glob intersection) | ~5.08 µs |
| `crosscheck_redirect` | `echo hi > …/.ssh/authorized_keys` | deny (redirect cross-check) | ~10.7 µs |
| `wrapper_env_aws` | `env aws ec2 terminate-instances` | deny (denied wrapper in head position) | ~2.08 µs |
| `wrapper_displaced_sudo` | `command sudo whoami` | deny (denied wrapper found on stage 2) | ~5.71 µs |
| `wrapper_stack_no_deny` | `! time command nice whoami` | ask (4 stages, none denies) | ~18.7 µs |
| `compound_and` | `cd /tmp && ls -la` | ask (2 units) | ~11.9 µs |
| `compound_pipe` | `cat file.txt \| grep something` | allow (2 units, both cross-checked) | ~15.3 µs |
| `compound_subshell` | `echo $(kubectl delete pod x)` | deny (substitution extracted) | ~2.94 µs |

### `path`: candidate forms vs the 33 `Read` deny globs (§6.5, §7)

| Case | Call | Decision | Time |
|---|---|---|---|
| `read_allow_tmp` | `Read(/tmp/notes.txt)` | allow | ~6.42 µs |
| `read_deny_ssh` | `Read(/home/user/.ssh/id_rsa)` | deny | ~4.20 µs |
| `read_deny_env` | `Read(/home/user/.env)` | deny | ~0.75 µs |
| `read_relative_env` | `Read(.env)` (cwd-absolutized) | deny | ~0.91 µs |
| `read_traversal_env` | `Read(/tmp/../repo/.env)` (lexically normalized) | deny | ~1.24 µs |
| `write_deny_bashrc` | `Write(/home/user/.bashrc)` | deny | ~1.09 µs |
| `glob_allow_skills` | `Glob(~/.claude/skills/x)` (`~` expansion) | allow | ~1.03 µs |

### `generic`: URL/host extraction and the `defaultMode` fall-back (§6.5)

| Case | Call | Decision | Time |
|---|---|---|---|
| `webfetch_deny` | `WebFetch(https://example.com/x)` | deny | ~0.42 µs |
| `websearch_deny` | `WebSearch(rust async)` | deny | ~0.26 µs |
| `mcp_default_ask` | `mcp__db__query(SELECT 1)` | ask (`defaultMode` fall-back) | ~0.26 µs |

**Reading the numbers.** Simple single-command Bash calls are ~2.5-4.6 µs over
the 174 Bash rules. Cost rises with *work*, not tier: `compound_pipe` splits into
two units and runs the file-access cross-check on each, which is why it is the
most expensive case here. A literal file operand takes the direct matcher path;
an operand such as `.en?` prepares its shell-glob representation once and reuses
it across the `Read` deny rules.

**Wrapper stages.** A unit that starts with a wrapper or a shell reserved word is
decided once per peel stage (§8 step 2), so the two wrapper cases bracket that
cost. `wrapper_displaced_sudo` denies on its second stage and stops there, which
also skips the cross-check, so it lands at ~5.7 µs. `wrapper_stack_no_deny` stacks
four peelable words with nothing denying, so every stage is decided and none is
skipped: ~19 µs, the worst realistic shape. Stages are capped at 32 per unit and
a unit past the cap is denied outright, which bounds a pathological chain that
would otherwise cost work quadratic in the unit's length (§9.1).

Path costs depend strongly on where a decisive deny appears in the tier-ordered
index. An uncarved deny returns immediately (`read_deny_env`, ~0.75 µs), while an
allow with no matching deny (`read_allow_tmp`, ~6.4 µs) must establish that no
later deny survives. Raw payload and URL-host candidates are borrowed; allocation
is limited to derived forms such as cwd absolutization, lexical normalization,
`~` expansion, or a lowercased host. Generic cases finish in ~260-420 ns.

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
tokens, which `MAX_RULE_BYTES` permits and no real rule reaches. Those registers
are now walked by set bit rather than by token, so a match costs live states per
input byte instead of pattern length (see the live-state update at the top).

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
The `path` gap is now accounted for and mostly closed: `read_allow_tmp` was
~3.3 µs then, ~40 µs after the NFA rewrite, ~19 µs after the register change, and
~6.4 µs after live-state iteration. The residue is rule growth, since that table
predates 51 added deny rules (142 to 193) and `read_allow_tmp` scans all of them
to prove no deny survives. The cause was the NFA rewrite itself: it removed a
real wildcard blow-up, and it also made every match pay the worst case, because
the backtracking matcher it replaced aborted on the first literal mismatch.
Reverting the wrapper-stage change made no difference, which is what ruled it out.
The `generic` family reproduced its earlier figures until the reason clause above,
which accounts for its current numbers.

**What is left on the table.** A candidate that lacks a pattern's longest
contiguous literal run cannot match it, so one substring test would reject most
deny rules before their NFA runs. Measured in isolation over the 33 `Read` deny
globs, that prefilter is a further 4x to 5x on top of live-state iteration
(`/tmp/notes.txt` 4,616 ns to 542 ns). It costs one byte string per compiled rule
and load-time work. Not implemented, since the engine's cost is already
immaterial against the ~2.3 ms fresh-process figure below.

## Why this is fast (and why the manifest looks the way it does)

The production cost model is **one fresh, short-lived process per tool call**, so
**startup cost dominates**: there is no steady state to amortize against. Three
manifest choices in `Cargo.toml` follow directly:

- **No `regex`, no `clap`.** Every matcher (§6.5) and the argument parser (§2)
  are hand-written. Hand-written globs cost microseconds cold, and compiling a regex
  set would cost milliseconds each launch with nothing to amortize. Loading and
  compiling the entire reference rule set is ~83 µs, cheaper than a single
  regex compilation would be.
- **`opt-level = "z"` + LTO + `strip`.** Size, not steady-state throughput, is
  the lever for a cold-start binary, and a smaller image pages in faster. The
  release binary is ~459 KiB. The live-state change above left that size
  unchanged; the growth against the earlier 443 KiB figure predates it.
- **`panic = "unwind"`** is retained (not `abort`) because hook mode relies on
  `catch_unwind` to convert any unexpected panic into `deny` (§9.1).

End-to-end, a fresh CLI invocation with a warm OS file cache (50 runs, spawned
from a Python driver) measures ~2.3 ms, almost entirely process creation and
dynamic loading. That figure includes the driver's own spawn overhead, so it sits
above the ~1.7 ms an earlier `hyperfine` run reported. The engine's own work is
the microsecond figures above.
