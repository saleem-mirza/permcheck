# Benchmarks

Measured with `cargo bench` (Criterion) against `rules/permissions.json`, the
canonical reference rule set, on a **MacBook Pro (Apple M3 Max)**, macOS 26,
release profile (`opt-level=z`, LTO, `strip`). Numbers are indicative; re-run
locally for your hardware.

## Steady-state `evaluate`

| Case | Tool call | Time |
|---|---|---|
| `bash_allow` | `Bash(aws ec2 describe-instances)` | ~2.3 µs |
| `bash_deny` | `Bash(aws ec2 terminate-instances)` | ~2.0 µs |
| `bash_compound` | `ls && cat .env \| grep x` | ~5.2 µs |
| `path_allow` | `Read(/tmp/notes.txt)` | ~2.8 µs |
| `path_deny` | `Read(/home/user/.ssh/id_rsa)` | ~4.3 µs |
| `generic_deny` | `WebFetch(https://example.com/x)` | ~0.45 µs |
| `load_str` | compile the whole reference set | ~63 µs |

The Path cases evaluate the candidate against every `Read`/`Write`/`Edit` rule
in the reference set (~30 globs) times up to three candidate forms, so their
absolute cost is naturally higher than the single-command Bash/Generic cases.
Path matching is a plain recursive glob matcher: rule specifiers are trusted
operator config (the rule file is the source of truth) and use at most a few
wildcards, so backtracking stays cheap. It is intentionally **not** hardened
against adversarial many-wildcard patterns — a documented non-goal (SPEC §9.2).
All figures remain far below the ~3 ms process-spawn floor below, so this is
immaterial end-to-end.

## Why this is fast (and why the manifest looks the way it does)

The production cost model is **one fresh, short-lived process per tool call**, so
**startup cost dominates** — there is no steady state to amortize against. Two
manifest choices follow directly (§12.2 of the spec):

- **No `regex`, no `clap`.** Every matcher (§6.5) and the argument parser (§2)
  are hand-written. Hand-written globs cost microseconds cold; compiling a regex
  set would cost milliseconds each launch with nothing to amortize. Loading and
  compiling the entire reference rule set is ~63 µs — cheaper than a single
  regex compilation would be.
- **`opt-level = "z"` + LTO + `strip`.** Size, not steady-state throughput, is
  the lever for a cold-start binary; a smaller image pages in faster. The
  release binary is ~360 KB.
- **`panic = "unwind"`** is retained (not `abort`) because hook mode relies on
  `catch_unwind` to convert any unexpected panic into `deny` (§9.1).

End-to-end, a cold CLI invocation (process spawn + load + evaluate + exit)
measures ~2.9 ms, almost entirely OS process-creation overhead; the engine's own
work is the microsecond figures above. The stripped release binary is ~361 KB.
