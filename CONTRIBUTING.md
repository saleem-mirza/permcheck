# Contributing

Building from source, tests, and benchmarks are covered in the
[README](README.md#build). This document covers the **code map** and **packaging /
releasing** — the parts a maintainer needs.

## Code map

`permcheck` is one crate: all engine logic in the library, a thin I/O shell in the
binary. Decision pipeline: `rules` → `matcher` → `engine`.

| File | Responsibility |
|---|---|
| `src/rules.rs` | grammar, loading, compiled `RuleSet` |
| `src/matcher.rs` | per-family matchers + specificity scoring |
| `src/engine.rs` | winner selection + candidate forms |
| `src/bash.rs` | compound-command splitter, tokenizer, file-access cross-check |
| `src/types.rs` | `Tier`, `Decision`, `Family`, payload extraction |
| `src/settings.rs` | `--install` / `--uninstall` JSON transforms |
| `src/lib.rs` | crate root: `evaluate()`, loaders, re-exports |
| `src/main.rs` | arg parsing, hook / CLI / install dispatch |

Tests live in `tests/` (separate crates, never linked into the binary).

## Building the plugin binaries

The plugin's `bin/` binaries come from the Rust source in the repo root:

```sh
cargo build --release
cp target/release/permcheck plugin/bin/permcheck-darwin-arm64   # this host
```

During development the binaries are gitignored. For full platform coverage they are
produced by the release workflow (below), not committed from a dev machine.

## Releasing

`.github/workflows/release.yml` cross-compiles all five targets on a version tag and
publishes them to a GitHub Release:

| Binary | Rust target | Runner |
|---|---|---|
| `permcheck-darwin-arm64` | `aarch64-apple-darwin` | macOS |
| `permcheck-darwin-x64` | `x86_64-apple-darwin` | macOS (cross) |
| `permcheck-linux-x64` | `x86_64-unknown-linux-musl` | Linux (static, via `cross`) |
| `permcheck-linux-arm64` | `aarch64-unknown-linux-musl` | Linux (static, via `cross`) |
| `permcheck-windows-x64.exe` | `x86_64-pc-windows-msvc` | Windows |

Cut a release by pushing a tag:

```sh
git tag v0.1.6 && git push origin v0.1.6
```

Each release attaches the five raw binaries **and** a ready-to-use
`permcheck-plugin-<tag>.zip` (the whole plugin with `bin/` populated). Install that
bundle directly:

```sh
claude --plugin-url https://github.com/saleem-mirza/permcheck/releases/download/<tag>/permcheck-plugin-<tag>.zip
```

The same workflow also rebuilds the **`plugin-dist`** branch as a **source-free
orphan** each release: it holds only `.claude-plugin/marketplace.json` and the
`plugin/` tree with `bin/` committed — no Rust source, and no accumulated old
binaries (the orphan drops all prior history). Bump the `version` in both
`Cargo.toml` and `plugin/.claude-plugin/plugin.json` before tagging, so
already-installed users get the update.

### Installing source-free from `plugin-dist`

Both the catalog and the plugin come from the one `plugin-dist` branch, so nothing
ever clones `src/`, `tests/`, or `Cargo.*` onto a user's machine. Add the marketplace
by the **raw URL of its `marketplace.json`** on that branch:

```sh
/plugin marketplace add \
  https://raw.githubusercontent.com/saleem-mirza/permcheck/plugin-dist/.claude-plugin/marketplace.json
```

This fetches only that one JSON file (no repo clone); the plugin then resolves via its
own `git-subdir` source, which pins `ref: plugin-dist` and is itself source-free.

Why the raw URL rather than the shorter `/plugin marketplace add saleem-mirza/permcheck`:
`add <owner/repo>` has **no branch option** — every remote form clones the repo's
**default branch** (`main`), which would drag the Rust source into the marketplace
clone. Branch pinning at registration time was requested and closed as *not planned*
([issue #23551](https://github.com/anthropics/claude-code/issues/23551)). The raw-URL
form is what keeps a normal source-carrying dev repo and a source-free install on the
same repository.

The same flow is scriptable via the non-interactive CLI, which is how a release can
smoke-test it. Verified end-to-end against Claude Code 2.1.204 — the client accepts the
raw URL, installs a source-free payload, and `marketplace update` re-fetches the URL so
version bumps propagate:

```sh
claude plugin marketplace add \
  https://raw.githubusercontent.com/saleem-mirza/permcheck/plugin-dist/.claude-plugin/marketplace.json
claude plugin install permcheck@zethian      # installs source-free, enabled
claude plugin marketplace update zethian      # re-fetches the raw URL
```

Point `CLAUDE_CONFIG_DIR` at a throwaway directory to test without touching your real
`~/.claude` config.

> One timing caveat: raw GitHub URLs sit behind a short CDN cache (~5 min), so a
> freshly pushed release isn't visible to `add`/`update` instantly.
>
> Alternative if you'd rather users use the `add <owner/repo>` shorthand: publish the
> orphan tree as its own repo's default branch and register that instead.
