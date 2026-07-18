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
binaries (the orphan drops all prior history). This branch is the **staging artifact**
the distribution repo is synced from (below). Bump the `version` in both `Cargo.toml`
and `plugin/.claude-plugin/plugin.json` before tagging, so already-installed users get
the update.

## Distribution repo (the install channel)

Users install from a **dedicated, source-free repo**,
[`saleem-mirza/marketplace`](https://github.com/saleem-mirza/marketplace), so the short
`owner/repo` shorthand works and no dev source is ever cloned:

```sh
/plugin marketplace add saleem-mirza/marketplace
/plugin install permcheck@zethian
```

Its default branch holds the catalog (`.claude-plugin/marketplace.json`, whose plugin
`source` is the relative path `"./plugin"` — not a `git-subdir`, since the plugin lives
in the same repo) and the `plugin/` bundle with binaries. The repo has no `src/` or
`Cargo.*`, so even the full clone the shorthand performs is source-free. Verified
end-to-end against Claude Code 2.1.204 (add → install → hook runs, payload source-free).
Smoke-test any change against a throwaway config:

```sh
export CLAUDE_CONFIG_DIR=$(mktemp -d)
claude plugin marketplace add saleem-mirza/marketplace
claude plugin install permcheck@zethian
```

### Syncing the distribution repo on release

The dist repo is synced from the `plugin-dist` staging branch. **This is currently a
manual step** — the release workflow does not yet push to the other repo:

```sh
git clone --depth 1 -b plugin-dist https://github.com/saleem-mirza/permcheck.git dist-src
git clone https://github.com/saleem-mirza/marketplace.git dist
rm -rf dist/plugin && cp -R dist-src/plugin dist/plugin   # keep .claude-plugin/marketplace.json as-is
cd dist && git add -A && git commit -m "permcheck <tag>" && git push
```

To automate it, add a job to `release.yml` that pushes the assembled bundle to
`saleem-mirza/marketplace` using a **fine-grained PAT** with `contents:write` on that
repo, stored as a secret (e.g. `DIST_REPO_TOKEN`) — the default `GITHUB_TOKEN` is scoped
to the current repo and cannot push cross-repo. Until that secret exists, sync stays
manual.
