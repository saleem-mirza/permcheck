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

The plugin's `bin/` binaries come from the Rust source in the repo root, and its
`rules/permissions.json` is a generated copy of the **canonical** top-level
`rules/permissions.json` (single source of truth — edit only the top-level file):

```sh
cargo build --release
cp target/release/permcheck plugin/bin/permcheck-darwin-arm64   # this host
cp rules/permissions.json plugin/rules/permissions.json         # bundled rules copy
```

Both `plugin/bin/permcheck-*` and `plugin/rules/permissions.json` are gitignored — they
are generated, not committed. The release workflow produces them for every platform; for
local `--plugin-dir` testing, run the two `cp`s above first so the plugin has a binary
and its rules.

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

Bump the `version` in both `Cargo.toml` and `plugin/.claude-plugin/plugin.json` before
tagging, so already-installed users get the update.

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

### How the dist repo is updated

The `publish-marketplace` job in `release.yml` pushes the source-free bundle to
`saleem-mirza/marketplace` on every tag: it clones that repo, preserves its catalog and
README, refreshes `plugin/` with the source files plus the freshly built binaries, and
force-pushes an orphan commit (so old binaries don't pile up in history). Editing the
catalog itself (adding a plugin, changing keywords) is done directly in the marketplace
repo — this repo no longer carries a `marketplace.json`.

**Auth — a write deploy key.** The default `GITHUB_TOKEN` is scoped to this repo and
cannot push to another, so the job authenticates with a **deploy key** on
`saleem-mirza/marketplace` (repo-scoped, no expiry, not tied to a personal account). It
is already configured: the public half is a write deploy key on that repo, and the
private half is the `DIST_DEPLOY_KEY` secret here. To rotate it, generate a new
`ed25519` keypair, replace the repo's deploy key with the new public key, and update the
secret:

```sh
ssh-keygen -t ed25519 -C permcheck-release -f dist_key -N ""
gh api -X POST repos/saleem-mirza/marketplace/keys -f title="permcheck release automation" \
  -f key="$(cat dist_key.pub)" -F read_only=false      # delete the old key in the repo's Settings → Deploy keys
gh secret set DIST_DEPLOY_KEY --repo saleem-mirza/permcheck < dist_key
rm dist_key dist_key.pub
```

To sync by hand without the workflow (e.g. from a local checkout):

```sh
git clone https://github.com/saleem-mirza/marketplace.git dist
rm -rf dist/plugin && cp -R plugin dist/plugin        # from a checkout of this repo
# drop the built binaries into dist/plugin/bin (from `cargo build --release` or a Release)
cd dist && git add -A && git commit -m "permcheck <tag>" && git push
```
