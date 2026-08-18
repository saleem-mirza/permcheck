# Contributing

Building from source, tests, and benchmarks are covered in the
[README](README.md#build). This document covers the **code map** and **packaging /
releasing**, the parts a maintainer needs.

## Code map

`permcheck` is one crate: all engine logic in the library, a thin I/O shell in the
binary. Decision pipeline: `rules` → `matcher` → `engine`.

| File | Responsibility |
|---|---|
| `src/rules.rs` | grammar, loading, compiled `RuleSet`, `starter_rules()` |
| `src/matcher.rs` | per-family matchers + specificity scoring |
| `src/engine.rs` | winner selection + candidate forms |
| `src/bash/` | Bash decision pipeline: orchestration, compound splitting, tokenizer, form normalization, file-access cross-check |
| `src/types.rs` | `Tier`, `Decision`, `Family`, payload extraction |
| `src/settings.rs` | `--install` / `--uninstall` JSON transforms |
| `src/lib.rs` | crate root: `evaluate()` for hook JSON, `evaluate_payload()` for an already-extracted payload, loaders, re-exports |
| `src/main.rs` | arg parsing, hook / CLI / install / init-rules dispatch |

Tests live in `tests/` (separate crates, never linked into the binary).

`src/rules.rs` holds two separate things. `starter_rules()` writes a small, self-contained
safe `deny` list (`STARTER_DENY`) for `permcheck --init-rules`, the minimal policy a user
grows. The canonical `rules/permcheck.json` is the full **reference set** for the spec and
tests; `src/rules.rs` embeds it via `include_str!` only in test builds (`#[cfg(test)]`) to
assert it loads and lints clean. Neither is a decision-time default: the hook always
requires an explicit `--rules`.

## Building the plugin binaries

The plugin's `bin/` binaries come from the Rust source in the repo root, and its
`rules/permcheck.json` is a generated copy of the **canonical** top-level
`rules/permcheck.json` (single source of truth, edit only the top-level file):

```sh
cargo build --release
cp target/release/permcheck plugin/bin/permcheck-darwin-arm64   # this host
cp rules/permcheck.json plugin/rules/permcheck.json         # bundled rules copy
```

Both `plugin/bin/permcheck-*` and `plugin/rules/permcheck.json` are gitignored,
generated, not committed. The release workflow produces them for every platform. For
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
git tag vX.Y.Z && git push origin vX.Y.Z
```

Each release attaches the five raw binaries, a ready-to-use
`permcheck-plugin-<tag>.zip` (the whole plugin with `bin/` populated), and a
`SHA256SUMS` covering both. Homebrew users get integrity from the formula's pinned
`sha256`; `SHA256SUMS` is the equivalent anchor for the plugin and direct-download
paths. Install the bundle directly:

```sh
claude --plugin-url https://github.com/saleem-mirza/permcheck/releases/download/<tag>/permcheck-plugin-<tag>.zip
```

Before tagging:

1. Bump `version` in both `Cargo.toml` and `plugin/.claude-plugin/plugin.json`, so
   already-installed users get the update.
2. If the blog changed, bump `<lastBuildDate>` in `blog/feed.xml` and `dateModified`
   in `blog/when-deny-doesnt-win.html`.

**Pinned actions.** Both workflows pin every action to a commit SHA with the tag in
a trailing comment. To move one, resolve the new SHA and update both the pin and the
comment:

```sh
curl -s https://api.github.com/repos/<owner>/<repo>/git/refs/tags/<tag> | jq -r .object.sha
# if that returns an annotated tag object, dereference it:
curl -s https://api.github.com/repos/<owner>/<repo>/git/tags/<sha> | jq -r .object.sha
```

## Distribution repo (the install channel)

Users install from a **dedicated, source-free repo**,
[`saleem-mirza/marketplace`](https://github.com/saleem-mirza/marketplace), so the short
`owner/repo` shorthand works and no dev source is ever cloned:

```sh
/plugin marketplace add saleem-mirza/marketplace
/plugin install permcheck@zethian
```

Its default branch holds the catalog (`.claude-plugin/marketplace.json`, whose plugin
`source` is the relative path `"./plugin"`, not a `git-subdir`, since the plugin lives
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
repo. This repo no longer carries a `marketplace.json`.

**Auth: a write deploy key.** The default `GITHUB_TOKEN` is scoped to this repo and
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
