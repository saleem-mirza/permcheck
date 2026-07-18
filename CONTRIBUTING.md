# Contributing

Building from source, tests, and benchmarks are covered in the
[README](README.md#build). This document covers **packaging the plugin and cutting
a release** — the parts a maintainer needs.

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

The same workflow also force-updates the **`plugin-dist`** branch — a self-contained
copy of the plugin with `bin/` committed — which the marketplace catalog
(`.claude-plugin/marketplace.json`, `git-subdir` source) serves. Bump the `version`
in both `Cargo.toml` and `plugin/.claude-plugin/plugin.json` before tagging, so
already-installed users get the update.
