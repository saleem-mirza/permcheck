#!/usr/bin/env sh
# permcheck PreToolUse hook wrapper (macOS / Linux / Windows-under-git-bash).
#
# Selects the prebuilt permcheck binary for this platform, resolves which rules
# file to use, then runs `permcheck --hook`, passing the PreToolUse event JSON
# (stdin) straight through and its decision JSON straight back out.
#
# Fail posture: if no matching binary is bundled, this fails OPEN (prints
# nothing, exits 0) so Claude Code falls back to its normal permission flow — a
# packaging/platform mismatch must never brick every tool call. permcheck is
# defense-in-depth, not the security boundary. The binary itself still fails
# CLOSED (deny) on decision-time errors (bad rules, unparseable input, panic).

set -u

# Plugin root: Claude Code sets CLAUDE_PLUGIN_ROOT; fall back to this script's
# parent dir so the wrapper is also runnable standalone (and in tests).
root="${CLAUDE_PLUGIN_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"

# --- select the binary for this OS/arch ---
case "$(uname -s 2>/dev/null || echo unknown)" in
  Darwin) plat=darwin ;;
  Linux) plat=linux ;;
  MINGW* | MSYS* | CYGWIN* | Windows_NT) plat=windows ;;
  *) plat=unknown ;;
esac
case "$(uname -m 2>/dev/null || echo unknown)" in
  arm64 | aarch64) arch=arm64 ;;
  x86_64 | amd64) arch=x64 ;;
  *) arch=unknown ;;
esac
ext=""
[ "$plat" = windows ] && ext=".exe"
bin="$root/bin/permcheck-${plat}-${arch}${ext}"

# --- resolve the rules file: env override, then project-local, then bundled ---
if [ -n "${PERMCHECK_RULES:-}" ]; then
  rules="$PERMCHECK_RULES"
elif [ -n "${CLAUDE_PROJECT_DIR:-}" ] && [ -f "$CLAUDE_PROJECT_DIR/.permcheck/rules.json" ]; then
  rules="$CLAUDE_PROJECT_DIR/.permcheck/rules.json"
else
  rules="$root/rules/permcheck.json"
fi

# --- fail open to native permissions if we can't run the engine ---
[ -x "$bin" ] || exit 0

exec "$bin" --hook --rules "$rules"
