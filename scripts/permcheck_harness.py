#!/usr/bin/env python3
"""Test and benchmark permcheck the way Claude Code actually calls it.

permcheck is a Claude Code PreToolUse hook that decides allow / ask / deny for a
tool call. In production Claude Code spawns it once per tool call as:

    permcheck --hook --rules <path>

and feeds a PreToolUse event as JSON on stdin. permcheck writes a decision as
JSON on stdout and always exits 0. This harness reproduces exactly that path:
full, realistic event objects on stdin, decision parsed from stdout.

Two jobs:

  test    Assert the decision for known cases (the SPEC §10 worked examples).
          Each case is driven as a real hook event. With --cross-check the same
          case is also run through the CLI exit-code interface and both must
          agree, catching interface drift.

  bench   Time end-to-end hook invocations. The production cost model is one
          fresh, short-lived process per tool call, so this measures whole-
          process wall-clock (spawn + load + evaluate + exit) — what Claude
          Code pays before every tool runs. Reports min / median / mean / p95
          per case and overall.

Usage:
  scripts/permcheck_harness.py                       # test, then bench (hook mode)
  scripts/permcheck_harness.py test --cross-check    # also verify CLI agrees
  scripts/permcheck_harness.py bench -n 300
  scripts/permcheck_harness.py --bin /path/to/permcheck --rules rules/permcheck.json

Exit status is 0 when all tests pass, 1 on any failure or setup error.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field

# CLI exit codes (SPEC §2.2), used only for the optional cross-check.
EXIT_TO_DECISION = {0: "allow", 1: "ask", 2: "deny", 3: "config_error"}

SESSION_ID = str(uuid.uuid4())
TRANSCRIPT = os.path.expanduser(f"~/.claude/projects/permcheck/{SESSION_ID}.jsonl")


def realistic_event(tool: str, tool_input: dict, cwd: str) -> dict:
    """A PreToolUse event shaped like the one Claude Code sends.

    permcheck consumes only tool_name, tool_input, and cwd; the rest
    (session_id, transcript_path, hook_event_name, permission_mode, …) are
    present in real events and must be tolerated and ignored (SPEC §2.1). We
    send them so the test exercises the real, noisier payload.
    """
    return {
        "session_id": SESSION_ID,
        "transcript_path": TRANSCRIPT,
        "cwd": cwd,
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
    }


@dataclass(frozen=True)
class Case:
    tool: str
    expected: str  # allow | ask | deny
    tool_input: dict  # realistic, full tool_input as Claude Code populates it
    why: str
    # Payload used for the optional CLI cross-check (the single primary string).
    cli_payload: str = ""
    label: str = field(default="")


def C(tool, expected, tool_input, why, cli_payload, label):
    return Case(tool, expected, tool_input, why, cli_payload, label)


# Cases from SPEC §10 against the canonical rules/permcheck.json reference set.
# tool_input mirrors what Claude Code really sends for each tool, including the
# secondary fields (description, old_string/new_string, content, prompt) that
# the engine ignores but a realistic event carries.
CASES: list[Case] = [
    C("Bash", "deny", {"command": "aws ec2 describe-instances", "description": "List EC2 instances"},
      "broad aws:* deny, no narrow allow", "aws ec2 describe-instances", "bash aws describe"),
    C("Bash", "deny", {"command": "kubectl get pods", "description": "List pods"},
      "only kubectl:* deny matches", "kubectl get pods", "bash kubectl get"),
    C("Bash", "deny", {"command": "kubectl delete pod x", "description": "Delete a pod"},
      "only kubectl:* deny matches", "kubectl delete pod x", "bash kubectl del"),
    C("Bash", "ask", {"command": "git push origin main", "description": "Push to origin"},
      "git push:* is in ask", "git push origin main", "bash git push"),
    C("Bash", "deny", {"command": "git push --force origin main", "description": "Force push"},
      "git push --force:* beats git push:* ask", "git push --force origin main", "bash push force"),
    C("Bash", "ask", {"command": "git status", "description": "Show working tree status"},
      "no rule -> defaultMode ask fall-back", "git status", "bash git status"),
    C("Bash", "deny", {"command": "cat .env", "description": "Read env file"},
      "file-access cross-check hits Read .env deny", "cat .env", "bash cat .env"),
    C("Bash", "ask", {"command": "some-tool --flag", "description": "Run some tool"},
      "no Bash rule -> ask fall-back", "some-tool --flag", "bash unknown"),
    C("Bash", "allow", {"command": 'python3 -c "import os"', "description": "Run python"},
      "python3 * allows it (known issue §11)", 'python3 -c "import os"', "bash python -c"),
    C("Bash", "deny", {"command": "env aws ec2 terminate-instances", "description": "Terminate"},
      "wrapper re-decision peels env", "env aws ec2 terminate-instances", "bash env aws"),
    C("Bash", "deny", {"command": "echo $(kubectl delete pod x)", "description": "Echo"},
      "substitution extracted then denied", "echo $(kubectl delete pod x)", "bash subshell"),
    C("Read", "allow", {"file_path": "/tmp/notes.txt"},
      "bare Read allow, no secret-path deny", "/tmp/notes.txt", "read tmp"),
    C("Read", "deny", {"file_path": "/home/user/.ssh/id_rsa"},
      "secret-path deny", "/home/user/.ssh/id_rsa", "read ssh key"),
    C("Read", "deny", {"file_path": "/home/user/.env"},
      "secret-path deny", "/home/user/.env", "read .env"),
    C("Write", "deny", {"file_path": "/home/user/.bashrc", "content": "export X=1\n"},
      "shell-rc write deny", "/home/user/.bashrc", "write bashrc"),
    C("Edit", "deny", {"file_path": "/home/user/.ssh/config", "old_string": "Host a", "new_string": "Host b"},
      "ssh-dir edit deny", "/home/user/.ssh/config", "edit ssh"),
    C("WebFetch", "deny", {"url": "https://example.com/x", "prompt": "Summarize this page"},
      "bare WebFetch deny", "https://example.com/x", "webfetch"),
    C("WebSearch", "deny", {"query": "rust async"},
      "bare WebSearch deny", "rust async", "websearch"),
    C("mcp__db__query", "ask", {"query": "SELECT 1"},
      "Generic family, no rule -> ask fall-back", "SELECT 1", "mcp query"),
    C("NotebookEdit", "ask", {"notebook_path": "/repo/nb.ipynb", "new_source": "print(1)", "cell_type": "code"},
      "no NotebookEdit rule, bare Edit does not cover it", "/repo/nb.ipynb", "notebook edit"),
]


class Harness:
    def __init__(self, binary: str, rules: str, cwd: str):
        self.binary = binary
        self.rules = rules
        self.cwd = cwd

    def decide_hook(self, case: Case) -> tuple[str, float]:
        """Drive permcheck the way Claude Code does: event JSON on stdin."""
        event = json.dumps(realistic_event(case.tool, case.tool_input, self.cwd))
        start = time.perf_counter()
        proc = subprocess.run(
            [self.binary, "--hook", "--rules", self.rules],
            input=event,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        elapsed = time.perf_counter() - start
        try:
            decision = json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"]
        except (json.JSONDecodeError, KeyError, TypeError):
            decision = "unparseable_output"
        return decision, elapsed

    def decide_cli(self, case: Case) -> str:
        """Optional cross-check via the CLI exit-code interface."""
        proc = subprocess.run(
            [self.binary, case.tool, case.cli_payload, "--rules", self.rules],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return EXIT_TO_DECISION.get(proc.returncode, f"exit_{proc.returncode}")


# ---------------------------------------------------------------------------
def run_tests(h: Harness, cross_check: bool) -> bool:
    print(f"TEST (hook mode)  binary={h.binary}\n                  rules={h.rules}\n")
    cols = f"{'RESULT':7} {'TOOL':14} {'EXPECT':6} {'HOOK':6}"
    if cross_check:
        cols += f" {'CLI':6}"
    cols += "  COMMAND / PATH"
    print(cols)
    print("-" * (len(cols) + 20))

    passed = failed = 0
    for c in CASES:
        hook, _ = h.decide_hook(c)
        ok = hook == c.expected
        cli = ""
        if cross_check:
            cli = h.decide_cli(c)
            ok = ok and cli == c.expected
        passed += ok
        failed += not ok
        tag = "ok" if ok else "FAIL"
        primary = c.tool_input.get("command") or c.tool_input.get("file_path") \
            or c.tool_input.get("url") or c.tool_input.get("query") \
            or c.tool_input.get("notebook_path") or ""
        primary = primary if len(primary) <= 40 else primary[:37] + "..."
        row = f"{tag:7} {c.tool:14} {c.expected:6} {hook:6}"
        if cross_check:
            row += f" {cli:6}"
        row += f"  {primary}"
        print(row)
        if not ok:
            print(f"        ^ expected {c.expected}: {c.why}")

    print("-" * (len(cols) + 20))
    print(f"{passed} passed, {failed} failed, {len(CASES)} total\n")
    return failed == 0


# ---------------------------------------------------------------------------
def summarize(samples_ms: list[float]) -> dict:
    s = sorted(samples_ms)
    p95 = s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]
    return {"min": s[0], "median": statistics.median(s), "mean": statistics.fmean(s), "p95": p95}


def run_bench(h: Harness, iterations: int, warmup: int) -> None:
    print(f"BENCH (hook mode)  binary={h.binary}\n                   rules={h.rules}")
    print(f"                   iterations={iterations} warmup={warmup} cases={len(CASES)}\n")
    print(f"      {'CASE':16} {'min':>8} {'median':>8} {'mean':>8} {'p95':>8}   (ms/call)")
    print("      " + "-" * 60)

    all_samples: list[float] = []
    for c in CASES:
        for _ in range(warmup):
            h.decide_hook(c)
        samples = [h.decide_hook(c)[1] * 1000.0 for _ in range(iterations)]
        all_samples.extend(samples)
        st = summarize(samples)
        print(f"      {c.label:16} {st['min']:8.2f} {st['median']:8.2f} {st['mean']:8.2f} {st['p95']:8.2f}")

    overall = summarize(all_samples)
    print("      " + "-" * 60)
    print(f"      {'ALL':16} {overall['min']:8.2f} {overall['median']:8.2f} "
          f"{overall['mean']:8.2f} {overall['p95']:8.2f}   ({len(all_samples)} samples)\n")
    print("This is whole-process wall-clock (spawn + load + evaluate + exit), the")
    print("cost Claude Code pays per tool call. It is dominated by OS process spawn")
    print("(~3 ms); permcheck's own decision work is microseconds (see benches/).")


# ---------------------------------------------------------------------------
def main() -> int:
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_rules = os.path.join(repo, "rules", "permcheck.json")
    ap = argparse.ArgumentParser(description="Test and benchmark permcheck via its hook interface.")
    ap.add_argument("mode", nargs="?", default="all", choices=["test", "bench", "all"],
                    help="test (correctness), bench (timing), or all (default)")
    ap.add_argument("--bin", default=shutil.which("permcheck"), help="permcheck binary (default: from PATH)")
    ap.add_argument("--rules", default=default_rules, help="rules JSON (default: repo rules/permcheck.json)")
    ap.add_argument("--cross-check", action="store_true", help="also verify the CLI exit-code interface agrees")
    ap.add_argument("-n", "--iterations", type=int, default=100, help="bench iterations per case (default: 100)")
    ap.add_argument("--warmup", type=int, default=3, help="bench warmup runs per case (default: 3)")
    args = ap.parse_args()

    if not args.bin:
        print("error: permcheck not found on PATH; pass --bin <path>", file=sys.stderr)
        return 1
    if not os.path.isfile(args.rules):
        print(f"error: rules file not found: {args.rules}", file=sys.stderr)
        return 1

    h = Harness(args.bin, args.rules, os.getcwd())
    ok = True
    if args.mode in ("test", "all"):
        ok = run_tests(h, args.cross_check)
    if args.mode in ("bench", "all"):
        run_bench(h, args.iterations, args.warmup)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
