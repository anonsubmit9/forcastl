#!/usr/bin/env python3
"""Drive the FORCAST-L reference evaluation: every model, Full corpus, 3 runs.

Dev-stage driver. It runs `forcastl-detect --mode all --runs 3
--include-benign` once per model, with provider-appropriate timeouts, and
verifies each manifest carries the current SCORING_VERSION with adequate
processed coverage (runs stamped with an older scoring may not be comparable).

It is **dry-run by default** — it prints the exact commands and prerequisites
without launching anything. Pass `--apply` to execute. Runs are sequential
(one model's local GPU / one API budget at a time) and **resumable**: a model
whose current-scoring manifest already exists for this run-id tag is skipped.

Prerequisites (the script checks what it can):
  - Local models: an OpenAI-compatible server (LM Studio / vLLM / Ollama) up,
    with each model loadable; pass its URL via the roster's `server`.
  - Anthropic models: ANTHROPIC_API_KEY in the environment.
  - OpenAI models: OPENAI_API_KEY in the environment.

Edit ROSTER below to match your actual deployment, then:
    python -m tools.run_reference_eval               # dry-run: show the plan
    python -m tools.run_reference_eval --apply        # execute sequentially
    python -m tools.run_reference_eval --apply --only qwen3.6-27b
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Optional

from forcastl import config
from forcastl.benchmark_contract import SCORING_VERSION

# ── Roster ────────────────────────────────────────────────────────────────────
# One entry per model in the reference set. `provider` selects the client:
#   lmstudio → OpenAI-compatible local server (needs `server`)
#   anthropic → Anthropic API (needs ANTHROPIC_API_KEY)
#   openai    → OpenAI API (needs OPENAI_API_KEY)
# `timeout` is the per-file hard cap in seconds — local models need a large cap
# for the heavy multi-event APT files; API models are fast. Edit to taste.
ROSTER: List[Dict] = [
    {"label": "qwen3.6-27b",          "provider": "lmstudio",  "model": "qwen3.6-27b",
     "server": "http://localhost:1234", "timeout": 600, "delay": 0.2},
    {"label": "foundation-sec-8b",    "provider": "lmstudio",  "model": "foundation-sec-8b",
     "server": "http://localhost:1234", "timeout": 600, "delay": 0.2},
    {"label": "gemma-3-12b-it",       "provider": "lmstudio",  "model": "gemma-3-12b-it",
     "server": "http://localhost:1234", "timeout": 600, "delay": 0.2},
    {"label": "gpt-5.5",              "provider": "openai",    "model": "gpt-5.5",
     "server": None, "timeout": 300, "delay": 0.5},
    {"label": "claude-opus-4-8",      "provider": "anthropic", "model": "claude-opus-4-8",
     "server": None, "timeout": 300, "delay": 0.5},
]

RUNS = 3                  # paper's repeatability protocol
MODE = "all"             # Full corpus (300)
# Canonical contract floor — a run that processed < this % of selected files is
# not a citable reference run (matches benchmark_contract coverage threshold).
MIN_PROCESSED_COVERAGE = 95.0


def _safe_model(model: str) -> str:
    import re
    return re.sub(r"[^\w\-.]", "_", model)


def _latest_manifest_for(model: str) -> Optional[Path]:
    pat = f"run_manifest_{_safe_model(model)}_*.json"
    hits = sorted(config.OUTPUTS_DIR.glob(pat))
    return hits[-1] if hits else None


def _manifest_is_complete(path: Path) -> Optional[str]:
    """Return None if the manifest is a complete run at the current scoring, else a reason."""
    try:
        m = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001 - reporting only
        return f"unreadable ({e})"
    if m.get("scoring_version") != SCORING_VERSION:
        return f"scoring_version={m.get('scoring_version', '(absent → v1)')}"
    summ = m.get("summary", {}) or {}
    total = summ.get("total_files") or 0
    processed = summ.get("processed") or 0
    if total and (100.0 * processed / total) < MIN_PROCESSED_COVERAGE:
        return f"coverage {processed}/{total} < {MIN_PROCESSED_COVERAGE}%"
    return None


def _build_cmd(entry: Dict) -> List[str]:
    cmd = [
        sys.executable, "-m", "forcastl.cli.detect",
        "--provider", entry["provider"],
        "--model", entry["model"],
        "--mode", MODE,
        "--runs", str(RUNS),
        "--include-benign",
        "--timeout", str(entry["timeout"]),
        "--delay", str(entry["delay"]),
    ]
    if entry.get("server"):
        cmd += ["--server", entry["server"]]
    return cmd


def _preflight(entry: Dict) -> Optional[str]:
    """Return a blocking reason if this model can't run, else None."""
    p = entry["provider"]
    if p == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
        return "ANTHROPIC_API_KEY not set"
    if p == "openai" and not os.environ.get("OPENAI_API_KEY"):
        return "OPENAI_API_KEY not set"
    if p == "lmstudio" and not entry.get("server"):
        return "no server URL for local provider"
    return None


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Run the FORCAST-L reference eval.")
    ap.add_argument("--apply", action="store_true",
                    help="Actually run (default: dry-run — print the plan only).")
    ap.add_argument("--only", action="append", default=None,
                    help="Limit to these model labels (repeatable).")
    ap.add_argument("--force", action="store_true",
                    help="Re-run even if a complete current-scoring manifest already exists.")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    config.require_data_dir()
    roster = [e for e in ROSTER if not args.only or e["label"] in args.only]
    if not roster:
        print(f"No roster entries match --only {args.only}", file=sys.stderr)
        return 2

    print(f"FORCAST-L reference eval — {SCORING_VERSION}")
    print(f"mode={MODE}  runs={RUNS}  include_benign=on  coverage_floor={MIN_PROCESSED_COVERAGE}%")
    print(f"outputs → {config.OUTPUTS_DIR}")
    print("=" * 78)

    plan = []
    for e in roster:
        block = _preflight(e)
        existing = _latest_manifest_for(e["model"])
        skip_reason = None
        if existing and not args.force:
            why = _manifest_is_complete(existing)
            if why is None:
                skip_reason = f"complete current-scoring manifest exists ({existing.name})"
        plan.append((e, block, skip_reason))

    for e, block, skip_reason in plan:
        cmd = _build_cmd(e)
        status = ("BLOCKED: " + block) if block else (("SKIP: " + skip_reason) if skip_reason else "RUN")
        print(f"\n[{status}] {e['label']}  ({e['provider']})")
        print("    " + " ".join(cmd))

    runnable = [(e, c) for (e, b, s), c in
                ((p, _build_cmd(p[0])) for p in plan) if not b and not s]
    print("\n" + "=" * 78)
    print(f"{len(runnable)} model(s) to run, {len(plan) - len(runnable)} skipped/blocked.")
    est_local = sum(1 for e, _ in runnable if e["provider"] == "lmstudio")
    if est_local:
        print(f"Rough wall-clock: ~{est_local * 2.5:.0f}h for {est_local} local model(s) "
              f"(Full × {RUNS} runs ≈ 2.5h each) + API models in parallel-ish.")

    if not args.apply:
        print("\nDry-run only. Re-run with --apply to execute sequentially.")
        return 0

    failures = []
    for e, cmd in runnable:
        print("\n" + "#" * 78)
        print(f"# RUNNING {e['label']} — {' '.join(cmd)}")
        print("#" * 78, flush=True)
        rc = subprocess.run(cmd, cwd=str(config.PROJECT_ROOT)).returncode
        man = _latest_manifest_for(e["model"])
        why = _manifest_is_complete(man) if man else "no manifest produced"
        if rc != 0 or why is not None:
            failures.append((e["label"], f"exit={rc}; {why}"))
            print(f"[WARN] {e['label']} incomplete: exit={rc}; {why}", flush=True)
        else:
            print(f"[OK] {e['label']} → {man.name} (current scoring, coverage ok)", flush=True)

    print("\n" + "=" * 78)
    if failures:
        print(f"{len(failures)} model(s) need attention:")
        for label, why in failures:
            print(f"  - {label}: {why}")
        return 1
    print("All reference runs complete and verified at the current scoring. "
          "Next: python -m tools.cross_model_audit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
