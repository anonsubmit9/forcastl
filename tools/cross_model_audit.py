#!/usr/bin/env python3
"""Cross-model consensus label audit over the FULL corpus.

The repo's proven label-audit signal (known_issues #26): when **every** model
independently disagrees with the ground-truth label on a file, the label — not
the models — is the likely error. Past audits only covered the 65-file Standard
sample; this runs it over all 300 by reading the reference-run manifests.

Two consensus signals are reported:
  1. VERDICT disagreement — every model's malicious YES/NO contradicts the GT
     label (a label to re-examine).
  2. HALLUCINATION consensus — every model is flagged hallucinating on the same
     file (a likely extraction/encoding gap or a decoded-IOC to allowlist).

Read-only. Writes a JSON report to outputs/ and prints a summary.

    python -m tools.cross_model_audit                     # newest manifest per model
    python -m tools.cross_model_audit --min-models 3      # require >=3 models
    python -m tools.cross_model_audit --manifests a.json b.json ...
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from forcastl import config
from forcastl.benchmark_contract import SCORING_VERSION


def _load(path: Path) -> Optional[Dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        print(f"[WARN] skip {path.name}: {e}", file=sys.stderr)
        return None


def _newest_per_model() -> List[Path]:
    """Newest detection manifest per model id."""
    by_model: Dict[str, Path] = {}
    for p in sorted(config.OUTPUTS_DIR.glob("run_manifest_*.json")):
        if p.name.startswith("run_manifest_multimodel_") or p.name.startswith("run_manifest_testcases_"):
            continue
        m = _load(p)
        if not m or m.get("kind") != "detection":
            continue
        model = m.get("model") or p.stem
        # sorted() is ascending → last write per model wins
        by_model[model] = p
    return list(by_model.values())


def gt_label(gt: Dict, fname: str) -> Optional[str]:
    """GT malicious label for a filename, with the .csv→.evtx key fallback."""
    e = gt.get(fname)
    if e is None and fname.lower().endswith(".csv"):
        e = gt.get(fname[:-4] + ".evtx")
    return (e or {}).get("malicious")


def collect_signals(manifests: List[tuple]):
    """From [(model_name, manifest_dict), ...] build per-file verdict + hallucination maps.

    Returns (verdicts, hall_flags): {file → {model → 'YES'/'NO'}} and
    {file → {model → bool}}, considering only `status == processed` rows.
    """
    verdicts: Dict[str, Dict[str, str]] = defaultdict(dict)
    hall_flags: Dict[str, Dict[str, bool]] = defaultdict(dict)
    for name, m in manifests:
        for r in m.get("files", []):
            if (r.get("status") or "processed") != "processed":
                continue
            fname = r.get("filename")
            if not fname:
                continue
            verdicts[fname][name] = "YES" if r.get("malicious") else "NO"
            rate = r.get("hallucination_rate")
            if rate is not None:
                hall_flags[fname][name] = rate > 0
    return verdicts, hall_flags


def find_verdict_disagreements(verdicts: Dict, gt: Dict, min_models: int) -> List[Dict]:
    """Files where >= min_models all processed the file and ALL contradict the GT label."""
    out = []
    for fname, per_model in verdicts.items():
        label = gt_label(gt, fname)
        if label not in ("YES", "NO"):
            continue
        if len(per_model) >= min_models and all(v != label for v in per_model.values()):
            out.append({"file": fname, "gt_label": label, "model_verdicts": dict(per_model)})
    return sorted(out, key=lambda d: d["file"])


def find_hallucination_consensus(hall_flags: Dict, min_models: int) -> List[Dict]:
    """Files where >= min_models all processed the file and ALL were flagged hallucinating."""
    out = []
    for fname, per_model in hall_flags.items():
        if len(per_model) >= min_models and all(per_model.values()):
            out.append({"file": fname, "models": sorted(per_model)})
    return sorted(out, key=lambda d: d["file"])


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Cross-model consensus label audit.")
    ap.add_argument("--manifests", nargs="+", default=None,
                    help="Explicit manifest paths (default: newest per model in outputs/).")
    ap.add_argument("--min-models", type=int, default=3,
                    help="Minimum models that must agree to flag a file (default 3).")
    ap.add_argument("--require-current", action="store_true",
                    help="Only include manifests stamped the current SCORING_VERSION.")
    ap.add_argument("--output", default=None, help="Report path (default: outputs/cross_model_audit.json).")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    config.require_data_dir()
    gt = json.loads(Path(config.GROUND_TRUTH_FILE).read_text(encoding="utf-8"))["files"]

    paths = [Path(p) for p in args.manifests] if args.manifests else _newest_per_model()
    manifests = []
    for p in paths:
        m = _load(p)
        if not m:
            continue
        if args.require_current and m.get("scoring_version") != SCORING_VERSION:
            print(f"[skip stale-scoring] {p.name} (scoring_version={m.get('scoring_version', 'absent')})")
            continue
        manifests.append((m.get("model") or p.stem, m))

    if len(manifests) < args.min_models:
        print(f"Only {len(manifests)} usable manifest(s); need >= {args.min_models}. "
              f"Run more reference models first (tools.run_reference_eval).", file=sys.stderr)
        return 2

    models = [name for name, _ in manifests]
    print(f"Auditing {len(models)} models: {', '.join(models)}")
    versions = {m.get("scoring_version", "absent") for _, m in manifests}
    if len(versions) > 1:
        print(f"[WARN] mixed scoring versions across manifests: {versions} — "
              f"verdicts compare OK but hallucination rates may not. Use --require-current.")

    verdicts, hall_flags = collect_signals(manifests)
    verdict_disagreements = find_verdict_disagreements(verdicts, gt, args.min_models)
    hallucination_consensus = find_hallucination_consensus(hall_flags, args.min_models)

    report = {
        "models": models,
        "scoring_versions": sorted(versions),
        "files_compared": len(verdicts),
        "min_models": args.min_models,
        "verdict_disagreements": verdict_disagreements,
        "hallucination_consensus": hallucination_consensus,
    }
    out = Path(args.output) if args.output else (config.OUTPUTS_DIR / "cross_model_audit.json")
    config.OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("=" * 78)
    print(f"Files compared (processed by all): {len(verdicts)}")
    print(f"\nVERDICT disagreements (all {args.min_models}+ models contradict GT) — "
          f"{len(verdict_disagreements)} file(s): labels to re-examine")
    for d in verdict_disagreements:
        print(f"  GT={d['gt_label']}  {d['file']}")
    print(f"\nHALLUCINATION consensus (all flagged) — {len(hallucination_consensus)} file(s): "
          f"likely extraction gap or decoded-IOC to allowlist (known_issues #34)")
    for d in hallucination_consensus:
        print(f"  {d['file']}")
    print("=" * 78)
    print(f"Report → {out}")
    print("Triage each verdict disagreement per the in-artifact-intent labeling "
          "principle; record the decision in the GT entry's `label_review`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
