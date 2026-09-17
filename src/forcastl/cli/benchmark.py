#!/usr/bin/env python3
"""Run EVTX/CSV benchmark testcases and export scoring sheet + manifest."""

from __future__ import annotations

import argparse
import csv
import glob
import json
import re
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from forcastl import config
from forcastl.benchmark_contract import (
    apply_canonical_preset,
    build_contract_metadata,
)
from forcastl.core import EVTXParser, PromptManager, score_benchmark_response
from forcastl.core.csv_evidence import build_csv_index, resolve_csv
from forcastl.core.inference import complete_openai_compatible
from forcastl.validation import load_test_case

MANIFEST_SCHEMA_VERSION = 1

SendFn = Callable[..., str]


def _classify_exception(exc: BaseException) -> str:
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.HTTPError):
        return "http_error"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "http_error"
    if isinstance(exc, ValueError):
        return "artefact_error"
    if isinstance(exc, (KeyError, IndexError, TypeError)):
        return "parse_error"
    return "error"


def _is_benign_testcase(testcase: Dict[str, Any]) -> bool:
    findings = testcase.get("expected_findings")
    if isinstance(findings, list) and len(findings) == 0:
        return True
    for field in ("scenario_prompt", "notes"):
        text = (testcase.get(field) or "").lower()
        if "benign" in text and "not malicious" not in text:
            return True
        if "not malicious" in text:
            return True
    return False


def _discover_testcases(patterns: List[str]) -> List[Path]:
    paths: List[Path] = []
    for pattern in patterns:
        # glob.glob, not Path().glob — the default pattern is absolute
        # (config.DATA_DIR), which pathlib refuses to glob.
        paths.extend(Path(p) for p in sorted(glob.glob(pattern)))
    deduped = sorted(set(paths))
    if not deduped:
        raise ValueError(
            "No testcase files matched provided patterns. If you expected the "
            f"bundled cases, check that the corpus exists at {config.DATA_DIR} "
            "(run from a git checkout or set FORCASTL_DATA_DIR)."
        )
    return deduped


def _safe_load_testcases(
    paths: List[Path],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return (loaded testcases, load-failure case entries)."""
    loaded: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    for path in paths:
        try:
            loaded.append(load_test_case(path))
        except Exception as e:
            failures.append({
                "path": str(path),
                "testcase_id": path.stem,
                "status": "testcase_load_error",
                "error": f"{type(e).__name__}: {e}",
                "run": None,
                "total_score": None,
                "grade": None,
            })
    return loaded, failures


def _load_artefact_data(
    parser: EVTXParser,
    testcase: Dict[str, Any],
    csv_index: Dict[str, str],
) -> str:
    artefact_file = testcase.get("artefact_file", "")
    if not artefact_file:
        raise ValueError(f"{testcase['id']}: missing artefact_file")

    # The CSV corpus (EvtxECmd output) is the only artefact source. The
    # testcase's artefact_file (an `.evtx` logical key, or a `.csv` path) is
    # resolved to its CSV by lowercased stem; the binary EVTX is never parsed.
    csv_path = resolve_csv(artefact_file, index=csv_index)
    if csv_path is None:
        raise FileNotFoundError(
            f"{testcase['id']}: no CSV resolved for artefact_file: {artefact_file}"
        )

    events = parser.parse_csv_file(csv_path)
    if not events:
        raise ValueError(f"{testcase['id']}: no events parsed from {csv_path}")
    return parser.format_for_llm_pure_raw_xml(events)


def _build_corpus_scope(testcases: List[Dict[str, Any]]) -> Dict[str, Any]:
    benign_count = sum(1 for tc in testcases if _is_benign_testcase(tc))
    malicious_count = len(testcases) - benign_count
    has_benign = benign_count > 0
    if has_benign:
        note = (
            f"Suite includes {benign_count} benign control(s) and "
            f"{malicious_count} malicious case(s)."
        )
    else:
        note = (
            "Malicious-only testcase suite: all cases expect attack indicators. "
            "False-positive rate is not measured by this runner."
        )
    return {
        "has_benign_controls": has_benign,
        "malicious_count": malicious_count,
        "benign_count": benign_count,
        "note": note,
    }


def _summarize_cases(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_status: Dict[str, int] = {}
    for c in cases:
        st = c.get("status") or "error"
        by_status[st] = by_status.get(st, 0) + 1
    processed = by_status.get("processed", 0)
    failed = len(cases) - processed
    scores = [
        c["total_score"] for c in cases
        if c.get("status") == "processed" and c.get("total_score") is not None
    ]
    avg_total_score = (sum(scores) / len(scores)) if scores else None
    return {
        "total_case_runs": len(cases),
        "processed": processed,
        "failed": failed,
        "by_status": by_status,
        "avg_total_score": avg_total_score,
    }


def _default_send(
    *,
    server_url: str,
    model: str,
    prompt: str,
    timeout: int,
    max_tokens: int,
    temperature: float,
) -> str:
    text, _rt = complete_openai_compatible(
        server_url=server_url,
        model=model,
        prompt=prompt,
        timeout=timeout,
        max_tokens=max_tokens,
        temperature=temperature,
    )
    if text.startswith("Error:"):
        raise RuntimeError(text)
    return text


def run_benchmark(args, *, send_fn: Optional[SendFn] = None) -> Dict[str, Any]:
    """Execute testcase contract benchmark; write CSV + manifest; return manifest."""
    if send_fn is None:
        send_fn = _default_send

    testcase_paths = _discover_testcases(args.testcases)
    loaded, load_failures = _safe_load_testcases(testcase_paths)

    safe_model = re.sub(r"[^\w\-.]", "_", args.model)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = uuid.uuid4().hex[:12]
    started_at = datetime.now().isoformat(timespec="seconds")

    config.OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    output_csv = args.output_csv or str(
        config.OUTPUTS_DIR / f"scoring_sheet_{safe_model}_{timestamp}.csv"
    )
    manifest_path = config.OUTPUTS_DIR / f"run_manifest_testcases_{safe_model}_{timestamp}.json"

    prompt_manager = PromptManager()
    csv_parser = EVTXParser(verbose=False)
    csv_index = build_csv_index()

    cases: List[Dict[str, Any]] = list(load_failures)
    scoring_rows: List[Dict[str, Any]] = []

    for run in range(1, (args.runs or 1) + 1):
        for testcase in loaded:
            tc_id = testcase["id"]
            case_entry: Dict[str, Any] = {
                "testcase_id": tc_id,
                "run": run,
                "path": testcase.get("artefact_file"),
            }
            try:
                artefact_data = _load_artefact_data(csv_parser, testcase, csv_index)
                prompt = prompt_manager.generate_benchmark_prompt(
                    testcase["artefact_type"],
                    testcase["scenario_prompt"],
                    artefact_data,
                )
                response_text = send_fn(
                    server_url=args.server,
                    model=args.model,
                    prompt=prompt,
                    timeout=args.timeout,
                    max_tokens=args.max_tokens,
                    temperature=args.temperature,
                )
                score = score_benchmark_response(response_text, testcase)
                case_entry.update({
                    "status": "processed",
                    "error": None,
                    "total_score": score["TotalScore"],
                    "grade": score["Grade"],
                })
                scoring_rows.append({
                    "TestID": tc_id,
                    "Model": args.model,
                    "Run": run,
                    "Extraction": score["Extraction"],
                    "Interpretation": score["Interpretation"],
                    "NoHallucination": score["NoHallucination"],
                    "Reasoning": score["Reasoning"],
                    "TotalScore": score["TotalScore"],
                    "Grade": score["Grade"],
                })
            except Exception as e:
                status = _classify_exception(e)
                case_entry.update({
                    "status": status,
                    "error": f"{type(e).__name__}: {e}",
                    "total_score": None,
                    "grade": None,
                })
            cases.append(case_entry)
            if getattr(args, "delay", 0):
                time.sleep(args.delay)

    summary = _summarize_cases(cases)
    finished_at = datetime.now().isoformat(timespec="seconds")

    artefact_types: Dict[str, int] = {}
    for tc in loaded:
        at = tc.get("artefact_type") or "unknown"
        artefact_types[at] = artefact_types.get(at, 0) + 1

    contract = build_contract_metadata(
        mode="testcases",
        sample_size=len(loaded),
        max_events=None,
        difficulty=None,
        test_set=None,
        input_format="csv",
        context_window=None,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        runs=args.runs,
    )

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run_id": run_id,
        "kind": "testcase_benchmark",
        "raw_only": True,
        "server": args.server,
        "model": args.model,
        "started_at": started_at,
        "finished_at": finished_at,
        "benchmark_contract": contract,
        "testcase_suite": {
            "patterns": list(args.testcases),
            "discovered_count": len(testcase_paths),
            "total_cases": len(loaded),
            "load_failure_count": len(load_failures),
            "load_failure_paths": [f["path"] for f in load_failures],
            "testcase_ids": [tc["id"] for tc in loaded],
            "artefact_types": artefact_types,
        },
        "corpus_scope": _build_corpus_scope(loaded),
        "summary": summary,
        "cases": cases,
        "outputs": {
            "scoring_csv": output_csv,
            "manifest": str(manifest_path),
        },
    }

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "TestID", "Model", "Run",
                "Extraction", "Interpretation", "NoHallucination",
                "Reasoning", "TotalScore", "Grade",
            ],
        )
        writer.writeheader()
        writer.writerows(scoring_rows)

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Scoring sheet saved to: {output_csv}")
    print(f"Manifest saved to: {manifest_path}")

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump({"manifest": manifest, "cases": cases}, f, indent=2)
        print(f"Detailed results saved to: {args.output_json}")

    return manifest


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Run EVTX/CSV benchmark testcases and export scoring sheet.",
    )
    parser.add_argument(
        "--testcases",
        nargs="+",
        default=[str(config.DATA_DIR / "benchmark_cases" / "*.json")],
        help="Glob patterns for testcase JSON files.",
    )
    parser.add_argument(
        "--server",
        default=config.DEFAULT_LLM_SERVER,
        help="LLM server URL (OpenAI-compatible).",
    )
    parser.add_argument("--model", required=True, help="Model id/name to query.")
    parser.add_argument("--runs", type=int, default=3, help="Repeatability runs per testcase.")
    parser.add_argument("--timeout", type=int, default=120, help="LLM request timeout seconds.")
    parser.add_argument("--max-tokens", type=int, default=None,
                        help="Optional cap on LLM output tokens. Default: unset — the "
                             "model server governs output length.")
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.1,
        help="Sampling temperature (0.0 for canonical runs).",
    )
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds.")
    parser.add_argument(
        "--canonical",
        action="store_true",
        help="Apply canonical preset (temperature=0.0, runs>=3).",
    )
    parser.add_argument(
        "--output-csv",
        default=None,
        help="Output scoring sheet path.",
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Optional detailed JSON output.",
    )
    argv = argv if argv is not None else sys.argv[1:]
    args = parser.parse_args(argv)

    if args.canonical:
        outcome = apply_canonical_preset(args, sys.argv, selection_flags=[])
        if outcome.conflicts:
            parser.error("; ".join(outcome.conflicts))

    run_benchmark(args)


if __name__ == "__main__":
    main()
