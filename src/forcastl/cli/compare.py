#!/usr/bin/env python3
"""Run detection against all available LLM models for comparison."""

import argparse
import json
import re
import sys
import time
import requests
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from forcastl import config
from forcastl.cli.detect import MaliciousActivityDetector
from forcastl.reporting.run_summary import compute_run_summary
import forcastl.reporting.comparison_report as comparison_report


def _summary_row(model_name: str, summary: dict, elapsed_s: float,
                 csv_file: str, html_file: str) -> dict:
    """Build one comparison-table row from a compute_run_summary result.

    Ground-truth-based by construction: recall/FP come from the same
    aggregation the manifest verdict uses (not 'fraction of files called
    malicious'). None rates render as 'N/A' (e.g. no benign in scope).
    """
    recall = summary.get('recall_pct')
    fp_rate = summary.get('fp_rate_pct')
    recall_ci = summary.get('recall_ci_pct')
    return {
        'model': model_name,
        'total_files': summary['total_files'],
        'processed_files': summary['processed'],
        'failed_files': summary['failed'],
        'true_positives': summary['true_positives'],
        'false_positives': summary['false_positives'],
        'total_malicious_in_scope': summary['total_malicious_in_scope'],
        'recall': f"{recall:.1f}%" if recall is not None else "N/A",
        'recall_ci_95': (f"{recall_ci['lo']:.0f}-{recall_ci['hi']:.0f}%"
                         if recall_ci else "N/A"),
        'fp_rate': f"{fp_rate:.1f}%" if fp_rate is not None else "N/A",
        'avg_alignment': f"{summary['avg_alignment']:.1f}%",
        'avg_confidence': f"{summary['avg_confidence']:.1f}%",
        'runtime_min': f"{elapsed_s/60:.1f}",
        'csv_file': csv_file,
        'html_file': html_file,
    }


def _fetch_models(server_url: str) -> list:
    """Fetch model list from OpenAI-compatible endpoint with validation."""
    resp = requests.get(f"{server_url}/v1/models", timeout=10)
    resp.raise_for_status()
    payload = resp.json()
    data = payload.get('data')
    if not isinstance(data, list):
        raise ValueError("Invalid /v1/models response: missing 'data' list")
    return data


def main():
    parser = argparse.ArgumentParser(
        description='Run detection across all available LLM models and produce a comparison summary'
    )
    parser.add_argument('--server', type=str, default=config.DEFAULT_LLM_SERVER,
                        help='LLM server URL (default: from LLM_SERVER_URL env var or localhost:1234)')
    parser.add_argument('--models', nargs='+', default=None,
                        help='Optional explicit model id(s) to test. If omitted, tests all non-embedding models.')
    parser.add_argument('--max-models', type=int, default=None,
                        help='Optional cap on number of models to test (after filtering). Useful to avoid long runs.')
    parser.add_argument('--mode', type=str, choices=['single', 'sample', 'all'], default='sample',
                        help='Test mode: single (first file), sample (spread across tactics), all (entire corpus).')
    parser.add_argument('--sample-size', type=int, default=50,
                        help='Number of files to test per model in sample mode (default: 50)')
    parser.add_argument('--timeout', type=int, default=300,
                        help='Request timeout in seconds (default: 300)')
    parser.add_argument('--delay', type=float, default=1.0,
                        help='Delay between files in seconds (default: 1.0)')
    parser.add_argument('--max-tokens', type=int, default=None,
                        help='Optional cap on LLM output tokens. Default: unset — the '
                             'model server governs output length. Pass a value to override.')
    parser.add_argument('--difficulty', type=str, choices=['easy', 'medium', 'hard'], default=None,
                        help='Filter test files by difficulty tag')
    parser.add_argument('--test-set', type=str, choices=['A', 'B', 'C'], default=None,
                        help='Filter test files by test set: A=Known, B=Obfuscated, C=Noise-heavy')
    parser.add_argument('--report', action='store_true',
                        help='Generate an HTML comparison report for the models tested in this run.')
    args = parser.parse_args()

    config.require_data_dir()

    run_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    started_at = datetime.now().isoformat(timespec="seconds")

    # Fetch available models
    print(f"Connecting to {args.server}...")
    try:
        all_models = _fetch_models(args.server)
    except Exception as e:
        print(f"[ERROR] Failed to fetch models from {args.server}: {e}")
        sys.exit(1)

    # Filter out embedding models
    skip_keywords = ['embedding', 'embed', 'vector', 'retrieval']
    models = []
    for m in all_models:
        model_id = m.get('id')
        if not model_id or not isinstance(model_id, str):
            continue
        if any(k in model_id.lower() for k in skip_keywords):
            continue
        models.append(m)
    model_names = [m['id'] for m in models]

    # Optional explicit selection
    if args.models:
        requested = list(args.models)
        available_set = set(model_names)
        missing = [m for m in requested if m not in available_set]
        if missing:
            print("[ERROR] Requested model(s) not found on server:")
            for m in missing:
                print(f"  - {m}")
            print("\nAvailable models:")
            for name in model_names:
                print(f"  - {name}")
            sys.exit(2)
        model_names = requested

    if args.max_models is not None and args.max_models > 0:
        model_names = model_names[:args.max_models]

    if len(model_names) == 1:
        # User intent: single model => single report; no comparative report needed.
        if args.report:
            print("[INFO] Single model selected; will generate a single-model report (skipping comparative report).")
            args.report = False

    print(f"Found {len(model_names)} LLM models to test:")
    for i, name in enumerate(model_names, 1):
        print(f"  {i}. {name}")
    print()

    results_summary = []
    csv_by_model = {}
    html_by_model = {}

    # Select files once so every model is benchmarked on the exact same artefacts.
    selector = MaliciousActivityDetector(
        timeout=args.timeout,
        delay=args.delay,
        max_tokens=args.max_tokens,
        verbose=False,
        difficulty=args.difficulty,
        test_set=args.test_set,
    )
    test_files = selector.select_files(mode=args.mode, sample_size=args.sample_size)
    if not test_files:
        print("[ERROR] No files selected for sample run.")
        sys.exit(3)

    for idx, model_name in enumerate(model_names, 1):
        print(f"\n{'='*80}")
        print(f"MODEL {idx}/{len(model_names)}: {model_name}")
        print(f"{'='*80}")

        start = time.time()

        try:
            detector = MaliciousActivityDetector(
                timeout=args.timeout,
                delay=args.delay,
                max_tokens=args.max_tokens,
                verbose=False,
                difficulty=args.difficulty,
                test_set=args.test_set,
            )

            detector.setup_llm(server=args.server, model=model_name)
            if not detector.selected_model:
                raise RuntimeError("Model selection failed")

            results = detector.run_detection(test_files)
            detector.display_summary(results)
            outputs = detector.generate_reports(
                results,
                run_id=run_id,
                started_at=started_at,
                finished_at=datetime.now().isoformat(timespec="seconds"),
                mode=args.mode,
                sample_size=(args.sample_size if args.mode == 'sample' else None),
                selected_files=test_files,
            )

            elapsed = time.time() - start

            # Read the model-specific CSV to extract stats
            safe_model = re.sub(r'[^\w\-.]', '_', model_name)
            latest_csv = outputs.get("csv_results") or str(config.OUTPUTS_DIR / f'detection_results_{safe_model}_{run_id}.csv')
            latest_html = outputs.get("html_report") or str(config.OUTPUTS_DIR / f'detection_report_{safe_model}_{run_id}.html')
            csv_by_model[model_name] = latest_csv
            html_by_model[model_name] = latest_html

            # Ground-truth-based metrics — the same aggregation the manifest
            # verdict uses (run_summary), so the comparison table reports real
            # recall/FP rate rather than "fraction of files called malicious"
            # (which counted false positives as detections).
            summary = compute_run_summary(results, detector.detector.ground_truth_data or {})
            results_summary.append(_summary_row(
                model_name, summary, elapsed, latest_csv, latest_html))

            print(f"\n>>> {model_name}: {summary['true_positives']}/{summary['total_malicious_in_scope']} "
                  f"attacks caught, {summary['false_positives']} FP, {summary['failed']} failed, "
                  f"{summary['avg_alignment']:.1f}% alignment, {elapsed/60:.1f} min")

        except Exception as e:
            print(f"\n>>> ERROR with {model_name}: {e}")
            results_summary.append({
                'model': model_name,
                'total_files': 0,
                'true_positives': 0,
                'false_positives': 0,
                'total_malicious_in_scope': 0,
                'recall': 'ERROR',
                'fp_rate': 'ERROR',
                'avg_alignment': 'ERROR',
                'avg_confidence': 'ERROR',
                'runtime_min': f"{(time.time()-start)/60:.1f}",
                'error': str(e)
            })

    # Print comparison table
    print(f"\n\n{'='*100}")
    print("MODEL COMPARISON RESULTS")
    print(f"{'='*100}")
    print(f"{'Model':<45} {'Files':>6} {'Proc':>6} {'Fail':>6} {'Caught':>10} {'Recall':>8} {'95% CI':>9} {'FP':>4} {'FP Rate':>8} {'Time':>6}")
    print(f"{'-'*45} {'-'*6} {'-'*6} {'-'*6} {'-'*10} {'-'*8} {'-'*9} {'-'*4} {'-'*8} {'-'*6}")

    for r in results_summary:
        proc = r.get('processed_files', 0)
        fail = r.get('failed_files', 0)
        caught = f"{r.get('true_positives', 0)}/{r.get('total_malicious_in_scope', 0)}"
        print(f"{r['model']:<45} {r['total_files']:>6} {proc:>6} {fail:>6} {caught:>10} {r['recall']:>8} {r.get('recall_ci_95', 'N/A'):>9} {r.get('false_positives', 0):>4} {r['fp_rate']:>8} {r['runtime_min']:>5}m")

    print(f"{'='*100}")
    print("Recall/FP rate are point estimates on this sample; 95% CI is the "
          "Wilson interval for recall. Rankings within overlapping CIs are "
          "not statistically meaningful.")

    # Save comparison JSON
    config.OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = run_id
    comparison_file = str(config.OUTPUTS_DIR / f"model_comparison_{timestamp}.json")
    with open(comparison_file, 'w', encoding='utf-8') as f:
        json.dump({
            'test_date': datetime.now().isoformat(),
            'server': args.server,
            'mode': args.mode,
            'sample_size': (args.sample_size if args.mode == 'sample' else None),
            'results': results_summary
        }, f, indent=2)
    print(f"\nComparison saved to: {comparison_file}")

    if args.report and len(model_names) > 1:
        # Generate the same HTML comparison report as `python -m reporting.comparison_report`,
        # but scoped to the models we just tested (not auto-discovered historical CSVs).
        if not csv_by_model:
            print("[WARN] No per-model CSVs collected; skipping report generation.")
            return

        gt_files, model_data, all_files, model_order = comparison_report.load_data(csv_by_model)
        sample_size = max(len(d) for d in model_data.values()) if model_data else 0
        test_config = {
            'max_tokens': args.max_tokens,
            'sample_size': sample_size,
            'server': args.server,
        }
        stats = comparison_report.compute_stats(model_data, gt_files, all_files, model_order)
        matrix = comparison_report.compute_file_matrix(model_data, gt_files, all_files, model_order)
        findings = comparison_report.compute_findings(stats, matrix, gt_files, model_order)
        fn_analysis = comparison_report.compute_fn_analysis(stats, matrix, gt_files, model_order)
        report_html = comparison_report.generate_html(
            stats, matrix, gt_files, findings, fn_analysis, model_order, test_config
        )

        report_path = config.OUTPUTS_DIR / f"model_comparison_report_{timestamp}.html"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_html)
        print(f"Model comparison HTML report saved to: {report_path}")

    # Write a top-level manifest for the multi-model run (for the web UI).
    try:
        if len(model_names) <= 1:
            return
        safe_run = run_id
        manifest_path = config.OUTPUTS_DIR / f"run_manifest_multimodel_{safe_run}.json"
        manifest = {
            "run_id": run_id,
            "kind": "multimodel_comparison",
            "raw_only": True,
            "server": args.server,
            "mode": "sample",
            "sample_size": args.sample_size,
            "max_output_tokens": args.max_tokens,
            "timeout_s": args.timeout,
            "delay_s": args.delay,
            "difficulty_filter": args.difficulty,
            "test_set_filter": args.test_set,
            "started_at": started_at,
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "selected_files": [Path(fi.get("full_path", "")).name for fi in test_files],
            "models": [
                {
                    "model": r.get("model"),
                    "csv_results": r.get("csv_file"),
                    "html_report": r.get("html_file"),
                    "runtime_min": r.get("runtime_min"),
                }
                for r in results_summary
            ],
        }
        if args.report:
            manifest["comparison_report"] = str(report_path)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print(f"Multi-model run manifest saved to: {manifest_path}")
    except Exception as e:
        print(f"[WARN] Failed to write multi-model manifest: {e}")


if __name__ == "__main__":
    main()
