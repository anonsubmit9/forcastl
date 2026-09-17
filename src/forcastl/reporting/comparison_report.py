#!/usr/bin/env python3
"""Generate HTML comparison report from model comparison CSV data.

Auto-discovers detection result CSVs from the outputs directory, or accepts
explicit CSV paths via CLI.  All test configuration (context window, max tokens,
server URL) is passed as arguments — nothing is hardcoded.
"""

import argparse
import json
import html
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from forcastl import config


# ── Data loading ─────────────────────────────────────────────────────────────

def _safe_float(value, default: float = 0.0) -> float:
    """Parse float safely for mixed/legacy CSV fields."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

def discover_csvs(outputs_dir: Path = None) -> Dict[str, str]:
    """Auto-discover detection_results_*.csv files and map model→path.

    When multiple CSVs exist for the same model the newest (by filename
    timestamp) is used.
    """
    if outputs_dir is None:
        outputs_dir = config.OUTPUTS_DIR

    from forcastl.reporting.csv_output import read_detection_csv
    model_csvs: Dict[str, str] = {}
    for csv_path in sorted(outputs_dir.glob('detection_results_*.csv')):
        try:
            rows = read_detection_csv(csv_path)
            first_row = rows[0] if rows else None
            if first_row and first_row.get('Model'):
                model_name = first_row['Model']
                # Latest file wins (glob is sorted alphabetically → by timestamp)
                model_csvs[model_name] = str(csv_path)
        except Exception:
            continue
    return model_csvs


def load_data(csv_paths: Optional[Dict[str, str]] = None):
    """Load ground truth and per-model CSV data.

    Args:
        csv_paths: dict mapping model_name → csv_file_path.
                   If None, auto-discovers from config.OUTPUTS_DIR.

    Returns:
        (gt_files, model_data, all_files, model_order)
    """
    if csv_paths is None:
        csv_paths = discover_csvs()

    if not csv_paths:
        raise SystemExit('No detection result CSVs found in outputs/. '
                         'Run detect_malicious.py first, or pass --csv explicitly.')

    with open(config.GROUND_TRUTH_FILE, 'r', encoding='utf-8') as f:
        gt = json.load(f)
    gt_files = gt['files']

    from forcastl.reporting.csv_output import read_detection_csv
    model_data: Dict[str, Dict] = {}
    for model, path in csv_paths.items():
        rows = read_detection_csv(path)
        model_data[model] = {r['Filename']: r for r in rows}

    # Stable ordering: alphabetical by model name
    model_order = sorted(model_data.keys())

    all_files = sorted(set().union(*(d.keys() for d in model_data.values())))
    return gt_files, model_data, all_files, model_order


# ── Statistics ───────────────────────────────────────────────────────────────

def compute_stats(model_data, gt_files, all_files, model_order):
    stats = {}
    def _status(row: Dict[str, Any]) -> str:
        # Newer CSVs include Status. Older CSVs don't; treat them as processed.
        s = (row.get('Status') or '').strip().lower()
        if s:
            return s
        # Backward-compat: infer status from legacy CSVs.
        resp = (row.get('LLM Response') or '').strip().lower()
        if 'context exceeded' in resp:
            return 'context_exceeded'
        if resp.startswith('error:'):
            return 'error'
        return 'processed'

    for model in model_order:
        rows = list(model_data[model].values())
        processed_rows = [r for r in rows if _status(r) == 'processed']

        total = len(all_files)
        processed = len(processed_rows)
        mal = sum(1 for r in processed_rows if r.get('Malicious') == 'YES')
        aligns = [_safe_float(r.get('Alignment %')) for r in processed_rows if r.get('Alignment %')]
        avg_a = sum(aligns) / len(aligns) if aligns else 0
        confs = [_safe_float(r.get('Confidence %')) for r in processed_rows if r.get('Confidence %')]
        avg_c = sum(confs) / len(confs) if confs else 0
        valid = sum(1 for r in processed_rows if r.get('Structure Valid') == 'YES')
        resp_times = [_safe_float(r.get('Response Time (s)')) for r in processed_rows if r.get('Response Time (s)')]
        avg_rt = sum(resp_times) / len(resp_times) if resp_times else 0
        total_rt = sum(resp_times) if resp_times else 0

        # Accuracy vs ground truth
        tp = 0
        fn_files = []
        fp_files = []
        tn = 0
        missing_files = []
        error_files = []
        missing_row_files = []
        for filename in all_files:
            gt_mal = gt_files.get(filename, {}).get('malicious', 'UNKNOWN')
            row = model_data[model].get(filename)
            if row is None:
                detected = 'MISSING'
                missing_files.append(filename)
                missing_row_files.append(filename)
            else:
                st = _status(row)
                if st != 'processed':
                    detected = 'ERROR'
                    missing_files.append(filename)
                    error_files.append(filename)
                else:
                    detected = row.get('Malicious', '?') or '?'

            if gt_mal == 'YES' and detected == 'YES':
                tp += 1
            elif gt_mal == 'YES' and detected in ('NO', 'MISSING', 'ERROR', '?'):
                fn_files.append(filename)
            elif gt_mal == 'NO' and detected == 'YES':
                fp_files.append(filename)
            elif gt_mal == 'NO' and detected == 'NO':
                tn += 1
            # If gt is benign and we have ERROR/MISSING, do not count it as TN/FP.

        precision = tp / (tp + len(fp_files)) if (tp + len(fp_files)) > 0 else 0
        recall = tp / (tp + len(fn_files)) if (tp + len(fn_files)) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        # 20-point scoring columns (may not exist in older CSVs)
        score_totals = []
        score_grades = []
        hall_rates_list = []
        for r in processed_rows:
            t = r.get('Total (20)', '')
            if t:
                try:
                    score_totals.append(float(t))
                except ValueError:
                    pass
            g = r.get('Grade', '')
            if g:
                score_grades.append(g)
            h = r.get('NoHallucination (4)', '')
            if h:
                try:
                    hall_rates_list.append(float(h))
                except ValueError:
                    pass

        avg_score_20 = sum(score_totals) / len(score_totals) if score_totals else 0
        avg_hall_score = sum(hall_rates_list) / len(hall_rates_list) if hall_rates_list else 0
        grade_dist = {}
        for g in score_grades:
            grade_dist[g] = grade_dist.get(g, 0) + 1

        stats[model] = {
            'total': total,
            'processed': processed,
            'errors': len(error_files),
            'missing_rows': len(missing_row_files),
            'malicious': mal,
            'det_rate': (mal / total * 100) if total else 0,
            'avg_alignment': avg_a, 'avg_confidence': avg_c,
            'struct_valid': valid, 'avg_response_time': avg_rt,
            'runtime': total_rt / 60,  # derive from sum of response times
            'tp': tp, 'fn': len(fn_files), 'fp': len(fp_files), 'tn': tn,
            'fn_files': fn_files, 'fp_files': fp_files,
            'missing': len(missing_files), 'missing_files': missing_files,
            'error_files': error_files, 'missing_row_files': missing_row_files,
            'coverage_pct': (processed / total * 100) if total else 0,
            'precision': precision, 'recall': recall, 'f1': f1,
            'avg_score_20': avg_score_20, 'grade_dist': grade_dist,
            'avg_hall_score': avg_hall_score,
        }
    return stats


# ── Per-file matrix ──────────────────────────────────────────────────────────

def compute_file_matrix(model_data, gt_files, all_files, model_order):
    """Per-file results across all models."""
    matrix = []
    def _status(row: Dict[str, Any]) -> str:
        s = (row.get('Status') or '').strip().lower()
        if s:
            return s
        resp = (row.get('LLM Response') or '').strip().lower()
        if 'context exceeded' in resp:
            return 'context_exceeded'
        if resp.startswith('error:'):
            return 'error'
        return 'processed'

    for filename in all_files:
        gt_mal = gt_files.get(filename, {}).get('malicious', 'UNKNOWN')
        row = {'filename': filename, 'ground_truth': gt_mal, 'models': {}}
        yes_count = 0
        for model in model_order:
            r = model_data[model].get(filename)
            if r is None:
                detected = 'MISSING'
                alignment = 0.0
                confidence = 0.0
                score_20 = 0.0
                grade = ''
                status = 'missing'
            else:
                status = _status(r)
                if status != 'processed':
                    detected = 'ERROR'
                else:
                    detected = r.get('Malicious', '?') or '?'
                alignment = _safe_float(r.get('Alignment %', 0))
                confidence = _safe_float(r.get('Confidence %', 0))
                score_20 = 0
                try:
                    score_20 = float(r.get('Total (20)', 0))
                except (ValueError, TypeError):
                    pass
                grade = r.get('Grade', '')
            row['models'][model] = {
                'detected': detected, 'alignment': alignment, 'confidence': confidence,
                'score_20': score_20, 'grade': grade, 'status': status,
            }
            if detected == 'YES':
                yes_count += 1
        row['consensus'] = yes_count
        matrix.append(row)
    return matrix


# ── Key findings ─────────────────────────────────────────────────────────────

def compute_findings(stats, matrix, gt_files, model_order):
    """Derive key findings from the data."""
    models = model_order
    findings = []
    total_missing = sum(stats[m].get('missing', 0) for m in models)
    total_errors = sum(stats[m].get('errors', 0) for m in models)
    total_missing_rows = sum(stats[m].get('missing_rows', 0) for m in models)
    if total_missing:
        findings.append({
            'title': f'{total_missing} Missing/Failed File Results Across Models',
            'detail': f'Some model outputs were not usable for scoring (missing rows: {total_missing_rows}, '
                      f'error/context-exceeded statuses: {total_errors}). '
                      'These are treated as missed detections for malicious files.',
            'severity': 'negative'
        })

    # Dataset limitations: if there are no benign files, FP/precision are not measurable.
    gt_vals = [gt_files.get(f, {}).get('malicious', 'UNKNOWN') for f in gt_files]
    has_benign = any(v == 'NO' for v in gt_vals)
    if not has_benign:
        findings.append({
            'title': 'No Benign Ground Truth Files (False Positives Not Measurable)',
            'detail': 'The current ground truth contains no benign (NO) files, so false-positive rate and precision '
                      'are not meaningful. Add a benign set to evaluate false alarms.',
            'severity': 'insight'
        })

    # 1. False positive rate
    if has_benign:
        total_fp = sum(stats[m]['fp'] for m in models)
        if total_fp == 0:
            findings.append({
                'title': 'Zero False Positives',
                'detail': 'No model flagged a benign file as malicious across all tests. '
                          'Every model demonstrated perfect precision — when a model says "malicious", it is correct.',
                'severity': 'positive'
            })
        else:
            findings.append({
                'title': f'{total_fp} False Positives Total',
                'detail': f'Across all models, {total_fp} benign files were incorrectly flagged as malicious.',
                'severity': 'negative'
            })

    # 2. Security-trained vs general purpose
    ranked = sorted(models, key=lambda m: -stats[m]['f1'])
    best = ranked[0]
    best_f1 = stats[best]['f1']
    second = ranked[1] if len(ranked) > 1 else None
    if second:
        gap = best_f1 - stats[second]['f1']
        if gap > 0.10:
            findings.append({
                'title': f'{best} Significantly Outperforms All Others',
                'detail': f'{best} achieved {best_f1:.0%} F1 score, {gap:.0%} ahead of the next best model ({second} at {stats[second]["f1"]:.0%}). '
                          f'This suggests domain-specific training provides a substantial advantage for security event analysis.',
                'severity': 'insight'
            })

    # 3. Evidence extraction vs classification gap
    high_align_fn = []
    for row in matrix:
        if row['ground_truth'] != 'YES':
            continue
        for model in models:
            m = row['models'][model]
            if m['detected'] == 'NO' and m['alignment'] >= 60:
                high_align_fn.append((model, row['filename'], m['alignment']))

    if high_align_fn:
        findings.append({
            'title': 'Evidence Extraction Succeeds Where Classification Fails',
            'detail': f'{len(high_align_fn)} instances where a model correctly extracted key evidence '
                      f'(alignment >= 60%) but still classified the file as benign. '
                      f'Models can identify the relevant data but lack the security knowledge to interpret it as malicious.',
            'severity': 'insight'
        })

    # 4. Reasoning model failure
    for model in models:
        s = stats[model]
        if s['recall'] == 0 and s['runtime'] > 100:
            findings.append({
                'title': f'{model}: Complete Detection Failure',
                'detail': f'{model} achieved 0% recall in {s["runtime"]:.0f} minutes. '
                          f'Chain-of-thought reasoning consumed the entire token budget before producing structured output, '
                          f'resulting in unparseable responses.',
                'severity': 'negative'
            })

    # 5. Hallucination patterns
    hall_models = [(m, stats[m]['avg_hall_score']) for m in models if stats[m].get('avg_hall_score', 0) > 0]
    if hall_models:
        best_hall = max(hall_models, key=lambda x: x[1])
        worst_hall = min(hall_models, key=lambda x: x[1])
        if best_hall[1] - worst_hall[1] >= 1.0:
            findings.append({
                'title': 'Hallucination Quality Varies Across Models',
                'detail': f'{best_hall[0]} achieved best hallucination avoidance ({best_hall[1]:.1f}/4), '
                          f'while {worst_hall[0]} scored lowest ({worst_hall[1]:.1f}/4). '
                          f'Higher scores indicate fewer fabricated evidence items.',
                'severity': 'insight'
            })

    # 6. 20-point scoring insights
    scored_models = [(m, stats[m]['avg_score_20']) for m in models if stats[m].get('avg_score_20', 0) > 0]
    if scored_models:
        best_scored = max(scored_models, key=lambda x: x[1])
        if best_scored[1] >= 14:
            findings.append({
                'title': f'{best_scored[0]} Leads on 20-Point Scoring ({best_scored[1]:.1f}/20)',
                'detail': f'Across extraction, interpretation, hallucination avoidance, and reasoning quality, '
                          f'{best_scored[0]} achieved the highest composite score.',
                'severity': 'positive'
            })

    # 7. Hardest files (missed by most models)
    hard_files = []
    for row in matrix:
        if row['ground_truth'] == 'YES':
            missed_by = sum(1 for m in models if row['models'][m]['detected'] in ('NO', 'MISSING', 'ERROR'))
            if missed_by >= len(models) - 1 and missed_by > 0:
                hard_files.append(row['filename'])
    if hard_files:
        findings.append({
            'title': f'{len(hard_files)} Files Detected by Only One Model (or None)',
            'detail': 'These files represent the hardest detection challenges — attacks that only '
                      'a security-specialized model can identify from raw event data: '
                      + ', '.join(html.escape(f) for f in hard_files[:5]),
            'severity': 'insight'
        })

    return findings


# ── False-negative analysis ──────────────────────────────────────────────────

def _build_malicious_description(filename, evidence, malicious_events_raw, keywords):
    """Build a human-readable description of why a file is malicious.

    Falls back to deriving context from the filename and evidence when the
    ground truth only contains generic placeholder text.
    """
    import re

    # Check if we have meaningful (non-generic) malicious_events
    meaningful = [e for e in malicious_events_raw
                  if not e.startswith('Malicious activity indicated by')]
    if meaningful:
        return meaningful

    # Derive attack description from filename
    name = re.sub(r'\.evtx$', '', filename, flags=re.IGNORECASE)
    name = re.sub(r'^ID[\d,\s]+-\s*', '', name)
    name = re.sub(r'^[\d,\s]+-\s*', '', name)
    attack_name = name.strip()

    desc_parts = []
    if attack_name:
        desc_parts.append(f'Attack type: {attack_name}')

    evidence_hints = []
    if evidence.get('commands'):
        cmds = evidence['commands'][:2]
        evidence_hints.append('Commands: ' + '; '.join(str(c)[:80] for c in cmds))
    if evidence.get('processes'):
        procs = [p.split('\\')[-1] for p in evidence['processes'][:3]]
        evidence_hints.append('Processes: ' + ', '.join(procs))
    if evidence.get('network'):
        evidence_hints.append('Network: ' + ', '.join(str(n) for n in evidence['network'][:3]))
    if evidence.get('registry'):
        regs = [r.split('\\')[-1] if '\\' in r else r for r in evidence['registry'][:2]]
        evidence_hints.append('Registry: ' + ', '.join(regs))
    if evidence.get('accounts'):
        evidence_hints.append('Accounts: ' + ', '.join(str(a) for a in evidence['accounts'][:3]))

    if evidence_hints:
        desc_parts.append('Key indicators: ' + ' | '.join(evidence_hints))

    if keywords:
        desc_parts.append('Keywords: ' + ', '.join(keywords))

    return desc_parts if desc_parts else ['No detailed description available']


def compute_fn_analysis(stats, matrix, gt_files, model_order):
    """Categorize false negatives by difficulty and evidence richness."""
    models = model_order
    fn_analysis = []

    for row in matrix:
        if row['ground_truth'] != 'YES':
            continue

        filename = row['filename']
        detected_by = [m for m in models if row['models'][m]['detected'] == 'YES']
        missed_by = [m for m in models if row['models'][m]['detected'] in ('NO', 'MISSING', 'ERROR')]

        if not missed_by:
            continue

        gt = gt_files.get(filename, {})
        evidence = gt.get('evidence', {})
        malicious_events_raw = gt.get('malicious_events', [])
        keywords = gt.get('explanation_keywords', [])

        evidence_count = sum(1 for field in ['event_ids', 'processes', 'accounts', 'commands', 'network', 'registry']
                            if evidence.get(field))

        malicious_desc = _build_malicious_description(filename, evidence, malicious_events_raw, keywords)

        if len(detected_by) == 0:
            difficulty = 'Undetectable'
        elif len(detected_by) <= 1:
            difficulty = 'Hard'
        elif len(detected_by) <= len(models) // 2:
            difficulty = 'Medium'
        else:
            difficulty = 'Easy'

        missed_aligns = [row['models'][m]['alignment'] for m in missed_by if row['models'][m]['alignment'] > 0]
        avg_missed_align = sum(missed_aligns) / len(missed_aligns) if missed_aligns else 0

        fn_analysis.append({
            'filename': filename,
            'detected_by': detected_by,
            'missed_by': missed_by,
            'difficulty': difficulty,
            'evidence_fields': evidence_count,
            'malicious_desc': malicious_desc,
            'evidence': evidence,
            'avg_missed_alignment': avg_missed_align,
        })

    difficulty_order = {'Undetectable': 0, 'Hard': 1, 'Medium': 2, 'Easy': 3}
    fn_analysis.sort(key=lambda x: (difficulty_order[x['difficulty']], -len(x['missed_by'])))

    return fn_analysis


# ── HTML generation ──────────────────────────────────────────────────────────

def _shorten_model_name(name: str, max_len: int = 16) -> str:
    """Produce a short column header from a model name."""
    # Strip common org prefixes
    for prefix in ('openai/', 'mistralai/', 'mistralai_', 'zai-org/', 'qwen/', 'deepseek/'):
        if name.lower().startswith(prefix):
            name = name[len(prefix):]
            break
    if len(name) <= max_len:
        return name
    return name[:max_len - 1] + '\u2026'


def generate_html(stats, matrix, gt_files, findings, fn_analysis, model_order,
                  test_config: Dict[str, Any]):
    models = model_order

    context_window = test_config.get('context_window', 'N/A')
    max_tokens = test_config.get('max_tokens', 'N/A')
    sample_size = test_config.get('sample_size', 'N/A')
    server_label = test_config.get('server', 'Local LLM Server')

    # Color helper
    def score_color(val, thresholds=(80, 50)):
        if val >= thresholds[0]:
            return '#27ae60'
        elif val >= thresholds[1]:
            return '#f39c12'
        return '#e74c3c'

    def rank_badge(rank):
        colors = {1: '#FFD700', 2: '#C0C0C0', 3: '#CD7F32'}
        if rank in colors:
            return f'<span style="background:{colors[rank]};color:#333;padding:2px 8px;border-radius:10px;font-weight:bold;">#{rank}</span>'
        return f'#{rank}'

    # Rank models by F1
    ranked = sorted(models, key=lambda m: -stats[m]['f1'])
    ranks = {m: i + 1 for i, m in enumerate(ranked)}

    # Summary cards
    cards_html = ''
    for model in models:
        s = stats[model]
        rank = ranks[model]
        border_color = score_color(s['f1'] * 100)
        cards_html += f'''
        <div class="model-card" style="border-left: 5px solid {border_color};">
            <div class="card-header">
                <span class="model-name">{html.escape(model)}</span>
                <span class="rank">{rank_badge(rank)}</span>
            </div>
            <div class="card-stats">
                <div class="card-stat">
                    <div class="card-stat-value" style="color:{score_color(s['recall']*100)}">{s['recall']:.0%}</div>
                    <div class="card-stat-label">Recall</div>
                </div>
                <div class="card-stat">
                    <div class="card-stat-value" style="color:{score_color(s['precision']*100)}">{s['precision']:.0%}</div>
                    <div class="card-stat-label">Precision</div>
                </div>
                <div class="card-stat">
                    <div class="card-stat-value" style="color:{score_color(s['f1']*100)}">{s['f1']:.0%}</div>
                    <div class="card-stat-label">F1 Score</div>
                </div>
                <div class="card-stat">
                    <div class="card-stat-value" style="color:{score_color(s['avg_alignment'])}">{s['avg_alignment']:.1f}%</div>
                    <div class="card-stat-label">Alignment</div>
                </div>
                <div class="card-stat">
                    <div class="card-stat-value">{s['malicious']}/{s['total']}</div>
                    <div class="card-stat-label">Detected</div>
                </div>
                <div class="card-stat">
                    <div class="card-stat-value">{s['runtime']:.0f}m</div>
                    <div class="card-stat-label">Runtime</div>
                </div>
            </div>
            <div class="card-detail">
                TP: {s['tp']} | FN: {s['fn']} | FP: {s['fp']} |
                Missing: {s['missing']} | Coverage: {s['coverage_pct']:.0f}% |
                Valid Structure: {s['struct_valid']}/{s['total']} |
                Avg Response: {s['avg_response_time']:.1f}s
            </div>
            <div class="card-detail" style="margin-top:6px;">
                Score: <strong>{s['avg_score_20']:.1f}/20</strong> |
                Hall: {s['avg_hall_score']:.1f}/4 |
                Grades: {' '.join(f'{g}:{c}' for g, c in sorted(s['grade_dist'].items())) if s['grade_dist'] else 'N/A'}
            </div>
        </div>
        '''

    # Detailed comparison table
    table_header = '<th>File</th><th>GT</th>'
    for m in models:
        short = html.escape(_shorten_model_name(m))
        table_header += f'<th>{short}</th>'
    table_header += '<th>Consensus</th>'

    table_rows = ''
    for row in sorted(matrix, key=lambda r: r['consensus']):
        gt_class = 'gt-yes' if row['ground_truth'] == 'YES' else 'gt-no'
        cells = f'<td class="filename">{html.escape(row["filename"][:70])}</td>'
        cells += f'<td class="{gt_class}">{row["ground_truth"]}</td>'

        for model in models:
            m = row['models'][model]
            if m['detected'] == 'YES':
                cls = 'det-yes'
                score_str = f" S:{m['score_20']:.0f}" if m.get('score_20') else ''
                tip = f"Align: {m['alignment']:.0f}% Conf: {m['confidence']:.0f}%{score_str}"
                grade_str = f" {m['grade']}" if m.get('grade') else ''
                cells += f'<td class="{cls}" title="{tip}">YES<br><small>{m["alignment"]:.0f}%{grade_str}</small></td>'
            elif m['detected'] == 'NO':
                fn_cls = 'det-fn' if row['ground_truth'] == 'YES' else 'det-no'
                grade_str = f"<br><small>{m.get('grade', '')}</small>" if m.get('grade') else ''
                cells += f'<td class="{fn_cls}">NO{grade_str}</td>'
            elif m['detected'] == 'ERROR':
                # Treat as a miss for malicious GT, but render as a distinct "error" state.
                err_cls = 'det-fn' if row['ground_truth'] == 'YES' else 'det-err'
                st = html.escape(str(m.get('status', 'error')))
                cells += f'<td class="{err_cls}" title="Status: {st}">ERR</td>'
            elif m['detected'] == 'MISSING':
                miss_cls = 'det-fn' if row['ground_truth'] == 'YES' else 'det-unknown'
                cells += f'<td class="{miss_cls}">MISSING</td>'
            else:
                cells += '<td class="det-unknown">?</td>'

        consensus_color = score_color(row['consensus'] / len(models) * 100, (80, 40))
        cells += f'<td style="font-weight:bold;color:{consensus_color}">{row["consensus"]}/{len(models)}</td>'
        table_rows += f'<tr>{cells}</tr>\n'

    # Key findings section
    findings_html = ''
    if findings:
        findings_html = '<h2>Key Findings</h2>\n'
        for f in findings:
            sev = f['severity']
            findings_html += f'''<div class="finding finding-{sev}">
                <div class="finding-title">{f['title']}</div>
                <div class="finding-detail">{f['detail']}</div>
            </div>\n'''

    # Enhanced false negative analysis
    fn_detail_html = ''
    if fn_analysis:
        hard = sum(1 for f in fn_analysis if f['difficulty'] in ('Hard', 'Undetectable'))
        medium = sum(1 for f in fn_analysis if f['difficulty'] == 'Medium')
        easy = sum(1 for f in fn_analysis if f['difficulty'] == 'Easy')
        fn_detail_html += f'<p><strong>{len(fn_analysis)} files</strong> missed by at least one model: '
        fn_detail_html += f'<span class="difficulty-badge diff-hard">{hard} Hard</span> '
        fn_detail_html += f'<span class="difficulty-badge diff-medium">{medium} Medium</span> '
        fn_detail_html += f'<span class="difficulty-badge diff-easy">{easy} Easy</span></p>'

        for item in fn_analysis:
            diff_cls = 'diff-' + item['difficulty'].lower()
            fn_detail_html += f'''<div class="fn-file">
                <div class="fn-file-header">
                    <span class="fn-file-name">{html.escape(item['filename'])}</span>
                    <span class="difficulty-badge {diff_cls}">{item['difficulty']}</span>
                </div>'''

            for desc_line in item['malicious_desc']:
                escaped = html.escape(desc_line)
                if ':' in escaped:
                    label, rest = escaped.split(':', 1)
                    fn_detail_html += f'<div class="fn-file-detail"><strong>{label}:</strong>{rest}</div>'
                else:
                    fn_detail_html += f'<div class="fn-file-detail">{escaped}</div>'

            if item['avg_missed_alignment'] > 0:
                fn_detail_html += f'<div class="fn-file-detail"><strong>Avg alignment when missed:</strong> {item["avg_missed_alignment"]:.0f}% &mdash; evidence was found but classified as benign</div>'

            fn_detail_html += '<div class="fn-model-tags">'
            for m in models:
                if m in item['detected_by']:
                    fn_detail_html += f'<span class="tag-detected">{html.escape(m)}: detected</span>'
                elif m in item['missed_by']:
                    fn_detail_html += f'<span class="tag-missed">{html.escape(m)}: missed</span>'
            fn_detail_html += '</div></div>\n'
    else:
        fn_detail_html = '<p>No false negatives — all malicious files detected by all models.</p>'

    # Conclusion
    ranked = sorted(models, key=lambda m: -stats[m]['f1'])
    best_model = ranked[0]
    best_s = stats[best_model]
    total_fn_files = len(set(f for m in models for f in stats[m]['fn_files']))
    unanimous = sum(1 for row in matrix if row['ground_truth'] == 'YES' and row['consensus'] == len(models))
    total_malicious = sum(1 for row in matrix if row['ground_truth'] == 'YES')

    conclusion_html = f'''<div class="conclusion">
        <h2>Conclusion</h2>
        <p>This benchmark tested {len(models)} LLMs on their ability to identify malicious activity from
        event XML reconstructed from EvtxECmd CSV output, with no external context, hints, or threat intelligence.</p>

        <p><strong>{best_model}</strong> demonstrated the strongest security analysis capability with
        {best_s['recall']:.0%} recall and {best_s['f1']:.0%} F1 score, detecting {best_s['tp']} of
        {best_s['tp'] + best_s['fn']} malicious files.</p>

        <p>Of {total_malicious} malicious files tested, <strong>{unanimous} ({unanimous/total_malicious*100:.0f}%)</strong>
        were unanimously detected by all models — these represent attack patterns clearly identifiable from raw event data.
        <strong>{total_fn_files}</strong> files were missed by at least one model, revealing where security domain
        knowledge separates specialized models from general-purpose ones.</p>

        <p>A consistent finding across all models: <strong>evidence extraction accuracy far exceeds classification
        accuracy</strong>. Models reliably identify the correct Event IDs, processes, accounts, and commands from
        raw XML, but general-purpose models lack the security context to interpret those indicators as malicious.
        They can see the data — they cannot see the threat.</p>
    </div>'''

    report_html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLM Model Comparison Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f0f2f5; }}
        .container {{ max-width: 1600px; margin: 0 auto; }}
        h1 {{ color: #1a1a2e; font-size: 28px; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #2c3e50; margin-top: 30px; }}

        .meta {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px 20px; margin: 15px 0; border-radius: 4px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px 20px; margin-top: 10px; }}
        .meta-item {{ font-size: 14px; }}
        .meta-item strong {{ color: #856404; }}

        .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px; margin: 20px 0; }}
        .model-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); }}
        .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .model-name {{ font-weight: bold; font-size: 16px; color: #2c3e50; }}
        .card-stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }}
        .card-stat {{ text-align: center; padding: 8px; background: #f8f9fa; border-radius: 5px; }}
        .card-stat-value {{ font-size: 22px; font-weight: bold; }}
        .card-stat-label {{ font-size: 11px; color: #7f8c8d; margin-top: 3px; }}
        .card-detail {{ margin-top: 12px; font-size: 12px; color: #7f8c8d; border-top: 1px solid #eee; padding-top: 10px; }}

        .table-container {{ overflow-x: auto; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{ background: #2c3e50; color: white; padding: 10px 8px; text-align: center; position: sticky; top: 0; }}
        td {{ padding: 8px; text-align: center; border-bottom: 1px solid #eee; }}
        .filename {{ text-align: left; font-size: 12px; max-width: 350px; word-break: break-all; }}

        .gt-yes {{ background: #ffeaa7; font-weight: bold; }}
        .gt-no {{ background: #dfe6e9; }}
        .det-yes {{ background: #d4edda; color: #155724; }}
        .det-no {{ background: #f8f9fa; color: #6c757d; }}
        .det-fn {{ background: #f8d7da; color: #721c24; font-weight: bold; }}
        .det-err {{ background: #fff3cd; color: #856404; font-weight: bold; }}
        .det-unknown {{ background: #e2e3e5; color: #383d41; }}

        .fn-section {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); margin: 20px 0; }}
        .fn-section h3 {{ color: #e74c3c; }}
        .fn-section ul {{ columns: 2; }}
        .fn-section li {{ font-size: 13px; margin: 3px 0; }}

        .legend {{ display: flex; gap: 15px; margin: 10px 0; font-size: 13px; flex-wrap: wrap; }}
        .legend-item {{ display: flex; align-items: center; gap: 5px; }}
        .legend-swatch {{ width: 16px; height: 16px; border-radius: 3px; border: 1px solid #ccc; }}

        .filter-bar {{ margin: 15px 0; }}
        .filter-btn {{ padding: 6px 14px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer; margin: 3px; font-size: 13px; }}
        .filter-btn:hover {{ background: #f0f0f0; }}
        .filter-btn.active {{ background: #3498db; color: white; border-color: #3498db; }}

        .methodology {{ background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); margin: 20px 0; line-height: 1.6; }}
        .methodology > summary {{ list-style: none; padding: 0; cursor: pointer; }}
        .methodology > summary::-webkit-details-marker {{ display: none; }}
        .methodology > summary::before {{ content: "\\25B6  "; font-size: 12px; color: #3498db; }}
        .methodology[open] > summary::before {{ content: "\\25BC  "; }}
        .methodology h3 {{ color: #2c3e50; margin-top: 18px; margin-bottom: 8px; }}
        .methodology p {{ margin: 6px 0; color: #444; font-size: 14px; }}
        .methodology code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
        .methodology .prompt-box {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; font-family: monospace; font-size: 12px; white-space: pre-wrap; margin: 10px 0; }}

        .finding {{ padding: 15px 20px; border-radius: 6px; margin: 10px 0; border-left: 4px solid; }}
        .finding-positive {{ background: #d4edda; border-color: #27ae60; }}
        .finding-negative {{ background: #f8d7da; border-color: #e74c3c; }}
        .finding-insight {{ background: #d1ecf1; border-color: #17a2b8; }}
        .finding-title {{ font-weight: bold; font-size: 15px; color: #2c3e50; margin-bottom: 5px; }}
        .finding-detail {{ font-size: 14px; color: #444; }}

        .fn-file {{ background: white; border: 1px solid #ddd; border-radius: 6px; padding: 15px; margin: 12px 0; }}
        .fn-file-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
        .fn-file-name {{ font-weight: bold; font-size: 14px; color: #2c3e50; }}
        .difficulty-badge {{ padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; }}
        .diff-hard {{ background: #e74c3c; }}
        .diff-medium {{ background: #f39c12; }}
        .diff-easy {{ background: #27ae60; }}
        .diff-undetectable {{ background: #6c757d; }}
        .fn-file-detail {{ font-size: 13px; color: #555; margin: 4px 0; }}
        .fn-model-tags {{ margin-top: 8px; }}
        .fn-model-tags span {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; margin: 2px; }}
        .tag-detected {{ background: #d4edda; color: #155724; }}
        .tag-missed {{ background: #f8d7da; color: #721c24; }}

        .conclusion {{ background: #2c3e50; color: #ecf0f1; padding: 25px; border-radius: 8px; margin: 20px 0; line-height: 1.7; }}
        .conclusion h2 {{ color: #ecf0f1; border-bottom: 2px solid #3498db; padding-bottom: 8px; margin-top: 0; }}
        .conclusion p {{ font-size: 14px; margin: 10px 0; }}
        .conclusion strong {{ color: #3498db; }}
    </style>
</head>
<body>
<div class="container">
    <h1>LLM Security Analysis Capability Benchmark</h1>

    <div class="meta">
        <strong>Test Configuration</strong>
        <div class="meta-grid">
            <div class="meta-item"><strong>Sample Size:</strong> {sample_size} files</div>
            <div class="meta-item"><strong>Distribution:</strong> Even across MITRE ATT&amp;CK tactics</div>
            <div class="meta-item"><strong>Models Tested:</strong> {len(models)}</div>
            <div class="meta-item"><strong>Context Window:</strong> {context_window} tokens</div>
            <div class="meta-item"><strong>Max Output Tokens:</strong> {max_tokens}</div>
            <div class="meta-item"><strong>Server:</strong> {html.escape(str(server_label))}</div>
            <div class="meta-item"><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
    </div>

    <details class="methodology">
        <summary><h2 style="margin:0; color:#2c3e50; display:inline; cursor:pointer;">Methodology</h2></summary>
        <p style="margin-top:12px;">This benchmark evaluates how well LLMs can identify malicious activity in Windows Event Log
        (EVTX) data using <strong>only their inherent security knowledge</strong>. Models receive no hints,
        no MITRE ATT&amp;CK context, and no indication that any file is known to be malicious.</p>

        <h3>What Each Model Receives</h3>
        <p>Each model is given event XML reconstructed from the EvtxECmd CSV rows for one artefact and a minimal prompt:</p>
        <div class="prompt-box">You are a cybersecurity analyst analyzing Windows Event Log data.

Analyze the logs and respond in this EXACT format:

MALICIOUS: [YES or NO]

EVIDENCE:
- Event IDs: [list all Event IDs you found]
- Processes: [list any process names/executables]
- Accounts: [list any usernames]
- Commands: [list any command lines]
- Network: [list any IP addresses or hostnames]
- Registry: [list any registry keys]

EXPLANATION:
[2-3 sentences explaining why this is or is not malicious]

CRITICAL RULES:
1. Use ONLY information found in the event data above
2. Follow the format EXACTLY as shown</div>

        <h3>What This Tests</h3>
        <p>The model must independently:</p>
        <p>&bull; Recognize attack patterns from raw event XML (e.g., RDP hijacking, credential dumping, log clearing)</p>
        <p>&bull; Distinguish malicious behavior from legitimate administration using the same tools</p>
        <p>&bull; Extract structured evidence fields accurately from unprocessed event data</p>
        <p>&bull; Produce a correct malicious/benign classification without any threat intelligence context</p>

        <h3>Scoring &amp; Glossary</h3>
        <table style="width:100%; font-size:13px; margin:10px 0;">
            <tr><th style="width:160px; text-align:left;">Term</th><th style="text-align:left;">Definition</th></tr>
            <tr><td><strong>True Positive (TP)</strong></td><td>A malicious file correctly identified as malicious by the model.</td></tr>
            <tr><td><strong>False Negative (FN)</strong></td><td>A malicious file the model incorrectly classified as benign &mdash; a missed detection.</td></tr>
            <tr><td><strong>False Positive (FP)</strong></td><td>A benign file the model incorrectly classified as malicious &mdash; a false alarm.</td></tr>
            <tr><td><strong>True Negative (TN)</strong></td><td>A benign file correctly identified as benign by the model.</td></tr>
            <tr><td><strong>Precision</strong></td><td>Of all files the model flagged as malicious, what percentage actually were? <code>TP / (TP + FP)</code>. High precision = few false alarms.</td></tr>
            <tr><td><strong>Recall</strong></td><td>Of all files that are actually malicious, what percentage did the model catch? <code>TP / (TP + FN)</code>. High recall = few missed threats.</td></tr>
            <tr><td><strong>F1 Score</strong></td><td>The harmonic mean of precision and recall: <code>2 &times; (P &times; R) / (P + R)</code>. Balances both metrics into a single score. 100% = perfect detection with no false alarms or missed threats.</td></tr>
            <tr><td><strong>Alignment</strong></td><td>How well the model's extracted evidence (Event IDs, processes, accounts, etc.) matches the ground truth, regardless of the malicious/benign classification. Scored per-field using substring and fuzzy matching.</td></tr>
            <tr><td><strong>Confidence</strong></td><td>A heuristic score derived from output structure quality and evidence completeness (not self-reported text).</td></tr>
            <tr><td><strong>Consensus</strong></td><td>How many of the tested models agreed on the detection for a given file. Higher consensus = easier-to-detect attack pattern.</td></tr>
            <tr><td><strong>Ground Truth</strong></td><td>The known-correct classification for each file, established by manual expert review of the EVTX content.</td></tr>
        </table>

        <h3>Constraints</h3>
        <p>Context window: <code>{context_window}</code> tokens. The benchmark reserves <code>{max_tokens}</code> tokens for the response.
        If a file cannot fit within the remaining context budget under the run settings, it is recorded as a
        <strong>Context Exceeded</strong> or <strong>Error</strong> status and treated as a missed detection for malicious files.</p>
    </details>

    <h2>Model Performance Summary</h2>
    <div class="cards">
        {cards_html}
    </div>

    {findings_html}

    <h2>Per-File Detection Matrix</h2>
    <div class="legend">
        <div class="legend-item"><div class="legend-swatch" style="background:#d4edda"></div> Detected (YES)</div>
        <div class="legend-item"><div class="legend-swatch" style="background:#f8d7da"></div> False Negative (missed)</div>
        <div class="legend-item"><div class="legend-swatch" style="background:#f8f9fa"></div> Not detected (NO)</div>
        <div class="legend-item"><div class="legend-swatch" style="background:#fff3cd"></div> Error / Context Exceeded</div>
        <div class="legend-item"><div class="legend-swatch" style="background:#ffeaa7"></div> Ground Truth: Malicious</div>
    </div>

    <div class="filter-bar">
        <button class="filter-btn active" onclick="filterRows('all', this)">All Files</button>
        <button class="filter-btn" onclick="filterRows('disagree', this)">Disagreements Only</button>
        <button class="filter-btn" onclick="filterRows('fn', this)">False Negatives Only</button>
    </div>

    <div class="table-container">
        <table id="matrix-table">
            <thead><tr>{table_header}</tr></thead>
            <tbody>{table_rows}</tbody>
        </table>
    </div>

    <h2>False Negative Analysis</h2>
    <div class="fn-section">
        {fn_detail_html}
    </div>

    {conclusion_html}
</div>

<script>
function filterRows(mode, btn) {{
    const rows = document.querySelectorAll('#matrix-table tbody tr');
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');

    rows.forEach(row => {{
        if (mode === 'all') {{
            row.style.display = '';
        }} else if (mode === 'disagree') {{
            const cells = row.querySelectorAll('td');
            const detections = Array.from(cells).slice(2, -1).map(c => c.textContent.trim().split('\\n')[0]);
            const unique = new Set(detections);
            row.style.display = unique.size > 1 ? '' : 'none';
        }} else if (mode === 'fn') {{
            const hasFN = row.querySelector('.det-fn');
            row.style.display = hasFN ? '' : 'none';
        }}
    }});
}}
</script>
</body>
</html>'''

    return report_html


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Generate HTML comparison report from detection result CSVs'
    )
    parser.add_argument(
        '--csv', nargs='+', metavar='FILE',
        help='Explicit CSV files to compare. If omitted, auto-discovers '
             'detection_results_*.csv from the outputs directory.',
    )
    parser.add_argument(
        '--context-window', type=int, default=8192,
        help='Context window size used during testing (default: 8192)',
    )
    parser.add_argument(
        '--max-tokens', type=int, default=1000,
        help='Max output tokens used during testing (default: 1000)',
    )
    parser.add_argument(
        '--server', type=str, default=config.DEFAULT_LLM_SERVER,
        help='LLM server URL shown in report metadata',
    )
    args = parser.parse_args()

    # Build model→CSV mapping
    if args.csv:
        from forcastl.reporting.csv_output import read_detection_csv
        csv_paths: Dict[str, str] = {}
        for path in args.csv:
            rows = read_detection_csv(path)
            first_row = rows[0] if rows else None
            if first_row and first_row.get('Model'):
                csv_paths[first_row['Model']] = path
            else:
                raise SystemExit(f'Cannot read Model column from {path}')
    else:
        csv_paths = None  # triggers auto-discovery in load_data()

    gt_files, model_data, all_files, model_order = load_data(csv_paths)

    # Derive sample size from the data
    sample_size = max(len(d) for d in model_data.values()) if model_data else 0

    test_config = {
        'context_window': args.context_window,
        'max_tokens': args.max_tokens,
        'sample_size': sample_size,
        'server': args.server,
    }

    stats = compute_stats(model_data, gt_files, all_files, model_order)
    matrix = compute_file_matrix(model_data, gt_files, all_files, model_order)
    findings = compute_findings(stats, matrix, gt_files, model_order)
    fn_analysis = compute_fn_analysis(stats, matrix, gt_files, model_order)
    report = generate_html(stats, matrix, gt_files, findings, fn_analysis,
                           model_order, test_config)

    config.OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = config.OUTPUTS_DIR / f'model_comparison_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f'Report saved to: {output_path}')


if __name__ == '__main__':
    main()
