"""Console display functions for detection results.

`compute_detection` does the scoring (the side effect — it writes
`result['detection']`); `display_result` only *reads* that and prints. They
used to be one function named "display" that secretly computed detection.
"""

from pathlib import Path
from typing import List, Dict, Optional
from colorama import Fore, Style

_EVIDENCE_FIELDS = ['event_ids', 'processes', 'accounts', 'commands', 'network', 'registry']


def compute_detection(result: Dict, file_info: Dict, detector) -> Optional[Dict]:
    """Score a per-file result and store it on ``result['detection']``.

    This is the side-effecting compute step. For error/context_exceeded files
    it stores a benign stub; otherwise it runs ``detector.detect``. Returns the
    detection dict (or None for a falsy result). ``display_result`` reads what
    this writes — it no longer computes anything itself.
    """
    if not result:
        return None

    status = result.get('status', 'processed')
    if status in ('error', 'context_exceeded'):
        detection = {
            'is_malicious': False, 'confidence': 0,
            'parsed': {'malicious': None, 'evidence': {f: [] for f in _EVIDENCE_FIELDS}, 'explanation': ''},
            'validation': {'is_valid': False, 'issues': [status], 'evidence_fields_populated': 0},
            'alignment': None,
        }
        result['detection'] = detection
        return detection

    expected_is_malicious = file_info.get('tactic_id') != 'BENIGN'
    ground_truth = {
        'tactic_name': file_info.get('tactic_name', 'Unknown'),
        'technique_name': file_info.get('technique_name', 'Unknown'),
        'event_ids': file_info.get('event_ids', []),
        'is_malicious': expected_is_malicious,
    }
    detection = detector.detect(
        result.get('llm_response', ''), result['file_path'], ground_truth,
        filename=Path(result['file_path']).name,
        sampled_evidence=result.get('sampled_evidence'),
        artefact_text=result.get('artefact_text'),
    )
    result['detection'] = detection
    return detection


def display_result(result: Dict, file_info: Dict, detector=None) -> None:
    """Print a per-file detection summary from ``result['detection']``.

    Pure display: it reads the detection scored by ``compute_detection``. For
    back-compat, if ``result['detection']`` is missing and a ``detector`` is
    supplied, it computes it first.
    """
    if not result:
        return
    if 'detection' not in result:
        if detector is None:
            return
        compute_detection(result, file_info, detector)

    filename = Path(result['file_path']).name
    llm_response = result.get('llm_response', '')

    # Handle error/context_exceeded results
    status = result.get('status', 'processed')
    if status in ('error', 'context_exceeded'):
        print(f"\n{Fore.YELLOW}File: {filename}{Style.RESET_ALL}")
        print("-" * 80)
        print(f"{Fore.RED}[{status.upper()}] {llm_response}{Style.RESET_ALL}")
        print("-" * 80)
        return

    expected_is_malicious = file_info.get('tactic_id') != 'BENIGN'
    detection = result['detection']

    # Display
    print(f"\n{Fore.CYAN}File: {filename}{Style.RESET_ALL}")
    print("-" * 80)
    print(f"{Fore.WHITE}LLM Response:{Style.RESET_ALL}\n")
    print(llm_response)
    print()

    # Structure validation
    validation = detection['validation']
    if validation['is_valid']:
        print(f"{Fore.GREEN}Structure: [+] Valid{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Structure: [!] Issues - {', '.join(validation['issues'])}{Style.RESET_ALL}")

    # Show what LLM extracted
    populated_fields = []
    for field in ['event_ids', 'processes', 'accounts', 'commands', 'network', 'registry']:
        if detection['parsed']['evidence'].get(field):
            populated_fields.append(field.replace('_', ' ').title())
    print(f"LLM Extracted: {', '.join(populated_fields) if populated_fields else 'None'}")
    print()

    # Ground truth alignment
    if detection['alignment']:
        alignment = detection['alignment']
        print(f"{Fore.WHITE}Ground Truth Alignment:{Style.RESET_ALL}")

        if 'field_matches' in alignment:
            print("+" + "-" * 78 + "+")
            print(f"| {'Field':<15} | {'Expected':<20} | {'LLM Detected':<20} | {'Score':<8} |")
            print("+" + "-" * 78 + "+")

            # Malicious field
            detected_mal = detection['parsed']['malicious'] or "?"
            match_icon = "[+]" if alignment['malicious_match'] else "[-]"
            expected_label = 'YES' if expected_is_malicious else 'NO'
            print(f"| {'Malicious':<15} | {expected_label:<20} | {detected_mal:<20} | {match_icon:<8} |")

            # All evidence fields (including registry)
            for field_name in ['event_ids', 'processes', 'accounts', 'commands', 'network', 'registry']:
                llm_detected = detection['parsed']['evidence'].get(field_name, [])
                detected_val = ', '.join(str(e)[:18] for e in llm_detected[:2]) if llm_detected else '-'
                if llm_detected and len(llm_detected) > 2:
                    detected_val += '...'

                if field_name in alignment['field_matches']:
                    field_data = alignment['field_matches'][field_name]
                    expected_val = ', '.join(str(e)[:18] for e in field_data['expected'][:2])
                    if len(field_data['expected']) > 2:
                        expected_val += '...'
                    score = field_data.get('score', 0)
                    score_str = f"{score:.0f}%"
                    if score >= 80:
                        score_display = f"{Fore.GREEN}{score_str}{Style.RESET_ALL}"
                    elif score >= 50:
                        score_display = f"{Fore.YELLOW}{score_str}{Style.RESET_ALL}"
                    else:
                        score_display = f"{Fore.RED}{score_str}{Style.RESET_ALL}"
                else:
                    expected_val = '-'
                    score_display = 'N/A' if llm_detected else '-'

                print(f"| {field_name.replace('_', ' ').title():<15} | {expected_val:<20} | {detected_val:<20} | {score_display:<8} |")

            print("+" + "-" * 78 + "+")
            if alignment.get('score') is not None:
                print(f"Overall Alignment: {alignment['score']:.0f}%")
            else:
                print("Overall Alignment: n/a (no expected evidence fields)")
            print()

    # Per-file Hallucination / Reasoning / Score-breakdown lines were removed
    # from the terminal — they were noisy and the verdict-aware report
    # surfaces the same numbers in aggregate (verdict drivers, avg score
    # tile, grade distribution). Underlying computation still runs because
    # `avg_hallucination_rate` is a verdict driver and `score_breakdown.total`
    # feeds the PDF cover page.
    _DISPLAY_PER_FILE_SCORING = False  # noqa: N806
    hallucination = detection.get('hallucination', {})
    if _DISPLAY_PER_FILE_SCORING and hallucination:
        h_score = hallucination.get('score', 4)
        h_total = hallucination.get('total_hallucinated', 0)
        # Show hallucinated items if any
        if h_total > 0:
            h_items = []
            for field, items in hallucination.get('hallucinated', {}).items():
                if items:
                    label = field.replace('_', ' ').title()
                    h_items.append(f"{label}: {', '.join(str(i) for i in items[:3])}")
            if h_items:
                print(f"{Fore.YELLOW}[!] Hallucinations: {' | '.join(h_items)}{Style.RESET_ALL}")
        print(f"Hallucination Check: {h_score}/4 ({h_total} fabricated items)")

    # Reasoning quality (suppressed — see _DISPLAY_PER_FILE_SCORING above)
    reasoning = detection.get('reasoning', {})
    if _DISPLAY_PER_FILE_SCORING and reasoning:
        r_score = reasoning.get('score', 0)
        r_details = ', '.join(reasoning.get('details', [])) or 'none'
        print(f"Reasoning Quality: {r_score}/4 ({r_details})")

    # Score breakdown (suppressed — see _DISPLAY_PER_FILE_SCORING above)
    score_bd = detection.get('score_breakdown', {})
    if _DISPLAY_PER_FILE_SCORING and score_bd:
        total = score_bd.get('total', 0)
        grade = score_bd.get('grade', '?')
        ext = score_bd.get('extraction', 0)
        interp = score_bd.get('interpretation', 0)
        hall = score_bd.get('hallucination', 0)
        reas = score_bd.get('reasoning', 0)

        grade_color = Fore.GREEN if grade == 'A' else (Fore.YELLOW if grade == 'B' else Fore.RED)
        print(f"\n{grade_color}Score: {total}/20 ({grade}){Style.RESET_ALL}"
              f" \u2014 Extraction: {ext} | Interpretation: {interp}"
              f" | Hallucination: {hall} | Reasoning: {reas}")
    print()

    # Final detection
    if detection['is_malicious']:
        print(f"{Fore.GREEN}Detection: [+] MALICIOUS (confidence: {detection['confidence']:.0f}%){Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Detection: [-] NOT MALICIOUS (confidence: {detection['confidence']:.0f}%){Style.RESET_ALL}")
    print("-" * 80)
    print()

    # Store detection for reporting
    result['detection'] = detection


def display_summary(results: List[Dict]) -> None:
    """Display summary statistics"""
    if not results:
        return

    def _status(r: Dict) -> str:
        return (r.get('status') or 'processed').strip().lower()

    processed = [r for r in results if _status(r) == 'processed']
    failed = [r for r in results if _status(r) != 'processed']

    malicious_count = sum(1 for r in processed if r.get('detection', {}).get('is_malicious', False))
    benign_count = len(processed) - malicious_count
    total = len(results)

    alignments = [r.get('detection', {}).get('alignment', {}).get('score')
                 for r in processed if r.get('detection', {}).get('alignment')]
    alignments = [a for a in alignments if a is not None]
    avg_alignment = sum(alignments) / len(alignments) if alignments else 0

    confidences = [r.get('detection', {}).get('confidence', 0)
                  for r in processed if r.get('detection')]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0

    print(f"\n{Fore.CYAN}Detection Summary{Style.RESET_ALL}")
    print("=" * 50)
    print(f"Total Files: {total}")
    print(f"Processed: {len(processed)}")
    print(f"Errors / Skipped: {Fore.YELLOW}{len(failed)}{Style.RESET_ALL}")
    print(f"Detected as Malicious: {Fore.GREEN}{malicious_count}{Style.RESET_ALL}")
    print(f"Detected as Benign: {Fore.RED}{benign_count}{Style.RESET_ALL}")
    print(f"Average Alignment: {Fore.YELLOW}{avg_alignment:.1f}%{Style.RESET_ALL}")
    print(f"Average Confidence: {avg_confidence:.1f}%")

    # Average Score / Grade Distribution / Avg Hallucination Rate were
    # removed from the run-end terminal summary — those scoring components
    # are still computed (hallucination rate is a verdict driver, total
    # score feeds the PDF cover page), they're just no longer the headline
    # the way they were before the verdict feature.


def display_repeatability_summary(all_runs: List[List[Dict]]) -> None:
    """Display cross-run repeatability summary."""
    print(f"\n{Fore.CYAN}Repeatability Summary ({len(all_runs)} runs){Style.RESET_ALL}")
    print("=" * 50)

    run_scores = []
    run_grades = []
    for results in all_runs:
        scores = [r.get('detection', {}).get('score_breakdown', {}).get('total', 0)
                  for r in results if r.get('detection', {}).get('score_breakdown')]
        avg = sum(scores) / len(scores) if scores else 0
        run_scores.append(avg)

        grades = [r.get('detection', {}).get('score_breakdown', {}).get('grade', 'D')
                  for r in results if r.get('detection', {}).get('score_breakdown')]
        run_grades.append(grades)

    for i, avg in enumerate(run_scores, 1):
        grade_dist = {}
        for g in run_grades[i - 1]:
            grade_dist[g] = grade_dist.get(g, 0) + 1
        dist_str = ', '.join(f"{g}:{c}" for g, c in sorted(grade_dist.items()))
        print(f"  Run {i}: Avg Score {avg:.1f}/20 | Grades: {dist_str}")

    if len(run_scores) > 1:
        mean = sum(run_scores) / len(run_scores)
        variance = sum((s - mean) ** 2 for s in run_scores) / len(run_scores)
        std_dev = variance ** 0.5
        print(f"\n  Mean: {mean:.1f} | Std Dev: {std_dev:.2f} | Range: {min(run_scores):.1f}-{max(run_scores):.1f}")
