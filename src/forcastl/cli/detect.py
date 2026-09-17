#!/usr/bin/env python3
"""
MITRE ATT&CK Malicious Activity Detector

Streamlined tool for detecting malicious activity in EVTX files using LLMs.
Focused on: Is it malicious? What evidence supports that?
"""

import sys
import os
import re
import time
import json
import argparse
from pathlib import Path
from typing import List, Dict, Optional
from tqdm import tqdm
from colorama import Fore, Style, init
from datetime import datetime

# Fix Windows console encoding to support Unicode
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Import detection modules
from forcastl import config
from forcastl.core import EVTXParser, MaliciousDetector, PromptManager, LLMModelSelector, LLMClient, FileSelector
from forcastl.core.csv_evidence import DEFAULT_CSV_DIR
from forcastl.reporting import RequestResponseLogger
from forcastl.reporting.console_display import (
    compute_detection as _compute_detection_fn,
    display_result as _display_result_fn,
    display_summary as _display_summary_fn,
    display_repeatability_summary as _display_repeatability_fn,
)
from forcastl.reporting.csv_output import (
    generate_csv as _generate_csv_fn,
    generate_scoring_csv as _generate_scoring_csv_fn,
    write_run_manifest as _write_run_manifest_fn,
)
from forcastl.validation import extract_evidence_from_event, merge_evidence
from forcastl.reporting.run_summary import compute_run_summary

init(autoreset=True)


def _json_safe(o):
    """JSON fallback for checkpoint records — sets to sorted lists, else str."""
    if isinstance(o, (set, frozenset)):
        return sorted(o, key=str)
    return str(o)


class FatalRunAbort(Exception):
    """Raised to STOP a run that hit a non-recoverable backend error (no credit /
    bad key). Retrying these per-file just burns the rest of the corpus stamping
    identical errors — and then the 'completed' run clears its own checkpoint. We
    instead abort immediately, leaving the checkpoint intact so `--resume` finishes
    the remainder once the user fixes billing/auth."""

    def __init__(self, reason: str, file_path: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.file_path = file_path


# Markers of a backend failure that WON'T clear by waiting or retrying — only the
# user can fix it (top up credit, fix the key). Kept tight so a transient 429/5xx
# still errors per-file and the run continues, as before.
_FATAL_API_MARKERS = (
    "credit balance is too low",
    "insufficient_quota",
    "invalid_api_key",
    "invalid x-api-key",
    "authentication_error",
    "incorrect api key",
)


def _is_fatal_api_error(result: dict) -> bool:
    if not result or result.get("status") != "error":
        return False
    blob = f"{result.get('error', '')} {result.get('llm_response', '')}".lower()
    return any(m in blob for m in _FATAL_API_MARKERS)


class MaliciousActivityDetector:
    """Streamlined detector for malicious EVTX analysis"""

    def __init__(self, timeout=120, delay=2.0, max_tokens=None,
                 log_requests=False, verbose=False, input_format='csv', csv_dir=None,
                 difficulty=None, test_set=None, include_benign=False,
                 provider='lmstudio', max_events=None, skip_preflight=False):
        self.timeout = timeout
        self.delay = delay
        self.max_tokens = max_tokens
        self.skip_preflight = skip_preflight
        self.max_events = max_events
        self.runs = 1
        self.verbose = verbose
        self.input_format = input_format
        # CSV-only: nothing parses the binary EVTX; default the CSV corpus dir.
        self.csv_dir = csv_dir if csv_dir is not None else str(DEFAULT_CSV_DIR)
        self.difficulty = difficulty
        self.test_set = test_set
        self.include_benign = include_benign
        self.provider = (provider or 'lmstudio').lower()
        # Initialize components
        self.parser = EVTXParser(verbose=verbose)
        self.detector = MaliciousDetector()
        self.prompt_manager = PromptManager()
        self.model_selector = LLMModelSelector()

        # Logging
        self.log_requests = log_requests
        self.request_logger = None
        if log_requests:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_dir = str(config.OUTPUTS_DIR / f'logs_{timestamp}')
            self.request_logger = RequestResponseLogger(log_dir, enabled=True)

        # Model info
        self.server_url = None
        self.selected_model = None
        self.llm_client = None
        self.metadata = self._load_metadata()
        self.file_selector = FileSelector(
            metadata=self.metadata,
            input_format=self.input_format,
            csv_dir=self.csv_dir,
            difficulty=self.difficulty,
            test_set=self.test_set,
            verbose=self.verbose,
            ground_truth_data=self.detector.ground_truth_data,
            include_benign=self.include_benign,
        )

    def _load_metadata(self) -> Dict:
        """Load file metadata"""
        try:
            with open(config.METADATA_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print(f"{Fore.GREEN}[OK] Loaded metadata for {len(data.get('files', {}))} files{Style.RESET_ALL}\n")
            return data
        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR] metadata.json not found{Style.RESET_ALL}")
            sys.exit(1)

    def setup_llm(self, server: str = None, model: str = None):
        """Connect to LLM server and select model"""
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}MALICIOUS ACTIVITY DETECTOR{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

        if self.provider == 'anthropic':
            if not model:
                print(f"{Fore.RED}[ERROR] --model is required for Anthropic provider{Style.RESET_ALL}")
                return
            from forcastl.core.anthropic_client import AnthropicClient
            try:
                self.llm_client = AnthropicClient(
                    model_id=model,
                    timeout=self.timeout,
                    max_tokens=self.max_tokens,
                )
            except RuntimeError as e:
                print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
                return
            self.server_url = "anthropic://api"
            self.selected_model = {"id": model, "name": model}
            print(f"{Fore.GREEN}[OK] Anthropic client ready (model: {model}){Style.RESET_ALL}")
            return

        if self.provider == 'openai':
            if not model:
                print(f"{Fore.RED}[ERROR] --model is required for OpenAI provider{Style.RESET_ALL}")
                return
            from forcastl.core.openai_client import OpenAIClient
            try:
                self.llm_client = OpenAIClient(
                    model_id=model,
                    timeout=self.timeout,
                    max_tokens=self.max_tokens,
                )
            except RuntimeError as e:
                print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
                return
            self.server_url = "openai://api"
            self.selected_model = {"id": model, "name": model}
            print(f"{Fore.GREEN}[OK] OpenAI client ready (model: {model}){Style.RESET_ALL}")
            return

        if server and model:
            # Non-interactive: use provided server and model
            self.model_selector.server_url = server
            if not self.model_selector.fetch_available_models():
                print(f"{Fore.RED}[ERROR] Could not connect to {server}{Style.RESET_ALL}")
                return
            # Find the requested model
            matched = [m for m in self.model_selector.available_models
                       if model.lower() in m.get('id', '').lower()
                       or model.lower() in m.get('name', '').lower()]
            if not matched:
                print(f"{Fore.RED}[ERROR] Model '{model}' not found. Available:{Style.RESET_ALL}")
                for m in self.model_selector.available_models:
                    print(f"  - {m.get('id', m.get('name'))}")
                return
            self.model_selector.selected_model = matched[0]
            name = matched[0].get('name', matched[0].get('id'))
            print(f"{Fore.GREEN}[OK] Selected model: {name}{Style.RESET_ALL}")
        else:
            # Interactive mode
            self.model_selector.run()

        # Store selections
        self.server_url = self.model_selector.server_url
        self.selected_model = self.model_selector.selected_model
        if self.selected_model:
            self.llm_client = LLMClient(
                server_url=self.server_url,
                model_id=self._get_model_id(),
                timeout=self.timeout,
                max_tokens=self.max_tokens,
            )

    def _get_model_id(self) -> str:
        """Get consistent model identifier (prefer 'id', fallback to 'name')"""
        return self.selected_model.get('id', self.selected_model.get('name', 'unknown'))

    def send_to_llm(self, prompt: str) -> tuple:
        """Send prompt to the client, with a hard wall-clock backstop.

        The SDK's own timeout can fail to fire on a wedged socket (e.g. after the
        host sleeps mid-request), freezing the whole run. The watchdog budget sits
        above the SDK's normal worst case (timeout x internal retries) so it only
        trips on a genuine hang, then errors the file so the loop continues.
        """
        import time as _t
        from forcastl.core.runtime import run_with_timeout, CallTimeout
        budget = (self.timeout or 120) * 3 + 30
        start = _t.time()
        try:
            return run_with_timeout(self.llm_client.send_to_llm, budget, prompt)
        except CallTimeout:
            return (f"Error: hard timeout after {budget:.0f}s (request wedged)",
                    _t.time() - start)

    def _extract_sampled_evidence(self, events: list) -> Dict:
        """Extract actual evidence from the events that were sent to the LLM."""
        evidence = {
            'event_ids': set(),
            'processes': set(),
            'accounts': set(),
            'commands': set(),
            'network': set(),
            'registry': set(),
        }
        for event in events:
            ev = extract_evidence_from_event(event)
            merge_evidence(evidence, ev)
        return evidence

    def process_file(self, file_path: str, file_info: Dict) -> Optional[Dict]:
        """Process a single artefact (resolved CSV-only).

        ``file_path`` is an EVTX-named LOGICAL key from metadata; the binary
        EVTX is never read. Resolve the matching EvtxECmd CSV by stem and parse
        that.
        """
        try:
            # Resolve and parse events from the EvtxECmd CSV (CSV-only).
            csv_path = self.file_selector._find_csv_for_evtx(file_path)
            if not csv_path:
                return {
                    'file_path': file_path,
                    'llm_response': 'Error: No matching CSV found',
                    'response_time': 0,
                    'status': 'error',
                    'error': f'No matching CSV found for {Path(file_path).name} in {self.csv_dir}',
                    'prompt': ''
                }
            events = self.parser.parse_csv_file(csv_path)

            if not events:
                return {
                    'file_path': file_path,
                    'llm_response': 'Error: No events parsed from file',
                    'response_time': 0,
                    'status': 'error',
                    'error': 'No events parsed from file',
                    'prompt': ''
                }

            original_event_count = len(events)
            event_cap_applied = False
            if self.max_events and original_event_count > self.max_events:
                events = events[: self.max_events]
                event_cap_applied = True
            effective_event_count = len(events)

            # Format and create prompt
            formatted_logs = self.parser.format_for_llm_pure_raw_xml(events)
            prompt = self.prompt_manager.generate_simple_malicious_prompt(formatted_logs)

            # Extract evidence from the exact artefact content sent to the model.
            sampled_evidence = self._extract_sampled_evidence(events)

            # Send to LLM
            llm_response, response_time = self.send_to_llm(prompt)

            # Detect server-side context overflow
            status = 'processed'
            error_reason = None
            if isinstance(llm_response, str) and llm_response.startswith("Error:"):
                lower = llm_response.lower()
                if any(k in lower for k in ("context", "too long", "max.*length", "token limit")):
                    status = 'context_exceeded'
                else:
                    status = 'error'
            elif isinstance(llm_response, str):
                # Catch prompt-echo / repetition-loop responses (typical of
                # under-quantized models). Scoring these would treat the
                # prompt template as a positive detection and poison FP/hall
                # metrics — route them to the error bucket instead.
                from forcastl.core.response_parser import (
                    looks_like_prompt_echo, is_incomplete_response)
                is_echo, why = looks_like_prompt_echo(llm_response)
                if is_echo:
                    status = 'error'
                    error_reason = f'prompt_echo: {why}'
                else:
                    # A response with no MALICIOUS verdict (empty / a reasoning
                    # model that ran out of output budget mid-think) must not
                    # default to a benign classification — bucket it as an error
                    # so it can't masquerade as a false negative.
                    incomplete, ireason = is_incomplete_response(llm_response)
                    if incomplete:
                        status = 'error'
                        error_reason = f'incomplete_response: {ireason}'

            # Log interaction
            if self.request_logger:
                model_name = self._get_model_id()
                self.request_logger.log_interaction(
                    prompt=prompt,
                    response=llm_response,
                    file_path=file_path,
                    expected_values=file_info,
                    score_result={'detection_mode': True},
                    response_time=response_time,
                    model_name=model_name
                )

            result = {
                'file_path': file_path,
                'llm_response': llm_response,
                'response_time': response_time,
                'status': status,
                'prompt': prompt,
                'sampled_evidence': sampled_evidence,
                'artefact_text': formatted_logs,
                'event_cap_applied': event_cap_applied,
                'original_event_count': original_event_count,
                'effective_event_count': effective_event_count,
            }
            if error_reason:
                result['error'] = error_reason
            return result

        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error processing {Path(file_path).name}: {e}{Style.RESET_ALL}")
            return {
                'file_path': file_path,
                'llm_response': f"Error: {str(e)}",
                'response_time': 0,
                'status': 'error',
                'error': str(e),
                'prompt': ''
            }

    def compute_detection(self, result, file_info):
        return _compute_detection_fn(result, file_info, self.detector)

    def display_result(self, result, file_info):
        _display_result_fn(result, file_info, self.detector)

    def _lookup_file_tag(self, filename: str, tag: str) -> Optional[str]:
        return self.file_selector._lookup_file_tag(filename, tag)

    def select_files(self, mode: str = None, sample_size: int = None) -> List[Dict]:
        return self.file_selector.select_files(mode=mode, sample_size=sample_size)

    def execute_runs(self, test_files: List[Dict], runs: Optional[int] = None) -> List[List[Dict]]:
        """Run ``run_detection`` ``runs`` times; set ``self.runs`` to executed count."""
        n = runs if runs is not None else getattr(self, "runs", 1) or 1
        if n < 1:
            n = 1
        all_runs: List[List[Dict]] = []
        for i in range(n):
            all_runs.append(self.run_detection(test_files, run_num=i + 1))
        self.runs = n
        return all_runs

    def _resume_path(self, run_num: int) -> Path:
        """Per-run checkpoint file (one JSON line per completed file)."""
        safe = re.sub(r"[^\w.-]", "_", str(self._get_model_id()))
        return config.OUTPUTS_DIR / f".resume-{safe}-run{run_num}.jsonl"

    def clear_resume_checkpoints(self, runs: int) -> None:
        """Remove checkpoints once a run has produced its final reports."""
        for n in range(1, max(runs, 1) + 1):
            try:
                self._resume_path(n).unlink(missing_ok=True)
            except OSError:
                pass

    def run_detection(self, test_files: List[Dict], run_num: int = 1) -> List[Dict]:
        """Process all test files, checkpointing each result so an interrupted
        run (sleep, crash, quota-out, kill) can be continued with --resume instead
        of repeating the paid/slow calls already made."""
        results: List[Dict] = []
        ckpt = self._resume_path(run_num)
        done = set()
        if getattr(self, "resume", False) and ckpt.exists():
            for line in ckpt.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                done.add(rec.get("_key"))
                results.append(rec)
            if done:
                print(f"{Fore.YELLOW}Resuming: {len(done)} file(s) already complete - "
                      f"skipping{Style.RESET_ALL}")

        pending = [fi for fi in test_files if fi['full_path'] not in done]
        if not pending:
            print(f"{Fore.GREEN}All selected files already in checkpoint - nothing to do.{Style.RESET_ALL}")
            return results

        print(f"\n{Fore.CYAN}Processing {len(pending)} files...{Style.RESET_ALL}\n")
        config.OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

        def _run_one(file_info: Dict) -> None:
            result = self.process_file(file_info['full_path'], file_info)
            if not result:
                return
            # Non-recoverable backend error (no credit / bad key): stop the whole
            # run NOW, before checkpointing this file, so the checkpoint holds only
            # the genuinely-completed files and `--resume` retries this one + the
            # rest once the user fixes billing/auth.
            if _is_fatal_api_error(result):
                raise FatalRunAbort(result.get('error') or result.get('llm_response', ''),
                                    file_info['full_path'])
            self.compute_detection(result, file_info)
            self.display_result(result, file_info)
            results.append(result)
            rec = dict(result)
            rec["_key"] = file_info['full_path']
            with open(ckpt, "a", encoding="utf-8") as cf:
                cf.write(json.dumps(rec, default=_json_safe) + "\n")
                cf.flush()
                os.fsync(cf.fileno())

        if len(pending) > 1:
            with tqdm(total=len(pending), desc="Processing files", unit="file") as pbar:
                for file_info in pending:
                    _run_one(file_info)
                    pbar.update(1)
                    time.sleep(self.delay)
        else:
            _run_one(pending[0])

        return results

    def _compute_run_summary(self, results: List[Dict]) -> Dict:
        return compute_run_summary(results, self.detector.ground_truth_data or {})

    def _write_run_manifest(self, *, run_id, started_at, finished_at, mode,
                             sample_size, results, outputs,
                             selected_files=None, recommendations=None,
                             summary_fn=None):
        return _write_run_manifest_fn(
            run_id=run_id, started_at=started_at, finished_at=finished_at,
            mode=mode, sample_size=sample_size, results=results, outputs=outputs,
            model_id=self._get_model_id(), input_format=self.input_format,
            csv_dir=self.csv_dir,
            max_tokens=self.max_tokens, timeout=self.timeout, delay=self.delay,
            difficulty=self.difficulty, test_set=self.test_set,
            server_url=self.server_url, selected_files=selected_files,
            recommendations=recommendations,
            compute_run_summary=summary_fn or self._compute_run_summary,
        )

    def generate_reports(self, results: List[Dict], *, run_id: str = None, started_at: str = None,
                         finished_at: str = None, mode: str = None, sample_size: int = None,
                         selected_files: Optional[List[Dict]] = None,
                         all_runs: Optional[List[List[Dict]]] = None) -> Dict[str, str]:
        """Generate HTML and CSV reports (and a run manifest)."""
        print(f"\n{Fore.CYAN}Generating Reports{Style.RESET_ALL}")
        print("=" * 50)

        run_id = run_id or datetime.now().strftime('%Y%m%d_%H%M%S')
        started_at = started_at or datetime.now().isoformat(timespec="seconds")
        finished_at = finished_at or datetime.now().isoformat(timespec="seconds")

        model_name = self._get_model_id()
        config.OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

        outputs: Dict[str, str] = {}

        # Compute the run summary first so recommendations can fold in the
        # run-level verdict (PASS/CAUTION/FAIL) alongside per-file alerts.
        # With --runs N the manifest summary/verdict aggregates ALL runs
        # (mean rates, per-run spread) — not just the last one; the per-file
        # rows in `results` stay from the final run.
        if all_runs and len(all_runs) > 1:
            from forcastl.reporting.run_summary import aggregate_run_summaries
            per_run = [self._compute_run_summary(r) for r in all_runs]
            summary = aggregate_run_summaries(per_run)
            summary_fn = lambda _results: summary
        else:
            summary = self._compute_run_summary(results)
            summary_fn = None

        # Generate recommendations once, shared by manifest and downstream consumers
        from forcastl.reporting.recommendations import generate_recommendations
        rec_config = {
            "max_tokens": self.max_tokens,
            "model_name": model_name,
            "timeout": self.timeout,
        }
        recommendations = generate_recommendations(results, rec_config, summary=summary)

        # HTML generation is replaced by on-demand PDF rendering in the web UI
        # (see /api/runs/{manifest}/pdf). CSV remains for data export.

        # CSV Export
        try:
            csv_file = self._generate_csv(results, run_id=run_id)
            print(f"{Fore.GREEN}[OK] CSV Export: {csv_file}{Style.RESET_ALL}")
            outputs["csv_results"] = str(Path(csv_file))
        except Exception as e:
            print(f"{Fore.YELLOW}[WARN] CSV Export Failed: {e}{Style.RESET_ALL}")

        # Run manifest
        try:
            manifest_file = self._write_run_manifest(
                run_id=run_id,
                started_at=started_at,
                finished_at=finished_at,
                mode=mode,
                sample_size=sample_size,
                results=results,
                outputs=outputs,
                selected_files=selected_files,
                recommendations=recommendations,
                summary_fn=summary_fn,
            )
            print(f"{Fore.GREEN}[OK] Run Manifest: {manifest_file}{Style.RESET_ALL}")
            outputs["run_manifest"] = manifest_file
        except Exception as e:
            print(f"{Fore.YELLOW}[WARN] Run Manifest Failed: {e}{Style.RESET_ALL}")

        # Log location
        if self.request_logger:
            print(f"{Fore.GREEN}[OK] Request Logs: {self.request_logger.output_dir}/{Style.RESET_ALL}")
            outputs["request_logs_dir"] = str(self.request_logger.output_dir)

        return outputs

    def _generate_csv(self, results, *, run_id=None):
        return _generate_csv_fn(
            results, model_name=self._get_model_id(), run_id=run_id,
            lookup_file_tag=self._lookup_file_tag,
        )

    def display_summary(self, results):
        _display_summary_fn(results)


    def _generate_scoring_csv(self, all_runs):
        _generate_scoring_csv_fn(
            all_runs, model_name=self._get_model_id(),
            lookup_file_tag=self._lookup_file_tag,
        )

    def _display_repeatability_summary(self, all_runs):
        _display_repeatability_fn(all_runs)

    def _preflight(self) -> bool:
        """Probe the model once before the run. Returns False to abort on a hard failure."""
        from forcastl.core.health_check import health_check, HARD_FAIL
        model_id = self._get_model_id()
        print(f"{Fore.CYAN}[PREFLIGHT] Checking {self.provider} model "
              f"'{model_id}'...{Style.RESET_ALL}", flush=True)
        r = health_check(
            provider=self.provider, server=self.server_url, model=model_id,
            timeout=min(self.timeout, 120),
        )
        status, msg = r["status"], r["message"]
        if status in HARD_FAIL:
            print(f"{Fore.RED}[PREFLIGHT] FAILED ({status}): {msg}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Aborting before the run. Fix the above, or pass "
                  f"--skip-preflight to bypass.{Style.RESET_ALL}")
            return False
        if status == "ok":
            print(f"{Fore.GREEN}[PREFLIGHT] OK: {msg}{Style.RESET_ALL}")
            return True
        # Soft: timeout (slow model) / no_verdict (format) — warn and proceed.
        print(f"{Fore.YELLOW}[PREFLIGHT] WARNING ({status}): {msg}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Proceeding anyway - results may be slow or unreliable.{Style.RESET_ALL}")
        return True

    def run(self, server: str = None, model: str = None, mode: str = None, sample_size: int = None, runs: int = 1):
        """Main execution"""
        run_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        started_at = datetime.now().isoformat(timespec="seconds")

        # Setup
        self.setup_llm(server=server, model=model)
        if not self.selected_model:
            print(f"{Fore.RED}[ERROR] No model selected{Style.RESET_ALL}")
            return

        # Pre-flight health check — confirm the model actually responds in the right
        # format before committing to the whole run (abort early instead of erroring
        # on every file). Skip with --skip-preflight.
        if not self.skip_preflight and not self._preflight():
            return

        # Select files
        test_files = self.select_files(mode=mode, sample_size=sample_size)
        if not test_files:
            print(f"{Fore.RED}No files selected{Style.RESET_ALL}")
            return

        all_runs = []
        try:
            for run_num in range(1, runs + 1):
                if runs > 1:
                    print(f"\n{'='*80}")
                    print(f"RUN {run_num}/{runs}")
                    print(f"{'='*80}")

                results = self.run_detection(test_files, run_num=run_num)
                all_runs.append(results)
        except FatalRunAbort as abort:
            # Leave the checkpoint(s) in place — do NOT generate reports for an
            # incomplete run, and do NOT clear checkpoints. Tell the user how to
            # finish it once the backend issue is fixed.
            print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.RED}[ABORTED] Non-recoverable backend error - run stopped to "
                  f"preserve progress.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Reason: {str(abort.reason)[:200]}{Style.RESET_ALL}")
            ckpts = [str(self._resume_path(n)) for n in range(1, runs + 1)
                     if self._resume_path(n).exists()]
            if ckpts:
                print(f"{Fore.CYAN}Checkpoint preserved: {ckpts[0]}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Fix billing/credentials, then re-run the SAME command "
                  f"with --resume to finish only the remaining files.{Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
            self._run_aborted = True
            return

        # Summary (last run)
        self.display_summary(all_runs[-1])

        # Reports
        finished_at = datetime.now().isoformat(timespec="seconds")
        if runs == 1:
            self.generate_reports(
                all_runs[0],
                run_id=run_id,
                started_at=started_at,
                finished_at=finished_at,
                mode=mode,
                sample_size=sample_size,
                selected_files=test_files,
            )
        else:
            self.generate_reports(
                all_runs[-1],
                run_id=run_id,
                started_at=started_at,
                finished_at=finished_at,
                mode=mode,
                sample_size=sample_size,
                selected_files=test_files,
                all_runs=all_runs,
            )
            self._generate_scoring_csv(all_runs)
            self._display_repeatability_summary(all_runs)

        # Reports are written — the run is durable now; drop the checkpoints so a
        # later run of the same command starts fresh instead of resuming.
        self.clear_resume_checkpoints(runs)

        print(f"\n{Fore.GREEN}Detection Complete!{Style.RESET_ALL}")


def main():
    """Entry point"""
    parser = argparse.ArgumentParser(
        description='MITRE ATT&CK Malicious Activity Detector - Streamlined LLM detection tool'
    )
    parser.add_argument('--timeout', type=int, default=120,
                       help='Request timeout in seconds (default: 120)')
    parser.add_argument('--delay', type=float, default=2.0,
                       help='Delay between files in seconds (default: 2.0)')
    parser.add_argument('--log-requests', action='store_true',
                       help='Enable detailed request/response logging')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--server', type=str, default=None,
                       help='LLM server URL (e.g., http://localhost:1234). Skips interactive prompt.')
    parser.add_argument('--model', type=str, default=None,
                       help='Model name/id to use (e.g., foundation-sec-8b). Skips interactive prompt.')
    parser.add_argument('--mode', type=str, choices=['single', 'sample', 'all'], default=None,
                       help='Test mode: single (first file), sample (per tactic), all (every file). Skips interactive prompt.')
    parser.add_argument('--sample-size', type=int, default=None,
                       help='Max files for sample mode (default: 1 per tactic ~11). Spreads evenly across tactics.')
    parser.add_argument('--max-tokens', type=int, default=None,
                       help='Optional cap on LLM output tokens. Default: unset — the '
                            'app does NOT impose a limit; your model server (LM Studio, '
                            'etc.) governs output length. Pass a value only to override.')
    parser.add_argument('--runs', type=int, default=1,
                       help='Number of test runs for repeatability (default: 1)')
    parser.add_argument('--input-format', type=str, choices=['csv'], default='csv',
                       help='Input file format: csv (EvtxECmd output). CSV is the only supported format.')
    parser.add_argument('--csv-dir', type=str, default=str(DEFAULT_CSV_DIR),
                       help='Directory containing CSV files (mirrors the EVTX folder structure). Defaults to the bundled data/csv corpus (override the data root with FORCASTL_DATA_DIR).')
    parser.add_argument('--difficulty', type=str, choices=['easy', 'medium', 'hard'], default=None,
                       help='Filter test files by difficulty tag (requires tag_metadata.py to have been run)')
    parser.add_argument('--test-set', type=str, choices=['A', 'B', 'C', 'D'], default=None,
                       help='Filter test files by test set: A=Known Pattern, B=Obfuscated, C=Noise-heavy, D=Benign (csv mode only)')
    parser.add_argument('--include-benign', action='store_true',
                       help='In sample mode, reserve slots for all benign files (requires --input-format csv)')
    parser.add_argument('--provider', type=str, choices=['lmstudio', 'anthropic', 'openai'], default='lmstudio',
                       help='Inference backend: lmstudio (default, uses --server/--model against an OpenAI-compatible endpoint), anthropic (uses --model + ANTHROPIC_API_KEY env var), or openai (uses --model + OPENAI_API_KEY env var).')
    parser.add_argument('--skip-preflight', action='store_true',
                       help='Skip the pre-flight health check that verifies the model responds in the right format before the run.')
    parser.add_argument('--resume', action='store_true',
                       help='Continue a prior interrupted run of the SAME command: skip files already in the per-run checkpoint (saved after each file) instead of re-calling the model.')
    parser.add_argument('--no-keep-awake', action='store_true',
                       help='Do not hold the host awake during the run (default: prevent idle-sleep cross-platform so a long run is not killed mid-flight).')
    args = parser.parse_args()

    config.require_data_dir()

    detector = MaliciousActivityDetector(
        timeout=args.timeout,
        delay=args.delay,
        max_tokens=args.max_tokens,
        log_requests=args.log_requests,
        verbose=args.verbose,
        input_format=args.input_format,
        csv_dir=args.csv_dir,
        difficulty=args.difficulty,
        test_set=args.test_set,
        include_benign=args.include_benign,
        provider=args.provider,
        skip_preflight=args.skip_preflight,
    )
    detector.resume = args.resume

    from forcastl.core.runtime import keep_awake
    import contextlib as _ctxlib
    guard = _ctxlib.nullcontext() if args.no_keep_awake else keep_awake("forcastl detection run")
    with guard:
        detector.run(server=args.server, model=args.model, mode=args.mode,
                     sample_size=args.sample_size, runs=args.runs)
    if getattr(detector, "_run_aborted", False):
        # Non-recoverable backend error mid-run; checkpoint preserved for --resume.
        raise SystemExit(2)


if __name__ == "__main__":
    main()
