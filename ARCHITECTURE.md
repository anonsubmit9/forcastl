# FORCAST-L — Architecture

> How FORCAST-L works, grounded in the source. Scoring uses the frozen `SCORING_VERSION='forcastl_scoring_20pt_v1'` contract (a change bumps the version).
>
> **Naming note.** The project is branded **FORCAST-L** (page title, brand mark, README title) and the package is `src/forcastl/` (the repo dir is `forcast/`). The FastAPI title is `'FORCAST-L UI'` (`webapp/app.py:36`) and the JSON-schema `title` is `'FORCAST-L Test Case'`. Version strings use the `forcastl_*` form; scoring is stamped `SCORING_VERSION='forcastl_scoring_20pt_v1'` (the frozen scoring contract).
>
> **Layout.** Code lives in the installable `src/forcastl/` package; the eval entry points are the console scripts **`forcastl-detect` / `forcastl-web`** (`pyproject.toml [project.scripts]`), mapping to `forcastl.cli.detect:main` / `forcastl.webapp.serve:main`. The corpus lives at `<repo>/data/` (override with `FORCASTL_DATA_DIR`); maintainer utilities live in `tools/` (run `python -m tools.<name>`).

---

## 1. What the tool is

FORCAST-L is a local benchmark harness that evaluates how well an LLM can perform **raw Windows forensic-artefact triage**: given unsummarized Windows Event Log data (event XML reconstructed from the EvtxECmd `.csv` corpus), the model must decide malicious-vs-benign, extract verbatim evidence, and avoid fabricating indicators. A scoring engine grades each response on a 20-point rubric and synthesizes a run-level PASS/CAUTION/FAIL verdict.

The product is a single **CSV/EVTX detection pipeline** — one code path with its own corpus, prompt, scorer, and output schema.

| Entry point | Corpus | Prompt fn | Scorer | Ground truth |
|-------------|--------|-----------|--------|--------------|
| `forcastl-detect` (`cli/detect.py`) | 328 `.csv` under `data/csv` (271 `.evtx` under `data/evtx` are attack provenance only), organized by MITRE tactic folders | `PromptManager.generate_simple_malicious_prompt` | `core/detector.py` `MaliciousDetector.detect` (via `reporting/console_display.compute_detection`) | `ground_truth_evidence.json` (328 entries, field matching) |

### What the web UI drives

- **The web UI (`forcastl-web`, or `python -m forcastl.webapp`) is the documented default entry point**, and its **benchmark runner drives the detection pipeline** (single-model detect runs over the **CSV** corpus). It hardcodes `input_format='csv'` and `csv_dir='data/csv'` (`webapp/static/ui.js:1411`). It never touches the binary EVTX detection corpus.
- The same web app also serves the **Ground-Truth Explorer** at `/gt` (opened from the runner's Advanced options panel) — a **separate curation tool**, not a benchmark run: it does not call a model or score anything; it views each source CSV and edits `ground_truth_evidence.json` in place (§5.1, §4.7).

### The pipeline is CSV-only

Detection is **CSV-only**: `--input-format` accepts **only `csv`** (the sole value and default), and there is **no EVTX detection path**. The detector reads the EvtxECmd CSV corpus via `parse_csv_file`; the binary `.evtx` are never parsed by the tool.

---

## 2. End-to-end data flow: artefact → prompt → model → parsed response → scoring → verdict → report

```
forcastl-detect → cli/detect.py main()   (calls config.require_data_dir() first)
  └─ MaliciousActivityDetector  (loads metadata.json, builds FileSelector)
     └─ run():
        1. setup_llm()              → picks LLMClient / AnthropicClient / OpenAIClient by --provider
        2. select_files(mode,size)  → core/file_selector.py FileSelector.select_files
                                       (difficulty/test_set PREFILTER the pool before sampling)
        3. for each of --runs:
             run_detection() → per file process_file():
               a. parse_csv_file()                        (core/parser.py)
               b. (optional) events[:max_events]          (constructor-only cap; NO CLI flag)
               c. format_for_llm_pure_raw_xml(events)     (raw record XML, blank-line joined, no headers)
               d. generate_simple_malicious_prompt(xml)   (core/prompt.py)
               e. send_to_llm()                           (client returns (text, seconds), never raises)
               f. classify status: processed | context_exceeded | error
        4. generate_reports() → compute_run_summary (or aggregate_run_summaries if --runs>1)
                                → recommendations → CSV → manifest
```

**Parsing (`core/parser.py`).** The model receives **raw event XML only**:
- The CSV path reconstructs XML from the EvtxECmd `Payload` JSON via `_csv_row_to_xml`; files are read `utf-8-sig`; rows without `Payload` or with invalid JSON are skipped; `_normalize_text` does unescape-then-escape-once to avoid double-encoding pre-escaped entities (e.g. SQL Server audit). The CSVs are **EvtxECmd output** — `core/parser.py` keys off EvtxECmd's columns (`Payload`, `EventRecordId`, `MapDescription`, `Provider`, `Channel`, …).
- `format_for_llm_pure_raw_xml` joins `_raw_xml` blocks with blank lines and adds **no** headers/summaries; empty input yields the literal `"No events found in log file."`.
- Note: the CSV dict-level `Event/System` fields are built independently of `_csv_row_to_xml`, so the dict view and the `_raw_xml` view can diverge — **only `_raw_xml` is sent to the model.**

**Prompting (`core/prompt.py`).** The pipeline uses `generate_simple_malicious_prompt`: a strict format demanding `MALICIOUS: YES|NO`, an `EVIDENCE:` block with exactly **6 dash-prefixed fields** (Event IDs, Processes, Accounts, Commands, Network, Registry), and `EXPLANATION:` of **exactly 2-3 sentences**, plus **8 CRITICAL RULES**. `split_simple_malicious_prompt` splits the prompt at the `WINDOWS EVENT LOG DATA:` / `CRITICAL RULES:` markers into a cacheable system block + variable user block (used by the Anthropic/OpenAI clients).

**Status classification (`cli/detect.py process_file`).**
- `context_exceeded`: the response starts with `Error:` and its lowercased text contains `context`, `too long`, or `token limit`.
- `error`: any other error, or a prompt-echo flagged by `looks_like_prompt_echo` (routed to `status='error'` with `error='prompt_echo: <why>'`).
- `processed`: everything else.

**Response parsing (`core/response_parser.py`).** `parse_structured_response` returns `{malicious: 'YES'|'NO'|None, evidence:{6 lists}, explanation, evidence_blob}`. Commands/registry split on `;`; other fields on `,`; `none`/`n/a` → empty; items deduped case-insensitively across **all** fields preserving order; event_ids strip parentheticals/brackets; accounts strip SID annotations; network strips trailing parentheticals.

**Aggregation → verdict (`reporting/run_summary.py`).** Per-file detection dicts are joined to ground truth by basename (with a `.csv`→`.evtx` key fallback) into a confusion matrix; `recall_pct`, `fp_rate_pct`, `precision_pct`, `avg_hallucination_rate`, `confabulation_rate_pct`, and 95% Wilson CIs (`recall_ci_pct`, `fp_rate_ci_pct`) are computed and passed to `core/verdict.py compute_verdict` (the actual source of truth for the tier). With `--runs N>1`, `aggregate_run_summaries` combines the N per-run summaries into across-run mean rates, recomputes the verdict from those means, and records `per_run_rates` + `rate_spread` (min/max) so run-to-run variance is visible.

---

## 3. The scoring & verdict model AS IMPLEMENTED

### 3.1 The 20-point composite (6 / 6 / 4 / 4)

The composite is split **6 / 6 / 4 / 4** (`core/detection_scoring.py compute_score_breakdown`):

| Dimension | Max | How computed |
|-----------|-----|--------------|
| **Extraction** | 6 | `round(6 * alignment.score/100, 1)` when ground-truth alignment present; else fallback `+2.0` (valid structure) + `min(populated_fields, 4)`; capped 6.0. `alignment.score` averages **only the matched evidence fields** — the malicious verdict is not folded into it (it would otherwise be double-counted with Interpretation). When the GT entry has **no** expected evidence fields, `alignment.score is None` and the structural fallback applies. |
| **Interpretation** | 6 | `+4.0` if `is_malicious` matches GT `malicious=='YES'` (or `+2.0` if no GT but a MALICIOUS field parsed); `+1.0` if ≥2 evidence fields populated; `+1.0` if reasoning flagged 'consistent'; capped 6.0. This is the **only** place the verdict match is scored. |
| **NoHallucination** | 4 | see 3.2 |
| **Reasoning** | 4 | `+1` explanation ≥50 chars; `+1` if ≥2 evidence items echoed in explanation; `+1` if mal/benign indicator words consistent with `is_malicious`; `+1` if any of 16 security-domain terms present |

Total = sum, out of 20. **A score is NOT ground-truth-independent**: both Extraction and Interpretation have dual paths (alignment-based when GT supplied, validation-fallback otherwise), so the same response scores differently with vs without ground truth. **Scores from different scoring stamps are not comparable** — every manifest/CSV carries `SCORING_VERSION` so provenance is auditable.

### 3.2 Hallucination score — fixed denominator of 6

`core/hallucination.py detect_hallucinations`: `ratio = min(1.0, total_hallucinated_items / EVIDENCE_FIELD_COUNT)` where `EVIDENCE_FIELD_COUNT = 6` (a **fixed constant, not the claim count**). `score = max(0, round(4*(1-ratio), 1))`. When `sampled_evidence` is absent it returns score `4` (int) — no fabrication penalty is possible. Per-field matching rules (`item_in_actual`, thresholds from `config.FUZZY_MATCH_THRESHOLDS`): event_ids exact-in-set; processes/accounts basename fuzzy ≥0.8; commands substring or fuzzy ≥0.6; network exact-lower; registry normalized substring; cross-field substring fallback requires claim length ≥4. **A claim is a fabrication only if absent from the sampled evidence, the cross-field corpus, the raw artefact text, AND the GT entry's curated `decoded_iocs` allowlist** — the last credits IOCs present only in *encoded* form, e.g. a correctly-deobfuscated payload URL; per-file, `event_ids` excluded.

> **Run-level hallucination % uses a different denominator than the per-file score.** `reporting/run_summary.py avg_hallucination_rate = total_hallucinated_fields / total_claimed_fields` (claim-based), then ×100 feeds the verdict; the per-file *score* divides by the fixed 6. Two normalizations by design.

### 3.3 Grade bands — single-sourced

Canonical bands, **single-sourced** in `core/detection_scoring.py grade_from_total`:

```
A ≥ 17,  B ≥ 14,  C ≥ 10,  D < 10
```

`MaliciousDetector._get_grade` delegates to `grade_from_total` — there is no inline band logic anywhere else. The CSV glossary (`reporting/csv_output.py`) and the `html_report.py` appendix both read `A>=17, B>=14, C>=10`.

### 3.4 Run-level verdict (`core/verdict.py compute_verdict`)

Three drivers, thresholds from `config.VERDICT_THRESHOLDS`:

| Driver | PASS | FAIL | Direction |
|--------|------|------|-----------|
| recall | ≥ 90% | < 60% | higher better |
| fp_rate | ≤ 10% | > 50% | lower better |
| hallucination | ≤ 10% | > 40% | lower better |

Tier strings are **lowercase** `pass`/`caution`/`fail`/`insufficient`. Final tier = worst (max-rank) driver (rank pass<caution<fail). Boundary semantics: `recall==60`→caution, `fp_rate==10`→pass, `fp_rate==50`→caution.

**Insufficient-data rules** (`MIN_SAMPLES_FOR_VERDICT = 30`): tier=`insufficient` (and `insufficient=True`) when `recall_pct is None` (no malicious samples in scope), OR `0 < n_malicious < 30`, OR (`has_benign` and `0 < n_benign < 30`). **Wilson 95% CIs** (`wilson_ci`, z=1.96) bound recall `(tp, n_malicious)` and fp `(fp, n_benign)`.

The verdict is computed **server-side in the run pipeline** (`core/verdict.py`, called by `reporting/run_summary.py`), not in the webapp. `reporting/recommendations.py` only *reads* the already-computed `verdict.tier`, and `webapp/app.py`/`ui.js` only render `summary.verdict` (the thresholds — recall 90/60, fp 10/50, hall 10/40 — are mirrored in `ui.js` for display).

---

## 4. Corpus & ground-truth model (exact numbers)

### 4.1 On-disk corpus (verified by `find`)

> **Provenance.** The corpus is **100% real and contains material under two licenses** — no synthetic data:
> - **265 attack files** — mdecrevoisier's **EVTX-to-MITRE-Attack** (`github.com/mdecrevoisier/EVTX-to-MITRE-Attack`, **CC0 1.0**), tagged `source: "folder_structure"`. Its README + LICENSE and the `TA00xx-Tactic/Txxxx-Technique/` folder taxonomy ship in `data/evtx/`.
> - **63 benign files** — **NextronSystems/evtx-baseline** (`github.com/NextronSystems/evtx-baseline`, **Apache-2.0**), real Windows baseline sliced into single-technique near-misses, tagged `source: "evtx-baseline"`.
>
> Both are transformed to CSV with **EvtxECmd** (the schema — `RecordNumber, EventRecordId, MapDescription, PayloadData1-6, Payload, …` — is EvtxECmd's); the model is fed event XML reconstructed from those rows. The `NOTICE` carries both attributions + EvtxECmd; both LICENSEs ship in `data/evtx/`.

| Asset | Count | Path |
|-------|-------|------|
| CSV detection corpus | **328** `.csv` = 265 attack-source + 63 benign-source | `data/csv` (benign isolated in `data/csv/_benign`) |
| EVTX detection corpus (attack provenance only) | **271** `.evtx` | `data/evtx` (+ `LICENSE`, `README`, the evtx-baseline LICENSE) |
| `metadata.json` | — | `config.METADATA_FILE` = `data/metadata.json` |
| `ground_truth_evidence.json` | — | `config.GROUND_TRUTH_FILE` = `data/ground_truth_evidence.json` |

The CSV corpus is organized into MITRE-tactic folders plus `_benign` and `EVTX_full_APT_attack_steps`, over **11 MITRE tactic folders** (the tactic set is **sparse** — `TA0001..TA0009`, then `TA0011`, then `TA0040`; **there is no `TA0010`**). `_benign` exists **only** under `data/csv` — there is no `_benign` under `data/evtx`, consistent with the code's "benign artefacts are CSV-only" rule.

### 4.2 The CSV corpus is fully tracked

**All 328 on-disk CSVs have both `metadata.json` and `ground_truth_evidence.json` rows** — the catalogues align 1:1, and every entry is scoreable.

### 4.3 Entry counts across the three sources (all real, by design)

| Source | Entries | Breakdown |
|--------|---------|-----------|
| disk (live CSV) | 328 | 265 attack-source + 63 benign-source |
| `metadata.json` `files` | **328** | 265 `folder_structure` + 63 `evtx-baseline`; zero `excluded` |
| `ground_truth_evidence.json` `files` | **328** | 219 malicious `YES` + 109 benign `NO` |

Both catalogues are keyed by **`.evtx` filename only** (never `.csv`); a CSV maps to its GT entry by swapping `.csv`→`.evtx`. The `.evtx` key is a *logical join key* even for benign files whose real on-disk path is a `.csv`. The **109 benign labels** split **63 `evtx-baseline`** (goodware near-misses) **+ 46 `folder_structure`** (attack-dataset slices relabeled benign on in-artifact intent, which keep their attack tactic). The verdict and sampler key on the **GT label**, not the folder or source.

The three catalogues align 1:1 — disk CSVs, `metadata.json`, and `ground_truth_evidence.json` are the **same 328 files** (locked by `tests/test_corpus_sizes.py`: `GT_TOTAL=328`, `GT_MALICIOUS=219`, `GT_BENIGN=109`, `METADATA_TOTAL=328`, `METADATA_EXCLUDED=0`). The 271 binary `.evtx` under `data/evtx*/` are upstream attack provenance only and are not tracked in either catalogue.

**Headers:** both `_metadata.total_files` read **328** and match their own `files`-dict lengths.

### 4.4 Difficulty & test_set

The CSV corpus carries a lowercase `difficulty` field (`easy/medium/hard`) and a `test_set` field (`A/B/C/D`, where **D = benign**). The distribution is **skewed easy** (live: 306 easy / 9 medium / 13 hard).

So any claim of a "balanced easy/medium/hard CSV benchmark" is false — the difficulty labels are hand-assigned and overwhelmingly `easy`. `cli/detect.py` allows `--test-set {A,B,C,D}`. **Difficulty/test_set filters apply to the candidate pool BEFORE sampling**, so `--difficulty hard --sample-size 50` returns up to the 13 hard files rather than only those that happened to land in the sample.

### 4.5 Ground-truth evidence schema

Each `ground_truth_evidence.json` entry has `malicious` (`YES`/`NO` string) + an `evidence` dict with **9 sub-lists**: the **6-field core** (`event_ids, processes, accounts, commands, network, registry`) plus 3 supplementary `attack_processes/attack_accounts/attack_commands`. Some entries also carry an optional entry-level **`decoded_iocs`** list (a sibling of `evidence`, not inside it) — curated IOCs present in the artefact only in encoded form, consulted by the hallucination check (§3.2). The validator's canonical set (`validation/ground_truth.py REQUIRED_EVIDENCE_FIELDS`) is only the **6 core**; `validate_schema` does **not** enforce difficulty, test_set, the `attack_*` fields, or `decoded_iocs` (the last is inert to validation and to the 6-field comparison). The production comparator `core/ground_truth_compare.py compare_ground_truth_evidence` scores against the **base evidence field** (its `_expected(field)` helper returns `evidence[field]`, the full forensic inventory); the `attack_*` sidecars are interpretation metadata only and are **not** read for scoring.

Population (all 328, live snapshot — shifts with GT-Explorer curation): `event_ids` 100%, `accounts` ~84%, `processes` ~57%, `commands` ~48%, `network` ~33%, `registry` ~20%. `event_ids` is the only field populated 100%; `network`/`registry` are sparse.

### 4.6 MITRE encoding

MITRE is per-file in `metadata.json` via `tactic_id`+`tactic_name` and `technique_id`+`technique_name`, echoed in the folder hierarchy. **11 distinct tactics**, **60 distinct technique IDs** across the 265 attack entries. The 63 `evtx-baseline` benign files use sentinel `tactic_id='BENIGN'`; the 46 `folder_structure` files relabeled benign keep their original attack tactic.

### 4.7 Ground truth is hand-curated

`ground_truth_evidence.json` (both the 6 evidence fields and the labels) is **hand-curated** through the Ground-Truth Explorer — see §5.1 (the tool) and §5.2 (the curation model and its implications for re-extraction and scoring).

---

## 5. The web app (`webapp/`)

FastAPI + Uvicorn single-page app, the documented default entry point.

- **Launch:** `forcastl-web` or `python -m forcastl.webapp` (→ `forcastl/webapp/serve.py main`, which calls `config.require_data_dir()` first), `--host 127.0.0.1 --port 8000 [--reload]`. ASGI object `forcastl.webapp.app:app` (title `'FORCAST-L UI'`).
- **Concurrency:** `MAX_CONCURRENT_JOBS = 3` (`webapp/app.py`); a 4th concurrent run → HTTP **429**. Jobs tracked in an in-process `JOBS` dict with **no persistence** — a server restart loses job/log handles. Finished jobs beyond `MAX_FINISHED_JOBS = 50` are evicted when a new job starts (and their log handles closed) so the dict can't grow unbounded.
- **Modes (`BENCH_PRESETS`, `ui.js:142-147`):** `smoke = {mode:'sample', sample_size:5, include_benign:true}`, `standard = {mode:'sample', sample_size:120, include_benign:true}`, `full = {mode:'all', include_benign:true}`. All three force `input_format='csv'`, `csv_dir='data/csv'`; difficulty/test_set always null.
- **Effective file counts.** `FileSelector` reserves benigns by **GT label**, so the surfaced sample size is not the file count. Three rules shape every selection:
  - *Split:* small/edge samples cap the benign reservation at **15** (`SMOKE_BENIGN_CAP`); a verdict-capable run splits the budget **evenly** between classes (each floored at `MIN_SAMPLES_FOR_VERDICT`, capped by availability, slack handed to the scarcer class).
  - *Difficulty order:* every pool is sorted **hard→medium→easy** (stable, GT difficulty) so scarce discriminating cases are picked first — otherwise the ~93%-easy corpus yields an almost-all-easy sample that flatters recall.
  - *Source-proportional benign:* the benign reservation is drawn largest-remainder over `metadata.source` (evtx-baseline goodware vs folder_structure near-misses) so a sample's **FP rate tracks the full corpus** (difficulty order preserved within each source).

  Resulting counts: **Smoke** `5` → ~**16** (≤15 benign + ≥1 attack; a pipeline check, not a scored sample). **Standard** `120` → **60 benign + 60 attack**, with **all 20 medium+hard attacks (9 med + 11 hard) + both hard benign always included** (verdict-grade overall; per-difficulty is descriptive coverage, not its own verdict); derivable from a Full run for free. **Full** → all **328**. `include_benign` is a **no-op for `mode='all'`**.
- **Request flow:** `ui.js startRun()` → `buildRequestBody()` → `POST /api/run/detect` → `run_detect()` validates a pydantic `DetectRequest` (sample_size 1–500; max_tokens 100–65536, **default unset/None** — no cap unless requested; timeout 10–600 default 300; delay 0–30 default 0.2; runs 1–10 default 1; `csv_dir` must resolve inside `PROJECT_ROOT`) → builds argv for `python -m forcastl.cli.detect` → `subprocess.Popen(cwd=PROJECT_ROOT, stdout→outputs/web_job_<id>.log)`. Cloud API keys flow via env only.
- **Live logs:** HTTP **polling** (not SSE/WebSocket). `GET /api/jobs/{id}/log?tail=` reads only the file tail (`tail*200` bytes). Interval 3 s while running / 30 s idle, paused when the tab is hidden. Stall flags at >2× (`stall-warn`) and >3× (`stall-bad`) the per-file timeout.
- **Run history:** reconstructed from `outputs/run_manifest_*.json`. Runs indexed by `run_id` via a cached `_run_id_index_map` (invalidated on outputs mtime change). `GET /api/runs` lists sorted by `started_at` desc (falling back to manifest filename timestamp).
- **Export:** `GET /api/runs/{manifest}/pdf` (lazy-rendered under a lock with a staleness re-check so concurrent requests don't double-render, cached beside the manifest, regenerated when manifest is newer) and `/xlsx` (2-sheet workbook). `/api/outputs/csv` returns **413** for files over 50 MB instead of loading them whole. XLSX 404s if no CSV recorded/on disk, 500s if `openpyxl` missing.
- **Security:** strict CSP + `X-Content-Type-Options nosniff` + `X-Frame-Options DENY`; `/api/outputs/file` restricted to `{.html,.csv,.json,.txt,.log,.pdf}` within `OUTPUTS_DIR`; pdf/xlsx names reject `/ \ ..` and require `.json`; `_validate_server_url` enforces http/https, no credentials, blocks SSRF prefixes (`169.254.`, `0.`) and `metadata.google.internal`. Cloud API keys are passed to the subprocess **via env only** — never argv, manifest, or log; stored only in browser localStorage.

**Static assets & defaults:** the server input defaults to `http://localhost:1234` (LM Studio), aligned with `config.DEFAULT_LLM_SERVER`; `webapp/static/` holds `ui.js`, `index.html`, `favicon.svg`, and the Explorer's `gt.html` + `gt.js`.

### 5.1 The Ground-Truth Explorer (`webapp/gt_explorer.py`) — the curation tool

Ground truth is **hand-curated** through the Explorer, a visual annotator served by the **same FastAPI app** (`gt_explorer.router` is mounted via `app.include_router(gt_explorer.router)`, `webapp/app.py:320-321`). It is a curation tool, **not** a benchmark run: it never calls a model or computes a score — it views each source CSV and edits `data/ground_truth_evidence.json` in place. The page lives at **`GET /gt`** (`static/gt.html` + `static/gt.js`), opened from the runner's **Advanced options** panel ("Ground-Truth Explorer →"); the API is under **`/api/gt/*`**.

| Route | Returns / does |
|-------|----------------|
| `GET /gt` | the Explorer page (`static/gt.html`) |
| `GET /api/gt/files` | **live** corpus listing read fresh on each call (so dataset expansion shows immediately): per file `malicious`, `source`, `difficulty`, per-field GT `counts` (the 6 core fields), and `reviewed`; plus a `reviewed_count` total |
| `GET /api/gt/file/{name}` | one file's events (recursively-flattened Payload) + its 6-field GT `evidence` + `malicious` label + `reviewed` (events capped at `_MAX_EVENTS = 800`, with a `truncated` flag) |
| `POST /api/gt/file/{name}/evidence` | add/remove **one** evidence value (artefact-grounded) |
| `POST /api/gt/file/{name}/evidence/batch` | apply a **staged set** of `adds`/`removes` + an optional `label`/`label_reason` in **ONE write** (the GUI's Save) |
| `POST /api/gt/file/{name}/review` | mark the file reviewed / unreviewed |

- **Source view — recursive Payload flatten.** `_flatten_payload` walks the EvtxECmd `Payload` JSON and surfaces **every leaf** regardless of shape — `EventData.Data {@Name,#text}` lists, `UserData` blocks, SQL-audit / raw structures, and arbitrarily nested dicts — so the displayed artefact contains everything the GT extractor can read. `EventID` is surfaced as its own field row (it lives in the CSV `EventId` column, not the Payload), giving the `event_ids` field a selectable value.
- **Highlighting (`gt.js`).** Each saved/staged GT value is highlighted in the source with a per-field colour (event_ids gray, processes orange, accounts blue, commands teal, network green, registry purple). `event_ids` match the **whole cell** exactly; the other five are substring-matched; `registry` is **hive-aware** (HKLM↔HKEY_LOCAL_MACHINE, HKCU↔HKEY_CURRENT_USER, HKCR/HKCC/HKU), so a normalized GT value still resolves to the short-form source.
- **Staged editing.** Pick a field → select source text → it's staged (yellow "unsaved" ring); click a highlight/chip to remove a value; the verdict toggle flips the MALICIOUS/BENIGN label (also staged). A "● N unsaved" indicator with **Save** (commits everything in one `…/evidence/batch` write) and **Revert** (discards) drives the bar; a per-file "Mark reviewed / ✓ Reviewed" toggle sits far right, alongside the "N / total reviewed" count and an "unreviewed only" filter.
- **Artefact-grounding guardrail (the GUI cannot fabricate GT).** An **added** value is rejected unless it is actually present in that file's source artefact — hive-aware for `registry`, checked against the file's event-id set for `event_ids`, normalized-substring otherwise (`_present`). The single-add endpoint returns **422**; the batch endpoint reports each rejection in its `rejected` list and applies the rest. Removals are unconditional. This is the same "must be in the data" rule the methodology requires.
- **Relabel audit trail.** A verdict change writes `entry.label_review = {reclassified: "<old>-><new>", date, reason, source: "manual-gui"}` — the **same convention as the curated relabels** elsewhere in the corpus (the default reason is "Relabeled via GT Explorer").
- **Operational state (both gitignored).** Every add/remove/relabel is appended to **`data/gt_edit_log.jsonl`**; reviewed state persists in **`data/gt_review_state.json`** (with a `reviewed_at` timestamp). Both are listed in `.gitignore` — they are operational state, not corpus content.

### 5.2 The hand-curation model (implications)

Because ground truth is hand-curated through the Explorer:

- **Do NOT re-run the re-extract scripts on curated data.** `sync_ground_truth_evidence` and `tag_metadata --recompute` (§8) overwrite manual edits — they re-derive the 6 evidence fields / the difficulty+test_set tags from heuristics and would clobber the human curation. Run them only on fresh, un-curated entries.
- **The validator's `missed_evidence` is a curation *signal*, not an error.** When the typed extractor (`validation/ground_truth.py`) would surface a value the curated GT omits, that is information for the curator — the human may have deliberately pruned it. The hard correctness invariant is the other direction: **`false_claims`** (a GT value absent from the source artefact) must stay empty — and the Explorer's add-guardrail enforces exactly that on every new value.
- **What an edit moves.** Editing **evidence** fields affects only extraction/alignment scoring (§3.1). Editing the **verdict** (label) changes recall / FP rate / the run-level verdict **and** the corpus-size locks (`GT_MALICIOUS`/`GT_BENIGN` in `tests/test_corpus_sizes.py`) — so after a relabel you must **re-score / re-run and update the locks** in the same commit.

---

## 6. Reporting outputs (`reporting/`)

The **JSON run manifest** is the canonical machine-readable record.

### Output naming (all under `config.OUTPUTS_DIR = PROJECT_ROOT/outputs`)

| Producer | File | Notes |
|----------|------|-------|
| `forcastl-detect` via `reporting/csv_output.py` | `detection_results_<safe_model>_<run_id>.csv` | 24 cols + `#`-prefixed glossary |
| | `run_manifest_<safe_model>_<run_id>.json` | `schema_version=1`, `kind='detection'`, `raw_only=True` |
| | `scoring_sheet_<safe_model>_<ts>.csv` | only when `runs>1` |

`safe_model = re.sub(r'[^\w\-.]','_', model)`; `run_id`/`ts` = `'%Y%m%d_%H%M%S'`.

### Key artefacts

- **detection CSV:** 24 columns (`Model, Filename, Difficulty, Test Set, Status, Malicious, Confidence %, Alignment %, Structure Valid, Event IDs, Processes, Accounts, Commands, Network, Registry, Hallucination %, Response Time (s), Extraction (6), Interpretation (6), NoHallucination (4), Reasoning (4), Total (20), Grade, LLM Response`) preceded by a `#` glossary. Read back via `read_detection_csv()` (skips `#`) or `pandas read_csv(comment='#')`.
- **manifest schema:** top-level `schema_version, run_id, kind, raw_only, server, model, input_format, csv_dir, mode, sample_size, max_output_tokens, timeout_s, delay_s, difficulty_filter, test_set_filter, started_at, finished_at, summary, outputs, selected_files, files, recommendations, failure_adjusted`. The `summary` block carries the confusion matrix, rates, `recall_ci_pct`/`fp_rate_ci_pct` (95% Wilson), and — for `--runs>1` — `per_run_rates` and `rate_spread`. Each `files` entry: `filename, status, malicious, confidence_pct, alignment_pct, score_20, grade, hallucination_rate, hallucinated_fields, claimed_fields, response_time_s` (non-status fields None unless `status=='processed'`). **Two metric views are always kept separate:** processed-only quality metrics (`run_summary`) vs failure-adjusted outcome metrics (`failure_metrics`, where unprocessed malicious files count as zero-score misses).
- **PDF:** rendered by **headless Chromium/Chrome** (not a Python PDF lib), cross-platform (`find_chromium()` checks a bundled binary under `chromium/`, then system Chrome). Flags: `--headless=new --disable-gpu --no-sandbox --no-pdf-header-footer --print-to-pdf-no-header --virtual-time-budget=10000 --print-to-pdf=<abs>`, 60 s subprocess timeout. Hard-coded to 3 letter-size pages.
- **XLSX (`render_user_facing_xlsx`):** 2 sheets — `Request` (the exact prompt template, rebuilt from `PromptManager` so it can't drift) and `Results` (16 trimmed columns; drops Confidence %, Alignment %, and the 5 scoring columns; keeps Hallucination %). Requires `openpyxl>=3.1.0`.

---

## 7. Supported model providers

Selected by `forcastl-detect --provider {lmstudio, anthropic, openai}` (default `lmstudio`).

| Provider | Client | Endpoint | Requires |
|----------|--------|----------|----------|
| `lmstudio` | `core/llm_client.py LLMClient` | `POST {server}/v1/chat/completions` | `--server` + `--model` |
| `anthropic` | `core/anthropic_client.py AnthropicClient` | Anthropic Messages API (streamed) | `--model` + `ANTHROPIC_API_KEY` (errors without `--model`) |
| `openai` | `core/openai_client.py OpenAIClient` | OpenAI Chat Completions SDK | `--model` + `OPENAI_API_KEY` (errors without `--model`) |

- All `send_to_llm` methods return `(text, elapsed_seconds)` and **never raise** — failures become `'Error: ...'` strings.
- **Temperature is uniform at 0.0 by default.** `LLMClient` defaults `temperature=0.0` (the detection pipeline passes none → 0.0); `AnthropicClient`/`OpenAIClient` also send `temperature=0.0` by default, with carve-outs where the API forbids it (Anthropic with extended thinking enabled; OpenAI reasoning families o1/o3/o4 and gpt-5).
- `LLMClient` has a wall-clock watchdog (`_total_budget`: base=timeout; >10K prompt-tokens → `min(timeout*1.35,450s)`; >20K → `min(timeout*1.75,600s)`; tokens ≈ `len(prompt)//3`), 3 attempts, backoff `[0,1.0,2.5]s`, `threading.Timer` force-closing the socket. **LM Studio auto-load:** `_preflight_check` probes `/api/v1/models` then `/api/v0/models`; if the target isn't loaded it POSTs `/api/v1/models/load` (up to 180 s) and re-confirms.
- **Run durability (`cli/detect.py` + `core/runtime.py`), the layer above the per-call watchdog.** `run()` executes inside `keep_awake()` (cross-platform idle-sleep inhibitor: macOS `caffeinate -w <pid>`, Windows `SetThreadExecutionState`, Linux `systemd-inhibit`; `--no-keep-awake` to skip). Each completed file is fsynced to `outputs/.resume-<model>-run<N>.jsonl`; `--resume` reloads it and processes **only files not already done**, then auto-clears the checkpoint on a clean finish (the webapp does **not** pass `--resume`, so resume is CLI-only). `send_to_llm` wraps the SDK call in `run_with_timeout` (a thread + `t.join(budget)`, `CallTimeout` → `"Error: hard timeout…"`) so a wedged socket can't freeze the loop. **Non-recoverable** backend errors (`_is_fatal_api_error`: no-credit / `insufficient_quota` / bad key) raise `FatalRunAbort` — the loop stops **before** checkpointing the failed file, skips report generation and the checkpoint-clear, and `main()` exits non-zero; transient 429/5xx still error per-file and continue.
- `OpenAIClient._uses_max_completion_tokens()`: ids starting `gpt-5`/`o1`/`o3`/`o4` send `max_completion_tokens` instead of `max_tokens`.

---

## 8. Curation/maintenance scripts vs the eval runtime

These scripts **build and maintain** `metadata.json` + `ground_truth_evidence.json` and the corpus. **None run during an eval** — they are invoked manually by a maintainer (`python -m tools.<name>`). The eval later consumes whatever they produced. The **live, maintained** utilities are in `tools/` (`add_sample.py`, `sync_ground_truth_evidence.py`, `tag_metadata.py`, `validate_ground_truth.py`, `quarantine_unusable_evtx.py`, `add_attack_fields.py`); the **one-off corpus-construction & audit tools** are under `tools/archive/` (see its `README.md`) — kept for dataset provenance, not part of the live tool.

> **Curation caveat (see §5.2).** `sync_ground_truth_evidence` and `tag_metadata --recompute` re-derive the evidence fields / difficulty+test_set from heuristics and **overwrite manual curation** — run them only on fresh, un-curated entries.

| Script (run as `python -m tools.<name>`) | What it does | Mutates? |
|--------|--------------|----------|
| `sync_ground_truth_evidence` | Re-extracts the 6 core evidence fields per GT entry. Reads each EvtxECmd CSV's structured `Payload` directly (un-escaped; XML-namespace/junk-network items filtered) — CSV-only, the binary EVTX is never parsed. Updates the 6 core fields **in place**, preserving `attack_*` sidecars and other keys; reproducible (hash-seed-independent); stamps `_metadata.evidence_source`. | yes (default overwrites GT) |
| `tag_metadata` | Refreshes `total_events/signal_events/signal_ratio` and tags `difficulty`/`test_set`. These are **curated** — existing labels are **preserved** by default (`--recompute` forces a heuristic re-derive); only entries lacking them are auto-derived. The signal-ratio heuristic emits `easy/medium/hard` + `A/B/C`; benign `D` controls and APT difficulty are hand-curated. | yes (stats + new-entry tags) |
| `add_sample` | **The going-forward way to add one CSV + GT entry** (idempotent, single-file): extract evidence → seed `attack_*` → tag (curated-preserving) → validate → print/`--write-locks` the corpus-size constants. See [`docs/adding_samples.md`](docs/adding_samples.md). | yes (one entry) |
| `quarantine_unusable_evtx` | Moves 0-event EVTX (+ CSV) to `*_quarantine`, sets `excluded=True`, `exclusion_reason='unusable_evtx_zero_events'`. **Dry-run by default**; `--apply` to move. | with `--apply` |
| `add_attack_fields` | Adds `attack_*` sidecars + rebuilds `processes/accounts/commands` as full inventory. Re-run-safe (won't clobber existing `attack_*`). Exposes `seed_attack_fields` (shared with `add_sample`). | yes |
| `validate_ground_truth` → `validation/ground_truth.run_validation` | 5-phase corpus-quality audit (schema, cross-ref, **re-read CSV** via `core/csv_evidence`, per-field compare, summary) → `outputs/ground_truth_validation_report.json` with a `quality_score`. | **read-only** |
| `tools/archive/*` one-offs — `fill_ground_truth_gaps`, `generate_benign_*`, `audit_ground_truth`, `audit_gt_residual_drift`, `hedge_tool_attribution`, `verify_drift_hits`, `_inspect_evtx`, `_audit_registry`, `_check_borderline` | _(archived)_ One-off corpus-construction + read-only audits / drift detectors (one editorial hedger has `--apply`). Kept for dataset provenance. See `tools/archive/README.md`. | mostly read-only |

**`extract_evidence_from_event` (in `validation/ground_truth.py`) is reused at runtime** by the live detector (`cli/detect.py`), so GT generation and the live hallucination check stay self-consistent. **GT generation, validation, and the maintenance audits all source from the CSV via the shared `core/csv_evidence` reader** (`Payload` read directly + **un-escaped** + network-noise filter); nothing in the GT pipeline parses the binary EVTX. The CSV is the source of truth — the EVTX is upstream provenance only. (For the CSV corpus the stored GT is thus a slightly cleaner view than the live detector's reconstructed-XML extraction.)

`sync_ground_truth_evidence` is idempotent — it updates only the 6 core evidence fields **in place** (preserving `attack_*` and other keys); `add_attack_fields` likewise preserves `attack_*` on re-run.

---

## 9. Testing & CI

- **Suite:** **682** tests across **42** `tests/test_*.py` files (mix of `unittest.TestCase` and bare `def test_*`). `pyproject.toml [tool.pytest.ini_options]` sets `pythonpath = ["src", "."]` and `testpaths = ["tests"]`; **no `conftest.py`** — the `pythonpath` entries let `forcastl.*`, `tools.*`, and top-level `config` import directly.
- **CI:** single workflow `.github/workflows/test.yml` (name `test`), runs on push/PR to `master`/`main` (plus `workflow_dispatch`), matrix Python **3.11 & 3.12** on `ubuntu-latest`. Installs `pip install -e ".[dev,web]"`, then runs **ruff**, a console-script `--help` smoke check, and `pytest` with a **coverage floor** (`--cov-fail-under=66`); a separate non-blocking `pip-audit` job scans dependencies. No Chromium install (PDF e2e is skipped).
- **Dependencies (declared in `pyproject.toml`, mirrored by `requirements*.txt`):** core (`requests, anthropic, openai, openpyxl, jinja2, tqdm, colorama`); `[web]` extra (`fastapi`, `uvicorn[standard]`); `[dev]` extra (`pytest`, `httpx`).
- **`tools/check_deps.py`** is a separate preflight, **never run by CI**.

### Coverage gaps to be aware of

- **Webapp routes are covered** — `tests/test_webapp_routes.py` (9 tests, via the FastAPI `TestClient`/`httpx`) exercises the HTTP routes, and CI installs the web deps. **PDF end-to-end is skipped in CI** — `tests/test_pdf_report.py` is gated by `skipUnless(pdf_export_available())` and there's no Chromium install step.
- **Corpus sizes are contractually locked** — `tests/test_corpus_sizes.py` asserts 328/328/328 alignment, the 219/109 GT split, and the 306/9/13 difficulty distribution; corpus drift fails CI.

### What the tests pin

The 20-point rubric (6/6/4/4), grade bands (A≥17/B≥14/C≥10/D), `config.VERDICT_THRESHOLDS` boundaries, the evidence-only alignment, multi-run aggregation (`aggregate_run_summaries`), Wilson CIs, the `decoded_iocs` allowlist, the pre-sampling tag filter, the prompt-echo guard, and the structured-response parser.
