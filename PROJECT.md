# FORCAST-L

FORCAST-L benchmarks how well an LLM triages **Windows Event Log data exported to CSV by
EvtxECmd**: given event XML reconstructed from the CSV rows, the model must decide
malicious-vs-benign, extract verbatim evidence, and avoid fabricating indicators. A scoring engine
grades each response and rolls the run up to a PASS / CAUTION / FAIL verdict.

The fastest way to use it is the **web UI** ([Quick start](#quick-start)). For how it works
end-to-end, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

## How it works in one paragraph

Source `.evtx` files are first converted to CSV with [Eric Zimmerman's
EvtxECmd](https://ericzimmerman.github.io/). The model is then fed **event XML reconstructed from
the EvtxECmd CSV rows** — never a summary or a reduced sample. If an artefact is too big for the
model's context, the run records `Status=context_exceeded` — that's a benchmark finding, not an
error. FORCAST-L reads **CSV only**; the binary `.evtx` files are kept as provenance and are never
parsed by the tool.

## The corpus

| | |
|---|---|
| **Size** | 328 EvtxECmd CSVs under `data/csv` (1:1 with `metadata.json` + `ground_truth_evidence.json`) |
| **Labels** | 219 malicious / 109 benign, assigned on *in-artifact attack intent* (not the source folder's MITRE tag) |
| **Source** | 100% real, mixed-license corpus: 265 attack logs from [mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) (CC0-1.0) + 63 benign baselines from [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline) (Apache-2.0) |
| **Difficulty** | 306 easy / 9 medium / 13 hard (deliberately not balanced) |
| **Coverage** | 11 MITRE tactics, 60 technique IDs |
| **Evidence fields** | `event_ids`, `processes`, `accounts`, `commands`, `network`, `registry` |

Counts are locked by `tests/test_corpus_sizes.py`. Attributions live in `NOTICE` and `data/evtx/`.
FORCAST-L's original code and documentation are Apache-2.0 licensed; bundled third-party data
retains the upstream licenses identified above.

## Quick start

Install from a **git clone** (the corpus ships in the repo, not the wheel):

```bash
git clone <repo-url> && cd forcast
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[web]"                               # add ",dev" for pytest
```

The dataset lives at `<repo>/data` (override with `FORCASTL_DATA_DIR`). Point the tool at your
OpenAI-compatible model server, then launch the UI:

```bash
export LLM_SERVER_URL='http://localhost:1234'     # PowerShell: $env:LLM_SERVER_URL=...
forcastl-web                                          # → http://127.0.0.1:8000
```

Open the URL, **Fetch Models**, pick **Standard**, and start a run. PDF/XLSX export needs
Chrome/Chromium on the host.

> **Deployment scope.** `forcastl-web` is built for **trusted local / LAN use** — it binds
> `127.0.0.1` by default and has **no authentication**. It runs and deletes benchmark jobs and
> edits ground truth, so do not expose it to an untrusted network. Cloud API keys are sent only in
> request bodies and forwarded to the run subprocess via the environment — never in URLs, logs, or
> the run manifest.

### Run modes

| Mode | Files | Verdict |
|------|-------|---------|
| **Smoke** | ~16 (benign capped at 15 + ≥1 attack) | Pipeline check only ("needs more data") |
| **Standard** | 120 (60 attack + 60 benign, difficulty-stratified) | Credible PASS / CAUTION / FAIL with FP rate |
| **Full** | 328 (whole corpus) | Full-corpus score |

Standard's attack half always includes all 20 medium+hard attacks; its benign half is
source-proportional. A Standard verdict can be sub-selected from a Full run for free. Runs always
use the CSV corpus and write to `outputs/`; CLI runs appear in the UI automatically.

### Reading the result

- **Verdict banner** — PASS / CAUTION / FAIL from recall, FP rate, and hallucination thresholds
  (or "needs more data" when the benign sample is too small).
- **KPIs** — detection rate, false-positive rate, hallucination %.
- **Details** — needs-attention items, grade distribution, confusion matrix, run config, and
  on-demand PDF / XLSX downloads.

## CLI

The CLI runs the same detection benchmark headless. Use the web UI for routine work.

```bash
forcastl-detect --server http://localhost:1234 --model foundation-sec-8b \
    --mode sample --sample-size 10 --timeout 300 --delay 0.2
```

Outputs (same layout as the UI): `outputs/detection_results_<model>_<ts>.csv` and
`outputs/run_manifest_<model>_<ts>.json`. The CSV `Status` column is `processed`,
`context_exceeded`, or `error`.

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `sample` | `single`, `sample`, or `all` |
| `--sample-size` | — | files to test in `sample` mode |
| `--include-benign` | — | reserve benign slots in `sample` mode (needed for an FP rate) |
| `--provider` | `lmstudio` | `lmstudio`, `anthropic`, or `openai` |
| `--difficulty` / `--test-set` | — | filter the pool before sampling (`A`/`B`/`C`, or `D` for benign) |
| `--runs` | 1 | repeat runs for repeatability |
| `--timeout` / `--delay` | 120 / 2.0 | per-file request timeout / sleep between files (seconds) |
| `--max-tokens` | unset | output cap; unset = let the server decide (Anthropic falls back to 8192) |

Mode equivalents: Smoke = `--mode sample --sample-size 5 --include-benign`; Standard =
`--sample-size 120 --include-benign`; Full = `--mode all --include-benign`.

## Ground-Truth Explorer

Ground truth is hand-curated through the **Ground-Truth Explorer** at `/gt` (opened from the
runner's **Advanced options**). It renders each source CSV with the six evidence fields shown as
colour-coded highlights, and lets you stage adds/removes and flip the malicious/benign label, then
**Save** as one batch. A guardrail rejects any added value not present in the source, so the GUI
**cannot introduce fabricated ground truth**. Edits are logged; reviewed state is tracked.

Because ground truth is hand-curated, **do not re-run the bulk re-extract scripts** — they
overwrite manual edits. Editing evidence affects extraction/alignment scoring; editing a label
changes recall / FP / verdict and the corpus-size locks (re-score and update the locks after a
relabel). Full reference: [`docs/gt_explorer.md`](docs/gt_explorer.md).

## Model-server tuning

The benchmark requests **temperature 0** (its determinism control) but does not set a context size —
that's the server admin's job. Pin **temperature 0** on your model server too (LM Studio / Ollama) so it
can't override the request. If runs slow down sharply after 20–40 files, the server is likely reserving a
huge KV cache per request. For ollama, set these before `ollama serve`:

| Variable | Suggested | Why |
|----------|-----------|-----|
| `OLLAMA_CONTEXT_LENGTH` | `32768`–`65536` | caps per-request KV cache (corpus p95 ≈ 35K tokens; over-cap artefacts land as `context_exceeded`) |
| `OLLAMA_FLASH_ATTENTION` | `1` | ~halves KV memory per token |
| `OLLAMA_KV_CACHE_TYPE` | `q8_0` | ~halves it again (negligible impact at temperature 0) |

## Maintainer tools

Console scripts: `forcastl-detect`, `forcastl-web`. Maintainer utilities run as
`python -m tools.<name>` — most commonly:

- **`tools.add_sample`** — add one CSV + ground-truth entry (auto-extracts evidence, tags, validates,
  prints the corpus-size locks). See [`docs/adding_samples.md`](docs/adding_samples.md).
- **`tools.validate_ground_truth -v`** — check ground truth for completeness/consistency.

## Tests

```bash
python -m pytest -q
```
