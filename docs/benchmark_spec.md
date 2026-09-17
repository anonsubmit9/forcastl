# Benchmark Specification

A fixed benchmark contract for artifact-driven LLM evaluation, run by `forcastl-detect`
and the web UI.

## Non-negotiable: raw input only

**Artefact content is never manipulated to "fit" a model.** The benchmark sends raw
artefact data — CSV reconstructed into event XML — to the LLM. If an artefact exceeds the
model's context, the run records a context failure as a *result* (it does not retry with
fewer events).

## Scope

The only supported artefact type is **CSV**: Windows Event Logs transformed with **Eric
Zimmerman's EZ Tools `EvtxECmd`**. The parser rebuilds event XML from each row's `Payload`
JSON and feeds that to the model. The tool reads CSV only — it does not parse binary EVTX
and has no `python-evtx`/`xmltodict` dependency. MFT and other artefact families are
future-state.

### Source dataset

The corpus is 100% real captured Windows Event Logs from two public datasets, both
converted to CSV with **EvtxECmd**:

- **Attack** — mdecrevoisier's public **`EVTX-to-MITRE-Attack`**
  (`github.com/mdecrevoisier/EVTX-to-MITRE-Attack`, **CC0 1.0**): 265
  `source=folder_structure` entries. README + LICENSE ship under `data/evtx/`.
- **Benign** — **`NextronSystems/evtx-baseline`**
  (`github.com/NextronSystems/evtx-baseline`, **Apache-2.0**): 63 `source=evtx-baseline`
  entries — real Windows baseline activity sliced into single-technique near-misses.
  License ships as `data/evtx/evtx-baseline-LICENSE`.

The 271 binary `.evtx` under `data/evtx/` are attack-provenance only and are never parsed.
Both attributions are carried in the repo-root `NOTICE`.

## CSV detection corpus

Stored under `data/` (`data/csv` for the EvtxECmd CSVs, `data/evtx` for binary
provenance). Override the data root with `FORCASTL_DATA_DIR`.

| | |
|---|---|
| **Size** | 328 EvtxECmd CSVs, each 1:1 with a `metadata.json` and `ground_truth_evidence.json` entry |
| **Labels** | 219 malicious (`YES`) / 109 benign (`NO`); the 109 benign = 46 `folder_structure` files relabeled benign on in-artifact intent + 63 `evtx-baseline` files |
| **Source** | 265 `source=folder_structure` (attack) + 63 `source=evtx-baseline` (benign); zero synthetic |
| **Difficulty** | 306 easy / 9 medium / 13 hard (lowercase) |
| **Coverage** | 11 MITRE tactics, 60 technique IDs (across the 265 attack entries) |
| **Evidence fields** | `event_ids`, `processes`, `accounts`, `commands`, `network`, `registry` |

These counts are locked in `tests/test_corpus_sizes.py` (`GT_TOTAL=328`,
`GT_MALICIOUS=219`, `GT_BENIGN=109`, `GT_DIFFICULTY={easy:306, medium:9, hard:13}`,
`METADATA_TOTAL=328`); a corpus change that drifts from them fails CI.

## Scoring model (20 points)

Scoring identity is `SCORING_VERSION = 'forcastl_scoring_20pt_v1'` — the frozen scoring contract (a change bumps the version). Hallucinations must
be explicitly flagged in reporting, regardless of grade.

| Component | Points | | Grade | Range |
|---|---|---|---|---|
| Correct Extraction | 6 | | `A` | 17–20 |
| Correct Interpretation | 6 | | `B` | 14–16 |
| Hallucination Avoidance | 4 | | `C` | 10–13 |
| Justification & Reasoning | 4 | | `D` | <10 |

## Web UI mode presets

The web interface collapses the CLI's `--mode`, `--sample-size`, `--difficulty`, and
`--test-set` flags into a single **Mode** selector. CLI users retain direct access to all
granular flags.

| Mode | Files | Scope | Use case |
|------|-------|-------|----------|
| **Smoke** | ~16 | `sample_size 5`, benign capped at 15 + ≥1 attack | Quick pipeline check (verdict: needs more data) |
| **Standard** | 120 | even split 60 attacks + 60 benigns, difficulty-stratified (all 20 medium+hard attacks always included); benign source-proportional | Verdict-grade (recall + FP, CIs ±~9–11%; per-difficulty = descriptive coverage) |
| **Full** | 328 | Entire CSV corpus, no filters | Final/published run |

A Standard sample is derived from a Full run for free. The names and sizes come from
`src/forcastl/webapp/static/ui.js` (`BENCH_PRESETS`): `smoke` `sample_size:5`, `standard`
`sample_size:120`, `full` `mode:all` — all force `input_format:'csv'` and
`include_benign:true`. The even attack/benign split, difficulty stratification (ordered
hard → medium → easy in `core/file_selector.py:select_files`), and source-proportional
benign picker are applied by the file selector.

## CLI workflow

The package installs console scripts (`pyproject.toml` `[project.scripts]`):
`forcastl-detect` and `forcastl-web`. Maintainer tools run via `python -m tools.<name>`.

```bash
forcastl-detect --model your-model-id --runs 1   # detection benchmark vs the CSV corpus
forcastl-web                                      # launch the web UI
```
