# Contributing to FORCAST-L

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,web]"
python -m pytest -q
```

This is a clone-and-editable-install project: the dataset lives at `<repo>/data`
(override with `FORCASTL_DATA_DIR`).

## Repository layout

- `src/forcastl/` — the importable package: `core/`, `validation/`, `reporting/`,
  `webapp/`, and `cli/` (the eval entry points). Installed console scripts:
  `forcastl-detect`, `forcastl-compare`, `forcastl-benchmark`, `forcastl-score`,
  `forcastl-web`.
- `data/` — the corpus (EvtxECmd CSVs + GT/metadata + the 33 JSON testcases).
- `tools/` — maintainer utilities, run as `python -m tools.<name>` (`add_sample`,
  `sync_ground_truth_evidence`, `tag_metadata`, `validate_ground_truth`,
  `quarantine_unusable_evtx`, `add_attack_fields`); `tools/archive/` holds the
  one-off corpus-build/audit scripts, kept for provenance.
- `docs/` — public documentation.
- `outputs/` — recorded evaluation runs (manifests, detection CSVs, GT audits) referenced by the paper.

## Adding a corpus sample

Use **`python -m tools.add_sample`** — one idempotent command. The full workflow,
conventions (curated `difficulty`/`test_set`, the `.evtx` join-key, the corpus-size
lock) and a manual fallback are documented in
**[`docs/adding_samples.md`](docs/adding_samples.md)**.

## Before merging (local verification gate)

GitHub Actions is **not running** (credits exhausted; the `test` workflow is
manual-trigger only). Run the same checks locally before merging — these are the
gate now:

```bash
ruff check src/ tools/ tests/                              # lint (pyflakes)
forcastl-detect --help && forcastl-compare --help \
  && forcastl-benchmark --help && forcastl-score --help \
  && forcastl-web --help                                  # console-script smoke
python -m pytest -q --cov=forcastl --cov-fail-under=66     # full suite + floor
# fast inner loop (skips the ~25-50s corpus tests): pytest -m "not slow"
```

Plus, when relevant:

- **Ground truth is curated through the Ground-Truth Explorer**, not by hand-editing
  `data/ground_truth_evidence.json`: run `forcastl-web`, open **Ground-Truth Explorer →**
  from the runner's Advanced options (or `GET /gt`), and add/remove evidence or flip the
  malicious/benign label against the rendered source. A source-presence guardrail rejects
  any added value absent from the artefact, so the tool **cannot introduce fabricated
  ground truth**; every edit is logged. Full reference:
  [`docs/gt_explorer.md`](docs/gt_explorer.md) (labeling rule:
  [`docs/gt_labeling_methodology.md`](docs/gt_labeling_methodology.md)). Do **not** re-run
  the bulk re-extract scripts (`sync_ground_truth_evidence`, `tag_metadata --recompute`) —
  they overwrite manual curation.
- `python -m tools.validate_ground_truth -v` reports quality 100 / 0 false / 0 missed
  if you touched ground truth.
- Corpus changes update the constants in `tests/test_corpus_sizes.py` (or run
  `python -m tools.add_sample --write-locks`).

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full system walkthrough and
[`docs/known_issues.md`](docs/known_issues.md) before trusting any number.
