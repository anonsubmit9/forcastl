# scripts/archive — one-off corpus-construction & audit tools

These scripts are **not part of the live tool's runtime**. They were used once to
*build* and *validate* the detection corpus, and are kept here for **provenance and
reproducibility** (this repository backs an academic paper — how the dataset was
generated is part of the record). They are runnable from here (`python
scripts/archive/<name>.py`) but are not invoked in normal operation, CI, or by any
imported module.

For the *going-forward* way to add a sample, use **`add_sample.py`** (see
[`docs/adding_samples.md`](../../docs/adding_samples.md)) — it supersedes the
benign-generator scripts below.

## Corpus construction (superseded by `add_sample.py`)
- `generate_benign_csvs.py` — first batch of benign EvtxECmd-shaped CSVs.
- `generate_benign_samples.py` — benign CSVs + their GT/metadata entries.
- `generate_more_benigns.py` — phase-2 benign expansion (22 scenarios).
- `fill_ground_truth_gaps.py` — backfilled missing GT fields during corpus build.

## Ground-truth audit / inspection (one-offs from the GT-validation work)
- `audit_ground_truth.py` — GT-vs-CSV consistency audit.
- `audit_gt_residual_drift.py` — residual extraction-drift audit.
- `verify_drift_hits.py` — spot-verify drift candidates.
- `hedge_tool_attribution.py` — tool-attribution hedging proposals.
- `_audit_registry.py` — registry-evidence spot audit.
- `_check_borderline.py` — borderline-label inspection (run from repo root; uses CWD).
- `_inspect_evtx.py` — ad-hoc CSV/event inspector.

> The live, maintained utilities stay at the top level (`validate_ground_truth.py`,
> `sync_ground_truth_evidence.py`, `tag_metadata.py`, `add_sample.py`) and in
> `scripts/add_attack_fields.py` (imported by the corpus pipeline).
