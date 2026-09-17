# Adding a Sample to the Detection Corpus

How to add one CSV + ground-truth entry. The corpus is kept exactly 1:1 across three
places: the CSVs on disk (`data/csv`), `data/metadata.json`, and
`data/ground_truth_evidence.json` — all three sit at **328** (**219 malicious / 109
benign**). This guide keeps them aligned and the suite green.

> **CSV-only.** The `.evtx` extension in the catalogues is a *logical join key* — a CSV
> resolves to its entry by lowercased filename stem (`ID999-Foo.csv` ↔ `ID999-Foo.evtx`).
> The 271 binary `.evtx` under `data/evtx` are attack provenance only and are never read.

## TL;DR — the one-command path

```bash
# 1. Put the EvtxECmd CSV on disk:
#      attack → data/csv/<TActic>/<Technique>/ID999-Thing.csv
#      benign → data/csv/_benign/BENIGN-ID999-Thing.csv

# 2. Add it (auto-extracts evidence, tags, validates, prints the lock constants):
python -m tools.add_sample --csv "data/csv/_benign/BENIGN-ID999-Thing.csv" \
    --label NO --test-set D \
    --keywords "benign,routine admin" --write-locks

# 3. For a malicious file, author the narrative the script can't infer, then run the suite:
python -m pytest -q
```

`tools/add_sample.py` is **single-file and idempotent**: it touches only the one entry —
it can't disturb another file's curated state, and re-running it is a no-op.

## What's automatic vs. what you author

| Automatic (`tools/add_sample.py`) | You author |
|---|---|
| The 6 evidence fields (`event_ids`, `processes`, `accounts`, `commands`, `network`, `registry`), extracted from the CSV `Payload` | `--label` (YES / NO) |
| `attack_*` sidecars (curated subset; = full inventory until you narrow it) | `malicious_events` — *why* it's malicious (`--malicious-event`, repeatable) |
| `difficulty` + `test_set` (signal-to-noise heuristic) | `explanation_keywords` (`--keywords`) |
| `metadata.json` entry (tactic/technique from the folder path; `csv_only` for benign) | `--test-set D` for benign controls (see below) |
| Embedded-IOC surfacing (IPs/URLs/UNC/registry inside commands) | The new lock constants (printed; `--write-locks` applies them) |

For a **malicious** sample, after running the script open
`data/ground_truth_evidence.json` and:
1. fill `malicious_events` with a short narrative of the attack the artifact shows;
2. narrow `attack_processes` / `attack_accounts` / `attack_commands` from the full
   inventory down to just the items that are part of the malicious activity.

**Review the auto-extracted evidence in the Ground-Truth Explorer.** `add_sample`
extracts the six fields and sets the label from your `--label`, but it can't judge
*forensic relevance*. Open the new entry in the **Ground-Truth Explorer** (`forcastl-web`
→ Advanced options → **Ground-Truth Explorer →**, or `GET /gt`) to see the fields
highlighted over the rendered source, prune spurious extractions, add anything the
extractor missed, and confirm the malicious/benign label against the artefact. The
Explorer's source-presence guardrail keeps every added value grounded in the source, and
every edit is logged. See [`docs/gt_explorer.md`](gt_explorer.md) and the labeling rule in
[`docs/gt_labeling_methodology.md`](gt_labeling_methodology.md).

## Conventions you need to know

- **`difficulty` / `test_set` are derived for new entries.** `tools/add_sample.py` (and
  `tools/tag_metadata.py`) compute them from the signal-to-noise ratio: `easy` (ratio ≥
  0.5 or ≤ 10 events) · `hard` (ratio < 0.15 and > 20 events) · `medium` otherwise;
  test_set `B` (obfuscated) / `C` (noise-heavy) / `A` (default). You can't *declare* a
  file "hard" — you shape the CSV's signal-to-noise so it lands there. Live split: **306
  easy / 9 medium / 13 hard** (lowercase).
- **They're preserved on re-runs.** `tools/tag_metadata.py` keeps existing curated
  `difficulty`/`test_set` and derives only for entries lacking them (factual stats —
  total/signal/ratio — always refresh). `--recompute` re-derives every label and
  overwrites curation.
- **`test_set:D` = benign control, and it is curated.** There is no derivation path to
  `D`, so pass `--test-set D` for a benign sample you want filterable via `--test-set D`;
  once set, it is preserved across re-runs.
- **`source` records provenance.** Attack files in a `TAxxxx/Txxxx` folder default to
  `source: folder_structure`; `_benign/` entries are marked `csv_only: true`. The shipped
  corpus is two real datasets: 265 `folder_structure` attack CSVs
  (mdecrevoisier/EVTX-to-MITRE-Attack, CC0 1.0) and 63 `evtx-baseline` benign CSVs
  (NextronSystems/evtx-baseline, Apache-2.0). Provenance and licenses live in `data/evtx/`
  (`README.md`, `LICENSE.md`, `evtx-baseline-LICENSE`) and top-level `NOTICE`. Pass
  `--source` to override.
- **The lock test is a contract.** `tests/test_corpus_sizes.py` pins `GT_TOTAL` (328),
  `GT_MALICIOUS` (219) / `GT_BENIGN` (109), `GT_DIFFICULTY` (`{easy: 306, medium: 9, hard:
  13}`), and `METADATA_TOTAL` (328). Growing the corpus *must* update those constants in
  the same commit — `--write-locks` does it, or paste the block the script prints. This
  keeps corpus changes explicit and reviewable.

## Manual fallback (what the wrapper automates)

If you ever need to do it by hand:

1. Place the CSV on disk (as above).
2. Add a stub to `data/ground_truth_evidence.json` → `files`, keyed by the `.evtx` name:
   `"ID999-Thing.evtx": { "malicious": "NO" }`.
3. `python -m tools.sync_ground_truth_evidence` — fills the 6 evidence fields from the CSV.
4. `python -m tools.add_attack_fields` — seeds the `attack_*` sidecars.
5. `python -m tools.tag_metadata` — computes `difficulty`/`test_set` and syncs
   `metadata.json` (for a brand-new benign you still set `test_set:D` + the `csv_only`
   metadata entry by hand; attack-folder metadata is derived).
6. Author `malicious_events` + `explanation_keywords`.
7. Update `tests/test_corpus_sizes.py` constants.
8. `python -m tools.validate_ground_truth -v` (expect quality 100 / 0 false / 0 missed) and
   `python -m pytest -q`.

`tools/add_sample.py` collapses steps 2–8 into one idempotent, single-file pass — and,
unlike `tools/tag_metadata.py` corpus-wide, never re-derives the other 327 files'
difficulty/test_set.

## Verify

```bash
python -m tools.validate_ground_truth -v   # quality_score 100, 0 false claims, 0 missed
python -m pytest -q                          # full suite, incl. the corpus-size lock
```
