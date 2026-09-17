# Ground-Truth Explorer

A visual web tool for viewing each source CSV and curating its ground truth by
highlighting strings in the artefact — the surface through which ground truth is
hand-curated for the CSV detection corpus.

Code: [`src/forcastl/webapp/gt_explorer.py`](../src/forcastl/webapp/gt_explorer.py),
[`static/gt.html`](../src/forcastl/webapp/static/gt.html),
[`static/gt.js`](../src/forcastl/webapp/static/gt.js); mounted on the main app via
`app.include_router(gt_explorer.router)` (`webapp/app.py:321`).

## Opening it

Served at **`GET /gt`** (`gt_explorer.py:159`). Start the web UI (`forcastl-web` →
`http://127.0.0.1:8000`) and click **Ground-Truth Explorer →** in the runner's
**Advanced options** panel, or go straight to `http://127.0.0.1:8000/gt`.
**← Back to runner** returns (`gt.html:79`). The API lives under `/api/gt/*`.

## File list (left pane)

`GET /api/gt/files` returns the live corpus listing — read fresh on each call, so
dataset expansion shows up immediately (`gt_explorer.py:167`). Each row carries the
file name, a **malicious badge** (`YES` red / `NO` green), `source`, `difficulty`,
per-field GT counts (summed as "N GT items"), and a **Reviewed ✓** marker (dimmed
row + green check). The pane has a **search** box (file-name substring) and an
**"unreviewed only"** filter, with a `N / total reviewed` bar. The endpoint also
returns top-level `reviewed_count`, `total`, and `fields`.

## Source view (right pane)

`GET /api/gt/file/{name}` returns the file's events plus its six-field GT evidence,
`malicious` label, and `reviewed` state (`gt_explorer.py:193`).

The EvtxECmd `Payload` JSON is **recursively flattened** into `{name, value}` rows
by `_flatten_payload` (`gt_explorer.py:97`), so **every leaf is surfaced** regardless
of shape — `EventData` `{@Name, #text}` lists, `UserData` blocks, SQL-audit / raw
structures, nested dicts — meaning the displayed artefact contains everything the GT
extractor can read. **EventID** is surfaced as its own field row (it lives in the
`EventId` column, not the Payload), giving the `event_ids` field a visible, selectable
value (`gt_explorer.py:135`). Rendering is capped at `_MAX_EVENTS = 800` events per
file; for larger logs the response flags `truncated` and the page shows "showing
first N".

GT values are highlighted in the source, one colour per field — each saved value
appears both as a colour `mark` over the matching source text and as a chip above
the events:

| Field | Colour | Matching |
|---|---|---|
| `event_ids` | gray | whole-cell match against the GT `event_ids` values |
| `processes` | orange | substring (case/whitespace-normalized) |
| `accounts` | blue | substring |
| `commands` | teal | substring |
| `network` | green | substring |
| `registry` | purple | substring, **hive-aware** |

Hive-aware matching: GT stores the long hive form (`HKEY_LOCAL_MACHINE`) while the
source often uses the short form (`HKLM`), and either resolves to the other —
`HKLM↔HKEY_LOCAL_MACHINE`, `HKCU↔HKEY_CURRENT_USER`, `HKCR↔HKEY_CLASSES_ROOT`,
`HKCC↔HKEY_CURRENT_CONFIG`, `HKU↔HKEY_USERS` (`_reg_variants`,
`gt_explorer.py:76`; mirrored client-side in `gt.js`).

## Editing (staged, then one batch write)

1. **Pick a field colour** in the toolbar (the active field gets a white outline).
2. **Select source text** in an event — on mouse-up it is **staged** as an addition
   to the active field, with a yellow "unsaved" ring on the new highlight/chip.
3. **Remove** a value by clicking its highlight or chip: saved values stage a removal
   (strikethrough); staged additions are simply dropped.
4. **Toggle the verdict** button (**MALICIOUS** / **BENIGN**) to flip the label, also
   staged. You are prompted for an optional reason; the button shows a `*` and a
   pending ring until saved.
5. A **● N unsaved** indicator with **Save** / **Revert** appears. **Save** commits
   all adds, removes, and the optional label change in **one** batch write; **Revert**
   discards everything staged.

A per-file **Mark reviewed / ✓ Reviewed** toggle sits at the far right; reviewed files
dim in the list and count toward `N / total reviewed`. Leaving the page or switching
files with unsaved changes prompts for confirmation.

## Guardrail: GT stays artefact-grounded

An **added** value must actually appear in the file's source artefact — hive-aware for
`registry`, and `event_ids` checked against the file's event-id set — or the add is
**rejected** (`_present`, `gt_explorer.py:88`): **422** on the single-edit endpoint,
or reported in the `rejected` list (and not applied) on the batch endpoint. The client
pre-checks on selection; the server re-checks authoritatively. The GUI therefore
cannot introduce fabricated ground truth. Removals are unrestricted.

## API

| Method & path | Purpose |
|---|---|
| `GET /gt` | The explorer page (`static/gt.html`). |
| `GET /api/gt/files` | Live file list: malicious, source, difficulty, per-field GT counts, reviewed, plus `reviewed_count`. |
| `GET /api/gt/file/{name}` | One file's events (flattened `Payload`) + the six-field GT evidence + label + reviewed. |
| `POST /api/gt/file/{name}/evidence` | Single artefact-grounded add/remove (422 on a rejected add). |
| `POST /api/gt/file/{name}/evidence/batch` | Staged save: `adds`, `removes`, optional `label` + `label_reason`; returns `applied`, `rejected`, new `malicious`, and `evidence`. |
| `POST /api/gt/file/{name}/review` | Set `{reviewed: bool}`; returns the new `reviewed_count`. |

## Audit & persistence

- Every add, remove, and relabel is appended to **`data/gt_edit_log.jsonl`** with a
  timestamp, file, field, value, op, result, and `source: "manual-gui"` (`_log_edit`,
  `gt_explorer.py:224`).
- A relabel writes `entry.label_review = {reclassified, date, reason,
  source: "manual-gui"}` into `ground_truth_evidence.json` — same convention as the
  curated relabels (`gt_explorer.py:355`); the reason defaults to "Relabeled via GT
  Explorer".
- Reviewed state persists in **`data/gt_review_state.json`** as `{reviewed: true,
  reviewed_at: <iso>}` per file (`set_review`, `gt_explorer.py:387`).
- Both files are **gitignored** (operational state; `.gitignore:46-47`).

## Curation model and impact

Ground truth is **hand-curated through the Explorer**. Two consequences:

- The re-extract scripts (`tools.sync_ground_truth_evidence`,
  `tools.tag_metadata --recompute`) must **not** be re-run on curated data — they
  overwrite manual edits. The validator's `missed_evidence` (the typed extractor would
  surface a value GT omits) is a **curation signal**, not an error; `false_claims`
  (a GT value absent from the source) remains the hard correctness invariant — and the
  guardrail above makes that case impossible to introduce through the GUI.
- Editing **evidence** fields only affects extraction / alignment scoring. Editing the
  **verdict** (label) changes recall / FP rate / verdict and the corpus-size locks
  (`GT_MALICIOUS` / `GT_BENIGN` in
  [`tests/test_corpus_sizes.py`](../tests/test_corpus_sizes.py)) — re-score / re-run
  and update the locks after relabeling.

## Corpus context

The Explorer browses the live CSV detection corpus: **328** EvtxECmd CSVs under
`data/csv` (the 271 binary `.evtx` under `data/evtx` are attack provenance, never
parsed). Labels are **219 malicious / 109 benign**; provenance is 265
`source=folder_structure` (mdecrevoisier, CC0) + 63 `source=evtx-baseline`
(NextronSystems, Apache-2.0); difficulty is 306 easy / 9 medium / 13 hard; MITRE
coverage is 11 tactics and 60 technique IDs across the attack entries. See
[`tests/test_corpus_sizes.py`](../tests/test_corpus_sizes.py) for the contractual
locks.
