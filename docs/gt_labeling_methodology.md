# Ground-truth labeling methodology (in-artifact intent)

How FORCAST-L assigns the `malicious: YES|NO` label, and how ground truth is curated,
audited, and changed through the **Ground-Truth Explorer** (`/gt`). Corpus: **328 files
= 219 malicious / 109 benign**.

## The rule

**Label on in-artifact attack intent — not on the MITRE technique, source folder, or
provenance.** A technique match (a `Txxxx` folder, a "DCShadow" filename) is a prompt to
investigate, not a verdict. An event is **malicious** only when the artifact *itself* shows
attack intent: a real security-weakening change, privilege/impact escalation, a
compromise/exfil/C2 signal, obfuscation, or a credential/lateral-movement action. Otherwise
it is **benign**, even if captured inside an attack scenario.

Provenance is recorded separately and is **never** changed by a relabel: `metadata.source`
stays `folder_structure` (mdecrevoisier attack dataset, CC0) or `evtx-baseline`
(NextronSystems goodware, Apache-2.0). **46 `folder_structure` files carry `malicious: NO`** —
attack-dataset EVTX whose sliced, single-technique artifact is, in isolation, routine admin.
The label reflects the artifact; the source reflects where the bytes came from.

## The discriminator — real security impact

Judge what the events actually *do*, by impact:

| Malicious (in-artifact attack signal) | Benign (routine / defensive / noise) |
|---|---|
| SQL `sysadmin` server-role grant (full-instance takeover) | SQL `db_accessadmin` grant to a test principal (scoped, routine) |
| 4738 **weakening**: password-not-required, no-preauth (AS-REP), DES-only, reversible-encryption | 4738 **defensive/neutral**: NOT_DELEGATED (hardening), password-never-expires, cannot-be-changed |
| High-count brute-force (27–72 failures, attacker IP) | Low-count / auth-*mode*-rejection failed logins (2–6, not credential guessing) |
| SPN/kerberoast recon (`setspn -a … -Q */*`, PowerShell SPN discovery) | Read-only generic admin discovery (`net group`, `netsh … show`, `auditpol /get`, `schtasks /query`) |
| Adds to **Administrators / DnsAdmins / Exchange** groups; `SeCreateToken` grant; hidden share → `C:\TOOLS\`; proxy → attacker host; time set **backward**; `1102` log-clear; DCSync/PtH/golden-ticket; rogue-DC (5137); RC4 kerberoast TGS | Non-privileged user/group ops; OpenSSH-server install/activate via `Add-WindowsCapability`; routine config (single GPO version bump, firewall rule) |

When genuinely ambiguous, prefer **benign-given-the-artifact** over technique-presence labeling.

## The Ground-Truth Explorer (`/gt`)

Ground truth is hand-curated through the **Ground-Truth Explorer**, a visual,
artefact-grounded, audited editing path served by the web UI. The page is at `GET /gt` (opened
from the runner's **Advanced options** panel, "Ground-Truth Explorer →"); its API lives under
`/api/gt/*`, mounted via `app.include_router(gt_explorer.router)` (`webapp/app.py:321`).
Implementation: `webapp/gt_explorer.py`; UI: `static/gt.html` + `static/gt.js`.

**What it shows.** The left pane is the live corpus listing (`GET /api/gt/files`): each file
with its `malicious` badge, `source`, `difficulty`, per-field GT counts, and reviewed state,
plus an `N / total reviewed` tally and an "unreviewed only" filter. Opening a file
(`GET /api/gt/file/{name}`) renders every event with its Payload **recursively flattened** so
every leaf is surfaced (EventData `{@Name,#text}` lists, UserData blocks, SQL-audit, nested
structures); `EventID` appears as its own selectable field row. The 6-field GT evidence is
drawn over the source as colour-coded highlights:

| Field | Colour | Match |
|---|---|---|
| `event_ids` | gray | whole-cell exact (against the file's event-id set) |
| `processes` | orange | substring |
| `accounts` | blue | substring |
| `commands` | teal | substring |
| `network` | green | substring |
| `registry` | purple | substring, hive-aware (`HKLM`↔`HKEY_LOCAL_MACHINE`, `HKCU`↔`HKEY_CURRENT_USER`, etc.) |

**How you edit.** Pick a field, select source text → it stages as an addition (yellow "unsaved"
ring); click any highlight or chip to stage its removal; the verdict button toggles the label
`MALICIOUS`↔`BENIGN` (staged, with an optional reason prompt). A `● N unsaved` counter offers
**Save** / **Revert**; Save commits adds, removes, and any label flip in **one batch write**
(`POST /api/gt/file/{name}/evidence/batch`). A per-file "Mark reviewed / ✓ Reviewed" toggle
(far right; `POST /api/gt/file/{name}/review`) drives the reviewed tally and filter.
`POST /api/gt/file/{name}/evidence` does a single add/remove without staging.

**The guardrail.** An **added** value is accepted only if actually present in that file's source
artefact — hive-aware for `registry`, checked against the file's event-id set for `event_ids`. A
value not in the source is rejected (`422` on the single endpoint; in the `rejected` list on the
batch endpoint) and never written. **The GUI cannot introduce fabricated ground truth.** Removes
and verdict flips carry no such constraint — they are conviction calls, not new assertions.

**The audit trail.** A verdict flip writes the same `label_review` object curated relabels use,
with `source: "manual-gui"`: `{reclassified, date, reason, source}`. Every add, remove, and
relabel is appended to `data/gt_edit_log.jsonl`; reviewed state (with `reviewed_at`) persists in
`data/gt_review_state.json`. Both are operational state and are **gitignored**.

## Curation model

Ground truth is **hand-curated** through the Explorer, with two consequences:

- **Do not re-run the bulk re-extract / re-derive scripts on curated data.**
  `sync_ground_truth_evidence` and `tag_metadata --recompute` overwrite manual edits — evidence
  curation and curated `difficulty`/`test_set` labels are lost. They are for fresh imports, not
  for maintaining the curated corpus.
- **The validator's `missed_evidence` is a curation signal, not an error.** When the typed
  extractor *would* surface a value GT omits, that is a prompt to consider adding it — not a
  failure. The hard invariant is `false_claims`: a GT value absent from the source (the guardrail
  prevents it on add, and `python -m tools.validate_ground_truth` keeps it at 0).

**Editing impact.** Editing **evidence** fields changes only extraction/alignment scoring.
Editing the **verdict** (label) changes recall, FP-rate, the run verdict, and the corpus-size
locks (`GT_MALICIOUS`/`GT_BENIGN`) — so after any relabel, re-score / re-run and update the
locks (procedure below).

## The relabel procedure

The Explorer's verdict toggle automates steps 1–3 (flips `malicious`, leaves everything else,
writes the `label_review`); step 4 is the post-edit reconciliation you do by hand.

1. **Decide on the artifact, not the model.** A capable model's per-file reasoning (e.g.
   opus-4.8) is a useful flag for re-examination, but the relabel must stand on the source events —
   **do not tailor GT to what an LLM says** (that biases GT toward the tested model). Read and quote
   the source events.
2. **Flip `malicious` only.** Leave `evidence`, `metadata.source`, `test_set`, `difficulty`
   untouched (a relabeled-benign attack file keeps `test_set: A` etc.).
3. **Record the audit trail** — a `label_review` object on the GT entry:
   ```json
   "label_review": {
     "reclassified": "malicious->benign",
     "date": "YYYY-MM-DD",
     "reason": "<artifact-grounded justification — quote the events>",
     "source": "manual-gui"
   }
   ```
   Relabeled entries carry one (**44** in the corpus, all `malicious->benign`).
4. **Reconcile + validate.** Update the locks in `tests/test_corpus_sizes.py`
   (`GT_MALICIOUS`/`GT_BENIGN`) and the counts in `CLAUDE.md`, then run
   `python -m tools.validate_ground_truth` (`false_claims` stays **0** because labels don't change
   extracted evidence; `missed_evidence` is a curation signal) and `pytest -q`.

## Cross-model consistency check

Items **both** models report but GT lacks are treated as **candidate GT gaps**, not asserted model
errors. A cross-model audit adjudicates each against the source CSV (with adversarial verification)
into real-in-source (GT incompleteness — e.g. free-text process/account/host the typed extractor
doesn't surface) vs absent-in-source. In dev we **do not call out specific hallucinations** — any
single disagreement may be a GT/extractor artifact. Some real free-text values (process names
inside command lines, accounts in messages, host FQDNs) aren't surfaced by the typed extractor and
score N/A, so no model is penalized; the remedy is an extractor improvement + uniform re-extract.

See also: `CLAUDE.md` → "Scoring & verdict".
