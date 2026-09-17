# Paper reproduction scripts

Scripts that produce the numbers and tables reported in the paper from the run
manifests and detection-result CSVs under `outputs/` and the corpus under `data/`.
Each script locates the repository root via `FORCASTL_ROOT` or, by default, two
directories above this folder. Run from the repository root with the project
installed (`pip install -e .`).

| Script | Paper item | Inputs | Notes |
|---|---|---|---|
| `pull_b6_b8_b10.py`, `b6_shared120_b10_errors.py` | Abstract and RQ1: absolute unsupported-claim counts, full-corpus FPRs, failure causes | `outputs/run_manifest_*_rescore_v1.json` | |
| `qwen_400_bound.py` | Table IV: observed context bound for the June Qwen3.6-27B deployment | `outputs/detection_results_qwen3.6-27b_20260615_194908.csv`, `data/csv` | needs `tiktoken` |
| `f34_fp_clustering.py` | RQ2: false-positive clustering and native-baseline FPRs | manifests under `outputs/` | |
| `f38_weight_sensitivity.py` | Results E, Table VIII: scoring-weight sensitivity | five `detection_results_*.csv` under `outputs/` | output recorded in `f38_output.txt` |
| `f32_csv_to_json.py`, `f32_flat_json.py` | Results F: rebuild Hayabusa input from EvtxECmd CSV and from EVTX | `data/csv`, `data/evtx` | `f32_flat_json.py` needs the `evtx` Python package |
| `f32_score_hayabusa.py`, `f32_roundtrip.py`, `f32_compare.py` | Results F, Table IX: deterministic Hayabusa/Sigma baseline and CSV-vs-EVTX round trip | `f32/hayabusa_*.jsonl` (Hayabusa 4.0.0 JSONL output, rules commit 5d21a2f9f, default profile) | summaries in `f32/*.txt`, `f32/sigma_combined_maxlevel.json` |
| `f33_perturb.py` | Results G: identity-renamed corpus for the contamination probe | `data/` | writes the perturbed copy to `work/f33_data/` |
| `f33_analyze.py` | Results G, Table X: original vs perturbed vs rerun comparison | two `detection_results_*.csv` (arguments), ground truth | inputs and analysis outputs under `outputs/f33/` |
| `verify_benign_split.py` | Corpus counts (Section V) | `data/metadata.json`, `data/ground_truth_evidence.json` | |
| `b11_review_log.py` | Section V-B review-window statistics | `data/gt_review_state.json`, `data/gt_edit_log.jsonl` | these two curation-state files are not part of this deposit |

Run outputs from the September 2026 replications (Qwen3.8-Flash-Next and
Qwen3.6-35B-A3B) sit beside the June runs in `outputs/`; the contamination-probe
runs, replays and analysis text are under `outputs/f33/`.
