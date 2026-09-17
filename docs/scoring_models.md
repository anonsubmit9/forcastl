# Scoring Models

FORCAST-L scores models on the CSV detection corpus. Use the **web UI** for runs and verdict review, or the CLI (`forcastl-detect`) for the same path headless. Both share **raw artefact input**, one scoring engine, and one manifest. Scoring uses the frozen `SCORING_VERSION = forcastl_scoring_20pt_v1` contract.

## Corpus detection (`forcastl-detect`)

| Aspect | Detail |
|--------|--------|
| **Data** | `data/metadata.json` + the 328 EvtxECmd CSVs under `data/csv` (benign controls in `data/csv/_benign`). The 271 binary `.evtx` under `data/evtx` are attack provenance only, **never parsed** — the tool is **CSV-only** (`--input-format` accepts only `csv`). |
| **Prompt** | `PromptManager.generate_simple_malicious_prompt` |
| **Scoring** | `MaliciousDetector` — structure validation, ground-truth alignment, field-level hallucination, 20-point grade |
| **Run verdict** | `core.verdict.compute_verdict` (recall, FP rate, hallucination %); needs `MIN_SAMPLES_FOR_VERDICT = 30` malicious and benign samples or the verdict is `insufficient` |
| **Temperature** | `0.0` — all three clients request temperature 0.0 (dropped only where the API rejects it: OpenAI reasoning families, Anthropic extended-thinking). Pin temperature 0 on a local model server too so it can't override the request. |
| **Manifest** | `kind: detection`, `schema_version: 1` |

## The 20-point rubric

A single engine scores **Extraction 6 + Interpretation 6 + NoHallucination 4 + Reasoning 4**: fuzzy ground-truth alignment for extraction and interpretation, plus field-level hallucination and reasoning checks. Grades: **A ≥ 17, B ≥ 14, C ≥ 10, D < 10** (`core/detection_scoring.grade_from_total`).

## Shared inference

Detection routes by `--provider` **directly** to `LLMClient` (OpenAI-compatible / LM Studio), `AnthropicClient`, or `OpenAIClient`. There is no Google/Gemini client — Gemma-family models run only behind a local OpenAI-compatible endpoint.

## When to compare runs

Only compare detection runs with the same:

- Corpus/version and prompt version
- Temperature and runs
- Model server configuration (context limits are server-side; see README)

A change to the scoring contract bumps `SCORING_VERSION`; only compare runs that share a `SCORING_VERSION`.
