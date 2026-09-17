from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import threading
import urllib.parse
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field, field_validator
import requests

from forcastl import config


OUTPUTS_DIR = Path(config.OUTPUTS_DIR).resolve()
STATIC_DIR = (Path(__file__).parent / "static").resolve()
PROJECT_ROOT = Path(config.PROJECT_ROOT).resolve()

MAX_CONCURRENT_JOBS = 3
# Finished jobs kept in memory for the UI's job list; older ones are evicted
# when a new job starts so a long-lived server doesn't grow without bound.
MAX_FINISHED_JOBS = 50
# /api/outputs/csv loads the whole file into memory for the JSON response.
MAX_CSV_BYTES = 50 * 1024 * 1024

app = FastAPI(title="FORCAST-L UI", version="0.1")

JOBS: Dict[str, Dict[str, Any]] = {}
_jobs_lock = threading.Lock()
_pdf_gen_lock = threading.Lock()

_run_id_index: Dict[str, Path] = {}
_run_id_index_stamp: float = 0.0
_run_id_index_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "script-src 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# Request models with validation
# ---------------------------------------------------------------------------

class DetectRequest(BaseModel):
    server: str = ""
    model: str
    mode: Literal["single", "sample", "all"] = "sample"
    sample_size: Optional[int] = Field(None, ge=1, le=500)
    max_tokens: Optional[int] = Field(None, ge=100, le=65536)
    timeout: int = Field(300, ge=10, le=600)
    delay: float = Field(0.2, ge=0.0, le=30.0)
    difficulty: Optional[Literal["easy", "medium", "hard"]] = None
    test_set: Optional[Literal["A", "B", "C", "D"]] = None
    input_format: Literal["csv"] = "csv"
    csv_dir: Optional[str] = None
    include_benign: bool = False
    runs: int = Field(1, ge=1, le=10)
    provider: Literal["lmstudio", "anthropic", "openai"] = "lmstudio"
    # Cloud-provider API keys — passed via env var to the subprocess so they
    # never land in the cmdline (visible in `ps`/job logs) or the saved manifest.
    anthropic_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None

    @field_validator("csv_dir")
    @classmethod
    def validate_csv_dir(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            resolved = Path(v).resolve()
            resolved.relative_to(PROJECT_ROOT)
        except (ValueError, OSError):
            raise ValueError("csv_dir must be within the project directory")
        return v


class PreflightRequest(BaseModel):
    provider: Literal["lmstudio", "anthropic", "openai"] = "lmstudio"
    server: str = ""
    model: str
    timeout: int = Field(300, ge=10, le=600)
    anthropic_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None


class CompareRequest(BaseModel):
    server: str = ""
    models: List[str]
    mode: Literal["single", "sample", "all"] = "sample"
    sample_size: int = Field(10, ge=1, le=500)
    max_tokens: Optional[int] = Field(None, ge=100, le=65536)
    timeout: int = Field(300, ge=10, le=600)
    delay: float = Field(0.2, ge=0.0, le=30.0)
    difficulty: Optional[Literal["easy", "medium", "hard"]] = None
    test_set: Optional[Literal["A", "B", "C", "D"]] = None

    @field_validator("models")
    @classmethod
    def validate_models(cls, v: List[str]) -> List[str]:
        cleaned = [m.strip() for m in v if m.strip()]
        if not cleaned:
            raise ValueError("models must be a non-empty list")
        return cleaned


def _is_within_outputs(p: Path) -> bool:
    try:
        p.resolve().relative_to(OUTPUTS_DIR)
        return True
    except Exception:
        return False


def _check_job_cap_locked() -> None:
    """Raise 429 if too many jobs are already running. Must be called with _jobs_lock held."""
    running = sum(1 for j in JOBS.values() if j.get("process") and j["process"].poll() is None)
    if running >= MAX_CONCURRENT_JOBS:
        raise HTTPException(status_code=429, detail=f"Too many concurrent jobs ({MAX_CONCURRENT_JOBS} max)")


def _evict_finished_jobs_locked() -> None:
    """Drop the oldest finished jobs beyond MAX_FINISHED_JOBS and close their
    log handles. Must be called with _jobs_lock held."""
    finished = [
        (job_id, job) for job_id, job in JOBS.items()
        if not (job.get("process") and job["process"].poll() is None)
    ]
    excess = len(finished) - MAX_FINISHED_JOBS
    if excess <= 0:
        return
    finished.sort(key=lambda kv: kv[1].get("created_at", ""))
    for job_id, job in finished[:excess]:
        JOBS.pop(job_id, None)
        lf = job.get("log_file")
        if lf and not lf.closed:
            try:
                lf.close()
            except Exception:
                pass


def _discover_manifests() -> List[Path]:
    if not OUTPUTS_DIR.exists():
        return []
    # NOTE: `run_manifest_multimodel_*.json` also matches `run_manifest_*.json`,
    # so we must avoid double-counting.
    multimodel = list(OUTPUTS_DIR.glob("run_manifest_multimodel_*.json"))
    single = [p for p in OUTPUTS_DIR.glob("run_manifest_*.json")
              if not p.name.startswith("run_manifest_multimodel_")]
    manifests = single + multimodel
    # newest first
    return sorted(manifests, key=lambda p: p.stat().st_mtime, reverse=True)


def _manifests_cache_stamp() -> float:
    """Latest mtime across manifest files — used to invalidate the run_id index."""
    if not OUTPUTS_DIR.exists():
        return 0.0
    latest = OUTPUTS_DIR.stat().st_mtime
    for path in _discover_manifests():
        try:
            latest = max(latest, path.stat().st_mtime)
        except OSError:
            continue
    return latest


def _invalidate_run_id_index() -> None:
    global _run_id_index_stamp
    with _run_id_index_lock:
        _run_id_index.clear()
        _run_id_index_stamp = 0.0


def _run_id_index_map() -> Dict[str, Path]:
    """Build or return cached ``run_id`` → manifest path (rebuilt when outputs change)."""
    global _run_id_index, _run_id_index_stamp
    stamp = _manifests_cache_stamp()
    with _run_id_index_lock:
        if _run_id_index and stamp == _run_id_index_stamp:
            return _run_id_index
        index: Dict[str, Path] = {}
        for path in _discover_manifests():
            try:
                data = _load_json(path)
                rid = data.get("run_id")
                if rid is not None:
                    index[str(rid)] = path
            except Exception:
                continue
        _run_id_index = index
        _run_id_index_stamp = stamp
        return _run_id_index


def _manifest_path_for_run_id(run_id: str) -> Optional[Path]:
    return _run_id_index_map().get(run_id)


def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

_SSRF_BLOCKED_PREFIXES = (
    "169.254.",       # link-local / cloud metadata
    "0.",             # unspecified
)
_SSRF_BLOCKED_HOSTS = {"metadata.google.internal"}


def _validate_server_url(server: str) -> str:
    server = (server or "").strip()
    if not server:
        raise HTTPException(status_code=400, detail="server is required")
    try:
        u = urllib.parse.urlparse(server)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid server URL")
    if u.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="server URL must start with http:// or https://")
    if not u.netloc:
        raise HTTPException(status_code=400, detail="invalid server URL (missing host)")
    if u.username or u.password:
        raise HTTPException(status_code=400, detail="server URL must not include credentials")
    hostname = u.hostname or ""
    if hostname in _SSRF_BLOCKED_HOSTS or any(hostname.startswith(p) for p in _SSRF_BLOCKED_PREFIXES):
        raise HTTPException(status_code=400, detail="server URL points to a blocked address")
    return server.rstrip("/")


def _extract_timeout_s(cmd: List[str]) -> Optional[int]:
    """Pull the per-file timeout (--timeout N) out of a command list."""
    if not cmd:
        return None
    for i, arg in enumerate(cmd):
        if arg == "--timeout" and i + 1 < len(cmd):
            try:
                return int(cmd[i + 1])
            except (TypeError, ValueError):
                return None
    return None


def _last_write_seconds_ago(log_rel: Optional[str]) -> Optional[float]:
    """Seconds since the job's log file was last touched, or None if unavailable."""
    if not log_rel:
        return None
    p = (OUTPUTS_DIR / log_rel).resolve()
    if not _is_within_outputs(p) or not p.exists():
        return None
    try:
        import time
        return max(0.0, time.time() - p.stat().st_mtime)
    except Exception:
        return None


def _job_status(job: Dict[str, Any]) -> Dict[str, Any]:
    p = job.get("process")
    log_rel = job.get("log_path")
    timeout_s = _extract_timeout_s(job.get("cmd"))
    last_write = _last_write_seconds_ago(log_rel)
    base: Dict[str, Any] = {
        "timeout_s": timeout_s,
        "last_write_seconds_ago": last_write,
    }
    if p is None:
        return {"status": job.get("status", "unknown"), **base}
    code = p.poll()
    if code is None:
        return {"status": "running", **base}
    return {"status": "finished", "exit_code": code, **base}


def _read_static_page(name: str) -> str:
    page_path = STATIC_DIR / name
    if not page_path.exists():
        raise HTTPException(status_code=500, detail=f"Missing static page: {name}")
    return page_path.read_text(encoding="utf-8")


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _read_static_page("index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Ground-truth explorer / annotator (page at /gt, API under /api/gt/*).
from forcastl.webapp import gt_explorer  # noqa: E402
app.include_router(gt_explorer.router)


@app.get("/api/runs")
def list_runs() -> List[Dict[str, Any]]:
    runs = []
    for path in _discover_manifests():
        try:
            data = _load_json(path)
            runs.append({
                "run_id": data.get("run_id"),
                "kind": data.get("kind"),
                "started_at": data.get("started_at"),
                "finished_at": data.get("finished_at"),
                "model": data.get("model"),
                "models": data.get("models"),
                "summary": data.get("summary"),
                "manifest_path": str(path.name),
            })
        except Exception:
            continue
    # Sort by run start time (newest first), not file mtime — mtime can be
    # bumped by backfills or patches and would push older runs to the top.
    # Fall back to manifest_path (which embeds the timestamp) when started_at
    # is missing on legacy manifests.
    runs.sort(
        key=lambda r: (r.get("started_at") or r.get("manifest_path") or ""),
        reverse=True,
    )
    return runs


@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> Dict[str, Any]:
    path = _manifest_path_for_run_id(run_id)
    if path is None:
        raise HTTPException(status_code=404, detail="Run not found")
    try:
        data = _load_json(path)
        data["manifest_path"] = str(path.name)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read manifest: {e}")


@app.get("/api/outputs/file")
def get_outputs_file(path: str = Query(..., description="Path relative to outputs/")):
    p = (OUTPUTS_DIR / path).resolve()
    if not _is_within_outputs(p) or not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    # Only allow serving typical report artefacts.
    if p.suffix.lower() not in {".html", ".csv", ".json", ".txt", ".log", ".pdf"}:
        raise HTTPException(status_code=400, detail="Unsupported file type")
    return FileResponse(str(p))


@app.get("/api/runs/{manifest_name}/pdf")
def get_run_pdf(manifest_name: str):
    """Generate (or reuse) a PDF report for a given run manifest.

    The manifest name is the bare filename (e.g. run_manifest_foo_20260423.json).
    On first hit we render the PDF alongside the manifest and cache it on disk.
    """
    # Prevent traversal — must resolve to a file directly inside OUTPUTS_DIR.
    if "/" in manifest_name or "\\" in manifest_name or ".." in manifest_name:
        raise HTTPException(status_code=400, detail="Invalid manifest name")
    manifest_path = (OUTPUTS_DIR / manifest_name).resolve()
    if not _is_within_outputs(manifest_path) or not manifest_path.exists():
        raise HTTPException(status_code=404, detail="Manifest not found")
    if manifest_path.suffix.lower() != ".json":
        raise HTTPException(status_code=400, detail="Not a manifest")

    pdf_path = manifest_path.with_suffix(".pdf")

    def _pdf_is_stale() -> bool:
        # Regenerate if the manifest is newer than the PDF so users always get
        # current data.
        return (not pdf_path.exists()
                or pdf_path.stat().st_mtime < manifest_path.stat().st_mtime)

    if _pdf_is_stale():
        # One Chromium render at a time; re-check staleness under the lock so
        # concurrent requests for the same run don't each regenerate the PDF.
        with _pdf_gen_lock:
            if _pdf_is_stale():
                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        manifest = json.load(f)
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Failed to read manifest: {e}")

                csv_rel = (manifest.get("outputs") or {}).get("csv_results")
                csv_rows: List[Dict[str, str]] = []
                if csv_rel:
                    csv_path = (OUTPUTS_DIR / Path(csv_rel).name).resolve()
                    if _is_within_outputs(csv_path) and csv_path.exists():
                        from forcastl.reporting.csv_output import read_detection_csv
                        csv_rows = read_detection_csv(csv_path)

                gt_data: Optional[Dict[str, Any]] = None
                try:
                    gt_path = Path(config.GROUND_TRUTH_FILE)
                    if gt_path.exists():
                        with open(gt_path, "r", encoding="utf-8") as gf:
                            gt_data = json.load(gf).get("files")
                except Exception:
                    gt_data = None

                from forcastl.reporting.pdf_report import generate_pdf_report
                try:
                    generate_pdf_report(manifest, csv_rows, pdf_path, ground_truth=gt_data)
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    model = manifest_name.replace("run_manifest_", "").replace(".json", "")
    return FileResponse(str(pdf_path), media_type="application/pdf",
                        filename=f"{model}_report.pdf")


@app.get("/api/runs/{manifest_name}/xlsx")
def get_run_xlsx(manifest_name: str):
    """Serve a 2-sheet Excel workbook for a run.

    Sheet 1 ("Request") is the standard prompt template — the exact text sent
    to the model for every file. Sheet 2 ("Results") is the trimmed per-file
    table. Splitting them into sheets keeps the data table uncluttered while
    keeping the prompt one click away when troubleshooting.
    """
    if "/" in manifest_name or "\\" in manifest_name or ".." in manifest_name:
        raise HTTPException(status_code=400, detail="Invalid manifest name")
    manifest_path = (OUTPUTS_DIR / manifest_name).resolve()
    if not _is_within_outputs(manifest_path) or not manifest_path.exists():
        raise HTTPException(status_code=404, detail="Manifest not found")
    if manifest_path.suffix.lower() != ".json":
        raise HTTPException(status_code=400, detail="Not a manifest")

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read manifest: {e}")

    csv_rel = (manifest.get("outputs") or {}).get("csv_results")
    if not csv_rel:
        raise HTTPException(status_code=404, detail="No CSV recorded for this run")
    csv_path = (OUTPUTS_DIR / Path(csv_rel).name).resolve()
    if not _is_within_outputs(csv_path) or not csv_path.exists():
        raise HTTPException(status_code=404, detail="CSV file missing on disk")

    from fastapi.responses import Response
    from forcastl.reporting.csv_output import read_detection_csv, render_user_facing_xlsx
    rows = read_detection_csv(csv_path)
    run_meta = {"model": manifest.get("model"), "run_id": manifest.get("run_id")}
    try:
        body = render_user_facing_xlsx(rows, run_meta=run_meta)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    model = manifest_name.replace("run_manifest_", "").replace(".json", "")
    return Response(
        content=body,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{model}_results.xlsx"'},
    )


@app.get("/api/outputs/csv")
def get_csv(path: str = Query(..., description="CSV path relative to outputs/")) -> Dict[str, Any]:
    p = (OUTPUTS_DIR / path).resolve()
    if not _is_within_outputs(p) or not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail="CSV not found")
    if p.suffix.lower() != ".csv":
        raise HTTPException(status_code=400, detail="Not a CSV")
    if p.stat().st_size > MAX_CSV_BYTES:
        raise HTTPException(status_code=413,
                            detail=f"CSV too large to render ({p.stat().st_size} bytes; "
                                   f"limit {MAX_CSV_BYTES})")

    with open(p, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return {"path": path, "rows": rows}

@app.get("/api/server/models")
def get_server_models(
    server: str = Query(..., description="OpenAI-compatible server base URL"),
    include_embeddings: bool = Query(False, description="Include embedding/vector models"),
) -> Dict[str, Any]:
    server_url = _validate_server_url(server)
    try:
        resp = requests.get(f"{server_url}/v1/models", timeout=10)
        resp.raise_for_status()
        payload = resp.json()
    except requests.exceptions.ConnectionError:
        raise HTTPException(
            status_code=502,
            detail=f"Could not connect to {server_url}. Is the model server running?",
        )
    except requests.exceptions.Timeout:
        raise HTTPException(
            status_code=502,
            detail=f"Connection to {server_url} timed out after 10 seconds.",
        )
    except requests.exceptions.HTTPError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Server returned HTTP {e.response.status_code} from {server_url}/v1/models.",
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to reach {server_url}: {type(e).__name__}")

    data = payload.get("data")
    if not isinstance(data, list):
        raise HTTPException(status_code=502, detail="invalid /v1/models response (missing data list)")

    models: List[Dict[str, Any]] = []
    seen: set = set()
    for m in data:
        if not isinstance(m, dict):
            continue
        mid = m.get("id")
        if not isinstance(mid, str) or not mid.strip():
            continue
        mid = mid.strip()
        if mid in seen:
            continue
        seen.add(mid)
        entry: Dict[str, Any] = {"id": mid}
        # Extract context length from common OpenAI-compatible fields
        for key in ("context_length", "max_model_len", "context_window"):
            val = m.get(key)
            if isinstance(val, (int, float)) and val > 0:
                entry["context_length"] = int(val)
                break
        models.append(entry)

    models.sort(key=lambda x: x["id"])
    if not include_embeddings:
        skip = ("embedding", "embed", "vector", "retrieval")
        models = [m for m in models if not any(k in m["id"].lower() for k in skip)]

    return {"server": server_url, "models": models}


_ANTHROPIC_FALLBACK_MODELS = [
    {"id": "claude-opus-4-7", "name": "Claude Opus 4.7"},
    {"id": "claude-opus-4-6", "name": "Claude Opus 4.6"},
    {"id": "claude-sonnet-4-6", "name": "Claude Sonnet 4.6"},
    {"id": "claude-haiku-4-5", "name": "Claude Haiku 4.5"},
]


@app.post("/api/anthropic/models")
def get_anthropic_models(api_key: Optional[str] = Body(None, embed=True)) -> Dict[str, Any]:
    """Return available Anthropic models. If a key is supplied (or in env),
    queries the live /v1/models endpoint; otherwise returns the curated
    fallback list so the UI can populate before the user enters a key.

    POST (not GET) so the API key travels in the request body, never in the URL
    (query strings leak via browser history, referrers, and proxy/access logs).
    """
    key = (api_key or "").strip() or os.environ.get("ANTHROPIC_API_KEY")
    if key:
        try:
            from forcastl.core.anthropic_client import list_anthropic_models
            live = list_anthropic_models(api_key=key)
            if live:
                return {"models": live, "source": "live"}
        except Exception:
            pass
    return {"models": _ANTHROPIC_FALLBACK_MODELS, "source": "fallback"}


_OPENAI_FALLBACK_MODELS = [
    {"id": "gpt-4o", "name": "GPT-4o"},
    {"id": "gpt-4o-mini", "name": "GPT-4o mini"},
    {"id": "o1-mini", "name": "o1-mini"},
]


@app.post("/api/openai/models")
def get_openai_models(api_key: Optional[str] = Body(None, embed=True)) -> Dict[str, Any]:
    """Return available OpenAI chat models. With a key, queries the live
    /v1/models endpoint and filters out non-chat (embedding/whisper/etc.).
    Without a key, returns a small curated fallback so the UI can populate.
    """
    key = (api_key or "").strip() or os.environ.get("OPENAI_API_KEY")
    if key:
        try:
            from forcastl.core.openai_client import list_openai_models
            live = list_openai_models(api_key=key)
            if live:
                return {"models": live, "source": "live"}
        except Exception:
            pass
    return {"models": _OPENAI_FALLBACK_MODELS, "source": "fallback"}


@app.get("/api/jobs")
def list_jobs() -> List[Dict[str, Any]]:
    out = []
    for job_id, job in sorted(JOBS.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True):
        st = _job_status(job)
        out.append({
            "job_id": job_id,
            "kind": job.get("kind"),
            "created_at": job.get("created_at"),
            "cmd": job.get("cmd"),
            "log_path": job.get("log_path"),
            **st,
        })
    return out


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> Dict[str, Any]:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    st = _job_status(job)
    return {
        "job_id": job_id,
        "kind": job.get("kind"),
        "created_at": job.get("created_at"),
        "cmd": job.get("cmd"),
        "log_path": job.get("log_path"),
        **st,
    }


@app.get("/api/jobs/{job_id}/log")
def get_job_log(job_id: str, tail: int = Query(200, ge=1, le=5000)) -> Dict[str, Any]:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    log_rel = job.get("log_path")
    if not log_rel:
        return {"job_id": job_id, "log": ""}
    p = (OUTPUTS_DIR / log_rel).resolve()
    if not _is_within_outputs(p) or not p.exists():
        return {"job_id": job_id, "log": ""}
    # Read only the tail of the log to avoid loading huge files on every poll.
    max_bytes = tail * 200  # ~200 bytes per line estimate
    size = p.stat().st_size
    with open(p, "r", encoding="utf-8", errors="replace") as lf:
        if size > max_bytes:
            lf.seek(size - max_bytes)
            lf.readline()  # discard partial first line
        lines = lf.read().splitlines()
    return {"job_id": job_id, "log": "\n".join(lines[-tail:])}


@app.post("/api/run/compare")
def run_compare(req: CompareRequest) -> Dict[str, Any]:
    """Start a multi-model comparison run (raw-only) as a background subprocess."""
    server = _validate_server_url(req.server or config.DEFAULT_LLM_SERVER)

    cmd = [
        sys.executable, "-m", "forcastl.cli.compare",
        "--server", server,
        "--models", *req.models,
        "--mode", req.mode,
        "--sample-size", str(req.sample_size),
        "--timeout", str(req.timeout),
        "--delay", str(req.delay),
        "--report",
    ]
    if req.max_tokens is not None:
        cmd += ["--max-tokens", str(req.max_tokens)]
    if req.difficulty:
        cmd += ["--difficulty", req.difficulty]
    if req.test_set:
        cmd += ["--test-set", req.test_set]

    with _jobs_lock:
        _check_job_cap_locked()
        _evict_finished_jobs_locked()
        job_id = uuid.uuid4().hex[:12]
        created_at = datetime.now().isoformat(timespec="seconds")
        log_rel = f"web_job_{job_id}.log"
        log_path = OUTPUTS_DIR / log_rel

        OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
        f = open(log_path, "w", encoding="utf-8", errors="replace")
        p = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=f,
            stderr=subprocess.STDOUT,
            text=True,
        )
        JOBS[job_id] = {
            "kind": "compare",
            "created_at": created_at,
            "cmd": cmd,
            "log_path": log_rel,
            "process": p,
            "log_file": f,
        }
    return {"job_id": job_id, "status": "running", "log_path": log_rel}


@app.post("/api/preflight")
def preflight(req: PreflightRequest) -> Dict[str, Any]:
    """Quick pre-flight health check before a run — verify the model is reachable,
    authenticated, and responds in the expected MALICIOUS/EVIDENCE format. Returns
    {status, message, latency_s, estimated_runtime_s}. Synchronous; one tiny probe."""
    from forcastl.core.health_check import health_check
    api_key = None
    server = req.server
    if req.provider == "anthropic":
        api_key = (req.anthropic_api_key or "").strip() or None
    elif req.provider == "openai":
        api_key = (req.openai_api_key or "").strip() or None
    else:
        # Local/OpenAI-compatible path: apply the same SSRF guard the run and
        # server-models endpoints use (loopback/LAN stay allowed; cloud-metadata
        # and unspecified/link-local addresses are blocked).
        server = _validate_server_url(req.server or config.DEFAULT_LLM_SERVER)
    return health_check(
        provider=req.provider, server=server, model=req.model, api_key=api_key,
        # Cap the synchronous probe so the endpoint can't block for the full run timeout.
        timeout=min(req.timeout, 120),
    )


@app.post("/api/run/detect")
def run_detect(req: DetectRequest) -> Dict[str, Any]:
    """Start a single-model detection run (raw-only) as a background subprocess."""
    if req.input_format == "csv" and not req.csv_dir:
        raise HTTPException(status_code=400, detail="csv_dir is required when input_format=csv")

    cmd = [
        sys.executable, "-m", "forcastl.cli.detect",
        "--model", req.model,
        "--mode", req.mode,
        "--timeout", str(req.timeout),
        "--delay", str(req.delay),
        "--input-format", req.input_format,
        "--provider", req.provider,
    ]
    if req.max_tokens is not None:
        cmd += ["--max-tokens", str(req.max_tokens)]
    # API key flows via env, never via cmdline — keeps it out of `ps` and the log.
    sub_env = os.environ.copy()
    if req.provider == "anthropic":
        if not (req.anthropic_api_key and req.anthropic_api_key.strip()) and not sub_env.get("ANTHROPIC_API_KEY"):
            raise HTTPException(status_code=400,
                                detail="Anthropic API key required (set in UI or ANTHROPIC_API_KEY env var)")
        if req.anthropic_api_key and req.anthropic_api_key.strip():
            sub_env["ANTHROPIC_API_KEY"] = req.anthropic_api_key.strip()
    elif req.provider == "openai":
        if not (req.openai_api_key and req.openai_api_key.strip()) and not sub_env.get("OPENAI_API_KEY"):
            raise HTTPException(status_code=400,
                                detail="OpenAI API key required (set in UI or OPENAI_API_KEY env var)")
        if req.openai_api_key and req.openai_api_key.strip():
            sub_env["OPENAI_API_KEY"] = req.openai_api_key.strip()
    else:
        # LM Studio path validates and adds --server.
        server = _validate_server_url(req.server or config.DEFAULT_LLM_SERVER)
        cmd += ["--server", server]

    if req.mode == "sample" and req.sample_size is not None:
        cmd += ["--sample-size", str(req.sample_size)]
    if req.input_format == "csv":
        cmd += ["--csv-dir", req.csv_dir]
    if req.difficulty:
        cmd += ["--difficulty", req.difficulty]
    if req.test_set:
        cmd += ["--test-set", req.test_set]
    if req.include_benign:
        cmd += ["--include-benign"]
    if req.runs and req.runs > 1:
        cmd += ["--runs", str(req.runs)]

    with _jobs_lock:
        _check_job_cap_locked()
        _evict_finished_jobs_locked()
        job_id = uuid.uuid4().hex[:12]
        created_at = datetime.now().isoformat(timespec="seconds")
        log_rel = f"web_job_{job_id}.log"
        log_path = OUTPUTS_DIR / log_rel

        OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
        f = open(log_path, "w", encoding="utf-8", errors="replace")
        p = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=f,
            stderr=subprocess.STDOUT,
            text=True,
            env=sub_env,
        )
        JOBS[job_id] = {
            "kind": "detect",
            "created_at": created_at,
            "cmd": cmd,
            "log_path": log_rel,
            "process": p,
            "log_file": f,
        }
    return {"job_id": job_id, "status": "running", "log_path": log_rel}


@app.delete("/api/runs/{run_id}")
def delete_run(run_id: str) -> Dict[str, Any]:
    """Delete a run manifest and its output files from disk."""
    path = _manifest_path_for_run_id(run_id)
    if path is None:
        raise HTTPException(status_code=404, detail="Run not found")
    try:
        data = _load_json(path)
    except Exception:
        raise HTTPException(status_code=404, detail="Run not found")

    try:
        # Collect output file paths from the manifest
        outputs = data.get("outputs")
        if isinstance(outputs, dict):
            for v in outputs.values():
                if not isinstance(v, str):
                    continue
                p = (OUTPUTS_DIR / Path(v).name).resolve()
                if _is_within_outputs(p) and p.exists() and p.is_file():
                    os.remove(p)

        # For multimodel manifests, also clean per-model outputs
        models = data.get("models")
        if isinstance(models, list):
            for m in models:
                if not isinstance(m, dict):
                    continue
                for key in ("csv_results", "html_report"):
                    v = m.get(key)
                    if not isinstance(v, str):
                        continue
                    p = (OUTPUTS_DIR / Path(v).name).resolve()
                    if _is_within_outputs(p) and p.exists() and p.is_file():
                        os.remove(p)
            # comparison report at top level
            cr = data.get("comparison_report")
            if isinstance(cr, str):
                p = (OUTPUTS_DIR / Path(cr).name).resolve()
                if _is_within_outputs(p) and p.exists() and p.is_file():
                    os.remove(p)

        # Delete the manifest itself
        if path.exists():
            os.remove(path)
        _invalidate_run_id_index()
        return {"deleted": run_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete run: {e}")


@app.delete("/api/jobs/finished")
def clear_finished_jobs() -> Dict[str, Any]:
    """Remove all non-running jobs from the in-memory job list."""
    to_remove = []
    for job_id, job in JOBS.items():
        st = _job_status(job)
        if st["status"] != "running":
            to_remove.append(job_id)
    for job_id in to_remove:
        job = JOBS.pop(job_id)
        lf = job.get("log_file")
        if lf and not lf.closed:
            try:
                lf.close()
            except Exception:
                pass
    return {"cleared": len(to_remove)}


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str) -> Dict[str, Any]:
    """Terminate a running job's subprocess."""
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    st = _job_status(job)
    if st["status"] != "running":
        raise HTTPException(status_code=409, detail="Job is not running")
    p = job.get("process")
    if p:
        p.terminate()
    return {"cancelled": job_id}
