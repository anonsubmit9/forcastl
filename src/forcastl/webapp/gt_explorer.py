"""Ground-truth explorer / annotator — a visual tool for viewing each source CSV
and curating its ground-truth evidence by highlighting strings in the artefact.

Routes (mounted on the main app via ``app.include_router(router)``):
- ``GET  /gt``                         -> the explorer page (static/gt.html)
- ``GET  /api/gt/files``               -> the corpus file list (live; reflects expansion)
- ``GET  /api/gt/file/{name}``         -> one file's events + its GT evidence + label
- ``POST /api/gt/file/{name}/evidence`` -> add/remove one evidence value (artefact-grounded)

Safety: a value can only be ADDED if it actually appears in that file's source
artefact (the same "must be in the data" rule the methodology requires), so the GUI
cannot introduce fabricated GT. Every edit is appended to ``data/gt_edit_log.jsonl``.
"""
from __future__ import annotations

import csv as _csv
import html
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from forcastl import config
from forcastl.core.csv_evidence import build_csv_index, resolve_csv, sort_event_ids, sort_text

router = APIRouter()

_STATIC_DIR = (Path(__file__).parent / "static").resolve()
_GT_PATH = Path(config.GROUND_TRUTH_FILE)
_META_PATH = Path(config.METADATA_FILE)
_EDIT_LOG = Path(config.DATA_DIR) / "gt_edit_log.jsonl"
_REVIEW_PATH = Path(config.DATA_DIR) / "gt_review_state.json"

# The six core evidence fields, in display order.
FIELDS = ["event_ids", "processes", "accounts", "commands", "network", "registry"]

# Cap rendered events so a huge baseline log can't blow up the page / response.
_MAX_EVENTS = 800

_gt_lock = threading.Lock()
_review_lock = threading.Lock()


def _load(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_review() -> Dict[str, Any]:
    if _REVIEW_PATH.is_file():
        try:
            return json.loads(_REVIEW_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return {}


def _norm(s: str) -> str:
    """Normalize for artefact-presence matching: lowercase, collapse whitespace."""
    return " ".join(str(s).lower().split())


# The GT extractor expands registry hive abbreviations; the raw source uses the
# short form. Match either way so normalized GT values still resolve to the source.
_REG_HIVES = [
    ("HKEY_LOCAL_MACHINE", "HKLM"), ("HKEY_CURRENT_USER", "HKCU"),
    ("HKEY_CLASSES_ROOT", "HKCR"), ("HKEY_CURRENT_CONFIG", "HKCC"), ("HKEY_USERS", "HKU"),
]


def _reg_variants(value: str) -> List[str]:
    v = str(value)
    up = v.upper()
    out = [v]
    for lng, sht in _REG_HIVES:
        if up.startswith(lng):
            out.append(sht + v[len(lng):])
        elif up.startswith(sht + "\\") or up == sht:
            out.append(lng + v[len(sht):])
    return out


def _present(field: str, value: str, artefact: str, id_set: set) -> bool:
    """Is `value` present in the source for this field (hive-aware for registry)?"""
    if field == "event_ids":
        return value in id_set
    if field == "registry":
        return any(_norm(x) in artefact for x in _reg_variants(value))
    return _norm(value) in artefact


def _flatten_payload(payload: Any) -> List[Dict[str, str]]:
    """Recursively flatten an EvtxECmd Payload JSON into [{name, value}] rows so
    EVERY leaf is surfaced regardless of shape (EventData.Data {@Name,#text} lists,
    UserData blocks, SQL-audit / raw structures, nested dicts). The displayed
    artefact must contain everything the GT extractor can read."""
    out: List[Dict[str, str]] = []

    def walk(node: Any, label: str) -> None:
        if isinstance(node, dict):
            name = node.get("@Name")
            if "#text" in node:  # the common EvtxECmd {@Name, #text} leaf
                out.append({"name": str(name or label), "value": html.unescape(str(node.get("#text") or ""))})
            for k, v in node.items():
                if k == "@Name" or k == "#text" or str(k).startswith("@"):
                    continue
                walk(v, str(k))
        elif isinstance(node, list):
            for item in node:
                walk(item, label)
        elif node is not None and str(node) != "":
            out.append({"name": label, "value": html.unescape(str(node))})

    walk(payload, "Payload")
    return out


def _read_events(csv_path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        for row in _csv.DictReader(f):
            raw = row.get("Payload") or ""
            try:
                payload = json.loads(raw) if raw else {}
            except (ValueError, TypeError):
                payload = {}
            eid = str(row.get("EventId") or "")
            # Surface EventID as its own field row so the event_ids GT field has a
            # visible, selectable value (the id lives in the EventId column, not the Payload).
            fields = ([{"name": "EventID", "value": eid}] if eid else []) + _flatten_payload(payload)
            events.append({
                "event_id": eid,
                "time": str(row.get("TimeCreated") or "")[:19],
                "provider": str(row.get("Provider") or ""),
                "channel": str(row.get("Channel") or ""),
                "map": str(row.get("MapDescription") or ""),
                "fields": fields,
            })
    return events


def _artefact_text(events: List[Dict[str, Any]]) -> str:
    parts: List[str] = []
    for ev in events:
        for fl in ev["fields"]:
            parts.append(fl["value"])
    return _norm(" \n ".join(parts))


def _event_id_set(events: List[Dict[str, Any]]) -> set:
    return {ev["event_id"] for ev in events if ev["event_id"]}


@router.get("/gt", response_class=HTMLResponse)
def gt_page() -> str:
    page = _STATIC_DIR / "gt.html"
    if not page.exists():
        raise HTTPException(status_code=500, detail="Missing static page: gt.html")
    return page.read_text(encoding="utf-8")


@router.get("/api/gt/files")
def list_gt_files() -> Dict[str, Any]:
    """Live corpus listing — read fresh so dataset expansion shows up immediately."""
    gt = _load(_GT_PATH)["files"]
    try:
        md = _load(_META_PATH)["files"]
    except Exception:
        md = {}
    review = _load_review()
    out = []
    for name, entry in gt.items():
        ev = entry.get("evidence", {}) or {}
        m = md.get(name, {})
        out.append({
            "name": name,
            "malicious": entry.get("malicious"),
            "source": m.get("source"),
            "difficulty": entry.get("difficulty") or m.get("difficulty"),
            "counts": {f: len(ev.get(f) or []) for f in FIELDS},
            "reviewed": bool(review.get(name, {}).get("reviewed")),
        })
    out.sort(key=lambda r: r["name"].lower())
    reviewed_count = sum(1 for r in out if r["reviewed"])
    return {"total": len(out), "reviewed_count": reviewed_count, "files": out, "fields": FIELDS}


@router.get("/api/gt/file/{name}")
def get_gt_file(name: str) -> Dict[str, Any]:
    gt = _load(_GT_PATH)["files"]
    entry = gt.get(name)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Not a ground-truth file: {name}")
    csv_path = resolve_csv(name, build_csv_index())
    if not csv_path or not Path(csv_path).is_file():
        raise HTTPException(status_code=404, detail=f"No source CSV resolves for {name}")
    events = _read_events(csv_path)
    truncated = len(events) > _MAX_EVENTS
    ev = entry.get("evidence", {}) or {}
    return {
        "name": name,
        "malicious": entry.get("malicious"),
        "difficulty": entry.get("difficulty"),
        "csv_path": str(Path(csv_path).relative_to(config.PROJECT_ROOT)) if str(csv_path).startswith(str(config.PROJECT_ROOT)) else str(csv_path),
        "event_count": len(events),
        "truncated": truncated,
        "events": events[:_MAX_EVENTS],
        "evidence": {f: list(ev.get(f) or []) for f in FIELDS},
        "reviewed": bool(_load_review().get(name, {}).get("reviewed")),
    }


class EvidenceEdit(BaseModel):
    field: str = Field(..., description="one of the six evidence fields")
    value: str = Field(..., min_length=1)
    op: str = Field("add", pattern="^(add|remove)$")


def _log_edit(name: str, edit: EvidenceEdit, result: str) -> None:
    rec = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "file": name, "field": edit.field, "value": edit.value,
        "op": edit.op, "result": result, "source": "manual-gui",
    }
    try:
        with open(_EDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


@router.post("/api/gt/file/{name}/evidence")
def edit_gt_evidence(name: str, edit: EvidenceEdit) -> Dict[str, Any]:
    if edit.field not in FIELDS:
        raise HTTPException(status_code=400, detail=f"field must be one of {FIELDS}")
    value = edit.value.strip()
    if not value:
        raise HTTPException(status_code=400, detail="value is empty")

    with _gt_lock:
        data = _load(_GT_PATH)
        entry = data["files"].get(name)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"Not a ground-truth file: {name}")
        csv_path = resolve_csv(name, build_csv_index())
        if not csv_path or not Path(csv_path).is_file():
            raise HTTPException(status_code=404, detail=f"No source CSV resolves for {name}")
        events = _read_events(csv_path)

        evidence = entry.setdefault("evidence", {})
        current = set(str(x) for x in (evidence.get(edit.field) or []))

        if edit.op == "add":
            # Artefact-grounding guardrail: only add what is actually in the source.
            present = _present(edit.field, value, _artefact_text(events), _event_id_set(events))
            if not present:
                _log_edit(name, edit, "rejected:not-in-artefact")
                raise HTTPException(
                    status_code=422,
                    detail="value not found in the source artefact — only artefact-present "
                           "evidence can be added (GT stays artefact-grounded).",
                )
            if any(value.lower() == c.lower() for c in current):
                _log_edit(name, edit, "noop:already-present")
            else:
                current.add(value)
        else:  # remove
            current = {c for c in current if c.lower() != value.lower()}

        ordered = sort_event_ids(current) if edit.field == "event_ids" else sort_text(current)
        evidence[edit.field] = ordered
        with open(_GT_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        _log_edit(name, edit, "ok")

    return {"name": name, "field": edit.field, "op": edit.op,
            "evidence": {f: list((entry.get("evidence", {}) or {}).get(f) or []) for f in FIELDS}}


def _order(field: str, values: set) -> List[str]:
    return sort_event_ids(values) if field == "event_ids" else sort_text(values)


class _FieldValue(BaseModel):
    field: str
    value: str = Field(..., min_length=1)


class BatchEdit(BaseModel):
    adds: List[_FieldValue] = []
    removes: List[_FieldValue] = []
    label: Optional[str] = None          # "YES"|"NO" to relabel; None = no change
    label_reason: Optional[str] = None


@router.post("/api/gt/file/{name}/evidence/batch")
def batch_edit_gt_evidence(name: str, batch: BatchEdit) -> Dict[str, Any]:
    """Apply a staged set of adds/removes in ONE write. Adds are artefact-grounded
    (rejected if not present in the source); rejected adds are returned, not applied."""
    with _gt_lock:
        data = _load(_GT_PATH)
        entry = data["files"].get(name)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"Not a ground-truth file: {name}")
        csv_path = resolve_csv(name, build_csv_index())
        if not csv_path or not Path(csv_path).is_file():
            raise HTTPException(status_code=404, detail=f"No source CSV resolves for {name}")
        events = _read_events(csv_path)
        artefact = _artefact_text(events)
        id_set = _event_id_set(events)
        evidence = entry.setdefault("evidence", {})
        rejected: List[Dict[str, str]] = []
        n_add = n_rem = 0

        for a in batch.adds:
            if a.field not in FIELDS:
                rejected.append({"field": a.field, "value": a.value, "reason": "bad-field"})
                continue
            v = a.value.strip()
            if not v:
                continue
            present = _present(a.field, v, artefact, id_set)
            if not present:
                rejected.append({"field": a.field, "value": v, "reason": "not-in-artefact"})
                _log_edit(name, EvidenceEdit(field=a.field, value=v, op="add"), "rejected:not-in-artefact")
                continue
            cur = set(str(x) for x in (evidence.get(a.field) or []))
            if not any(v.lower() == c.lower() for c in cur):
                cur.add(v)
                n_add += 1
            evidence[a.field] = _order(a.field, cur)
            _log_edit(name, EvidenceEdit(field=a.field, value=v, op="add"), "ok")

        for r in batch.removes:
            if r.field not in FIELDS:
                continue
            v = r.value.strip()
            cur = {c for c in (str(x) for x in (evidence.get(r.field) or [])) if c.lower() != v.lower()}
            if len(cur) != len(evidence.get(r.field) or []):
                n_rem += 1
            evidence[r.field] = _order(r.field, cur)
            _log_edit(name, EvidenceEdit(field=r.field, value=v, op="remove"), "ok")

        # Optional label change (malicious/benign conviction), recorded with a
        # label_review audit trail like the curated relabels.
        n_label = 0
        if batch.label in ("YES", "NO") and batch.label != entry.get("malicious"):
            old = entry.get("malicious")
            entry["malicious"] = batch.label
            entry["label_review"] = {
                "reclassified": f"{str(old).lower()}->{batch.label.lower()}",
                "date": datetime.now().isoformat(timespec="seconds")[:10],
                "reason": (batch.label_reason or "").strip() or "Relabeled via GT Explorer",
                "source": "manual-gui",
            }
            n_label = 1
            try:
                with open(_EDIT_LOG, "a", encoding="utf-8") as lf:
                    lf.write(json.dumps({"ts": datetime.now().isoformat(timespec="seconds"),
                                         "file": name, "field": "malicious", "value": batch.label,
                                         "op": "relabel", "result": "ok", "source": "manual-gui",
                                         "reason": entry["label_review"]["reason"]}, ensure_ascii=False) + "\n")
            except OSError:
                pass

        with open(_GT_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    return {
        "name": name,
        "applied": {"adds": n_add, "removes": n_rem, "label": n_label},
        "rejected": rejected,
        "malicious": entry.get("malicious"),
        "evidence": {f: list((entry.get("evidence", {}) or {}).get(f) or []) for f in FIELDS},
    }


class ReviewState(BaseModel):
    reviewed: bool


@router.post("/api/gt/file/{name}/review")
def set_review(name: str, st: ReviewState) -> Dict[str, Any]:
    """Mark a file reviewed / unreviewed (persisted in data/gt_review_state.json)."""
    if name not in _load(_GT_PATH)["files"]:
        raise HTTPException(status_code=404, detail=f"Not a ground-truth file: {name}")
    with _review_lock:
        review = _load_review()
        if st.reviewed:
            review[name] = {"reviewed": True, "reviewed_at": datetime.now().isoformat(timespec="seconds")}
        else:
            review.pop(name, None)
        _REVIEW_PATH.write_text(json.dumps(review, indent=2, ensure_ascii=False), encoding="utf-8")
        reviewed_count = sum(1 for v in review.values() if v.get("reviewed"))
    return {"name": name, "reviewed": st.reviewed, "reviewed_count": reviewed_count}
