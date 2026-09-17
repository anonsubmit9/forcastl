"""Canonical CSV → evidence path for the ground-truth pipeline.

The CSV corpus (EvtxECmd output) is the source of truth for ground truth; nothing
in the GT build/validation/audit pipeline parses the binary EVTX anymore. This
module is the single place that:

  * resolves a GT/metadata entry (keyed by `.evtx` name) to its CSV, by lowercased
    stem — the SAME resolution the runtime uses to score CSV runs
    (`core/file_selector._build_csv_lookup`);
  * reads each CSV row's structured `Payload` JSON directly (no XML round-trip),
    HTML-unescaping the values EvtxECmd stored escaped;
  * aggregates the six core evidence fields and drops network noise that free-text
    IOC scanning surfaces (XML namespaces, structural tokens, degenerate IPs).

GT generation (`sync_ground_truth_evidence.py`), validation (`validation/
ground_truth.py`), and the maintenance audits all import from here so their
extraction stays byte-for-byte consistent with the stored ground truth.
"""

from __future__ import annotations

import csv
import html
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Set

from forcastl import config


FIELDS = ("event_ids", "processes", "accounts", "commands", "network", "registry")
DEFAULT_CSV_DIR = config.DATA_DIR / "csv"

# EvtxECmd writes payload values HTML-escaped; drop XML namespace URIs that are
# never real network IOCs (e.g. schemas.microsoft.com/.../task, www.w3.org/...).
_XML_NAMESPACE_MARKERS = ("schemas.", "w3.org")
# Structural tokens that leak from path/field text (e.g. \Device\ConDrv, %TEMP%).
_NETWORK_TOKEN_DENYLIST = {"device", "win", "root", "temp"}
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


# ── CSV resolution (by lowercased stem) ──────────────────────────────────────
def build_csv_index(csv_dir: Path | str = DEFAULT_CSV_DIR) -> Dict[str, str]:
    """Map stem(lowercase) -> CSV path, matching core/file_selector._build_csv_lookup."""
    root = Path(csv_dir)
    if not root.exists():
        raise FileNotFoundError(f"CSV directory not found: {root}")
    index: Dict[str, str] = {}
    for csv_file in root.rglob("*.csv"):
        index.setdefault(csv_file.stem.lower(), str(csv_file))
    return index


def resolve_csv(
    name: str,
    index: Dict[str, str] | None = None,
    csv_dir: Path | str = DEFAULT_CSV_DIR,
) -> str | None:
    """Resolve a GT/metadata entry name (e.g. 'ID33205-….evtx') to its CSV path.

    Pass a prebuilt `index` when resolving many names; otherwise a one-off rglob
    is used. Returns None if no CSV matches the stem.
    """
    stem = Path(name).stem.lower()
    if index is not None:
        return index.get(stem)
    for csv_file in Path(csv_dir).rglob(f"{Path(name).stem}.csv"):
        return str(csv_file)
    return None


# ── CSV → events → evidence ──────────────────────────────────────────────────
def _unescape(obj: Any) -> Any:
    """Recursively HTML-unescape string values in a parsed Payload tree.

    EvtxECmd stores payload `#text` HTML-escaped (``&lt;``, ``&gt;``, ``&amp;``);
    unescaping yields the canonical command/registry text a model would emit.
    """
    if isinstance(obj, str):
        return html.unescape(obj)
    if isinstance(obj, list):
        return [_unescape(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _unescape(v) for k, v in obj.items()}
    return obj


def read_csv_events(csv_path: str) -> List[Dict[str, Any]]:
    """Read an EvtxECmd CSV into event dicts in `extract_evidence_from_event`
    format, reading each row's structured `Payload` JSON directly (un-escaped).
    No XML reconstruction — this is the GT-side counterpart to the runtime's
    `core/parser.parse_csv_file`. One dict per row (= one event)."""
    events: List[Dict[str, Any]] = []
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            raw = row.get("Payload") or ""
            try:
                payload = json.loads(raw) if raw else {}
            except (ValueError, TypeError):
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            events.append(
                {
                    "Event": {
                        "System": {"EventID": {"#text": str(row.get("EventId") or "")}},
                        **_unescape(payload),
                    }
                }
            )
    return events


def clean_network(items: Set[str]) -> Set[str]:
    """Drop non-IOC network noise surfaced by free-text IOC scanning: XML
    namespaces, structural path tokens, and degenerate/version-like IPv4 (first
    octet 0 or >=224 reserved/multicast, or 3+ zero octets like 1.0.0.0). Real
    hosts (JUMP01, fs03vuln) and routable IPs are kept."""
    out: Set[str] = set()
    for n in items:
        low = n.lower()
        if low in _NETWORK_TOKEN_DENYLIST:
            continue
        if any(m in low for m in _XML_NAMESPACE_MARKERS):
            continue
        m = _IPV4_RE.match(n)
        if m:
            octs = [int(g) for g in m.groups()]
            if octs[0] == 0 or octs[0] >= 224 or octs.count(0) >= 3:
                continue
        out.add(n)
    return out


def evidence_from_events(events: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    """Aggregate the six core evidence sets across events, then filter network
    noise. Uses the same per-event extractor as the live detector so GT stays
    self-consistent with runtime hallucination checks."""
    # Lazy import to avoid a core <-> validation import cycle.
    from forcastl.validation.ground_truth import extract_evidence_from_event, merge_evidence

    evidence: Dict[str, Set[str]] = {f: set() for f in FIELDS}
    for event in events:
        merge_evidence(evidence, extract_evidence_from_event(event))
    evidence["network"] = clean_network(evidence["network"])
    return evidence


def evidence_from_csv(csv_path: str) -> Dict[str, Set[str]]:
    """Convenience: aggregated, noise-filtered evidence for one CSV file."""
    return evidence_from_events(read_csv_events(csv_path))


# ── Deterministic ordering (shared by every GT writer) ───────────────────────
# sync_ground_truth_evidence (the canonical GT writer), scripts/add_attack_fields,
# and add_sample.py all sort the six evidence fields through these so the corpus
# has ONE stable order — runs are reproducible (hash-seed-independent) and
# re-running any writer produces no spurious diff.
def sort_event_ids(values: Set[str]) -> List[str]:
    """Numeric-aware sort; trailing raw string breaks ties (e.g. '4'/'004')."""
    def _k(v: str):
        s = str(v).strip()
        return (0, int(s), s) if s.isdigit() else (1, 0, s)

    return [str(v) for v in sorted(values, key=_k)]


def sort_text(values: Set[str]) -> List[str]:
    """Case-insensitive sort; the exact string breaks case-variant ties
    (e.g. ``\\TEMP`` vs ``\\temp``) so the order is stable across runs."""
    return sorted(
        (str(v) for v in values if str(v).strip()), key=lambda s: (s.lower(), s)
    )
