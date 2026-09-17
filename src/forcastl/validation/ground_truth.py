#!/usr/bin/env python3
"""
Ground Truth Evidence Validator

Resolves every entry in ground_truth_evidence.json to its CSV (EvtxECmd output —
the source of truth) and cross-references all claimed evidence (event IDs,
processes, accounts, commands, network, registry) against the actual content
found in the CSV data. Nothing here parses the binary EVTX anymore.

Produces a JSON report with per-file, per-field validation results.
"""

import csv
import json
import re
from datetime import datetime
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Set

from tqdm import tqdm

from forcastl.core.csv_evidence import (
    build_csv_index,
    evidence_from_events,
    read_csv_events,
    resolve_csv,
)

# ── Field extraction keys ──────────────────────────────────────────────────────
PROCESS_KEYS = {
    "Image", "NewProcessName", "ParentProcessName", "ProcessName",
    "ParentImage", "SourceImage", "TargetImage", "ImagePath", "ServiceFileName",
    "ServiceName",
}
ACCOUNT_KEYS = {
    "SubjectUserName", "TargetUserName", "User", "AccountName",
    "MemberName", "SamAccountName", "ObjectDN",
}
COMMAND_KEYS = {"CommandLine", "ScriptBlockText", "TaskContent"}
# Keys deliberately EXCLUDED from commands (see _is_command_noise + internal/known_issues):
#   RelativeTargetName — EID 5145 share-access *file paths* (a file read is not a command)
#   Payload            — EvtxECmd's verbose rendered-message column; duplicates the
#                        structured fields as free text and was never the sole command
#                        source for any file. Both were dumping hundreds of non-command
#                        lines into `commands` and depressing extraction scores unfairly.

# PowerShell module/cmdletization *source* markers. EID 4103/4104 ScriptBlock logging
# captures a module's generated cmdlet definitions when it loads (e.g. NetSecurity) —
# that is module source, not an executed command. Attack payloads (obfuscated loaders,
# IEX downloaders, decimal-byte arrays) don't contain these declaration markers, so the
# filter never drops a real malicious command.
_COMMAND_NOISE_MARKERS = (
    "cmdletization", "validatenotnull(", "parametersetname=",
    "<cmdletparametermetadata", "generatedtypes", "commandinvocation(",
    "parameterbinding(", "[parameter(", "[validatenotnull", "[validateset",
    "outputtype(", "[cmdletbinding",
)
NETWORK_KEYS = {
    "IpAddress", "SourceIp", "DestinationIp",
    "SourceAddress", "DestinationAddress", "DCName",
    "ClientAddress", "WorkstationName", "TargetServerName", "ShareName",
}
REGISTRY_KEYS = {"TargetObject", "ObjectName"}

# IPs embedded in SQL raw strings: [CLIENT: x.x.x.x]
SQL_CLIENT_RE = re.compile(r"\[CLIENT:\s*([\d.]+)\]")
# Hostnames in network fields
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$")
# IP pattern
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# SQL raw-string key=value pattern (e.g. "server_principal_name:sa")
SQL_KV_RE = re.compile(r"^([a-z_]+):(.+)$", re.MULTILINE)

# Account-like keys that can appear in SQL raw strings
SQL_ACCOUNT_KEYS = {
    "server_principal_name", "target_server_principal_name",
    "database_principal_name", "target_database_principal_name",
    "session_server_principal_name",
}

# IOCs embedded inside command/script text (see _iocs_from_text). High-precision
# patterns only, so we never invent evidence that isn't literally in the text.
URL_RE = re.compile(r"https?://[^\s\"'<>)\]}|]+", re.IGNORECASE)
UNC_HOST_RE = re.compile(r"\\\\([A-Za-z0-9][A-Za-z0-9._-]*)\\")  # \\host\share
REG_PATH_RE = re.compile(
    r"\b(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)(\\[^\s\"'<>|,;]+)",
    re.IGNORECASE,
)
_REG_HIVE_EXPAND = {
    "HKLM": "HKEY_LOCAL_MACHINE", "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT", "HKU": "HKEY_USERS", "HKCC": "HKEY_CURRENT_CONFIG",
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def fuzzy_ratio(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    a_n, b_n = a.lower().strip(), b.lower().strip()
    if a_n == b_n:
        return 1.0
    return SequenceMatcher(None, a_n, b_n).ratio()


def extract_filename(path: str) -> str:
    """Return just the filename from a Windows-style path."""
    return Path(path.replace("\\", "/")).name


def _values_from_data_list(data_list: list, keys: set) -> List[str]:
    """Extract values from EventData.Data when it is a list of dicts."""
    values: List[str] = []
    for item in data_list:
        if isinstance(item, dict):
            name = item.get("@Name", "")
            text = item.get("#text", "")
            if name in keys and text and text != "-":
                values.append(text)
    return values


def _values_from_data_dict(data_dict: dict, keys: set) -> List[str]:
    """Extract values from EventData.Data when it is a single dict (or EventData itself)."""
    values: List[str] = []
    for key in keys:
        val = data_dict.get(key)
        if val and isinstance(val, str) and val != "-":
            values.append(val)
    return values


def _is_command_noise(text: str) -> bool:
    """True for PowerShell module/cmdletization *source* lines captured by EID
    4103/4104 ScriptBlock logging on module load — module source, not an executed
    command. Keeps real commands (incl. obfuscated attack payloads, which carry no
    declaration markers) while dropping the generated-cmdlet-definition fragments
    that otherwise flood the `commands` evidence field.
    """
    if not text:
        return False
    low = text.lower()
    return any(m in low for m in _COMMAND_NOISE_MARKERS)


def _clean_commands(values) -> List[str]:
    """Drop module-source noise from a list of candidate command strings."""
    return [v for v in values if not _is_command_noise(v)]


def _parse_sql_raw_string(raw: str) -> Dict[str, List[str]]:
    """
    Parse a SQL audit raw string and extract evidence fields.

    Returns dict with keys: accounts, network, commands.
    """
    result: Dict[str, List[str]] = {"accounts": [], "network": [], "commands": []}

    # Key=value pairs
    for match in SQL_KV_RE.finditer(raw):
        key, value = match.group(1), match.group(2).strip()
        if not value:
            continue
        if key in SQL_ACCOUNT_KEYS:
            result["accounts"].append(value)

    # [CLIENT: x.x.x.x] pattern
    for match in SQL_CLIENT_RE.finditer(raw):
        ip = match.group(1)
        if ip and ip not in ("0.0.0.0",):
            result["network"].append(ip)

    # address field in XML additional_information
    for match in re.finditer(r"<address>([\d.]+)</address>", raw):
        ip = match.group(1)
        if ip and ip not in ("0.0.0.0",) and ip not in result["network"]:
            result["network"].append(ip)

    # statement field often contains the SQL command
    stmt_match = re.search(r"^statement:(.+)$", raw, re.MULTILINE)
    if stmt_match:
        stmt = stmt_match.group(1).strip()
        if stmt:
            result["commands"].append(stmt)

    return result


def _valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _iocs_from_text(text: str) -> Dict[str, Set[str]]:
    """Surface network/registry IOCs embedded inside command/script text.

    Adversaries' commands carry IPs (``\\\\127.0.0.1\\ADMIN$``), URLs
    (``bitsadmin ... https://evil/x``), UNC hosts (``sc \\\\fs02\\ create``), and
    registry paths (``reg add HKLM\\...``). The structured parser only files the
    whole command under ``commands``, so the discrete ``network``/``registry``
    fields miss them — which made the ground truth read as "false claims" and,
    more importantly, made the hallucination detector flag a model that
    *correctly* reported such an IOC. We extract them here with high-precision
    patterns only, so nothing not literally present in the text is invented.
    """
    net: Set[str] = set()
    reg: Set[str] = set()
    if not text or not isinstance(text, str):
        return {"network": net, "registry": reg}

    for m in IP_RE.finditer(text):
        ip = m.group(0)
        if _valid_ipv4(ip) and ip != "0.0.0.0":
            net.add(ip)
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;)'\"")
        net.add(url)
        host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].split(":")[0]
        if host:
            net.add(host)
    for m in UNC_HOST_RE.finditer(text):
        host = m.group(1)
        if host and not _valid_ipv4(host):  # IPs already handled above
            net.add(host)
    for m in REG_PATH_RE.finditer(text):
        hive, rest = m.group(1), m.group(2)
        full = (hive + rest).rstrip("\\.,;\"' ")
        reg.add(full)
        canon = _REG_HIVE_EXPAND.get(hive.upper())
        if canon:  # also store HKEY_* long form so GT's notation matches either way
            reg.add((canon + rest).rstrip("\\.,;\"' "))

    return {"network": net, "registry": reg}


# ── Evidence extraction from a single parsed event ─────────────────────────────

def extract_evidence_from_event(event: Dict[str, Any]) -> Dict[str, Set[str]]:
    """
    Extract all evidence fields from a single parsed EVTX event dict.

    Returns a dict of sets: event_ids, processes, accounts, commands, network, registry.
    """
    evidence: Dict[str, Set[str]] = {
        "event_ids": set(),
        "processes": set(),
        "accounts": set(),
        "commands": set(),
        "network": set(),
        "registry": set(),
    }

    evt = event.get("Event", {})
    system = evt.get("System", {})

    # ── Event ID ───────────────────────────────────────────────────────────
    eid = system.get("EventID")
    if isinstance(eid, dict):
        eid_text = eid.get("#text", "")
    elif isinstance(eid, (str, int)):
        eid_text = str(eid)
    else:
        eid_text = ""
    if eid_text:
        evidence["event_ids"].add(str(eid_text))

    # ── EventData ──────────────────────────────────────────────────────────
    event_data = evt.get("EventData")
    data = event_data.get("Data") if isinstance(event_data, dict) else None

    if isinstance(data, list):
        # Format 1: list of dicts  [{@Name: ..., #text: ...}, ...]
        evidence["processes"].update(_values_from_data_list(data, PROCESS_KEYS))
        evidence["accounts"].update(_values_from_data_list(data, ACCOUNT_KEYS))
        evidence["commands"].update(_clean_commands(_values_from_data_list(data, COMMAND_KEYS)))
        evidence["network"].update(_values_from_data_list(data, NETWORK_KEYS))
        evidence["registry"].update(_values_from_data_list(data, REGISTRY_KEYS))

    elif isinstance(data, dict):
        # Format 2: single dict  {SubjectUserName: ..., ...}
        evidence["processes"].update(_values_from_data_dict(data, PROCESS_KEYS))
        evidence["accounts"].update(_values_from_data_dict(data, ACCOUNT_KEYS))
        evidence["commands"].update(_clean_commands(_values_from_data_dict(data, COMMAND_KEYS)))
        evidence["network"].update(_values_from_data_dict(data, NETWORK_KEYS))
        evidence["registry"].update(_values_from_data_dict(data, REGISTRY_KEYS))

    elif isinstance(data, str):
        # Format 3: raw string (SQL audit events)
        sql = _parse_sql_raw_string(data)
        evidence["accounts"].update(sql["accounts"])
        evidence["network"].update(sql["network"])
        evidence["commands"].update(sql["commands"])

    # Also check EventData itself for direct key=value pairs (some providers)
    if isinstance(event_data, dict):
        for key_set, field in [
            (PROCESS_KEYS, "processes"),
            (ACCOUNT_KEYS, "accounts"),
            (COMMAND_KEYS, "commands"),
            (NETWORK_KEYS, "network"),
            (REGISTRY_KEYS, "registry"),
        ]:
            for k in key_set:
                val = event_data.get(k)
                if val and isinstance(val, str) and val != "-":
                    if field == "commands" and _is_command_noise(val):
                        continue
                    evidence[field].add(val)

    # ── UserData ───────────────────────────────────────────────────────────
    # EventLog 1102/104, PrintService and Servicing pack their fields under
    # {"UserData":{"<EventName>":{<field>:<value>,...}}} instead of EventData
    # (the parser now renders these too). Run the same key-sets over each inner
    # element dict so e.g. the log-clear SubjectUserName is captured.
    # Only the typed key-sets run over UserData's structured fields — NOT the
    # free-text IOC scan, which mis-reads names like a printer's "Kiwi Legit
    # Printer" or a bare hostname as network indicators.
    user_data = evt.get("UserData")
    if isinstance(user_data, dict):
        for inner in user_data.values():
            if isinstance(inner, dict):
                evidence["processes"].update(_values_from_data_dict(inner, PROCESS_KEYS))
                evidence["accounts"].update(_values_from_data_dict(inner, ACCOUNT_KEYS))
                evidence["commands"].update(_clean_commands(_values_from_data_dict(inner, COMMAND_KEYS)))
                evidence["network"].update(_values_from_data_dict(inner, NETWORK_KEYS))
                evidence["registry"].update(_values_from_data_dict(inner, REGISTRY_KEYS))

    # Surface IOCs embedded anywhere in the event's text (command args, share
    # names, BITS URLs, reg-add paths, ...) into the discrete network/registry
    # fields (see _iocs_from_text). Scan all event-data strings, not just
    # commands, since the human annotator read the whole event.
    blob: List[str] = list(evidence["commands"])
    if isinstance(data, list):
        blob += [str(it.get("#text", "")) for it in data if isinstance(it, dict)]
    elif isinstance(data, dict):
        blob += [v for v in data.values() if isinstance(v, str)]
    elif isinstance(data, str):
        blob.append(data)
    if isinstance(event_data, dict):
        blob += [v for v in event_data.values() if isinstance(v, str)]
    iocs = _iocs_from_text("\n".join(p for p in blob if p))
    evidence["network"].update(iocs["network"])
    evidence["registry"].update(iocs["registry"])

    return evidence


# ── Phase 1: Schema validation ────────────────────────────────────────────────

REQUIRED_EVIDENCE_FIELDS = {"event_ids", "processes", "accounts", "commands", "network", "registry"}


def validate_schema(gt_data: dict) -> Dict[str, Any]:
    """Validate ground truth JSON against the expected schema."""
    result: Dict[str, Any] = {"pass": True, "issues": []}

    # Metadata checks
    meta = gt_data.get("_metadata", {})
    for key in ("description", "version", "total_files"):
        if key not in meta:
            result["issues"].append(f"_metadata missing '{key}'")
            result["pass"] = False

    files = gt_data.get("files", {})
    for fname, entry in files.items():
        # malicious field
        mal = entry.get("malicious")
        if mal is None:
            result["issues"].append(f"{fname}: missing 'malicious' field")
            result["pass"] = False
        elif not isinstance(mal, str) or mal not in ("YES", "NO"):
            result["issues"].append(f"{fname}: 'malicious' should be 'YES' or 'NO', got {mal!r}")
            result["pass"] = False

        # evidence dict
        ev = entry.get("evidence")
        if ev is None:
            result["issues"].append(f"{fname}: missing 'evidence' dict")
            result["pass"] = False
            continue
        if not isinstance(ev, dict):
            result["issues"].append(f"{fname}: 'evidence' should be a dict, got {type(ev).__name__}")
            result["pass"] = False
            continue

        for field in REQUIRED_EVIDENCE_FIELDS:
            if field not in ev:
                result["issues"].append(f"{fname}: evidence missing '{field}'")
                result["pass"] = False
            elif not isinstance(ev[field], list):
                result["issues"].append(f"{fname}: evidence.{field} should be a list, got {type(ev[field]).__name__}")
                result["pass"] = False

    return result


# ── Phase 2: Cross-reference metadata.json ─────────────────────────────────────

def cross_reference_metadata(gt_data: dict, meta_data: dict) -> Dict[str, Any]:
    """Compare ground truth files against metadata.json."""
    gt_files = set(gt_data.get("files", {}).keys())
    meta_files = set(meta_data.get("files", {}).keys())

    in_meta_not_gt = sorted(meta_files - gt_files)
    in_gt_not_meta = sorted(gt_files - meta_files)

    # Event ID mismatches
    event_id_mismatches = []
    common = gt_files & meta_files
    for fname in sorted(common):
        gt_ids = set(gt_data["files"][fname].get("evidence", {}).get("event_ids", []))
        meta_ids = set(meta_data["files"][fname].get("event_ids", []))
        if gt_ids != meta_ids:
            event_id_mismatches.append({
                "file": fname,
                "ground_truth_ids": sorted(gt_ids),
                "metadata_ids": sorted(meta_ids),
            })

    return {
        "in_metadata_not_ground_truth": in_meta_not_gt,
        "in_ground_truth_not_metadata": in_gt_not_meta,
        "event_id_mismatches": event_id_mismatches,
        "counts": {
            "metadata_only": len(in_meta_not_gt),
            "ground_truth_only": len(in_gt_not_meta),
            "event_id_mismatches": len(event_id_mismatches),
        },
    }


# ── Phase 3 & 4: Read CSV + compare ─────────────────────────────────────────────

def merge_evidence(accumulator: Dict[str, Set[str]], new: Dict[str, Set[str]]) -> None:
    """Merge new evidence sets into accumulator in-place."""
    for field in accumulator:
        accumulator[field].update(new.get(field, set()))


def compare_field_event_ids(claimed: List[str], actual: Set[str]) -> Dict[str, Any]:
    """Exact string match for event IDs."""
    claimed_set = set(claimed)
    confirmed = sorted(claimed_set & actual)
    false_claims = sorted(claimed_set - actual)
    missed = sorted(actual - claimed_set)
    ratio = len(confirmed) / len(claimed_set) if claimed_set else 1.0
    return {
        "claimed": sorted(claimed_set),
        "actual": sorted(actual),
        "confirmed": confirmed,
        "false_claims": false_claims,
        "missed_by_ground_truth": missed,
        "match_ratio": round(ratio, 4),
    }


def compare_field_processes(claimed: List[str], actual: Set[str]) -> Dict[str, Any]:
    """Case-insensitive filename comparison for processes."""
    claimed_names = {extract_filename(p).lower(): p for p in claimed}
    actual_names = {extract_filename(p).lower(): p for p in actual}

    confirmed = []
    false_claims = []
    for name_lower, original in claimed_names.items():
        matched = False
        for act_lower in actual_names:
            if fuzzy_ratio(name_lower, act_lower) >= 0.8:
                matched = True
                break
        if matched:
            confirmed.append(original)
        else:
            false_claims.append(original)

    missed = []
    for act_lower, act_original in actual_names.items():
        found = False
        for cl_lower in claimed_names:
            if fuzzy_ratio(act_lower, cl_lower) >= 0.8:
                found = True
                break
        if not found:
            missed.append(act_original)

    ratio = len(confirmed) / len(claimed_names) if claimed_names else 1.0
    return {
        "claimed": claimed,
        "actual": sorted(actual),
        "confirmed": confirmed,
        "false_claims": false_claims,
        "missed_by_ground_truth": missed,
        "match_ratio": round(ratio, 4),
    }


def compare_field_accounts(claimed: List[str], actual: Set[str]) -> Dict[str, Any]:
    """Case-insensitive + 0.8 fuzzy threshold for accounts."""
    actual_lower = {a.lower(): a for a in actual}
    confirmed = []
    false_claims = []
    for cl in claimed:
        cl_l = cl.lower()
        matched = False
        for al in actual_lower:
            if fuzzy_ratio(cl_l, al) >= 0.8:
                matched = True
                break
        if matched:
            confirmed.append(cl)
        else:
            false_claims.append(cl)

    missed = []
    for al, a_orig in actual_lower.items():
        found = False
        for cl in claimed:
            if fuzzy_ratio(al, cl.lower()) >= 0.8:
                found = True
                break
        if not found:
            missed.append(a_orig)

    ratio = len(confirmed) / len(claimed) if claimed else 1.0
    return {
        "claimed": claimed,
        "actual": sorted(actual),
        "confirmed": confirmed,
        "false_claims": false_claims,
        "missed_by_ground_truth": missed,
        "match_ratio": round(ratio, 4),
    }


def compare_field_commands(claimed: List[str], actual: Set[str]) -> Dict[str, Any]:
    """Substring or 0.6 fuzzy threshold for commands."""
    confirmed = []
    false_claims = []
    for cl in claimed:
        cl_l = cl.lower()
        matched = False
        for act in actual:
            act_l = act.lower()
            if cl_l in act_l or act_l in cl_l or fuzzy_ratio(cl, act) >= 0.6:
                matched = True
                break
        if matched:
            confirmed.append(cl)
        else:
            false_claims.append(cl)

    missed = []
    for act in actual:
        act_l = act.lower()
        found = False
        for cl in claimed:
            cl_l = cl.lower()
            if cl_l in act_l or act_l in cl_l or fuzzy_ratio(act, cl) >= 0.6:
                found = True
                break
        if not found:
            missed.append(act)

    ratio = len(confirmed) / len(claimed) if claimed else 1.0
    return {
        "claimed": [c[:200] for c in claimed],
        "actual": [a[:200] for a in sorted(actual)],
        "confirmed": [c[:200] for c in confirmed],
        "false_claims": [c[:200] for c in false_claims],
        "missed_by_ground_truth": [m[:200] for m in missed],
        "match_ratio": round(ratio, 4),
    }


def compare_field_network(claimed: List[str], actual: Set[str]) -> Dict[str, Any]:
    """Exact match for IPs/network."""
    claimed_set = set(claimed)
    confirmed = sorted(claimed_set & actual)
    false_claims = sorted(claimed_set - actual)
    missed = sorted(actual - claimed_set)
    ratio = len(confirmed) / len(claimed_set) if claimed_set else 1.0
    return {
        "claimed": sorted(claimed_set),
        "actual": sorted(actual),
        "confirmed": confirmed,
        "false_claims": false_claims,
        "missed_by_ground_truth": missed,
        "match_ratio": round(ratio, 4),
    }


def compare_field_registry(claimed: List[str], actual: Set[str]) -> Dict[str, Any]:
    """Substring match on registry paths."""
    confirmed = []
    false_claims = []
    for cl in claimed:
        cl_l = cl.lower()
        matched = any(cl_l in act.lower() or act.lower() in cl_l for act in actual)
        if matched:
            confirmed.append(cl)
        else:
            false_claims.append(cl)

    missed = []
    for act in actual:
        act_l = act.lower()
        found = any(cl.lower() in act_l or act_l in cl.lower() for cl in claimed)
        if not found:
            missed.append(act)

    ratio = len(confirmed) / len(claimed) if claimed else 1.0
    return {
        "claimed": claimed,
        "actual": sorted(actual),
        "confirmed": confirmed,
        "false_claims": false_claims,
        "missed_by_ground_truth": missed,
        "match_ratio": round(ratio, 4),
    }


# ── Main validation logic ──────────────────────────────────────────────────────

def run_validation(
    gt_path: str = "ground_truth_evidence.json",
    meta_path: str = "metadata.json",
    output_path: str = "outputs/ground_truth_validation_report.json",
    verbose: bool = False,
) -> Dict[str, Any]:
    """Run the full 5-phase validation and return the report dict."""

    start_time = datetime.now()

    # ── Load data ──────────────────────────────────────────────────────────
    with open(gt_path, "r", encoding="utf-8") as f:
        gt_data = json.load(f)
    with open(meta_path, "r", encoding="utf-8") as f:
        meta_data = json.load(f)

    gt_files = gt_data.get("files", {})
    meta_files = meta_data.get("files", {})

    # ── Phase 1: Schema validation ─────────────────────────────────────────
    if verbose:
        print("Phase 1: Schema validation...")
    schema_result = validate_schema(gt_data)
    if verbose:
        status = "PASS" if schema_result["pass"] else f"FAIL ({len(schema_result['issues'])} issues)"
        print(f"  Schema: {status}")

    # ── Phase 2: Cross-reference metadata ──────────────────────────────────
    if verbose:
        print("Phase 2: Cross-referencing metadata.json...")
    xref_result = cross_reference_metadata(gt_data, meta_data)
    if verbose:
        c = xref_result["counts"]
        print(f"  Metadata-only files: {c['metadata_only']}")
        print(f"  Ground-truth-only files: {c['ground_truth_only']}")
        print(f"  Event ID mismatches: {c['event_id_mismatches']}")

    # ── Phase 3 & 4: Read CSV files and compare ───────────────────────────
    if verbose:
        print("Phase 3-4: Reading CSV files and comparing evidence...")

    csv_index = build_csv_index()
    file_results: Dict[str, Any] = {}
    parse_failures: List[Dict[str, str]] = []
    all_false_claims: List[Dict[str, Any]] = []
    all_missed: List[Dict[str, Any]] = []

    # Build file list: iterate over ground truth entries
    filenames = list(gt_files.keys())

    for fname in tqdm(filenames, desc="Validating CSV files", disable=not verbose):
        gt_entry = gt_files[fname]
        gt_evidence = gt_entry.get("evidence", {})

        # Resolve the GT entry (keyed by .evtx name) to its CSV by lowercased stem.
        csv_path = resolve_csv(fname, csv_index)

        # ── Read CSV ──────────────────────────────────────────────────────
        actual_evidence: Dict[str, Set[str]] = {
            "event_ids": set(),
            "processes": set(),
            "accounts": set(),
            "commands": set(),
            "network": set(),
            "registry": set(),
        }
        event_count = 0
        parse_error = None

        if csv_path and Path(csv_path).is_file():
            try:
                events = read_csv_events(csv_path)
                event_count = len(events)
                # Aggregate with the shared helper so the result matches the
                # noise-filtered ground truth (no spurious network drift).
                actual_evidence = evidence_from_events(events)
            except (OSError, UnicodeDecodeError, csv.Error, json.JSONDecodeError) as e:
                # A genuine bad/unreadable CSV is a per-file parse failure (does
                # not abort the audit). We deliberately do NOT catch generic
                # Exception: a bug in read_csv_events/evidence_from_events should
                # crash the validator loudly, not be miscounted as a data issue
                # that quietly lowers the quality score.
                parse_error = f"{type(e).__name__}: {e}"
                parse_failures.append({"file": fname, "error": parse_error})
        elif csv_path and not Path(csv_path).is_file():
            parse_error = f"CSV not found: {csv_path}"
            parse_failures.append({"file": fname, "error": parse_error})
        else:
            parse_error = "No CSV for stem"
            parse_failures.append({"file": fname, "error": parse_error})

        # Artifact-text view for the re-anchored false-claim check:
        # a GT value present in the reconstructed XML the model sees is REAL
        # evidence the narrow key-set extractor missed — not a fabrication. We
        # reconstruct lazily (only when the file has any claims to check).
        _artefact_norm = [None]  # boxed for the closure

        def _artefact():
            if _artefact_norm[0] is None and csv_path and Path(csv_path).is_file():
                from forcastl.core.parser import EVTXParser
                from forcastl.core.hallucination import _normalize_artefact
                xml = EVTXParser().format_for_llm_pure_raw_xml(
                    EVTXParser().parse_csv_file(csv_path))
                _artefact_norm[0] = _normalize_artefact(xml)
            return _artefact_norm[0]

        def _drop_artifact_present(field_name: str, fr: Dict[str, Any]) -> None:
            """Move false_claims that ARE in the artifact into confirmed and
            recompute match_ratio (event_ids stay exact-matched)."""
            if field_name == "event_ids" or not fr.get("false_claims"):
                return
            from forcastl.core.hallucination import present_in_artefact
            art = _artefact()
            if not art:
                return
            credited = [c for c in fr["false_claims"] if present_in_artefact(c, art)]
            if not credited:
                return
            fr["false_claims"] = [c for c in fr["false_claims"] if c not in credited]
            fr["confirmed"] = list(fr.get("confirmed", [])) + credited
            denom = len(fr["confirmed"]) + len(fr["false_claims"])
            fr["match_ratio"] = round(len(fr["confirmed"]) / denom, 4) if denom else 1.0

        # ── Compare per field ─────────────────────────────────────────────
        field_results: Dict[str, Any] = {}
        field_results["event_ids"] = compare_field_event_ids(
            gt_evidence.get("event_ids", []), actual_evidence["event_ids"]
        )
        field_results["processes"] = compare_field_processes(
            gt_evidence.get("processes", []), actual_evidence["processes"]
        )
        field_results["accounts"] = compare_field_accounts(
            gt_evidence.get("accounts", []), actual_evidence["accounts"]
        )
        field_results["commands"] = compare_field_commands(
            gt_evidence.get("commands", []), actual_evidence["commands"]
        )
        field_results["network"] = compare_field_network(
            gt_evidence.get("network", []), actual_evidence["network"]
        )
        field_results["registry"] = compare_field_registry(
            gt_evidence.get("registry", []), actual_evidence["registry"]
        )

        # Re-anchor: credit GT values present in the artifact text (real evidence
        # the narrow extractor missed), so a full-inventory GT validates clean.
        for _fn, _fr in field_results.items():
            _drop_artifact_present(_fn, _fr)

        file_results[fname] = {
            "csv_path": csv_path,
            "events_parsed": event_count,
            "parse_error": parse_error,
            "fields": field_results,
        }

        # Aggregate issues
        for field_name, fr in field_results.items():
            if fr["false_claims"]:
                all_false_claims.append({
                    "file": fname,
                    "field": field_name,
                    "false_claims": fr["false_claims"],
                })
            if fr["missed_by_ground_truth"]:
                # Limit missed items to keep report manageable
                missed_items = fr["missed_by_ground_truth"]
                if len(missed_items) > 20:
                    missed_items = missed_items[:20] + [f"... and {len(missed_items) - 20} more"]
                all_missed.append({
                    "file": fname,
                    "field": field_name,
                    "missed": missed_items,
                })

    # ── Phase 5: Build summary ─────────────────────────────────────────────
    if verbose:
        print("Phase 5: Building report...")

    # Per-field accuracy
    field_accuracy: Dict[str, Dict[str, Any]] = {}
    for field_name in REQUIRED_EVIDENCE_FIELDS:
        ratios = []
        total_claimed = 0
        total_confirmed = 0
        total_false = 0
        total_missed = 0
        for fr_data in file_results.values():
            fr = fr_data["fields"].get(field_name, {})
            if fr.get("claimed"):
                ratios.append(fr.get("match_ratio", 0))
                total_claimed += len(fr.get("claimed", []))
                total_confirmed += len(fr.get("confirmed", []))
                total_false += len(fr.get("false_claims", []))
            # Count missed but cap to avoid counting huge lists
            missed = fr.get("missed_by_ground_truth", [])
            total_missed += min(len(missed), 100)

        avg_ratio = sum(ratios) / len(ratios) if ratios else 1.0
        field_accuracy[field_name] = {
            "average_match_ratio": round(avg_ratio, 4),
            "files_with_claims": len(ratios),
            "total_claimed": total_claimed,
            "total_confirmed": total_confirmed,
            "total_false_claims": total_false,
            "total_missed": total_missed,
        }

    # Overall quality score: weighted average of field match ratios
    all_ratios = []
    for fa in field_accuracy.values():
        if fa["files_with_claims"] > 0:
            all_ratios.append(fa["average_match_ratio"])
    quality_score = round(sum(all_ratios) / len(all_ratios) * 100, 2) if all_ratios else 0.0

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    report = {
        "report_metadata": {
            "generated_at": end_time.isoformat(),
            "duration_seconds": round(duration, 1),
            "ground_truth_path": str(gt_path),
            "metadata_path": str(meta_path),
            "ground_truth_files": len(gt_files),
            "metadata_files": len(meta_files),
        },
        "summary": {
            "quality_score": quality_score,
            "total_files_validated": len(file_results),
            "total_parse_failures": len(parse_failures),
            "total_false_claims": sum(len(fc["false_claims"]) for fc in all_false_claims),
            "total_missed_evidence": len(all_missed),
            "field_accuracy": field_accuracy,
        },
        "schema_validation": schema_result,
        "cross_reference": xref_result,
        "file_results": file_results,
        "issues": {
            "false_claims": all_false_claims,
            "missed_evidence": all_missed,
            "parse_failures": parse_failures,
        },
    }

    # ── Write output ───────────────────────────────────────────────────────
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    if verbose:
        print(f"\nValidation complete in {duration:.1f}s")
        print(f"Quality score: {quality_score}%")
        print(f"False claims: {report['summary']['total_false_claims']}")
        print(f"Parse failures: {len(parse_failures)}")
        print(f"Report written to: {out_path}")

    return report
