#!/usr/bin/env python3
"""Curate single-technique benign slices from converted evtx-baseline CSVs and
batch-ingest them as benign corpus entries (source=evtx-baseline).

Reads the staged EvtxECmd CSVs in data/_import_staging/, carves out one small,
single-technique slice per benign scenario (real rows, so format parity is
automatic), writes each under data/csv/_benign/BENIGN-*.csv, and ingests them via
tools.add_sample's exact entry-building — but with the per-file validator patched
off so the whole-corpus validation runs ONCE at the end instead of per slice.

    python -m tools.curate_benign_baseline            # dry-run: list planned slices
    python -m tools.curate_benign_baseline --apply
"""
from __future__ import annotations

import argparse
import csv as _csv
import io
import json
import re
import sys
from pathlib import Path

from forcastl.core.csv_evidence import DEFAULT_CSV_DIR

STAGING = Path("data/_import_staging")
BENIGN = Path(DEFAULT_CSV_DIR) / "_benign"
COLS = None  # set from the first staged CSV header


def _read(name):
    p = STAGING / name
    rows = list(_csv.DictReader(p.read_text(encoding="utf-8-sig", errors="replace").splitlines()))
    return rows, (list(rows[0].keys()) if rows else [])


def _payload(r):
    try:
        return {x["@Name"]: x["#text"] for x in json.loads(r["Payload"])["EventData"]["Data"]}
    except Exception:
        return {}


def _base(p):
    return (p or "").split("\\")[-1].lower()


def _slug(s, n=48):
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower()
    return s[:n] or "x"


def _write_slice(name, header, rows):
    """Write a benign slice CSV (header + chosen rows) in EvtxECmd format."""
    out = BENIGN / f"{name}.csv"
    buf = io.StringIO()
    w = _csv.DictWriter(buf, fieldnames=header)
    w.writeheader()
    for r in rows:
        w.writerow({c: r.get(c, "") for c in header})
    out.write_text(buf.getvalue(), encoding="utf-8-sig")
    return out


# ── Scenario builders: each yields (filename, [rows], keywords) ───────────────
ADMIN_TOOLS = {"net.exe", "net1.exe", "reg.exe", "sc.exe", "wmic.exe", "powershell.exe", "pwsh.exe",
               "schtasks.exe", "dsadd.exe", "dsquery.exe", "nltest.exe", "whoami.exe", "klist.exe",
               "query.exe", "tasklist.exe", "netsh.exe", "bcdedit.exe", "vssadmin.exe", "wevtutil.exe",
               "gpupdate.exe", "gpresult.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe",
               "regsvr32.exe", "mmc.exe", "icacls.exe", "takeown.exe", "fsutil.exe", "dism.exe",
               "auditpol.exe", "sqlcmd.exe", "arp.exe", "route.exe", "systeminfo.exe", "quser.exe"}


def process_slices(header, max_n):
    """Distinct admin-tool process-creation near-misses (one event each)."""
    seen = {}
    for src in ("ad-sysmon.csv", "client-sysmon.csv"):
        rows, _ = _read(src)
        for r in rows:
            if r.get("EventId") != "1":
                continue
            d = _payload(r)
            img = _base(d.get("Image", ""))
            if img not in ADMIN_TOOLS:
                continue
            cmd = (d.get("CommandLine", "") or "")
            toks = cmd.split()
            action = _slug(toks[1]) if len(toks) > 1 else "run"
            key = (img, action)
            if key in seen:
                continue
            tool = img[:-4]
            seen[key] = (f"BENIGN-ID1-{tool}-{action}", [r],
                         [tool, action.replace("-", " "), "admin", "benign"])
            if len(seen) >= max_n:
                break
    return list(seen.values())


def logon_slices(header):
    """One 4624 slice per distinct LogonType."""
    rows, _ = _read("ad-security.csv")
    by_type = {}
    names = {"2": "interactive", "3": "network", "4": "batch", "5": "service",
             "7": "unlock", "8": "networkcleartext", "9": "newcredentials",
             "10": "remoteinteractive-rdp", "11": "cachedinteractive"}
    out = []
    for r in rows:
        if r.get("EventId") != "4624":
            continue
        lt = _payload(r).get("LogonType", "")
        if not lt or lt == "-" or lt in by_type:
            continue
        by_type[lt] = r
        label = names.get(lt, f"type{lt}")
        out.append((f"BENIGN-ID4624-{label}-logon", [r], ["logon", label, "benign"]))
    return out


_REG_INTEREST = ("\\run", "\\services\\", "\\lsa", "\\winlogon", "\\policies\\",
                 "image file execution", "\\firewall", "windows defender", "\\audit",
                 "\\schedule", "\\netsh", "currentversion\\runonce", "\\appinit")


def _stream(name):
    with open(STAGING / name, encoding="utf-8-sig", errors="replace", newline="") as fh:
        yield from _csv.DictReader(fh)


def registry_slices(header, max_n):
    """Distinct benign registry SetValue (Sysmon 13) near-misses — prioritise
    security-relevant hives (Run/Services/Lsa/Policies/Defender), then fill with
    other distinct keys; mirrors malicious registry persistence."""
    seen, out, generic = set(), [], []
    for src in ("ad-sysmon.csv", "client-sysmon.csv"):
        for r in _stream(src):
            if r.get("EventId") != "13":
                continue
            tobj = _payload(r).get("TargetObject", "")
            low = tobj.lower()
            # scenario key = the key path minus the trailing value name
            key = "\\".join(tobj.split("\\")[:-1]).lower()
            if not key or key in seen:
                continue
            seen.add(key)
            interesting = any(t in low for t in _REG_INTEREST)
            tail = _slug("-".join(tobj.split("\\")[-3:]))
            rec = (f"BENIGN-ID13-reg-{tail}", [r], ["registry", "setvalue", "config", "benign"])
            (out if interesting else generic).append(rec)
            if len(out) >= max_n:
                break
        if len(out) >= max_n:
            break
    # top up with generic distinct registry configs if needed
    for rec in generic:
        if len(out) >= max_n:
            break
        out.append(rec)
    return out


def file_slices(header, max_n):
    """Distinct benign file-create (Sysmon 11) near-misses, keyed by folder+ext —
    installs, startup folder, temp; mirrors malicious file drops."""
    seen, out = set(), []
    for src in ("client-sysmon.csv", "ad-sysmon.csv"):
        for r in _stream(src):
            if r.get("EventId") != "11":
                continue
            tf = _payload(r).get("TargetFilename", "")
            parts = tf.split("\\")
            folder = parts[-2].lower() if len(parts) > 1 else ""
            ext = parts[-1].split(".")[-1].lower() if "." in parts[-1] else "noext"
            key = (folder, ext)
            if not folder or key in seen:
                continue
            seen.add(key)
            out.append((f"BENIGN-ID11-file-{_slug(folder)}-{ext}", [r],
                        ["file create", folder, ext, "benign"]))
            if len(out) >= max_n:
                break
        if len(out) >= max_n:
            break
    return out


def account_slices(header):
    """Account-management near-misses: create / change / group-add."""
    rows, _ = _read("ad-security.csv")
    picks = {"4720": ("user-created", ["account", "user created", "benign"]),
             "4738": ("user-changed", ["account", "user modified", "benign"]),
             "4728": ("added-to-global-group", ["group", "membership", "benign"]),
             "4732": ("added-to-local-group", ["group", "membership", "benign"]),
             "4672": ("special-privileges-logon", ["privileges", "admin logon", "benign"])}
    out, seen = [], set()
    for r in rows:
        e = r.get("EventId")
        if e in picks and e not in seen:
            seen.add(e)
            desc, kw = picks[e]
            out.append((f"BENIGN-ID{e}-{desc}", [r], kw))
    return out


def powershell_slices(header, max_n):
    """Distinct benign PowerShell script-block (4104) slices, keyed by the leading
    cmdlets so distinct scripts are kept (not collapsed)."""
    rows, _ = _read("client-ps.csv")
    seen, out = set(), []
    for r in rows:
        if r.get("EventId") != "4104":
            continue
        sbt = (_payload(r).get("ScriptBlockText", "") or "").strip()
        if not sbt:
            continue
        # key = first ~4 alnum tokens (captures the distinct command shape)
        toks = re.findall(r"[A-Za-z0-9\-]+", sbt)[:4]
        k = _slug("-".join(toks), 40)
        if not k or k in seen:
            continue
        seen.add(k)
        out.append((f"BENIGN-ID4104-ps-{k}", [r], ["powershell", "scriptblock", "benign"]))
        if len(out) >= max_n:
            break
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--max-process", type=int, default=46)
    ap.add_argument("--max-ps", type=int, default=12)
    ap.add_argument("--max-reg", type=int, default=12)
    ap.add_argument("--max-file", type=int, default=8)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    _, header = _read("ad-security.csv")
    plan = (process_slices(header, args.max_process) + logon_slices(header)
            + account_slices(header) + powershell_slices(header, args.max_ps)
            + registry_slices(header, args.max_reg) + file_slices(header, args.max_file))
    # de-dupe names
    uniq, names = [], set()
    for name, rows, kw in plan:
        if name in names or not rows:
            continue
        names.add(name)
        uniq.append((name, rows, kw))

    print(f"planned benign slices: {len(uniq)}")
    for name, rows, kw in uniq:
        print(f"   {name}  ({len(rows)} ev)  kw={kw}")
    if not args.apply:
        print("\ndry-run. Re-run with --apply to write slices + ingest.")
        return 0

    # write slices
    written = []
    for name, rows, kw in uniq:
        p = _write_slice(name, header, rows)
        written.append((p, kw))

    # batch-ingest with validation patched off; validate once at the end
    import tools.add_sample as A
    from forcastl.validation.ground_truth import run_validation
    from forcastl import config
    real = A.run_validation
    A.run_validation = lambda **k: {"summary": {}}
    try:
        for p, kw in written:
            A.add_sample(str(p), "NO", test_set="D", source="evtx-baseline", keywords=kw)
    finally:
        A.run_validation = real
    print(f"\ningested {len(written)} benign slices. Validating corpus once...")
    s = run_validation(gt_path=str(config.GROUND_TRUTH_FILE), meta_path=str(config.METADATA_FILE),
                       output_path=str(config.OUTPUTS_DIR / "ground_truth_validation_report.json"))["summary"]
    print(f"validator: quality={s.get('quality_score')} false={s.get('total_false_claims')} "
          f"missed={s.get('total_missed_evidence')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
