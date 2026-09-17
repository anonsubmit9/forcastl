"""F33: build a perturbed copy of the corpus (all 328 CSVs + metadata + GT).

Perturbation = consistent renaming of ENVIRONMENT identity + timestamp shift:
  hosts, domains (DNS + NetBIOS), the domain SID, user/service accounts,
  victim-network IPv4 (10.23.x.y -> 172.19.x.y) and the one IPv6, and all
  timestamps shifted by +611 days. Attacker-authored strings (hacker-proxy.lan,
  command lines, tool names, file names) are left intact: the probe removes
  memorisable environment identity, not evidence. Case is preserved per match
  (ALL-CAPS match -> ALL-CAPS replacement, otherwise lower-case replacement).
The same function perturbs GT, metadata, and saved model responses so the
scoring pipeline can be validated by replay.
"""
import json, re, shutil
from datetime import datetime, timedelta
from pathlib import Path

import os
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
SRC = REPO / "data"
DST = REPO / "work" / "f33_data"  # short path: MAX_PATH
SHIFT = timedelta(days=611)

HOSTS = {  # longest first at apply time
    "fs03vuln": "srv2207", "fs03": "srv1103", "fs01": "srv1101", "fs02": "srv1102",
    "win10-02": "wks4402", "win10-client01": "wks4401", "rootdc1": "dc0901",
    "srvdefender01": "srv0417", "jump01": "srv3308", "pki01": "srv0555", "mssql01": "srv0777",
    "hack-me-pc": "wks4409", "n900b7ffd": "wks7719", "desktop-a8calr3": "wks5525",
    "win-fpv0dsic9o6": "wks6631", "2012r2srv": "srv9012",
}
DOMAINS = {
    "dc=offsec,dc=lan": "DC=corp-nb,DC=example",  # LDAP DN form, before the bare tokens
    "offsec-company": "corpnb-company",
    "offsec.lan": "corp-nb.example", "offsec": "corpnb",
    "sigma.fr": "ex-two.example", "sigma": "extwo",
    "maincorp.local": "mc-three.example", "maincorp": "mcthree",
    "kapsch.co.at": "ex-four.example", "kbceu.kbcnet.tech": "ex-five.example",
}
USERS = {
    "admmig": "j.varela", "hack1": "t.okafor", "lambda-user": "svc-batch02", "hacker2": "m.lindqvist",
    "honey-pot1": "a.petrov", "admmarsid": "r.chen", "test-sql": "qa-sql1", "group02": "grpfin17",
}
SID = ("S-1-5-21-4230534742-2542757381-3142984815", "S-1-5-21-1745239661-903118207-2266114905")
IPV6 = ("fe80::1cae:5aa4:9d8d:106a", "fe80::9b1c:22de:7a01:44f2")

def _case(match_text, repl):
    return repl.upper() if match_text.isupper() and any(c.isalpha() for c in match_text) else repl

# token regexes: word-ish boundaries that still allow a trailing '$' (machine accounts) or '.' (FQDN)
_TOK = {}
for m in (HOSTS, DOMAINS, USERS):
    for k in m:
        _TOK[k] = re.compile(r"(?<![A-Za-z0-9])" + re.escape(k) + r"(?![A-Za-z0-9])", re.I)
ORDER = sorted(list(HOSTS) + list(DOMAINS) + list(USERS), key=len, reverse=True)
REPL = {**HOSTS, **DOMAINS, **USERS}
_IP = re.compile(r"\b10\.23\.(\d{1,3})\.(\d{1,3})\b")
_TS = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})([ T])(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z?)\b")

def _shift_ts(m):
    y, mo, d, sep, hh, mm, ss, frac, z = m.groups()
    try:
        t = datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss)) + SHIFT
    except ValueError:
        return m.group(0)
    return f"{t:%Y-%m-%d}{sep}{t:%H:%M:%S}{frac or ''}{z}"

def perturb(text: str) -> str:
    for k in ORDER:
        text = _TOK[k].sub(lambda m, k=k: _case(m.group(0), REPL[k]), text)
    text = text.replace(SID[0], SID[1]).replace(IPV6[0], IPV6[1])
    text = _IP.sub(lambda m: f"172.19.{m.group(1)}.{m.group(2)}", text)
    text = _TS.sub(_shift_ts, text)
    return text

def perturb_json(obj):
    if isinstance(obj, str): return perturb(obj)
    if isinstance(obj, list): return [perturb_json(x) for x in obj]
    if isinstance(obj, dict): return {k: perturb_json(v) for k, v in obj.items()}  # keys (filenames) untouched
    return obj

if __name__ == "__main__":
    if DST.exists(): shutil.rmtree(DST)
    (DST / "csv").mkdir(parents=True)
    n = 0; changed = 0
    for p in (SRC / "csv").rglob("*.csv"):
        rel = p.relative_to(SRC / "csv"); out = DST / "csv" / rel; out.parent.mkdir(parents=True, exist_ok=True)
        t = p.read_text(encoding="utf-8-sig"); q = perturb(t)
        out.write_text(q, encoding="utf-8"); n += 1; changed += (t != q)
    print(f"csv: {n} files written, {changed} changed")
    for name in ("metadata.json", "ground_truth_evidence.json"):
        obj = json.load(open(SRC / name, encoding="utf-8"))
        json.dump(perturb_json(obj), open(DST / name, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print("wrote", name)
    # residual check: any original identity token left anywhere in the perturbed CSVs?
    residual = {}
    for p in (DST / "csv").rglob("*.csv"):
        t = p.read_text(encoding="utf-8")
        for k in ("offsec", "admmig", "fs03vuln", "rootdc1", "10.23.", SID[0], "2021-11-03"):
            if k.lower() in t.lower(): residual[k] = residual.get(k, 0) + 1
    print("residual original tokens (files):", residual or "none")
