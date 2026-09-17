"""GT review tooling: packet triage + the validated writer's fabrication guard."""
import csv
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from forcastl.core.csv_evidence import build_csv_index
from forcastl.core.hallucination import _normalize_artefact
from tools.gt_apply_review import validate_corrected
from tools.gt_review_packets import build_packet

_COLS = ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level",
         "Provider", "Channel", "Computer", "Payload"]


def _write_csv(path: Path, payloads):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=_COLS)
        w.writeheader()
        for i, (eid, pl) in enumerate(payloads, 1):
            row = {c: "" for c in _COLS}
            row.update(RecordNumber=str(i), EventId=eid, Channel="Security",
                       Provider="Microsoft-Windows-Security-Auditing",
                       Computer="PYTEST.lan", Payload=json.dumps(pl))
            w.writerow(row)


class ValidateCorrectedTests(unittest.TestCase):
    """The writer accepts only values actually present in the artifact."""

    def setUp(self):
        self.art = _normalize_artefact(
            "<Event><EventData>"
            "<Data Name='NewProcessName'>C:\\Windows\\evil.exe</Data>"
            "<Data Name='IpAddress'>10.0.0.9</Data></EventData></Event>")
        self.ids = {"4688"}

    def test_accepts_present_rejects_absent(self):
        corrected = {
            "event_ids": ["4688", "9999"],          # 9999 not an event id
            "processes": ["C:\\Windows\\evil.exe", "C:\\fake\\nope.exe"],
            "accounts": [], "commands": [],
            "network": ["10.0.0.9", "203.0.113.1"],  # 2nd not in artifact
            "registry": [],
        }
        accepted, rejected = validate_corrected(corrected, self.art, self.ids)
        self.assertEqual(accepted["event_ids"], {"4688"})
        self.assertIn("C:\\Windows\\evil.exe", accepted["processes"])
        self.assertEqual(accepted["network"], {"10.0.0.9"})
        self.assertIn("event_ids: 9999", rejected)
        self.assertIn("processes: C:\\fake\\nope.exe", rejected)
        self.assertIn("network: 203.0.113.1", rejected)


class BuildPacketTests(unittest.TestCase):
    """Under-population is flagged with the artifact-presence signal, even when
    the missing item makes the file a candidate independent of alignment."""

    def test_underpopulation_in_artifact_flagged(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            csv_path = d / "ATTACK-pkt.csv"
            # Real EvtxECmd Payload shape: EventData.Data as {@Name,#text} dicts.
            _write_csv(csv_path, [
                ("4688", {"EventData": {"Data": [
                    {"@Name": "NewProcessName", "#text": "C:\\Windows\\evil.exe"},
                    {"@Name": "SubjectUserName", "#text": "ADMIN"},
                    {"@Name": "IpAddress", "#text": "10.0.0.9"}]}})])
            csv_index = build_csv_index(d)
            # GT expected lists ONLY the event id + account — processes/network missing.
            gt = {"ATTACK-pkt.evtx": {"malicious": "YES", "evidence": {
                "event_ids": ["4688"], "processes": [], "accounts": ["ADMIN"],
                "commands": [], "network": [], "registry": []}}}
            # Model (oracle) reported the real process + IP that GT lacks.
            row = {
                "Filename": "ATTACK-pkt.csv", "Status": "processed", "Alignment %": "100.0",
                "LLM Response": ("MALICIOUS: YES\nEVIDENCE:\n"
                                 "- Event IDs: 4688\n- Processes: C:\\Windows\\evil.exe\n"
                                 "- Accounts: ADMIN\n- Commands: None\n"
                                 "- Network: 10.0.0.9\n- Registry: None\n"
                                 "EXPLANATION:\nx.\n"),
            }
            pkt = build_packet(row, gt, csv_index)
            self.assertIsNotNone(pkt)
            # processes + network under-populated, both present in the artifact.
            proc = pkt["under_population"].get("processes", [])
            net = pkt["under_population"].get("network", [])
            self.assertTrue(any(x["in_artifact"] for x in proc))
            self.assertTrue(any(x["in_artifact"] for x in net))
            # Candidate despite 100% alignment (pure-alignment triage would miss it).
            self.assertIn("under_population", pkt["triage_reasons"])
            self.assertTrue(pkt["is_candidate"])


class GrandfatherBaseTests(unittest.TestCase):
    """A short pre-existing base value (below the artifact-presence length floor)
    is preserved on apply; a genuinely-new value still needs the artifact."""

    def test_existing_short_base_value_kept(self):
        art = _normalize_artefact("<Event><EventData>"
                                  "<Data Name='IpAddress'>10.0.0.9</Data></EventData></Event>")
        # 'dbo' is 3 chars (below the 4-char floor) but already in base → kept.
        corrected = {"event_ids": [], "processes": [], "accounts": ["dbo", "ghost"],
                     "commands": [], "network": ["10.0.0.9"], "registry": []}
        current_base = {"accounts": ["dbo"]}
        accepted, rejected = validate_corrected(corrected, art, set(), current_base)
        self.assertIn("dbo", accepted["accounts"])        # grandfathered
        self.assertEqual(rejected, ["accounts: ghost"])    # new + not in artifact → rejected
        self.assertIn("10.0.0.9", accepted["network"])     # new + in artifact → accepted


if __name__ == "__main__":
    unittest.main()
