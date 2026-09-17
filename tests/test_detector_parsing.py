from forcastl.core.detector import MaliciousDetector


def test_commands_not_split_on_commas():
    detector = MaliciousDetector(ground_truth_file="missing.json")
    response = """
MALICIOUS: YES

EVIDENCE:
- Event IDs: 4688
- Processes: powershell.exe
- Accounts: OFFSEC\\admmig
- Commands: powershell -Command "[string]((91,78,101,116,46))"
- Network: None
- Registry: None

EXPLANATION:
Suspicious encoded command.
"""
    parsed = detector._parse_structured_response(response)
    assert parsed["evidence"]["commands"] == ['powershell -Command "[string]((91,78,101,116,46))"']


def test_registry_uses_semicolon_as_list_delimiter():
    detector = MaliciousDetector(ground_truth_file="missing.json")
    response = """
MALICIOUS: YES

EVIDENCE:
- Event IDs: 13
- Processes: reg.exe
- Accounts: OFFSEC\\admmig
- Commands: reg add HKLM\\A
- Network: None
- Registry: HKLM\\Path\\One; HKLM\\Path\\Two

EXPLANATION:
Registry modifications detected.
"""
    parsed = detector._parse_structured_response(response)
    assert parsed["evidence"]["registry"] == ["HKLM\\Path\\One", "HKLM\\Path\\Two"]


def test_accounts_strip_trailing_sid_annotation():
    detector = MaliciousDetector(ground_truth_file="missing.json")
    response = """
MALICIOUS: YES

EVIDENCE:
- Event IDs: 4688
- Processes: cmd.exe
- Accounts: admmig (S-1-5-21-4230534742-2542757381-3142984815-1111)
- Commands: whoami
- Network: None
- Registry: None

EXPLANATION:
Suspicious command execution.
"""
    parsed = detector._parse_structured_response(response)
    assert parsed["evidence"]["accounts"] == ["admmig"]


def test_evidence_values_are_deduplicated_case_insensitive():
    detector = MaliciousDetector(ground_truth_file="missing.json")
    response = """
MALICIOUS: YES

EVIDENCE:
- Event IDs: 5600
- Processes: None
- Accounts: None
- Commands: None
- Network: 88.88.88.88, 88.88.88.88, 88.88.88.88
- Registry: None

EXPLANATION:
Repeated network indicator.
"""
    parsed = detector._parse_structured_response(response)
    assert parsed["evidence"]["network"] == ["88.88.88.88"]


def test_accounts_sid_prefix_wrapper_normalized_to_account_name():
    detector = MaliciousDetector(ground_truth_file="missing.json")
    response = """
MALICIOUS: NO

EVIDENCE:
- Event IDs: 4779
- Processes: tscon.exe
- Accounts: S-1-5-21-4230534742-2542757381-3142984815-1111 (admmig)
- Commands: tscon 2 /dest:rdp-tcp#8
- Network: None
- Registry: None

EXPLANATION:
Session change.
"""
    parsed = detector._parse_structured_response(response)
    assert parsed["evidence"]["accounts"] == ["admmig"]


def test_network_wrapper_annotation_removed():
    detector = MaliciousDetector(ground_truth_file="missing.json")
    response = """
MALICIOUS: NO

EVIDENCE:
- Event IDs: 4778
- Processes: None
- Accounts: None
- Commands: None
- Network: 10.23.123.11 (JUMP01), 10.23.123.11 (ClientAddress)
- Registry: None

EXPLANATION:
Connection established.
"""
    parsed = detector._parse_structured_response(response)
    assert parsed["evidence"]["network"] == ["10.23.123.11"]
