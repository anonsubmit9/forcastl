"""Tests for core/detector.py — scoring, hallucination, grading, confidence, and orchestration."""
import pytest

from forcastl.core.detector import MaliciousDetector


# All tests use a detector with no ground truth file (empty dict).
def _det():
    return MaliciousDetector(ground_truth_file="missing.json")


# ── _get_grade ───────────────────────────────────────────────────────────────

def test_grade_a_boundary():
    assert MaliciousDetector._get_grade(17.0) == "A"
    assert MaliciousDetector._get_grade(20.0) == "A"

def test_grade_b_boundary():
    assert MaliciousDetector._get_grade(14.0) == "B"
    assert MaliciousDetector._get_grade(16.9) == "B"

def test_grade_c_boundary():
    assert MaliciousDetector._get_grade(10.0) == "C"
    assert MaliciousDetector._get_grade(13.9) == "C"

def test_grade_d_boundary():
    assert MaliciousDetector._get_grade(9.9) == "D"
    assert MaliciousDetector._get_grade(0.0) == "D"


# ── _determine_malicious ────────────────────────────────────────────────────

def test_determine_malicious_yes():
    d = _det()
    parsed = {"malicious": "YES"}
    assert d._determine_malicious(parsed, "") is True

def test_determine_malicious_no():
    d = _det()
    parsed = {"malicious": "NO"}
    assert d._determine_malicious(parsed, "") is False

def test_determine_malicious_keyword_fallback():
    d = _det()
    parsed = {"malicious": None}
    assert d._determine_malicious(parsed, "This is a malicious attack") is True

def test_determine_malicious_keyword_fallback_benign():
    d = _det()
    parsed = {"malicious": None}
    assert d._determine_malicious(parsed, "Nothing to report.") is False


# ── _calculate_confidence ────────────────────────────────────────────────────

def test_confidence_perfect_structure():
    d = _det()
    parsed = {"malicious": "YES", "explanation": "Long explanation here."}
    validation = {"is_valid": True, "evidence_fields_populated": 4}
    conf = d._calculate_confidence(parsed, validation, True)
    # 50 base + 30 valid + 20 evidence(4*5) + 10 explanation + 10 malicious = 120 → capped 100
    assert conf == 100.0

def test_confidence_minimal():
    d = _det()
    parsed = {"malicious": None, "explanation": None}
    validation = {"is_valid": False, "evidence_fields_populated": 0}
    conf = d._calculate_confidence(parsed, validation, False)
    # 50 base only
    assert conf == 50.0

def test_confidence_partial():
    d = _det()
    parsed = {"malicious": "NO", "explanation": None}
    validation = {"is_valid": False, "evidence_fields_populated": 2}
    conf = d._calculate_confidence(parsed, validation, False)
    # 50 + 0(invalid) + 10(2*5) + 0(no explanation) + 10(malicious present) = 70
    assert conf == 70.0


# ── _clean_response ──────────────────────────────────────────────────────────

def test_clean_removes_markdown_code_blocks():
    d = _det()
    result = d._clean_response("```text\nMALICIOUS: YES\n```")
    assert "```" not in result
    assert "MALICIOUS: YES" in result

def test_clean_removes_bold_markers():
    d = _det()
    result = d._clean_response("**MALICIOUS:** YES")
    assert "**" not in result

def test_clean_normalizes_brackets():
    d = _det()
    result = d._clean_response("MALICIOUS: [yes]")
    assert "MALICIOUS: YES" in result

def test_clean_normalizes_field_names():
    d = _det()
    result = d._clean_response("Process Names: cmd.exe\nAccount Names: admin\nCommand Lines: whoami")
    assert "Processes:" in result
    assert "Accounts:" in result
    assert "Commands:" in result

def test_clean_deduplicates_evidence_sections():
    d = _det()
    result = d._clean_response("EVIDENCE:\n- Event IDs: 1\nEVIDENCE:\n- Event IDs: 2")
    assert result.count("EVIDENCE:") == 1


# ── _validate_structure ──────────────────────────────────────────────────────

def test_validate_valid_structure():
    d = _det()
    parsed = {
        "malicious": "YES",
        "explanation": "Suspicious activity",
        "evidence": {"event_ids": ["4688"], "processes": ["cmd.exe"],
                     "accounts": [], "commands": [], "network": [], "registry": []},
    }
    response = "MALICIOUS: YES\nEVIDENCE:\n- Event IDs: 4688\nEXPLANATION: Suspicious"
    val = d._validate_structure(parsed, response)
    assert val["is_valid"] is True
    assert val["has_malicious_field"] is True
    assert val["has_evidence_section"] is True
    assert val["has_explanation"] is True
    assert val["evidence_fields_populated"] == 2

def test_validate_missing_malicious():
    d = _det()
    parsed = {"malicious": None, "explanation": "test",
              "evidence": {"event_ids": [], "processes": [], "accounts": [],
                           "commands": [], "network": [], "registry": []}}
    val = d._validate_structure(parsed, "EVIDENCE:\nEXPLANATION: test")
    assert val["is_valid"] is False
    assert "Missing MALICIOUS field" in val["issues"]

def test_validate_no_evidence_populated():
    d = _det()
    parsed = {"malicious": "YES", "explanation": "test",
              "evidence": {"event_ids": [], "processes": [], "accounts": [],
                           "commands": [], "network": [], "registry": []}}
    val = d._validate_structure(parsed, "MALICIOUS: YES\nEVIDENCE:\nEXPLANATION: test")
    assert "No evidence fields populated" in val["issues"]


# ── _fuzzy_match ─────────────────────────────────────────────────────────────

def test_fuzzy_match_exact():
    d = _det()
    assert d._fuzzy_match("cmd.exe", "cmd.exe") == 1.0

def test_fuzzy_match_case_insensitive():
    d = _det()
    assert d._fuzzy_match("CMD.EXE", "cmd.exe") == 1.0

def test_fuzzy_match_empty():
    d = _det()
    assert d._fuzzy_match("", "cmd.exe") == 0.0
    assert d._fuzzy_match("cmd.exe", "") == 0.0


# ── _compare_ground_truth_evidence ───────────────────────────────────────────

def test_gt_comparison_full_match():
    d = _det()
    parsed = {
        "malicious": "YES",
        "evidence": {
            "event_ids": ["4688"],
            "processes": ["cmd.exe"],
            "accounts": ["admin"],
            "commands": ["whoami"],
            "network": ["10.0.0.1"],
            "registry": [],
        },
    }
    expected = {
        "malicious": "YES",
        "evidence": {
            "event_ids": ["4688"],
            "processes": ["cmd.exe"],
            "accounts": ["admin"],
            "commands": ["whoami"],
            "network": ["10.0.0.1"],
            "registry": [],
        },
    }
    result = d._compare_ground_truth_evidence(parsed, expected)
    assert result["malicious_match"] is True
    assert result["score"] == 100.0

def test_gt_comparison_malicious_mismatch():
    d = _det()
    parsed = {"malicious": "NO", "evidence": {"event_ids": [], "processes": [],
              "accounts": [], "commands": [], "network": [], "registry": []}}
    expected = {"malicious": "YES", "evidence": {}}
    result = d._compare_ground_truth_evidence(parsed, expected)
    assert result["malicious_match"] is False
    # With no expected evidence fields the alignment score is
    # undefined (the verdict is scored in Interpretation, not here).
    assert result["score"] is None

def test_gt_comparison_empty_gt_fields_skipped():
    """Empty ground truth fields should not count against the LLM."""
    d = _det()
    parsed = {
        "malicious": "YES",
        "evidence": {"event_ids": ["4688"], "processes": ["cmd.exe"],
                     "accounts": [], "commands": [], "network": [], "registry": []},
    }
    expected = {
        "malicious": "YES",
        "evidence": {"event_ids": ["4688"], "processes": [], "accounts": [],
                     "commands": [], "network": [], "registry": []},
    }
    result = d._compare_ground_truth_evidence(parsed, expected)
    # malicious match + event_ids match = 2/2 = 100%
    assert result["score"] == 100.0

def test_gt_comparison_partial_event_ids():
    d = _det()
    parsed = {
        "malicious": "YES",
        "evidence": {"event_ids": ["4688"], "processes": [], "accounts": [],
                     "commands": [], "network": [], "registry": []},
    }
    expected = {
        "malicious": "YES",
        "evidence": {"event_ids": ["4688", "4689"], "processes": [], "accounts": [],
                     "commands": [], "network": [], "registry": []},
    }
    result = d._compare_ground_truth_evidence(parsed, expected)
    # event_ids: 1/2 = 50% which is >= 0.5, so it counts as a match
    assert result["field_matches"]["event_ids"]["score"] == 50.0
    assert result["malicious_match"] is True

def test_gt_comparison_process_fuzzy_match():
    d = _det()
    parsed = {
        "malicious": "YES",
        "evidence": {"event_ids": [], "processes": ["C:\\Windows\\System32\\cmd.exe"],
                     "accounts": [], "commands": [], "network": [], "registry": []},
    }
    expected = {
        "malicious": "YES",
        "evidence": {"event_ids": [], "processes": ["cmd.exe"],
                     "accounts": [], "commands": [], "network": [], "registry": []},
    }
    result = d._compare_ground_truth_evidence(parsed, expected)
    assert result["field_matches"]["processes"]["score"] == 100.0

def test_gt_comparison_command_substring_match():
    d = _det()
    parsed = {
        "malicious": "YES",
        "evidence": {"event_ids": [], "processes": [], "accounts": [],
                     "commands": ["whoami"], "network": [], "registry": []},
    }
    expected = {
        "malicious": "YES",
        "evidence": {"event_ids": [], "processes": [], "accounts": [],
                     "commands": ["C:\\Windows\\system32\\cmd.exe /c whoami"],
                     "network": [], "registry": []},
    }
    result = d._compare_ground_truth_evidence(parsed, expected)
    assert result["field_matches"]["commands"]["score"] == 100.0

def test_gt_comparison_overall_score_is_mean_not_binarised():
    """Earlier code binarised each field at the 50% bar (any field >=50% → full
    match), so a row with three 100%s and two 50%s reported Overall=100%.
    The honest score is the mean of the field percentages: (100+100+100+50+50)/5
    = 80%."""
    d = _det()
    parsed = {
        "malicious": "YES",
        "evidence": {
            "event_ids": ["1"],
            # detected matches one of the two expected basenames (powershell.exe)
            "processes": ["powershell.exe"],
            "accounts": ["OFFSEC\\admmig"],
            "commands": ["fragment of command"],
            "network": [],
            "registry": [],
        },
    }
    expected = {
        "malicious": "YES",
        "evidence": {
            # 100% on event_ids
            "event_ids": ["1"],
            # 50% — only one of two expected processes is matched
            "processes": ["C:\\Windows\\System32\\powershell.exe", "C:\\Windows\\System32\\bar.exe"],
            # 100% on accounts
            "accounts": ["OFFSEC\\admmig"],
            # 50% — only one of two expected commands is substring-matched
            "commands": ["something fragment of command", "totally different other thing"],
            "network": [], "registry": [],
        },
    }
    result = d._compare_ground_truth_evidence(parsed, expected)
    assert result["field_matches"]["event_ids"]["score"] == 100.0
    assert result["field_matches"]["processes"]["score"] == 50.0
    assert result["field_matches"]["accounts"]["score"] == 100.0
    assert result["field_matches"]["commands"]["score"] == 50.0
    # Mean over EVIDENCE fields only (the verdict is no longer
    # folded into this average): (100 + 50 + 100 + 50) / 4 = 75
    assert result["score"] == pytest.approx(75.0)


def test_gt_comparison_below_threshold_field_still_contributes_to_mean():
    """A field that scored, say, 25% used to round to zero under the old
    binarisation. Now it contributes 25 to the mean."""
    d = _det()
    parsed = {
        "malicious": "YES",
        "evidence": {
            "event_ids": ["1"],
            "processes": ["only_one_match"],
            "accounts": [], "commands": [], "network": [], "registry": [],
        },
    }
    expected = {
        "malicious": "YES",
        "evidence": {
            "event_ids": ["1"],
            # 1 of 4 expected matches — 25%, below the 0.5 threshold
            "processes": ["only_one_match", "p2", "p3", "p4"],
            "accounts": [], "commands": [], "network": [], "registry": [],
        },
    }
    result = d._compare_ground_truth_evidence(parsed, expected)
    assert result["field_matches"]["processes"]["score"] == 25.0
    # Mean over evidence fields only: (100 + 25) / 2 = 62.5
    assert result["score"] == pytest.approx(62.5)


def test_gt_comparison_attack_processes_ignored_under_v3():
    """`attack_*` precedence is RETIRED — the FULL inventory (base
    `processes`) is the expected, so a model that cites only one of several
    real processes is credited for recall of that one (not a free 100% from the
    curated attack subset)."""
    d = _det()
    parsed = {
        "malicious": "YES",
        "evidence": {
            "event_ids": [], "processes": ["ntdsutil.exe"],
            "accounts": [], "commands": [], "network": [], "registry": [],
        },
    }
    expected = {
        "malicious": "YES",
        "evidence": {
            "event_ids": [],
            "processes": ["ntdsutil.exe", "SearchFilterHost.exe", "svchost.exe"],
            "attack_processes": ["ntdsutil.exe"],   # present but NO LONGER scored
            "accounts": [], "commands": [], "network": [], "registry": [],
        },
    }
    result = d._compare_ground_truth_evidence(parsed, expected)
    # 1 of 3 base processes matched → 33.3% (attack_* subset is ignored).
    assert result["field_matches"]["processes"]["score"] == pytest.approx(100 / 3)


def test_gt_comparison_legacy_processes_used_when_attack_field_absent():
    """Legacy GT entries (no attack_processes sidecar) still score against
    the `processes` field — additive change, no breaking compat."""
    d = _det()
    parsed = {
        "malicious": "YES",
        "evidence": {
            "event_ids": [], "processes": ["cmd.exe"],
            "accounts": [], "commands": [], "network": [], "registry": [],
        },
    }
    expected = {
        "malicious": "YES",
        "evidence": {
            "event_ids": [], "processes": ["cmd.exe"],
            # no attack_processes — legacy shape
            "accounts": [], "commands": [], "network": [], "registry": [],
        },
    }
    result = d._compare_ground_truth_evidence(parsed, expected)
    assert result["field_matches"]["processes"]["score"] == 100.0


def test_gt_comparison_empty_attack_no_longer_suppresses_base():
    """An empty `attack_processes` (typical on benign files) NO
    LONGER suppresses the real base inventory from scoring — this was the core
    under-population bug. The model is now credited for the real processes it
    read instead of the process check being skipped."""
    d = _det()
    parsed = {
        "malicious": "NO",
        "evidence": {
            "event_ids": [], "processes": ["powershell.exe"],
            "accounts": [], "commands": [], "network": [], "registry": [],
        },
    }
    expected = {
        "malicious": "NO",
        "evidence": {
            "event_ids": [],
            "processes": ["powershell.exe", "explorer.exe"],
            "attack_processes": [],          # empty — but base is now scored
            "accounts": [], "commands": [], "network": [], "registry": [],
        },
    }
    result = d._compare_ground_truth_evidence(parsed, expected)
    # base processes ARE scored now: 1 of 2 matched → 50%.
    assert "processes" in result["field_matches"]
    assert result["field_matches"]["processes"]["score"] == pytest.approx(50.0)


def test_gt_comparison_attack_accounts_and_commands_ignored_under_v3():
    """attack_accounts/attack_commands are likewise ignored — the
    full base inventory is scored for both fields."""
    d = _det()
    parsed = {
        "malicious": "YES",
        "evidence": {
            "event_ids": [], "processes": [],
            "accounts": ["admmig"],
            "commands": ["ntdsutil ifm create full c:\\hacker"],
            "network": [], "registry": [],
        },
    }
    expected = {
        "malicious": "YES",
        "evidence": {
            "event_ids": [], "processes": [],
            "accounts": ["admmig", "ROOTDC1$", "SYSTEM"],
            "attack_accounts": ["admmig"],          # ignored
            "commands": ["ntdsutil ifm create full c:\\hacker", "taskhostw.exe SYSTEM"],
            "attack_commands": ["ntdsutil ifm create full c:\\hacker"],  # ignored
            "network": [], "registry": [],
        },
    }
    result = d._compare_ground_truth_evidence(parsed, expected)
    # accounts: 1 of 3 base = 33.3%; commands: 1 of 2 base = 50%.
    assert result["field_matches"]["accounts"]["score"] == pytest.approx(100 / 3)
    assert result["field_matches"]["commands"]["score"] == pytest.approx(50.0)


def test_gt_comparison_registry_substring_match():
    d = _det()
    parsed = {
        "malicious": "YES",
        "evidence": {"event_ids": [], "processes": [], "accounts": [],
                     "commands": [], "network": [],
                     "registry": ["HKLM\\Software\\Policies\\Microsoft"]},
    }
    expected = {
        "malicious": "YES",
        "evidence": {"event_ids": [], "processes": [], "accounts": [],
                     "commands": [], "network": [],
                     "registry": ["HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services"]},
    }
    result = d._compare_ground_truth_evidence(parsed, expected)
    assert result["field_matches"]["registry"]["score"] == 100.0


# ── _item_in_actual ──────────────────────────────────────────────────────────

def test_item_in_actual_event_id():
    d = _det()
    assert d._item_in_actual("4688", {"4688", "4689"}, "event_ids") is True
    assert d._item_in_actual("9999", {"4688"}, "event_ids") is False

def test_item_in_actual_process_fuzzy():
    d = _det()
    assert d._item_in_actual("cmd.exe", {"C:\\Windows\\System32\\cmd.exe"}, "processes") is True
    assert d._item_in_actual("notepad.exe", {"cmd.exe"}, "processes") is False

def test_item_in_actual_account_fuzzy():
    d = _det()
    assert d._item_in_actual("ADMIN", {"admin"}, "accounts") is True
    assert d._item_in_actual("hacker", {"admin"}, "accounts") is False

def test_item_in_actual_command_substring():
    d = _det()
    assert d._item_in_actual("whoami", {"cmd /c whoami"}, "commands") is True
    assert d._item_in_actual("rm -rf", {"whoami"}, "commands") is False

def test_item_in_actual_network_exact():
    d = _det()
    assert d._item_in_actual("10.0.0.1", {"10.0.0.1"}, "network") is True
    assert d._item_in_actual("10.0.0.2", {"10.0.0.1"}, "network") is False

def test_item_in_actual_registry_substring():
    d = _det()
    assert d._item_in_actual("HKLM\\Software", {"HKLM\\Software\\Key"}, "registry") is True
    assert d._item_in_actual("HKCU\\Other", {"HKLM\\Software"}, "registry") is False

def test_item_in_actual_empty():
    d = _det()
    assert d._item_in_actual("", {"4688"}, "event_ids") is False
    assert d._item_in_actual("4688", set(), "event_ids") is False
    assert d._item_in_actual("4688", None, "event_ids") is False


# ── _detect_hallucinations ───────────────────────────────────────────────────

def test_hallucination_no_sampled_evidence():
    d = _det()
    parsed = {"evidence": {"event_ids": ["4688"], "processes": [], "accounts": [],
                           "commands": [], "network": [], "registry": []}}
    result = d._detect_hallucinations(parsed, None)
    assert result["score"] == 4
    assert result["total_hallucinated"] == 0

def test_hallucination_none_fabricated():
    d = _det()
    parsed = {"evidence": {"event_ids": ["4688"], "processes": ["cmd.exe"],
                           "accounts": [], "commands": [], "network": [], "registry": []}}
    sampled = {"event_ids": {"4688"}, "processes": {"cmd.exe"},
               "accounts": set(), "commands": set(), "network": set(), "registry": set()}
    result = d._detect_hallucinations(parsed, sampled)
    assert result["total_hallucinated"] == 0
    assert result["score"] == 4
    assert result["ratio"] == 0

def test_hallucination_two_fabricated_six_field_denominator():
    """Denominator is the total evidence-field count (6), not the count of
    items the LLM claimed. Two fabricated items → 2/6 ≈ 33%."""
    d = _det()
    parsed = {"evidence": {"event_ids": ["9999"], "processes": ["fake.exe"],
                           "accounts": [], "commands": [], "network": [], "registry": []}}
    sampled = {"event_ids": {"4688"}, "processes": {"cmd.exe"},
               "accounts": set(), "commands": set(), "network": set(), "registry": set()}
    result = d._detect_hallucinations(parsed, sampled)
    assert result["total_hallucinated"] == 2
    assert result["total_claimed"] == 2
    assert result["ratio"] == pytest.approx(2 / 6)
    # score = 4 * (1 - 2/6) = 2.667 → 2.7
    assert result["score"] == 2.7

def test_hallucination_partial_six_field_denominator():
    """One fabricated item out of two claims → 1/6 ≈ 16.67% (the
    denominator stays 6 regardless of how many items the model claimed)."""
    d = _det()
    parsed = {"evidence": {"event_ids": ["4688", "9999"], "processes": [],
                           "accounts": [], "commands": [], "network": [], "registry": []}}
    sampled = {"event_ids": {"4688"}, "processes": set(),
               "accounts": set(), "commands": set(), "network": set(), "registry": set()}
    result = d._detect_hallucinations(parsed, sampled)
    assert result["total_hallucinated"] == 1
    assert result["total_claimed"] == 2
    assert result["ratio"] == pytest.approx(1 / 6)
    # score = 4 * (1 - 1/6) ≈ 3.333 → 3.3
    assert result["score"] == 3.3

def test_hallucination_clipped_at_one():
    """Many fabricated items can exceed 6 (e.g., 10 fabricated IPs) — the
    ratio must clip to 1.0 so it stays within [0,1] / [0%, 100%]."""
    d = _det()
    parsed = {"evidence": {
        "event_ids": [], "processes": [], "accounts": [],
        "commands": [], "network": [f"{i}.{i}.{i}.{i}" for i in range(1, 11)],
        "registry": [],
    }}
    sampled = {
        "event_ids": set(), "processes": set(), "accounts": set(),
        "commands": set(), "network": set(), "registry": set(),
    }
    result = d._detect_hallucinations(parsed, sampled)
    assert result["total_hallucinated"] == 10
    assert result["ratio"] == 1.0
    assert result["score"] == 0.0


# ── Hallucination cross-field fallback ───────────────────────────────────────
# An LLM that correctly identifies an attacker tool from a CommandLine string
# (e.g. "mimikatz.exe" pulled out of `netsh add helper mimikatz.exe`) is doing
# exactly what FORCAST-L should reward — the binary is named in the events,
# even if it never appears as a process that ran. The hallucination score
# should not penalize this.

def test_hallucination_fallback_substring_in_other_field():
    """Process claim found in commands corpus → not hallucinated."""
    d = _det()
    parsed = {"evidence": {
        "event_ids": [], "processes": ["mimikatz.exe"],
        "accounts": [], "commands": [], "network": [], "registry": [],
    }}
    sampled = {
        "event_ids": {"4688"},
        "processes": {"netsh.exe", "cmd.exe"},  # mimikatz.exe NOT directly in process field
        "accounts": set(),
        "commands": {"netsh add helper mimikatz.exe"},  # but it IS in a CommandLine
        "network": set(), "registry": set(),
    }
    result = d._detect_hallucinations(parsed, sampled)
    assert result["total_hallucinated"] == 0
    assert result["hallucinated"]["processes"] == []


def test_hallucination_fallback_short_claim_still_flagged():
    """Short claims (<4 chars) cannot use the substring fallback — too risky.
    A model claiming `cmd` as a process when only longer commands exist must
    still be flagged."""
    d = _det()
    parsed = {"evidence": {
        "event_ids": [], "processes": ["abc"],
        "accounts": [], "commands": [], "network": [], "registry": [],
    }}
    sampled = {
        "event_ids": set(), "processes": set(), "accounts": set(),
        "commands": {"abcdefgh"},  # contains 'abc' substring but claim too short
        "network": set(), "registry": set(),
    }
    result = d._detect_hallucinations(parsed, sampled)
    assert result["total_hallucinated"] == 1


def test_hallucination_fallback_does_not_save_pure_fabrication():
    """A claim that appears NOWHERE in any field must still be flagged."""
    d = _det()
    parsed = {"evidence": {
        "event_ids": [], "processes": ["completely_made_up.exe"],
        "accounts": [], "commands": [], "network": [], "registry": [],
    }}
    sampled = {
        "event_ids": {"4688"}, "processes": {"cmd.exe"},
        "accounts": {"admin"}, "commands": {"whoami /all"},
        "network": {"10.0.0.1"}, "registry": set(),
    }
    result = d._detect_hallucinations(parsed, sampled)
    assert result["total_hallucinated"] == 1
    assert "completely_made_up.exe" in result["hallucinated"]["processes"]


def test_hallucination_fallback_account_via_command_substring():
    """Account name extracted from a command line is also rescued by the
    fallback — same principle, different field."""
    d = _det()
    parsed = {"evidence": {
        "event_ids": [], "processes": [], "accounts": ["honey-pot1"],
        "commands": [], "network": [], "registry": [],
    }}
    sampled = {
        "event_ids": set(), "processes": set(),
        "accounts": {"admmig"},  # honey-pot1 not in account field
        "commands": {"SetSPN -a MSSQLSvc/HACK-ME-PC.offsec.lan offsec\\honey-pot1"},
        "network": set(), "registry": set(),
    }
    result = d._detect_hallucinations(parsed, sampled)
    assert result["total_hallucinated"] == 0


# ── _score_reasoning ─────────────────────────────────────────────────────────

def test_reasoning_full_score():
    d = _det()
    parsed = {
        "explanation": (
            "Event 4688 shows a credential dumping attack that indicates lateral movement. "
            "The attacker used lsass.exe to dump credentials from memory."
        ),
        "evidence": {
            "event_ids": ["4688"],
            "processes": ["lsass.exe"],
            "accounts": [], "commands": [], "network": [], "registry": [],
        },
    }
    validation = {"is_valid": True}
    result = d._score_reasoning(parsed, validation, True)
    assert result["score"] == 4
    assert "substantive" in result["details"]
    assert "evidence-grounded" in result["details"]
    assert "consistent" in result["details"]
    assert "domain-aware" in result["details"]

def test_reasoning_zero_score():
    d = _det()
    parsed = {"explanation": "bad", "evidence": {"event_ids": [], "processes": [],
              "accounts": [], "commands": [], "network": [], "registry": []}}
    validation = {"is_valid": False}
    result = d._score_reasoning(parsed, validation, True)
    assert result["score"] == 0

def test_reasoning_substance_needs_50_chars():
    d = _det()
    short = "x" * 49
    long = "x" * 50
    parsed_short = {"explanation": short, "evidence": {"event_ids": [], "processes": [],
                    "accounts": [], "commands": [], "network": [], "registry": []}}
    parsed_long = {"explanation": long, "evidence": {"event_ids": [], "processes": [],
                   "accounts": [], "commands": [], "network": [], "registry": []}}
    r1 = d._score_reasoning(parsed_short, {}, True)
    r2 = d._score_reasoning(parsed_long, {}, True)
    assert "substantive" not in r1["details"]
    assert "substantive" in r2["details"]

def test_reasoning_consistency_malicious():
    d = _det()
    parsed = {"explanation": "This is a malicious attack on the system and is very long text to pass substance check",
              "evidence": {"event_ids": [], "processes": [], "accounts": [],
                           "commands": [], "network": [], "registry": []}}
    result = d._score_reasoning(parsed, {}, True)
    assert "consistent" in result["details"]

def test_reasoning_consistency_benign():
    d = _det()
    parsed = {"explanation": "This is a legitimate normal operation on the system which is perfectly fine and expected behavior",
              "evidence": {"event_ids": [], "processes": [], "accounts": [],
                           "commands": [], "network": [], "registry": []}}
    result = d._score_reasoning(parsed, {}, False)
    assert "consistent" in result["details"]

def test_reasoning_inconsistent_malicious_says_benign():
    d = _det()
    parsed = {"explanation": "This is legitimate normal activity nothing suspicious here at all very long text",
              "evidence": {"event_ids": [], "processes": [], "accounts": [],
                           "commands": [], "network": [], "registry": []}}
    result = d._score_reasoning(parsed, {}, True)
    assert "consistent" not in result["details"]


# ── _compute_score_breakdown ─────────────────────────────────────────────────

def test_score_breakdown_perfect():
    d = _det()
    alignment = {"score": 100.0}
    hallucination = {"score": 4}
    reasoning = {"score": 4, "details": ["substantive", "evidence-grounded", "consistent", "domain-aware"]}
    validation = {"is_valid": True, "evidence_fields_populated": 4}
    parsed = {"malicious": "YES"}
    result = d._compute_score_breakdown(alignment, hallucination, reasoning, validation, parsed, True, "YES")
    assert result["extraction"] == 6.0
    assert result["interpretation"] == 6.0
    assert result["hallucination"] == 4
    assert result["reasoning"] == 4
    assert result["total"] == 20.0
    assert result["grade"] == "A"

def test_score_breakdown_no_ground_truth():
    d = _det()
    hallucination = {"score": 4}
    reasoning = {"score": 2, "details": ["substantive", "evidence-grounded"]}
    validation = {"is_valid": True, "evidence_fields_populated": 3}
    parsed = {"malicious": "YES"}
    # No alignment, no expected_malicious
    result = d._compute_score_breakdown(None, hallucination, reasoning, validation, parsed, True, None)
    # extraction heuristic: 2 (valid) + 3 (evidence fields) = 5
    assert result["extraction"] == 5.0
    # interpretation: 2 (partial, no GT) + 1 (>= 2 fields) = 3
    assert result["interpretation"] == 3.0

def test_score_breakdown_classification_mismatch():
    d = _det()
    alignment = {"score": 80.0}
    hallucination = {"score": 4}
    reasoning = {"score": 2, "details": ["substantive", "evidence-grounded"]}
    validation = {"is_valid": True, "evidence_fields_populated": 3}
    parsed = {"malicious": "NO"}
    # LLM said NO but ground truth is YES — classification mismatch
    result = d._compute_score_breakdown(alignment, hallucination, reasoning, validation, parsed, False, "YES")
    # extraction: 6 * 80/100 = 4.8
    assert result["extraction"] == 4.8
    # interpretation: 0 (mismatch) + 1 (>= 2 fields) + 0 (no consistent in details) = 1
    assert result["interpretation"] == 1.0

def test_score_breakdown_interpretation_capped_at_6():
    d = _det()
    alignment = {"score": 100.0}
    hallucination = {"score": 4}
    reasoning = {"score": 4, "details": ["substantive", "evidence-grounded", "consistent", "domain-aware"]}
    validation = {"is_valid": True, "evidence_fields_populated": 6}
    parsed = {"malicious": "YES"}
    result = d._compute_score_breakdown(alignment, hallucination, reasoning, validation, parsed, True, "YES")
    assert result["interpretation"] <= 6.0


# ── Full detect() orchestration ──────────────────────────────────────────────

def test_detect_full_response():
    d = _det()
    response = (
        "MALICIOUS: YES\n\n"
        "EVIDENCE:\n"
        "- Event IDs: 4688\n"
        "- Processes: cmd.exe\n"
        "- Accounts: admin\n"
        "- Commands: whoami\n"
        "- Network: 10.0.0.1\n"
        "- Registry: None\n\n"
        "EXPLANATION:\n"
        "This indicates a credential dumping attack. The attacker used cmd.exe "
        "to execute whoami, suggesting reconnaissance activity."
    )
    sampled = {
        "event_ids": {"4688"},
        "processes": {"cmd.exe"},
        "accounts": {"admin"},
        "commands": {"whoami"},
        "network": {"10.0.0.1"},
        "registry": set(),
    }
    result = d.detect(response, "test.evtx", sampled_evidence=sampled)
    assert result["is_malicious"] is True
    assert result["confidence"] == 100.0
    assert result["validation"]["is_valid"] is True
    assert result["hallucination"]["total_hallucinated"] == 0
    assert result["score_breakdown"]["total"] > 0
    assert result["score_breakdown"]["grade"] in ("A", "B", "C", "D")

def test_detect_benign_response():
    d = _det()
    response = (
        "MALICIOUS: NO\n\n"
        "EVIDENCE:\n"
        "- Event IDs: 4624\n"
        "- Processes: None\n"
        "- Accounts: SYSTEM\n"
        "- Commands: None\n"
        "- Network: None\n"
        "- Registry: None\n\n"
        "EXPLANATION:\n"
        "This is a routine login event with no indication of malicious activity."
    )
    result = d.detect(response, "test.evtx")
    assert result["is_malicious"] is False
    assert result["parsed"]["malicious"] == "NO"

def test_detect_with_markdown_wrapping():
    d = _det()
    response = (
        "```text\n"
        "**MALICIOUS:** [YES]\n\n"
        "EVIDENCE:\n"
        "- Event IDs: 4688\n"
        "- Processes: cmd.exe\n"
        "- Accounts: admin\n"
        "- Commands: whoami\n"
        "- Network: None\n"
        "- Registry: None\n\n"
        "EXPLANATION:\n"
        "Suspicious activity detected.\n"
        "```"
    )
    result = d.detect(response, "test.evtx")
    assert result["is_malicious"] is True
    assert result["parsed"]["malicious"] == "YES"
    assert "cmd.exe" in result["parsed"]["evidence"]["processes"]


def test_clean_response_normalizes_field_name_at_line_start():
    """Field name normalization works when the variant is at line start (no bullet prefix)."""
    d = _det()
    response = (
        "MALICIOUS: YES\n\n"
        "EVIDENCE:\n"
        "Event IDs: 4688\n"
        "Process Names: cmd.exe\n"
        "Account Names: admin\n"
        "Command Lines: whoami\n"
        "Network: None\n"
        "Registry: None\n\n"
        "EXPLANATION:\n"
        "Suspicious activity.\n"
    )
    result = d.detect(response, "test.evtx")
    assert "cmd.exe" in result["parsed"]["evidence"]["processes"]
    assert "admin" in result["parsed"]["evidence"]["accounts"]


# ── benign .csv ground-truth resolution (false-positive misclassification) ────

def _benign_gt():
    return {
        "BENIGN-X.evtx": {
            "malicious": "NO",
            "evidence": {"event_ids": ["4624"], "processes": [], "accounts": ["SYSTEM"],
                         "commands": [], "network": [], "registry": []},
        }
    }


def test_benign_csv_filename_resolves_gt_and_flags_false_positive():
    """A benign control reaches scoring as `.csv` but is keyed `.evtx` in GT.
    Without the fallback it gets no alignment, so a false positive (benign
    flagged malicious) is never surfaced as a misclassification."""
    d = _det()
    d.ground_truth_data = _benign_gt()
    response = (
        "MALICIOUS: YES\n\nEVIDENCE:\n- Event IDs: 4624\n- Processes: None\n"
        "- Accounts: SYSTEM\n- Commands: None\n- Network: None\n- Registry: None\n\n"
        "EXPLANATION:\nFlagged as malicious."
    )
    result = d.detect(response, filename="BENIGN-X.csv")
    assert result["alignment"] is not None              # GT resolved via fallback
    assert result["alignment"]["malicious_match"] is False  # FP -> misclassification


def test_benign_csv_correct_verdict_matches():
    d = _det()
    d.ground_truth_data = _benign_gt()
    response = (
        "MALICIOUS: NO\n\nEVIDENCE:\n- Event IDs: 4624\n- Processes: None\n"
        "- Accounts: SYSTEM\n- Commands: None\n- Network: None\n- Registry: None\n\n"
        "EXPLANATION:\nRoutine login."
    )
    result = d.detect(response, filename="BENIGN-X.csv")
    assert result["alignment"] is not None
    assert result["alignment"]["malicious_match"] is True
