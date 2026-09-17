"""Hallucination check: a model claim is only a fabrication if it is absent from
the artefact the model was actually shown (not merely from the narrow extracted
evidence). Covers the artefact-text fallback added so honest reads of the
<Computer> host / TaskContent commands aren't scored as hallucinations."""
import unittest

from forcastl.core.hallucination import detect_hallucinations

FIELDS = ("event_ids", "processes", "accounts", "commands", "network", "registry")


def _parsed(**fields):
    return {"evidence": {f: fields.get(f, []) for f in FIELDS}}


def _sampled(**fields):
    return {f: set(fields.get(f, [])) for f in FIELDS}


ARTEFACT = (
    '<Event><System><Computer>win10-admin.offsec.lan</Computer></System>'
    '<EventData><Data Name="CommandLine">net.exe group "Domain Admins" /domain</Data>'
    '</EventData></Event>'
)


class TestHallucinationArtefactFallback(unittest.TestCase):
    def setUp(self):
        # Extraction did NOT surface the <Computer> host into network.
        self.sampled = _sampled(event_ids=["1"])

    def test_host_in_artefact_not_flagged(self):
        # Model reports the Computer host as a network indicator — it IS in the
        # artefact, so it must not be scored as a fabrication.
        r = detect_hallucinations(_parsed(network=["win10-admin.offsec.lan"]),
                                  self.sampled, artefact_text=ARTEFACT)
        self.assertEqual(r["hallucinated"]["network"], [])
        self.assertEqual(r["total_hallucinated"], 0)

    def test_real_fabrication_still_flagged(self):
        r = detect_hallucinations(_parsed(network=["evil-c2.attacker.com"]),
                                  self.sampled, artefact_text=ARTEFACT)
        self.assertEqual(r["hallucinated"]["network"], ["evil-c2.attacker.com"])
        self.assertEqual(r["total_hallucinated"], 1)

    def test_backward_compatible_without_artefact_text(self):
        # No artefact_text -> prior behaviour (host flagged), so the param is
        # purely additive.
        r = detect_hallucinations(_parsed(network=["win10-admin.offsec.lan"]),
                                  self.sampled)
        self.assertEqual(r["hallucinated"]["network"], ["win10-admin.offsec.lan"])

    def test_event_ids_never_credited_by_substring(self):
        # A fabricated event_id that happens to be a substring of a GUID in the
        # artefact must still be flagged (event_ids stay exact-matched).
        artefact = "<Event><ProcessGuid>{1234-4624-aabb}</ProcessGuid></Event>"
        r = detect_hallucinations(_parsed(event_ids=["4624"]),
                                  _sampled(event_ids=["1"]), artefact_text=artefact)
        self.assertEqual(r["hallucinated"]["event_ids"], ["4624"])

    def test_comma_joined_real_values_not_flagged(self):
        # The model packs several real evidence values into one field entry
        # (", "-joined). The joined string is not a verbatim substring, but every
        # part is present, so it is an enumeration, not a fabrication.
        artefact = ('<Event><EventData>'
                    '<Data Name="ImagePath">C:\\TOOLS\\mimidrv.sys</Data>'
                    '<Data Name="ImagePath">\\SystemRoot\\system32\\DRIVERS\\npcap.sys</Data>'
                    '</EventData></Event>')
        r = detect_hallucinations(
            _parsed(processes=["C:\\TOOLS\\mimidrv.sys, \\SystemRoot\\system32\\DRIVERS\\npcap.sys"]),
            _sampled(event_ids=["1"]), artefact_text=artefact)
        self.assertEqual(r["hallucinated"]["processes"], [])

    def test_comma_joined_with_one_fabricated_part_still_flagged(self):
        # If even one comma-separated part is absent (a transcription near-miss or
        # an invented value), the joined claim stays flagged — the credit is
        # all-or-nothing across parts.
        artefact = '<Event><EventData><Data Name="ImagePath">C:\\TOOLS\\mimidrv.sys</Data></EventData></Event>'
        r = detect_hallucinations(
            _parsed(processes=["C:\\TOOLS\\mimidrv.sys, C:\\fake\\invented.exe"]),
            _sampled(event_ids=["1"]), artefact_text=artefact)
        self.assertEqual(len(r["hallucinated"]["processes"]), 1)

    def test_escaped_taskcontent_command_credited(self):
        # A command verbatim inside an HTML-escaped TaskContent blob is credited
        # after unescape+normalize.
        artefact = ('<Data Name="TaskContent">&lt;Exec&gt;&lt;Command&gt;'
                    'C:\\Windows\\System32\\certutil.exe -hashfile x&lt;/Command&gt;</Data>')
        r = detect_hallucinations(
            _parsed(commands=["C:\\Windows\\System32\\certutil.exe -hashfile x"]),
            _sampled(event_ids=["1"]), artefact_text=artefact)
        self.assertEqual(r["hallucinated"]["commands"], [])


class TestScheduledTaskAndPlaceholders(unittest.TestCase):
    """Scheduled-task commands are HTML-escaped and split across <Command>/<Arguments>
    elements; the artefact normaliser must unescape + strip tags so a model's clean
    read matches. Empty-field markers ("-") are non-answers, never fabrications."""

    def test_command_split_across_command_and_arguments_tags(self):
        # As EvtxECmd stores it: HTML-escaped TaskContent XML, command in <Command>,
        # args in <Arguments> — the model reports the combined "exe args".
        artefact = (
            "&lt;Task&gt;&lt;Actions&gt;&lt;Exec&gt;"
            "&lt;Command&gt;%windir%\\system32\\usoclient.exe&lt;/Command&gt;"
            "&lt;Arguments&gt;StartInstall&lt;/Arguments&gt;"
            "&lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;"
        )
        r = detect_hallucinations(
            _parsed(commands=["%windir%\\system32\\usoclient.exe StartInstall"]),
            _sampled(event_ids=["1"]), artefact_text=artefact)
        self.assertEqual(r["hallucinated"]["commands"], [])

    def test_angle_bracket_value_not_stripped(self):
        """A value that *looks* like a tag (a proxy bypass <local>) is in the artefact
        and must not be flagged just because tag-stripping would remove it."""
        artefact = "Payload: ProxyServer = http://internal.lan;&lt;local&gt;"
        r = detect_hallucinations(
            _parsed(network=["<local>", "http://internal.lan;<local>"]),
            _sampled(event_ids=["1"]), artefact_text=artefact)
        self.assertEqual(r["hallucinated"]["network"], [])

    def test_placeholder_marker_not_a_claim(self):
        r = detect_hallucinations(
            _parsed(processes=["-"]),
            _sampled(event_ids=["1"]), artefact_text="<Event/>")
        self.assertEqual(r["hallucinated"]["processes"], [])
        self.assertEqual(r["total_claimed"], 0)      # "-" is not counted as a claim
        self.assertEqual(r["total_hallucinated"], 0)


class DecodedIocAllowlistTests(unittest.TestCase):
    """A decoded payload IOC (present only ENCODED in the artefact) is credited
    when listed in the curated decoded_iocs allowlist, but only for that file."""

    # Artefact contains the IOC only as char codes, not as the plaintext URL.
    ENCODED = "<Event><EventData><Data>104,116,116,112,115</Data></EventData></Event>"
    DECODED = ["https://10.23.123.11:443/Invoke-Mimikatz.ps1", "10.23.123.11"]

    def test_decoded_ioc_credited(self):
        r = detect_hallucinations(
            _parsed(network=["https://10.23.123.11:443/Invoke-Mimikatz.ps1"]),
            _sampled(event_ids=["1"]),
            artefact_text=self.ENCODED, decoded_iocs=self.DECODED)
        self.assertEqual(r["hallucinated"]["network"], [])

    def test_decoded_ioc_substring_both_directions(self):
        # A model reporting just the bare IP matches the fuller listed URL.
        r = detect_hallucinations(
            _parsed(network=["10.23.123.11"]),
            _sampled(event_ids=["1"]),
            artefact_text=self.ENCODED, decoded_iocs=self.DECODED)
        self.assertEqual(r["hallucinated"]["network"], [])

    def test_allowlist_does_not_credit_other_fabrications(self):
        r = detect_hallucinations(
            _parsed(network=["10.23.123.11", "203.0.113.9"]),
            _sampled(event_ids=["1"]),
            artefact_text=self.ENCODED, decoded_iocs=self.DECODED)
        self.assertEqual(r["hallucinated"]["network"], ["203.0.113.9"])

    def test_no_allowlist_still_flags(self):
        # Same encoded artefact, no allowlist -> the plaintext IOC is a fabrication.
        r = detect_hallucinations(
            _parsed(network=["10.23.123.11"]),
            _sampled(event_ids=["1"]), artefact_text=self.ENCODED)
        self.assertEqual(r["hallucinated"]["network"], ["10.23.123.11"])

    def test_event_ids_never_credited_by_allowlist(self):
        # event_ids stay exact-matched even if someone lists one in decoded_iocs.
        r = detect_hallucinations(
            _parsed(event_ids=["9999"]),
            _sampled(event_ids=["1"]),
            artefact_text=self.ENCODED, decoded_iocs=["9999"])
        self.assertEqual(r["hallucinated"]["event_ids"], ["9999"])


if __name__ == "__main__":
    unittest.main()
