"""Tests for core/parser.py — CSV reconstruction and LLM formatting."""
import unittest

from forcastl.core.parser import EVTXParser


class TestCsvRowToXml(unittest.TestCase):
    def setUp(self):
        self.parser = EVTXParser()

    def _make_row(self, **overrides):
        row = {
            "Provider": "Microsoft-Windows-Security-Auditing",
            "EventId": "4688",
            "TimeCreated": "2024-01-01T00:00:00Z",
            "Computer": "WORKSTATION1",
            "Channel": "Security",
        }
        row.update(overrides)
        return row

    def test_basic_reconstruction(self):
        event_data = {"EventData": {"Data": [
            {"@Name": "SubjectUserName", "#text": "admin"},
        ]}}
        xml = self.parser._csv_row_to_xml(self._make_row(), event_data)
        self.assertIn("<EventID>4688</EventID>", xml)
        self.assertIn('Name="Microsoft-Windows-Security-Auditing"', xml)
        self.assertIn("<Computer>WORKSTATION1</Computer>", xml)
        self.assertIn('<Data Name="SubjectUserName">admin</Data>', xml)

    def test_html_special_chars_escaped(self):
        row = self._make_row(Provider='Test&"Provider<>')
        event_data = {"EventData": {"Data": [
            {"@Name": "Command", "#text": "echo <script>alert(1)</script>"},
        ]}}
        xml = self.parser._csv_row_to_xml(row, event_data)
        # Provider goes in attribute (quote=True): & and " must be escaped
        self.assertIn("&amp;", xml)
        # Data text: < and > must be escaped
        self.assertIn("&lt;script&gt;", xml)

    def test_empty_event_data(self):
        event_data = {"EventData": {"Data": []}}
        xml = self.parser._csv_row_to_xml(self._make_row(), event_data)
        self.assertIn("<EventData>", xml)
        self.assertIn("</EventData>", xml)

    def test_no_data_key_emits_empty_eventdata(self):
        """When EventData.Data is missing, get('EventData',{}).get('Data',[]) returns []
        which is still a list, so an empty EventData section is emitted."""
        event_data = {"SomeOtherKey": {}}
        xml = self.parser._csv_row_to_xml(self._make_row(), event_data)
        self.assertIn("<EventData>", xml)
        self.assertIn("</EventData>", xml)
        # But no Data elements inside
        self.assertNotIn("<Data ", xml)

    def test_empty_string_event_data_does_not_crash(self):
        """EvtxECmd emits {"EventData": ""} for fieldless events (some DNS/OCSP
        records). EventData is then a str, not a dict, so .get('Data') would raise
        'str object has no attribute get'. It must degrade to an empty section."""
        event_data = {"EventData": ""}
        xml = self.parser._csv_row_to_xml(self._make_row(), event_data)
        self.assertIn("<EventData>", xml)
        self.assertIn("</EventData>", xml)
        self.assertNotIn("<Data ", xml)

    def test_userdata_reconstructed_when_no_eventdata(self):
        """Microsoft-Windows-EventLog 1102 / PrintService / Servicing pack their
        fields under {"UserData":{"<EventName>":{...}}}, not EventData. Without
        reconstruction these render as an empty <EventData/> and the model sees
        nothing (the log-clear subject, the malicious printer name) — see
        internal/known_issues.md."""
        event_data = {"UserData": {"LogFileCleared": {
            "SubjectUserName": "admmig", "SubjectDomainName": "OFFSEC", "Channel": "System"}}}
        xml = self.parser._csv_row_to_xml(self._make_row(EventId="1102"), event_data)
        self.assertIn("<UserData>", xml)
        self.assertIn("<LogFileCleared>", xml)
        self.assertIn("<SubjectUserName>admmig</SubjectUserName>", xml)
        self.assertIn("<Channel>System</Channel>", xml)

    def test_no_userdata_section_when_absent(self):
        event_data = {"EventData": {"Data": [{"@Name": "X", "#text": "y"}]}}
        xml = self.parser._csv_row_to_xml(self._make_row(), event_data)
        self.assertNotIn("<UserData>", xml)

    def test_missing_row_fields(self):
        row = {"EventId": "1234"}  # Minimal row
        event_data = {"EventData": {"Data": []}}
        xml = self.parser._csv_row_to_xml(row, event_data)
        self.assertIn("<EventID>1234</EventID>", xml)
        # Empty fields should still produce valid XML
        self.assertIn('<Provider Name=""/>', xml)


class TestFormatForLlmPureRawXml(unittest.TestCase):
    def setUp(self):
        self.parser = EVTXParser()

    def test_joins_events_with_double_newline(self):
        events = [
            {"_raw_xml": "<Event>1</Event>"},
            {"_raw_xml": "<Event>2</Event>"},
        ]
        result = self.parser.format_for_llm_pure_raw_xml(events)
        self.assertEqual(result, "<Event>1</Event>\n\n<Event>2</Event>")

    def test_empty_events_list(self):
        result = self.parser.format_for_llm_pure_raw_xml([])
        self.assertEqual(result, "No events found in log file.")

    def test_skips_events_without_raw_xml(self):
        events = [
            {"_raw_xml": "<Event>1</Event>"},
            {"no_xml": True},
            {"_raw_xml": "<Event>3</Event>"},
        ]
        result = self.parser.format_for_llm_pure_raw_xml(events)
        self.assertEqual(result, "<Event>1</Event>\n\n<Event>3</Event>")

    def test_single_event(self):
        events = [{"_raw_xml": "<Event>only</Event>"}]
        result = self.parser.format_for_llm_pure_raw_xml(events)
        self.assertEqual(result, "<Event>only</Event>")

    def test_preserves_raw_xml_content(self):
        raw = '<Event xmlns="http://example.com">\n  <System>\n    <EventID>4688</EventID>\n  </System>\n</Event>'
        events = [{"_raw_xml": raw}]
        result = self.parser.format_for_llm_pure_raw_xml(events)
        self.assertEqual(result, raw)


class TestParseCsvFileFailureModes(unittest.TestCase):
    """A genuine unreadable CSV degrades to [] (file dropped); a bug in
    row→XML reconstruction must propagate, not be masked as a read failure."""

    def setUp(self):
        self.parser = EVTXParser()

    def test_missing_file_degrades_to_empty(self):
        # OSError path: nonexistent file → [] (graceful), not a crash.
        self.assertEqual(self.parser.parse_csv_file("/no/such/file.csv"), [])

    def test_reconstruction_bug_propagates(self):
        from unittest import mock
        import tempfile
        import os
        fd, path = tempfile.mkstemp(suffix=".csv")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write('Payload,EventId,RecordNumber\n"{}",4688,1\n')
            # An unexpected error inside reconstruction must NOT be swallowed as
            # "couldn't read the file".
            with mock.patch.object(self.parser, "_csv_row_to_xml",
                                   side_effect=KeyError("boom")):
                with self.assertRaises(KeyError):
                    self.parser.parse_csv_file(path)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
