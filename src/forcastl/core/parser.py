#!/usr/bin/env python3
"""
Artefact Parser Module (CSV-only)

Parses EvtxECmd CSV artefacts into events for LLM analysis. The tool operates on
the CSV corpus only; the binary EVTX is upstream provenance and is never parsed.
The class name ``EVTXParser`` is retained for compatibility.
"""

from typing import List, Dict, Any
from pathlib import Path
import logging
from html import escape


class EVTXParser:
    def __init__(self, verbose=False):
        self.logger = logging.getLogger(__name__)
        self.verbose = verbose

    def parse_csv_file(self, csv_path: str) -> List[Dict[str, Any]]:
        """
        Parse an EvtxECmd CSV file into a list of event dictionaries.

        Args:
            csv_path: Path to the CSV file (EvtxECmd output)

        Returns:
            List of event dictionaries (one per CSV row), each with an `Event`
            tree, `_metadata`, and reconstructed `_raw_xml`.
        """
        import csv
        import json
        all_events: List[Dict[str, Any]] = []
        try:
            with open(csv_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    payload_json = row.get('Payload', '')
                    if not payload_json:
                        continue

                    try:
                        event_data = json.loads(payload_json)
                    except json.JSONDecodeError:
                        continue

                    event_id = row.get('EventId', '0')
                    event_dict = {
                        'Event': {
                            'System': {
                                'EventID': event_id,
                                'TimeCreated': {'@SystemTime': row.get('TimeCreated', '')},
                                'Provider': {'@Name': row.get('Provider', '')},
                                'Computer': row.get('Computer', ''),
                                'Channel': row.get('Channel', ''),
                                'EventRecordID': row.get('EventRecordId', ''),
                            },
                            **event_data  # Merges EventData at Event level
                        },
                        '_metadata': {
                            'record_id': int(row.get('RecordNumber', 0) or 0),
                            'timestamp': row.get('TimeCreated', ''),
                            'source_file': Path(csv_path).stem + '.evtx'
                        },
                        '_raw_xml': self._csv_row_to_xml(row, event_data)
                    }
                    all_events.append(event_dict)
        except (OSError, UnicodeDecodeError, csv.Error) as e:
            # Genuine file-read failure: degrade gracefully (the file lands as a
            # 0-event/error result downstream) but log loudly so a dropped file
            # is visible rather than silently shrinking the corpus. We do NOT
            # catch generic Exception here — a bug in row→XML reconstruction
            # should surface, not be masked as "couldn't read the file".
            self.logger.warning(
                "Could not read CSV %s (%s: %s) — file dropped from this run",
                csv_path, type(e).__name__, e,
            )
            return []

        return all_events

    @staticmethod
    def _normalize_text(text: str) -> str:
        """Normalize possibly-pre-escaped text to a single round of XML escaping.

        EvtxECmd's Payload JSON stores some fields (notably SQL Server audit
        ``additional_information``) with HTML entities already encoded (``&lt;``).
        A plain ``escape()`` would double-encode those to ``&amp;lt;``, leaving
        the LLM to read markup instead of content. Unescape first, then escape
        once so the output has exactly one escape layer regardless of upstream
        encoding.
        """
        from html import unescape
        return escape(unescape(text), quote=False)

    def _csv_row_to_xml(self, row: Dict[str, str], event_data: Dict[str, Any]) -> str:
        """Reconstruct XML event from CSV row for LLM consumption."""
        provider = escape(str(row.get("Provider", "")), quote=True)
        event_id = escape(str(row.get("EventId", "")), quote=False)
        time_created = escape(str(row.get("TimeCreated", "")), quote=True)
        computer = escape(str(row.get("Computer", "")), quote=False)
        channel = escape(str(row.get("Channel", "")), quote=False)

        parts = ['<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">']
        parts.append('  <System>')
        parts.append(f'    <Provider Name="{provider}"/>')
        parts.append(f'    <EventID>{event_id}</EventID>')
        parts.append(f'    <TimeCreated SystemTime="{time_created}"/>')
        parts.append(f'    <Computer>{computer}</Computer>')
        parts.append(f'    <Channel>{channel}</Channel>')
        parts.append('  </System>')

        # Reconstruct EventData from Payload JSON. Data can be:
        #   - a list of {@Name, #text} dicts (classic Windows events like 4673)
        #   - a single string blob (SQL Server audit packs the whole record here)
        #   - a single dict (rare but observed)
        # EventData itself may be an empty string ({"EventData":""}) for events
        # with no fields (e.g. some DNS/OCSP records) — treat that as no Data.
        # Always emit EventData for CSV reconstruction (empty section when no fields).
        event_data_section = event_data.get('EventData', {})
        data_items = (
            event_data_section.get('Data', [])
            if isinstance(event_data_section, dict)
            else []
        )
        parts.append('  <EventData>')
        if data_items:
            if isinstance(data_items, list):
                for item in data_items:
                    if isinstance(item, dict):
                        name = escape(str(item.get('@Name', '')), quote=True)
                        text = self._normalize_text(str(item.get('#text', '')))
                        parts.append(f'    <Data Name="{name}">{text}</Data>')
                    elif isinstance(item, str):
                        parts.append(f'    <Data>{self._normalize_text(item)}</Data>')
            elif isinstance(data_items, str):
                parts.append(f'    <Data>{self._normalize_text(data_items)}</Data>')
            elif isinstance(data_items, dict):
                name = escape(str(data_items.get('@Name', '')), quote=True)
                text = self._normalize_text(str(data_items.get('#text', '')))
                parts.append(f'    <Data Name="{name}">{text}</Data>')
        parts.append('  </EventData>')

        # Some providers (Microsoft-Windows-EventLog 1102/104, PrintService,
        # Servicing) store their fields under a {"UserData":{"<EventName>":{...}}}
        # root instead of EventData. Without this they reconstruct as an empty
        # <EventData/> and the model sees nothing — e.g. the log-clear subject or
        # the malicious printer name (see internal/known_issues.md).
        user_data = event_data.get('UserData')
        if isinstance(user_data, dict) and user_data:
            parts.append('  <UserData>')
            for elem_name, fields in user_data.items():
                ename = escape(str(elem_name), quote=False)
                if isinstance(fields, dict):
                    parts.append(f'    <{ename}>')
                    for k, v in fields.items():
                        kk = escape(str(k), quote=False)
                        vv = self._normalize_text(str(v))
                        parts.append(f'      <{kk}>{vv}</{kk}>')
                    parts.append(f'    </{ename}>')
                else:
                    parts.append(f'    <{ename}>{self._normalize_text(str(fields))}</{ename}>')
            parts.append('  </UserData>')

        parts.append('</Event>')
        return '\n'.join(parts)

    def format_for_llm_pure_raw_xml(self, events: List[Dict[str, Any]]) -> str:
        """
        Return only the raw XML from parsed events, with no added headers, summaries,
        or wrapper comments.

        This is the safest option for unbiased model evaluation: the model sees only
        the original event XML content.
        """
        if not events:
            return "No events found in log file."

        parts: List[str] = []
        for event in events:
            xml = event.get("_raw_xml")
            if xml:
                parts.append(xml)
        return "\n\n".join(parts)
