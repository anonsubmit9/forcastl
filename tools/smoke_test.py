"""Quick smoke test - verify imports, server connectivity, and CSV parsing."""
import sys
import requests
from forcastl import config

# 1. Test all imports
print("1. Testing imports...")
from forcastl.core import EVTXParser, MaliciousDetector, PromptManager, LLMModelSelector
from forcastl.core.csv_evidence import resolve_csv
from forcastl.reporting import RequestResponseLogger
print("   All imports OK")

# 2. Test server connectivity
print(f"\n2. Testing LLM server at {config.DEFAULT_LLM_SERVER}...")
try:
    resp = requests.get(f"{config.DEFAULT_LLM_SERVER}/v1/models", timeout=5)
    if resp.status_code == 200:
        models = resp.json().get("data", [])
        print(f"   Server OK - {len(models)} model(s) available:")
        for m in models:
            print(f"     - {m.get('id', 'unknown')}")
    else:
        print(f"   Server returned HTTP {resp.status_code}")
except Exception as e:
    print(f"   Server unreachable: {e}")

# 3. Test CSV parsing on first available file
print("\n3. Testing CSV parsing...")
import json
with open(config.METADATA_FILE, encoding="utf-8") as f:
    meta = json.load(f)
files = meta.get("files", {})
if files:
    parser = EVTXParser(verbose=False)
    selected = None
    selected_events = []

    # Some corpus files are known zero-event/unreadable; find first parseable sample.
    # metadata full_path is an EVTX path used only as a logical key; resolve to CSV by stem.
    for file_info in files.values():
        path = file_info["full_path"]
        csv_path = resolve_csv(path)
        if not csv_path:
            continue
        events = parser.parse_csv_file(csv_path)
        if events:
            selected = file_info
            selected_events = events
            break

    if selected:
        sel_path = selected["full_path"]
        print(f"   Parsed {len(selected_events)} events from {selected.get('filename', sel_path)}")
        # For unbiased evaluation, send only the raw XML content without headers/summaries.
        xml_output = parser.format_for_llm_pure_raw_xml(selected_events)
        print(f"   Formatted output: {len(xml_output)} chars")
    else:
        print("   No parseable CSV files found in metadata list")

# 4. Test detector with mock response
print("\n4. Testing malicious detector...")
detector = MaliciousDetector()
mock_response = """MALICIOUS: YES

EVIDENCE:
- Event IDs: 4625, 4776
- Processes: lsass.exe
- Accounts: administrator
- Commands: None
- Network: 10.0.0.50
- Registry: None

EXPLANATION:
Multiple failed login attempts indicate brute force attack."""

result = detector.detect(mock_response, "test.evtx", filename="test.evtx")
print(f"   Malicious: {result['is_malicious']}")
print(f"   Confidence: {result['confidence']}%")
print(f"   Structure valid: {result['validation']['is_valid']}")

print("\n--- All smoke tests passed ---")
print("Ready to run: python detect_malicious.py")
