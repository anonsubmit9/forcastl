#!/usr/bin/env python3
"""Score a model response against benchmark testcase JSON (EVTX/CSV scope)."""

import argparse
import json

from forcastl.core import score_benchmark_response
from forcastl.validation import load_test_case


def main():
    parser = argparse.ArgumentParser(description="Score LLM benchmark response")
    parser.add_argument("--response", required=True, help="Path to response text file")
    parser.add_argument("--testcase", required=True, help="Path to testcase JSON file")
    args = parser.parse_args()

    test_case = load_test_case(args.testcase)
    with open(args.response, "r", encoding="utf-8") as f:
        response_text = f.read()

    result = score_benchmark_response(response_text, test_case)

    print("\n--- Scoring Result ---")
    for key in [
        "TestID",
        "Extraction",
        "Interpretation",
        "NoHallucination",
        "Reasoning",
        "TotalScore",
        "Grade",
        "HallucinationFlag",
    ]:
        print(f"{key}: {result[key]}")

    print("\nRaw JSON:")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
