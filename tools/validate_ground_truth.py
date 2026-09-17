#!/usr/bin/env python3
"""CLI wrapper for ground truth validation."""

import argparse
from forcastl import config
from forcastl.validation.ground_truth import run_validation


def main():
    parser = argparse.ArgumentParser(
        description="Validate ground truth evidence against actual EVTX content"
    )
    parser.add_argument(
        "--output", "-o",
        default=str(config.OUTPUTS_DIR / "ground_truth_validation_report.json"),
        help="Path for the JSON report",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show progress and summary during validation",
    )
    parser.add_argument(
        "--ground-truth",
        default=str(config.GROUND_TRUTH_FILE),
        help="Path to ground_truth_evidence.json",
    )
    parser.add_argument(
        "--metadata",
        default=str(config.METADATA_FILE),
        help="Path to metadata.json",
    )
    args = parser.parse_args()

    run_validation(
        gt_path=args.ground_truth,
        meta_path=args.metadata,
        output_path=args.output,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
