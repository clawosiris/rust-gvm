#!/usr/bin/env python3
"""Fail when an sbomqs JSON report is missing, malformed, or below policy."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any


DEFAULT_THRESHOLD = 8.3


def entry_score(entry: dict[str, Any]) -> float:
    value = entry.get("sbom_quality_score", entry.get("avg_score"))
    if isinstance(value, bool):
        raise ValueError("score must be numeric")
    try:
        score = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError("score is missing or non-numeric") from error
    if not math.isfinite(score) or not 0.0 <= score <= 10.0:
        raise ValueError("score must be between 0 and 10")
    return score


def entry_path(entry: dict[str, Any]) -> str:
    return str(
        entry.get("file_name")
        or entry.get("path")
        or entry.get("file")
        or entry.get("fileName")
        or "<unknown>"
    )


def check_report(report: dict[str, Any], threshold: float) -> list[tuple[str, float]]:
    files = report.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("sbomqs report contains no scored files")

    failures = []
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            raise ValueError(f"files[{index}] must be a JSON object")
        path = entry_path(entry)
        score = entry_score(entry)
        print(f"{path}: {score:.2f}/10")
        if score < threshold:
            failures.append((path, score))
    return failures


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="JSON output from sbomqs score --json")
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f"minimum score for every SBOM (default: {DEFAULT_THRESHOLD})",
    )
    args = parser.parse_args(argv)
    if not math.isfinite(args.threshold) or not 0.0 <= args.threshold <= 10.0:
        parser.error("--threshold must be between 0 and 10")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        report = json.loads(args.report.read_text())
        if not isinstance(report, dict):
            raise ValueError("sbomqs report must be a JSON object")
        failures = check_report(report, args.threshold)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"::error file={args.report}::Invalid sbomqs report: {error}")
        return 2

    for path, score in failures:
        print(
            f"::error file={path}::SBOM quality score below "
            f"{args.threshold:.1f}: {score:.2f}"
        )
    return int(bool(failures))


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    sys.exit(main(sys.argv[1:]))
