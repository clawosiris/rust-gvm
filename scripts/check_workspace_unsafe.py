#!/usr/bin/env python3
"""Fail if workspace crates use unsafe code (via cargo-geiger JSON reports)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "target" / "geiger"
CRATES = [
    "gvm-protocol",
    "gvm-gmp",
    "gvm-client",
    "gvm-connection",
    "gvm-mock-server",
]


def unsafe_total(used: dict) -> int:
    return sum(section.get("unsafe_", 0) for section in used.values())


def run() -> int:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    violations: list[tuple[str, int]] = []

    for crate in CRATES:
        manifest = ROOT / "crates" / crate / "Cargo.toml"
        output = REPORT_DIR / f"{crate}.json"

        with output.open("w", encoding="utf-8") as fp:
            result = subprocess.run(
                [
                    "cargo",
                    "geiger",
                    "--manifest-path",
                    str(manifest),
                    "--all-features",
                    "--all-dependencies",
                    "--output-format",
                    "Json",
                ],
                cwd=ROOT,
                stdout=fp,
                stderr=subprocess.DEVNULL,
                check=False,
            )

        if result.returncode != 0:
            print(f"error: cargo geiger failed for {crate} (exit {result.returncode})")
            return 2

        try:
            payload = json.loads(output.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"error: invalid geiger JSON for {crate}: {exc}")
            return 2

        package = next(
            (
                pkg
                for pkg in payload.get("packages", [])
                if pkg.get("package", {}).get("id", {}).get("name") == crate
            ),
            None,
        )
        if package is None:
            print(f"error: package {crate} not found in geiger report")
            return 2

        total = unsafe_total(package.get("unsafety", {}).get("used", {}))
        print(f"{crate}: used_unsafe={total}")
        if total > 0:
            violations.append((crate, total))

    if violations:
        print("\nUnsafe usage detected in workspace crates:")
        for crate, count in violations:
            print(f"  - {crate}: {count}")
        return 1

    print("\nNo unsafe usage detected in workspace crates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
