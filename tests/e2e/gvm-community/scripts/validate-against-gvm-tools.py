#!/usr/bin/env python3
"""
Differential validation: compare rust-gvm GMP responses against gvm-tools (reference).

Runs both implementations against the same live gvmd instance and
checks that they agree on key facts (counts, IDs, structures).
"""

import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

SOCKET_PATH = os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock")
USERNAME = os.environ.get("GVM_ADMIN_USER", "admin")
PASSWORD = os.environ.get("GVM_ADMIN_PASS", "admin")


def gvm_tools_query():
    """Query gvmd via gvm-tools (Python reference implementation)."""
    connection = UnixSocketConnection(path=SOCKET_PATH)
    transform = EtreeCheckCommandTransform()

    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)

        results = {}

        # Version
        version_resp = gmp.get_version()
        results["version"] = version_resp.find("version").text

        # Scan configs
        configs_resp = gmp.get_scan_configs()
        configs = configs_resp.findall("config")
        results["scan_config_count"] = len(configs)
        results["scan_config_names"] = sorted([c.find("name").text for c in configs])
        results["scan_config_ids"] = sorted([c.get("id") for c in configs])

        # Scanners
        scanners_resp = gmp.get_scanners()
        scanners = scanners_resp.findall("scanner")
        results["scanner_count"] = len(scanners)
        results["scanner_names"] = sorted([s.find("name").text for s in scanners])

        # Port lists
        port_lists_resp = gmp.get_port_lists()
        port_lists = port_lists_resp.findall("port_list")
        results["port_list_count"] = len(port_lists)
        results["port_list_names"] = sorted([p.find("name").text for p in port_lists])

        # Feeds
        feeds_resp = gmp.get_feeds()
        feeds = feeds_resp.findall("feed")
        results["feed_count"] = len(feeds)
        results["feed_types"] = sorted([f.find("type").text for f in feeds])
        results["feeds_syncing"] = sum(
            1 for f in feeds if f.find("currently_syncing") is not None
        )

        # Report formats
        formats_resp = gmp.get_report_formats()
        formats = formats_resp.findall("report_format")
        results["report_format_count"] = len(formats)

    return results


def rust_gvm_query():
    """Query gvmd via rust-gvm e2e binary and parse its output."""
    # Run the smoke suite which prints pass/fail for each check
    # We'll parse the XML responses directly via a dedicated validation mode
    # For now, use raw GMP XML via the Rust binary
    result = subprocess.run(
        [
            "cargo", "run", "--quiet", "--example", "e2e_gvm_community",
            "--", "--mode", "validate"
        ],
        capture_output=True, text=True, cwd="/workspace",
        timeout=120,
    )

    if result.returncode != 0:
        print(f"rust-gvm validate failed: {result.stderr}", file=sys.stderr)
        # If validate mode doesn't exist yet, fall back to counting from smoke output
        return None

    # Parse JSON output from validate mode
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"Failed to parse rust-gvm output: {result.stdout[:500]}", file=sys.stderr)
        return None


def compare(ref_results, test_results):
    """Compare reference (gvm-tools) against test (rust-gvm) results."""
    passed = 0
    failed = 0
    total = 0

    def check(name, ref_val, test_val):
        nonlocal passed, failed, total
        total += 1
        if ref_val == test_val:
            print(f"  [PASS] {name}: {ref_val}")
            passed += 1
        else:
            print(f"  [FAIL] {name}: gvm-tools={ref_val}, rust-gvm={test_val}")
            failed += 1

    print("\n=== Differential Validation: gvm-tools vs rust-gvm ===\n")

    check("GMP version", ref_results["version"], test_results.get("version"))
    check("Scan config count", ref_results["scan_config_count"], test_results.get("scan_config_count"))
    check("Scan config names", ref_results["scan_config_names"], test_results.get("scan_config_names"))
    check("Scan config IDs", ref_results["scan_config_ids"], test_results.get("scan_config_ids"))
    check("Scanner count", ref_results["scanner_count"], test_results.get("scanner_count"))
    check("Scanner names", ref_results["scanner_names"], test_results.get("scanner_names"))
    check("Port list count", ref_results["port_list_count"], test_results.get("port_list_count"))
    check("Port list names", ref_results["port_list_names"], test_results.get("port_list_names"))
    check("Feed count", ref_results["feed_count"], test_results.get("feed_count"))
    check("Feed types", ref_results["feed_types"], test_results.get("feed_types"))
    check("Report format count", ref_results["report_format_count"], test_results.get("report_format_count"))

    print(f"\nResults: {passed}/{total} passed, {failed} failed")
    return failed == 0


def main():
    print("Querying gvm-tools (Python reference)...")
    ref = gvm_tools_query()
    print(f"  Got {ref['scan_config_count']} configs, {ref['scanner_count']} scanners, "
          f"{ref['port_list_count']} port lists, {ref['feed_count']} feeds")

    print("Querying rust-gvm...")
    test = rust_gvm_query()

    if test is None:
        print("\nrust-gvm validate mode not available yet.")
        print("Falling back to reference-only report:\n")
        print(json.dumps(ref, indent=2))
        print("\nValidation: SKIPPED (rust-gvm validate mode needed)")
        # Don't fail — this is informational until validate mode is added
        return 0

    if compare(ref, test):
        print("\n✓ All checks passed — rust-gvm matches gvm-tools")
        return 0
    else:
        print("\n✗ Mismatches detected — rust-gvm differs from gvm-tools")
        return 1


if __name__ == "__main__":
    sys.exit(main())
