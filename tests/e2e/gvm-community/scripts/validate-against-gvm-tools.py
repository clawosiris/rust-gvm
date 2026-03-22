#!/usr/bin/env python3
"""
gvm-tools fallback diagnostic: when rust-gvm reports a failure, re-run
the same GMP query via gvm-tools to determine fault location.

Usage:
  python3 validate-against-gvm-tools.py --check <check_name>

Checks: get_version, get_scan_configs, get_scanners, get_port_lists,
        get_feeds, get_report_formats, authenticate

Exit codes:
  0 = gvm-tools also succeeds (bug likely in rust-gvm)
  1 = gvm-tools also fails (problem in GVM stack)
  2 = usage error
"""

import argparse
import json
import os
import sys

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

SOCKET_PATH = os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock")
USERNAME = os.environ.get("GVM_ADMIN_USER", "admin")
PASSWORD = os.environ.get("GVM_ADMIN_PASS", "admin")

CHECKS = {
    "get_version": lambda gmp: gmp.get_version(),
    "get_scan_configs": lambda gmp: gmp.get_scan_configs(),
    "get_scanners": lambda gmp: gmp.get_scanners(),
    "get_port_lists": lambda gmp: gmp.get_port_lists(),
    "get_feeds": lambda gmp: gmp.get_feeds(),
    "get_report_formats": lambda gmp: gmp.get_report_formats(),
}


def run_check(check_name):
    connection = UnixSocketConnection(path=SOCKET_PATH)
    transform = EtreeCheckCommandTransform()

    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)

        if check_name == "all":
            results = {}
            for name, fn in CHECKS.items():
                try:
                    resp = fn(gmp)
                    results[name] = {"status": "ok", "element_count": len(list(resp))}
                except Exception as e:
                    results[name] = {"status": "error", "error": str(e)}
            return results

        if check_name not in CHECKS:
            print(f"Unknown check: {check_name}", file=sys.stderr)
            print(f"Available: {', '.join(CHECKS.keys())}, all", file=sys.stderr)
            sys.exit(2)

        resp = CHECKS[check_name](gmp)
        children = list(resp)
        result = {
            "check": check_name,
            "status": "ok",
            "element_count": len(children),
        }

        # Add detail for key checks
        if check_name == "get_scan_configs":
            configs = resp.findall("config")
            result["configs"] = [
                {"name": c.find("name").text, "id": c.get("id")} for c in configs
            ]
        elif check_name == "get_scanners":
            scanners = resp.findall("scanner")
            result["scanners"] = [
                {"name": s.find("name").text, "id": s.get("id")} for s in scanners
            ]
        elif check_name == "get_feeds":
            feeds = resp.findall("feed")
            result["feeds"] = []
            for f in feeds:
                feed_info = {"type": f.find("type").text}
                syncing = f.find("currently_syncing")
                if syncing is not None:
                    feed_info["syncing"] = True
                result["feeds"].append(feed_info)

        return result


def main():
    parser = argparse.ArgumentParser(description="gvm-tools fallback diagnostic")
    parser.add_argument(
        "--check", required=True,
        help="GMP check to run (get_version, get_scan_configs, etc., or 'all')"
    )
    args = parser.parse_args()

    try:
        result = run_check(args.check)
        print(json.dumps(result, indent=2))

        # Determine if gvm-tools succeeded
        if isinstance(result, dict) and "status" in result:
            if result["status"] == "ok":
                print(f"\n→ gvm-tools: {args.check} SUCCEEDED", file=sys.stderr)
                print("→ Fault likely in rust-gvm implementation", file=sys.stderr)
                return 0
            else:
                print(f"\n→ gvm-tools: {args.check} FAILED", file=sys.stderr)
                print("→ Problem in GVM stack, not rust-gvm", file=sys.stderr)
                return 1
        elif isinstance(result, dict):
            # "all" mode — check if any failed
            failures = [k for k, v in result.items() if v.get("status") != "ok"]
            if failures:
                print(f"\n→ gvm-tools failures: {failures}", file=sys.stderr)
                print("→ Problem in GVM stack", file=sys.stderr)
                return 1
            print("\n→ gvm-tools: all checks SUCCEEDED", file=sys.stderr)
            print("→ Fault likely in rust-gvm implementation", file=sys.stderr)
            return 0

    except Exception as e:
        print(f"gvm-tools error: {e}", file=sys.stderr)
        print("→ gvm-tools also failed — problem in GVM stack", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
