# Copyright (C) 2022 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
This script is to test the community containers.
It needs two parameters after the script name.

1. <host_ip>        IP Address of the host system

Example:
 $ gvm-script --gmp-username name --gmp-password pass \
   ssh --hostname <gsm> scripts/scan-new-system.gmp.py \
   <host_ip>
"""

import argparse
import os
import sys
import time
from argparse import Namespace

from gvm.protocols.gmp import Gmp

sys.path.append(os.getcwd())

from lib.task_scan import ScanTask


class BasicScanTest(ScanTask):
    """Run a basic scan test"""

    def run(self, args: Namespace) -> None:
        """Run a simple test scan"""

        self.wait_for_feed(print_state=True)
        if not args.no_target_create:
            self.create_target(args.hosts)
        if not args.no_task_create:
            self.create_task()
        self.start_task()

        # Wait that the scan is done
        while True:
            test_status = self.get_task_progress_status()
            print(f"Task status: {test_status}", flush=True)
            if test_status == "Stopped":
                print("Scan Error: Stopped", flush=True)
                return 1
            if test_status == "Interrupted":
                print("Scan Error: Interrupted", flush=True)
                return 2
            if test_status == "Done":
                print("Scan OK", flush=True)
                return 0
            time.sleep(30)


def get_args(args: Namespace):
    """Get commandline arguments"""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--hosts",
        type=str,
        nargs="+",
        required=False,
        default=["192.168.0.0/16"],
        help="Hosts to scan e.g IP/SUBNET",
    )
    parser.add_argument(
        "--target-name",
        type=str,
        default="TestTarget",
        required=False,
        help='Target name to use and or create e.g "TestTarget"',
    )
    parser.add_argument(
        "--no-target-create",
        required=False,
        action="store_true",
        help="Do not create the target, otherwise it needs to exist, default False",
    )
    parser.add_argument(
        "--task-name",
        type=str,
        default="TestTask",
        required=False,
        help='Task name to use andor create e.g "TestTask"',
    )
    parser.add_argument(
        "--no-task-create",
        required=False,
        action="store_true",
        help="Do not create the task, otherwise it needs to exist, default False",
    )
    parser.add_argument(
        "--port-list",
        type=str,
        default="All IANA assigned TCP",
        required=False,
        help='Port list as name to use with the task e.g "All IANA assigned TCP"',
    )
    parser.add_argument(
        "--scan-config",
        type=str,
        default="Full and fast",
        required=False,
        help='Scan config as name to use with the task e.g "Full and fast"',
    )
    parser.add_argument(
        "--scanner",
        type=str,
        default="OpenVAS Default",
        required=False,
        help='Scanner as name to use with the task e.g "OpenVAS Default"',
    )

    return parser.parse_args(args.script_args)


def main(gmp: Gmp, args: Namespace) -> None:
    """Run Tests"""
    args = get_args(args)
    bst = BasicScanTest(
        gmp,
        args.target_name,
        args.task_name,
        scanner_name=args.scanner,
        scan_config_name=args.scan_config,
        port_list_name=args.port_list,
    )
    return bst.run(args)


if __name__ == "__gmp__":
    # pylint: disable=undefined-variable
    sys.exit(main(gmp, args))
