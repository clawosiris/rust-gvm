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
Basic module for gvmd task related things.
"""

import time
from collections import defaultdict
from typing import Any, Optional

from gvm.protocols.gmp import Gmp

GmpObject = dict[str, Any]


def etree_to_dict(etree) -> GmpObject:
    """Convert etree to dict"""
    # pylint: disable=invalid-name

    d = {etree.tag: {} if etree.attrib else etree.text}
    children = list(etree)
    if children:
        dd = defaultdict(list)
        for dc in map(etree_to_dict, children):
            for k, v in dc.items():
                dd[k].append(v)
        d = {etree.tag: {k: v[0] if len(v) == 1 else v for k, v in dd.items()}}
    if etree.attrib:
        d[etree.tag].update(("@" + k, v) for k, v in etree.attrib.items())
    if etree.text:
        if children or etree.attrib:
            d[etree.tag]["#text"] = etree.text
    return d


def etree_to_dict_handler(func):
    """Handle etree to dict"""

    def inner_function(*args, **kwargs):
        return etree_to_dict(func(*args, **kwargs))

    return inner_function


class GvmdBase:
    """Some Gvmd base functions"""

    def __init__(
        self,
        gmp: Gmp,
        scanner_name: str = "OpenVAS Default",
        scan_config_name: str = "Full and fast",
        port_list_name: str = "All IANA assigned TCP",
    ):
        self.gmp = gmp
        self.port_list_name = port_list_name
        self.scan_config_name = scan_config_name
        self.scanner_name = scanner_name
        self.scanner_info = self._get_scanners()
        self.scan_config_info = self._get_scan_configs()
        self.port_list_info = self._get_port_lists()

    # pylint: disable=too-many-arguments
    def _get_response_value(
        self,
        response_name: str,
        response_types: list,
        value_name: str,
        info: dict,
        obj_name: str = None,
    ):
        """Get a value from a response
        !!ONLY FIRST LEVEL ENTRIES!!"""

        # Get response value from single obj response
        for response_type in response_types:
            resp = f"{response_type}_{response_name}_response"
            if resp in info and value_name in info[resp]:
                return info[resp][value_name]
        # Get response value from list response
        list_resp = f"get_{response_name}s_response"
        if list_resp in info and response_name in info[list_resp]:
            if (
                isinstance(info[list_resp][response_name], dict)
                and value_name in info[list_resp][response_name]
            ):
                return info[list_resp][response_name][value_name]
            if isinstance(info[list_resp][response_name], list) and obj_name:
                for _type in info[list_resp][response_name]:
                    if "name" in _type and _type["name"] == obj_name:
                        return _type[value_name]
        return None

    @etree_to_dict_handler
    def _get_scanners(self) -> GmpObject:
        """Inner function to get a list of scanners"""

        return self.gmp.get_scanners()

    @etree_to_dict_handler
    def _get_scan_configs(self) -> GmpObject:
        """Inner function to get a list of scan configs"""

        return self.gmp.get_scan_configs()

    @etree_to_dict_handler
    def _get_port_lists(self) -> GmpObject:
        """Inner function to get a list of port lists"""

        return self.gmp.get_port_lists()

    def _get_scanner_id(self) -> str:
        """Get scanner id from create_scanner_response or get_scanners_response"""

        return self._get_response_value(
            "scanner",
            ["create"],
            "@id",
            self.scanner_info,
            obj_name=self.scanner_name,
        )

    def _get_scan_config_id(self) -> str:
        """Get scan config id from create_scan_config_response or get_scan_config_response"""

        return self._get_response_value(
            "config",
            ["create"],
            "@id",
            self.scan_config_info,
            obj_name=self.scan_config_name,
        )

    def _get_port_list_id(self) -> str:
        """Get port list id from create_port_list_response or get_port_list_response"""

        return self._get_response_value(
            "port_list",
            ["create"],
            "@id",
            self.port_list_info,
            obj_name=self.port_list_name,
        )

    def get_scanners(self) -> GmpObject:
        """Get a list of scanners"""

        self.scanner_info = self._get_scanners()
        return self.scanner_info

    def get_scan_configs(self) -> GmpObject:
        """ "Get a list of scan configs"""

        self.scan_config_info = self._get_scan_configs()
        return self.scan_config_info

    def get_port_lists(self) -> GmpObject:
        """Get a list of port lists"""

        self.port_list_info = self._get_port_lists()
        return self.port_list_info


class FeedUpdate(GvmdBase):
    """Feed update related functions"""

    def __init__(
        self,
        gmp: Gmp,
        scanner_name: str = "OpenVAS Default",
        scan_config_name: str = "Full and fast",
        port_list_name: str = "All IANA assigned TCP",
    ):
        super().__init__(
            gmp,
            scanner_name=scanner_name,
            scan_config_name=scan_config_name,
            port_list_name=port_list_name,
        )
        self.feed_info = None

    @etree_to_dict_handler
    def _get_feeds_status(self) -> GmpObject:
        """Inner function to start a task"""

        return self.gmp.get_feeds()

    def get_feeds_status(self) -> Optional[list[GmpObject]]:
        """Get a list with feed info dicts"""

        self.feed_info = self._get_feeds_status()
        if "get_feeds_response" in self.feed_info:
            return self.feed_info["get_feeds_response"]["feed"]

        return None

    def get_feeds_in_syncing(self) -> Optional[list[GmpObject]]:
        """Get a list with feed type names
        which are currently in sync process"""

        feeds_in_progress = self.get_feeds_status()
        for feed in list(feeds_in_progress):
            if "currently_syncing" not in feed:
                feeds_in_progress.remove(feed)
        return feeds_in_progress

    def wait_for_feed(self, print_state: bool = False) -> None:
        """Wait for feed update"""

        # Wait for feed update
        feeds_in_progress = self.get_feeds_in_syncing()

        # Check if feed is in sync state for GVMD timeout after
        if feeds_in_progress:
            in_sync = True
        else:
            in_sync = False

        while feeds_in_progress:
            if print_state:
                for feed in feeds_in_progress:
                    print(f'Feed {feed["type"]} still syncing', flush=True)
            time.sleep(30)
            feeds_in_progress = self.get_feeds_in_syncing()

        # Wait for scan configs
        while "config" not in self.get_scan_configs()["get_configs_response"]:
            if print_state:
                print("Wait for scan configs", flush=True)
            time.sleep(30)

        # GVMD needs some more time to load the scan configs
        if in_sync:
            time.sleep(60)


class ScanTaskError(Exception):
    """ScanTask base exception"""


class ScanTaskTaskExistError(ScanTaskError):
    """ScanTask task exist exception"""


class ScanTask(FeedUpdate):
    """Base class for scan task related functions"""

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        gmp: Gmp,
        target_name: str = "None",
        task_name: str = "None",
        scanner_name: str = "OpenVAS Default",
        scan_config_name: str = "Full and fast",
        port_list_name: str = "All IANA assigned TCP",
    ) -> None:
        super().__init__(
            gmp,
            scanner_name=scanner_name,
            scan_config_name=scan_config_name,
            port_list_name=port_list_name,
        )
        self.target_name = target_name
        self.task_name = task_name
        self.target_info = self._get_targets()
        self.task_info = self._get_tasks()
        self.report_info = None

    @etree_to_dict_handler
    def _create_target(self, hosts: list[str]) -> GmpObject:
        """Inner function to create a target"""

        return self.gmp.create_target(
            name=self.target_name,
            hosts=hosts,
            port_list_id=self._get_port_list_id(),
        )

    @etree_to_dict_handler
    def _create_task(self) -> GmpObject:
        """Inner function to create a task"""

        return self.gmp.create_task(
            name=self.task_name,
            config_id=self._get_scan_config_id(),
            target_id=self._get_target_id(),
            scanner_id=self._get_scanner_id(),
        )

    @etree_to_dict_handler
    def _start_task(self) -> GmpObject:
        """Inner function to start a task"""

        return self.gmp.start_task(self._get_task_id())

    @etree_to_dict_handler
    def _get_task_status(self) -> GmpObject:
        """Inner function to get a task status"""

        return self.gmp.get_task(self._get_task_id())

    @etree_to_dict_handler
    def _get_targets(self) -> GmpObject:
        """Inner function to get a list of targets"""

        return self.gmp.get_targets()

    @etree_to_dict_handler
    def _get_tasks(self) -> GmpObject:
        """Inner function to get a list of tasks"""

        return self.gmp.get_tasks()

    def _get_target_id(self) -> str:
        """Get target id from create_target_response or get_targets_response"""

        return self._get_response_value(
            "target",
            ["create"],
            "@id",
            self.target_info,
            obj_name=self.target_name,
        )

    def _get_task_id(self) -> str:
        """Get task id from create_task_response or get_tasks_response"""

        return self._get_response_value(
            "task", ["create"], "@id", self.task_info, obj_name=self.task_name
        )

    def _get_report_id(self) -> str:
        """Get report id from start_task_response or get_reports_response"""

        return self._get_response_value(
            "task", ["start"], "report_id", self.report_info
        )

    def create_target(self, hosts: list[str], name: str = None) -> GmpObject:
        """Create a scan target"""

        # INFO
        ## Create targets all ready dont allow
        ## target with the same name

        if name:
            self.target_name = name
        self.target_info = self._create_target(hosts)
        return self.target_info

    def create_task(self, name: str = None) -> GmpObject:
        """Create a task"""

        if name:
            self.task_name = name

        if self._get_task_id() is not None:
            raise ScanTaskTaskExistError(f"Task: {self.task_name} exist!")

        self.task_info = self._create_task()
        return self.task_info

    def start_task(self) -> GmpObject:
        """Start a task"""

        self.report_info = self._start_task()
        return self.report_info

    def get_task_status(self) -> GmpObject:
        """Get task status"""

        self.task_info = self._get_task_status()
        return self.task_info

    def get_task_progress_status(self) -> str:
        """Get the current progress status"""

        self.get_task_status()
        return self._get_response_value(
            "task",
            ["create"],
            "status",
            self.task_info,
        )
