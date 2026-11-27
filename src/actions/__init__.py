# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from typing import cast

from soar_sdk.app import App
from soar_sdk.types import NamedCallable

from .add_listitem import AddListitemSummary, add_listitem
from .allow_hash import AllowHashSummary, allow_hash
from .block_hash import BlockHashSummary, block_hash
from .change_group import ChangeGroupSummary, change_group
from .change_policy import ChangePolicySummary, change_policy
from .disallow_hash import DisallowHashSummary, disallow_hash
from .find_device import FindDeviceSummary, find_device
from .find_listitem import FindListitemSummary, find_listitem
from .get_device_events import GetDeviceEventsSummary, get_device_events
from .get_device_info import GetDeviceInfoSummary, get_device_info
from .get_device_trajectory import GetDeviceTrajectorySummary, get_device_trajectory
from .get_filelist import GetFilelistSummary, get_filelist
from .hunt_file import HuntFileSummary, hunt_file
from .hunt_ip import HuntIpSummary, hunt_ip
from .hunt_url import HuntUrlSummary, hunt_url
from .list_endpoints import ListEndpointsSummary, list_endpoints
from .list_filelists import ListFilelistsSummary, list_filelists
from .list_groups import ListGroupsSummary, list_groups
from .list_policies import ListPoliciesSummary, list_policies
from .make_request import make_request
from .quarantine_device import quarantine_device
from .remove_listitem import RemoveListitemSummary, remove_listitem
from .unblock_hash import UnblockHashSummary, unblock_hash
from .unquarantine_device import unquarantine_device


def register_actions(app: App) -> App:
    """Register FireAMP actions and their typed summaries."""
    app.make_request()(make_request)
    # SDK NamedCallable marks function.__globals__ as writable; the cast only
    # bridges that typing mismatch for ordinary Python action functions.
    app.register_action(
        cast(NamedCallable, list_endpoints),
        name="list endpoints",
        identifier="list_endpoints",
        description="List all of the endpoints connected to FireAMP",
        verbose="",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ListEndpointsSummary,
    )
    app.register_action(
        cast(NamedCallable, hunt_file),
        name="hunt file",
        identifier="hunt_file",
        description="Search for a file matching a SHA256 hash across all endpoints",
        verbose="",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=HuntFileSummary,
    )
    app.register_action(
        cast(NamedCallable, hunt_ip),
        name="hunt ip",
        identifier="hunt_ip",
        description="Search for a given IP",
        verbose="",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=HuntIpSummary,
    )
    app.register_action(
        cast(NamedCallable, hunt_url),
        name="hunt url",
        identifier="hunt_url",
        description="Search for a given URL",
        verbose="",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=HuntUrlSummary,
    )
    app.register_action(
        cast(NamedCallable, list_groups),
        name="list groups",
        identifier="list_groups",
        description="List all of the groups are present in FireAMP",
        verbose="",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ListGroupsSummary,
    )
    app.register_action(
        cast(NamedCallable, list_policies),
        name="list policies",
        identifier="list_policies",
        description="List all of the policies present in FireAMP",
        verbose="",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ListPoliciesSummary,
    )
    app.register_action(
        cast(NamedCallable, change_policy),
        name="change policy",
        identifier="change_policy",
        description="Updates group to given windows policy",
        verbose="",
        action_type="contain",
        read_only=False,
        render_as="table",
        summary_type=ChangePolicySummary,
    )
    app.register_action(
        cast(NamedCallable, change_group),
        name="change group",
        identifier="change_group",
        description="Change the group of provided GUID endpoint",
        verbose="",
        action_type="investigate",
        read_only=False,
        render_as="table",
        summary_type=ChangeGroupSummary,
    )
    app.register_action(
        cast(NamedCallable, unquarantine_device),
        name="unquarantine device",
        identifier="unquarantine_device",
        description="Stop host isolation based on connector GUID",
        verbose="",
        action_type="correct",
        read_only=False,
        render_as="table",
    )
    app.register_action(
        cast(NamedCallable, quarantine_device),
        name="quarantine device",
        identifier="quarantine_device",
        description="Isolate host based on connector GUID",
        verbose="",
        action_type="contain",
        read_only=False,
        render_as="table",
    )
    app.register_action(
        cast(NamedCallable, find_device),
        name="find device",
        identifier="find_device",
        description="Finds system with search parameters",
        verbose="If finding by user, no other search options can be used. Additionally group name and group GUID are mutually exclusive search options.",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=FindDeviceSummary,
    )
    app.register_action(
        cast(NamedCallable, get_device_info),
        name="get device info",
        identifier="get_device_info",
        description="Get information about a device, given its connector GUID",
        verbose="",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=GetDeviceInfoSummary,
    )
    app.register_action(
        cast(NamedCallable, block_hash),
        name="block hash",
        identifier="block_hash",
        description="Add a file hash (sha256 only) to a file list specified by GUID",
        verbose="",
        action_type="contain",
        read_only=False,
        render_as="table",
        summary_type=BlockHashSummary,
    )
    app.register_action(
        cast(NamedCallable, unblock_hash),
        name="unblock hash",
        identifier="unblock_hash",
        description="Remove a file hash (sha256 only) from a file list specified by GUID",
        verbose="",
        action_type="contain",
        read_only=False,
        render_as="table",
        summary_type=UnblockHashSummary,
    )
    app.register_action(
        cast(NamedCallable, allow_hash),
        name="allow hash",
        identifier="allow_hash",
        description="Add a file hash (sha256 only) to a file list specified by GUID",
        verbose="",
        action_type="contain",
        read_only=False,
        render_as="table",
        summary_type=AllowHashSummary,
    )
    app.register_action(
        cast(NamedCallable, disallow_hash),
        name="disallow hash",
        identifier="disallow_hash",
        description="Remove all sha256 file hashes from a file list specified by GUID",
        verbose="",
        action_type="contain",
        read_only=False,
        render_as="table",
        summary_type=DisallowHashSummary,
    )
    app.register_action(
        cast(NamedCallable, list_filelists),
        name="list filelists",
        identifier="list_filelists",
        description="List all of the File Lists (application blocking & simple custom detections) in FireAMP",
        verbose="",
        action_type="generic",
        read_only=True,
        render_as="table",
        summary_type=ListFilelistsSummary,
    )
    app.register_action(
        cast(NamedCallable, get_filelist),
        name="get filelist",
        identifier="get_filelist",
        description="Get all of the hashes in a File List in FireAMP. Lists can be retrieved by UUID, or file list name and type",
        verbose="",
        action_type="generic",
        read_only=True,
        render_as="table",
        summary_type=GetFilelistSummary,
    )
    app.register_action(
        cast(NamedCallable, remove_listitem),
        name="remove listitem",
        identifier="remove_listitem",
        description="Removes file hash from file list",
        verbose="",
        action_type="correct",
        read_only=False,
        render_as="table",
        summary_type=RemoveListitemSummary,
    )
    app.register_action(
        cast(NamedCallable, add_listitem),
        name="add listitem",
        identifier="add_listitem",
        description="Add file hash as listitem to file list",
        verbose="",
        action_type="correct",
        read_only=False,
        render_as="table",
        summary_type=AddListitemSummary,
    )
    app.register_action(
        cast(NamedCallable, find_listitem),
        name="find listitem",
        identifier="find_listitem",
        description="Finds file hash in specified file list",
        verbose="",
        action_type="generic",
        read_only=True,
        render_as="table",
        summary_type=FindListitemSummary,
    )
    app.register_action(
        cast(NamedCallable, get_device_trajectory),
        name="get device trajectory",
        identifier="get_device_trajectory",
        description="Retrieve trajectory info about a device",
        verbose="",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=GetDeviceTrajectorySummary,
    )
    app.register_action(
        cast(NamedCallable, get_device_events),
        name="get device events",
        identifier="get_device_events",
        description="Retrieve device events",
        verbose="",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=GetDeviceEventsSummary,
    )
    return app
