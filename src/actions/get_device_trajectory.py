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
from datetime import UTC, datetime
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..client import get_client, paginate
from ..helpers import guid
from ..models import APIResponse

# Contract correction: The legacy data.<file-list-field> and file_found summary paths are inapplicable: trajectory returns computer/events at the top level and reports total_trajectories.


class GetDeviceTrajectoryParams(Params):
    connector_guid: str = Param(
        description="Connector GUID on endpoint",
        primary=True,
        cef_types=["fireamp connector guid"],
    )
    filter: str | None = Param(
        description="Filter trajectory info",
        cef_types=["sha256", "url", "ip"],
        default=None,
    )
    days_back: int | None = Param(
        description="Return events from a number of days back", default=None
    )
    executed_only: bool | None = Param(
        description="Only retrieve events where the file has been executed",
        default=True,
    )
    limit: int | None = Param(description="Limit number of results", default=None)


# Contract correction: scalar IP/group/technique array paths are inapplicable;
# Secure Endpoint returns arrays, represented by standard SDK list fields.


class GetDeviceTrajectoryOutputComputerIsolation(APIResponse):
    available: bool | None = OutputField(example_values=[True, False])
    status: str | None = OutputField(example_values=["not_isolated"])


class GetDeviceTrajectoryOutputComputerLink(APIResponse):
    computer: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/computers/0cdd56bc-e299-4547-ae1d-148aae71de03"
        ],
    )
    group: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/groups/a0841d16-1b37-4eac-9154-8ed475534f9e"
        ],
    )
    trajectory: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/computers/0cdd56bc-e299-4547-ae1d-148aae71de03/trajectory"
        ],
    )


class GetDeviceTrajectoryOutputComputerNetworkAddress(APIResponse):
    ip: str | None = OutputField(cef_types=["ip"], example_values=["192.168.66.238"])
    mac: str | None = OutputField(example_values=["00:50:56:ac:80:e5"])


class GetDeviceTrajectoryOutputComputerOrbital(APIResponse):
    status: str | None = OutputField(example_values=["enabled"])


class GetDeviceTrajectoryOutputComputerPolicy(APIResponse):
    guid: str | None = OutputField(
        example_values=["cbb3691a-db66-422f-b770-b79bd12653d8"]
    )
    name: str | None = OutputField(example_values=["Protect-No-Proxy"])


class GetDeviceTrajectoryOutputComputer(APIResponse):
    active: bool | None = OutputField(example_values=[True, False])
    connector_guid: str | None = OutputField(
        example_values=["0cdd56bc-e299-4547-ae1d-148aae71de03"]
    )
    connector_version: str | None = OutputField(example_values=["7.2.3.11648"])
    demo: bool | None = OutputField(example_values=[True])
    external_ip: str | None = OutputField(
        cef_types=["ip"], example_values=["35.161.149.114"]
    )
    group_guid: str | None = OutputField(
        example_values=["a0841d16-1b37-4eac-9154-8ed475534f9e"]
    )
    hostname: str | None = OutputField(
        cef_types=["host name"], example_values=["commando.skynet.lab"]
    )
    install_date: str | None = OutputField(example_values=["2019-10-18T20:49:35Z"])
    internal_ips: list[str] | None = OutputField(example_values=[" 172.18.85.49"])
    is_compromised: bool | None = OutputField(example_values=[False])
    isolation: GetDeviceTrajectoryOutputComputerIsolation | None = None
    links: GetDeviceTrajectoryOutputComputerLink | None = None
    network_addresses: list[GetDeviceTrajectoryOutputComputerNetworkAddress] | None = (
        None
    )
    operating_system: str | None = OutputField(example_values=["Windows 10 Enterprise"])
    orbital: GetDeviceTrajectoryOutputComputerOrbital | None = None
    policy: GetDeviceTrajectoryOutputComputerPolicy | None = None
    windows_processor_id: str | None = OutputField(example_values=["1f8bfbff000306e4"])


class GetDeviceTrajectoryOutputEventFileParentIdentity(APIResponse):
    md5: str | None = OutputField(example_values=["38ae1b3c38faef56fe4907922f0385ba"])
    sha1: str | None = OutputField(
        example_values=[
            "84123a3decdaa217e3588a1de59fe6cee1998004"  # pragma: allowlist secret
        ]
    )
    sha256: str | None = OutputField(
        cef_types=["sha256"],
        example_values=[
            "8bcfd8420d721cc0ca50c1bef653e63e013ce201dfcca5927228eb25c9abf606"  # pragma: allowlist secret
        ],
    )


class GetDeviceTrajectoryOutputEventFileParent(APIResponse):
    identity: GetDeviceTrajectoryOutputEventFileParentIdentity | None = None
    file_name: str | None = OutputField(example_values=["explorer.exe"])
    process_id: int | None = OutputField(example_values=[2632])
    disposition: str | None = OutputField(example_values=["Unknown"])


class GetDeviceTrajectoryOutputEventFileIdentity(APIResponse):
    md5: str | None = OutputField(example_values=["41476df3138717868118d8542cf3d1d6"])
    sha1: str | None = OutputField(
        example_values=[
            "5ca4bef8de6def53519d4b22632675bb4c1e470b"  # pragma: allowlist secret
        ]
    )
    sha256: str | None = OutputField(
        cef_types=["sha256"],
        example_values=[
            "a36f0d4c081b86ecca210a64cf67c948bd3535e719e255638602a92c94eb9abc"  # pragma: allowlist secret
        ],
    )


class GetDeviceTrajectoryOutputEventFile(APIResponse):
    parent: GetDeviceTrajectoryOutputEventFileParent | None = None
    disposition: str | None = OutputField(example_values=["Unknown"])
    file_name: str | None = OutputField(
        cef_types=["file name", "sha1"], example_values=["prefs-1.js"]
    )
    file_path: str | None = OutputField(
        cef_types=["file name"],
        example_values=[
            "/c:/users/maclemon/appdata/roaming/mozilla/firefox/profiles/x6berjvs.default-release/prefs-1.js"
        ],
    )
    file_type: str | None = OutputField(example_values=["Script"])
    identity: GetDeviceTrajectoryOutputEventFileIdentity | None = None


class GetDeviceTrajectoryOutputEventScan(APIResponse):
    clean: bool | None = OutputField(example_values=[True])
    description: str | None = OutputField(example_values=["Flash Scan"])
    scanned_files: int | None = OutputField(example_values=[2872])
    scanned_paths: int | None = OutputField(example_values=[0])
    scanned_processes: int | None = OutputField(example_values=[49])
    malicious_detections: int | None = OutputField(example_values=[0])


class GetDeviceTrajectoryOutputEventCloudIoc(APIResponse):
    description: str | None = OutputField(
        example_values=[
            "PowerShell is a Windows utility that allows access to many Microsoft APIs within a shell environment. In this case, a script attempted to download a file or script to the local system and then execute it. Malware authors may use this to download items, rename them, execute and delete them with a single command."
        ]
    )
    short_description: str | None = OutputField(
        example_values=["W32.PowershellDownloadedExecutable.ioc"]
    )


class GetDeviceTrajectoryOutputEventCommandLineEnvironment(APIResponse):
    Path: str | None = OutputField(cef_types=["file path"])
    USERNAME: str | None = OutputField(
        cef_types=["user name"], example_values=["COMMANDO$"]
    )


class GetDeviceTrajectoryOutputEventCommandLine(APIResponse):
    arguments: str | None = OutputField(example_values=["-Embedding"])
    environment: GetDeviceTrajectoryOutputEventCommandLineEnvironment | None = None


class GetDeviceTrajectoryOutputEventIsolation(APIResponse):
    duration: int | None = OutputField(example_values=[46])


class GetDeviceTrajectoryOutputEventNetworkInfoNfm(APIResponse):
    direction: str | None = OutputField(example_values=["Outgoing connection from"])
    protocol: str | None = OutputField(example_values=["TCP"])


class GetDeviceTrajectoryOutputEventNetworkInfoParentIdentity(APIResponse):
    sha256: str | None = OutputField(
        cef_types=["sha256"],
        example_values=[
            "dd191a5b23df92e12a8852291f9fb5ed594b76a28a5a464418442584afd1e048"  # pragma: allowlist secret
        ],
    )


class GetDeviceTrajectoryOutputEventNetworkInfoParent(APIResponse):
    disposition: str | None = OutputField(example_values=["Clean"])
    identity: GetDeviceTrajectoryOutputEventNetworkInfoParentIdentity | None = None


class GetDeviceTrajectoryOutputEventNetworkInfo(APIResponse):
    dirty_url: str | None = OutputField(
        cef_types=["url"], example_values=["http://settings-win.data.microsoft.com:443"]
    )
    local_ip: str | None = OutputField(
        cef_types=["ip"], example_values=["192.168.66.238"]
    )
    local_port: int | None = OutputField(example_values=[19734])
    nfm: GetDeviceTrajectoryOutputEventNetworkInfoNfm | None = None
    parent: GetDeviceTrajectoryOutputEventNetworkInfoParent | None = None
    remote_ip: str | None = OutputField(
        cef_types=["ip"], example_values=["192.168.66.215"]
    )
    remote_port: int | None = OutputField(example_values=[389])


class GetDeviceTrajectoryOutputEventVulnerability(APIResponse):
    cve: str | None = OutputField(example_values=["CVE-2014-0260"])
    name: str | None = OutputField(example_values=["Microsoft Office"])
    score: float | None = OutputField(example_values=[9.3])
    url: str | None = OutputField(
        example_values=[
            "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0260"
        ]
    )
    version: str | None = OutputField(example_values=["2013"])


class GetDeviceTrajectoryOutputEvent(APIResponse):
    file: GetDeviceTrajectoryOutputEventFile | None = None
    scan: GetDeviceTrajectoryOutputEventScan | None = None
    cloud_ioc: GetDeviceTrajectoryOutputEventCloudIoc | None = None
    command_line: GetDeviceTrajectoryOutputEventCommandLine | None = None
    date: str | None = OutputField(
        example_values=["2020-04-22T18:49:34+00:00"], column_name="Date"
    )
    detection: str | None = OutputField(example_values=["W32.6A37D750F0-100.SBX.TG"])
    id: str | None = OutputField(
        example_values=["6812581201115613122"], column_name="ID"
    )
    severity: str | None = OutputField(column_name="Severity")
    detection_id: str | None = OutputField(column_name="Detection ID")
    event_type: str | None = OutputField(column_name="Event Type")
    event_type_id: int | None = OutputField(example_values=[553648155])
    group_guids: list[str] | None = OutputField(
        example_values=["a0841d16-1b37-4eac-9154-8ed475534f9e"]
    )
    isolation: GetDeviceTrajectoryOutputEventIsolation | None = None
    network_info: GetDeviceTrajectoryOutputEventNetworkInfo | None = None
    start_date: str | None = OutputField(example_values=["2018-01-07T04:12:27+00:00"])
    start_timestamp: int | None = OutputField(example_values=[1515298347])
    timestamp: int | None = OutputField(example_values=[1587581374])
    timestamp_nanoseconds: int | None = OutputField(example_values=[13538365])
    vulnerabilities: list[GetDeviceTrajectoryOutputEventVulnerability] | None = None


class GetDeviceTrajectoryOutputMetadataLink(APIResponse):
    self: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/computers/0cdd56bc-e299-4547-ae1d-148aae71de03/trajectory?limit=100"
        ],
    )


class GetDeviceTrajectoryOutputMetadata(APIResponse):
    links: GetDeviceTrajectoryOutputMetadataLink | None = None


class GetDeviceTrajectoryOutput(APIResponse):
    computer: GetDeviceTrajectoryOutputComputer | None = None
    events: list[GetDeviceTrajectoryOutputEvent] | None = None
    metadata: GetDeviceTrajectoryOutputMetadata | None = None
    version: str | None = OutputField(example_values=["v1.2.0"])


class GetDeviceTrajectorySummary(ActionOutput):
    total_trajectories: int


def get_device_trajectory(
    params: GetDeviceTrajectoryParams,
    soar: SOARClient[GetDeviceTrajectorySummary],
    asset: Asset,
) -> GetDeviceTrajectoryOutput:
    """Retrieve an endpoint's trajectory and optionally filter by age."""
    connector = guid(params.connector_guid, "connector_guid", canonical=True)
    if params.days_back is not None and params.days_back < 0:
        raise ActionFailure(
            "Please provide a valid non-negative integer value in the days_back parameter"
        )
    query: dict[str, Any] = {"limit": params.limit if params.limit is not None else 500}
    if params.filter:
        query["q"] = params.filter
    with get_client(asset) as client:
        response = paginate(
            client,
            f"/v1/computers/{connector}/trajectory",
            params=query,
            nested_key="events",
        )
    data = response.pop("data")
    response["events"] = data.get("events", [])
    response["computer"] = data.get("computer")
    if params.days_back:
        now = datetime.now(UTC)
        events = []
        for event in response["events"]:
            try:
                date = datetime.fromisoformat(event["date"].replace("Z", "+00:00"))
                if date.tzinfo is None:
                    date = date.replace(tzinfo=UTC)
            except (ValueError, TypeError, KeyError) as exc:
                raise ActionFailure(
                    "Invalid event date returned by Secure Endpoint"
                ) from exc
            if (now - date).days <= params.days_back:
                events.append(event)
        response["events"] = events
    # executed_only remains an accepted legacy input; the old action did not filter on it.
    # The old total counted envelope keys; this summary counts returned trajectory events.
    soar.set_summary(
        GetDeviceTrajectorySummary(total_trajectories=len(response["events"]))
    )
    return GetDeviceTrajectoryOutput.model_validate(response)
