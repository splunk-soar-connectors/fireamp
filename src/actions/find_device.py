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
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..client import get_client, paginate, request_json
from ..helpers import resolve_named_guid
from ..models import APIResponse

# Contract correction: The legacy data.<computer-field> paths are inapplicable: both search routes return a list in data[]. User-search results retain the legacy top-level links/results fields.


class FindDeviceParams(Params):
    group_guid: str | None = Param(description="Group GUID", default=None)
    group_name: str | None = Param(description="Group name", default=None)
    user: str | None = Param(description="User", default=None)
    hostname: str | None = Param(description="Hostname", default=None)
    external_ip: str | None = Param(
        description="External ip", primary=True, cef_types=["ip"], default=None
    )
    internal_ip: str | None = Param(
        description="Internal ip", primary=True, cef_types=["ip"], default=None
    )


# Contract correction: scalar IP/group/technique array paths are inapplicable;
# Secure Endpoint returns arrays, represented by standard SDK list fields.


class FindDeviceOutputDataIsolation(APIResponse):
    available: bool | None = OutputField(example_values=[True])
    status: str | None = OutputField(example_values=["not_isolated"])


class FindDeviceOutputDataLink(APIResponse):
    computer: str | None = OutputField(cef_types=["url"])
    group: str | None = OutputField(cef_types=["url"])
    trajectory: str | None = OutputField(cef_types=["url"])


class FindDeviceOutputDataNetworkAddress(APIResponse):
    ip: str | None = OutputField(cef_types=["ip"], column_name="Ips")
    mac: str | None = OutputField(cef_types=["mac address"])


class FindDeviceOutputDataOrbital(APIResponse):
    status: str | None = OutputField(example_values=["not_enabled"])


class FindDeviceOutputDataPolicy(APIResponse):
    guid: str | None = None
    name: str | None = None


class FindDeviceOutputData(APIResponse):
    active: bool | None = OutputField(column_name="Active")
    connector_guid: str | None = OutputField(
        cef_types=["fireamp connector guid"], column_name="Connector GUID"
    )
    connector_version: str | None = None
    demo: bool | None = OutputField(example_values=[True])
    external_ip: str | None = OutputField(cef_types=["ip"])
    group_guid: str | None = None
    hostname: str | None = OutputField(cef_types=["host name"], column_name="Host Name")
    install_date: str | None = OutputField(example_values=["2021-04-20T09:55:41Z"])
    internal_ips: list[str] | None = OutputField(cef_types=["ip"])
    is_compromised: bool | None = OutputField(example_values=[False])
    isolation: FindDeviceOutputDataIsolation | None = None
    last_seen: str | None = OutputField(example_values=["2021-05-20T09:55:41Z"])
    links: FindDeviceOutputDataLink | None = None
    network_addresses: list[FindDeviceOutputDataNetworkAddress] | None = None
    operating_system: str | None = OutputField(column_name="Operating System")
    orbital: FindDeviceOutputDataOrbital | None = None
    policy: FindDeviceOutputDataPolicy | None = None
    windows_processor_id: str | None = OutputField(example_values=["65a9fd1b78043e2"])


class FindDeviceOutputLink(APIResponse):
    self: str | None = OutputField(
        example_values=[
            "https://api.amp.sourcefire.com/v1/computers/user_activity?q=johndoe"
        ]
    )


class FindDeviceOutputMetadataLink(APIResponse):
    self: str | None = OutputField(cef_types=["url"])


class FindDeviceOutputMetadataResult(APIResponse):
    current_item_count: int | None = OutputField(example_values=[25])
    index: int | None = OutputField(example_values=[0])
    items_per_page: int | None = OutputField(example_values=[500])
    total: int | None = OutputField(example_values=[25])


class FindDeviceOutputMetadata(APIResponse):
    links: FindDeviceOutputMetadataLink | None = None
    results: FindDeviceOutputMetadataResult | None = None


class FindDeviceOutputResult(APIResponse):
    current_item_count: int | None = OutputField(example_values=[7])
    index: int | None = OutputField(example_values=[0])
    items_per_page: int | None = OutputField(example_values=[500])
    total: int | None = OutputField(example_values=[7])


class FindDeviceOutput(APIResponse):
    data: list[FindDeviceOutputData] | None = None
    links: FindDeviceOutputLink | None = None
    metadata: FindDeviceOutputMetadata | None = None
    results: FindDeviceOutputResult | None = None
    version: str | None = None


class FindDeviceSummary(ActionOutput):
    total_endpoints: int


def find_device(
    params: FindDeviceParams, soar: SOARClient[FindDeviceSummary], asset: Asset
) -> list[FindDeviceOutput]:
    """Search endpoints by group, host, address, or user activity."""
    with get_client(asset) as client:
        query = {}
        if params.group_name and params.group_guid:
            raise ActionFailure("Provide either a group name or group guid, not both")
        if params.group_name:
            query["group_guid[]"] = resolve_named_guid(
                client, params.group_name, "group"
            )
        elif params.group_guid:
            query["group_guid[]"] = params.group_guid
        for source, target in (
            (params.hostname, "hostname[]"),
            (params.external_ip, "external_ip"),
            (params.internal_ip, "internal_ip"),
        ):
            if source:
                query[target] = source
        if query and params.user:
            raise ActionFailure(
                "User cannot be used in conjunction with any other search option"
            )
        if not (query or params.user):
            raise ActionFailure(
                "Must provide at least one of the following: group_name, group_guid, hostname, external_ip, internal_ip, user"
            )
        if params.user:
            activity = paginate(
                client, "/v1/computers/user_activity", params={"q": params.user}
            )
            if not activity["data"]:
                soar.set_summary(FindDeviceSummary(total_endpoints=0))
                soar.set_message("Unable to find endpoint by user")
                return []
            # Preserve the legacy user-search envelope, where links/results are top-level.
            response = {
                **activity.get("metadata", {}),
                "version": activity.get("version"),
                "data": [],
            }
            for computer in activity["data"]:
                details = request_json(
                    client, f"/v1/computers/{computer['connector_guid']}"
                )
                response["data"].append(details.get("data") if details else None)
        else:
            response = paginate(client, "/v1/computers", params=query)
    soar.set_summary(FindDeviceSummary(total_endpoints=len(response["data"])))
    return [FindDeviceOutput.model_validate(response)]
