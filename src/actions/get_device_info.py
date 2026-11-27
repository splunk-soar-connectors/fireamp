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
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..client import get_client, request_json
from ..helpers import guid
from ..models import APIResponse


class GetDeviceInfoParams(Params):
    connector_guid: str = Param(
        description="Connector GUID on endpoint",
        primary=True,
        cef_types=["fireamp connector guid"],
    )


# Contract correction: scalar IP/group/technique array paths are inapplicable;
# Secure Endpoint returns arrays, represented by standard SDK list fields.


class GetDeviceInfoOutputDataLink(APIResponse):
    computer: str | None = OutputField(cef_types=["url"])
    group: str | None = OutputField(cef_types=["url"])
    trajectory: str | None = OutputField(cef_types=["url"])


class GetDeviceInfoOutputDataOrbital(APIResponse):
    status: str | None = OutputField(example_values=["not_enabled"])


class GetDeviceInfoOutputDataIsolation(APIResponse):
    status: str | None = OutputField(example_values=["not_isolated"])
    available: bool | None = OutputField(example_values=[True])


class GetDeviceInfoOutputDataNetworkAddress(APIResponse):
    ip: str | None = OutputField(cef_types=["ip"], column_name="Ips")
    mac: str | None = OutputField(cef_types=["mac address"])


class GetDeviceInfoOutputDataPolicy(APIResponse):
    guid: str | None = None
    name: str | None = None


class GetDeviceInfoOutputData(APIResponse):
    active: bool | None = OutputField(column_name="Active")
    connector_guid: str | None = OutputField(
        cef_types=["fireamp connector guid"], column_name="Connector GUID"
    )
    connector_version: str | None = None
    external_ip: str | None = OutputField(cef_types=["ip"])
    group_guid: str | None = None
    hostname: str | None = OutputField(cef_types=["host name"], column_name="Host Name")
    internal_ips: list[str] | None = OutputField(cef_types=["ip"])
    links: GetDeviceInfoOutputDataLink | None = None
    demo: bool | None = OutputField(example_values=[True])
    orbital: GetDeviceInfoOutputDataOrbital | None = None
    isolation: GetDeviceInfoOutputDataIsolation | None = None
    last_seen: str | None = OutputField(example_values=["2021-05-20T09:55:41Z"])
    install_date: str | None = OutputField(example_values=["2021-04-20T09:55:41Z"])
    is_compromised: bool | None = OutputField(example_values=[False])
    windows_processor_id: str | None = OutputField(example_values=["198a4d60e2f7b53"])
    network_addresses: list[GetDeviceInfoOutputDataNetworkAddress] | None = None
    operating_system: str | None = OutputField(column_name="Operating System")
    policy: GetDeviceInfoOutputDataPolicy | None = None


class GetDeviceInfoOutputMetadataLink(APIResponse):
    self: str | None = OutputField(cef_types=["url"])


class GetDeviceInfoOutputMetadata(APIResponse):
    links: GetDeviceInfoOutputMetadataLink | None = None


class GetDeviceInfoOutput(APIResponse):
    data: GetDeviceInfoOutputData | None = None
    metadata: GetDeviceInfoOutputMetadata | None = None
    version: str | None = None


class GetDeviceInfoSummary(ActionOutput):
    total_endpoints: int


def get_device_info(
    params: GetDeviceInfoParams, soar: SOARClient[GetDeviceInfoSummary], asset: Asset
) -> GetDeviceInfoOutput:
    """Get endpoint details by connector GUID."""
    connector = guid(params.connector_guid, "connector_guid")
    with get_client(asset) as client:
        response = request_json(client, f"/v1/computers/{connector}")
    soar.set_summary(GetDeviceInfoSummary(total_endpoints=1))
    return GetDeviceInfoOutput.model_validate(response)
