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
from soar_sdk.params import Params

from ..asset import Asset
from ..client import get_client, paginate
from ..models import APIResponse


class ListEndpointsParams(Params):
    pass


# Contract correction: scalar IP/group/technique array paths are inapplicable;
# Secure Endpoint returns arrays, represented by standard SDK list fields.


class ListEndpointsOutputDataIsolation(APIResponse):
    available: bool | None = OutputField(example_values=[False])
    status: str | None = OutputField(example_values=["not_isolated"])


class ListEndpointsOutputDataLink(APIResponse):
    computer: str | None = None
    group: str | None = OutputField(cef_types=["url"])
    trajectory: str | None = OutputField(
        example_values=[
            "https://api.amp.sourcefire.com/v1/computers/05f5a5e6-6281-4582-a2c9-6d28d451cd9e/trajectory"
        ]
    )


class ListEndpointsOutputDataNetworkAddress(APIResponse):
    ip: str | None = OutputField(cef_types=["ip"], column_name="IP")
    mac: str | None = OutputField(cef_types=["mac address"])


class ListEndpointsOutputDataOrbital(APIResponse):
    status: str | None = OutputField(example_values=["not_enabled"])


class ListEndpointsOutputDataPolicy(APIResponse):
    guid: str | None = None
    name: str | None = None


class ListEndpointsOutputData(APIResponse):
    active: bool | None = OutputField(column_name="Active")
    connector_guid: str | None = OutputField(
        cef_types=["fireamp connector guid"], column_name="Connector GUID"
    )
    connector_version: str | None = None
    demo: bool | None = OutputField(example_values=[True])
    external_ip: str | None = OutputField(cef_types=["ip"], column_name="External IP")
    group_guid: str | None = None
    hostname: str | None = OutputField(
        cef_types=["host name"], example_values=["Demo_AMP"], column_name="Host Name"
    )
    install_date: str | None = OutputField(example_values=["2021-02-27T07:00:07Z"])
    internal_ips: list[str] | None = OutputField(cef_types=["ip"])
    is_compromised: bool | None = OutputField(example_values=[True])
    isolation: ListEndpointsOutputDataIsolation | None = None
    last_seen: str | None = OutputField(example_values=["2021-03-01T08:37:03Z"])
    links: ListEndpointsOutputDataLink | None = None
    network_addresses: list[ListEndpointsOutputDataNetworkAddress] | None = None
    operating_system: str | None = OutputField(column_name="Operating System")
    orbital: ListEndpointsOutputDataOrbital | None = None
    policy: ListEndpointsOutputDataPolicy | None = None
    windows_processor_id: str | None = OutputField(example_values=["8e03697a1d25bf4"])


class ListEndpointsOutputMetadataLink(APIResponse):
    self: str | None = None


class ListEndpointsOutputMetadataResult(APIResponse):
    current_item_count: int | None = None
    index: int | None = None
    items_per_page: int | None = None
    total: int | None = None


class ListEndpointsOutputMetadata(APIResponse):
    links: ListEndpointsOutputMetadataLink | None = None
    results: ListEndpointsOutputMetadataResult | None = None


class ListEndpointsOutput(APIResponse):
    data: list[ListEndpointsOutputData] | None = None
    metadata: ListEndpointsOutputMetadata | None = None
    version: str | None = None


class ListEndpointsSummary(ActionOutput):
    total_endpoints: int


def list_endpoints(
    params: ListEndpointsParams, soar: SOARClient[ListEndpointsSummary], asset: Asset
) -> ListEndpointsOutput:
    """List every endpoint connected to FireAMP."""
    with get_client(asset) as client:
        response = paginate(client, "/v1/computers")
    total = (
        response.get("metadata", {})
        .get("results", {})
        .get("total", len(response["data"]))
    )
    soar.set_summary(ListEndpointsSummary(total_endpoints=total))
    return ListEndpointsOutput.model_validate(response)
