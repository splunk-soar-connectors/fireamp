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
from ..client import get_client
from ..helpers import hunt
from ..models import APIResponse


class HuntIpParams(Params):
    ip: str = Param(description="IP Address to hunt", primary=True, cef_types=["ip"])


class HuntIpOutputDataLink(APIResponse):
    computer: str | None = OutputField(cef_types=["url"])
    group: str | None = OutputField(cef_types=["url"])
    trajectory: str | None = OutputField(cef_types=["url"])


class HuntIpOutputData(APIResponse):
    active: bool | None = None
    connector_guid: str | None = OutputField(
        cef_types=["fireamp connector guid"], column_name="Connector GUID"
    )
    hostname: str | None = OutputField(cef_types=["host name"], column_name="Host Name")
    links: HuntIpOutputDataLink | None = None
    windows_processor_id: str | None = OutputField(
        column_name="Processor ID",
        example_values=["8792fb4e63d51a0"],  # pragma: allowlist secret
    )


class HuntIpOutputMetadataLink(APIResponse):
    self: str | None = OutputField(cef_types=["url"])


class HuntIpOutputMetadataResult(APIResponse):
    current_item_count: int | None = None
    index: int | None = None
    items_per_page: int | None = None
    total: int | None = None


class HuntIpOutputMetadata(APIResponse):
    links: HuntIpOutputMetadataLink | None = None
    results: HuntIpOutputMetadataResult | None = None


class HuntIpOutput(APIResponse):
    data: list[HuntIpOutputData] | None = None
    metadata: HuntIpOutputMetadata | None = None
    version: str | None = None


class HuntIpSummary(ActionOutput):
    device_count: int


def hunt_ip(
    params: HuntIpParams, soar: SOARClient[HuntIpSummary], asset: Asset
) -> HuntIpOutput:
    """Find endpoints with matching activity."""
    with get_client(asset) as client:
        response = hunt(client, params.ip)
    soar.set_summary(HuntIpSummary(device_count=len(response["data"])))
    return HuntIpOutput.model_validate(response)
