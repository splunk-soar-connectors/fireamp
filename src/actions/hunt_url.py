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
from soar_sdk.params import Param

from ..asset import Asset
from ..client import get_client
from ..helpers import hunt
from ..models import APIResponse
from ..params import FireAMPParams


class HuntUrlParams(FireAMPParams):
    url: str = Param(
        description="URL to hunt", primary=True, cef_types=["url"], column_name="URL"
    )


class HuntUrlOutputDataLink(APIResponse):
    computer: str | None = OutputField(cef_types=["url"])
    group: str | None = OutputField(cef_types=["url"])
    trajectory: str | None = OutputField(cef_types=["url"])


class HuntUrlOutputData(APIResponse):
    active: bool | None = OutputField(column_name="Active")
    connector_guid: str | None = OutputField(
        cef_types=["fireamp connector guid"], column_name="Connector GUID"
    )
    hostname: str | None = OutputField(cef_types=["host name"], column_name="Host Name")
    links: HuntUrlOutputDataLink | None = None


class HuntUrlOutputMetadataLink(APIResponse):
    self: str | None = OutputField(cef_types=["url"])


class HuntUrlOutputMetadataResult(APIResponse):
    current_item_count: int | None = None
    index: int | None = None
    items_per_page: int | None = None
    total: int | None = None


class HuntUrlOutputMetadata(APIResponse):
    links: HuntUrlOutputMetadataLink | None = None
    results: HuntUrlOutputMetadataResult | None = None


class HuntUrlOutput(APIResponse):
    data: list[HuntUrlOutputData] | None = None
    metadata: HuntUrlOutputMetadata | None = None
    version: str | None = None


class HuntUrlSummary(ActionOutput):
    device_count: int


def hunt_url(
    params: HuntUrlParams, soar: SOARClient[HuntUrlSummary], asset: Asset
) -> HuntUrlOutput:
    """Find endpoints with matching activity."""
    with get_client(asset) as client:
        response = hunt(client, params.url)
    soar.set_summary(HuntUrlSummary(device_count=len(response["data"])))
    return HuntUrlOutput.model_validate(response)
