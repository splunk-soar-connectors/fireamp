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


class HuntFileParams(FireAMPParams):
    hash: str = Param(
        description="SHA256 of file to hunt",
        primary=True,
        cef_types=["hash", "sha256"],
        column_name="SHA256 Hash",
    )
    check_execution: bool | None = Param(
        description="Check file execution", default=None
    )


class HuntFileOutputDataFileExecutionDetail(APIResponse):
    executed: bool | None = None
    file_name: str | None = OutputField(cef_types=["file path"])
    file_path: str | None = OutputField(cef_types=["file name"])
    message: str | None = OutputField(column_name="File Execution Details")


class HuntFileOutputDataLink(APIResponse):
    computer: str | None = OutputField(cef_types=["url"])
    group: str | None = OutputField(cef_types=["url"])
    trajectory: str | None = OutputField(
        example_values=[
            "https://api.amp.sourcefire.com/v1/computers/120da585-44f6-4b50-8d29-e5a87b7548a0/trajectory?q=ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ]
    )


class HuntFileOutputData(APIResponse):
    active: bool | None = OutputField(column_name="Active")
    connector_guid: str | None = OutputField(
        cef_types=["fireamp connector guid"], column_name="Connector GUID"
    )
    file_execution_details: HuntFileOutputDataFileExecutionDetail | None = None
    hostname: str | None = OutputField(cef_types=["host name"], column_name="Host Name")
    links: HuntFileOutputDataLink | None = None
    windows_processor_id: str | None = OutputField(example_values=["04ba26ed5813f97"])


class HuntFileOutputMetadataLink(APIResponse):
    self: str | None = OutputField(cef_types=["url"])


class HuntFileOutputMetadataResult(APIResponse):
    current_item_count: int | None = None
    index: int | None = None
    items_per_page: int | None = None
    total: int | None = None


class HuntFileOutputMetadata(APIResponse):
    links: HuntFileOutputMetadataLink | None = None
    results: HuntFileOutputMetadataResult | None = None


class HuntFileOutput(APIResponse):
    data: list[HuntFileOutputData] | None = None
    metadata: HuntFileOutputMetadata | None = None
    version: str | None = None


class HuntFileSummary(ActionOutput):
    device_count: int


def hunt_file(
    params: HuntFileParams, soar: SOARClient[HuntFileSummary], asset: Asset
) -> HuntFileOutput:
    """Find endpoints with matching activity."""
    with get_client(asset) as client:
        response = hunt(
            client, params.hash, check_execution=bool(params.check_execution)
        )
    soar.set_summary(HuntFileSummary(device_count=len(response["data"])))
    return HuntFileOutput.model_validate(response)
