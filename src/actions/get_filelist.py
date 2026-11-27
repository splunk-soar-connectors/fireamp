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
from ..client import get_client, paginate
from ..helpers import file_list_guid
from ..models import APIResponse

# Contract correction: The legacy file_count, file_list_guid, file_list_name and total_endpoints summaries are inapplicable: this handler produces total_hashes.


class GetFilelistParams(Params):
    file_list_guid: str | None = Param(
        description="File List GUID on FireAMP",
        primary=True,
        cef_types=["fireamp file list guid"],
        default=None,
    )
    name: str | None = Param(description="File list name", default=None)
    type: str | None = Param(
        description="File list type",
        value_list=["application_blocking", "simple_custom_detections"],
        default=None,
    )


class GetFilelistOutputDataItemLink(APIResponse):
    file_list: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/file_lists/81486554-e6ef-4a57-90ee-bc564a98a94e"
        ],
        column_name="Link",
    )


class GetFilelistOutputDataItem(APIResponse):
    description: str | None = OutputField(
        example_values=["Manual add"], column_name="Description"
    )
    links: GetFilelistOutputDataItemLink | None = None
    sha256: str | None = OutputField(
        cef_types=["sha256"],
        example_values=[
            "ad3f8b790a9012c3ab113501a0d31b6ca5af6a07f7ac5ee745c4bbd5757e2cb3"  # pragma: allowlist secret
        ],
        column_name="SHA256",
    )


class GetFilelistOutputDataPolicieLink(APIResponse):
    policy: str | None = OutputField(cef_types=["url"])


class GetFilelistOutputDataPolicy(APIResponse):
    guid: str | None = None
    links: GetFilelistOutputDataPolicieLink | None = None
    name: str | None = OutputField(example_values=["Test hash list"])


class GetFilelistOutputData(APIResponse):
    guid: str | None = OutputField(
        cef_types=["fireamp file list guid"],
        example_values=["81486554-e6ef-4a57-90ee-bc564a98a94e"],
    )
    items: list[GetFilelistOutputDataItem] | None = None
    name: str | None = None
    policies: list[GetFilelistOutputDataPolicy] | None = None


class GetFilelistOutputMetadataLink(APIResponse):
    self: str | None = OutputField(cef_types=["url"])


class GetFilelistOutputMetadataResult(APIResponse):
    current_item_count: int | None = None
    index: int | None = None
    items_per_page: int | None = None
    total: int | None = None


class GetFilelistOutputMetadata(APIResponse):
    links: GetFilelistOutputMetadataLink | None = None
    results: GetFilelistOutputMetadataResult | None = None


class GetFilelistOutput(APIResponse):
    data: GetFilelistOutputData | None = None
    metadata: GetFilelistOutputMetadata | None = None
    version: str | None = None


class GetFilelistSummary(ActionOutput):
    total_hashes: int


def get_filelist(
    params: GetFilelistParams, soar: SOARClient[GetFilelistSummary], asset: Asset
) -> GetFilelistOutput:
    """Get every file from a list selected by GUID or name and type."""
    with get_client(asset) as client:
        file_list = file_list_guid(
            client, params.file_list_guid, params.name, params.type
        )
        response = paginate(
            client, f"/v1/file_lists/{file_list}/files", nested_key="items"
        )
    total = (
        response.get("metadata", {})
        .get("results", {})
        .get("total", len(response["data"]["items"]))
    )
    soar.set_summary(GetFilelistSummary(total_hashes=total))
    return GetFilelistOutput.model_validate(response)
