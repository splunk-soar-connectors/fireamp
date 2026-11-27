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
from ..helpers import file_list_guid
from ..models import APIResponse


class FindListitemParams(Params):
    hash: str = Param(
        description="File hash (sha256)", primary=True, cef_types=["sha256"]
    )
    file_list_guid: str | None = Param(
        description="File List GUID on FireAMP",
        primary=True,
        cef_types=["fireamp file list guid"],
        default=None,
    )
    name: str | None = Param(
        description="File list name to find the file list GUID", default=None
    )
    type: str | None = Param(
        description="File list type to find the file list GUID",
        value_list=["application_blocking", "simple_custom_detections"],
        default=None,
    )


class FindListitemOutputDataLink(APIResponse):
    file_list: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/file_lists/81486554-e6ef-4a57-90ee-bc564a98a94e"
        ],
        column_name="Link",
    )


class FindListitemOutputData(APIResponse):
    description: str | None = OutputField(
        example_values=["Manual add"], column_name="Description"
    )
    guid: str | None = OutputField(
        cef_types=["fireamp file list guid"],
        example_values=["81486554-e6ef-4a57-90ee-bc564a98a94e"],
    )
    links: FindListitemOutputDataLink | None = None
    sha256: str | None = OutputField(
        cef_types=["sha256"],
        example_values=[
            "ad3f8b790a9012c3ab113501a0d31b6ca5af6a07f7ac5ee745c4bbd5757e2cb3"  # pragma: allowlist secret
        ],
        column_name="SHA256",
    )
    source: str | None = OutputField(
        example_values=["Created by entering SHA-256 via Web from 23.251.93.203."],
        column_name="Source",
    )


class FindListitemOutputMetadataLink(APIResponse):
    self: str | None = OutputField(cef_types=["url"])


class FindListitemOutputMetadata(APIResponse):
    links: FindListitemOutputMetadataLink | None = None


class FindListitemOutput(APIResponse):
    data: FindListitemOutputData | None = None
    metadata: FindListitemOutputMetadata | None = None
    version: str | None = None


class FindListitemSummary(ActionOutput):
    file_found: bool


def find_listitem(
    params: FindListitemParams, soar: SOARClient[FindListitemSummary], asset: Asset
) -> FindListitemOutput:
    """File found."""
    with get_client(asset) as client:
        file_list = file_list_guid(
            client, params.file_list_guid, params.name, params.type
        )
        response = request_json(
            client,
            f"/v1/file_lists/{file_list}/files/{params.hash}",
            method="GET",
            allow_duplicate=False,
        )
    soar.set_summary(FindListitemSummary(file_found=True))
    soar.set_message("File found")
    return FindListitemOutput.model_validate(response)
