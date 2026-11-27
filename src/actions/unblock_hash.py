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


class UnblockHashParams(Params):
    file_list_guid: str = Param(
        description="File List GUID on FireAMP",
        primary=True,
        cef_types=["fireamp file list guid"],
    )
    hash: str = Param(
        description="SHA256 of file to remove from file list",
        primary=True,
        cef_types=["hash", "sha256"],
        column_name="Hash",
    )


class UnblockHashOutputData(APIResponse):
    description: str | None = None


class UnblockHashOutputMetadataLink(APIResponse):
    self: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/file_lists/81486554-e6ef-4a57-90ee-bc564a98a94e/files/27b10529a38e0fd3128a84a543de108dc83c2b0e786ea81df8a8dc4a9e47a2e4"
        ],
    )


class UnblockHashOutputMetadata(APIResponse):
    links: UnblockHashOutputMetadataLink | None = None


class UnblockHashOutput(APIResponse):
    data: UnblockHashOutputData | None = None
    metadata: UnblockHashOutputMetadata | None = None
    version: str | None = OutputField(example_values=["v1.2.0"])


class UnblockHashSummary(ActionOutput):
    file_removed_from_list: bool = OutputField(column_name="File Hash Removed")


def unblock_hash(
    params: UnblockHashParams, soar: SOARClient[UnblockHashSummary], asset: Asset
) -> list[UnblockHashOutput]:
    """Remove a hash from the specified file list."""
    file_list = guid(params.file_list_guid, "file_list_guid")
    soar.set_summary(UnblockHashSummary(file_removed_from_list=False))
    with get_client(asset) as client:
        response = request_json(
            client,
            f"/v1/file_lists/{file_list}/files/{params.hash}",
            method="DELETE",
            allow_duplicate=False,
        )
    soar.set_summary(UnblockHashSummary(file_removed_from_list=True))
    soar.set_message("Hash removed from list")
    return [UnblockHashOutput.model_validate(response)]
