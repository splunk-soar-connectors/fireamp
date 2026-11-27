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
from ..client import DUPLICATE_FILE_HASH, get_client, request_json
from ..helpers import guid
from ..models import APIResponse

# Contract correction: The legacy file_hash_added summary is inapplicable: the handler only produces file_added_to_list.


class BlockHashParams(Params):
    file_list_guid: str = Param(
        description="File List GUID on FireAMP",
        primary=True,
        cef_types=["fireamp file list guid"],
    )
    hash: str = Param(
        description="SHA256 of file to add to file list",
        primary=True,
        cef_types=["hash", "sha256"],
    )


class BlockHashOutputDataLink(APIResponse):
    file_list: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/file_lists/81486554-e6ef-4a57-90ee-bc564a98a94e"
        ],
        column_name="File List Link",
    )


class BlockHashOutputData(APIResponse):
    description: str | None = None
    links: BlockHashOutputDataLink | None = None
    sha256: str | None = OutputField(
        cef_types=["hash", "sha256"],
        example_values=[
            "27b10529a38e0fd3128a84a543de108dc83c2b0e786ea81df8a8dc4a9e47a2e4"  # pragma: allowlist secret
        ],
        column_name="Hash",
    )
    source: str | None = OutputField(
        example_values=["Created by entering SHA-256 via Public api."]
    )


class BlockHashOutputMetadataLink(APIResponse):
    self: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/file_lists/81486554-e6ef-4a57-90ee-bc564a98a94e/files/27b10529a38e0fd3128a84a543de108dc83c2b0e786ea81df8a8dc4a9e47a2e4"
        ],
    )


class BlockHashOutputMetadata(APIResponse):
    links: BlockHashOutputMetadataLink | None = None


class BlockHashOutput(APIResponse):
    data: BlockHashOutputData | None = None
    metadata: BlockHashOutputMetadata | None = None
    version: str | None = OutputField(example_values=["v1.2.0"])


class BlockHashSummary(ActionOutput):
    # Legacy file_hash_added was never emitted; preserve its table label on the actual field.
    file_added_to_list: bool = OutputField(column_name="File Hash Added")


def block_hash(
    params: BlockHashParams, soar: SOARClient[BlockHashSummary], asset: Asset
) -> list[BlockHashOutput]:
    """Add a hash to the specified file list."""
    file_list = guid(params.file_list_guid, "file_list_guid")
    soar.set_summary(BlockHashSummary(file_added_to_list=False))
    with get_client(asset) as client:
        response = request_json(
            client,
            f"/v1/file_lists/{file_list}/files/{params.hash}",
            method="POST",
            allow_duplicate=True,
        )
    if response is None:
        soar.set_message(DUPLICATE_FILE_HASH)
        return []
    if not response.get("data", {}).get("sha256"):
        raise ActionFailure("Secure Endpoint did not confirm the hash was added")
    soar.set_summary(BlockHashSummary(file_added_to_list=True))
    soar.set_message("Hash added to list")
    return [BlockHashOutput.model_validate(response)]
