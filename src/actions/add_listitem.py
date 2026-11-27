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
from ..client import DUPLICATE_FILE_HASH, get_client, request_json
from ..helpers import file_list_guid
from ..models import APIResponse

# A duplicate hash supplies no API object. Return its message without a
# fabricated string data row; normal responses use the declared object schema.
# Contract correction: The legacy data.file_added and summary.file_deleted paths are inapplicable: file_added is a summary only, and this action does not delete a file.


class AddListitemParams(Params):
    hash: str = Param(
        description="File hash (sha256)", primary=True, cef_types=["sha256"]
    )
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


class AddListitemOutputDataLink(APIResponse):
    file_list: str | None = OutputField(
        example_values=[
            "https://api.amp.sourcefire.com/v1/file_lists/93265c88-0b72-40eb-8187-7fc58b5e31f8"
        ],
        column_name="File List",
    )


class AddListitemOutputData(APIResponse):
    links: AddListitemOutputDataLink | None = None
    sha256: str | None = OutputField(
        example_values=[
            "f69fc2fd5bd864916a3285f9e3a691f6f060d430d251d18944ce3e69066d04b7"  # pragma: allowlist secret
        ],
        column_name="File Hash",
    )
    source: str | None = OutputField(
        example_values=["Created by entering SHA-256 via Public api."],
        column_name="Source",
    )


class AddListitemOutputMetadataLink(APIResponse):
    self: str | None = OutputField(
        example_values=[
            "https://api.amp.sourcefire.com/v1/file_lists/93265c88-0b72-40eb-8187-7fc58b5e31f8/files/f69fc2fd5bd864916a3285f9e3a691f6f060d430d251d18944ce3e69066d04b7"
        ]
    )


class AddListitemOutputMetadata(APIResponse):
    links: AddListitemOutputMetadataLink | None = None


class AddListitemOutput(APIResponse):
    data: AddListitemOutputData | None = None
    metadata: AddListitemOutputMetadata | None = None
    version: str | None = OutputField(example_values=["v1.2.0"])


class AddListitemSummary(ActionOutput):
    file_added: bool


def add_listitem(
    params: AddListitemParams, soar: SOARClient[AddListitemSummary], asset: Asset
) -> list[AddListitemOutput]:
    """File successfully added."""
    with get_client(asset) as client:
        file_list = file_list_guid(
            client, params.file_list_guid, params.name, params.type
        )
        response = request_json(
            client,
            f"/v1/file_lists/{file_list}/files/{params.hash}",
            method="POST",
            allow_duplicate=True,
        )
    soar.set_summary(AddListitemSummary(file_added=True))
    soar.set_message("File successfully added")
    if response is None:
        soar.set_message(DUPLICATE_FILE_HASH)
        return []
    return [AddListitemOutput.model_validate(response)]
