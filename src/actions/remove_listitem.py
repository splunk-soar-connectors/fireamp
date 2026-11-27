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
from ..client import get_client, request_json
from ..helpers import file_list_guid
from ..models import APIResponse
from ..params import FireAMPParams


class RemoveListitemParams(FireAMPParams):
    hash: str = Param(
        description="File hash (sha256)",
        primary=True,
        cef_types=["sha256"],
        column_name="File Hash",
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


class RemoveListitemOutput(APIResponse):
    file_deleted: bool | None = OutputField(column_name="File Deleted")


class RemoveListitemSummary(ActionOutput):
    file_deleted: bool


def remove_listitem(
    params: RemoveListitemParams, soar: SOARClient[RemoveListitemSummary], asset: Asset
) -> RemoveListitemOutput:
    """File deleted from list."""
    with get_client(asset) as client:
        file_list = file_list_guid(
            client, params.file_list_guid, params.name, params.type
        )
        request_json(
            client,
            f"/v1/file_lists/{file_list}/files/{params.hash}",
            method="DELETE",
            allow_duplicate=False,
        )
    soar.set_summary(RemoveListitemSummary(file_deleted=True))
    soar.set_message("File deleted from list")
    return RemoveListitemOutput(file_deleted=True)
