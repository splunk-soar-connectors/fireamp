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
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Params

from ..asset import Asset
from ..client import get_client, paginate
from ..models import APIResponse

# Contract correction: The legacy empty-list response envelope is inapplicable to the declared list-row schema: no file lists now returns no rows.


class ListFilelistsParams(Params):
    pass


class ListFilelistsOutputLink(APIResponse):
    file_list: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/file_lists/81486554-e6ef-4a57-90ee-bc564a98a94e"
        ],
    )


class ListFilelistsOutput(APIResponse):
    guid: str | None = OutputField(
        cef_types=["fireamp file list guid"],
        example_values=["81486554-e6ef-4a57-90ee-bc564a98a94e"],
        column_name="File List GUID",
    )
    links: ListFilelistsOutputLink | None = None
    name: str | None = OutputField(
        example_values=["Test hash list"], column_name="File List Name"
    )
    type: str | None = OutputField(
        example_values=["application_blocking"], column_name="File List Type"
    )


class ListFilelistsSummary(ActionOutput):
    total_lists: int


def list_filelists(
    params: ListFilelistsParams, soar: SOARClient[ListFilelistsSummary], asset: Asset
) -> list[ListFilelistsOutput]:
    """List application-blocking and custom-detection file lists."""
    rows: list[ListFilelistsOutput] = []
    total = 0
    completed_endpoint = False
    with get_client(asset) as client:
        for list_type in ("application_blocking", "simple_custom_detections"):
            try:
                response = paginate(client, f"/v1/file_lists/{list_type}")
            except ActionFailure as exc:
                if not completed_endpoint:
                    raise

                # This action combines two independent requests. Preserve the
                # first response's rows and summary if the second request fails,
                # matching the legacy partial-result behavior.
                # ActionResult is used only here because the regular ActionOutput
                # contract cannot express partial data with a failed status.
                result = ActionResult(
                    status=False,
                    message=str(exc),
                    param=params.model_dump(),
                )
                for row in rows:
                    result.add_data(row.model_dump(by_alias=True))
                result.set_summary(ListFilelistsSummary(total_lists=total).model_dump())
                return result
            rows.extend(
                ListFilelistsOutput.model_validate(row) for row in response["data"]
            )
            total += int(
                response.get("metadata", {})
                .get("results", {})
                .get("total", len(response["data"]))
            )
            completed_endpoint = True
    soar.set_summary(ListFilelistsSummary(total_lists=total))
    return rows
