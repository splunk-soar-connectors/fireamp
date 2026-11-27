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
from soar_sdk.params import Params

from ..asset import Asset
from ..client import get_client, paginate
from ..models import APIResponse


class ListGroupsParams(Params):
    pass


class ListGroupsOutputDataLink(APIResponse):
    group: str | None = OutputField(cef_types=["url"])


class ListGroupsOutputData(APIResponse):
    description: str | None = None
    guid: str | None = OutputField(column_name="Group GUID")
    links: ListGroupsOutputDataLink | None = None
    name: str | None = OutputField(column_name="Group Name")
    source: str | None = OutputField(column_name="Source")


class ListGroupsOutputMetadataLink(APIResponse):
    self: str | None = OutputField(cef_types=["url"])


class ListGroupsOutputMetadataResult(APIResponse):
    current_item_count: int | None = None
    index: int | None = None
    items_per_page: int | None = None
    total: int | None = None


class ListGroupsOutputMetadata(APIResponse):
    links: ListGroupsOutputMetadataLink | None = None
    results: ListGroupsOutputMetadataResult | None = None


class ListGroupsOutput(APIResponse):
    data: list[ListGroupsOutputData] | None = None
    metadata: ListGroupsOutputMetadata | None = None
    version: str | None = OutputField(example_values=["v1.2.0"], column_name="Version")


class ListGroupsSummary(ActionOutput):
    group_count: int


def list_groups(
    params: ListGroupsParams, soar: SOARClient[ListGroupsSummary], asset: Asset
) -> ListGroupsOutput:
    """Retrieve all matching group records."""
    with get_client(asset) as client:
        response = paginate(client, "/v1/groups", params={})
    count = len(response["data"])
    soar.set_summary(ListGroupsSummary(group_count=count))
    soar.set_message(f"Found {count} groups")
    return ListGroupsOutput.model_validate(response)
