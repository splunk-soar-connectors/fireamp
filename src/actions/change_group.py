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
from ..helpers import choose_guid, guid
from ..models import APIResponse


class ChangeGroupParams(Params):
    connector_guid: str = Param(
        description="Connector GUID on endpoint",
        primary=True,
        cef_types=["fireamp connector guid"],
    )
    group_guid: str | None = Param(description="Group GUID", default=None)
    group_name: str | None = Param(description="Group name", default=None)


class ChangeGroupOutput(APIResponse):
    group_changed: bool | None = None
    group_guid: str | None = None


class ChangeGroupSummary(ActionOutput):
    group_changed: bool = OutputField(column_name="Group Changed")
    group_guid: str = OutputField(column_name="Group GUID")


def change_group(
    params: ChangeGroupParams, soar: SOARClient[ChangeGroupSummary], asset: Asset
) -> ChangeGroupOutput:
    """Move an endpoint to a group selected by name or GUID."""
    connector = guid(params.connector_guid, "connector_guid")
    with get_client(asset) as client:
        group = choose_guid(client, params.group_guid, params.group_name, "group")
        request_json(
            client,
            f"/v1/computers/{connector}",
            method="PATCH",
            json={"group_guid": group},
        )
    soar.set_summary(ChangeGroupSummary(group_changed=True, group_guid=group))
    soar.set_message("Successfully changed group")
    return ChangeGroupOutput(group_changed=True, group_guid=group)
