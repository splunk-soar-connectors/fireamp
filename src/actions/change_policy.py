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
from ..helpers import choose_guid
from ..models import APIResponse


class ChangePolicyParams(Params):
    policy_guid: str | None = Param(description="Windows policy GUID", default=None)
    policy_name: str | None = Param(description="Windows policy name", default=None)
    group_guid: str | None = Param(description="Group GUID", default=None)
    group_name: str | None = Param(description="Group name", default=None)


class ChangePolicyOutput(APIResponse):
    policy_changed: bool | None = None
    policy_guid: str | None = OutputField(column_name="Group Policy GUID")


class ChangePolicySummary(ActionOutput):
    policy_changed: bool = OutputField(column_name="Group Policy Changed")
    policy_guid: str = OutputField(column_name="Group Policy GUID")


def change_policy(
    params: ChangePolicyParams, soar: SOARClient[ChangePolicySummary], asset: Asset
) -> ChangePolicyOutput:
    """Change the Windows policy for a group."""
    with get_client(asset) as client:
        group = choose_guid(
            client, params.group_guid, params.group_name, "group", strict=True
        )
        policy = choose_guid(
            client, params.policy_guid, params.policy_name, "policy", strict=True
        )
        request_json(
            client,
            f"/v1/groups/{group}",
            method="PATCH",
            json={"windows_policy_guid": policy},
        )
    soar.set_summary(ChangePolicySummary(policy_changed=True, policy_guid=policy))
    soar.set_message("Successfully changed windows policy")
    return ChangePolicyOutput(policy_changed=True, policy_guid=policy)
