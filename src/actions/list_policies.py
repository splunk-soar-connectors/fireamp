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
from ..models import APIResponse

# Contract correction: The legacy data.install_date path is inapplicable: policies are returned in data[], not a computer object.


class ListPoliciesParams(Params):
    name: str | None = Param(description="Policy Name Filter", default=None)
    product: str | None = Param(description="Product Name Filter", default=None)


class ListPoliciesOutputDataLink(APIResponse):
    policy: str | None = OutputField(cef_types=["url"])


class ListPoliciesOutputData(APIResponse):
    default: bool | None = None
    description: str | None = OutputField(column_name="Description")
    guid: str | None = OutputField(column_name="Policy GUID")
    links: ListPoliciesOutputDataLink | None = None
    name: str | None = OutputField(column_name="Policy Name")
    product: str | None = OutputField(column_name="Product")
    serial_number: int | None = OutputField(example_values=[23])


class ListPoliciesOutputMetadataLink(APIResponse):
    next: str | None = OutputField(cef_types=["url"])
    prev: str | None = OutputField(cef_types=["url"])
    self: str | None = OutputField(
        example_values=["https://api.amp.sourcefire.com/v1/policies?name%5B%5D=windows"]
    )


class ListPoliciesOutputMetadataResult(APIResponse):
    current_item_count: int | None = None
    index: int | None = None
    items_per_page: int | None = None
    total: int | None = None


class ListPoliciesOutputMetadata(APIResponse):
    links: ListPoliciesOutputMetadataLink | None = None
    results: ListPoliciesOutputMetadataResult | None = None


class ListPoliciesOutput(APIResponse):
    data: list[ListPoliciesOutputData] | None = None
    metadata: ListPoliciesOutputMetadata | None = None
    version: str | None = OutputField(example_values=["v1.2.0"])


class ListPoliciesSummary(ActionOutput):
    policy_count: int


def list_policies(
    params: ListPoliciesParams, soar: SOARClient[ListPoliciesSummary], asset: Asset
) -> ListPoliciesOutput:
    """Retrieve all matching policy records."""
    with get_client(asset) as client:
        response = paginate(
            client,
            "/v1/policies",
            params={
                key + "[]": value
                for key, value in {
                    "name": params.name,
                    "product": params.product,
                }.items()
                if value
            },
        )
    count = len(response["data"])
    soar.set_summary(ListPoliciesSummary(policy_count=count))
    soar.set_message(f"Found {count} policies")
    return ListPoliciesOutput.model_validate(response)
