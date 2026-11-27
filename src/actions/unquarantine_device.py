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
from soar_sdk.action_results import OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..client import get_client
from ..helpers import isolation
from ..models import APIResponse


# Legacy scalar action_result.data/summary paths are inapplicable: the SDK
# owns these structured result containers. Isolation has no action summary.
class UnquarantineDeviceParams(Params):
    connector_guid: str = Param(
        description="Connector GUID on endpoint",
        primary=True,
        cef_types=["fireamp connector guid"],
        column_name="Connector GUID",
    )


class UnquarantineDeviceOutputData(APIResponse):
    available: bool | None = None
    comment: str | None = None
    isolated_by: str | None = OutputField(
        example_values=["User"], column_name="Isolated By"
    )
    status: str | None = OutputField(column_name="Device Status")
    unlock_code: str | None = None


class UnquarantineDeviceOutputMetadataLink(APIResponse):
    self: str | None = None


class UnquarantineDeviceOutputMetadata(APIResponse):
    links: UnquarantineDeviceOutputMetadataLink | None = None


class UnquarantineDeviceOutput(APIResponse):
    data: UnquarantineDeviceOutputData | None = None
    version: str | None = OutputField(column_name="Version")
    metadata: UnquarantineDeviceOutputMetadata | None = None


def unquarantine_device(
    params: UnquarantineDeviceParams, soar: SOARClient, asset: Asset
) -> UnquarantineDeviceOutput:
    """Stop endpoint isolation."""
    with get_client(asset) as client:
        response = isolation(client, params.connector_guid, start=False)
    soar.set_message(f"Success: stop quarantine on {params.connector_guid}")
    return UnquarantineDeviceOutput.model_validate(response)
