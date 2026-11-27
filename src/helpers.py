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
from typing import Any
from uuid import UUID

import httpx
from soar_sdk.exceptions import ActionFailure

from .client import paginate, request_json
from .security import canonical_uuid4, unique_exact_guid


def guid(value: str, parameter: str, *, canonical: bool = False) -> str:
    """Validate UUIDs; retain the legacy strict UUID4 checks where used."""
    try:
        if canonical:
            return canonical_uuid4(value, parameter)
        UUID(value, version=4)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ActionFailure(f"Parameter {parameter} failed validation") from exc
    return value


def resolve_named_guid(client: httpx.Client, name: str, resource: str) -> str:
    query = (
        {"name": name}
        if resource == "group"
        else {"name[]": name, "product[]": "windows"}
    )
    endpoint = "/v1/groups" if resource == "group" else "/v1/policies"
    response = paginate(client, endpoint, params=query)
    try:
        return unique_exact_guid(response.get("data", []), name, resource)
    except ValueError as exc:
        raise ActionFailure(str(exc)) from exc


def choose_guid(
    client: httpx.Client,
    value: str | None,
    name: str | None,
    resource: str,
    *,
    strict: bool = False,
) -> str:
    if value and name:
        raise ActionFailure(
            f"Provide either a {resource} name or {resource} guid, not both"
        )
    if not (value or name):
        raise ActionFailure(f"Provide either a {resource} name or {resource} guid")
    if name:
        return resolve_named_guid(client, name, resource)
    if value is None:
        raise ActionFailure(f"Missing {resource} guid")
    return guid(value, f"{resource}_guid", canonical=strict)


def file_list_guid(
    client: httpx.Client, value: str | None, name: str | None, list_type: str | None
) -> str:
    if value:
        return guid(value, "file_list_guid")
    if not name or not list_type:
        raise ActionFailure(
            "Either type and name, or GUID are required for retrieving a file list"
        )
    if list_type not in {"application_blocking", "simple_custom_detections"}:
        raise ActionFailure("Invalid file list type")
    response = paginate(client, f"/v1/file_lists/{list_type}")
    matches = [
        item["guid"]
        for item in response["data"]
        if item.get("name", "").lower() == name.lower()
    ]
    if not matches:
        raise ActionFailure(f"File list ({name}) not found")
    return str(matches[0])


def hunt(
    client: httpx.Client, query: str, *, check_execution: bool = False
) -> dict[str, Any]:
    response = paginate(client, "/v1/computers/activity", params={"q": query})
    if check_execution:
        for computer in response["data"]:
            details = {
                "executed": False,
                "file_name": "",
                "file_path": "",
                "message": "File not executed",
            }
            computer["file_execution_details"] = details
            try:
                trajectory = paginate(
                    client,
                    f"/v1/computers/{computer['connector_guid']}/trajectory",
                    params={"q": query},
                    nested_key="events",
                )
            except ActionFailure as exc:
                details["message"] = (
                    f"Unable to retrieve execution details. Details - {exc}"
                )
                continue
            for event in trajectory.get("data", {}).get("events", []):
                file = event.get("file", {})
                if (
                    event.get("event_type") == "Executed by"
                    and file.get("identity", {}).get("sha256") == query
                ):
                    details.update(
                        executed=True,
                        file_name=file.get("file_name", ""),
                        file_path=file.get("file_path", ""),
                        message="File executed",
                    )
    return response


def isolation(
    client: httpx.Client, connector_guid: str, *, start: bool
) -> dict[str, Any]:
    connector_guid = guid(connector_guid, "connector_guid")
    method = "PUT" if start else "DELETE"
    try:
        return (
            request_json(
                client, f"/v1/computers/{connector_guid}/isolation", method=method
            )
            or {}
        )
    except ActionFailure as exc:
        action = "start" if start else "stop"
        raise ActionFailure(
            f"Failed to {action} quarantine on {connector_guid}. Details: {exc}"
        ) from exc
