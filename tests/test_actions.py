# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import base64
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from src.test_connectivity import test_connectivity as check_connectivity

from .conftest import GUID, HASH, OTHER_GUID, page

CASES = [
    (
        "list_endpoints",
        {},
        "GET",
        "/v1/computers",
        page([{"connector_guid": GUID}]),
        {"total_endpoints": 1},
    ),
    (
        "hunt_file",
        {"hash": HASH},
        "GET",
        "/v1/computers/activity",
        page([{"connector_guid": GUID}]),
        {"device_count": 1},
    ),
    (
        "hunt_ip",
        {"ip": "192.0.2.1"},
        "GET",
        "/v1/computers/activity",
        page([{"connector_guid": GUID}]),
        {"device_count": 1},
    ),
    (
        "hunt_url",
        {"url": "https://example.com"},
        "GET",
        "/v1/computers/activity",
        page([{"connector_guid": GUID}]),
        {"device_count": 1},
    ),
    (
        "list_groups",
        {},
        "GET",
        "/v1/groups",
        page([{"guid": GUID, "name": "group"}]),
        {"group_count": 1},
    ),
    (
        "list_policies",
        {"name": "policy", "product": "windows"},
        "GET",
        "/v1/policies",
        page([{"guid": GUID}]),
        {"policy_count": 1},
    ),
    (
        "change_policy",
        {"group_guid": GUID, "policy_guid": OTHER_GUID},
        "PATCH",
        f"/v1/groups/{GUID}",
        {},
        {"policy_changed": True, "policy_guid": OTHER_GUID},
    ),
    (
        "change_group",
        {"connector_guid": GUID, "group_guid": OTHER_GUID},
        "PATCH",
        f"/v1/computers/{GUID}",
        {},
        {"group_changed": True, "group_guid": OTHER_GUID},
    ),
    (
        "quarantine_device",
        {"connector_guid": GUID},
        "PUT",
        f"/v1/computers/{GUID}/isolation",
        {"data": {"available": True, "status": "pending_start"}},
        {},
    ),
    (
        "unquarantine_device",
        {"connector_guid": GUID},
        "DELETE",
        f"/v1/computers/{GUID}/isolation",
        {"data": {"available": True, "status": "pending_stop"}},
        {},
    ),
    (
        "find_device",
        {"hostname": "host"},
        "GET",
        "/v1/computers",
        page([{"hostname": "host"}]),
        {"total_endpoints": 1},
    ),
    (
        "get_device_info",
        {"connector_guid": GUID},
        "GET",
        f"/v1/computers/{GUID}",
        {"data": {"connector_guid": GUID}},
        {"total_endpoints": 1},
    ),
    (
        "block_hash",
        {"file_list_guid": GUID, "hash": HASH},
        "POST",
        f"/v1/file_lists/{GUID}/files/{HASH}",
        {"data": {"sha256": HASH}},
        {"file_added_to_list": True},
    ),
    (
        "allow_hash",
        {"file_list_guid": GUID, "hash": HASH},
        "POST",
        f"/v1/file_lists/{GUID}/files/{HASH}",
        {"data": {"sha256": HASH}},
        {"file_added_to_list": True},
    ),
    (
        "unblock_hash",
        {"file_list_guid": GUID, "hash": HASH},
        "DELETE",
        f"/v1/file_lists/{GUID}/files/{HASH}",
        {"data": {"description": "removed"}},
        {"file_removed_from_list": True},
    ),
    (
        "disallow_hash",
        {"file_list_guid": GUID, "hash": HASH},
        "DELETE",
        f"/v1/file_lists/{GUID}/files/{HASH}",
        {"data": {"description": "removed"}},
        {"file_removed_from_list": True},
    ),
    (
        "get_filelist",
        {"file_list_guid": GUID},
        "GET",
        f"/v1/file_lists/{GUID}/files",
        page({"items": [{"sha256": HASH}]}),
        {"total_hashes": 1},
    ),
    (
        "remove_listitem",
        {"file_list_guid": GUID, "hash": HASH},
        "DELETE",
        f"/v1/file_lists/{GUID}/files/{HASH}",
        {},
        {"file_deleted": True},
    ),
    (
        "add_listitem",
        {"file_list_guid": GUID, "hash": HASH},
        "POST",
        f"/v1/file_lists/{GUID}/files/{HASH}",
        {"data": {"sha256": HASH}},
        {"file_added": True},
    ),
    (
        "find_listitem",
        {"file_list_guid": GUID, "hash": HASH},
        "GET",
        f"/v1/file_lists/{GUID}/files/{HASH}",
        {"data": {"sha256": HASH}},
        {"file_found": True},
    ),
    (
        "get_device_trajectory",
        {"connector_guid": GUID},
        "GET",
        f"/v1/computers/{GUID}/trajectory",
        page({"events": [{"event_type": "Executed by"}]}),
        {"total_trajectories": 1},
    ),
    (
        "get_device_events",
        {"connector_guid": GUID},
        "GET",
        "/v1/events",
        page([{"event_type": "Threat Detected"}]),
        {"total_events": 1},
    ),
]


@pytest.mark.parametrize(
    "identifier,params,method,path,payload,summary",
    CASES,
    ids=[case[0] for case in CASES],
)
def test_registered_action_executes_and_emits_typed_data(
    mock_api, run_action, identifier, params, method, path, payload, summary
):
    requests, _ = mock_api(lambda request: httpx.Response(200, json=payload))
    result = run_action(identifier, **params)
    assert result.get_status(), result.get_message()
    assert result.get_data()
    assert result.get_summary() == summary
    assert len(requests) == 1
    assert requests[0].method == method
    assert requests[0].url.path == path
    assert (
        requests[0].headers["Authorization"]
        == "Basic " + base64.b64encode(b"test-client:test-key").decode()
    )
    if identifier == "change_policy":
        assert json.loads(requests[0].content) == {"windows_policy_guid": OTHER_GUID}
    elif identifier == "change_group":
        assert json.loads(requests[0].content) == {"group_guid": OTHER_GUID}
    elif identifier == "list_policies":
        assert dict(requests[0].url.params) == {
            "name[]": "policy",
            "product[]": "windows",
        }


def test_list_filelists_preserves_partial_results_when_second_endpoint_fails(
    mock_api, run_action
):
    def handler(request):
        if request.url.path.endswith("application_blocking"):
            return httpx.Response(
                200,
                json=page(
                    [{"guid": GUID, "name": "Blocking", "type": "application_blocking"}]
                ),
            )
        return httpx.Response(503, text="temporary service failure")

    requests, _ = mock_api(handler)
    result = run_action("list_filelists")

    assert not result.get_status()
    assert "temporary service failure" in result.get_message()
    assert [row["guid"] for row in result.get_data()] == [GUID]
    assert result.get_summary() == {"total_lists": 1}
    assert [request.url.path for request in requests] == [
        "/v1/file_lists/application_blocking",
        "/v1/file_lists/simple_custom_detections",
    ]


def test_lists_are_flat_rows_across_both_file_list_types(mock_api, run_action):
    def handler(request):
        name = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=page([{"guid": GUID, "name": name}]))

    requests, _ = mock_api(handler)
    result = run_action("list_filelists")
    assert result.get_status()
    assert len(result.get_data()) == 2
    assert result.get_data()[0]["guid"] == GUID
    assert result.get_summary() == {"total_lists": 2}
    assert len(requests) == 2


@pytest.mark.parametrize(
    "identifier,params,nested",
    [
        ("list_endpoints", {}, None),
        ("get_filelist", {"file_list_guid": GUID}, "items"),
        ("get_device_trajectory", {"connector_guid": GUID}, "events"),
        ("get_device_events", {"offset": 5, "limit": 1}, None),
    ],
)
def test_pagination_collects_all_pages_and_preserves_initial_offset(
    mock_api, run_action, identifier, params, nested
):
    initial = params.get("offset", 0)

    def handler(request):
        item = {"connector_guid": GUID, "sha256": HASH, "event_type": "Executed by"}
        return httpx.Response(
            200, json=page({nested: [item]} if nested else [item], total=initial + 2)
        )

    requests, _ = mock_api(handler)
    result = run_action(identifier, **params)
    assert result.get_status(), result.get_message()
    assert [int(r.url.params.get("offset", 0)) for r in requests] == [
        initial,
        initial + 1,
    ]
    assert next(iter(result.get_summary().values())) == 2
    data = result.get_data()[0]
    items = (
        data["data"][nested]
        if identifier == "get_filelist"
        else data["events"]
        if "events" in data
        else data["data"]
    )
    assert len(items) == 2
    if "limit" in params:
        assert all(r.url.params["limit"] == "1" for r in requests)


@pytest.mark.parametrize("identifier", ["block_hash", "allow_hash", "add_listitem"])
def test_duplicate_hash_is_success_without_output_rows(
    mock_api, run_action, identifier
):
    mock_api(
        lambda request: httpx.Response(409, json={"error": {"message": "duplicate"}})
    )
    result = run_action(identifier, file_list_guid=GUID, hash=HASH)
    assert result.get_status()
    assert result.get_data() == []
    assert "Hash already in list" in result.get_message()


@pytest.mark.parametrize(
    "identifier", ["unblock_hash", "disallow_hash", "remove_listitem"]
)
def test_delete_accepts_no_content(mock_api, run_action, identifier):
    mock_api(lambda request: httpx.Response(204))
    result = run_action(identifier, file_list_guid=GUID, hash=HASH)
    assert result.get_status(), result.get_message()
    assert next(iter(result.get_summary().values())) is True


def test_find_device_by_user_preserves_top_level_metadata(mock_api, run_action):
    def handler(request):
        if request.url.path.endswith("user_activity"):
            return httpx.Response(200, json=page([{"connector_guid": GUID}]))
        return httpx.Response(
            200, json={"data": {"hostname": "user-host", "internal_ips": ["192.0.2.1"]}}
        )

    mock_api(handler)
    result = run_action("find_device", user="analyst")
    assert result.get_status(), result.get_message()
    data = result.get_data()[0]
    assert data["results"]["total"] == 1
    assert data["data"][0]["hostname"] == "user-host"
    assert data["data"][0]["internal_ips"] == ["192.0.2.1"]


def test_empty_user_search(mock_api, run_action):
    mock_api(lambda request: httpx.Response(200, json=page([])))
    result = run_action("find_device", user="nobody")
    assert result.get_status()
    assert result.get_data() == []
    assert result.get_summary() == {"total_endpoints": 0}


@pytest.mark.parametrize(
    "parameters",
    [
        {},
        {"hostname": "host", "user": "name"},
        {"group_name": "name", "group_guid": GUID},
    ],
)
def test_find_device_rejects_ambiguous_or_empty_queries(
    mock_api, run_action, parameters
):
    requests, _ = mock_api(lambda request: pytest.fail("Unexpected API request"))
    result = run_action("find_device", **parameters)
    assert not result.get_status()
    assert requests == []


def test_change_policy_resolves_exact_names_across_pages(mock_api, run_action):
    def handler(request):
        if request.method == "PATCH":
            assert json.loads(request.content) == {"windows_policy_guid": OTHER_GUID}
            return httpx.Response(200, json={})
        if request.url.path.endswith("groups"):
            if "offset" not in request.url.params:
                return httpx.Response(
                    200,
                    json=page([{"name": "prod-extra", "guid": OTHER_GUID}], total=2),
                )
            return httpx.Response(
                200, json=page([{"name": "prod", "guid": GUID}], total=2)
            )
        assert request.url.path == "/v1/policies"
        assert request.url.params["product[]"] == "windows"
        return httpx.Response(200, json=page([{"name": "strict", "guid": OTHER_GUID}]))

    requests, _ = mock_api(handler)
    result = run_action("change_policy", group_name="prod", policy_name="strict")
    assert result.get_status(), result.get_message()
    assert requests[-1].url.path == f"/v1/groups/{GUID}"


def test_ambiguous_exact_name_cannot_change_group(mock_api, run_action):
    requests, _ = mock_api(
        lambda request: httpx.Response(
            200,
            json=page(
                [{"name": "prod", "guid": GUID}, {"name": "prod", "guid": OTHER_GUID}]
            ),
        )
    )
    result = run_action("change_group", connector_guid=GUID, group_name="prod")
    assert not result.get_status()
    assert "More than one group" in result.get_message()
    assert len(requests) == 1
    assert requests[0].method == "GET"


def test_file_list_lookup_is_case_insensitive(mock_api, run_action):
    def handler(request):
        if request.url.path.endswith("application_blocking"):
            return httpx.Response(200, json=page([{"name": "BlockList", "guid": GUID}]))
        return httpx.Response(200, json={"data": {"sha256": HASH}})

    requests, _ = mock_api(handler)
    result = run_action(
        "find_listitem", name="blocklist", type="application_blocking", hash=HASH
    )
    assert result.get_status(), result.get_message()
    assert requests[-1].url.path == f"/v1/file_lists/{GUID}/files/{HASH}"


def test_hunt_file_execution_uses_all_trajectory_pages(mock_api, run_action):
    def handler(request):
        if request.url.path.endswith("activity"):
            return httpx.Response(200, json=page([{"connector_guid": GUID}]))
        if "offset" not in request.url.params:
            return httpx.Response(
                200, json=page({"events": [{"event_type": "Created"}]}, total=2)
            )
        return httpx.Response(
            200,
            json=page(
                {
                    "events": [
                        {
                            "event_type": "Executed by",
                            "file": {
                                "identity": {"sha256": HASH},
                                "file_name": "bad.exe",
                                "file_path": "C:/bad.exe",
                            },
                        }
                    ]
                },
                total=2,
            ),
        )

    mock_api(handler)
    result = run_action("hunt_file", hash=HASH, check_execution=True)
    assert result.get_status(), result.get_message()
    assert result.get_data()[0]["data"][0]["file_execution_details"] == {
        "executed": True,
        "file_name": "bad.exe",
        "file_path": "C:/bad.exe",
        "message": "File executed",
    }


def test_hunt_file_execution_failure_remains_per_device(mock_api, run_action):
    def handler(request):
        return (
            httpx.Response(200, json=page([{"connector_guid": GUID}]))
            if request.url.path.endswith("activity")
            else httpx.Response(403, json={"error": {"message": "denied"}})
        )

    mock_api(handler)
    result = run_action("hunt_file", hash=HASH, check_execution=True)
    assert result.get_status()
    details = result.get_data()[0]["data"][0]["file_execution_details"]
    assert details["executed"] is False
    assert "denied" in details["message"]


def test_trajectory_age_filter_and_count(mock_api, run_action):
    now = datetime.now(UTC)
    events = [
        {"date": now.isoformat(), "event_type": "Created"},
        {"date": (now - timedelta(days=9)).isoformat(), "event_type": "Executed by"},
    ]
    mock_api(lambda request: httpx.Response(200, json=page({"events": events})))
    result = run_action(
        "get_device_trajectory", connector_guid=GUID, days_back=2, executed_only=True
    )
    assert result.get_status(), result.get_message()
    assert len(result.get_data()[0]["events"]) == 1
    assert result.get_summary() == {"total_trajectories": 1}


def test_connectivity_uses_version_endpoint(mock_api, asset):
    requests, _ = mock_api(lambda request: httpx.Response(200, json={"version": "v1"}))
    check_connectivity(asset)
    assert requests[0].url.path == "/v1/version"


def test_vendor_event_extensions_survive_typed_output(mock_api, run_action):
    event = {
        "id": 42,
        "event_type": "Executed by",
        "future_event_payload": {"value": [1, 2]},
        "command_line": {"environment": {"CUSTOM_ENV": "value"}},
    }
    mock_api(lambda request: httpx.Response(200, json=page({"events": [event]})))
    result = run_action("get_device_trajectory", connector_guid=GUID)
    assert result.get_status(), result.get_message()
    output = result.get_data()[0]["events"][0]
    assert output["id"] == "42"
    assert output["future_event_payload"] == {"value": [1, 2]}
    assert output["command_line"]["environment"]["CUSTOM_ENV"] == "value"
