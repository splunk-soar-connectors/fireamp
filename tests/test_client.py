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
import httpx
import pytest
from soar_sdk.exceptions import ActionFailure

from src.client import get_client

from .conftest import GUID, HASH, page


@pytest.mark.parametrize(
    "status,payload,message",
    [
        (401, {"error": {"message": "bad credentials"}}, "bad credentials"),
        (403, {"errors": [{"details": ["missing scope"]}]}, "missing scope"),
        (404, {}, "Specified endpoint not found"),
        (409, {"error": {"message": "conflict"}}, "conflict"),
        (500, ["unexpected"], "HTTP 500"),
    ],
)
def test_api_failures_are_action_failures(
    mock_api, run_action, status, payload, message
):
    mock_api(lambda request: httpx.Response(status, json=payload))
    result = run_action("list_endpoints")
    assert not result.get_status()
    assert message in result.get_message()
    assert "Traceback" not in result.get_message()


@pytest.mark.parametrize(
    "status,content", [(200, b"not-json"), (200, b"[]"), (502, b"gateway unavailable")]
)
def test_non_object_and_non_json_responses_fail_cleanly(
    mock_api, run_action, status, content
):
    mock_api(lambda request: httpx.Response(status, content=content))
    result = run_action("list_endpoints")
    assert not result.get_status()
    assert "Traceback" not in result.get_message()


@pytest.mark.parametrize(
    "payload",
    [
        page([], total=1),
        {"data": [], "metadata": {"results": {"total": "invalid"}}},
        {"data": [], "metadata": {"results": None}},
        {"data": {}, "metadata": {}},
    ],
)
def test_invalid_or_incomplete_pagination_cannot_report_success(
    mock_api, run_action, payload
):
    mock_api(lambda request: httpx.Response(200, json=payload))
    result = run_action("list_endpoints")
    assert not result.get_status()
    assert "Traceback" not in result.get_message()


def test_empty_following_page_is_failure(mock_api, run_action):
    def handler(request):
        return httpx.Response(
            200,
            json=page(
                [] if "offset" in request.url.params else [{"connector_guid": GUID}],
                total=2,
            ),
        )

    requests, _ = mock_api(handler)
    result = run_action("list_endpoints")
    assert not result.get_status()
    assert len(requests) == 2


@pytest.mark.parametrize(
    "identifier,parameters",
    [
        ("get_device_info", {"connector_guid": "invalid"}),
        (
            "get_device_trajectory",
            {"connector_guid": "11111111-1111-1111-8111-111111111111"},
        ),
        ("get_device_trajectory", {"connector_guid": GUID, "days_back": -1}),
        ("block_hash", {"file_list_guid": "invalid", "hash": HASH}),
        ("find_listitem", {"hash": HASH}),
        ("change_policy", {"group_guid": GUID, "policy_guid": "invalid"}),
        (
            "change_policy",
            {"group_guid": GUID, "group_name": "name", "policy_guid": GUID},
        ),
        ("change_policy", {"group_guid": GUID}),
    ],
)
def test_invalid_mutation_targets_fail_before_http(
    mock_api, run_action, identifier, parameters
):
    requests, _ = mock_api(lambda request: pytest.fail("Unexpected API request"))
    result = run_action(identifier, **parameters)
    assert not result.get_status()
    assert requests == []


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://user:password@example.com",  # pragma: allowlist secret
        "https://example.com?key=value",
        "example.com",
    ],
)
def test_invalid_base_url_is_rejected(asset, url):
    asset.base_url = url
    with pytest.raises(ActionFailure):
        get_client(asset)
