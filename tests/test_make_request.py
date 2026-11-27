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
import json

import httpx
import pytest


@pytest.mark.parametrize(
    "method", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
)
def test_generic_request_supports_all_methods_and_returns_raw_http_error(
    mock_api, run_action, method
):
    requests, options = mock_api(
        lambda request: httpx.Response(429, text="rate limited")
    )
    result = run_action(
        "make_request",
        http_method=method,
        endpoint="/v2/arbitrary/resource?existing=1",
        query_parameters='{"name":"a & b","tag":["one","two"]}',
        headers='{"X-Custom":"value","content-type":"application/json","Authorization":"ignored"}',
        body='{"flag": false}',
        timeout=12,
        verify_ssl=False,
    )
    assert result.get_status(), result.get_message()
    assert result.get_data() == [{"status_code": 429, "response_body": "rate limited"}]
    assert requests[0].method == method
    assert requests[0].url.host == "api.amp.cisco.com"
    assert requests[0].url.path == "/v2/arbitrary/resource"
    assert requests[0].url.params["existing"] == "1"
    assert requests[0].url.params["name"] == "a & b"
    assert requests[0].url.params.get_list("tag") == ["one", "two"]
    assert requests[0].headers["X-Custom"] == "value"
    assert requests[0].headers["Authorization"].startswith("Basic ")
    assert json.loads(requests[0].content) == {"flag": False}
    assert options[-1]["timeout"] == 12
    assert options[-1]["verify"] is False


@pytest.mark.parametrize("query", ["?q=one&q=two", "q=one&q=two"])
def test_query_string_supports_repeated_keys(mock_api, run_action, query):
    requests, _ = mock_api(lambda request: httpx.Response(200, text="ok"))
    result = run_action(
        "make_request",
        http_method="GET",
        endpoint="v1/events?start=1",
        query_parameters=query,
    )
    assert result.get_status(), result.get_message()
    assert requests[0].url.params.get_list("q") == ["one", "two"]
    assert requests[0].url.params["start"] == "1"


@pytest.mark.parametrize("body", ["[]", '[{"key":1}]', '"text"', "false", "0", "null"])
def test_json_body_preserves_all_json_types(mock_api, run_action, body):
    requests, _ = mock_api(lambda request: httpx.Response(204))
    result = run_action(
        "make_request", http_method="POST", endpoint="/v1/resource", body=body
    )
    assert result.get_status(), result.get_message()
    assert requests[0].content.decode() == body
    assert result.get_data() == [{"status_code": 204, "response_body": ""}]


def test_custom_content_type_accepts_form_body_and_text_response(mock_api, run_action):
    requests, _ = mock_api(lambda request: httpx.Response(200, text="not JSON"))
    result = run_action(
        "make_request",
        http_method="POST",
        endpoint="/v1/resource",
        body="name=a&name=b",
        headers='{"content-type":"application/x-www-form-urlencoded"}',
    )
    assert result.get_status()
    assert requests[0].content == b"name=a&name=b"
    assert result.get_data()[0]["response_body"] == "not JSON"


@pytest.mark.parametrize(
    "parameters",
    [
        {"endpoint": "https://other.example/v1/events"},
        {"endpoint": "//other.example/v1/events"},
        {"endpoint": "/v1/events#fragment"},
        {"endpoint": "\\other.example"},
        {"endpoint": ""},
        {"headers": "not-json"},
        {"headers": "[]"},
        {"headers": '{"X-Custom": 1}'},
        {"query_parameters": "[]"},
        {"query_parameters": "null"},
        {"body": "not-json"},
        {"timeout": 0},
        {"timeout": -1},
    ],
)
def test_invalid_generic_inputs_fail_before_sending(mock_api, run_action, parameters):
    requests, _ = mock_api(lambda request: pytest.fail("Unexpected HTTP request"))
    result = run_action(
        "make_request",
        **({"http_method": "GET", "endpoint": "/v1/events"} | parameters),
    )
    assert not result.get_status()
    assert requests == []


def test_redirect_is_returned_without_forwarding_credentials(mock_api, run_action):
    requests, _ = mock_api(
        lambda request: httpx.Response(
            302, headers={"Location": "https://other.example/"}
        )
    )
    result = run_action("make_request", http_method="GET", endpoint="/v1/events")
    assert result.get_status()
    assert result.get_data()[0]["status_code"] == 302
    assert len(requests) == 1


def test_timeout_is_reported_as_action_failure(mock_api, run_action):
    def handler(request):
        raise httpx.ReadTimeout("timed out", request=request)

    mock_api(handler)
    result = run_action("make_request", http_method="GET", endpoint="/v1/events")
    assert not result.get_status()
    assert "REST call to server failed" in result.get_message()
