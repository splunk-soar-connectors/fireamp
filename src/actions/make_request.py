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
import json
from typing import Any

import httpx
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams

from ..asset import Asset
from ..client import DEFAULT_TIMEOUT, get_client, relative_endpoint, send_request


def _headers(value: str | None) -> httpx.Headers:
    headers = httpx.Headers(
        {"Accept": "application/json", "Content-Type": "application/json"}
    )
    if not value:
        return headers
    try:
        parsed = json.loads(value)
    except ValueError as exc:
        raise ActionFailure(
            "Invalid headers: provide a JSON object with string values"
        ) from exc
    if not isinstance(parsed, dict) or any(
        not isinstance(item, str) for item in parsed.values()
    ):
        raise ActionFailure("Invalid headers: provide a JSON object with string values")
    try:
        headers.update(parsed)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ActionFailure("Invalid HTTP headers") from exc
    return headers


def _query(endpoint: str, value: str | None) -> str:
    if not value:
        return endpoint
    try:
        parsed = json.loads(value)
    except ValueError:
        query = value.lstrip("?")
    else:
        if not isinstance(parsed, dict):
            raise ActionFailure(
                "Invalid query parameters: provide a JSON object or query string"
            )
        query = str(httpx.QueryParams(parsed))
    if query:
        endpoint += ("&" if "?" in endpoint else "?") + query
    return endpoint


def make_request(params: MakeRequestParams, asset: Asset) -> MakeRequestOutput:
    """Call a Secure Endpoint API path using the asset's credentials."""
    endpoint = _query(relative_endpoint(params.endpoint), params.query_parameters)
    headers = _headers(params.headers)
    timeout = params.timeout if params.timeout is not None else DEFAULT_TIMEOUT
    if timeout <= 0:
        raise ActionFailure("Timeout must be a positive number of seconds")
    method = params.http_method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise ActionFailure("Unsupported HTTP method")
    body: dict[str, Any] = {}
    if params.body:
        if "json" in headers.get("Content-Type", "").lower():
            # Validate JSON but send the supplied text, preserving arrays, scalars and null.
            try:
                json.loads(params.body)
            except ValueError as exc:
                raise ActionFailure("Invalid JSON body") from exc
        body["content"] = params.body
    with get_client(asset, verify=params.verify_ssl, timeout=timeout) as client:
        response = send_request(
            client, endpoint, method=method, headers=headers, **body
        )
    # Generic calls expose arbitrary response formats and HTTP error statuses verbatim.
    # Named-action output schemas cannot describe every possible API endpoint.
    return MakeRequestOutput(
        status_code=response.status_code, response_body=response.text
    )
