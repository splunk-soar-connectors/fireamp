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
from urllib.parse import urlsplit

import httpx
from soar_sdk import logging
from soar_sdk.auth import BasicAuth
from soar_sdk.exceptions import ActionFailure

from .asset import DEFAULT_BASE_URL, Asset

DEFAULT_TIMEOUT = 30
DUPLICATE_FILE_HASH = "Hash already in list"


def get_client(
    asset: Asset, *, verify: bool = True, timeout: int = DEFAULT_TIMEOUT
) -> httpx.Client:
    """Use the same asset authentication for named and generic actions."""
    base_url = (asset.base_url or DEFAULT_BASE_URL).rstrip("/")
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ActionFailure(
            "Base URL must be an HTTP(S) URL without credentials, query parameters or a fragment"
        )
    return httpx.Client(
        base_url=base_url,
        auth=BasicAuth(asset.api_client_id, asset.api_key),
        headers={"Accept": "application/json"},
        timeout=timeout,
        verify=verify,
        follow_redirects=False,
    )


def relative_endpoint(endpoint: str) -> str:
    """Keep asset credentials on the configured API service."""
    endpoint = endpoint.strip()
    parsed = urlsplit(endpoint)
    if (
        not endpoint
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or endpoint.startswith("//")
        or "\\" in endpoint
    ):
        raise ActionFailure(
            "Endpoint must be an API path relative to the asset Base URL, for example /v1/computers"
        )
    return "/" + endpoint.lstrip("/")


def send_request(
    client: httpx.Client, endpoint: str, *, method: str = "GET", **kwargs: Any
) -> httpx.Response:
    logging.progress("Making API call")
    try:
        return client.request(method, relative_endpoint(endpoint), **kwargs)
    except (httpx.HTTPError, ValueError) as exc:
        raise ActionFailure(f"REST call to server failed: {exc}") from exc


def request_json(
    client: httpx.Client,
    endpoint: str,
    *,
    method: str = "GET",
    params: dict[str, Any] | None = None,
    json: dict[str, Any] | None = None,
    allow_duplicate: bool = False,
) -> dict[str, Any] | None:
    """Return a successful object response; None denotes an allowed duplicate hash."""
    response = send_request(client, endpoint, method=method, params=params, json=json)
    if allow_duplicate and response.status_code == 409:
        return None
    if not response.is_success:
        if response.status_code == 404 and "/computers" in endpoint:
            raise ActionFailure("Specified endpoint not found")
        if response.status_code == 404 and "/file_lists" in endpoint:
            message = (
                "Specified file list not found"
                if method == "POST"
                else "File not found in specified list. Verify list and file."
            )
            raise ActionFailure(message)
        try:
            payload = response.json()
            error = payload.get("error", {})
            details = (
                error.get("message")
                or payload.get("errors", [{}])[0].get("details", [response.text])[0]
            )
        except (ValueError, TypeError, AttributeError, IndexError):
            details = response.text or response.reason_phrase
        raise ActionFailure(
            f"Error processing request (HTTP {response.status_code}): {details}"
        )
    # DELETE endpoints can return 204 without a JSON body.
    if response.status_code == 204:
        return {}
    try:
        payload = response.json()
    except ValueError as exc:
        raise ActionFailure(
            "Error while parsing response: expected JSON from Secure Endpoint"
        ) from exc
    if not isinstance(payload, dict):
        raise ActionFailure(
            "Invalid response returned by Secure Endpoint: expected a JSON object"
        )
    return payload


def paginate(
    client: httpx.Client,
    endpoint: str,
    *,
    params: dict[str, Any] | None = None,
    nested_key: str | None = None,
) -> dict[str, Any]:
    """Collect all pages, including nested file-list items and trajectory events."""
    query = dict(params or {})
    response = request_json(client, endpoint, params=query)
    if response is None:
        raise ActionFailure("Invalid empty response from Secure Endpoint")
    data = response.get("data")
    items = data.get(nested_key) if nested_key and isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ActionFailure("Invalid pagination response returned by Secure Endpoint")
    try:
        results = response.get("metadata", {}).get("results", {})
        total = int(results.get("total", len(items)))
        offset = int(query.get("offset", 0))
        if total < 0 or offset < 0:
            raise ValueError("Negative pagination value")
    except (TypeError, ValueError, AttributeError) as exc:
        raise ActionFailure(
            "Invalid pagination metadata returned by Secure Endpoint"
        ) from exc
    next_offset = offset + len(items)
    if not items and next_offset < total:
        raise ActionFailure(
            "Secure Endpoint pagination stopped before all results were returned"
        )
    while next_offset < total:
        page = request_json(client, endpoint, params={**query, "offset": next_offset})
        page_data = page.get("data") if page else None
        page_items = (
            page_data.get(nested_key)
            if nested_key and isinstance(page_data, dict)
            else page_data
        )
        if not isinstance(page_items, list) or not page_items:
            raise ActionFailure(
                "Secure Endpoint pagination stopped before all results were returned"
            )
        items.extend(page_items)
        next_offset += len(page_items)
    return response
