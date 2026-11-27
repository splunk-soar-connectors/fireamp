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
from types import SimpleNamespace

import httpx
import pytest

from src.app import create_fireamp_app
from src.asset import Asset

GUID = "11111111-1111-4111-8111-111111111111"
OTHER_GUID = "22222222-2222-4222-8222-222222222222"
HASH = "a" * 64


@pytest.fixture
def asset():
    return Asset(
        base_url="https://api.amp.cisco.com/",
        api_client_id="test-client",
        api_key="test-key",  # pragma: allowlist secret
    )


@pytest.fixture
def mock_api(monkeypatch):
    real_client = httpx.Client
    requests = []
    options = []

    def install(handler):
        def record(request):
            requests.append(request)
            return handler(request)

        def client(**kwargs):
            options.append(kwargs.copy())
            return real_client(transport=httpx.MockTransport(record), **kwargs)

        monkeypatch.setattr("src.client.httpx.Client", client)
        return requests, options

    return install


@pytest.fixture
def run_action(asset):
    def run(identifier, **parameters):
        app = create_fireamp_app()
        state = {"summary": None, "message": ""}
        soar = SimpleNamespace(
            set_summary=lambda summary: state.update(summary=summary),
            get_summary=lambda: state["summary"],
            set_message=lambda message: state.update(message=message),
            get_message=lambda: state["message"],
        )
        action = app.get_actions()[identifier]
        params = action.params_class(**parameters)
        status = action(params, soar=soar, asset=asset)
        result = app.actions_manager.get_results()[-1]
        assert status == result.get_status()
        return result

    return run


def page(data, total=None):
    count = len(data) if isinstance(data, list) else len(next(iter(data.values())))
    return {
        "version": "v1.2.0",
        "metadata": {"results": {"total": count if total is None else total}},
        "data": data,
    }
