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
from soar_sdk.app import App

from .actions import register_actions
from .asset import Asset
from .test_connectivity import test_connectivity


def create_fireamp_app() -> App:
    app = App(
        name="FireAMP",
        app_type="endpoint",
        logo="logo_cisco.svg",
        logo_dark="logo_cisco_dark.svg",
        product_vendor="Cisco Systems",
        product_name="FireAMP",
        publisher="Splunk",
        appid="897890aa-14f5-4d6c-b68c-e557ff30d251",
        python_version="3.13",
        min_phantom_version="7.0.0",
        fips_compliant=True,
        asset_cls=Asset,
    )
    # The SDK owns the connectivity identifier (legacy: test_asset_connectivity).
    app.test_connectivity()(test_connectivity)
    return register_actions(app)


app = create_fireamp_app()

if __name__ == "__main__":
    app.cli()
