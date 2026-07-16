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

import unittest
from pathlib import Path

from fireamp_security import canonical_uuid4, unique_exact_guid


ROOT = Path(__file__).parent


class FireAmpSecurityTests(unittest.TestCase):
    def test_uuid_path_parameters_are_canonical_uuid4(self):
        value = "123e4567-e89b-42d3-a456-426614174000"
        self.assertEqual(canonical_uuid4(value, "connector_guid"), value)

        self.assertEqual(canonical_uuid4(value.upper(), "connector_guid"), value)

        for invalid in ("../audit_logs?", "123e4567-e89b-12d3-a456-426614174000"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    canonical_uuid4(invalid, "connector_guid")

    def test_name_resolution_requires_one_exact_match(self):
        items = [
            {"name": "Isolation", "guid": "exact"},
            {"name": "Isolation Exceptions", "guid": "fuzzy"},
        ]
        self.assertEqual(unique_exact_guid(items, "Isolation", "group"), "exact")

        with self.assertRaises(ValueError):
            unique_exact_guid(items, "isolation", "group")
        with self.assertRaises(ValueError):
            unique_exact_guid([*items, {"name": "Isolation", "guid": "duplicate"}], "Isolation", "group")

    def test_not_found_transport_results_are_errors(self):
        source = (ROOT / "fireamp_connector.py").read_text()

        self.assertIn("return (phantom.APP_ERROR, AMP_ENDPOINT_NOT_FOUND)", source)
        self.assertIn("return (phantom.APP_ERROR, AMP_FILE_LIST_NOT_FOUND)", source)
        self.assertIn("return (phantom.APP_ERROR, AMP_FILE_UNBLOCK_NOT_FOUND)", source)


if __name__ == "__main__":
    unittest.main()
