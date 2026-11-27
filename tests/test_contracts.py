# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
import json
from pathlib import Path

import pytest
from soar_sdk.action_results import ActionOutput
from soar_sdk.cli.manifests.processors import ManifestProcessor
from soar_sdk.params import MakeRequestParams

from src.app import app

LEGACY = json.loads(
    (Path(__file__).parent / "fixtures/legacy_contract.json").read_text()
)

# Each removed path has a contract explanation beside the action model.
REMOVED = {
    "list_policies": {"action_result.data.*.data.install_date"},
    "quarantine_device": {"action_result.data", "action_result.summary"},
    "unquarantine_device": {"action_result.data", "action_result.summary"},
    "find_device": {
        f"action_result.data.*.data.{field}"
        for field in (
            "demo",
            "install_date",
            "is_compromised",
            "isolation.available",
            "isolation.status",
            "last_seen",
            "orbital.status",
            "windows_processor_id",
        )
    },
    "get_filelist": {
        f"action_result.summary.{field}"
        for field in (
            "file_count",
            "file_list_guid",
            "file_list_name",
            "total_endpoints",
        )
    },
    "block_hash": {"action_result.summary.file_hash_added"},
    "allow_hash": {"action_result.summary.file_hash_added"},
    "add_listitem": {
        "action_result.data.*.file_added",
        "action_result.summary.file_deleted",
    },
    "get_device_trajectory": {"action_result.summary.file_found"}
    | {
        f"action_result.data.*.data.{field}"
        for field in ("description", "guid", "sha256", "source", "links.file_list")
    },
    "get_device_events": {"action_result.summary.file_found"},
}


@pytest.fixture(scope="module")
def manifest():
    return (
        ManifestProcessor("", str(Path(__file__).parent.parent))
        .build()
        .to_json_manifest()
    )


def test_app_identity_and_special_sdk_contracts(manifest):
    assert manifest["appid"] == "897890aa-14f5-4d6c-b68c-e557ff30d251"
    assert manifest["main_module"] == "src.app:app"
    assert manifest["min_phantom_version"] == "7.0.0"
    assert manifest["python_version"] == "3.13"
    assert {a["identifier"] for a in manifest["actions"]} == (
        set(LEGACY) - {"test_asset_connectivity"}
    ) | {"test_connectivity", "make_request"}
    assert app.get_actions()["make_request"].params_class is MakeRequestParams


@pytest.mark.parametrize(
    "identifier", sorted(set(LEGACY) - {"test_asset_connectivity"})
)
def test_legacy_input_and_output_recommendation_contracts(manifest, identifier):
    previous = LEGACY[identifier]
    current = next(
        action for action in manifest["actions"] if action["identifier"] == identifier
    )
    assert (current["action"], current["type"], current["read_only"]) == (
        previous["action"],
        previous["type"],
        previous["read_only"],
    )
    assert set(current["parameters"]) == set(previous["parameters"])
    for name, old in previous["parameters"].items():
        for field in (
            "data_type",
            "required",
            "primary",
            "default",
            "contains",
            "value_list",
        ):
            default = False if field in ("required", "primary") else None
            assert current["parameters"][name].get(field, default) == old.get(
                field, default
            ), (name, field)
    input_columns = {
        "hunt_file": {"hash": "SHA256 Hash"},
        "hunt_url": {"url": "URL"},
        "remove_listitem": {"hash": "File Hash"},
    }
    for name, column_name in input_columns.get(identifier, {}).items():
        assert current["parameters"][name].get("column_name") == column_name
    outputs = {field["data_path"]: field for field in current["output"]}
    missing = set(previous["outputs"]) - set(outputs)
    # Array element paths replace the old scalar declaration for actual API arrays.
    arrays = {path for path in missing if path + ".*" in outputs}
    assert missing - arrays == REMOVED.get(identifier, set())
    for path in arrays:
        old = previous["outputs"][path]
        assert outputs[path + ".*"]["data_type"] == old["data_type"]
        assert outputs[path + ".*"].get("contains", []) == old.get("contains", [])
    for path in set(previous["outputs"]) & set(outputs):
        old = previous["outputs"][path]
        expected = (
            "boolean"
            if identifier == "quarantine_device" and path.endswith("data.available")
            else old["data_type"]
        )
        assert outputs[path]["data_type"] == expected, path
        assert outputs[path].get("contains", []) == old.get("contains", []), path
    expected_columns = {
        (
            "change_policy",
            "action_result.summary.policy_changed",
        ): "Group Policy Changed",
        ("change_policy", "action_result.summary.policy_guid"): "Group Policy GUID",
        ("allow_hash", "action_result.summary.file_added_to_list"): "File Hash Added",
        ("block_hash", "action_result.summary.file_added_to_list"): "File Hash Added",
        (
            "unblock_hash",
            "action_result.summary.file_removed_from_list",
        ): "File Hash Removed",
        (
            "disallow_hash",
            "action_result.summary.file_removed_from_list",
        ): "File Hash Removed",
    }
    for (action_id, path), column_name in expected_columns.items():
        if action_id == identifier:
            assert outputs[path].get("column_name") == column_name


def test_output_models_use_standard_sdk_schema_generation():
    for action in app.get_actions().values():
        assert issubclass(action.meta.output, ActionOutput)
        assert (
            action.meta.output._to_json_schema.__func__
            is ActionOutput._to_json_schema.__func__
        )
