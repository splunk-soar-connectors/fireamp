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
from soar_sdk.params import Params


class FireAMPParams(Params):
    """Preserve input table labels with SDK 7.3.1.

    Param accepts column_name, but SDK 7.3.1's Params schema generation
    drops it. Copy the metadata into the generated schema so SOAR can display
    the established input columns.
    """

    @classmethod
    def _to_json_schema(cls) -> dict:
        schema = super()._to_json_schema()
        for field_name, field in cls.model_fields.items():
            metadata = field.json_schema_extra
            if not isinstance(metadata, dict):
                continue
            if column_name := metadata.get("column_name"):
                schema[field.alias or field_name]["column_name"] = column_name
        return schema
