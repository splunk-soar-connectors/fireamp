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

from uuid import UUID


def canonical_uuid4(value, parameter_name):
    """Return a canonical UUID4 string or raise a parameter-specific error."""
    try:
        parsed = UUID(str(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"Parameter {parameter_name} failed validation") from exc
    if parsed.version != 4 or str(parsed) != str(value).casefold():
        raise ValueError(f"Parameter {parameter_name} failed validation")
    return str(parsed)


def unique_exact_guid(items, requested_name, resource_name):
    """Resolve exactly one case-sensitive resource name to its GUID."""
    matches = [item.get("guid") for item in items if item.get("name") == requested_name and item.get("guid")]
    if not matches:
        raise ValueError(f"Unable to find specified {resource_name}")
    if len(matches) > 1:
        raise ValueError(f"More than one {resource_name} exactly matched the requested name")
    return matches[0]
