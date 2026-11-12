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
"""Timer asset configuration."""

from soar_sdk.asset import AssetField, BaseAsset, FieldCategory


class Asset(BaseAsset):
    event_name: str = AssetField(description="Name of the created event", default="$label created on $now", category=FieldCategory.INGEST)
    severity: str = AssetField(description="Severity of the created event", required=False, default="medium", category=FieldCategory.INGEST)
    sensitivity: str = AssetField(
        description="Sensitivity of the created event",
        required=False,
        default="amber",
        value_list=["white", "green", "amber", "red"],
        category=FieldCategory.INGEST,
    )
