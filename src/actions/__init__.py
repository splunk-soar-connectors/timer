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
"""Register Timer actions."""

from soar_sdk.action_results import ActionOutput
from soar_sdk.app import App

from ..asset import Asset
from .on_poll import PollParams, run_on_poll


def register_actions(app: App) -> App:
    def on_poll(params: PollParams, asset: Asset):
        return run_on_poll(params, asset, app)

    app.register_action(
        action=on_poll,
        name="on poll",
        identifier="on_poll",
        description="Create one empty event to kick off a playbook",
        action_type="ingest",
        read_only=True,
        params_class=PollParams,
        output_class=ActionOutput,
    )
    return app
