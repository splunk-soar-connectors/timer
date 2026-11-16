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

from collections.abc import Iterator

from soar_sdk.app import App
from soar_sdk.models.container import Container
from soar_sdk.params import OnPollParams

from ..asset import Asset
from .on_poll import run_on_poll


def register_actions(app: App) -> App:
    @app.on_poll()
    def on_poll(params: OnPollParams, asset: Asset) -> Iterator[Container]:
        """Create one empty event to kick off a playbook."""
        yield from run_on_poll(params, asset, app)

    return app
