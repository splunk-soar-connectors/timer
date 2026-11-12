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

"""Behavior and contract checks for the SDK Timer connector."""

import json
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from src.actions.on_poll import PollParams, format_event_name
from src.app import app
from src.asset import Asset
from src.test_connectivity import logger


class TimerTests(unittest.TestCase):
    def setUp(self):
        if hasattr(app, "_asset"):
            del app._asset
        app.actions_manager.action_results = []

    def run_action(self, identifier, event_name="$label event", label="events", parameters=None, **config):
        asset_config = {
            "app_version": "2.0.23",
            "directory": ".",
            "main_module": "src.app:app",
            "event_name": event_name,
            "ingest": {"container_label": label},
            **config,
        }
        app.handle(json.dumps({"identifier": identifier, "asset_id": "123", "config": asset_config, "parameters": [parameters or {}]}))
        return app.actions_manager.get_results()[-1]

    def test_format_event_name_preserves_token_boundaries_and_literal_label(self):
        fixed_now = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
        name = format_event_name("$label on $now; before$label after$now; $label", r"A\1$now", fixed_now)
        self.assertEqual(name, r"A\1$now on 2026-01-02T03:04:05+00:00; before$label after$now; A\1$now")

    def test_poll_creates_one_empty_automated_container_with_configured_fields(self):
        with patch.object(app.actions_manager, "save_container", return_value=(True, "saved", 42)) as save:
            result = self.run_action(
                "on_poll",
                label=r"Back\slash",
                parameters={"container_id": 7, "container_count": 1.5},
                severity="high",
                sensitivity="red",
            )
        save.assert_called_once_with({"name": r"Back\slash event", "run_automation": True, "severity": "high", "sensitivity": "red"})
        self.assertTrue(result.get_status())
        self.assertEqual(result.get_message(), "Created Container")
        self.assertEqual(result.get_data(), [])

    def test_poll_uses_defaults_and_reports_save_failure(self):
        with patch.object(app.actions_manager, "save_container", return_value=(False, "database unavailable", None)) as save:
            result = self.run_action("on_poll", event_name="scheduled", label="")
        save.assert_called_once_with({"name": "scheduled", "run_automation": True, "severity": "medium", "sensitivity": "amber"})
        self.assertFalse(result.get_status())
        self.assertEqual(result.get_message(), "Unable to create container: database unavailable")
        self.assertEqual(result.get_data(), [])

    def test_poll_handles_missing_ingest_label(self):
        with patch.object(app.actions_manager, "save_container", return_value=(True, "saved", 42)) as save:
            result = self.run_action("on_poll", event_name="$label event", ingest=None)
        self.assertTrue(result.get_status())
        self.assertEqual(save.call_args.args[0]["name"], " event")

    def test_connectivity_formats_name_without_creating_container(self):
        with patch.object(logger, "progress") as progress, patch.object(app.actions_manager, "save_container") as save:
            result = self.run_action("test_connectivity", event_name="$label event", label=r"Back\slash")
        progress.assert_any_call(r"Event Name: Back\slash event")
        progress.assert_any_call("Test Connectivity Passed")
        save.assert_not_called()
        self.assertTrue(result.get_status())

    def test_poll_params_keep_numeric_ignored_parameters_and_asset_defaults(self):
        expected_parameters = ["start_time", "end_time", "container_id", "container_count", "artifact_count"]
        self.assertEqual(
            list(PollParams.model_fields),
            expected_parameters,
        )
        self.assertTrue(all(field.annotation == float | None for field in PollParams.model_fields.values()))
        self.assertTrue(all(not field.is_required() for field in PollParams.model_fields.values()))
        self.assertEqual(Asset.model_validate({}).severity, "medium")
        self.assertEqual(Asset.model_validate({}).sensitivity, "amber")


if __name__ == "__main__":
    unittest.main()
