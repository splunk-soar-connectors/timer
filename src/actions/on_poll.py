"""Create a scheduled Timer event."""

import re
from datetime import UTC, datetime

from soar_sdk.action_results import ActionResult
from soar_sdk.app import App
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset


logger = getLogger()


class PollParams(Params):
    start_time: float | None = Param(description="Parameter Ignored in this app", required=False)
    end_time: float | None = Param(description="Parameter Ignored in this app", required=False)
    container_id: float | None = Param(description="Parameter Ignored in this app", required=False)
    container_count: float | None = Param(description="Parameter Ignored in this app", required=False)
    artifact_count: float | None = Param(description="Parameter Ignored in this app", required=False)


def format_event_name(event_name: str, label: str, now: datetime | None = None) -> str:
    """Substitute standalone $now and $label tokens as the legacy app did."""
    iso_now = (now or datetime.now(UTC)).isoformat()
    event_name = re.sub(r"(^|[^0-9a-zA-Z]+)(\$now)($|[^0-9a-zA-Z]+)", rf"\g<1>{iso_now}\g<3>", event_name)
    return re.sub(
        r"(^|[^0-9a-zA-Z]+)(\$label)($|[^0-9a-zA-Z]+)",
        lambda match: f"{match.group(1)}{label}{match.group(3)}",
        event_name,
    )


def current_event_name(asset: Asset, app: App) -> str:
    # SOAR supplies the ingest label in the action config, outside SDK asset fields.
    config = app.actions_manager.get_config()
    label = (config.get("ingest") or {}).get("container_label", "")
    return format_event_name(asset.event_name, label)


def run_on_poll(params: PollParams, asset: Asset, app: App) -> ActionResult:
    """Create one empty event to kick off a playbook."""
    event_name = current_event_name(asset, app)
    logger.progress("saving the container")
    # The SDK's on_poll helper changes the ignored container_id parameter to a string.
    # Use its BaseConnector bridge to retain the legacy numeric input and result messages.
    success, message, _container_id = app.actions_manager.save_container(
        {"name": event_name, "run_automation": True, "severity": asset.severity, "sensitivity": asset.sensitivity}
    )
    if not success:
        return ActionResult(False, f"Unable to create container: {message}", params.model_dump(exclude_none=True))
    return ActionResult(True, "Created Container", params.model_dump(exclude_none=True))
