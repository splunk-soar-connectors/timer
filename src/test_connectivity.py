"""Timer asset connectivity check."""

from soar_sdk.app import App
from soar_sdk.logging import getLogger

from .actions.on_poll import current_event_name
from .asset import Asset


logger = getLogger()


def run_test_connectivity(asset: Asset, app: App) -> None:
    logger.progress(f"Event Name: {current_event_name(asset, app)}")
    logger.progress("Test Connectivity Passed")
