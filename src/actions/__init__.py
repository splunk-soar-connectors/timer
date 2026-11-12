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
