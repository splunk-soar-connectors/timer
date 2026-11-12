"""Splunk SOAR Timer connector."""

from soar_sdk.app import App

from .actions import register_actions
from .asset import Asset
from .test_connectivity import run_test_connectivity


def create_timer_app() -> App:
    app = App(
        name="Timer",
        app_type="generic",
        logo="logo_splunk.svg",
        logo_dark="logo_splunk_dark.svg",
        product_vendor="Phantom",
        product_name="Timer",
        publisher="Splunk",
        appid="7f714055-3a13-4f99-9b18-56efe30a3cb6",
        python_version="3.13",
        min_phantom_version="7.0.0",
        fips_compliant=True,
        asset_cls=Asset,
    )
    register_actions(app)

    @app.test_connectivity()
    def test_connectivity(asset: Asset) -> None:
        """Validate the asset configuration for connectivity using supplied configuration."""
        run_test_connectivity(asset, app)

    return app


app: App = create_timer_app()


if __name__ == "__main__":
    app.cli()
