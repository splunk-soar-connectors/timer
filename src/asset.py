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
