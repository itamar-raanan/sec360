from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


SUPPORTED_ENDPOINT_PRODUCT_TAGS = ("S1", "DLP", "WSS")
DEFAULT_ENDPOINT_PRODUCT_TAGS = SUPPORTED_ENDPOINT_PRODUCT_TAGS


def normalize_product_tags(value) -> tuple[str, ...]:
    """Return supported product tags in their canonical display order."""
    if value is None:
        return DEFAULT_ENDPOINT_PRODUCT_TAGS
    selected = set(value)
    return tuple(tag for tag in SUPPORTED_ENDPOINT_PRODUCT_TAGS if tag in selected)


async def load_product_tags(db: AsyncSession) -> tuple[str, ...]:
    from app.models.system_settings import SystemSettings

    cfg = (await db.execute(
        select(SystemSettings).where(SystemSettings.id == 1)
    )).scalar_one_or_none()
    return normalize_product_tags(cfg.endpoint_product_tags if cfg else None)
