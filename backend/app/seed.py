"""
Seed script for Sec360. Run with: python -m app.seed
"""
import asyncio

from app.core.database import engine, Base, AsyncSessionLocal
from app.core.config import settings
from app.core.security import hash_password
from app.models.user import AuthUser


async def seed():
    print("Creating tables...")
    async with engine.begin() as conn:
        from app.models import user, endpoint, agent, activity, compliance, application, audit  # noqa
        from app.models.integration import IntegrationConfig  # noqa
        await conn.run_sync(Base.metadata.create_all)

    print("Seeding data...")
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select

        # ── Auth users ──────────────────────────────────────────────────────
        print("  Checking bootstrap administrator...")
        existing = (await db.execute(select(AuthUser))).scalars().first()
        if existing is None:
            password = settings.BOOTSTRAP_ADMIN_PASSWORD or ""
            if len(password) < 12 or password.startswith("CHANGE_ME"):
                raise RuntimeError(
                    "Set BOOTSTRAP_ADMIN_PASSWORD to a unique value of at least "
                    "12 characters before running the seed command."
                )
            db.add(AuthUser(
                email=settings.BOOTSTRAP_ADMIN_EMAIL.strip().lower(),
                hashed_password=hash_password(password),
                role="admin",
                must_change_password=True,
            ))

        await db.flush()

        # ── Default integration configs ──────────────────────────────────────
        print("  Creating default integration configs...")
        from app.integrations.catalog import INTEGRATION_DEFAULTS
        from app.models.integration import IntegrationConfig

        for itype, display_name in INTEGRATION_DEFAULTS:
            existing = (await db.execute(
                select(IntegrationConfig).where(IntegrationConfig.integration_type == itype)
            )).scalar_one_or_none()
            if not existing:
                db.add(IntegrationConfig(
                    integration_type=itype,
                    display_name=display_name,
                    is_enabled=False,
                    status="unconfigured",
                ))

        await db.commit()

    print("Seed complete!")
    print(f"Bootstrap administrator: {settings.BOOTSTRAP_ADMIN_EMAIL.strip().lower()}")
    print("The bootstrap password is never printed; change it at first login.")


if __name__ == "__main__":
    asyncio.run(seed())
