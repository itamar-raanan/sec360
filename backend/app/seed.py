"""
Seed script for Sec360. Run with: python -m app.seed
"""
import asyncio

from app.core.database import engine, Base, AsyncSessionLocal
from app.core.security import hash_password
from app.models.user import AuthUser


AUTH_USERS = [
    ("admin@sec360.local", "Admin123!", "admin"),
    ("analyst@sec360.local", "Analyst123!", "analyst"),
]


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
        print("  Creating auth users...")
        for email, password, role in AUTH_USERS:
            existing = (await db.execute(select(AuthUser).where(AuthUser.email == email))).scalar_one_or_none()
            if not existing:
                db.add(AuthUser(email=email, hashed_password=hash_password(password), role=role))

        await db.flush()

        # ── Default integration configs ──────────────────────────────────────
        print("  Creating default integration configs...")
        from app.models.integration import IntegrationConfig

        INTEGRATIONS = [
            ("jumpcloud", "JumpCloud"),
            ("sentinelone", "SentinelOne"),
            ("symantec_dlp", "Symantec DLP"),
            ("google_workspace", "Google Workspace"),
            ("hibob", "HiBob"),
        ]

        for itype, display_name in INTEGRATIONS:
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
    print("Auth users:")
    for email, password, role in AUTH_USERS:
        print(f"  {email} / {password} ({role})")


if __name__ == "__main__":
    asyncio.run(seed())
