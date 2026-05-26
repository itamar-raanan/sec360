from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.core.config import settings


engine = create_async_engine(
    settings.DB_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Create all tables and apply incremental schema patches."""
    async with engine.begin() as conn:
        from app.models import user, endpoint, agent, activity, compliance, application, audit, system_settings, report, note  # noqa
        await conn.run_sync(Base.metadata.create_all)
        # Incremental patches — safe to run repeatedly
        from sqlalchemy import text
        patches = [
            # Invitation flow
            "ALTER TABLE auth_users         ADD COLUMN IF NOT EXISTS invitation_token  VARCHAR(64)",
            "ALTER TABLE auth_users         ADD COLUMN IF NOT EXISTS invitation_expires_at TIMESTAMPTZ",
            "ALTER TABLE auth_users         ADD COLUMN IF NOT EXISTS invited_by        VARCHAR(255)",
            "ALTER TABLE endpoints          ADD COLUMN IF NOT EXISTS source           VARCHAR(50)  DEFAULT 'jumpcloud'",
            "ALTER TABLE endpoints          ADD COLUMN IF NOT EXISTS serial_number    VARCHAR(100)",
            "ALTER TABLE users              ADD COLUMN IF NOT EXISTS source           VARCHAR(50)  DEFAULT 'jumpcloud'",
            "ALTER TABLE auth_users         ADD COLUMN IF NOT EXISTS mfa_enabled      BOOLEAN      DEFAULT FALSE",
            # Compliance — new per-product checks
            "ALTER TABLE compliance_statuses ADD COLUMN IF NOT EXISTS dlp_installed   BOOLEAN      DEFAULT FALSE",
            "ALTER TABLE compliance_statuses ADD COLUMN IF NOT EXISTS edr_version_ok  BOOLEAN      DEFAULT FALSE",
            "ALTER TABLE compliance_statuses ADD COLUMN IF NOT EXISTS dlp_version_ok  BOOLEAN      DEFAULT FALSE",
            # System settings — minimum agent versions
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS min_s1_version   VARCHAR(50)  DEFAULT ''",
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS min_dlp_version  VARCHAR(50)  DEFAULT ''",
            # Users — suspended flag from JumpCloud
            "ALTER TABLE users              ADD COLUMN IF NOT EXISTS suspended         BOOLEAN      DEFAULT FALSE",
            # System settings — new risk weight columns
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS risk_weight_edr_version FLOAT DEFAULT 20.0",
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS risk_weight_no_dlp      FLOAT DEFAULT 25.0",
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS risk_weight_dlp_version FLOAT DEFAULT 15.0",
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS risk_weight_no_user     FLOAT DEFAULT 10.0",
            # Notes — analyst comments on endpoints / users
            """
            CREATE TABLE IF NOT EXISTS notes (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                entity_type VARCHAR(50)  NOT NULL,
                entity_id   VARCHAR(100) NOT NULL,
                content     TEXT         NOT NULL,
                author_email VARCHAR(255) NOT NULL,
                created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
            )
            """,
            "CREATE INDEX IF NOT EXISTS ix_notes_entity ON notes (entity_type, entity_id)",
            # Google SAML SSO — auth_users tracking
            "ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS saml_subject VARCHAR(255)",
            "CREATE INDEX IF NOT EXISTS ix_auth_users_saml_subject ON auth_users (saml_subject)",
            # Google SAML SSO — system-wide configuration (stored in system_settings)
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS saml_enabled       BOOLEAN       DEFAULT FALSE",
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS saml_sp_entity_id  VARCHAR(500)  DEFAULT ''",
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS saml_sp_acs_url    VARCHAR(500)  DEFAULT ''",
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS saml_idp_entity_id VARCHAR(500)  DEFAULT ''",
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS saml_idp_sso_url   VARCHAR(500)  DEFAULT ''",
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS saml_idp_cert      TEXT          DEFAULT ''",
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS saml_default_role  VARCHAR(20)   DEFAULT 'viewer'",
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS saml_sp_cert       TEXT          DEFAULT ''",
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS saml_sp_key             TEXT          DEFAULT ''",
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS saml_allowed_emails      TEXT          DEFAULT ''",
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS saml_require_mfa        BOOLEAN       DEFAULT FALSE",
            # S1 enrichment on security_agents
            "ALTER TABLE security_agents ADD COLUMN IF NOT EXISTS disk_encrypted         BOOLEAN       DEFAULT NULL",
            "ALTER TABLE security_agents ADD COLUMN IF NOT EXISTS encryption_status      VARCHAR(50)   DEFAULT NULL",
            "ALTER TABLE security_agents ADD COLUMN IF NOT EXISTS device_control_enabled BOOLEAN       DEFAULT NULL",
            # Tags, last_reboot, all_ips on endpoints
            "ALTER TABLE endpoints       ADD COLUMN IF NOT EXISTS tags                   VARCHAR(500)  DEFAULT NULL",
            "ALTER TABLE endpoints       ADD COLUMN IF NOT EXISTS last_reboot            TIMESTAMPTZ   DEFAULT NULL",
            "ALTER TABLE endpoints       ADD COLUMN IF NOT EXISTS all_ips                VARCHAR(500)  DEFAULT NULL",
            # S1 agent group
            "ALTER TABLE security_agents ADD COLUMN IF NOT EXISTS agent_group            VARCHAR(255)  DEFAULT NULL",
            # Device control + encryption on compliance_statuses
            "ALTER TABLE compliance_statuses ADD COLUMN IF NOT EXISTS device_control_enabled BOOLEAN   DEFAULT NULL",
            # Make disk_encrypted nullable (was NOT NULL DEFAULT FALSE)
            "ALTER TABLE compliance_statuses ALTER COLUMN disk_encrypted DROP NOT NULL",
            "ALTER TABLE compliance_statuses ALTER COLUMN disk_encrypted SET DEFAULT NULL",
            # D-1/R-4: external event ID — prevents duplicate inserts across concurrent collection runs
            "ALTER TABLE activity_events ADD COLUMN IF NOT EXISTS external_id VARCHAR(255)",
            "CREATE UNIQUE INDEX IF NOT EXISTS uix_activity_events_external_id ON activity_events (external_id) WHERE external_id IS NOT NULL",
        ]
        for sql in patches:
            await conn.execute(text(sql))

    # Seed singleton system_settings row
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        from app.models.system_settings import SystemSettings
        existing = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
        if not existing:
            db.add(SystemSettings(id=1))
            await db.commit()
