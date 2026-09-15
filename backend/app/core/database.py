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
        from app.models import user, endpoint, agent, activity, compliance, application, audit, system_settings, report, note, puppet  # noqa
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
            # Endpoint lifecycle / data-quality review
            "ALTER TABLE endpoints          ADD COLUMN IF NOT EXISTS lifecycle_state      VARCHAR(32) NOT NULL DEFAULT 'active'",
            "ALTER TABLE endpoints          ADD COLUMN IF NOT EXISTS lifecycle_reason     TEXT",
            "ALTER TABLE endpoints          ADD COLUMN IF NOT EXISTS lifecycle_changed_at TIMESTAMPTZ",
            "ALTER TABLE endpoints          ADD COLUMN IF NOT EXISTS lifecycle_changed_by VARCHAR(255)",
            "UPDATE endpoints SET lifecycle_state = 'stale' WHERE is_active = FALSE AND lifecycle_state = 'active'",
            "CREATE INDEX IF NOT EXISTS ix_endpoints_lifecycle_state ON endpoints (lifecycle_state)",
            "ALTER TABLE users              ADD COLUMN IF NOT EXISTS source           VARCHAR(50)  DEFAULT 'jumpcloud'",
            "ALTER TABLE auth_users         ADD COLUMN IF NOT EXISTS mfa_enabled      BOOLEAN      DEFAULT FALSE",
            # Compliance — new per-product checks
            "ALTER TABLE compliance_statuses ADD COLUMN IF NOT EXISTS dlp_installed   BOOLEAN      DEFAULT FALSE",
            "ALTER TABLE compliance_statuses ADD COLUMN IF NOT EXISTS edr_version_ok  BOOLEAN      DEFAULT FALSE",
            "ALTER TABLE compliance_statuses ADD COLUMN IF NOT EXISTS dlp_version_ok  BOOLEAN      DEFAULT FALSE",
            # System settings — minimum agent versions
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS min_s1_version   VARCHAR(50)  DEFAULT ''",
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS min_dlp_version  VARCHAR(50)  DEFAULT ''",
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS min_wss_version  VARCHAR(50)  DEFAULT ''",
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS endpoint_product_tags JSONB NOT NULL DEFAULT '[\"S1\", \"DLP\", \"WSS\"]'::jsonb",
            # Users — suspended flag from JumpCloud
            "ALTER TABLE users              ADD COLUMN IF NOT EXISTS suspended         BOOLEAN      DEFAULT FALSE",
            # System settings — new risk weight columns
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS risk_weight_edr_version FLOAT DEFAULT 20.0",
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS risk_weight_no_dlp      FLOAT DEFAULT 25.0",
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS risk_weight_dlp_version FLOAT DEFAULT 15.0",
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS risk_weight_no_wss      FLOAT DEFAULT 15.0",
            "ALTER TABLE system_settings    ADD COLUMN IF NOT EXISTS risk_weight_wss_version FLOAT DEFAULT 10.0",
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
            # SAML SSO — auth_users tracking
            "ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS saml_subject VARCHAR(255)",
            "CREATE INDEX IF NOT EXISTS ix_auth_users_saml_subject ON auth_users (saml_subject)",
            # SAML SSO — system-wide configuration (stored in system_settings)
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS saml_provider      VARCHAR(30)   DEFAULT 'google'",
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
            # RADIUS authentication. The JSON payload is encrypted by the ORM.
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS radius_enabled BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS radius_config JSONB",
            # Symantec WSS compliance fields (safe for upgraded installations)
            "ALTER TABLE compliance_statuses ADD COLUMN IF NOT EXISTS wss_installed  BOOLEAN DEFAULT FALSE",
            "ALTER TABLE compliance_statuses ADD COLUMN IF NOT EXISTS wss_version_ok BOOLEAN DEFAULT FALSE",
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
            # Removed feature storage. No retained feature references depend on it.
            "DROP TABLE IF EXISTS ai_insights",
            # Retired integrations: remove credentials and source-specific data,
            # while retaining canonical users that may be owned by another source.
            "DELETE FROM integration_configs WHERE integration_type IN ('hibob', 'cloudsoc')",
            "UPDATE users SET sources = sources - 'hibob' WHERE sources ? 'hibob'",
            "DELETE FROM activity_events WHERE details->>'app' = 'cloudsoc'",
            # Puppet inventory and searchable facts.
            """
            CREATE TABLE IF NOT EXISTS puppet_nodes (
                certname VARCHAR(500) PRIMARY KEY,
                endpoint_id UUID REFERENCES endpoints(id) ON DELETE SET NULL,
                environment VARCHAR(255),
                latest_report_status VARCHAR(100),
                report_timestamp TIMESTAMPTZ,
                catalog_timestamp TIMESTAMPTZ,
                facts_timestamp TIMESTAMPTZ,
                synced_at TIMESTAMPTZ NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS ix_puppet_nodes_endpoint_id ON puppet_nodes (endpoint_id)",
            "CREATE INDEX IF NOT EXISTS ix_puppet_nodes_environment ON puppet_nodes (environment)",
            "CREATE INDEX IF NOT EXISTS ix_puppet_nodes_latest_report_status ON puppet_nodes (latest_report_status)",
            "CREATE INDEX IF NOT EXISTS ix_puppet_nodes_synced_at ON puppet_nodes (synced_at)",
            """
            CREATE TABLE IF NOT EXISTS puppet_facts (
                id UUID PRIMARY KEY,
                certname VARCHAR(500) NOT NULL REFERENCES puppet_nodes(certname) ON DELETE CASCADE,
                name VARCHAR(500) NOT NULL,
                value JSONB NOT NULL,
                environment VARCHAR(255),
                synced_at TIMESTAMPTZ NOT NULL,
                CONSTRAINT uq_puppet_fact_certname_name UNIQUE (certname, name)
            )
            """,
            "CREATE INDEX IF NOT EXISTS ix_puppet_facts_certname ON puppet_facts (certname)",
            "CREATE INDEX IF NOT EXISTS ix_puppet_facts_name ON puppet_facts (name)",
            "CREATE INDEX IF NOT EXISTS ix_puppet_facts_environment ON puppet_facts (environment)",
            "CREATE INDEX IF NOT EXISTS ix_puppet_facts_synced_at ON puppet_facts (synced_at)",
            "CREATE INDEX IF NOT EXISTS ix_puppet_facts_name_certname ON puppet_facts (name, certname)",
            "ALTER TABLE puppet_facts ADD COLUMN IF NOT EXISTS value_type VARCHAR(20)",
            "UPDATE puppet_facts SET value_type = COALESCE(jsonb_typeof(value), 'null') WHERE value_type IS NULL",
            "ALTER TABLE puppet_facts ALTER COLUMN value_type SET DEFAULT 'string'",
            "ALTER TABLE puppet_facts ALTER COLUMN value_type SET NOT NULL",
            "CREATE INDEX IF NOT EXISTS ix_puppet_facts_value_type ON puppet_facts (value_type)",
            """
            CREATE TABLE IF NOT EXISTS puppet_fact_favorites (
                id UUID PRIMARY KEY,
                user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
                fact_name VARCHAR(500) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                CONSTRAINT uq_puppet_fact_favorite_user_name UNIQUE (user_id, fact_name)
            )
            """,
            "CREATE INDEX IF NOT EXISTS ix_puppet_fact_favorites_user_id ON puppet_fact_favorites (user_id)",
            "CREATE INDEX IF NOT EXISTS ix_puppet_fact_favorites_fact_name ON puppet_fact_favorites (fact_name)",
            """
            CREATE TABLE IF NOT EXISTS puppet_fact_saved_views (
                id UUID PRIMARY KEY,
                user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
                name VARCHAR(120) NOT NULL,
                definition JSONB NOT NULL,
                is_default BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                CONSTRAINT uq_puppet_fact_saved_view_user_name UNIQUE (user_id, name)
            )
            """,
            "CREATE INDEX IF NOT EXISTS ix_puppet_fact_saved_views_user_id ON puppet_fact_saved_views (user_id)",
            # GlobalProtect retirement — remove stale records and schema fields.
            "DELETE FROM security_agents WHERE product_name::text = 'globalprotect'",
            "ALTER TABLE compliance_statuses DROP COLUMN IF EXISTS gp_version_ok",
            "ALTER TABLE compliance_statuses DROP COLUMN IF EXISTS gp_installed",
            "ALTER TABLE system_settings DROP COLUMN IF EXISTS min_gp_version",
            """
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1
                    FROM pg_type t
                    JOIN pg_enum e ON e.enumtypid = t.oid
                    WHERE t.typname = 'agent_product_enum'
                      AND e.enumlabel = 'globalprotect'
                ) THEN
                    ALTER TYPE agent_product_enum RENAME TO agent_product_enum_with_globalprotect;
                    CREATE TYPE agent_product_enum AS ENUM (
                        'sentinelone', 'symantec', 'prisma', 'symantec_wss', 'other'
                    );
                    ALTER TABLE security_agents
                        ALTER COLUMN product_name TYPE agent_product_enum
                        USING product_name::text::agent_product_enum;
                    DROP TYPE agent_product_enum_with_globalprotect;
                END IF;
            END $$
            """,
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
