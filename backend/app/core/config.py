import logging
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Sec360"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # Database
    DB_URL: str = "postgresql+asyncpg://sec360:sec360pass@postgres:5432/sec360"

    # JWT
    JWT_SECRET: str = "changeme-super-secret-key-for-jwt-signing-at-least-32-chars"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 480  # 8 hour access token
    JWT_REFRESH_EXPIRE_HOURS: int = 168  # 7 day refresh token
    COOKIE_SECURE: bool = True  # Set to False only for local HTTP development
    TRUST_PROXY_HEADERS: bool = False

    # First-run administrator. These values are used only when auth_users is
    # empty; the created account must change its password before using the app.
    BOOTSTRAP_ADMIN_EMAIL: str = "admin@sec360.local"
    BOOTSTRAP_ADMIN_PASSWORD: Optional[str] = None

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://frontend:3000"]

    # Frontend URL (used in invite/report email links)
    APP_URL: str = "http://localhost:3000"

    # Shared TLS directory used by the certificate manager and nginx.
    TLS_CERT_DIR: str = "/var/lib/sec360/tls"

    # SMTP — leave empty to disable email (invite links will be logged instead)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "noreply@sec360.local"
    SMTP_TLS: bool = True

    # Collector schedule (minutes)
    COLLECTOR_INTERVAL_MINUTES: int = 10

    # Credential encryption — generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    CREDENTIALS_ENCRYPTION_KEY: Optional[str] = None

    # Redis — optional; enables persistent brute-force rate limiting across restarts
    REDIS_URL: Optional[str] = None
    REQUIRE_REDIS_RATE_LIMIT: bool = False

    # SentinelOne
    SENTINELONE_URL: Optional[str] = None
    SENTINELONE_API_TOKEN: Optional[str] = None

    # Google Workspace
    GOOGLE_WORKSPACE_DOMAIN: Optional[str] = None
    GOOGLE_SERVICE_ACCOUNT_JSON: Optional[str] = None

    # Symantec DLP
    SYMANTEC_URL: Optional[str] = None
    SYMANTEC_USERNAME: Optional[str] = None
    SYMANTEC_PASSWORD: Optional[str] = None

    # Google SAML SSO
    # Set SAML_IDP_SSO_URL, SAML_IDP_ENTITY_ID, and SAML_IDP_CERT to enable SSO
    SAML_SP_ENTITY_ID: str = ""
    SAML_SP_ACS_URL: str = ""        # e.g. https://sec360.yourcompany.com/api/auth/saml/acs
    SAML_IDP_ENTITY_ID: str = ""     # from the identity provider's SAML app setup
    SAML_IDP_SSO_URL: str = ""       # identity provider SSO endpoint
    SAML_IDP_CERT: str = ""          # identity provider x509 signing certificate
    SAML_SP_CERT: str = ""           # optional: SP signing cert
    SAML_SP_KEY: str = ""            # optional: SP signing private key
    SAML_DEFAULT_ROLE: str = "viewer"  # role assigned to auto-provisioned SSO users

    @property
    def SAML_ENABLED(self) -> bool:
        return bool(self.SAML_IDP_SSO_URL and self.SAML_IDP_ENTITY_ID and self.SAML_IDP_CERT)

    # Ignore retired keys left in an existing deployment's .env so feature
    # removal cannot prevent the backend from starting after an upgrade.
    model_config = {"env_file": ".env", "case_sensitive": True, "extra": "ignore"}


settings = Settings()

_DEFAULT_JWT_SECRET = "changeme-super-secret-key-for-jwt-signing-at-least-32-chars"
if settings.JWT_SECRET == _DEFAULT_JWT_SECRET:
    logging.warning(
        "JWT_SECRET is set to the default insecure value. "
        "Set a strong, unique JWT_SECRET environment variable before deploying to production."
    )

if settings.CREDENTIALS_ENCRYPTION_KEY is None:
    logging.warning(
        "CREDENTIALS_ENCRYPTION_KEY is not set. Integration credentials will be stored "
        "in plaintext in the database. Generate a key with: "
        "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\" "
        "and set CREDENTIALS_ENCRYPTION_KEY in your environment."
    )


def validate_runtime_security(config: Settings = settings) -> None:
    """Refuse an unsafe production configuration instead of merely warning."""
    if config.ENVIRONMENT.strip().lower() != "production":
        return

    errors: list[str] = []
    if config.JWT_SECRET == _DEFAULT_JWT_SECRET or len(config.JWT_SECRET) < 32:
        errors.append("JWT_SECRET must be a unique value of at least 32 characters")
    if not config.COOKIE_SECURE:
        errors.append("COOKIE_SECURE must be true")
    if not config.CREDENTIALS_ENCRYPTION_KEY:
        errors.append("CREDENTIALS_ENCRYPTION_KEY is required")
    else:
        try:
            from cryptography.fernet import Fernet

            Fernet(config.CREDENTIALS_ENCRYPTION_KEY.encode())
        except Exception:
            errors.append("CREDENTIALS_ENCRYPTION_KEY must be a valid Fernet key")
    if config.REQUIRE_REDIS_RATE_LIMIT and not config.REDIS_URL:
        errors.append("REDIS_URL is required when REQUIRE_REDIS_RATE_LIMIT is true")

    if errors:
        raise RuntimeError("Unsafe production configuration: " + "; ".join(errors))
