import logging
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Sec360"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database
    DB_URL: str = "postgresql+asyncpg://sec360:sec360pass@postgres:5432/sec360"

    # JWT
    JWT_SECRET: str = "changeme-super-secret-key-for-jwt-signing-at-least-32-chars"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 480  # 8 hour access token
    JWT_REFRESH_EXPIRE_HOURS: int = 168  # 7 day refresh token
    COOKIE_SECURE: bool = True  # Set to False only for local HTTP development

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://frontend:3000"]

    # Frontend URL (used in invite/report email links)
    APP_URL: str = "http://localhost:3000"

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

    # AI Engine — set ANTHROPIC_API_KEY to enable LLM-powered explanations
    ANTHROPIC_API_KEY: Optional[str] = None

    # SentinelOne
    SENTINELONE_URL: Optional[str] = None
    SENTINELONE_API_TOKEN: Optional[str] = None

    # HiBob
    HIBOB_API_URL: str = "https://api.hibob.com"
    HIBOB_SERVICE_USER_ID: Optional[str] = None
    HIBOB_SERVICE_TOKEN: Optional[str] = None

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
    SAML_IDP_ENTITY_ID: str = ""     # from Google Admin SAML app setup
    SAML_IDP_SSO_URL: str = ""       # from Google Admin SAML app setup
    SAML_IDP_CERT: str = ""          # x509 cert from Google Admin (no headers, no newlines)
    SAML_SP_CERT: str = ""           # optional: SP signing cert
    SAML_SP_KEY: str = ""            # optional: SP signing private key
    SAML_DEFAULT_ROLE: str = "viewer"  # role assigned to auto-provisioned SSO users

    @property
    def SAML_ENABLED(self) -> bool:
        return bool(self.SAML_IDP_SSO_URL and self.SAML_IDP_ENTITY_ID and self.SAML_IDP_CERT)

    model_config = {"env_file": ".env", "case_sensitive": True}


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
