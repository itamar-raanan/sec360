"""
Fernet-based encryption for sensitive DB columns.

Usage:
  - Set CREDENTIALS_ENCRYPTION_KEY to a URL-safe base64-encoded 32-byte key.
  - Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  - If the key is unset, data is stored and returned as plaintext with a startup warning.

Column format: JSON object {"_enc": "<fernet_token>"}.
Unencrypted legacy rows (plain dict without "_enc") are read transparently.
"""
import json
import logging
from typing import Any

from sqlalchemy import JSON
from sqlalchemy.types import TypeDecorator

logger = logging.getLogger(__name__)

_warned_no_key = False


def _fernet():
    from cryptography.fernet import Fernet
    from app.core.config import settings

    key = settings.CREDENTIALS_ENCRYPTION_KEY
    if not key:
        return None
    return Fernet(key.encode() if isinstance(key, str) else key)


class EncryptedJSON(TypeDecorator):
    """JSON column that transparently encrypts/decrypts using Fernet.

    Encrypted rows are stored as {"_enc": "<token>"}.
    Legacy plaintext rows are returned as-is so old data stays readable
    until re-saved (at which point it becomes encrypted).
    """

    impl = JSON
    cache_ok = True

    def process_bind_param(self, value: Any, dialect) -> Any:
        if value is None:
            return None
        f = _fernet()
        if f is None:
            global _warned_no_key
            if not _warned_no_key:
                logger.warning(
                    "CREDENTIALS_ENCRYPTION_KEY is not set — "
                    "integration credentials are stored in plaintext. "
                    "Set this key in production."
                )
                _warned_no_key = True
            return value
        token = f.encrypt(json.dumps(value).encode()).decode()
        return {"_enc": token}

    def process_result_value(self, value: Any, dialect) -> Any:
        if value is None:
            return None
        if isinstance(value, dict) and "_enc" in value:
            f = _fernet()
            if f is None:
                logger.error("Cannot decrypt credentials: CREDENTIALS_ENCRYPTION_KEY is not set")
                return None
            try:
                return json.loads(f.decrypt(value["_enc"].encode()))
            except Exception as e:
                logger.error("Failed to decrypt credentials: %s", e)
                return None
        # Legacy plaintext row — return as-is
        return value
