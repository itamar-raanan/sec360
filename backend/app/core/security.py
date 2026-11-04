from datetime import datetime, timedelta, timezone
from typing import Optional, Any
import hashlib
import hmac
import secrets
from jose import jwt, JWTError
from passlib.context import CryptContext
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ROLES = ["admin", "analyst", "viewer"]
ROLE_HIERARCHY = {"admin": 3, "analyst": 2, "viewer": 1}
API_KEY_PREFIX = "sec360_"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_personal_api_key() -> tuple[str, str, str]:
    """Return the one-time raw key, its public lookup prefix, and keyed digest."""
    public_id = secrets.token_hex(8)
    key_prefix = f"{API_KEY_PREFIX}{public_id}"
    raw_key = f"{key_prefix}_{secrets.token_urlsafe(32)}"
    return raw_key, key_prefix, hash_personal_api_key(raw_key)


def personal_api_key_prefix(raw_key: str) -> str | None:
    parts = raw_key.split("_", 2)
    if len(parts) != 3 or parts[0] != "sec360" or len(parts[1]) != 16:
        return None
    try:
        int(parts[1], 16)
    except ValueError:
        return None
    return f"sec360_{parts[1]}"


def hash_personal_api_key(raw_key: str) -> str:
    return hmac.new(
        settings.JWT_SECRET.encode("utf-8"),
        raw_key.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def create_access_token(data: dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc), "type": "access"})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_sso_mfa_pending_token(data: dict[str, Any]) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=10)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc), "type": "sso_mfa_pending"})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(hours=settings.JWT_REFRESH_EXPIRE_HOURS)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc), "type": "refresh"})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")


def has_role(user_role: str, required_role: str) -> bool:
    return ROLE_HIERARCHY.get(user_role, 0) >= ROLE_HIERARCHY.get(required_role, 0)
