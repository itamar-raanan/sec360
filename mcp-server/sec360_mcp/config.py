"""Environment-backed configuration for the SEC360 MCP server."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


def _boolean(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be one of true/false, 1/0, yes/no, or on/off")


def _integer(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    value = int(raw) if raw is not None else default
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class Settings:
    sec360_url: str
    api_key: str
    verify_ssl: bool | str
    timeout_seconds: float
    transport: str
    host: str
    port: int

    @classmethod
    def from_env(cls) -> "Settings":
        raw_url = os.getenv("SEC360_URL", "").strip().rstrip("/")
        if not raw_url:
            raise ValueError("SEC360_URL is required")
        parsed = urlparse(raw_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("SEC360_URL must be an absolute http:// or https:// URL")
        if parsed.username or parsed.password:
            raise ValueError("SEC360_URL must not contain embedded credentials")

        api_key = os.getenv("SEC360_API_KEY", "").strip()
        if not api_key:
            raise ValueError("SEC360_API_KEY is required")
        if not api_key.startswith("sec360_"):
            raise ValueError("SEC360_API_KEY is not a SEC360 personal API key")

        ca_bundle = os.getenv("SEC360_CA_BUNDLE", "").strip()
        if ca_bundle:
            ca_path = Path(ca_bundle).expanduser()
            if not ca_path.is_file():
                raise ValueError("SEC360_CA_BUNDLE does not point to a readable file")
            verify_ssl: bool | str = str(ca_path)
        else:
            verify_ssl = _boolean("SEC360_VERIFY_SSL", True)

        transport = os.getenv("SEC360_MCP_TRANSPORT", "stdio").strip().lower()
        if transport not in {"stdio", "streamable-http"}:
            raise ValueError("SEC360_MCP_TRANSPORT must be stdio or streamable-http")

        return cls(
            sec360_url=raw_url,
            api_key=api_key,
            verify_ssl=verify_ssl,
            timeout_seconds=float(_integer("SEC360_TIMEOUT_SECONDS", 30, minimum=5, maximum=120)),
            transport=transport,
            host=os.getenv("SEC360_MCP_HOST", "127.0.0.1").strip() or "127.0.0.1",
            port=_integer("SEC360_MCP_PORT", 9000, minimum=1, maximum=65535),
        )
