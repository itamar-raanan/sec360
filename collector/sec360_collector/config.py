import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
SOURCE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
SUPPORTED_TYPES = {"cisco_wlc", "fortigate", "mikrotik"}


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        return ENV_RE.sub(lambda match: os.environ.get(match.group(1), ""), value)
    if isinstance(value, list):
        return [_expand(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand(item) for key, item in value.items()}
    return value


def load_config(path: str | None = None) -> dict[str, Any]:
    config_path = Path(path or os.environ.get("SEC360_COLLECTOR_CONFIG", "/etc/sec360-collector/config.yml"))
    with config_path.open("r", encoding="utf-8") as handle:
        config = _expand(yaml.safe_load(handle) or {})
    sec360 = config.get("sec360") or {}
    sec360_url = str(sec360.get("url") or "")
    if not sec360_url.startswith(("http://", "https://")):
        raise ValueError("sec360.url must be an absolute HTTP(S) URL")
    if sec360_url.startswith("http://") and not sec360.get("allow_insecure_http", False):
        raise ValueError("sec360.url must use HTTPS (or explicitly set allow_insecure_http for development)")
    token = str(sec360.get("token") or "")
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != "nmc":
        raise ValueError("sec360.token is not a valid SEC360 collector credential")
    sources = config.get("sources") or []
    if not sources:
        raise ValueError("At least one source must be configured")
    seen = set()
    for source in sources:
        source_id = str(source.get("id") or "")
        source_type = str(source.get("type") or "")
        if not SOURCE_ID_RE.fullmatch(source_id):
            raise ValueError(f"Invalid source id: {source_id!r}")
        if source_id in seen:
            raise ValueError(f"Duplicate source id: {source_id}")
        if source_type not in SUPPORTED_TYPES:
            raise ValueError(f"Unsupported source type: {source_type}")
        seen.add(source_id)
        if source_type == "cisco_wlc":
            missing = [key for key in ("host", "username", "password") if not source.get(key)]
            if missing:
                raise ValueError(f"{source_id}: missing required fields: {', '.join(missing)}")
        if source_type in {"fortigate", "mikrotik"}:
            parsed = urlsplit(str(source.get("base_url") or ""))
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError(f"{source_id}: base_url must be an absolute HTTP(S) URL")
            if source_type == "fortigate" and parsed.scheme != "https":
                raise ValueError(f"{source_id}: FortiGate requires HTTPS")
        if source_type == "fortigate" and not source.get("api_token"):
            raise ValueError(f"{source_id}: api_token is required")
        if source_type == "mikrotik":
            missing = [key for key in ("username", "password") if not source.get(key)]
            if missing:
                raise ValueError(f"{source_id}: missing required fields: {', '.join(missing)}")
    config["sec360"] = sec360
    config["sources"] = sources
    config.setdefault("collection_interval_seconds", 120)
    config.setdefault("queue_path", "/var/lib/sec360-collector/queue.db")
    return config
