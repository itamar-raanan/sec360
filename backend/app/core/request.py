from ipaddress import ip_address

from fastapi import Request

from app.core.config import settings


def get_client_ip(request: Request) -> str:
    """Return proxy-provided IP only when this deployment explicitly trusts it."""
    if settings.TRUST_PROXY_HEADERS:
        real_ip = request.headers.get("X-Real-IP", "").strip()
        if real_ip and _valid_ip(real_ip):
            return real_ip
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            # nginx overwrites this header with the directly observed peer.
            candidate = forwarded.split(",")[-1].strip()
            if _valid_ip(candidate):
                return candidate
    return request.client.host if request.client else "unknown"


def _valid_ip(value: str) -> bool:
    try:
        ip_address(value)
        return True
    except ValueError:
        return False
