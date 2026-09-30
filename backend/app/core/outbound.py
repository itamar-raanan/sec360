import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from app.core.config import settings


class OutboundTargetError(ValueError):
    pass


async def validate_outbound_host(host: str, port: int) -> str:
    """Resolve a socket target and reject loopback/link-local destinations."""
    hostname = host.strip().rstrip(".").lower()
    if not hostname:
        raise OutboundTargetError("Integration host is required")
    if not 1 <= port <= 65535:
        raise OutboundTargetError("Integration port must be between 1 and 65535")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise OutboundTargetError("Loopback integration targets are not allowed")
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            records = await asyncio.get_running_loop().getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise OutboundTargetError(f"DNS could not resolve integration host '{hostname}'") from exc
        addresses = list({ipaddress.ip_address(item[4][0]) for item in records})

    if not addresses:
        raise OutboundTargetError("Integration host did not resolve to an address")
    for address in addresses:
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise OutboundTargetError(f"Integration target address {address} is not allowed")
    return hostname


async def validate_outbound_url(url: str) -> str:
    """Reject dangerous destinations before an integration opens a socket."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise OutboundTargetError("Integration URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise OutboundTargetError("Credentials must not be embedded in an integration URL")
    if settings.ENVIRONMENT.strip().lower() == "production" and parsed.scheme != "https":
        raise OutboundTargetError("Integration URLs must use HTTPS in production")

    await validate_outbound_host(
        parsed.hostname,
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )
    return url
