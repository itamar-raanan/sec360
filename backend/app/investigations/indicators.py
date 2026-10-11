import asyncio
import hashlib
import ipaddress
import re
import socket
from dataclasses import asdict, dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SENSITIVE_QUERY_NAMES = {
    "access_token", "apikey", "api_key", "auth", "code", "credential",
    "key", "password", "reset", "session", "sessionid", "sig", "signature",
    "token", "userkey",
}
SENSITIVE_PATH_MARKERS = ("/reset-password", "/password-reset", "/magic-link", "/invite/")


@dataclass(frozen=True)
class NormalizedIndicator:
    original: str
    normalized: str
    indicator_type: str
    exact_url: str | None
    hostname: str
    registrable_domain: str
    scan_target: str
    preview: str
    is_sensitive: bool
    sensitive_reasons: list[str]
    resolved_ips: list[str]
    resolution_ms: int
    indicator_hash: str

    def to_dict(self, *, include_original: bool = True) -> dict:
        value = asdict(self)
        if not include_original:
            value.pop("original", None)
        return value


def _refang(value: str) -> str:
    value = value.strip()
    value = re.sub(r"(?i)^hxxps://", "https://", value)
    value = re.sub(r"(?i)^hxxp://", "http://", value)
    return value.replace("[.]", ".").replace("(.)", ".")


def _registrable_domain(hostname: str) -> str:
    try:
        import tldextract

        extracted = tldextract.TLDExtract(suffix_list_urls=())(hostname)
        return extracted.top_domain_under_public_suffix or hostname
    except ImportError:
        # The production image installs tldextract. This conservative fallback
        # keeps local tooling usable without pretending uncommon suffixes are exact.
        labels = hostname.split(".")
        return ".".join(labels[-2:]) if len(labels) > 1 else hostname


def _mask_url(url: str) -> tuple[str, list[str]]:
    parsed = urlsplit(url)
    reasons: list[str] = []
    masked_pairs: list[tuple[str, str]] = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        sensitive = name.lower() in SENSITIVE_QUERY_NAMES or any(
            marker in name.lower() for marker in ("token", "secret", "password", "signature")
        )
        if sensitive:
            reasons.append(f"Sensitive query parameter: {name}")
            masked_pairs.append((name, "REDACTED"))
        else:
            masked_pairs.append((name, value))
    if any(marker in parsed.path.lower() for marker in SENSITIVE_PATH_MARKERS):
        reasons.append("Sensitive account-action path")
    masked = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(masked_pairs, doseq=True), ""))
    return masked, reasons


def _validate_public_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(value)
    if not address.is_global:
        raise ValueError(f"Internal, reserved, or non-public target '{address}' is not allowed")
    return address


async def _resolve_public(hostname: str) -> tuple[list[str], int]:
    started = asyncio.get_running_loop().time()
    try:
        literal = _validate_public_ip(hostname)
        return [str(literal)], round((asyncio.get_running_loop().time() - started) * 1000)
    except ValueError as literal_error:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise literal_error

    try:
        records = await asyncio.get_running_loop().getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise ValueError(f"DNS could not resolve '{hostname}'") from exc
    addresses = sorted({record[4][0].split("%", 1)[0] for record in records})
    if not addresses:
        raise ValueError(f"DNS returned no addresses for '{hostname}'")
    for address in addresses:
        _validate_public_ip(address)
    return addresses, round((asyncio.get_running_loop().time() - started) * 1000)


async def normalize_indicator(raw: str, *, resolve_dns: bool = True) -> NormalizedIndicator:
    original = raw.strip()
    if not original or len(original) > 4096:
        raise ValueError("Enter a URL or domain no longer than 4096 characters")
    refanged = _refang(original)
    has_scheme = "://" in refanged
    candidate = refanged if has_scheme else f"//{refanged}"
    parsed = urlsplit(candidate, scheme="https" if has_scheme else "")
    if has_scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS indicators are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not allowed")
    if parsed.fragment:
        raise ValueError("URL fragments are not sent to servers; remove the # fragment")
    if not parsed.hostname:
        raise ValueError("Enter a valid URL or domain")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").rstrip(".").lower()
    except UnicodeError as exc:
        raise ValueError("The hostname is not valid internationalized-domain syntax") from exc
    if not hostname or hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Internal and localhost targets are not allowed")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if "." not in hostname:
            raise ValueError("Single-label and internal hostnames are not allowed")
    if not has_scheme and (parsed.path not in {"", "/"} or parsed.query):
        raise ValueError("Include http:// or https:// when investigating a URL path or query")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The URL port is invalid") from exc

    if ":" in hostname:
        netloc_host = f"[{hostname}]"
    else:
        netloc_host = hostname
    netloc = f"{netloc_host}:{port}" if port is not None else netloc_host
    indicator_type = "url" if has_scheme else "domain"
    if indicator_type == "url":
        exact_url = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
        normalized = exact_url
        preview, sensitive_reasons = _mask_url(exact_url)
        scan_target = exact_url
    else:
        if port is not None:
            raise ValueError("A domain-only investigation cannot include a port")
        exact_url = None
        normalized = hostname
        preview = hostname
        sensitive_reasons = []
        scan_target = f"https://{netloc_host}/"
    resolved_ips, resolution_ms = await _resolve_public(hostname) if resolve_dns else ([], 0)
    digest = hashlib.sha256(f"{indicator_type}\0{normalized}".encode()).hexdigest()
    return NormalizedIndicator(
        original=original,
        normalized=normalized,
        indicator_type=indicator_type,
        exact_url=exact_url,
        hostname=hostname,
        registrable_domain=_registrable_domain(hostname),
        scan_target=scan_target,
        preview=preview,
        is_sensitive=bool(sensitive_reasons),
        sensitive_reasons=sensitive_reasons,
        resolved_ips=resolved_ips,
        resolution_ms=resolution_ms,
        indicator_hash=digest,
    )
