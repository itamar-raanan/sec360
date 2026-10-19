import asyncio
import re
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.outbound import validate_outbound_host, validate_outbound_url


MAC_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b|"
    r"\b(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}\b"
)
STATE_TOKENS = {
    "associated", "probing", "authenticating", "idle", "run",
    "eap-assoc", "eap-auth", "eap-webauth", "assoc", "webauth",
}


def normalize_mac(value: Any) -> str | None:
    digits = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    if len(digits) != 12:
        return None
    return ":".join(digits[index:index + 2] for index in range(0, 12, 2))


def parse_wlc_clients(text: str) -> list[dict[str, Any]]:
    clients: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = MAC_RE.search(line)
        mac = normalize_mac(match.group(0)) if match else None
        if not mac:
            continue
        tokens = line.split()
        mac_idx = next((i for i, token in enumerate(tokens) if normalize_mac(token) == mac), 0)
        state_idx = next((i for i, token in enumerate(tokens) if token.lower() in STATE_TOKENS), None)
        if state_idx is None:
            state_idx = min(mac_idx + 1, len(tokens) - 1)
        between = tokens[mac_idx + 1:state_idx]
        wlan = next((token for token in between if token.isdigit()), None)
        ap_tokens = [token for token in between if not token.isdigit()]
        clients.append({
            "mac": mac,
            "ap": " ".join(ap_tokens).strip(),
            "wlan": wlan,
            "state": tokens[state_idx] if state_idx < len(tokens) else "",
        })
    return clients


def parse_wlc_wlans(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        tokens = line.split()
        if len(tokens) >= 2 and tokens[0].isdigit():
            result[tokens[0]] = tokens[2] if len(tokens) >= 3 else tokens[1]
    return result


def parse_wlc_aps(text: str) -> list[dict[str, Any]]:
    aps: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = MAC_RE.search(line)
        mac = normalize_mac(match.group(0)) if match else None
        if not match or not mac:
            continue
        tokens = line.split()
        mac_idx = next((i for i, token in enumerate(tokens) if normalize_mac(token) == mac), 0)
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line[match.end():])
        aps.append({
            "name": tokens[0],
            "mac": mac,
            "model": tokens[mac_idx - 1] if mac_idx > 0 else "",
            "ip": ip_match.group(0) if ip_match else "",
        })
    return aps


class _WlcSession:
    def __init__(self, config: dict[str, Any]):
        try:
            import paramiko
        except ImportError as exc:
            raise RuntimeError("The Cisco WLC collector requires the paramiko package") from exc

        self.timeout = int(config.get("timeout_seconds") or 15)
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        if config.get("allow_unknown_host_key", False):
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.client.connect(
            config["host"],
            port=int(config.get("port") or 22),
            username=config.get("username") or "admin",
            password=config.get("password") or "",
            timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        self.shell = self.client.invoke_shell(term="vt100", width=220, height=2000)
        banner = self._read_silence(1.2, 8)
        if banner.rstrip().endswith("User:"):
            self.shell.send((str(config.get("username") or "admin") + "\n").encode())
            self._read_until("Password:", 10)
            self.shell.send((str(config.get("password") or "") + "\n").encode())
            banner += self._read_silence(1.2, 10)
        self.shell.send(b"\n")
        banner += self._read_silence(1.2, 6)
        lines = [line.strip() for line in banner.splitlines() if line.strip()]
        self.prompt = lines[-1] if lines and lines[-1].endswith(("#", ">")) else None
        if not self.prompt:
            self.close()
            raise RuntimeError("Could not detect Cisco WLC CLI prompt")
        self.variant = "iosxe" if self.prompt.endswith("#") else "aireos"
        if self.prompt.endswith(">"):
            probe = self.run("show sysinfo")
            self.variant = "iosxe" if "% Invalid" in probe else "aireos"

    def _recv(self) -> str:
        return self.shell.recv(65535).decode("utf-8", "ignore")

    def _read_silence(self, quiet: float, max_wait: float) -> str:
        buffer = ""
        last = time.time()
        end = time.time() + max_wait
        while time.time() < end and time.time() - last < quiet:
            if self.shell.recv_ready():
                buffer += self._recv()
                last = time.time()
            else:
                time.sleep(0.05)
        return buffer

    def _read_until(self, marker: str, timeout: int | None = None) -> str:
        buffer = ""
        end = time.time() + (timeout or self.timeout)
        while time.time() < end:
            if self.shell.recv_ready():
                chunk = self._recv()
                buffer += chunk
                if "--More--" in chunk:
                    self.shell.send(b" ")
                    buffer = buffer.replace("--More--", "")
                    end = time.time() + (timeout or self.timeout)
                if buffer.rstrip().endswith(marker):
                    break
            else:
                time.sleep(0.05)
        return buffer

    def run(self, command: str) -> str:
        self.shell.send((command + "\n").encode())
        output = self._read_until(self.prompt)
        return output.replace("--More--", "").replace(self.prompt, "").strip()

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass


def _collect_wlc_sync(config: dict[str, Any]) -> dict[str, Any]:
    session = _WlcSession(config)
    try:
        if session.variant == "iosxe":
            session.run("terminal length 0")
            raw_clients = session.run("show wireless client summary")
        else:
            raw_clients = session.run("show client summary")
        if any(marker in raw_clients.lower() for marker in ("% invalid", "denied", "unauthorized")):
            raise RuntimeError("Cisco WLC client summary command was rejected; retained topology was not replaced")
        clients = parse_wlc_clients(raw_clients)
        aps = parse_wlc_aps(session.run("show ap summary"))
        wlans = parse_wlc_wlans(session.run("show wlan summary"))
        return {"variant": session.variant, "clients": clients, "aps": aps, "wlans": wlans}
    finally:
        session.close()


async def collect_cisco_wlc(config: dict[str, Any]) -> dict[str, Any]:
    await validate_outbound_host(str(config.get("host") or ""), int(config.get("port") or 22))
    return await asyncio.to_thread(_collect_wlc_sync, config)


def parse_fortigate_leases(data: Any) -> list[dict[str, Any]]:
    results = data.get("results", data) if isinstance(data, dict) else data
    rows: list[tuple[Any, str | None]] = []
    if isinstance(results, dict):
        for vdom, entries in results.items():
            if isinstance(entries, list):
                rows.extend((entry, str(vdom)) for entry in entries)
    elif isinstance(results, list):
        rows.extend((entry, None) for entry in results)
    leases = []
    for row, vdom in rows:
        if not isinstance(row, dict):
            continue
        mac = normalize_mac(row.get("mac"))
        if not mac:
            continue
        leases.append({
            "mac": mac,
            "ip": row.get("ip") or "",
            "hostname": row.get("hostname") or "",
            "interface": row.get("interface") or "",
            "status": row.get("status") or "",
            "reserved": bool(row.get("reserved")),
            "vdom": vdom,
        })
    return leases


async def collect_fortigate(config: dict[str, Any]) -> dict[str, Any]:
    base_url = str(config.get("base_url") or "").rstrip("/")
    await validate_outbound_url(base_url)
    headers = {"Authorization": f"Bearer {config.get('api_token') or ''}"}
    vdom = config.get("vdom") or "*"
    endpoints = (
        ("/api/v2/monitor/router/dhcp", {"vdom": vdom}),
        ("/api/v2/monitor/router/dhcp", None),
        ("/api/v2/monitor/system/dhcp", {"vdom": vdom}),
        ("/api/v2/monitor/system/dhcp", None),
    )
    errors = []
    async with httpx.AsyncClient(
        timeout=float(config.get("timeout_seconds") or 10),
        verify=bool(config.get("verify_ssl", True)),
    ) as client:
        for path, params in endpoints:
            try:
                response = await client.get(f"{base_url}{path}", headers=headers, params=params)
                if response.status_code == 200:
                    return {"leases": parse_fortigate_leases(response.json())}
                errors.append(f"{path}: HTTP {response.status_code}")
            except (httpx.HTTPError, ValueError) as exc:
                errors.append(f"{path}: {exc}")
    raise RuntimeError("FortiGate DHCP fetch failed: " + " | ".join(errors))


def _collect_swos_sync(config: dict[str, Any]) -> dict[str, Any]:
    try:
        import requests
        from requests.auth import HTTPDigestAuth
        from swos.core import parse_js_object
    except ImportError as exc:
        raise RuntimeError("The MikroTik SwOS collector requires mikrotik-swos") from exc

    url = str(config.get("base_url") or "").rstrip("/")
    response = requests.get(
        f"{url}/!dhost.b",
        auth=HTTPDigestAuth(config.get("username") or "admin", config.get("password") or ""),
        timeout=float(config.get("timeout_seconds") or 10),
        verify=bool(config.get("verify_ssl", False)),
    )
    response.raise_for_status()
    parsed = parse_js_object(response.text) if response.text.strip() else []
    if not isinstance(parsed, list):
        raise RuntimeError("MikroTik SwOS returned a malformed host table; retained topology was not replaced")
    hosts = []
    for row in parsed:
        if not isinstance(row, dict):
            continue
        mac = normalize_mac(row.get("i01") or row.get("adr"))
        if not mac:
            continue
        try:
            port = int(row.get("i02", row.get("prt", 0)) or 0) + 1
        except (TypeError, ValueError):
            port = 1
        hosts.append({"mac": mac, "port": str(port), "vlan": str(row.get("vid") or "")})
    return {"hosts": hosts}


async def collect_mikrotik(config: dict[str, Any]) -> dict[str, Any]:
    url = str(config.get("base_url") or "").rstrip("/")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("MikroTik SwOS URL must be an absolute HTTP(S) URL without embedded credentials")
    # SwOS commonly exposes only HTTP Digest on trusted management networks;
    # still resolve and validate the target before opening a socket.
    await validate_outbound_host(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    return await asyncio.to_thread(_collect_swos_sync, config)


async def collect_for_type(connection_type: str, config: dict[str, Any]) -> dict[str, Any]:
    if connection_type == "cisco_wlc":
        return await collect_cisco_wlc(config)
    if connection_type == "fortigate":
        return await collect_fortigate(config)
    if connection_type == "mikrotik":
        return await collect_mikrotik(config)
    raise ValueError(f"Unsupported Network Map connection type: {connection_type}")
