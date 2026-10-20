import re
import time
from typing import Any

import paramiko
import requests
from requests.auth import HTTPDigestAuth
from swos.core import parse_js_object


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
    clients = []
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
        if wlan is None:
            wlan = next((token for token in tokens[state_idx + 1:] if token.isdigit()), None)
        clients.append({
            "mac": mac,
            "ap": " ".join(token for token in between if not token.isdigit()).strip(),
            "wlan": wlan,
            "state": tokens[state_idx] if state_idx < len(tokens) else "",
        })
    return clients


def parse_wlc_aps(text: str) -> list[dict[str, Any]]:
    aps = []
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


def parse_wlc_wlans(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        tokens = line.split()
        if len(tokens) >= 2 and tokens[0].isdigit():
            result[tokens[0]] = tokens[2] if len(tokens) >= 3 else tokens[1]
    return result


class WlcSession:
    def __init__(self, config: dict[str, Any]):
        self.timeout = int(config.get("timeout_seconds") or 15)
        self.client = paramiko.SSHClient()
        known_hosts = str(config.get("known_hosts") or "")
        if known_hosts:
            self.client.load_host_keys(known_hosts)
        else:
            self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy() if config.get("allow_unknown_host_key", False) else paramiko.RejectPolicy()
        )
        self.client.connect(
            str(config["host"]), port=int(config.get("port") or 22),
            username=str(config.get("username") or "admin"),
            password=str(config.get("password") or ""), timeout=self.timeout,
            banner_timeout=self.timeout, auth_timeout=self.timeout,
            allow_agent=False, look_for_keys=False,
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
            self.variant = "iosxe" if "% Invalid" in self.run("show sysinfo") else "aireos"

    def _recv(self) -> str:
        return self.shell.recv(65535).decode("utf-8", "ignore")

    def _read_silence(self, quiet: float, max_wait: float) -> str:
        output, last, end = "", time.time(), time.time() + max_wait
        while time.time() < end and time.time() - last < quiet:
            if self.shell.recv_ready():
                output += self._recv()
                last = time.time()
            else:
                time.sleep(0.05)
        return output

    def _read_until(self, marker: str, timeout: int | None = None) -> str:
        output, duration = "", timeout or self.timeout
        end = time.time() + duration
        while time.time() < end:
            if self.shell.recv_ready():
                chunk = self._recv()
                output += chunk
                if "--More--" in chunk:
                    self.shell.send(b" ")
                    output = output.replace("--More--", "")
                    end = time.time() + duration
                if output.rstrip().endswith(marker):
                    break
            else:
                time.sleep(0.05)
        return output

    def run(self, command: str) -> str:
        self.shell.send((command + "\n").encode())
        return self._read_until(self.prompt).replace("--More--", "").replace(self.prompt, "").strip()

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass


def collect_wlc(config: dict[str, Any]) -> dict[str, Any]:
    session = WlcSession(config)
    try:
        if session.variant == "iosxe":
            session.run("terminal length 0")
            raw_clients = session.run("show wireless client summary")
        else:
            raw_clients = session.run("show client summary")
        if any(marker in raw_clients.lower() for marker in ("% invalid", "denied", "unauthorized")):
            raise RuntimeError("Cisco WLC client summary command was rejected")
        raw_wlans = session.run("show wlan summary")
        return {
            "clients": parse_wlc_clients(raw_clients),
            "access_points": parse_wlc_aps(session.run("show ap summary")),
            "wlans": {} if "% invalid" in raw_wlans.lower() else parse_wlc_wlans(raw_wlans),
        }
    finally:
        session.close()


def _lease(row: Any, vdom: str | None = None) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    mac = normalize_mac(row.get("mac"))
    if not mac:
        return None
    result = {
        "mac": mac, "ip": row.get("ip") or "", "hostname": row.get("hostname") or "",
        "interface": row.get("interface") or "", "status": row.get("status") or "",
        "reserved": bool(row.get("reserved")), "vdom": vdom,
    }
    if row.get("expire_time") is not None:
        result["expire_time"] = row["expire_time"]
    return result


def parse_fortigate_leases(data: Any) -> list[dict[str, Any]]:
    results = data.get("results", data) if isinstance(data, dict) else data
    leases = []
    if isinstance(results, dict):
        for vdom, rows in results.items():
            if isinstance(rows, list):
                leases.extend(item for row in rows if (item := _lease(row, str(vdom))))
    elif isinstance(results, list):
        leases.extend(item for row in results if (item := _lease(row)))
    return leases


def collect_fortigate(config: dict[str, Any]) -> dict[str, Any]:
    base_url = str(config["base_url"]).rstrip("/")
    headers = {"Authorization": f"Bearer {config.get('api_token') or ''}"}
    vdom = config.get("vdom") or "*"
    endpoints = (
        ("/api/v2/monitor/router/dhcp", {"vdom": vdom}),
        ("/api/v2/monitor/router/dhcp", None),
        ("/api/v2/monitor/system/dhcp", {"vdom": vdom}),
        ("/api/v2/monitor/system/dhcp", None),
    )
    errors = []
    for path, params in endpoints:
        try:
            response = requests.get(
                f"{base_url}{path}", params=params, headers=headers,
                timeout=float(config.get("timeout_seconds") or 10),
                verify=config.get("verify_ssl", True),
            )
            if response.status_code == 200:
                return {"leases": parse_fortigate_leases(response.json())}
            errors.append(f"{path}: HTTP {response.status_code}")
        except (requests.RequestException, ValueError) as exc:
            errors.append(f"{path}: {exc}")
    raise RuntimeError("FortiGate DHCP fetch failed: " + " | ".join(errors))


def collect_mikrotik(config: dict[str, Any]) -> dict[str, Any]:
    base_url = str(config["base_url"]).rstrip("/")
    response = requests.get(
        f"{base_url}/!dhost.b",
        auth=HTTPDigestAuth(str(config.get("username") or "admin"), str(config.get("password") or "")),
        timeout=float(config.get("timeout_seconds") or 10),
        verify=config.get("verify_ssl", True),
    )
    response.raise_for_status()
    parsed = parse_js_object(response.text) if response.text.strip() else []
    if not isinstance(parsed, list):
        raise RuntimeError("MikroTik SwOS returned a malformed host table")
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
    return {
        "switch": {"name": config.get("name") or config["id"], "base_url": base_url},
        "hosts": hosts,
    }


def collect_source(config: dict[str, Any]) -> dict[str, Any]:
    source_type = config["type"]
    if source_type == "cisco_wlc":
        return collect_wlc(config)
    if source_type == "fortigate":
        return collect_fortigate(config)
    if source_type == "mikrotik":
        return collect_mikrotik(config)
    raise ValueError(f"Unsupported source type: {source_type}")
