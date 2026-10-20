from typing import Any

import requests


class PermanentDeliveryError(RuntimeError):
    pass


class Sec360Client:
    def __init__(self, config: dict[str, Any]):
        self.base_url = str(config["url"]).rstrip("/")
        self.timeout = float(config.get("timeout_seconds") or 30)
        self.verify = config.get("verify_ssl", True)
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Collector {config['token']}",
            "User-Agent": "SEC360-Network-Collector/1.0",
        })

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.session.post(
            f"{self.base_url}{path}", json=payload, timeout=self.timeout, verify=self.verify
        )
        if 400 <= response.status_code < 500 and response.status_code not in {401, 429}:
            raise PermanentDeliveryError(f"HTTP {response.status_code}: {response.text[:500]}")
        response.raise_for_status()
        return response.json()

    def ingest(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/network-map/collector/ingest", payload)

    def heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/network-map/collector/heartbeat", payload)
