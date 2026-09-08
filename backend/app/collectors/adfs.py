import xml.etree.ElementTree as ET

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.base import BaseCollector


class ADFSCollector(BaseCollector):
    """Monitor an ADFS federation service through its public metadata document."""

    name = "adfs"

    def __init__(self, credentials: dict | None = None, db: AsyncSession | None = None):
        super().__init__()
        values = credentials or {}
        service_url = str(values.get("service_url") or "").strip().rstrip("/")
        self.metadata_url = str(values.get("metadata_url") or "").strip()
        if not self.metadata_url and service_url:
            self.metadata_url = (
                f"{service_url}/FederationMetadata/2007-06/FederationMetadata.xml"
            )
        verify_ssl = values.get("verify_ssl", True)
        self.verify_ssl = verify_ssl not in (False, "false", "0", 0)
        self.db = db

    async def test_connection(self) -> dict:
        if not self.metadata_url:
            return {
                "success": False,
                "message": "ADFS service URL or federation metadata URL is required",
            }
        try:
            async with httpx.AsyncClient(timeout=20.0, verify=self.verify_ssl) as client:
                response = await client.get(
                    self.metadata_url,
                    headers={"Accept": "application/xml, text/xml"},
                    follow_redirects=True,
                )
                if response.status_code in (401, 403):
                    return {
                        "success": False,
                        "message": "ADFS metadata is not publicly readable",
                    }
                response.raise_for_status()
                root = ET.fromstring(response.content)
                entity_id = root.attrib.get("entityID") or "federation service"
                return {
                    "success": True,
                    "message": f"Connected successfully. ADFS metadata found for {entity_id}.",
                }
        except ET.ParseError:
            return {
                "success": False,
                "message": "The ADFS endpoint did not return valid federation metadata XML",
            }
        except httpx.TimeoutException:
            return {"success": False, "message": "ADFS metadata request timed out"}
        except Exception as exc:
            return {"success": False, "message": f"ADFS connection failed: {exc}"}

    async def collect(self) -> dict:
        result = await self.test_connection()
        if not result.get("success"):
            return {"records_synced": 0, "error": result.get("message")}
        return {"records_synced": 0}
