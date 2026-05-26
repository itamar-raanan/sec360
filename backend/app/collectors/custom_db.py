import asyncio
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


def _default_port(db_type: str) -> int:
    if db_type == "mssql":
        return 1433
    if db_type == "mysql":
        return 3306
    return 5432  # postgresql default


class CustomDbCollector:
    name = "custom_db"

    def __init__(self, credentials: dict, db: AsyncSession):
        self.db_type = credentials.get("db_type", "postgresql").lower()
        self.db_host = credentials.get("db_host", "")
        self.db_port = int(credentials.get("db_port") or _default_port(self.db_type))
        self.db_name = credentials.get("db_name", "")
        self.db_user = credentials.get("db_user", "")
        self.db_password = credentials.get("db_password", "")
        self.query = credentials.get("query", "SELECT 1")
        self.entity_type = credentials.get("entity_type", "endpoint")
        self.display_name = credentials.get("custom_name", "Custom DB")
        self.db = db

    async def test_connection(self) -> dict:
        if not self.db_host:
            return {"success": False, "message": "No database host configured"}
        if not self.db_name:
            return {"success": False, "message": "No database name configured"}

        try:
            if self.db_type == "postgresql":
                return await self._test_postgresql()
            elif self.db_type in ("mssql", "sqlserver"):
                return await asyncio.get_event_loop().run_in_executor(None, self._test_mssql)
            elif self.db_type == "mysql":
                return await asyncio.get_event_loop().run_in_executor(None, self._test_mysql)
            else:
                return {"success": False, "message": f"Unsupported DB type: {self.db_type}"}
        except Exception as e:
            return {"success": False, "message": f"Connection error: {str(e)}"}

    async def _test_postgresql(self) -> dict:
        import asyncpg
        try:
            conn = await asyncpg.connect(
                host=self.db_host,
                port=self.db_port,
                database=self.db_name,
                user=self.db_user,
                password=self.db_password,
                timeout=15,
            )
            await conn.execute("SELECT 1")
            await conn.close()
            return {"success": True, "message": f"Connected to PostgreSQL {self.db_host}/{self.db_name}"}
        except Exception as e:
            return {"success": False, "message": f"PostgreSQL error: {str(e)}"}

    def _test_mssql(self) -> dict:
        import pymssql
        try:
            conn = pymssql.connect(
                server=self.db_host,
                port=str(self.db_port),
                database=self.db_name,
                user=self.db_user,
                password=self.db_password,
                timeout=15,
                login_timeout=15,
            )
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            conn.close()
            return {"success": True, "message": f"Connected to MSSQL {self.db_host}/{self.db_name}"}
        except Exception as e:
            return {"success": False, "message": f"MSSQL error: {str(e)}"}

    def _test_mysql(self) -> dict:
        try:
            import pymysql  # type: ignore
        except ImportError:
            return {"success": False, "message": "pymysql is not installed — MySQL is not supported in this deployment"}
        try:
            conn = pymysql.connect(
                host=self.db_host,
                port=self.db_port,
                database=self.db_name,
                user=self.db_user,
                password=self.db_password,
                connect_timeout=15,
            )
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            conn.close()
            return {"success": True, "message": f"Connected to MySQL {self.db_host}/{self.db_name}"}
        except Exception as e:
            return {"success": False, "message": f"MySQL error: {str(e)}"}

    async def collect(self) -> dict:
        if not self.db_host or not self.db_name:
            return {"records_synced": 0, "error": "Database host and name are required"}

        try:
            if self.db_type == "postgresql":
                rows = await self._collect_postgresql()
            elif self.db_type in ("mssql", "sqlserver"):
                rows = await asyncio.get_event_loop().run_in_executor(None, self._collect_mssql)
            elif self.db_type == "mysql":
                rows = await asyncio.get_event_loop().run_in_executor(None, self._collect_mysql)
            else:
                return {"records_synced": 0, "error": f"Unsupported DB type: {self.db_type}"}

            count = await self._store_rows(rows)
            return {"records_synced": count}
        except Exception as e:
            logger.error(f"CustomDB collect error: {e}", exc_info=True)
            return {"records_synced": 0, "error": str(e)}

    async def _collect_postgresql(self) -> list[dict[str, Any]]:
        import asyncpg
        conn = await asyncpg.connect(
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
            user=self.db_user,
            password=self.db_password,
            timeout=30,
        )
        try:
            rows = await conn.fetch(self.query)
            return [dict(row) for row in rows]
        finally:
            await conn.close()

    def _collect_mssql(self) -> list[dict[str, Any]]:
        import pymssql
        conn = pymssql.connect(
            server=self.db_host,
            port=str(self.db_port),
            database=self.db_name,
            user=self.db_user,
            password=self.db_password,
            timeout=30,
            login_timeout=15,
        )
        try:
            cursor = conn.cursor(as_dict=True)
            cursor.execute(self.query)
            return cursor.fetchall()
        finally:
            conn.close()

    def _collect_mysql(self) -> list[dict[str, Any]]:
        import pymysql  # type: ignore
        import pymysql.cursors
        conn = pymysql.connect(
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
            user=self.db_user,
            password=self.db_password,
            connect_timeout=15,
            cursorclass=pymysql.cursors.DictCursor,
        )
        try:
            with conn.cursor() as cursor:
                cursor.execute(self.query)
                return cursor.fetchall()
        finally:
            conn.close()

    async def _store_rows(self, rows: list[dict[str, Any]]) -> int:
        from app.models.application import RawData

        count = 0
        for row in rows:
            # Ensure all values are JSON-serialisable
            clean: dict[str, Any] = {}
            for k, v in row.items():
                if hasattr(v, "isoformat"):
                    clean[k] = v.isoformat()
                elif isinstance(v, (int, float, str, bool, type(None))):
                    clean[k] = v
                else:
                    clean[k] = str(v)
            raw = RawData(
                source=self.display_name,
                entity_type=self.entity_type,
                raw_json=clean,
            )
            self.db.add(raw)
            count += 1

        if count:
            await self.db.flush()
        return count
