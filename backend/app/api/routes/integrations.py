import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from fastapi import Request
from app.api.deps import get_db, get_current_user, require_role, audit_action
from app.core.database import AsyncSessionLocal
from app.models.user import AuthUser
from app.models.integration import IntegrationConfig
from app.schemas.integration import (
    IntegrationConfigResponse,
    IntegrationConfigUpdate,
    SyncResult,
    CustomIntegrationCreate,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations", tags=["integrations"])

INTEGRATION_DEFAULTS = [
    ("jumpcloud", "JumpCloud"),
    ("sentinelone", "SentinelOne"),
    ("symantec_dlp", "Symantec DLP"),
    ("google_workspace", "Google Workspace"),
    ("hibob", "HiBob"),
    ("puppet", "Puppet"),
    ("active_directory", "Active Directory"),
]


def _to_response(config: IntegrationConfig) -> IntegrationConfigResponse:
    return IntegrationConfigResponse(
        id=config.id,
        integration_type=config.integration_type,
        display_name=config.display_name,
        is_enabled=config.is_enabled,
        status=config.status,
        last_sync=config.last_sync,
        last_error=config.last_error,
        records_synced=config.records_synced,
        credentials_configured=bool(config.credentials),
    )


async def _ensure_defaults(db: AsyncSession) -> None:
    """Create default integration rows if they don't exist."""
    for itype, display_name in INTEGRATION_DEFAULTS:
        existing = (await db.execute(
            select(IntegrationConfig).where(IntegrationConfig.integration_type == itype)
        )).scalar_one_or_none()
        if not existing:
            db.add(IntegrationConfig(
                integration_type=itype,
                display_name=display_name,
                is_enabled=False,
                status="unconfigured",
            ))
    await db.flush()


@router.get("", response_model=List[IntegrationConfigResponse])
async def list_integrations(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(get_current_user),
):
    await _ensure_defaults(db)
    result = await db.execute(select(IntegrationConfig))
    configs = result.scalars().all()
    # Order by INTEGRATION_DEFAULTS order
    order = {itype: i for i, (itype, _) in enumerate(INTEGRATION_DEFAULTS)}
    configs = sorted(configs, key=lambda c: order.get(c.integration_type, 99))
    return [_to_response(c) for c in configs]


@router.put("/{integration_type}", response_model=IntegrationConfigResponse)
async def update_integration(
    integration_type: str,
    body: IntegrationConfigUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    config = (await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.integration_type == integration_type)
    )).scalar_one_or_none()

    if not config:
        # Find display name
        display_name = next(
            (dn for it, dn in INTEGRATION_DEFAULTS if it == integration_type),
            integration_type,
        )
        config = IntegrationConfig(
            integration_type=integration_type,
            display_name=display_name,
        )
        db.add(config)

    config.credentials = body.credentials
    config.is_enabled = body.is_enabled
    if config.status == "unconfigured" or not config.status:
        config.status = "unconfigured"
    await db.flush()
    await audit_action("update_integration", "integration", integration_type, request, db, current, {"enabled": body.is_enabled})
    return _to_response(config)


@router.delete("/{integration_type}/credentials", status_code=status.HTTP_204_NO_CONTENT)
async def delete_integration_credentials(
    integration_type: str,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    config = (await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.integration_type == integration_type)
    )).scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Integration not found")

    config.credentials = None
    config.is_enabled = False
    config.status = "unconfigured"
    config.last_error = None
    config.last_sync = None
    config.records_synced = None
    await db.flush()


@router.post("/{integration_type}/test")
async def test_integration(
    integration_type: str,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    config = (await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.integration_type == integration_type)
    )).scalar_one_or_none()

    if not config:
        return {"success": False, "message": "Integration not found"}

    if not config.credentials:
        return {"success": False, "message": "No credentials configured"}

    result = await _run_test(integration_type, config.credentials, db)

    # Update status based on test result
    if result.get("success"):
        if config.status == "unconfigured":
            config.status = "unconfigured"  # Keep unconfigured until sync
    else:
        config.last_error = result.get("message", "Test failed")

    await db.flush()
    return result


@router.post("/{integration_type}/sync", response_model=SyncResult)
async def sync_integration(
    integration_type: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    config = (await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.integration_type == integration_type)
    )).scalar_one_or_none()

    if not config:
        return SyncResult(success=False, message="Integration not found")

    if not config.credentials:
        return SyncResult(success=False, message="No credentials configured")

    result = await _run_collect(integration_type, config.credentials)

    now = datetime.now(timezone.utc)
    if result.get("error"):
        config.status = "error"
        config.last_error = result["error"]
        config.last_sync = now
        await db.flush()
        await audit_action("sync_integration", "integration", integration_type, request, db, current, {"success": False, "error": result["error"]})
        return SyncResult(
            success=False,
            message=result["error"],
            error=result["error"],
            records_synced=result.get("records_synced", 0),
        )
    else:
        config.status = "connected"
        config.last_error = None
        config.last_sync = now
        count = result.get("records_synced", 0)
        config.records_synced = str(count)
        await db.flush()
        await audit_action("sync_integration", "integration", integration_type, request, db, current, {"success": True, "records_synced": count})
        return SyncResult(
            success=True,
            message=f"Sync completed. {count} records synced.",
            records_synced=count,
        )


async def _run_test(integration_type: str, credentials: dict, db: AsyncSession) -> dict:
    try:
        if integration_type == "jumpcloud":
            from app.collectors.jumpcloud import JumpCloudCollector
            collector = JumpCloudCollector(credentials=credentials, db=db)
            return await collector.test_connection()

        elif integration_type == "sentinelone":
            from app.collectors.sentinelone import SentinelOneCollector
            collector = SentinelOneCollector(credentials=credentials, db=db)
            return await collector.test_connection()

        elif integration_type == "symantec_dlp":
            from app.collectors.symantec import SymantecCollector
            collector = SymantecCollector(credentials=credentials, db=db)
            return await collector.test_connection()

        elif integration_type == "google_workspace":
            from app.collectors.google_workspace import GoogleWorkspaceCollector
            collector = GoogleWorkspaceCollector(credentials=credentials, db=db)
            return await collector.test_connection()

        elif integration_type == "hibob":
            from app.collectors.hibob import HiBobCollector
            collector = HiBobCollector(credentials=credentials, db=db)
            return await collector.test_connection()

        elif integration_type == "puppet":
            from app.collectors.puppet import PuppetCollector
            collector = PuppetCollector(credentials=credentials, db=db)
            return await collector.test_connection()

        elif integration_type == "active_directory":
            from app.collectors.active_directory import ActiveDirectoryCollector
            collector = ActiveDirectoryCollector(credentials=credentials, db=db)
            return await collector.test_connection()

        elif integration_type == "cloudsoc":
            from app.collectors.cloudsoc import CloudSOCCollector
            collector = CloudSOCCollector(credentials=credentials, db=db)
            return await collector.test_connection()

        elif integration_type.startswith("custom_api"):
            from app.collectors.custom_api import CustomApiCollector
            collector = CustomApiCollector(credentials=credentials, db=db)
            return await collector.test_connection()

        elif integration_type.startswith("custom_db"):
            from app.collectors.custom_db import CustomDbCollector
            collector = CustomDbCollector(credentials=credentials, db=db)
            return await collector.test_connection()

        else:
            return {"success": False, "message": f"Unknown integration type: {integration_type}"}

    except Exception as e:
        logger.error(f"Test connection error for {integration_type}: {e}", exc_info=True)
        return {"success": False, "message": f"Unexpected error: {str(e)}"}


async def _run_collect(integration_type: str, credentials: dict) -> dict:
    """Run a collector in its own isolated DB session so failures never contaminate the caller's transaction."""
    async with AsyncSessionLocal() as session:
        try:
            if integration_type == "jumpcloud":
                from app.collectors.jumpcloud import JumpCloudCollector
                collector = JumpCloudCollector(credentials=credentials, db=session)
            elif integration_type == "sentinelone":
                from app.collectors.sentinelone import SentinelOneCollector
                collector = SentinelOneCollector(credentials=credentials, db=session)
            elif integration_type == "symantec_dlp":
                from app.collectors.symantec import SymantecCollector
                collector = SymantecCollector(credentials=credentials, db=session)
            elif integration_type == "google_workspace":
                from app.collectors.google_workspace import GoogleWorkspaceCollector
                collector = GoogleWorkspaceCollector(credentials=credentials, db=session)
            elif integration_type == "hibob":
                from app.collectors.hibob import HiBobCollector
                collector = HiBobCollector(credentials=credentials, db=session)
            elif integration_type == "puppet":
                from app.collectors.puppet import PuppetCollector
                collector = PuppetCollector(credentials=credentials, db=session)
            elif integration_type == "active_directory":
                from app.collectors.active_directory import ActiveDirectoryCollector
                collector = ActiveDirectoryCollector(credentials=credentials, db=session)
            elif integration_type == "cloudsoc":
                from app.collectors.cloudsoc import CloudSOCCollector
                collector = CloudSOCCollector(credentials=credentials, db=session)
            elif integration_type.startswith("custom_api"):
                from app.collectors.custom_api import CustomApiCollector
                collector = CustomApiCollector(credentials=credentials, db=session)
            elif integration_type.startswith("custom_db"):
                from app.collectors.custom_db import CustomDbCollector
                collector = CustomDbCollector(credentials=credentials, db=session)
            else:
                return {"records_synced": 0, "error": f"Unknown integration type: {integration_type}"}

            result = await collector.collect()

            if result.get("error"):
                await session.rollback()
            else:
                await session.commit()

            return result

        except Exception as e:
            await session.rollback()
            logger.error(f"Collect error for {integration_type}: {e}", exc_info=True)
            return {"records_synced": 0, "error": str(e)}


# ── Custom integration management ─────────────────────────────────────────────

@router.post("", response_model=IntegrationConfigResponse, status_code=201)
async def create_custom_integration(
    body: CustomIntegrationCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    """Create a new custom integration (custom_api_* or custom_db_*)."""
    if not (body.integration_type.startswith("custom_api") or body.integration_type.startswith("custom_db")):
        raise HTTPException(
            status_code=400,
            detail="integration_type must start with 'custom_api' or 'custom_db'",
        )

    existing = (await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.integration_type == body.integration_type)
    )).scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Integration '{body.integration_type}' already exists",
        )

    config = IntegrationConfig(
        integration_type=body.integration_type,
        display_name=body.display_name,
        credentials=body.credentials,
        is_enabled=body.is_enabled,
        status="unconfigured",
    )
    db.add(config)
    await db.flush()
    await audit_action("create_integration", "integration", body.integration_type, request, db, current, {"display_name": body.display_name})
    return _to_response(config)


@router.delete("/{integration_type}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_integration(
    integration_type: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("admin")),
):
    """Delete a custom integration entirely, or clear credentials for a built-in one."""
    config = (await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.integration_type == integration_type)
    )).scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Integration not found")

    if integration_type.startswith("custom_"):
        # Custom integrations: delete the row entirely
        await db.delete(config)
    else:
        # Built-in integrations: just clear credentials (keep the row)
        config.credentials = None
        config.is_enabled = False
        config.status = "unconfigured"
        config.last_error = None
        config.last_sync = None
        config.records_synced = None

    await db.flush()
    await audit_action("delete_integration", "integration", integration_type, request, db, current, {})
