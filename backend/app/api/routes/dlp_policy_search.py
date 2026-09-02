import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit_action, get_db, require_role
from app.models.integration import IntegrationConfig
from app.models.user import AuthUser
from app.schemas.dlp_policy_search import DlpPolicySearchResponse
from app.services.dlp_policy_search import MAX_DLP_POLICY_ROWS, query_dlp_policy_exclusions

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/dlp-policy-search", tags=["dlp-policy-search"])


@router.get("", response_model=DlpPolicySearchResponse)
async def get_dlp_policy_exclusions(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    integration = (await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.integration_type == "symantec_dlp"
        )
    )).scalar_one_or_none()

    if not integration or not integration.credentials:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Symantec DLP database credentials are not configured.",
        )

    credentials = integration.credentials
    if str(credentials.get("db_type", "")).lower() != "oracle":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="DLP User Policy Search requires the Symantec DLP integration to use Oracle.",
        )

    required_fields = ("db_host", "db_port", "db_name", "db_user", "db_password")
    if any(not credentials.get(field) for field in required_fields):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The Symantec DLP Oracle connection is missing required credentials.",
        )

    started = time.perf_counter()
    try:
        items, truncated = await query_dlp_policy_exclusions(credentials)
    except Exception as exc:
        logger.error("DLP policy exclusion query failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The Symantec DLP database query failed. Verify the integration and database permissions.",
        ) from exc

    duration_ms = round((time.perf_counter() - started) * 1000)
    await audit_action(
        "search_dlp_user_policies",
        "symantec_dlp",
        None,
        request,
        db,
        current,
        {"rows_returned": len(items), "truncated": truncated, "duration_ms": duration_ms},
    )
    return DlpPolicySearchResponse(
        items=items,
        row_count=len(items),
        max_rows=MAX_DLP_POLICY_ROWS,
        truncated=truncated,
        query_duration_ms=duration_ms,
        source_refreshed_at=datetime.now(timezone.utc),
        integration_status=integration.status,
    )
