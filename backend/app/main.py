import logging
import time
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.database import init_db

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":%(message)s}',
)
logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())[:8]
        request.state.request_id = request_id
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 1)
        logger.info(
            '"method":"%s","path":"%s","status":%d,"ms":%s,"rid":"%s"',
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            request_id,
        )
        response.headers["X-Request-ID"] = request_id
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info('"Starting Sec360 API"')
    await init_db()
    await _seed_auth_defaults()
    await _seed_integration_defaults()
    from app.collectors.scheduler import start_scheduler
    start_scheduler()
    logger.info('"Sec360 API ready"')
    yield
    from app.collectors.scheduler import stop_scheduler
    stop_scheduler()
    logger.info('"Sec360 API shutdown complete"')


async def _seed_auth_defaults():
    """Create default admin user on first run if no auth users exist."""
    from sqlalchemy import select
    from app.core.database import AsyncSessionLocal
    from app.core.security import hash_password
    from app.models.user import AuthUser

    try:
        async with AsyncSessionLocal() as db:
            count = (await db.execute(select(AuthUser))).scalars().first()
            if count is None:
                db.add(AuthUser(
                    email="admin@sec360.local",
                    hashed_password=hash_password("Admin123!"),
                    role="admin",
                    is_active=True,
                ))
                await db.commit()
                logger.info('"Default admin created: admin@sec360.local / Admin123!"')
    except Exception as e:
        logger.warning('"Could not seed default admin: %s"', e)


async def _seed_integration_defaults():
    from sqlalchemy import select
    from app.core.database import AsyncSessionLocal
    from app.models.integration import IntegrationConfig

    INTEGRATIONS = [
        ("jumpcloud",        "JumpCloud"),
        ("sentinelone",      "SentinelOne"),
        ("symantec_dlp",     "Symantec DLP"),
        ("puppet",           "Puppet"),
        ("active_directory", "Active Directory"),
        ("google_workspace", "Google Workspace"),
        ("hibob",            "HiBob"),
        ("cloudsoc",         "Symantec CloudSOC"),
    ]

    try:
        async with AsyncSessionLocal() as db:
            for itype, display_name in INTEGRATIONS:
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
            await db.commit()
    except Exception as e:
        logger.warning('"Could not seed integration defaults: %s"', e)


app = FastAPI(
    title="Sec360 API",
    description="Security Visibility Platform API",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(RequestLoggingMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
    expose_headers=["X-Total-Count", "X-Request-ID"],
)


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", "?")
    logger.error('"Unhandled exception rid=%s: %s"', rid, exc, exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


from app.api.routes import auth, users, endpoints, compliance, risk, activity, search, integrations, reports, notes, dlp_policy_search, data_quality  # noqa
from app.api.routes import settings as settings_router  # noqa — avoids shadowing app.core.config.settings
from app.api.routes import ai as ai_router  # noqa
from app.api.routes import ai_chat as ai_chat_router  # noqa

app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(endpoints.router, prefix="/api")
app.include_router(compliance.router, prefix="/api")
app.include_router(risk.router, prefix="/api")
app.include_router(activity.router, prefix="/api")
app.include_router(search.router, prefix="/api")
app.include_router(integrations.router, prefix="/api")
app.include_router(settings_router.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(notes.router, prefix="/api")
app.include_router(ai_router.router, prefix="/api")
app.include_router(ai_chat_router.router, prefix="/api")
app.include_router(dlp_policy_search.router, prefix="/api")
app.include_router(data_quality.router, prefix="/api")


@app.get("/health")
async def health_check():
    from app.core.database import engine
    from app.collectors.scheduler import scheduler
    from sqlalchemy import text

    db_ok = False
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        logger.error('"Health check DB error: %s"', e)

    scheduler_ok = scheduler.running

    overall = "ok" if (db_ok and scheduler_ok) else "degraded"
    return {
        "status": overall,
        "version": settings.APP_VERSION,
        "checks": {
            "database": "ok" if db_ok else "error",
            "scheduler": "ok" if scheduler_ok else "stopped",
        },
    }
