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
    from app.core.config import validate_runtime_security

    validate_runtime_security()
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
    """Create an explicit, one-time bootstrap admin on an empty installation."""
    from sqlalchemy import func, select
    from app.core.database import AsyncSessionLocal
    from app.core.security import hash_password, verify_password
    from app.models.user import AuthUser

    try:
        async with AsyncSessionLocal() as db:
            first_user = (await db.execute(select(AuthUser))).scalars().first()
            password = settings.BOOTSTRAP_ADMIN_PASSWORD or ""
            valid_bootstrap_password = len(password) >= 12 and not password.startswith("CHANGE_ME")
            if first_user is None:
                if not valid_bootstrap_password:
                    raise RuntimeError(
                        "No users exist. Set BOOTSTRAP_ADMIN_PASSWORD to a unique "
                        "value of at least 12 characters, then restart SEC360."
                    )
                db.add(AuthUser(
                    email=settings.BOOTSTRAP_ADMIN_EMAIL.strip().lower(),
                    hashed_password=hash_password(password),
                    role="admin",
                    is_active=True,
                    must_change_password=True,
                ))
                await db.commit()
                logger.warning(
                    '"Bootstrap admin created for %s; password change is required"',
                    settings.BOOTSTRAP_ADMIN_EMAIL.strip().lower(),
                )
                return

            # Upgraded installations may still contain the historical public
            # default. Invalidate it before the API begins serving requests.
            legacy_admin = (await db.execute(
                select(AuthUser).where(func.lower(AuthUser.email) == "admin@sec360.local")
            )).scalar_one_or_none()
            if legacy_admin and verify_password("Admin123!", legacy_admin.hashed_password):
                if not valid_bootstrap_password:
                    raise RuntimeError(
                        "The legacy default administrator password is still active. "
                        "Set BOOTSTRAP_ADMIN_PASSWORD to a unique value of at least "
                        "12 characters, then restart SEC360."
                    )
                legacy_admin.hashed_password = hash_password(password)
                legacy_admin.must_change_password = True
                await db.commit()
                logger.warning(
                    '"Legacy default administrator password invalidated; password change is required"'
                )
    except Exception as e:
        logger.error('"Could not create bootstrap admin: %s"', e)
        raise


async def _seed_integration_defaults():
    from sqlalchemy import select
    from app.core.database import AsyncSessionLocal
    from app.integrations.catalog import INTEGRATION_DEFAULTS, RETIRED_INTEGRATION_TYPES
    from app.models.integration import IntegrationConfig

    try:
        async with AsyncSessionLocal() as db:
            retired = (await db.execute(
                select(IntegrationConfig).where(
                    IntegrationConfig.integration_type.in_(RETIRED_INTEGRATION_TYPES)
                )
            )).scalars().all()
            for config in retired:
                await db.delete(config)
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


from app.api.routes import auth, users, endpoints, compliance, risk, activity, search, integrations, reports, notes, dlp_policy_search, application_vulnerabilities, puppet_facts  # noqa
from app.api.routes import settings as settings_router  # noqa — avoids shadowing app.core.config.settings

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
app.include_router(dlp_policy_search.router, prefix="/api")
app.include_router(application_vulnerabilities.router, prefix="/api")
app.include_router(puppet_facts.router, prefix="/api")


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
