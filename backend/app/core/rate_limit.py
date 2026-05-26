"""
Brute-force rate limiting for login endpoints.

Uses Redis when REDIS_URL is configured; falls back to an in-process dict
(works for single-instance deployments, resets on restart).

Sliding window: MAX_ATTEMPTS failures within LOCKOUT_WINDOW triggers a 429.
"""
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Optional

from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

LOCKOUT_WINDOW = timedelta(minutes=15)
MAX_ATTEMPTS = 10

# ── In-memory fallback ─────────────────────────────────────────────────────────
_failed: dict[str, list[datetime]] = defaultdict(list)
_failed_lock = Lock()

# ── Redis client (lazy init) ──────────────────────────────────────────────────
_redis_client = None
_redis_unavailable = False


async def _get_redis():
    global _redis_client, _redis_unavailable
    if _redis_unavailable:
        return None
    if _redis_client is not None:
        return _redis_client

    from app.core.config import settings
    if not settings.REDIS_URL:
        return None

    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=2)
        await client.ping()
        _redis_client = client
        logger.info("Rate limiter: connected to Redis at %s", settings.REDIS_URL)
        return _redis_client
    except Exception as e:
        logger.warning("Rate limiter: Redis unavailable (%s) — using in-memory fallback", e)
        _redis_unavailable = True
        return None


def _mem_check(key: str) -> None:
    now = datetime.now(timezone.utc)
    cutoff = now - LOCKOUT_WINDOW
    with _failed_lock:
        _failed[key] = [t for t in _failed[key] if t > cutoff]
        if len(_failed[key]) >= MAX_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again in 15 minutes.",
            )


def _mem_record(key: str) -> None:
    with _failed_lock:
        _failed[key].append(datetime.now(timezone.utc))


def _mem_clear(key: str) -> None:
    with _failed_lock:
        _failed.pop(key, None)


# ── Public API ────────────────────────────────────────────────────────────────

async def check_rate_limit(email: str, ip: str) -> None:
    key = f"bf:{email}:{ip}"
    r = await _get_redis()
    if r:
        try:
            count = await r.get(key)
            if count and int(count) >= MAX_ATTEMPTS:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many failed login attempts. Try again in 15 minutes.",
                )
            return
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("Rate limiter: Redis error on check (%s), falling back to memory", e)
    _mem_check(key)


async def record_failure(email: str, ip: str) -> None:
    key = f"bf:{email}:{ip}"
    r = await _get_redis()
    if r:
        try:
            pipe = r.pipeline()
            pipe.incr(key)
            pipe.expire(key, int(LOCKOUT_WINDOW.total_seconds()))
            await pipe.execute()
            return
        except Exception as e:
            logger.warning("Rate limiter: Redis error on record (%s), falling back to memory", e)
    _mem_record(key)


async def clear_failures(email: str, ip: str) -> None:
    key = f"bf:{email}:{ip}"
    r = await _get_redis()
    if r:
        try:
            await r.delete(key)
            return
        except Exception as e:
            logger.warning("Rate limiter: Redis error on clear (%s), falling back to memory", e)
    _mem_clear(key)
