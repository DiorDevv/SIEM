"""
Redis-backed per-IP rate limiting middleware.

Rate limit zones (requests per minute):
  /api/auth/*    — 20  (strict, brute-force protection)
  /api/logs/*    — 600 (agents send batches; high throughput needed)
  /api/*         — 300 (general API)
  default        — 120
"""
import json
import logging
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_RATE_ZONES = [
    ("/api/auth/", 20),
    ("/api/logs/ingest", 600),
    ("/api/", 300),
]
_DEFAULT_LIMIT = 120
_SKIP_PATHS = {"/api/health", "/api/metrics"}


def _get_limit(path: str) -> int:
    for prefix, limit in _RATE_ZONES:
        if path.startswith(prefix):
            return limit
    return _DEFAULT_LIMIT


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, redis_url: str):
        super().__init__(app)
        self._redis_url = redis_url
        self._redis: aioredis.Redis | None = None

    async def _get_redis(self) -> aioredis.Redis | None:
        if self._redis is None:
            try:
                self._redis = aioredis.from_url(self._redis_url, decode_responses=True)
                await self._redis.ping()
            except Exception as e:
                logger.warning(f"RateLimitMiddleware: Redis unavailable ({e}), skipping limits")
                self._redis = None
        return self._redis

    async def dispatch(self, request: Request, call_next: any) -> Response:
        path = request.url.path
        if path in _SKIP_PATHS:
            return await call_next(request)

        redis = await self._get_redis()
        if redis is None:
            return await call_next(request)

        client_ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
        limit = _get_limit(path)
        window = 60  # seconds
        key = f"siem:rl:{client_ip}:{path.split('/')[2] if path.count('/') >= 2 else 'root'}"

        try:
            now = time.time()
            cutoff = now - window
            pipe = redis.pipeline()
            await pipe.zremrangebyscore(key, 0, cutoff)
            await pipe.zadd(key, {f"{now}:{id(request)}": now})
            await pipe.zcard(key)
            await pipe.expire(key, window)
            results = await pipe.execute()
            count = results[2]

            if count > limit:
                retry_after = window
                return Response(
                    content=json.dumps({
                        "detail": "Rate limit exceeded",
                        "limit": limit,
                        "window_seconds": window,
                    }),
                    status_code=429,
                    media_type="application/json",
                    headers={"Retry-After": str(retry_after)},
                )
        except Exception as e:
            logger.warning(f"Rate limit check error: {e}")

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Window"] = str(window)
        return response
