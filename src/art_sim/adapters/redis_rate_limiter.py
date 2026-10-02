"""Redis-backed distributed rate limiter — a real, deployment-owned production adapter.

This is the first concrete adapter for one of the project's production ports. It satisfies
``DistributedRateLimiter`` so it can be injected into ``create_production_app``. The limiter
is an atomic sliding-window log implemented with a sorted set and a single Lua script, so the
decision is correct and race-free across every API replica that shares one Redis.

The ``redis`` dependency is optional (``pip install .[redis]``); importing this module requires
it. Core domain and API code never import it.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Awaitable
from typing import Any, ClassVar, cast

from pydantic import BaseModel, ConfigDict, Field
from redis.asyncio import Redis
from redis.exceptions import RedisError

from art_sim.domain.exceptions import DependencyUnavailableError
from art_sim.security.rate_limit import RateLimitDecision, RateLimiterScope, RateLimitPolicy

# Atomic sliding-window log. KEYS[1]=bucket; ARGV: now_ms, window_ms, limit, member.
# Expired entries are trimmed, the current count is read, and admission + insertion happen
# in the same server-side call so concurrent replicas cannot exceed the limit.
_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count < limit then
  redis.call('ZADD', key, now, member)
  redis.call('PEXPIRE', key, window)
  return {1, 0}
end
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local retry_ms = window
if oldest[2] then
  retry_ms = (tonumber(oldest[2]) + window) - now
  if retry_ms < 0 then retry_ms = 0 end
end
return {0, retry_ms}
"""


class RedisRateLimiterSettings(BaseModel):
    """Non-secret configuration for the Redis limiter adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key_prefix: str = Field(default="art-sim:rl", pattern=r"^[A-Za-z0-9_:.-]{1,64}$")


class RedisRateLimiter:
    """Distributed sliding-window limiter backed by a shared Redis instance."""

    deployment_scope: ClassVar[RateLimiterScope] = RateLimiterScope.DISTRIBUTED

    def __init__(self, client: Redis, settings: RedisRateLimiterSettings | None = None) -> None:
        """Inject a configured ``redis.asyncio.Redis`` client and optional settings."""
        self._client = client
        self._settings = settings or RedisRateLimiterSettings()

    @classmethod
    def from_url(cls, url: str, settings: RedisRateLimiterSettings | None = None) -> RedisRateLimiter:
        """Build an adapter from a redis(s):// URL owned by the deployment."""
        return cls(Redis.from_url(url, decode_responses=False), settings)

    async def consume(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision:
        """Atomically admit or reject one request against the shared sliding window."""
        now_ms = int(time.time() * 1000)
        window_ms = policy.window_seconds * 1000
        member = f"{time.monotonic_ns()}-{secrets.token_hex(8)}"
        bucket = f"{self._settings.key_prefix}:{policy.name}:{key}"
        try:
            # redis types EVAL args as strings; Lua `tonumber` parses them back. The async
            # client's return is typed as a sync/async union, so we cast to an awaitable.
            result = await cast(
                "Awaitable[Any]",
                self._client.eval(
                    _SLIDING_WINDOW_LUA,
                    1,
                    bucket,
                    str(now_ms),
                    str(window_ms),
                    str(policy.requests),
                    member,
                ),
            )
        except RedisError as error:
            raise DependencyUnavailableError("Rate limiter backend is unavailable") from error
        allowed = bool(int(result[0]))
        if allowed:
            return RateLimitDecision(True)
        retry_after_seconds = max(1, (int(result[1]) + 999) // 1000)
        return RateLimitDecision(False, retry_after_seconds)

    async def health_check(self) -> None:
        """Verify the shared backend is reachable without consuming caller capacity."""
        try:
            await self._client.ping()
        except RedisError as error:
            raise DependencyUnavailableError("Rate limiter backend is unavailable") from error

    async def close(self) -> None:
        """Release the Redis connection pool during graceful shutdown."""
        await self._client.aclose()
