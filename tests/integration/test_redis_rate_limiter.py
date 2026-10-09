"""Tests for the Redis distributed rate-limiter adapter using an in-process fake that
executes the real Lua sliding-window script."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

import pytest
from redis.asyncio import Redis
from redis.exceptions import RedisError

from art_sim.adapters.redis_rate_limiter import RedisRateLimiter, RedisRateLimiterSettings
from art_sim.domain.exceptions import DependencyUnavailableError
from art_sim.security.rate_limit import RateLimiterScope, RateLimitPolicy


@pytest.fixture
async def limiter(redis_client: Redis) -> AsyncGenerator[RedisRateLimiter]:
    client = redis_client
    adapter = RedisRateLimiter(client, RedisRateLimiterSettings(key_prefix="test:rl"))
    yield adapter
    await adapter.close()


async def test_adapter_declares_distributed_scope() -> None:
    assert RedisRateLimiter.deployment_scope is RateLimiterScope.DISTRIBUTED


async def test_allows_up_to_limit_then_rejects(limiter: RedisRateLimiter) -> None:
    policy = RateLimitPolicy("login", requests=3, window_seconds=60)
    decisions = [await limiter.consume("1.2.3.4", policy) for _ in range(4)]
    assert [d.allowed for d in decisions] == [True, True, True, False]
    assert decisions[-1].retry_after_seconds >= 1


async def test_independent_keys_do_not_share_capacity(limiter: RedisRateLimiter) -> None:
    policy = RateLimitPolicy("create", requests=1, window_seconds=60)
    assert (await limiter.consume("alice", policy)).allowed is True
    assert (await limiter.consume("bob", policy)).allowed is True
    assert (await limiter.consume("alice", policy)).allowed is False


async def test_independent_policies_do_not_share_capacity(limiter: RedisRateLimiter) -> None:
    key = "same-subject"
    assert (await limiter.consume(key, RateLimitPolicy("a", 1, 60))).allowed is True
    # A different policy name is a different bucket even for the same subject.
    assert (await limiter.consume(key, RateLimitPolicy("b", 1, 60))).allowed is True


async def test_window_rolls_over_after_expiry(limiter: RedisRateLimiter) -> None:
    policy = RateLimitPolicy("short", requests=1, window_seconds=1)
    assert (await limiter.consume("roller", policy)).allowed is True
    assert (await limiter.consume("roller", policy)).allowed is False
    await asyncio.sleep(1.2)
    assert (await limiter.consume("roller", policy)).allowed is True


async def test_concurrent_consume_never_exceeds_limit(limiter: RedisRateLimiter) -> None:
    policy = RateLimitPolicy("burst", requests=5, window_seconds=60)
    results = await asyncio.gather(*(limiter.consume("race", policy) for _ in range(20)))
    assert sum(1 for d in results if d.allowed) == 5


async def test_health_check_succeeds_against_live_backend(limiter: RedisRateLimiter) -> None:
    await limiter.health_check()


async def test_backend_errors_map_to_dependency_unavailable() -> None:
    class _BrokenRedis:
        async def eval(self, *_: object) -> object:
            raise RedisError("down")

        async def ping(self) -> object:
            raise RedisError("down")

        async def aclose(self) -> None:
            return None

    adapter = RedisRateLimiter(_BrokenRedis())  # type: ignore[arg-type]
    with pytest.raises(DependencyUnavailableError):
        await adapter.consume("k", RateLimitPolicy("p", 1, 60))
    with pytest.raises(DependencyUnavailableError):
        await adapter.health_check()
    await adapter.close()
