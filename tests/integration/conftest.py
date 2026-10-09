"""Shared integration fixtures.

``redis_client`` runs every Redis-backed test twice when a real server is available:
once against ``fakeredis`` (always) and once against a real Redis named by
``ART_REDIS_TEST_URL`` (e.g. ``redis://127.0.0.1:6379/15``). The real variant is skipped,
visibly, when the variable is unset or the server is unreachable — so a green run never
silently pretends a real broker was exercised. The target database is flushed first: point
it at a throwaway instance/database, never at one that holds data you care about.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator

import fakeredis.aioredis as fakeredis
import pytest
from redis.asyncio import Redis
from redis.exceptions import RedisError

REDIS_URL = os.getenv("ART_REDIS_TEST_URL")


@pytest.fixture(params=["fakeredis", "real-redis"])
async def redis_client(request: pytest.FixtureRequest) -> AsyncGenerator[Redis]:
    if request.param == "fakeredis":
        client: Redis = fakeredis.FakeRedis()
    else:
        if not REDIS_URL:
            pytest.skip("ART_REDIS_TEST_URL is not set; real Redis not exercised")
        client = Redis.from_url(REDIS_URL)
        try:
            await client.ping()
        except (OSError, RedisError):
            await client.aclose()
            pytest.skip(f"Redis at {REDIS_URL} is unreachable")
        await client.flushdb()
    yield client
    if request.param == "real-redis":
        await client.flushdb()
    await client.aclose()
