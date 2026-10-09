"""Tests for ``RedisStreamsBrokerTransport.purge_dead_letter`` using fakeredis.

Uses explicit Redis Streams entry IDs (``<milliseconds>-<sequence>``) instead of relying on
real wall-clock timing, so the retention cutoff logic is exercised deterministically.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from redis.asyncio import Redis

from art_sim.adapters.redis_streams_broker import RedisStreamsBrokerTransport, RedisStreamsSettings

SETTINGS = RedisStreamsSettings()


def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


@pytest.fixture
async def transport(redis_client: Redis) -> RedisStreamsBrokerTransport:
    return RedisStreamsBrokerTransport(redis_client, SETTINGS)


async def _add_dlq_entry(transport: RedisStreamsBrokerTransport, when: datetime, reason: str) -> None:
    await transport._client.xadd(
        SETTINGS.dlq_stream,
        {b"payload": b"{}", b"reason": reason.encode("utf-8"), b"correlation_id": b"corr-1"},
        id=f"{_ms(when)}-0",
    )


async def test_purges_only_entries_older_than_cutoff(transport: RedisStreamsBrokerTransport) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    await _add_dlq_entry(transport, now - timedelta(days=60), "old")
    await _add_dlq_entry(transport, now - timedelta(days=1), "recent")

    cutoff = now - timedelta(days=30)
    purged = await transport.purge_dead_letter(older_than=cutoff, dry_run=False)
    assert purged == 1

    remaining = await transport._client.xrange(SETTINGS.dlq_stream, min="-", max="+")
    assert len(remaining) == 1
    assert remaining[0][1][b"reason"] == b"recent"


async def test_dry_run_counts_without_deleting(transport: RedisStreamsBrokerTransport) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    await _add_dlq_entry(transport, now - timedelta(days=60), "old")

    cutoff = now - timedelta(days=30)
    purged = await transport.purge_dead_letter(older_than=cutoff, dry_run=True)
    assert purged == 1

    remaining = await transport._client.xrange(SETTINGS.dlq_stream, min="-", max="+")
    assert len(remaining) == 1  # dry run deleted nothing


async def test_empty_dlq_purges_nothing(transport: RedisStreamsBrokerTransport) -> None:
    purged = await transport.purge_dead_letter(older_than=datetime.now(UTC), dry_run=False)
    assert purged == 0


async def test_nothing_past_cutoff_purges_nothing(transport: RedisStreamsBrokerTransport) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    await _add_dlq_entry(transport, now - timedelta(days=1), "recent")

    cutoff = now - timedelta(days=30)
    purged = await transport.purge_dead_letter(older_than=cutoff, dry_run=False)
    assert purged == 0
