"""Tests for the Redis Streams broker transport and consumer using fakeredis."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from art_sim.adapters.redis_streams_broker import (
    RedisStreamsBrokerTransport,
    RedisStreamsJobConsumer,
    RedisStreamsSettings,
)
from art_sim.worker.broker import BrokerProvider
from art_sim.worker.jobs import SimulationJobV1

FAST = RedisStreamsSettings(visibility_timeout_seconds=1, dedup_ttl_seconds=60)


def _job(scenario: str = "shadow-demo", attempt: int = 1) -> SimulationJobV1:
    return SimulationJobV1(
        message_id=uuid4(),
        run_id=uuid4(),
        workflow_version="v1",
        scenario_id=scenario,
        attempt=attempt,
        created_at=datetime.now(UTC),
        correlation_id="corr-1",
    )


@pytest.fixture
async def broker(
    redis_client: Redis,
) -> AsyncGenerator[tuple[RedisStreamsBrokerTransport, RedisStreamsJobConsumer]]:
    client = redis_client
    transport = RedisStreamsBrokerTransport(client, FAST)
    consumer = RedisStreamsJobConsumer(client, "worker-1", FAST)
    yield transport, consumer
    await transport.close()


async def test_transport_declares_redis_streams_provider() -> None:
    assert RedisStreamsBrokerTransport.provider is BrokerProvider.REDIS_STREAMS


async def test_publish_is_idempotent_by_dedup_key(
    broker: tuple[RedisStreamsBrokerTransport, RedisStreamsJobConsumer],
) -> None:
    transport, _ = broker
    job = _job()
    assert await transport.publish(job, "dedup-A") is True
    assert await transport.publish(job, "dedup-A") is False  # logical duplicate
    assert await transport.publish(job, "dedup-B") is True


async def test_published_job_is_received_and_decodes(
    broker: tuple[RedisStreamsBrokerTransport, RedisStreamsJobConsumer],
) -> None:
    transport, consumer = broker
    job = _job(scenario="shadow-container-breakout")
    await transport.publish(job, "k1")
    delivery = await consumer.receive(timeout_seconds=1)
    assert delivery is not None
    assert delivery.correlation_id == "corr-1"
    assert delivery.delivery_attempt == 1
    decoded = SimulationJobV1.decode(delivery.payload)
    assert decoded.run_id == job.run_id
    assert decoded.scenario_id == "shadow-container-breakout"


async def test_acknowledge_prevents_redelivery(
    broker: tuple[RedisStreamsBrokerTransport, RedisStreamsJobConsumer],
) -> None:
    transport, consumer = broker
    await transport.publish(_job(), "k1")
    delivery = await consumer.receive(timeout_seconds=1)
    assert delivery is not None
    await delivery.acknowledge()
    assert await consumer.receive(timeout_seconds=1) is None


async def test_unacked_message_is_reclaimed_after_visibility_timeout(
    broker: tuple[RedisStreamsBrokerTransport, RedisStreamsJobConsumer],
) -> None:
    transport, consumer = broker
    await transport.publish(_job(), "k1")
    first = await consumer.receive(timeout_seconds=1)
    assert first is not None and first.delivery_attempt == 1
    await first.retry_later()  # leave pending
    await asyncio.sleep(1.2)  # exceed the 1s visibility timeout
    second = await consumer.receive(timeout_seconds=1)
    assert second is not None
    assert second.delivery_id == first.delivery_id
    assert second.delivery_attempt >= 2


async def test_dead_letter_moves_to_dlq_and_settles(
    broker: tuple[RedisStreamsBrokerTransport, RedisStreamsJobConsumer],
) -> None:
    transport, consumer = broker
    client = transport._client
    await transport.publish(_job(), "k1")
    delivery = await consumer.receive(timeout_seconds=1)
    assert delivery is not None
    await delivery.dead_letter("poison")
    assert await client.xlen(FAST.dlq_stream) == 1
    assert await consumer.receive(timeout_seconds=1) is None


async def test_negative_acknowledge_without_requeue_dead_letters(
    broker: tuple[RedisStreamsBrokerTransport, RedisStreamsJobConsumer],
) -> None:
    transport, consumer = broker
    client = transport._client
    await transport.publish(_job(), "k1")
    delivery = await consumer.receive(timeout_seconds=1)
    assert delivery is not None
    await delivery.negative_acknowledge(requeue=False)
    assert await client.xlen(FAST.dlq_stream) == 1


async def test_publish_cancellation_writes_to_cancellation_stream(
    broker: tuple[RedisStreamsBrokerTransport, RedisStreamsJobConsumer],
) -> None:
    transport, _ = broker
    client = transport._client
    assert await transport.publish_cancellation(uuid4(), "corr-1") is True
    assert await client.xlen(FAST.cancellations_stream) == 1


async def test_pause_stops_delivery_until_resume(
    broker: tuple[RedisStreamsBrokerTransport, RedisStreamsJobConsumer],
) -> None:
    transport, consumer = broker
    await transport.publish(_job(), "k1")
    await consumer.pause()
    assert await consumer.receive(timeout_seconds=1) is None
    await consumer.resume()
    assert await consumer.receive(timeout_seconds=1) is not None


async def test_health_checks_report_ready(
    broker: tuple[RedisStreamsBrokerTransport, RedisStreamsJobConsumer],
) -> None:
    transport, consumer = broker
    assert (await transport.health_check()).ready is True
    assert (await consumer.health_check()).ready is True
