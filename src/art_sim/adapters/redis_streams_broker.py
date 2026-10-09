"""Redis Streams broker transport + consumer — a real, deployment-owned production adapter.

Implements the ``BrokerTransport`` publishing boundary and the ``BrokerJobConsumer`` /
``BrokerJobDelivery`` consumption contract over Redis Streams consumer groups:

- publish idempotency via a ``SET NX`` dedup key (returns False on a logical duplicate);
- at-least-once delivery with explicit ack (``XACK`` + ``XDEL``);
- visibility / redelivery of stalled messages via ``XAUTOCLAIM`` with a min-idle timeout;
- a dead-letter stream for poison jobs.

The operational store (not this broker) remains the correctness authority for one live owner,
leases, and fencing; the broker only provides durable at-least-once activation.

``redis`` is an opt-in extra (``pip install .[redis]``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError

from art_sim.worker.broker import BrokerHealth, BrokerProvider
from art_sim.worker.jobs import SimulationJobV1

_PAYLOAD_FIELD = b"payload"
_CORRELATION_FIELD = b"correlation_id"


class RedisStreamsSettings(BaseModel):
    """Non-secret Redis Streams topology and delivery settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key_prefix: str = Field(default="art-sim", pattern=r"^[A-Za-z0-9_:.-]{1,64}$")
    consumer_group: str = Field(default="workers", pattern=r"^[A-Za-z0-9_:.-]{1,64}$")
    visibility_timeout_seconds: int = Field(default=300, ge=1, le=86_400)
    dedup_ttl_seconds: int = Field(default=3600, ge=1, le=86_400)

    @property
    def jobs_stream(self) -> str:
        return f"{self.key_prefix}:jobs"

    @property
    def dlq_stream(self) -> str:
        return f"{self.key_prefix}:jobs:dlq"

    @property
    def cancellations_stream(self) -> str:
        return f"{self.key_prefix}:cancellations"


class RedisStreamsBrokerTransport:
    """Publish jobs and cancellations to Redis Streams with logical-dedup idempotency."""

    provider: ClassVar[BrokerProvider] = BrokerProvider.REDIS_STREAMS

    def __init__(self, client: Redis, settings: RedisStreamsSettings | None = None) -> None:
        self._client = client
        self._settings = settings or RedisStreamsSettings()

    @classmethod
    def from_url(cls, url: str, settings: RedisStreamsSettings | None = None) -> RedisStreamsBrokerTransport:
        return cls(Redis.from_url(url, decode_responses=False), settings)

    async def publish(self, job: SimulationJobV1, deduplication_key: str) -> bool:
        """Publish once logically; return False when the dedup key already exists."""
        dedup = f"{self._settings.key_prefix}:dedup:{deduplication_key}"
        reserved = await self._client.set(dedup, b"1", nx=True, ex=self._settings.dedup_ttl_seconds)
        if not reserved:
            return False
        await self._client.xadd(
            self._settings.jobs_stream,
            {_PAYLOAD_FIELD: job.encode(), _CORRELATION_FIELD: job.correlation_id.encode("utf-8")},
        )
        return True

    async def publish_cancellation(self, run_id: UUID, correlation_id: str) -> bool:
        """Publish a cooperative cancellation signal to the cancellation stream."""
        await self._client.xadd(
            self._settings.cancellations_stream,
            {b"run_id": str(run_id).encode("utf-8"), _CORRELATION_FIELD: correlation_id.encode("utf-8")},
        )
        return True

    async def health_check(self) -> BrokerHealth:
        """Verify connectivity without publishing a job or disclosing configuration."""
        try:
            await self._client.ping()
            return BrokerHealth(provider=self.provider, ready=True)
        except RedisError:
            return BrokerHealth(provider=self.provider, ready=False)

    async def purge_dead_letter(self, *, older_than: datetime, dry_run: bool) -> int:
        """Delete dead-lettered jobs older than ``older_than`` (``RetentionPurgeBroker``).

        Redis Streams entry IDs are ``<milliseconds>-<sequence>``, so an exclusive upper
        bound of ``cutoff_ms - 1`` (an ID with no explicit sequence) selects every entry
        strictly before the cutoff regardless of its sequence component.
        """
        cutoff_ms = int(older_than.timestamp() * 1000)
        if cutoff_ms <= 0:
            return 0
        entries = await self._client.xrange(
            self._settings.dlq_stream, min="-", max=str(cutoff_ms - 1), count=10_000
        )
        if not entries:
            return 0
        if dry_run:
            return len(entries)
        entry_ids = [entry_id for entry_id, _fields in entries]
        await self._client.xdel(self._settings.dlq_stream, *entry_ids)
        return len(entry_ids)

    async def close(self) -> None:
        await self._client.aclose()


class RedisStreamsJobDelivery:
    """One delivered job with explicit settlement over Redis Streams."""

    def __init__(
        self,
        client: Redis,
        settings: RedisStreamsSettings,
        *,
        delivery_id: str,
        payload: bytes,
        correlation_id: str,
        delivery_attempt: int,
    ) -> None:
        self._client = client
        self._settings = settings
        self.delivery_id = delivery_id
        self.payload = payload
        self.correlation_id = correlation_id
        self.delivery_attempt = delivery_attempt

    async def acknowledge(self) -> None:
        """Settle the message so it is never redelivered."""
        await self._client.xack(self._settings.jobs_stream, self._settings.consumer_group, self.delivery_id)
        await self._client.xdel(self._settings.jobs_stream, self.delivery_id)

    async def retry_later(self) -> None:
        """Leave the message pending so the visibility timeout triggers redelivery."""
        # No settlement: XAUTOCLAIM will reclaim it after the min-idle window elapses.

    async def negative_acknowledge(self, *, requeue: bool) -> None:
        """Requeue for redelivery, or dead-letter when the message must not be retried."""
        if requeue:
            return
        await self.dead_letter("negative_acknowledge")

    async def extend_visibility(self, timeout_seconds: int) -> None:
        """Reset the idle timer by reclaiming the message to this owner."""
        del timeout_seconds
        try:
            await self._client.xclaim(
                self._settings.jobs_stream,
                self._settings.consumer_group,
                "extend",
                min_idle_time=0,
                message_ids=[self.delivery_id],
            )
        except RedisError:
            return

    async def dead_letter(self, reason_code: str) -> None:
        """Move the poison job to the dead-letter stream and settle the original."""
        await self._client.xadd(
            self._settings.dlq_stream,
            {
                _PAYLOAD_FIELD: self.payload,
                b"reason": reason_code.encode("utf-8"),
                _CORRELATION_FIELD: self.correlation_id.encode("utf-8"),
            },
        )
        await self._client.xack(self._settings.jobs_stream, self._settings.consumer_group, self.delivery_id)
        await self._client.xdel(self._settings.jobs_stream, self.delivery_id)


class RedisStreamsJobConsumer:
    """Consume jobs from a Redis Streams consumer group with visibility redelivery."""

    def __init__(
        self,
        client: Redis,
        consumer_name: str,
        settings: RedisStreamsSettings | None = None,
    ) -> None:
        self._client = client
        self._consumer = consumer_name
        self._settings = settings or RedisStreamsSettings()
        self._paused = False
        self._group_ready = False

    async def _ensure_group(self) -> None:
        if self._group_ready:
            return
        try:
            await self._client.xgroup_create(
                self._settings.jobs_stream, self._settings.consumer_group, id="0", mkstream=True
            )
        except ResponseError as error:
            if "BUSYGROUP" not in str(error):
                raise
        self._group_ready = True

    async def receive(self, *, timeout_seconds: float = 5.0) -> RedisStreamsJobDelivery | None:
        """Reclaim a stalled message or read a new one; return None when idle or paused."""
        if self._paused:
            return None
        await self._ensure_group()
        reclaimed = await self._reclaim_stalled()
        if reclaimed is not None:
            return reclaimed
        # redis types stream reads with broad unions; bind to Any and read positionally.
        response: Any = await self._client.xreadgroup(
            self._settings.consumer_group,
            self._consumer,
            {self._settings.jobs_stream: ">"},
            count=1,
            block=max(1, int(timeout_seconds * 1000)),
        )
        if not response:
            return None
        entries = response[0][1]
        if not entries:
            return None
        message_id, fields = entries[0]
        return await self._build_delivery(message_id, fields)

    async def _reclaim_stalled(self) -> RedisStreamsJobDelivery | None:
        min_idle = self._settings.visibility_timeout_seconds * 1000
        claimed: Any = await self._client.xautoclaim(
            self._settings.jobs_stream,
            self._settings.consumer_group,
            self._consumer,
            min_idle_time=min_idle,
            start_id="0",
            count=1,
        )
        entries = claimed[1] if len(claimed) >= 2 else []
        if not entries:
            return None
        message_id, fields = entries[0]
        return await self._build_delivery(message_id, fields)

    async def _build_delivery(self, message_id: Any, fields: dict[Any, Any]) -> RedisStreamsJobDelivery:
        delivery_id = message_id.decode("utf-8") if isinstance(message_id, bytes) else str(message_id)
        payload = fields.get(_PAYLOAD_FIELD) or fields.get("payload") or b""
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        correlation_raw = fields.get(_CORRELATION_FIELD) or fields.get("correlation_id") or b""
        correlation = correlation_raw.decode("utf-8") if isinstance(correlation_raw, bytes) else str(correlation_raw)
        attempt = await self._delivery_attempt(delivery_id)
        return RedisStreamsJobDelivery(
            self._client,
            self._settings,
            delivery_id=delivery_id,
            payload=payload,
            correlation_id=correlation,
            delivery_attempt=attempt,
        )

    async def _delivery_attempt(self, delivery_id: str) -> int:
        pending: Any = await self._client.xpending_range(
            self._settings.jobs_stream,
            self._settings.consumer_group,
            min=delivery_id,
            max=delivery_id,
            count=1,
        )
        if pending:
            return int(pending[0]["times_delivered"])
        return 1

    async def pause(self) -> None:
        self._paused = True

    async def resume(self) -> None:
        self._paused = False

    async def health_check(self) -> BrokerHealth:
        try:
            await self._client.ping()
            return BrokerHealth(provider=BrokerProvider.REDIS_STREAMS, ready=True)
        except RedisError:
            return BrokerHealth(provider=BrokerProvider.REDIS_STREAMS, ready=False)

    async def close(self) -> None:
        await self._client.aclose()
