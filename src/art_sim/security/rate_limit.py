"""Rate-limiting port with a bounded single-node development adapter."""

from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import StrEnum
from time import monotonic
from typing import ClassVar, Protocol


class RateLimiterScope(StrEnum):
    """Deployment capability declared by a rate-limiter adapter."""

    DISABLED = "disabled"
    PROCESS = "process"
    DISTRIBUTED = "distributed"


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """Maximum requests allowed in a fixed rolling window."""

    name: str
    requests: int
    window_seconds: int = 60

    def __post_init__(self) -> None:
        if self.requests < 1 or self.window_seconds < 1:
            raise ValueError("Rate limit values must be positive")


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Outcome without exposing the internal bucket key."""

    allowed: bool
    retry_after_seconds: int = 0


class RateLimiter(Protocol):
    """Provider-neutral asynchronous limiter suitable for Redis or edge adapters."""

    deployment_scope: ClassVar[RateLimiterScope]

    async def consume(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision: ...


class DistributedRateLimiter(RateLimiter, Protocol):
    """Port for an atomic limiter shared by every production API replica.

    Implementations must declare ``deployment_scope = RateLimiterScope.DISTRIBUTED``.
    This project intentionally provides no fake Redis or edge adapter.
    """

    async def health_check(self) -> None:
        """Verify the shared atomic backend without consuming caller capacity."""

    async def close(self) -> None:
        """Release shared-backend connections during graceful shutdown."""


class InMemoryRateLimiter:
    """Concurrency-safe rolling-window limiter for development and one process only."""

    deployment_scope: ClassVar[RateLimiterScope] = RateLimiterScope.PROCESS

    def __init__(self) -> None:
        self._buckets: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def consume(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision:
        """Consume capacity atomically and return a bounded retry delay."""
        now = monotonic()
        cutoff = now - policy.window_seconds
        async with self._lock:
            bucket = self._buckets[(policy.name, key)]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= policy.requests:
                retry_after = max(1, int(policy.window_seconds - (now - bucket[0])) + 1)
                return RateLimitDecision(False, retry_after)
            bucket.append(now)
            return RateLimitDecision(True)


class UnlimitedRateLimiter:
    """Explicitly disabled limiter for injected test compositions."""

    deployment_scope: ClassVar[RateLimiterScope] = RateLimiterScope.DISABLED

    async def consume(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision:
        """Allow without retaining identity or request data."""
        del key, policy
        return RateLimitDecision(True)
