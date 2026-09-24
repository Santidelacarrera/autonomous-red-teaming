"""Rate-limiting port with a bounded single-node development adapter."""

from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass
from time import monotonic
from typing import Protocol


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

    async def consume(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision: ...


class InMemoryRateLimiter:
    """Concurrency-safe rolling-window limiter for development and one process only."""

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

    async def consume(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision:
        """Allow without retaining identity or request data."""
        del key, policy
        return RateLimitDecision(True)
