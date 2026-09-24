"""Explicit bounded retry classification for external adapter operations."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

from pydantic import BaseModel, ConfigDict, Field


class TransientAdapterError(Exception):
    """A broker, database, telemetry, or network operation may safely be retried."""


class RetryPolicy(BaseModel):
    """Bounded exponential backoff with configurable full jitter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_attempts: int = Field(default=3, ge=1, le=10)
    initial_backoff_seconds: float = Field(default=0.1, ge=0.0, le=30.0)
    maximum_backoff_seconds: float = Field(default=5.0, ge=0.0, le=300.0)
    jitter_ratio: float = Field(default=0.2, ge=0.0, le=1.0)

    def delay(self, attempt: int, *, random_value: float | None = None) -> float:
        """Return a capped delay for a one-based failed attempt."""
        if attempt < 1:
            raise ValueError("Retry attempt must be positive")
        base = min(
            self.maximum_backoff_seconds,
            self.initial_backoff_seconds * (2 ** (attempt - 1)),
        )
        sample = random.random() if random_value is None else random_value
        if not 0.0 <= sample <= 1.0:
            raise ValueError("Jitter sample must be between zero and one")
        return float(base * (1.0 - self.jitter_ratio + (2.0 * self.jitter_ratio * sample)))


T = TypeVar("T")


async def retry_transient(
    operation: Callable[[], Awaitable[T]],
    policy: RetryPolicy,
) -> T:
    """Retry only explicitly transient failures and propagate every other error."""
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return await operation()
        except TransientAdapterError:
            if attempt >= policy.max_attempts:
                raise
            await asyncio.sleep(policy.delay(attempt))
    raise RuntimeError("Bounded retry loop terminated unexpectedly")
