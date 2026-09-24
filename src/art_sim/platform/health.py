"""Framework-neutral liveness and readiness probes with no secret disclosure."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from pydantic import BaseModel, ConfigDict

from art_sim.domain.exceptions import ExternalDependencyError, GraphEngineError


class HealthStatus(BaseModel):
    """Safe health response suitable for a future HTTP adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str
    checks: dict[str, str]


class HealthService:
    """Expose process liveness and dependency readiness without an API dependency."""

    def __init__(
        self,
        checks: dict[str, Callable[[], Awaitable[None]]],
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        """Inject explicit non-sensitive dependency probes."""
        if not 0.1 <= timeout_seconds <= 60.0:
            raise ValueError("readiness timeout must be between 0.1 and 60 seconds")
        self._checks = dict(checks)
        self._timeout_seconds = timeout_seconds

    async def health(self) -> HealthStatus:
        """Return liveness without contacting external dependencies."""
        return HealthStatus(status="ok", checks={"process": "ok"})

    async def readiness(self) -> HealthStatus:
        """Return ready only when every critical dependency probe completes."""
        async def run(name: str, check: Callable[[], Awaitable[None]]) -> tuple[str, str]:
            try:
                await asyncio.wait_for(check(), timeout=self._timeout_seconds)
            except (
                ExternalDependencyError,
                GraphEngineError,
                OSError,
                RuntimeError,
                TimeoutError,
            ):
                return name, "unavailable"
            return name, "ok"

        results = dict(
            await asyncio.gather(
                *(run(name, check) for name, check in self._checks.items())
            )
        )
        return HealthStatus(status="ok" if all(value == "ok" for value in results.values()) else "not_ready", checks=results)
