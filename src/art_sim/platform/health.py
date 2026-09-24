"""Framework-neutral liveness and readiness probes with no secret disclosure."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from pydantic import BaseModel, ConfigDict

from art_sim.domain.exceptions import GraphEngineError


class HealthStatus(BaseModel):
    """Safe health response suitable for a future HTTP adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str
    checks: dict[str, str]


class HealthService:
    """Expose process liveness and dependency readiness without an API dependency."""

    def __init__(self, checks: dict[str, Callable[[], Awaitable[None]]]) -> None:
        """Inject explicit non-sensitive dependency probes."""
        self._checks = dict(checks)

    async def health(self) -> HealthStatus:
        """Return liveness without contacting external dependencies."""
        return HealthStatus(status="ok", checks={"process": "ok"})

    async def readiness(self) -> HealthStatus:
        """Return ready only when every critical dependency probe completes."""
        results: dict[str, str] = {}
        for name, check in self._checks.items():
            try:
                await check()
            except (GraphEngineError, OSError, RuntimeError):
                results[name] = "unavailable"
            else:
                results[name] = "ok"
        return HealthStatus(status="ok" if all(value == "ok" for value in results.values()) else "not_ready", checks=results)
