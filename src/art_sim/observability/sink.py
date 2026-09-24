"""Safe telemetry-sink abstraction for future external observability adapters."""

from __future__ import annotations

import json
import logging
from typing import Protocol

from art_sim.observability.telemetry import AgentTelemetry


class TelemetrySink(Protocol):
    """Accept a typed telemetry event without requiring a specific backend."""

    def emit(self, event: AgentTelemetry) -> None:
        """Write one safe, correlated telemetry event."""


class StructuredLoggingTelemetrySink:
    """Emit JSON logs from typed fields only; no raw state or secret material is accepted."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        """Use an injected application logger or this module's logger."""
        self._logger = logger or logging.getLogger(__name__)

    def emit(self, event: AgentTelemetry) -> None:
        """Write a one-line structured event correlated by run and trace IDs."""
        self._logger.info(
            json.dumps(
                {
                    "event": "agent.execution",
                    "run_id": str(event.run_id),
                    "trace_id": str(event.trace_id),
                    "component": event.agent_name,
                    "node": event.node_name,
                    "status": event.status,
                    "duration_ms": event.duration_ms,
                }, separators=(",", ":")
            )
        )
