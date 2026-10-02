"""Production ASGI entrypoint: build the composed app in the serving event loop and run it.

The production app wires async-constructed adapters (an asyncpg pool bound to this loop), so
it is built inside the same loop that serves requests rather than at import time. Run with:

    python -m art_sim.api.serve
"""

from __future__ import annotations

import asyncio
import os

import uvicorn

from art_sim.api.compose import build_production_app


async def _serve() -> None:
    app = await build_production_app()
    config = uvicorn.Config(
        app,
        # Binds all interfaces by design: the process runs inside a container whose network
        # exposure is controlled by the orchestrator (Service, NetworkPolicy) and TLS edge.
        host=os.getenv("ART_HOST", "0.0.0.0"),
        port=int(os.getenv("ART_PORT", "8080")),
        lifespan="on",
        access_log=False,
        server_header=False,
        date_header=True,
    )
    await uvicorn.Server(config).serve()


def main() -> None:
    """Synchronous console entrypoint used by the container command."""
    asyncio.run(_serve())


if __name__ == "__main__":
    main()
