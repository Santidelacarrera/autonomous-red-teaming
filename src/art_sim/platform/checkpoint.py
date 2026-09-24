"""Native LangGraph SQLite saver factory kept outside domain and workflow policy."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

from art_sim.domain.exceptions import ConfigurationError


@asynccontextmanager
async def sqlite_langgraph_checkpointer(database_path: Path) -> AsyncIterator[AsyncSqliteSaver]:
    """Yield an official durable LangGraph SQLite saver for one worker lifetime.

    The caller must keep this context open for every start/resume operation. SQLite is
    appropriate for single-node operation; select a server-backed LangGraph saver for
    multi-node or multi-region workloads.
    """
    if database_path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
        raise ConfigurationError("LangGraph checkpoint database must be a SQLite file")
    database_path.parent.mkdir(parents=True, exist_ok=True)
    async with AsyncSqliteSaver.from_conn_string(str(database_path)) as saver:
        yield saver
