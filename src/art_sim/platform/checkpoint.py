"""Native LangGraph SQLite saver factory kept outside domain and workflow policy."""

from __future__ import annotations

import importlib
import inspect
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from enum import Enum
from pathlib import Path

import aiosqlite
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from pydantic import BaseModel

from art_sim.domain.exceptions import ConfigurationError

# Modules whose classes may legitimately appear inside a persisted workflow state. Everything
# else is refused at load time (see ``checkpoint_serde``).
CHECKPOINT_STATE_MODULES: tuple[str, ...] = (
    "art_sim.agents.models",
    "art_sim.attack.simulated_graph",
    "art_sim.domain.models",
    "art_sim.remediation.models",
    "art_sim.remediation.state_machine",
    "art_sim.security.sanitizer",
)


def allowed_checkpoint_types() -> tuple[tuple[str, str], ...]:
    """The exact ``(module, class)`` pairs a checkpoint may reconstruct.

    Derived from the project's own state modules: only pydantic models, enums and the
    lifecycle value object *defined in those modules* qualify, never imported third-party
    classes. Deriving the list (instead of hand-maintaining it) means a new state field
    type added to one of these modules keeps working, while a type from anywhere else —
    the shape of a deserialization attack — stays blocked.
    """
    allowed: list[tuple[str, str]] = []
    for module_name in CHECKPOINT_STATE_MODULES:
        module = importlib.import_module(module_name)
        for name, member in inspect.getmembers(module, inspect.isclass):
            if member.__module__ != module_name:
                continue
            if issubclass(member, BaseModel | Enum) or name == "RemediationLifecycle":
                allowed.append((module_name, name))
    return tuple(sorted(allowed))


def checkpoint_serde() -> JsonPlusSerializer:
    """Serializer that deserializes only the allow-listed workflow-state types.

    LangGraph's default is permissive (any importable type is rebuilt, with a warning) and its
    own documentation warns that anyone able to write to the checkpoint database could then
    trigger code execution. Pinning the allow-list removes that, and keeps resumption working
    when a future LangGraph release makes strict mode the default.
    """
    return JsonPlusSerializer(allowed_msgpack_modules=list(allowed_checkpoint_types()))


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
    async with aiosqlite.connect(str(database_path)) as connection:
        saver = AsyncSqliteSaver(connection, serde=checkpoint_serde())
        await saver.setup()
        yield saver
