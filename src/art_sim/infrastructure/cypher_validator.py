"""Conservative validation for static, parameterized Cypher statements."""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum

from art_sim.domain.exceptions import CypherValidationError


class CypherIntent(StrEnum):
    """Allowed semantic class of a graph query."""

    READ = "read"
    WRITE = "write"


class CypherValidator:
    """Reject dangerous syntax before Neo4j receives a query.

    This guard is deliberately strict: dynamic labels, APOC procedures, comments,
    multiple statements, and schema-administration clauses are not accepted.
    """

    _FORBIDDEN = re.compile(
        r"\b(CALL|LOAD\s+CSV|CREATE\s+INDEX|DROP|DELETE|DETACH|FOREACH|USE|SHOW|GRANT|DENY|REVOKE)\b|//|/\*|;",
        re.IGNORECASE,
    )
    _READ_START = re.compile(r"^\s*(MATCH|OPTIONAL\s+MATCH)\b", re.IGNORECASE)
    _WRITE_START = re.compile(r"^\s*(MERGE|MATCH)\b", re.IGNORECASE)

    def validate(self, query: str, parameters: Mapping[str, object], intent: CypherIntent) -> None:
        """Validate query shape and enforce parameter-only caller supplied values."""
        normalized = query.strip()
        if not normalized:
            raise CypherValidationError("Cypher query must not be empty")
        if self._FORBIDDEN.search(normalized):
            raise CypherValidationError("Cypher query contains a prohibited clause or delimiter")
        pattern = self._READ_START if intent is CypherIntent.READ else self._WRITE_START
        if not pattern.search(normalized):
            raise CypherValidationError(f"Cypher query is not valid for {intent.value} intent")
        referenced_parameters = set(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", normalized))
        missing = referenced_parameters.difference(parameters)
        if missing:
            raise CypherValidationError(f"Cypher query is missing parameters: {sorted(missing)}")
