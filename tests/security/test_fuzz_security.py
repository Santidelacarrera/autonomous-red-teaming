"""Dependency-free randomized fuzzing of the security primitives.

Hypothesis is unavailable in this environment (its native extension is blocked by Windows
Application Control), so we fuzz with the standard library: thousands of pseudo-random and
adversarial inputs asserting the controls' invariants. A fixed seed keeps failures
reproducible.
"""

from __future__ import annotations

import random
import string

import pytest

from art_sim.domain.exceptions import CypherValidationError
from art_sim.infrastructure.cypher_validator import CypherIntent, CypherValidator
from art_sim.security.redaction import REDACTED, redact_security_text
from art_sim.security.sanitizer import PromptInjectionSanitizer

SEED = 1337
ITERATIONS = 3000

VALIDATOR = CypherValidator()
SANITIZER = PromptInjectionSanitizer()

_CYPHER_FORBIDDEN_WORDS = (
    "CALL",
    "DROP",
    "DELETE",
    "DETACH",
    "REMOVE",
    "CREATE",
    "FOREACH",
    "USE",
    "SHOW",
    "GRANT",
    "DENY",
    "REVOKE",
    "TERMINATE",
)
_CYPHER_TOKENS = (
    *_CYPHER_FORBIDDEN_WORDS,
    "MATCH",
    "OPTIONAL MATCH",
    "UNWIND",
    "MERGE",
    "SET",
    "RETURN",
    "WHERE",
    "WITH",
    ";",
    "//",
    "/*",
    "$param",
    "LOAD CSV",
    "(a)",
    "1",
    " ",
)


def _random_cypher(rng: random.Random) -> str:
    return " ".join(rng.choice(_CYPHER_TOKENS) for _ in range(rng.randint(0, 8)))


def test_fuzz_cypher_validator_only_raises_domain_error_and_blocks_forbidden() -> None:
    rng = random.Random(SEED)
    for _ in range(ITERATIONS):
        query = _random_cypher(rng)
        intent = rng.choice((CypherIntent.READ, CypherIntent.WRITE))
        try:
            VALIDATOR.validate(query, {"param": "x"}, intent)
            accepted = True
        except CypherValidationError:
            accepted = False
        # Invariant: nothing containing a globally forbidden token or delimiter is accepted.
        upper = query.upper()
        has_forbidden = any(
            f" {w} " in f" {upper} " or upper.startswith(f"{w} ") or upper == w
            for w in _CYPHER_FORBIDDEN_WORDS
        ) or any(marker in query for marker in (";", "//", "/*"))
        if accepted:
            assert not has_forbidden, f"accepted a forbidden query: {query!r}"
            # A read must never be accepted while containing write clauses.
            if intent is CypherIntent.READ:
                assert " SET " not in f" {upper} " and " MERGE " not in f" {upper} "


def test_fuzz_cypher_validator_never_raises_unexpected_type() -> None:
    rng = random.Random(SEED + 1)
    for _ in range(ITERATIONS):
        query = "".join(rng.choice(string.printable) for _ in range(rng.randint(0, 40)))
        for intent in (CypherIntent.READ, CypherIntent.WRITE):
            try:
                VALIDATOR.validate(query, {}, intent)
            except CypherValidationError:
                pass  # the only permitted failure mode


_CONTROL_CHARS = [chr(c) for c in range(0x20)] + ["\x7f"]


def test_fuzz_sanitizer_invariants() -> None:
    rng = random.Random(SEED + 2)
    alphabet = string.printable + "".join(_CONTROL_CHARS) + "ñçüΩ你好"
    for _ in range(ITERATIONS):
        raw = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 120)))
        max_length = rng.randint(1, 256)
        cleaned = SANITIZER.sanitize_text(raw, max_length=max_length)
        # Invariant 1: bounded length.
        assert len(cleaned) <= max_length
        # Invariant 2: no control characters survive.
        assert not any(ch in cleaned for ch in _CONTROL_CHARS)
        # Invariant 3: idempotent (sanitizing again changes nothing).
        assert SANITIZER.sanitize_text(cleaned, max_length=max_length) == cleaned


_SECRET_MARKERS = ["password", "secret", "authorization", "cookie", "credential", "access_token"]


def test_fuzz_redaction_never_leaks_marked_secrets() -> None:
    rng = random.Random(SEED + 3)
    for _ in range(ITERATIONS):
        payload = "".join(rng.choice(string.ascii_letters + " =:") for _ in range(rng.randint(0, 30)))
        marker = rng.choice(_SECRET_MARKERS)
        tainted = f"{payload} {marker}={rng.randint(0, 10**9)}"
        assert redact_security_text(tainted) == REDACTED
        # A benign string without any marker is returned unchanged.
        if not any(m in payload.lower() for m in _SECRET_MARKERS) and "bearer" not in payload.lower():
            assert redact_security_text(payload) == payload


@pytest.mark.parametrize("marker", _SECRET_MARKERS)
def test_redaction_is_total_not_partial(marker: str) -> None:
    secret = f"{marker}: TOPSECRETVALUE-0xDEADBEEF"
    assert redact_security_text(secret) == REDACTED
    assert "TOPSECRETVALUE" not in (redact_security_text(secret) or "")
