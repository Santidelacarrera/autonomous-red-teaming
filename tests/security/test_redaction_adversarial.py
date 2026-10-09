"""Adversarial coverage for credential redaction on audit/telemetry boundaries."""

from __future__ import annotations

import pytest

from art_sim.security.redaction import REDACTED, redact_security_text

SECRET_SHAPED = [
    "Authorization: Bearer abc.def.ghi",
    "bearer sometoken",
    "password=hunter2",
    "passwd: s3cr3t",
    "my access_token is live",
    "refresh-token rotated",
    "cookie: session=xyz",
    "credential leaked here",
    "the secret value",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl",
]


@pytest.mark.parametrize("value", SECRET_SHAPED)
def test_secret_shaped_text_is_fully_redacted(value: str) -> None:
    assert redact_security_text(value) == REDACTED


def test_none_passes_through() -> None:
    assert redact_security_text(None) is None


def test_benign_text_is_unchanged() -> None:
    value = "simulation run 7 reached the crown jewel in 3 hops"
    assert redact_security_text(value) == value


def test_redaction_is_case_insensitive() -> None:
    assert redact_security_text("AUTHORIZATION header present") == REDACTED
    assert redact_security_text("Bearer TOKEN") == REDACTED


def test_redaction_never_returns_partial_secret() -> None:
    # A redacted result must not leak any portion of the original credential.
    original = "password=SuperSecret123!"
    result = redact_security_text(original)
    assert result == REDACTED
    assert "SuperSecret123" not in (result or "")
