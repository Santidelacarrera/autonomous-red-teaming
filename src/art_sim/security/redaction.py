"""Central redaction rules for security telemetry and audit boundaries."""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"
_SENSITIVE_LABEL = re.compile(
    r"(?:authorization|cookie|password|passwd|secret|access[_ -]?token|refresh[_ -]?token|credential)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"\bbearer\s+\S+", re.IGNORECASE)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def redact_security_text(value: str | None) -> str | None:
    """Replace credential-like audit text instead of attempting partial masking."""
    if value is None:
        return None
    if _SENSITIVE_LABEL.search(value) or _BEARER.search(value) or _JWT.search(value):
        return REDACTED
    return value
