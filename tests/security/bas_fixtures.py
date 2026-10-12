"""Fixtures for the breach-and-attack-simulation tests.

The authorization files written here live in ``tmp_path`` and are *test fixtures*, not the
real gate: the real file is ``authorizations/local-lab.json``, signed off by the system owner.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from art_sim.bas.runner import catalogue_digest


def authorization_document(**overrides: Any) -> dict[str, Any]:
    """A valid authorization document; ``overrides`` replace or (with ``None``) remove fields."""
    now = datetime.now(UTC)
    document: dict[str, Any] = {
        "organization": "Nexus Security & AI Lab",
        "authorized_by": "Test Owner",
        "system_owner": "Test Owner",
        "statement": "Test fixture: breach-and-attack simulation against the synthetic lab only.",
        "targets": ["local-lab"],
        "backends": ["sqlite", "postgresql-loopback"],
        "valid_from": (now - timedelta(hours=1)).isoformat(),
        "valid_until": (now + timedelta(days=30)).isoformat(),
        "catalogue_sha256": catalogue_digest(),
        "acknowledges_lab_only": True,
    }
    document.update(overrides)
    return {key: value for key, value in document.items() if value is not None}


def write_authorization(path: Path, **overrides: Any) -> Path:
    path.write_text(json.dumps(authorization_document(**overrides)), encoding="utf-8")
    return path
