"""Typed vocabulary shared by attack cases, the runner and AegisTrace."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from art_sim.bas.lab import Lab


class Category(StrEnum):
    """Attack families, one per trust boundary under test."""

    TENANT_ISOLATION = "tenant_isolation"
    INJECTION = "injection"
    PROMPT_INJECTION = "prompt_injection"
    DATASTORE = "datastore"


class Verdict(StrEnum):
    """Outcome of one attack attempt, from the defender's point of view."""

    BLOCKED = "blocked"  # the control held (and, where required, was logged)
    BREACHED = "breached"  # the attacker obtained something the control must deny
    GAP = "gap"  # held, but a defence-in-depth property is missing (e.g. no RLS, not logged)
    ERROR = "error"  # the harness could not reach a conclusion; never counts as a pass


@dataclass(frozen=True)
class Observation:
    """What an attack case saw. ``detail`` must be short and free of secrets."""

    verdict: Verdict
    detail: str
    status_code: int | None = None
    evidence: str = ""  # raw material hashed (never stored) into the incident record


@dataclass(frozen=True)
class AttackCase:
    """One reproducible attack. ``technique`` uses MITRE ATT&CK / ATLAS identifiers."""

    case_id: str
    category: Category
    technique: str
    title: str
    run: Callable[[Lab], Awaitable[Observation]]
    expect_detection: bool = False  # the platform must also emit a denial/failure audit event
    payload: str = ""  # attacker-supplied input, recorded as digest + bounded preview only
    attacker_tenant: str | None = None
    victim_tenant: str | None = None
