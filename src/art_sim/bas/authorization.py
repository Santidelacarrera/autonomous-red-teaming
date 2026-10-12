"""Written-authorization gate: without a valid authorization file, nothing runs.

An offensive-security technique is only exercised when the owner of the system has authorised
it **in writing**, for a **named scope**, for a **limited time**. This module turns that rule
into code: ``run_campaign`` demands a :class:`GrantedAuthorization`, and the only way to obtain
one is :func:`verify_authorization`, which fails closed on every doubt.

What the file attests (all required):

* ``authorized_by`` / ``system_owner`` — a named person, never a placeholder;
* ``targets`` — exactly ``["local-lab"]``: the in-process synthetic lab. Any other entry
  (a hostname, URL, address, wildcard) invalidates the whole authorization;
* ``backends`` — ``sqlite`` and/or ``postgresql-loopback``;
* ``valid_from`` / ``valid_until`` — ISO-8601 with time zone, at most ``MAX_VALIDITY_DAYS`` apart,
  so authorizations are renewed instead of living forever;
* ``catalogue_sha256`` — the digest of the attack catalogue that was reviewed. Adding or changing
  an attack changes the digest, so it needs a renewed authorization;
* ``acknowledges_lab_only`` — explicit acknowledgement that no real system is in scope.

Limit, stated plainly: this is an *attestation* gate, not cryptographic identity. A person with
write access to the repository can author the file. The control is procedural plus review:
``authorizations/`` is owned in ``CODEOWNERS`` and the file's digest is written into the
forensic log of every campaign. Anchor that log outside the writer for stronger guarantees.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

LAB_TARGET = "local-lab"
ALLOWED_BACKENDS = frozenset({"sqlite", "postgresql-loopback"})
MAX_VALIDITY_DAYS = 90
DEFAULT_AUTHORIZATION = Path("authorizations/local-lab.json")
ORGANIZATION = "Nexus Security & AI Lab"
_PLACEHOLDER_MARKERS = ("<", ">", "TODO", "CHANGEME", "PENDING", "REPLACE")


class AuthorizationError(RuntimeError):
    """The campaign is not authorised. The message says why and never includes file contents."""


class AuthorizationFile(BaseModel):
    """Schema of the written authorization. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    organization: str = Field(min_length=3, max_length=120)
    authorized_by: str = Field(min_length=3, max_length=120)
    system_owner: str = Field(min_length=3, max_length=120)
    statement: str = Field(min_length=20, max_length=1000)
    targets: tuple[str, ...] = Field(min_length=1, max_length=4)
    backends: tuple[str, ...] = Field(min_length=1, max_length=2)
    valid_from: datetime
    valid_until: datetime
    catalogue_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    acknowledges_lab_only: bool


@dataclass(frozen=True)
class GrantedAuthorization:
    """Proof that :func:`verify_authorization` succeeded. Do not construct it by hand."""

    authorized_by: str
    system_owner: str
    organization: str
    valid_until: datetime
    backends: frozenset[str]
    catalogue_sha256: str
    file_sha256: str
    source: str


def _fail(reason: str) -> AuthorizationError:
    return AuthorizationError(f"not authorised: {reason}")


def verify_authorization(
    path: Path | None,
    *,
    catalogue_sha256: str,
    backend: str,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> GrantedAuthorization:
    """Return a grant or raise :class:`AuthorizationError`. Never returns a partial grant."""
    if path is None:
        if not DEFAULT_AUTHORIZATION.is_file():
            raise _fail(
                f"no authorization file (pass --authorization or create {DEFAULT_AUTHORIZATION}; "
                "start from authorizations/local-lab.template.json)"
            )
        path = DEFAULT_AUTHORIZATION
    if not path.is_file():
        raise _fail(f"authorization file {path} does not exist")
    raw = path.read_bytes()
    if len(raw) > 16_384:
        raise _fail("authorization file is implausibly large")
    try:
        document = AuthorizationFile.model_validate(json.loads(raw))
    except (ValueError, ValidationError) as error:
        raise _fail(f"authorization file is invalid ({type(error).__name__})") from error

    for label, value in (
        ("authorized_by", document.authorized_by),
        ("system_owner", document.system_owner),
        ("statement", document.statement),
    ):
        if any(marker in value for marker in _PLACEHOLDER_MARKERS):
            raise _fail(f"{label} still holds a placeholder; a named person must complete it")
    if not document.acknowledges_lab_only:
        raise _fail("acknowledges_lab_only must be true")
    if document.targets != (LAB_TARGET,):
        raise _fail(f"scope must be exactly [{LAB_TARGET!r}]; real systems are never in scope")
    if not set(document.backends) <= ALLOWED_BACKENDS:
        raise _fail(f"backends must be within {sorted(ALLOWED_BACKENDS)}")
    if backend not in document.backends:
        raise _fail(f"backend {backend!r} is not covered by this authorization")

    moment = now()
    if document.valid_from.tzinfo is None or document.valid_until.tzinfo is None:
        raise _fail("valid_from and valid_until need a time zone")
    if document.valid_until <= document.valid_from:
        raise _fail("valid_until must be after valid_from")
    if document.valid_until - document.valid_from > timedelta(days=MAX_VALIDITY_DAYS):
        raise _fail(f"validity window exceeds {MAX_VALIDITY_DAYS} days")
    if moment < document.valid_from:
        raise _fail("authorization is not valid yet")
    if moment >= document.valid_until:
        raise _fail("authorization has expired; renew it")
    if document.catalogue_sha256 != catalogue_sha256:
        raise _fail(
            "the attack catalogue changed since it was authorised; review it and set "
            f"catalogue_sha256 to {catalogue_sha256}"
        )
    return GrantedAuthorization(
        authorized_by=document.authorized_by,
        system_owner=document.system_owner,
        organization=document.organization,
        valid_until=document.valid_until,
        backends=frozenset(document.backends),
        catalogue_sha256=document.catalogue_sha256,
        file_sha256=sha256(raw).hexdigest(),
        source=str(path),
    )


def backend_label(postgres_dsn: str | None) -> str:
    """Name of the backend a campaign will use, in the vocabulary of the authorization file."""
    return "postgresql-loopback" if postgres_dsn else "sqlite"
