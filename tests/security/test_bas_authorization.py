"""The written-authorization gate: without a valid file, nothing runs.

Every rejection path is tested, each with the same assertion that matters: no output directory,
no store and no forensic log is created. The campaign is never reachable by "almost" valid input.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from bas_fixtures import authorization_document, write_authorization

from art_sim.bas.__main__ import EXIT_NOT_AUTHORISED, main
from art_sim.bas.authorization import (
    MAX_VALIDITY_DAYS,
    AuthorizationError,
    GrantedAuthorization,
    verify_authorization,
)
from art_sim.bas.runner import catalogue_digest, run_campaign

pytest_plugins = ["bas_plugin"]  # provides the `bas_grant` fixture

DIGEST = catalogue_digest()
REPO = Path(__file__).resolve().parents[2]


def verify(
    path: Path | None, *, backend: str = "sqlite", now: datetime | None = None
) -> GrantedAuthorization:
    return verify_authorization(
        path,
        catalogue_sha256=DIGEST,
        backend=backend,
        now=(lambda: now) if now else (lambda: datetime.now(UTC)),
    )


# ----------------------------------------------------------------------------- the happy path


def test_a_complete_authorization_is_granted(tmp_path: Path) -> None:
    path = write_authorization(tmp_path / "a.json")
    grant = verify(path)
    assert grant.authorized_by == "Test Owner" and grant.organization == "Nexus Security & AI Lab"
    assert grant.catalogue_sha256 == DIGEST and len(grant.file_sha256) == 64
    assert grant.backends == {"sqlite", "postgresql-loopback"}


def test_the_grant_binds_the_exact_bytes_of_the_file(tmp_path: Path) -> None:
    first = verify(write_authorization(tmp_path / "a.json"))
    second = verify(write_authorization(tmp_path / "b.json", authorized_by="Someone Else"))
    assert first.file_sha256 != second.file_sha256


# ------------------------------------------------------------------ no file, no run (fail closed)


def test_no_file_means_no_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)  # no authorizations/local-lab.json here
    with pytest.raises(AuthorizationError, match="no authorization file"):
        verify(None)
    with pytest.raises(AuthorizationError, match="does not exist"):
        verify(tmp_path / "missing.json")


def test_a_directory_is_not_an_authorization(tmp_path: Path) -> None:
    with pytest.raises(AuthorizationError):
        verify(tmp_path)


def test_the_shipped_template_is_never_accepted() -> None:
    """The template documents the format; it must not work by itself."""
    with pytest.raises(AuthorizationError):
        verify(REPO / "authorizations" / "local-lab.template.json")


@pytest.mark.parametrize(
    "content",
    [b"", b"not json", b"[]", b'{"organization": 1}', b"\xff\xfe", b"x" * 20_000],
)
def test_garbage_is_rejected(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(content)
    with pytest.raises(AuthorizationError):
        verify(path)


def test_unknown_fields_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(AuthorizationError):
        verify(write_authorization(tmp_path / "a.json", also_allow_production=True))


@pytest.mark.parametrize(
    "missing",
    [
        "authorized_by",
        "system_owner",
        "statement",
        "valid_until",
        "catalogue_sha256",
        "acknowledges_lab_only",
        "targets",
    ],
)
def test_every_required_field_is_required(tmp_path: Path, missing: str) -> None:
    with pytest.raises(AuthorizationError):
        verify(write_authorization(tmp_path / "a.json", **{missing: None}))


@pytest.mark.parametrize("field", ["authorized_by", "system_owner", "statement"])
@pytest.mark.parametrize(
    "placeholder",
    ["<your name>", "TODO fill in the name", "PENDING approval here", "CHANGEME please"],
)
def test_placeholders_are_rejected(tmp_path: Path, field: str, placeholder: str) -> None:
    value = placeholder if field != "statement" else placeholder + " " * 5 + "x" * 20
    with pytest.raises(AuthorizationError, match="placeholder"):
        verify(write_authorization(tmp_path / "a.json", **{field: value}))


def test_the_lab_only_acknowledgement_must_be_true(tmp_path: Path) -> None:
    with pytest.raises(AuthorizationError, match="acknowledges_lab_only"):
        verify(write_authorization(tmp_path / "a.json", acknowledges_lab_only=False))


# ------------------------------------------------------------- scope: the local lab and nothing else


@pytest.mark.parametrize(
    "targets",
    [
        ["local-lab", "https://prod.example.com"],
        ["prod.example.com"],
        ["127.0.0.1"],
        ["*"],
        ["local-lab", "local-lab"],
        ["LOCAL-LAB"],
        ["staging"],
    ],
)
def test_any_target_other_than_the_local_lab_invalidates_the_authorization(
    tmp_path: Path, targets: list[str]
) -> None:
    with pytest.raises(AuthorizationError, match="scope"):
        verify(write_authorization(tmp_path / "a.json", targets=targets))


def test_empty_scope_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(AuthorizationError):
        verify(write_authorization(tmp_path / "a.json", targets=[]))


def test_a_remote_database_backend_cannot_be_authorised(tmp_path: Path) -> None:
    with pytest.raises(AuthorizationError, match="backends"):
        verify(write_authorization(tmp_path / "a.json", backends=["sqlite", "postgresql"]))


def test_the_backend_in_use_must_be_covered(tmp_path: Path) -> None:
    path = write_authorization(tmp_path / "a.json", backends=["sqlite"])
    verify(path, backend="sqlite")
    with pytest.raises(AuthorizationError, match="not covered"):
        verify(path, backend="postgresql-loopback")


# ----------------------------------------------------------------------------- limited in time


def test_validity_window_is_enforced(tmp_path: Path) -> None:
    start = datetime(2026, 10, 1, tzinfo=UTC)
    path = write_authorization(
        tmp_path / "a.json",
        valid_from=start.isoformat(),
        valid_until=(start + timedelta(days=10)).isoformat(),
    )
    verify(path, now=start + timedelta(days=5))
    with pytest.raises(AuthorizationError, match="not valid yet"):
        verify(path, now=start - timedelta(seconds=1))
    with pytest.raises(AuthorizationError, match="expired"):
        verify(path, now=start + timedelta(days=10))  # the end instant is already outside
    with pytest.raises(AuthorizationError, match="expired"):
        verify(path, now=start + timedelta(days=400))


def test_authorizations_cannot_be_open_ended(tmp_path: Path) -> None:
    start = datetime(2026, 10, 1, tzinfo=UTC)
    long = write_authorization(
        tmp_path / "long.json",
        valid_from=start.isoformat(),
        valid_until=(start + timedelta(days=MAX_VALIDITY_DAYS + 1)).isoformat(),
    )
    with pytest.raises(AuthorizationError, match="exceeds"):
        verify(long, now=start + timedelta(days=1))
    edge = write_authorization(
        tmp_path / "edge.json",
        valid_from=start.isoformat(),
        valid_until=(start + timedelta(days=MAX_VALIDITY_DAYS)).isoformat(),
    )
    verify(edge, now=start + timedelta(days=1))


def test_reversed_or_naive_dates_are_rejected(tmp_path: Path) -> None:
    start = datetime(2026, 10, 1, tzinfo=UTC)
    reversed_ = write_authorization(
        tmp_path / "r.json",
        valid_from=start.isoformat(),
        valid_until=(start - timedelta(days=1)).isoformat(),
    )
    with pytest.raises(AuthorizationError):
        verify(reversed_, now=start)
    naive = write_authorization(
        tmp_path / "n.json", valid_from="2026-10-01T00:00:00", valid_until="2026-10-20T00:00:00"
    )
    with pytest.raises(AuthorizationError, match="time zone"):
        verify(naive, now=start + timedelta(days=1))


# ----------------------------------------------------------------- bound to the reviewed catalogue


def test_a_changed_catalogue_needs_a_new_authorization(tmp_path: Path) -> None:
    stale = write_authorization(tmp_path / "a.json", catalogue_sha256="0" * 64)
    with pytest.raises(AuthorizationError, match="catalogue changed") as caught:
        verify(stale)
    assert DIGEST in str(caught.value)  # the owner is told exactly what to review and set


def test_error_messages_never_echo_file_contents(tmp_path: Path) -> None:
    secret = "do-not-print-me-0123456789"
    path = write_authorization(tmp_path / "a.json", statement=f"TODO {secret} " + "x" * 30)
    with pytest.raises(AuthorizationError) as caught:
        verify(path)
    assert secret not in str(caught.value)


# --------------------------------------------- the campaign itself cannot be reached without a grant


async def test_run_campaign_rejects_anything_but_a_verified_grant(tmp_path: Path) -> None:
    class Forged:
        authorized_by = "me"
        backends = frozenset({"sqlite"})
        catalogue_sha256 = DIGEST
        file_sha256 = "0" * 64

    with pytest.raises(TypeError):
        await run_campaign(tmp_path / "out", authorization=Forged())  # type: ignore[arg-type]
    assert not (tmp_path / "out").exists()


async def test_run_campaign_rechecks_the_catalogue_and_the_backend(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    import dataclasses

    stale = dataclasses.replace(bas_grant, catalogue_sha256="1" * 64)
    with pytest.raises(PermissionError, match="catalogue"):
        await run_campaign(tmp_path / "a", authorization=stale)
    sqlite_only = dataclasses.replace(bas_grant, backends=frozenset({"sqlite"}))
    with pytest.raises(PermissionError, match="backend"):
        await run_campaign(
            tmp_path / "b", authorization=sqlite_only, postgres_dsn="postgresql://u@127.0.0.1/db"
        )
    assert not (tmp_path / "a").exists() and not (tmp_path / "b").exists()


async def test_a_remote_database_is_refused_before_anything_is_created(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    from art_sim.bas.lab import UnsafeTargetError

    with pytest.raises(UnsafeTargetError):
        await run_campaign(
            tmp_path / "out",
            authorization=bas_grant,
            postgres_dsn="postgresql://u@db.example.com/x",
        )
    assert not (tmp_path / "out").exists()


# ----------------------------------------------------------------------------------- the command


def test_cli_without_authorization_exits_3_and_creates_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ART_BAS_AUTHORIZATION", raising=False)
    assert main(["--out", str(tmp_path / "out")]) == EXIT_NOT_AUTHORISED
    assert not (tmp_path / "out").exists()
    assert "refused: not authorised" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"targets": ["https://prod.example.com"]},
        {"valid_until": "2000-01-01T00:00:00+00:00", "valid_from": "1999-12-01T00:00:00+00:00"},
        {"catalogue_sha256": "2" * 64},
        {"acknowledges_lab_only": False},
        {"authorized_by": "<name>"},
    ],
)
def test_cli_with_an_invalid_authorization_exits_3_and_creates_nothing(
    tmp_path: Path, overrides: dict[str, Any]
) -> None:
    auth = write_authorization(tmp_path / "auth.json", **overrides)
    out = tmp_path / "out"
    assert main(["--out", str(out), "--authorization", str(auth)]) == EXIT_NOT_AUTHORISED
    assert not out.exists()


def test_cli_with_a_valid_authorization_runs_and_reports_who_authorised(tmp_path: Path) -> None:
    auth = write_authorization(tmp_path / "auth.json")
    out = tmp_path / "out"
    assert main(["--out", str(out), "--authorization", str(auth), "--only", "TEN-NO-CREDS"]) == 0
    report = json.loads((out / "report.json").read_text())
    assert report["authorized_by"] == "Test Owner" and len(report["authorization_sha256"]) == 64
    first = json.loads((out / "aegistrace.jsonl").read_text().splitlines()[0])
    assert first["event"]["phase"] == "campaign.authorized"
    assert first["event"]["authorization_sha256"] == report["authorization_sha256"]


def test_listing_and_digest_are_read_only_and_need_no_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["--print-catalogue-digest"]) == 0
    assert capsys.readouterr().out.strip() == DIGEST
    assert main(["--list-scenarios"]) == 0
    assert "SCN-01" in capsys.readouterr().out
    assert list(tmp_path.iterdir()) == []


def test_the_environment_variable_can_supply_the_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth = write_authorization(tmp_path / "env-auth.json")
    monkeypatch.setenv("ART_BAS_AUTHORIZATION", str(auth))
    assert main(["--out", str(tmp_path / "out"), "--only", "TEN-NO-CREDS"]) == 0


def test_the_authorizations_directory_is_owned_by_the_maintainer() -> None:
    owners = (REPO / ".github" / "CODEOWNERS").read_text()
    assert "/authorizations/" in owners and "authorization.py" in owners


def test_no_real_authorization_is_committed_with_placeholders() -> None:
    """If a signed file is committed, it must be valid for the current catalogue or absent."""
    path = REPO / "authorizations" / "local-lab.json"
    if path.exists():
        document = json.loads(path.read_text())
        assert document["targets"] == ["local-lab"]
        assert "<" not in document["authorized_by"]
    assert authorization_document()["targets"] == ["local-lab"]
