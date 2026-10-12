"""pytest plugin for the breach-and-attack-simulation tests (registers ``bas_grant``)."""

from __future__ import annotations

import pytest
from bas_fixtures import write_authorization

from art_sim.bas.authorization import GrantedAuthorization, verify_authorization
from art_sim.bas.runner import catalogue_digest


@pytest.fixture
def bas_grant(tmp_path_factory: pytest.TempPathFactory) -> GrantedAuthorization:
    folder = tmp_path_factory.mktemp("authorization")
    path = write_authorization(folder / "local-lab.json")
    return verify_authorization(path, catalogue_sha256=catalogue_digest(), backend="sqlite")
