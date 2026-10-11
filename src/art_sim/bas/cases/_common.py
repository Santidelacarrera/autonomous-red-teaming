"""Helpers shared by attack cases."""

from __future__ import annotations

import json

import httpx

from art_sim.bas.models import Observation, Verdict


def shape(response: httpx.Response) -> str:
    """Status plus body with the per-request correlation id removed (stable for comparison)."""
    try:
        body = response.json()
    except ValueError:
        return f"{response.status_code}:{response.text[:200]}"
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        body["error"].pop("request_id", None)
    return f"{response.status_code}:{json.dumps(body, sort_keys=True)}"


def blocked(response: httpx.Response, detail: str) -> Observation:
    return Observation(Verdict.BLOCKED, detail, response.status_code, shape(response))


def breached(response: httpx.Response, detail: str) -> Observation:
    return Observation(Verdict.BREACHED, detail, response.status_code, shape(response))
