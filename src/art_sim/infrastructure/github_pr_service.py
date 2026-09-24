"""Asynchronous, idempotent GitHub REST adapter for remediation pull requests."""

from __future__ import annotations

import base64
from collections.abc import Awaitable, Callable, Mapping
from typing import TypeVar
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, SecretStr
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from art_sim.domain.exceptions import GitHubIntegrationError
from art_sim.remediation.models import PullRequestReceipt, RemediationArtifact, RemediationRequest
from art_sim.remediation.ports import PullRequestPublisher

ResultT = TypeVar("ResultT")


class GitHubSettings(BaseModel):
    """Validated settings supplied by the application composition root."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    owner: str = Field(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37})$")
    repository: str = Field(pattern=r"^[A-Za-z0-9._-]{1,100}$")
    token: SecretStr
    base_branch: str = Field(default="main", pattern=r"^[A-Za-z0-9._/-]{1,128}$")
    api_url: HttpUrl = HttpUrl("https://api.github.com")
    timeout_seconds: float = Field(default=15.0, gt=0.0, le=60.0)
    draft_pull_requests: bool = True


class GitHubApiClient:
    """Small async REST boundary replaceable by a deterministic test double."""

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, object] | None = None,
        params: Mapping[str, str] | None = None,
        allow_not_found: bool = False,
    ) -> object | None:
        """Issue one GitHub request and decode its JSON response."""
        raise NotImplementedError


class HttpxGitHubApiClient(GitHubApiClient):
    """GitHub REST-compatible client with transient failure retries."""

    _RETRYABLE_STATUS_CODES = frozenset((408, 429, 500, 502, 503, 504))

    def __init__(self, settings: GitHubSettings, client: httpx.AsyncClient | None = None) -> None:
        """Create an authenticated client or accept an injected test client."""
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=str(settings.api_url).rstrip("/"),
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {settings.token.get_secret_value()}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=settings.timeout_seconds,
        )

    async def close(self) -> None:
        """Close only the client created by this adapter."""
        if self._owns_client:
            await self._client.aclose()

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, object] | None = None,
        params: Mapping[str, str] | None = None,
        allow_not_found: bool = False,
    ) -> object | None:
        """Retry transient failures and map all other HTTP failures to a domain error."""

        async def operation() -> object | None:
            response = await self._client.request(method, path, json=json_body, params=params)
            if allow_not_found and response.status_code == httpx.codes.NOT_FOUND:
                return None
            if response.status_code in self._RETRYABLE_STATUS_CODES:
                raise _RetryableGitHubError(f"GitHub returned transient HTTP {response.status_code}")
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as error:
                raise GitHubIntegrationError("GitHub rejected the remediation publication request") from error
            payload: object = response.json()
            return payload

        try:
            return await self._retry(operation)
        except (httpx.RequestError, _RetryableGitHubError) as error:
            raise GitHubIntegrationError("GitHub could not be reached after retry attempts") from error

    @staticmethod
    async def _retry(operation: Callable[[], Awaitable[ResultT]]) -> ResultT:
        """Run API I/O with bounded exponential backoff and jitter."""
        async for attempt in AsyncRetrying(
            retry=retry_if_exception_type((httpx.RequestError, _RetryableGitHubError)),
            wait=wait_exponential_jitter(initial=0.25, max=4.0),
            stop=stop_after_attempt(3),
            reraise=True,
        ):
            with attempt:
                return await operation()
        raise AssertionError("tenacity retry loop completed without returning or raising")


class GitHubPRService(PullRequestPublisher):
    """Create or reuse a branch, commit, and pull request for one remediation artifact."""

    def __init__(self, settings: GitHubSettings, client: GitHubApiClient) -> None:
        """Inject settings and transport separately to keep external I/O testable."""
        self._settings = settings
        self._client = client
        self._repository_path = f"/repos/{settings.owner}/{settings.repository}"

    async def publish(
        self, artifact: RemediationArtifact, request: RemediationRequest
    ) -> PullRequestReceipt:
        """Publish deterministically while avoiding duplicate branches, commits, and PRs."""
        branch = f"ctem/remediation/{artifact.idempotency_key[:16]}"
        await self._ensure_branch(branch)
        created_commit = await self._upsert_content(branch, artifact)
        existing_pr = await self._find_open_pull_request(branch)
        if existing_pr is not None:
            return self._receipt(existing_pr, branch, created_commit)
        payload: dict[str, object] = {
            "title": f"CTEM: {artifact.remediation_kind.value} remediation candidate",
            "head": branch,
            "base": self._settings.base_branch,
            "body": self._pull_request_body(artifact, request),
            "draft": self._settings.draft_pull_requests,
        }
        response = await self._client.request("POST", f"{self._repository_path}/pulls", json_body=payload)
        return self._receipt(self._mapping(response), branch, created_commit)

    async def _ensure_branch(self, branch: str) -> None:
        """Create the deterministic branch only when it does not already exist."""
        encoded_branch = quote(branch, safe="")
        existing = await self._client.request(
            "GET", f"{self._repository_path}/git/ref/heads/{encoded_branch}", allow_not_found=True
        )
        if existing is not None:
            return
        base = self._mapping(
            await self._client.request(
                "GET", f"{self._repository_path}/git/ref/heads/{quote(self._settings.base_branch, safe='')}"
            )
        )
        base_object = self._mapping(base.get("object"))
        base_sha = base_object.get("sha")
        if not isinstance(base_sha, str) or not base_sha:
            raise GitHubIntegrationError("GitHub base branch response did not contain an object SHA")
        await self._client.request(
            "POST",
            f"{self._repository_path}/git/refs",
            json_body={"ref": f"refs/heads/{branch}", "sha": base_sha},
        )

    async def _upsert_content(self, branch: str, artifact: RemediationArtifact) -> bool:
        """Commit only when the branch does not already contain the reviewed artifact."""
        encoded_path = "/".join(quote(part, safe="") for part in artifact.file_path.split("/"))
        current = await self._client.request(
            "GET",
            f"{self._repository_path}/contents/{encoded_path}",
            params={"ref": branch},
            allow_not_found=True,
        )
        current_mapping = self._mapping(current) if current is not None else None
        if current_mapping is not None and self._content_matches(current_mapping, artifact.content):
            return False
        body: dict[str, object] = {
            "message": f"CTEM: add {artifact.remediation_kind.value} candidate",
            "content": base64.b64encode(artifact.content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if current_mapping is not None:
            sha = current_mapping.get("sha")
            if not isinstance(sha, str) or not sha:
                raise GitHubIntegrationError("GitHub content response did not contain a file SHA")
            body["sha"] = sha
        await self._client.request("PUT", f"{self._repository_path}/contents/{encoded_path}", json_body=body)
        return True

    async def _find_open_pull_request(self, branch: str) -> Mapping[str, object] | None:
        """Return an existing open PR for the deterministic branch, if present."""
        response = await self._client.request(
            "GET",
            f"{self._repository_path}/pulls",
            params={
                "state": "open",
                "head": f"{self._settings.owner}:{branch}",
                "base": self._settings.base_branch,
            },
        )
        if not isinstance(response, list):
            raise GitHubIntegrationError("GitHub pull request lookup returned an unexpected payload")
        if not response:
            return None
        return self._mapping(response[0])

    @staticmethod
    def _content_matches(current: Mapping[str, object], content: str) -> bool:
        """Compare GitHub base64 content with the rendered bytes before committing."""
        encoded = current.get("content")
        if not isinstance(encoded, str):
            return False
        try:
            return base64.b64decode(encoded.encode("ascii"), validate=False) == content.encode("utf-8")
        except ValueError:
            return False

    @staticmethod
    def _pull_request_body(artifact: RemediationArtifact, request: RemediationRequest) -> str:
        """Document structured evidence only, never raw scanner or telemetry text."""
        techniques = ", ".join(step.technique.technique_id for step in request.plan.steps)
        return "\n".join(
            (
                "## CTEM remediation candidate",
                "",
                f"- Plan: `{request.plan.plan_id}`",
                f"- Simulated target: `{request.target.asset_id}`",
                f"- MITRE techniques: `{techniques}`",
                f"- Artifact digest: `{artifact.content_sha256}`",
                "- Evidence: successful Shadow simulation; no production action was performed.",
                "",
                "Review required before applying this opt-in policy candidate.",
            )
        )

    @staticmethod
    def _receipt(payload: Mapping[str, object], branch: str, created_commit: bool) -> PullRequestReceipt:
        """Validate the minimal PR response required by callers."""
        number = payload.get("number")
        url = payload.get("html_url")
        if not isinstance(number, int) or not isinstance(url, str):
            raise GitHubIntegrationError("GitHub pull request response is incomplete")
        return PullRequestReceipt(number=number, url=url, branch=branch, created_commit=created_commit)

    @staticmethod
    def _mapping(payload: object | None) -> Mapping[str, object]:
        """Narrow untyped external JSON payload to the mapping required by this adapter."""
        if not isinstance(payload, Mapping):
            raise GitHubIntegrationError("GitHub response did not contain an object payload")
        return payload


class _RetryableGitHubError(Exception):
    """Internal marker used to retry specific transient GitHub HTTP status codes."""
