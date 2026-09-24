"""OIDC access-token verification with strict claims and rotating JWKS."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from time import monotonic
from typing import Any

import httpx
import jwt
from pydantic import BaseModel, ConfigDict, Field, field_validator
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from art_sim.domain.exceptions import AuthenticationError
from art_sim.security.identity import (
    ApiRole,
    AuthenticationContext,
    AuthenticationMethod,
    AuthenticationStrength,
    Identity,
)
from art_sim.security.permissions import permissions_for_roles


class OidcSettings(BaseModel):
    """Validated public OIDC resource-server configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer: str = Field(min_length=8, max_length=512)
    audience: str = Field(min_length=1, max_length=256)
    jwks_url: str = Field(min_length=8, max_length=1024)
    algorithms: tuple[str, ...] = ("RS256",)
    jwks_cache_seconds: int = Field(default=300, ge=30, le=86_400)
    clock_skew_seconds: int = Field(default=30, ge=0, le=300)

    @field_validator("issuer", "jwks_url")
    @classmethod
    def require_https(cls, value: str) -> str:
        """Prevent insecure metadata or key retrieval."""
        if not value.startswith("https://"):
            raise ValueError("OIDC endpoints must use HTTPS")
        return value.rstrip("/")

    @field_validator("algorithms")
    @classmethod
    def restrict_algorithms(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Allow only asymmetric algorithms; `none` and shared-secret confusion fail closed."""
        allowed = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
        if not value or any(algorithm not in allowed for algorithm in value):
            raise ValueError("OIDC algorithms must be approved asymmetric algorithms")
        return value


class OidcIdentityProvider:
    """Validate signed JWT access tokens against an allow-listed OIDC provider."""

    provider_kind = "oidc"

    def __init__(self, settings: OidcSettings, client: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._client = client
        self._keys: dict[str, dict[str, Any]] = {}
        self._cache_deadline = 0.0
        self._lock = asyncio.Lock()

    async def authenticate(self, authorization: str | None) -> Identity:
        """Extract one bearer token without exposing it in failures."""
        if authorization is None or not authorization.startswith("Bearer "):
            raise AuthenticationError("Authentication is required")
        token = authorization.removeprefix("Bearer ")
        if not token or len(token) > 16_384:
            raise AuthenticationError("Authentication credential is invalid")
        return await self.validate_token(token)

    async def validate_token(self, token: str) -> Identity:
        """Validate signature, algorithm, kid, issuer, audience, time, and subject."""
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            algorithm = header.get("alg")
            if not isinstance(kid, str) or not kid or algorithm not in self._settings.algorithms:
                raise AuthenticationError("Authentication credential is invalid")
            jwk = await self._key(kid)
            if jwk.get("use") not in (None, "sig") or jwk.get("alg") not in (None, algorithm):
                raise AuthenticationError("Authentication credential is invalid")
            key = jwt.PyJWK.from_dict(jwk, algorithm=algorithm).key
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(self._settings.algorithms),
                audience=self._settings.audience,
                issuer=self._settings.issuer,
                leeway=self._settings.clock_skew_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
            return self._identity(claims)
        except AuthenticationError:
            raise
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as error:
            raise AuthenticationError("Authentication credential is invalid") from error

    async def get_identity(self, authorization: str | None) -> Identity:
        """Alias authentication for provider-neutral callers."""
        return await self.authenticate(authorization)

    async def _key(self, kid: str) -> dict[str, Any]:
        if monotonic() >= self._cache_deadline or kid not in self._keys:
            await self._refresh_keys()
        key = self._keys.get(kid)
        if key is None:
            await self._refresh_keys(force=True)
            key = self._keys.get(kid)
        if key is None:
            raise AuthenticationError("Authentication credential is invalid")
        return key

    async def _refresh_keys(self, *, force: bool = False) -> None:
        async with self._lock:
            if not force and monotonic() < self._cache_deadline and self._keys:
                return
            try:
                async for attempt in AsyncRetrying(
                    stop=stop_after_attempt(3),
                    wait=wait_exponential_jitter(initial=0.1, max=1.0),
                    retry=retry_if_exception_type((httpx.HTTPError, ValueError)),
                    reraise=True,
                ):
                    with attempt:
                        payload = await self._fetch_jwks()
                        keys = payload.get("keys")
                        if not isinstance(keys, list):
                            raise TypeError("JWKS response is invalid")
                        parsed = {
                            str(key["kid"]): key
                            for key in keys
                            if isinstance(key, dict)
                            and isinstance(key.get("kid"), str)
                            and key.get("use") in (None, "sig")
                        }
                        if not parsed:
                            raise ValueError("JWKS contains no usable keys")
                self._keys = parsed
                self._cache_deadline = monotonic() + self._settings.jwks_cache_seconds
            except (httpx.HTTPError, TypeError, ValueError) as error:
                raise AuthenticationError("Identity provider is unavailable") from error

    async def _fetch_jwks(self) -> dict[str, Any]:
        if self._client is not None:
            response = await self._client.get(self._settings.jwks_url)
        else:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                response = await client.get(self._settings.jwks_url)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise TypeError("JWKS response is invalid")
        return payload

    def _identity(self, claims: dict[str, Any]) -> Identity:
        if not isinstance(claims.get("sub"), str):
            raise AuthenticationError("Authentication credential is invalid")
        raw_roles = claims.get("roles", claims.get("role", []))
        if isinstance(raw_roles, str):
            raw_roles = [raw_roles]
        if not isinstance(raw_roles, list):
            raise AuthenticationError("Authentication credential is invalid")
        roles = frozenset(ApiRole(role) for role in raw_roles if role in {item.value for item in ApiRole})
        if not roles:
            raise AuthenticationError("Authentication credential is invalid")
        amr = claims.get("amr", [])
        mfa = isinstance(amr, list) and any(value in {"mfa", "otp", "hwk"} for value in amr)
        auth_time = claims.get("auth_time", claims["iat"])
        return Identity(
            subject=str(claims["sub"]),
            issuer=self._settings.issuer,
            roles=roles,
            permissions=permissions_for_roles(roles),
            authentication=AuthenticationContext(
                method=AuthenticationMethod.OIDC,
                strength=AuthenticationStrength.MFA if mfa else AuthenticationStrength.STANDARD,
                authenticated_at=datetime.fromtimestamp(float(auth_time), tz=UTC),
                mfa_satisfied=mfa,
            ),
            token_id=str(claims["jti"]) if claims.get("jti") is not None else None,
            session_id=str(claims["sid"]) if claims.get("sid") is not None else None,
        )
