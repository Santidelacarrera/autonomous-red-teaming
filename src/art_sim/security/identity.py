"""Provider-neutral authenticated identity and authentication contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, Protocol

from pydantic import BaseModel, ConfigDict, Field


class ApiRole(StrEnum):
    """Stable platform roles mapped to permissions by one central policy."""

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


class AuthenticationMethod(StrEnum):
    """Authentication mechanisms understood by the security boundary."""

    DEVELOPMENT = "development"
    OIDC = "oidc"


class AuthenticationStrength(StrEnum):
    """Authentication assurance available for step-up decisions."""

    STANDARD = "standard"
    MFA = "mfa"


class IdentityProviderCapability(StrEnum):
    """Verification capability declared by an identity adapter."""

    DEVELOPMENT = "development"
    OIDC_VERIFIED = "oidc_verified"


class AuthenticationContext(BaseModel):
    """Non-secret assurance context supplied by a verified identity provider."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: AuthenticationMethod
    strength: AuthenticationStrength = AuthenticationStrength.STANDARD
    authenticated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    mfa_satisfied: bool = False


class Identity(BaseModel):
    """Verified caller identity containing no credentials or raw access token."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject: str = Field(min_length=1, max_length=128)
    issuer: str = Field(min_length=1, max_length=512)
    roles: frozenset[ApiRole] = Field(min_length=1)
    permissions: frozenset[str]
    authentication: AuthenticationContext
    token_id: str | None = Field(default=None, max_length=128)
    session_id: str | None = Field(default=None, max_length=128)

    @property
    def primary_role(self) -> ApiRole:
        """Return the highest-privilege role for presentation only."""
        for role in (ApiRole.ADMIN, ApiRole.OPERATOR, ApiRole.VIEWER):
            if role in self.roles:
                return role
        raise ValueError("Identity has no supported role")


class IdentityProvider(Protocol):
    """Authenticate a bearer credential through an injected provider."""

    provider_kind: str
    deployment_capability: ClassVar[IdentityProviderCapability]

    async def authenticate(self, authorization: str | None) -> Identity: ...

    async def validate_token(self, token: str) -> Identity: ...

    async def get_identity(self, authorization: str | None) -> Identity: ...


Authenticator = IdentityProvider
Principal = Identity
