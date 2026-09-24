"""Explicit development-only identity provider."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar

from art_sim.domain.exceptions import AuthenticationError, ConfigurationError
from art_sim.security.identity import (
    ApiRole,
    AuthenticationContext,
    AuthenticationMethod,
    Identity,
    IdentityProviderCapability,
)
from art_sim.security.permissions import permissions_for_roles


class DevelopmentHeaderAuthenticator:
    """Parse a local bearer identity only when explicitly enabled."""

    provider_kind = "development"
    deployment_capability: ClassVar[IdentityProviderCapability] = (
        IdentityProviderCapability.DEVELOPMENT
    )

    def __init__(self, *, enabled: bool) -> None:
        if not enabled:
            raise ConfigurationError("Development header authentication is disabled")

    async def authenticate(self, authorization: str | None) -> Identity:
        """Authenticate `Bearer development:<role>:<subject>` without persistence."""
        if authorization is None or not authorization.startswith("Bearer "):
            raise AuthenticationError("Authentication is required")
        return await self.validate_token(authorization.removeprefix("Bearer "))

    async def validate_token(self, token: str) -> Identity:
        """Validate the constrained development credential format."""
        prefix = "development:"
        if not token.startswith(prefix):
            raise AuthenticationError("Authentication credential is invalid")
        fields = token.removeprefix(prefix).split(":", maxsplit=1)
        if len(fields) != 2:
            raise AuthenticationError("Authentication credential is invalid")
        try:
            role = ApiRole(fields[0])
        except ValueError as error:
            raise AuthenticationError("Authentication credential is invalid") from error
        subject = fields[1]
        if not subject or len(subject) > 128 or any(character.isspace() for character in subject):
            raise AuthenticationError("Authentication credential is invalid")
        roles = frozenset({role})
        return Identity(
            subject=subject,
            issuer="art-sim-development",
            roles=roles,
            permissions=permissions_for_roles(roles),
            authentication=AuthenticationContext(
                method=AuthenticationMethod.DEVELOPMENT,
                authenticated_at=datetime.now(UTC),
            ),
        )

    async def get_identity(self, authorization: str | None) -> Identity:
        """Alias authentication for provider-neutral callers."""
        return await self.authenticate(authorization)
