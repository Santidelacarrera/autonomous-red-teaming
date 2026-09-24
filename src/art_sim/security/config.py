"""Fail-closed identity, CORS, rate-limit, and assurance configuration."""

from __future__ import annotations

import os
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from art_sim.domain.exceptions import ConfigurationError
from art_sim.platform.config import RuntimeEnvironment
from art_sim.security.providers.oidc import OidcSettings


class AuthenticationProviderKind(StrEnum):
    """Supported identity boundary adapters."""

    DEVELOPMENT = "development"
    OIDC = "oidc"


class SecuritySettings(BaseModel):
    """Validated non-secret security controls selected at startup."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: RuntimeEnvironment = RuntimeEnvironment.DEVELOPMENT
    authentication_provider: AuthenticationProviderKind = AuthenticationProviderKind.DEVELOPMENT
    oidc: OidcSettings | None = None
    cors_allowed_origins: tuple[str, ...] = ()
    rate_limit_enabled: bool = True
    auth_requests_per_minute: int = Field(default=60, ge=1, le=10_000)
    simulation_creates_per_minute: int = Field(default=10, ge=1, le=1000)
    approval_requests_per_minute: int = Field(default=10, ge=1, le=1000)
    admin_requests_per_minute: int = Field(default=30, ge=1, le=1000)
    mfa_required_for_sensitive_actions: bool = False
    hsts_enabled: bool = False

    @field_validator("cors_allowed_origins")
    @classmethod
    def validate_origins(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Accept only normalized HTTP origins without paths or control characters."""
        for value in values:
            if not value.startswith(("https://", "http://localhost", "http://127.0.0.1")):
                raise ValueError("CORS origins must be HTTPS or an explicit local development origin")
            authority = value.split("://", maxsplit=1)[1]
            if not authority or "/" in authority or any(character.isspace() for character in value):
                raise ValueError("CORS origins must not include paths or whitespace")
        return values

    @model_validator(mode="after")
    def fail_closed(self) -> SecuritySettings:
        """Reject development auth and incomplete edge policy outside development."""
        if (
            self.environment is not RuntimeEnvironment.DEVELOPMENT
            and (self.authentication_provider is not AuthenticationProviderKind.OIDC or self.oidc is None)
        ):
            raise ValueError("Non-development profiles require complete OIDC configuration")
        if self.authentication_provider is AuthenticationProviderKind.OIDC and self.oidc is None:
            raise ValueError("OIDC provider requires issuer, audience, and JWKS configuration")
        if "*" in self.cors_allowed_origins:
            raise ValueError("Wildcard CORS origins are forbidden")
        if self.environment is RuntimeEnvironment.PRODUCTION and not self.cors_allowed_origins:
            raise ValueError("Production requires an explicit CORS origin allow-list")
        if self.environment is RuntimeEnvironment.PRODUCTION and any(
            not origin.startswith("https://") for origin in self.cors_allowed_origins
        ):
            raise ValueError("Production CORS origins must use HTTPS")
        if self.environment is RuntimeEnvironment.PRODUCTION and not self.rate_limit_enabled:
            raise ValueError("Production rate limiting must be enabled")
        if self.environment is RuntimeEnvironment.PRODUCTION and not self.hsts_enabled:
            raise ValueError("Production HSTS must be enabled")
        if self.hsts_enabled and self.environment is RuntimeEnvironment.DEVELOPMENT:
            raise ValueError("HSTS must not be enabled for local HTTP development")
        return self

    @classmethod
    def from_environment(cls, environment: RuntimeEnvironment) -> SecuritySettings:
        """Build validated settings without defaulting production to development auth."""
        provider_default = "development" if environment is RuntimeEnvironment.DEVELOPMENT else "oidc"
        provider = AuthenticationProviderKind(os.getenv("ART_AUTH_PROVIDER", provider_default))
        issuer = os.getenv("ART_OIDC_ISSUER")
        audience = os.getenv("ART_OIDC_AUDIENCE")
        jwks_url = os.getenv("ART_OIDC_JWKS_URL")
        oidc = None
        if any((issuer, audience, jwks_url)):
            if not all((issuer, audience, jwks_url)):
                raise ConfigurationError("OIDC configuration is incomplete")
            oidc = OidcSettings(issuer=issuer or "", audience=audience or "", jwks_url=jwks_url or "")
        origins = tuple(value.strip() for value in os.getenv("ART_CORS_ALLOWED_ORIGINS", "").split(",") if value.strip())
        try:
            return cls(
                environment=environment,
                authentication_provider=provider,
                oidc=oidc,
                cors_allowed_origins=origins,
                rate_limit_enabled=_bool_env("ART_RATE_LIMIT_ENABLED", True),
                auth_requests_per_minute=_int_env("ART_AUTH_REQUESTS_PER_MINUTE", 60),
                simulation_creates_per_minute=_int_env("ART_SIMULATION_CREATES_PER_MINUTE", 10),
                approval_requests_per_minute=_int_env("ART_APPROVAL_REQUESTS_PER_MINUTE", 10),
                admin_requests_per_minute=_int_env("ART_ADMIN_REQUESTS_PER_MINUTE", 30),
                mfa_required_for_sensitive_actions=_bool_env("ART_MFA_REQUIRED_FOR_SENSITIVE_ACTIONS", False),
                hsts_enabled=_bool_env("ART_HSTS_ENABLED", environment is RuntimeEnvironment.PRODUCTION),
            )
        except ValueError as error:
            raise ConfigurationError("Security configuration is invalid") from error


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    if value.lower() not in {"true", "false", "1", "0"}:
        raise ConfigurationError(f"{name} must be true or false")
    return value.lower() in {"true", "1"}


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as error:
        raise ConfigurationError(f"{name} must be an integer") from error
