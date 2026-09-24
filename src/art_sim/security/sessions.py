"""Session lifecycle abstraction for bearer and future OIDC/BFF deployments."""

from __future__ import annotations

from typing import Protocol

from art_sim.security.identity import Identity


class SessionLifecycle(Protocol):
    """Invalidate provider-managed session state where supported."""

    async def logout(self, identity: Identity) -> None: ...


class StatelessBearerSession:
    """Bearer lifecycle: clients discard tokens; revocation remains an IdP responsibility."""

    async def logout(self, identity: Identity) -> None:
        """Complete local logout without persisting or logging token material."""
        del identity
