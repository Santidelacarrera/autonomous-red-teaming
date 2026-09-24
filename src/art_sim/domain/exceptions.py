"""Domain-specific failures with actionable, safe context."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from art_sim.agents.models import SupervisorFinding


class GraphEngineError(Exception):
    """Base class for graph-engine failures."""


class ConfigurationError(GraphEngineError):
    """Raised when a required secure runtime configuration value is absent or invalid."""


class AuthenticationError(GraphEngineError):
    """Raised when caller credentials cannot produce a verified identity."""


class AuthorizationError(GraphEngineError):
    """Raised when an authenticated identity lacks an explicit permission."""


class GraphConnectionError(GraphEngineError):
    """Raised when connectivity to Neo4j cannot be established."""


class GraphQueryError(GraphEngineError):
    """Raised when a graph query cannot be safely executed."""


class CypherValidationError(GraphQueryError):
    """Raised when a Cypher statement violates the local safety policy."""


class TopologyNotFoundError(GraphEngineError):
    """Raised when no eligible deterministic path exists in the topology."""


class ScopeViolationError(GraphEngineError):
    """Raised when recon or planning tries to leave the approved shadow boundary."""

    def __init__(self, findings: Sequence[SupervisorFinding]) -> None:
        """Retain structured policy findings without echoing untrusted input."""
        self.findings = tuple(findings)
        super().__init__("Shadow-environment scope policy rejected the operation")

    @classmethod
    def from_code(cls, code: str, detail: str) -> ScopeViolationError:
        """Build one finding lazily to avoid a domain-to-agent runtime import cycle."""
        from art_sim.agents.models import SupervisorFinding

        return cls((SupervisorFinding(code=code, detail=detail),))


class RemediationEligibilityError(GraphEngineError):
    """Raised when remediation lacks a successful, approved Shadow simulation."""


class GitHubIntegrationError(GraphEngineError):
    """Raised when GitHub cannot safely publish a remediation candidate."""


class RemediationExportError(GraphEngineError):
    """Raised when a review-only remediation artifact cannot be rendered safely."""


class ApprovalRequiredError(GraphEngineError):
    """Raised when a remediation workflow attempts to bypass human approval."""


class VerificationError(GraphEngineError):
    """Raised when post-remediation verification cannot analyze the simulated graph."""
