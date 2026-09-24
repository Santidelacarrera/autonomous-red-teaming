"""Ports for remediation renderers and source-control publishers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from art_sim.remediation.models import (
    PullRequestReceipt,
    RemediationArtifact,
    RemediationPrompt,
    RemediationRequest,
)


class RemediationGenerator(ABC):
    """Generates a patch from an allow-listed structured remediation prompt."""

    @abstractmethod
    async def generate(self, prompt: RemediationPrompt) -> RemediationArtifact:
        """Return an idempotent patch candidate without making external changes."""


class PullRequestPublisher(ABC):
    """Publishes a reviewed remediation artifact to a source-control provider."""

    @abstractmethod
    async def publish(
        self, artifact: RemediationArtifact, request: RemediationRequest
    ) -> PullRequestReceipt:
        """Create or reuse an idempotent pull request for the artifact."""
