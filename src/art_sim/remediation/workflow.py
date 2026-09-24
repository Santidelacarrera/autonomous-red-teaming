"""Application service that coordinates generation and source-control publication."""

from __future__ import annotations

from art_sim.remediation.agent import RemediationAgent
from art_sim.remediation.models import PullRequestReceipt, RemediationRequest
from art_sim.remediation.ports import PullRequestPublisher


class RemediationWorkflow:
    """Publish only the artifact generated from a validated remediation request."""

    def __init__(self, agent: RemediationAgent, publisher: PullRequestPublisher) -> None:
        """Inject the generation agent and SCM publisher independently."""
        self._agent = agent
        self._publisher = publisher

    async def create_pull_request(self, request: RemediationRequest) -> PullRequestReceipt:
        """Generate a candidate patch and create or reuse its pull request."""
        artifact = await self._agent.generate(request)
        return await self._publisher.publish(artifact, request)
