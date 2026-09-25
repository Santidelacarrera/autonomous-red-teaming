"""Deterministic pre-approval policy for generated defensive countermeasures."""

from __future__ import annotations

from art_sim.remediation.models import (
    AutomatedPreApproval,
    NormalizedRemediation,
    PreApprovalStatus,
    RemediationArtifact,
    VerificationResult,
    VerificationStatus,
)


class CountermeasurePreApprovalPolicy:
    """Recommend safe candidates for review without granting authorization."""

    def evaluate(
        self,
        remediation: NormalizedRemediation,
        artifact: RemediationArtifact,
        verification: VerificationResult,
    ) -> AutomatedPreApproval:
        """Evaluate explicit, reproducible controls over a Shadow-only candidate."""
        checks = {
            "simulation_only": remediation.simulated_only,
            "artifact_integrity_valid": bool(artifact.content_sha256),
            "verification_succeeded": verification.status is VerificationStatus.VERIFIED,
            "risk_reduced": verification.risk_after < verification.risk_before,
            "attack_path_removed": (
                verification.paths_removed > 0 and verification.remaining_paths == 0
            ),
        }
        recommended = all(checks.values())
        return AutomatedPreApproval(
            status=(
                PreApprovalStatus.RECOMMENDED
                if recommended
                else PreApprovalStatus.BLOCKED
            ),
            checks=checks,
            summary=(
                "Automated controls passed; human cybersecurity approval is still required."
                if recommended
                else "Automated controls blocked this candidate from human approval."
            ),
        )
