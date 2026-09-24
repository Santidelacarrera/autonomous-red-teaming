"""Deterministic exporters for review-only remediation formats."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod

from art_sim.domain.exceptions import RemediationExportError
from art_sim.remediation.models import ExportedRemediation, ExportFormat, NormalizedRemediation


class RemediationExporter(ABC):
    """Render a normalized remediation without applying it to any provider."""

    @abstractmethod
    def export(self, remediation: NormalizedRemediation) -> ExportedRemediation:
        """Return one deterministic text artifact fit for human review."""


class JsonRemediationExporter(RemediationExporter):
    """Export the canonical normalized remediation JSON representation."""

    def export(self, remediation: NormalizedRemediation) -> ExportedRemediation:
        """Render stable JSON with explicit simulation-only semantics."""
        content = remediation.model_dump_json(indent=2) + "\n"
        return ExportedRemediation(
            export_format=ExportFormat.JSON,
            file_name=f"remediation-{remediation.remediation_id.hex[:12]}.json",
            content=content,
        )


class _HclRemediationExporter(RemediationExporter):
    """Shared HCL implementation; Terraform and OpenTofu differ only in naming."""

    _format: ExportFormat
    _tool_name: str

    def export(self, remediation: NormalizedRemediation) -> ExportedRemediation:
        """Render review-only locals rather than a resource that would change infrastructure."""
        content = "\n".join(
            (
                f"# {self._tool_name} review-only remediation candidate.",
                "# Applying this file is intentionally outside this simulator.",
                "locals {",
                "  ctem_remediation = {",
                f'    remediation_id = "{remediation.remediation_id}"',
                f'    action         = "{remediation.action.value}"',
                f'    relationship   = "{remediation.relationship_type.value}"',
                f'    source_asset   = "{remediation.source_asset_id}"',
                f'    target_asset   = "{remediation.target_asset_id}"',
                "    simulated_only = true",
                "  }",
                "}",
                "",
            )
        )
        self._validate_hcl(content)
        return ExportedRemediation(
            export_format=self._format,
            file_name=f"remediation-{remediation.remediation_id.hex[:12]}.tf",
            content=content,
        )

    @staticmethod
    def _validate_hcl(content: str) -> None:
        """Perform a dependency-free structural validation of generated static HCL."""
        if content.count("{") != content.count("}") or "ctem_remediation" not in content:
            raise RemediationExportError("Generated HCL failed structural validation")


class TerraformRemediationExporter(_HclRemediationExporter):
    """Export review-only HCL compatible with Terraform syntax."""

    _format = ExportFormat.TERRAFORM
    _tool_name = "Terraform"


class OpenTofuRemediationExporter(_HclRemediationExporter):
    """Export review-only HCL compatible with OpenTofu syntax."""

    _format = ExportFormat.OPENTOFU
    _tool_name = "OpenTofu"


class OPARegoExporter(RemediationExporter):
    """Render a Rego v1 policy that detects the modeled unsafe relation."""

    def export(self, remediation: NormalizedRemediation) -> ExportedRemediation:
        """Generate a policy using only identifiers from normalized remediation state."""
        reason = json.dumps(remediation.reason)
        action = json.dumps(remediation.action.value)
        relation = json.dumps(remediation.relationship_type.value)
        content = "\n".join(
            (
                "package ctem.security",
                "",
                f'violation contains {{"resource": input.resource, "reason": {reason}, "severity": "high", "remediation": {action}}} if {{',
                f"  input.relationship_type == {relation}",
                "}",
                "",
            )
        )
        return ExportedRemediation(
            export_format=ExportFormat.OPA_REGO,
            file_name=f"remediation-{remediation.remediation_id.hex[:12]}.rego",
            content=content,
        )


class GatekeeperExporter(RemediationExporter):
    """Render a ConstraintTemplate-compatible review artifact embedding Rego logic."""

    def export(self, remediation: NormalizedRemediation) -> ExportedRemediation:
        """Render an opt-in Gatekeeper template; installation is intentionally excluded."""
        name = f"ctemrelation{remediation.remediation_id.hex[:12]}"
        content = "\n".join(
            (
                "apiVersion: templates.gatekeeper.sh/v1",
                "kind: ConstraintTemplate",
                "metadata:",
                f"  name: {name}",
                "spec:",
                "  crd:",
                "    spec:",
                f"      names:\n        kind: Ctem{remediation.remediation_id.hex[:8]}",
                "  targets:",
                "    - target: admission.k8s.gatekeeper.sh",
                "      rego: |",
                "        package ctem.gatekeeper",
                "        violation[{\"msg\": msg}] {",
                f"          input.review.object.metadata.labels[\"ctem.openai.com/relation\"] == \"{remediation.relationship_type.value}\"",
                f"          msg := \"{remediation.action.value} required\"",
                "        }",
                "",
            )
        )
        return ExportedRemediation(
            export_format=ExportFormat.GATEKEEPER,
            file_name=f"remediation-{remediation.remediation_id.hex[:12]}-gatekeeper.yaml",
            content=content,
        )
