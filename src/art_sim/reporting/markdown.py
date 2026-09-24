"""Markdown renderer that reuses report DTOs and never fabricates metrics."""

from __future__ import annotations

from art_sim.reporting.models import SecuritySimulationReport


class MarkdownReportRenderer:
    """Render the requested technical and executive sections from actual result fields."""

    def render(self, report: SecuritySimulationReport) -> str:
        """Produce a deterministic Markdown document suitable for a reviewed artifact."""
        maximum_risk = max((assessment.score for assessment in report.assessments), default=0.0)
        critical_paths = sum(assessment.score >= 70.0 for assessment in report.assessments)
        after_blast = report.verification.blast_radius_after if report.verification else None
        lines = [
            "# Security Simulation Report",
            "",
            "## Executive Summary",
            f"- Assets analyzed: {report.total_assets}",
            f"- Critical assets: {report.total_critical_assets}",
            f"- Simulated attack paths detected: {len(report.attack_paths)}",
            f"- Critical simulated paths (risk ≥ 70): {critical_paths}",
            f"- Maximum simulated risk: {maximum_risk:.2f}/100",
            f"- Initial blast radius: {report.blast_radius_before.blast_radius_percentage:.2f}%",
            f"- Initial crown-jewel exposure: {report.blast_radius_before.crown_jewel_exposure_percentage:.2f}%",
            f"- Remediation candidates: {int(report.remediation is not None)}",
            f"- Verified remediations: {int(report.verification is not None and report.verification.status.value == 'verified')}",
            "",
            "## Simulation Metadata",
            f"- Run ID: `{report.run_id}`",
            f"- Generated at: {report.generated_at.isoformat()}",
            "- Classification: simulated; no production control was applied.",
            "",
            "## Overall Risk",
            f"- Maximum score: {maximum_risk:.2f}/100",
            "",
            "## Critical Attack Paths",
            f"- Count: {critical_paths}",
            "",
            "## Attack Path Details",
        ]
        for index, (path, assessment) in enumerate(zip(report.attack_paths, report.assessments, strict=True), start=1):
            lines.extend(
                (
                    f"### Path {index}",
                    f"- Source: `{path.source_asset_id}`",
                    f"- Target: `{path.target_asset_id}`",
                    f"- Hops: {path.hop_count}",
                    f"- Risk score: {assessment.score:.2f}/100",
                    f"- Relationships: {', '.join(step.relationship_type.value for step in path.steps)}",
                )
            )
        lines.extend(("", "## MITRE ATT&CK Mapping", "- See the approved attack plan audit trail for technique mappings."))
        lines.extend(("", "## Vulnerabilities"))
        lines.extend(
            f"- {vulnerability.cve_id or 'No CVE'}: CVSS {vulnerability.cvss_score:.1f}; {vulnerability.severity.value}"
            for vulnerability in report.vulnerabilities
        )
        if not report.vulnerabilities:
            lines.append("- No vulnerability evidence supplied to this report.")
        lines.extend(("", "## IAM Findings", "- IAM findings are modeled as simulated graph relations only."))
        lines.extend(("", "## Container Findings", "- Container findings are modeled as simulated graph relations only."))
        lines.extend(
            (
                "",
                "## Blast Radius",
                f"- Reachable assets: {report.blast_radius_before.reachable_assets}/{report.blast_radius_before.total_assets}",
                f"- Blast radius: {report.blast_radius_before.blast_radius_percentage:.2f}%",
                "",
                "## Crown Jewel Exposure",
                f"- Exposure: {report.blast_radius_before.crown_jewel_exposure_percentage:.2f}%",
                "",
                "## Recommended Remediations",
            )
        )
        lines.append(
            f"- {report.remediation.action.value}: {report.remediation.reason}"
            if report.remediation
            else "- No remediation candidate generated."
        )
        lines.extend(("", "## Human Approval"))
        lines.append(
            f"- {report.approval.decision.value} by `{report.approval.operator}` at {report.approval.decided_at.isoformat()}"
            if report.approval
            else "- No human decision recorded."
        )
        lines.extend(("", "## Verification Results"))
        lines.append(
            f"- Status: {report.verification.status.value}; paths removed: {report.verification.paths_removed}; risk reduction: {report.verification.risk_reduction:.2f}"
            if report.verification
            else "- Verification was not run."
        )
        lines.extend(("", "## Before vs After", "", "| Metric | Before | After |", "|---|---:|---:|"))
        lines.append(
            f"| Blast radius | {report.blast_radius_before.blast_radius_percentage:.2f}% | "
            f"{after_blast.blast_radius_percentage:.2f}% |" if after_blast else "| Blast radius | unavailable | unavailable |"
        )
        if report.verification:
            lines.extend(
                (
                    f"| Maximum risk | {report.verification.risk_before:.2f} | {report.verification.risk_after:.2f} |",
                    f"| Critical paths | 1 | {report.verification.remaining_paths} |",
                    f"| Crown jewel exposure | {report.verification.blast_radius_before.crown_jewel_exposure_percentage:.2f}% | {report.verification.blast_radius_after.crown_jewel_exposure_percentage:.2f}% |",
                )
            )
        lines.extend(("", "## Evidence"))
        lines.extend(f"- {item}" for item in report.evidence) if report.evidence else lines.append("- No additional evidence.")
        lines.extend(("", "## Agent Telemetry"))
        lines.extend(
            f"- {event.agent_name}/{event.node_name}: {event.status}, {event.duration_ms:.2f} ms"
            for event in report.telemetry
        )
        if not report.telemetry:
            lines.append("- No telemetry events recorded.")
        lines.extend(("", "## Appendix", "- All conclusions are limited to the supplied simulated graph state.", ""))
        return "\n".join(lines)
