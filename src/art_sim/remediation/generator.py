"""Deterministic policy renderer used as the safe baseline remediation generator."""

from __future__ import annotations

import json
from hashlib import sha256

from art_sim.remediation.models import RemediationArtifact, RemediationKind, RemediationPrompt
from art_sim.remediation.ports import RemediationGenerator


class PolicyRemediationGenerator(RemediationGenerator):
    """Render reviewed YAML/JSON templates; it never applies them to infrastructure."""

    async def generate(self, prompt: RemediationPrompt) -> RemediationArtifact:
        """Create a stable candidate filename and content from structured values only."""
        target_token = prompt.target_asset_id.hex[:12]
        idempotency_key = self._idempotency_key(prompt)
        if prompt.remediation_kind is RemediationKind.AWS_IAM_POLICY:
            file_path = f"aws/iam-policies/ctem-shadow-assume-role-{target_token}.json"
            content = self._render_iam_policy(idempotency_key)
            summary = "Candidate IAM guardrail for simulated role-assumption traversal."
        else:
            file_path = f"kubernetes/network-policies/ctem-shadow-egress-{target_token}.yaml"
            content = self._render_network_policy(target_token, idempotency_key)
            summary = "Opt-in Shadow NetworkPolicy candidate for simulated network traversal."
        return RemediationArtifact(
            remediation_kind=prompt.remediation_kind,
            file_path=file_path,
            content=content,
            summary=summary,
            idempotency_key=idempotency_key,
            content_sha256=sha256(content.encode("utf-8")).hexdigest(),
        )

    @staticmethod
    def _idempotency_key(prompt: RemediationPrompt) -> str:
        """Use stable identifiers, never untrusted evidence, for artifact identity."""
        material = ":".join(
            (
                "ctem-remediation-v1",
                prompt.remediation_kind.value,
                str(prompt.target_asset_id),
                ",".join(action.value for action in prompt.simulated_actions),
            )
        )
        return sha256(material.encode("utf-8")).hexdigest()

    @staticmethod
    def _render_network_policy(target_token: str, idempotency_key: str) -> str:
        """Render an opt-in policy selecting no workload until an operator adds its label."""
        return f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ctem-shadow-egress-{target_token}
  namespace: shadow
  labels:
    app.kubernetes.io/managed-by: ctem
    ctem.openai.com/idempotency-key: {idempotency_key[:16]}
spec:
  podSelector:
    matchLabels:
      ctem.openai.com/egress-remediation: {target_token}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
"""

    @staticmethod
    def _render_iam_policy(idempotency_key: str) -> str:
        """Render an unattached, review-only IAM policy with a Shadow tag condition."""
        document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": f"CtemShadowAssumeRole{idempotency_key[:12]}",
                    "Effect": "Deny",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::${aws:PrincipalAccount}:role/ctem-shadow-*",
                    "Condition": {"StringNotEquals": {"aws:PrincipalTag/ctem-shadow": "true"}},
                }
            ],
        }
        return json.dumps(document, indent=2, sort_keys=True) + "\n"
