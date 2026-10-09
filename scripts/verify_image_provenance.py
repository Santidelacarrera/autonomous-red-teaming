"""Independently verify a container image's build-provenance attestation before it is
deployed — the control docs/supply-chain.md calls "provenance is configured, not
validated" until it exists.

This is deliberately *not* part of the job that builds, scans or attests the image
(`.github/workflows/ci.yml``'s `container`/`attest-container` jobs). It re-derives trust
from only two public inputs — the image reference+digest and the GitHub repository that is
supposed to have built it — using GitHub's own `gh attestation verify`, which checks the
Sigstore signature, the attestation's subject digest, and that the attestation was issued by
the named repository's GitHub Actions OIDC identity. A deployment pipeline (or an operator
doing a manual promotion) runs this against the exact digest about to be deployed; a pass
means the bytes it is about to run are provably the bytes that went through CI's scan/SBOM
steps, not a same-tag image substituted afterward.

Usage:

    python scripts/verify_image_provenance.py ghcr.io/OWNER/REPO@sha256:... --repo OWNER/REPO

Exits non-zero (and prints why) on any verification failure — a missing/invalid
attestation, a digest mismatch, or an untrusted issuer. Requires the ``gh`` CLI,
authenticated with a token that can read attestations for the repository (``GH_TOKEN`` or
``GITHUB_TOKEN``).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

_DIGEST_REF = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]*@sha256:[0-9a-f]{64}$")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "image_ref",
        help="Fully-qualified image reference by digest, e.g. ghcr.io/owner/repo@sha256:...",
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="owner/repo expected to have produced the attestation (GitHub Actions OIDC identity)",
    )
    args = parser.parse_args(argv)

    if not _DIGEST_REF.match(args.image_ref):
        print(
            f"Refusing to verify {args.image_ref!r}: a tag is not a stable identity, "
            "pass an image reference pinned by @sha256:<digest>",
            file=sys.stderr,
        )
        return 2

    result = subprocess.run(
        [
            "gh",
            "attestation",
            "verify",
            f"oci://{args.image_ref}",
            "--repo",
            args.repo,
            "--format",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Provenance verification FAILED for {args.image_ref}", file=sys.stderr)
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return result.returncode

    print(f"Provenance verification PASSED for {args.image_ref} (expected repo: {args.repo})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
