"""Generate deterministic SHA-256 evidence for release artifacts."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def digest(path: Path) -> str:
    """Return the SHA-256 digest of one regular file using bounded reads."""
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> None:
    """Write a stable manifest for explicit files under the repository root."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("files", nargs="+", type=Path)
    arguments = parser.parse_args()
    files = sorted(path.resolve() for path in arguments.files)
    missing = [path for path in files if not path.is_file()]
    if missing:
        raise SystemExit("Artifact manifest input is missing")
    repository = Path.cwd().resolve()
    lines: list[str] = []
    for path in files:
        try:
            relative = path.relative_to(repository).as_posix()
        except ValueError as error:
            raise SystemExit("Artifact manifest input must be inside the repository") from error
        lines.append(f"{digest(path)}  {relative}")
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
