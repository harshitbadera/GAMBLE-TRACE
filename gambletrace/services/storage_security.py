"""Best-effort restrictive permissions for case evidence and generated exports."""

from __future__ import annotations

import os
from pathlib import Path


def restrict_directory(path: str | Path) -> None:
    """Limit a case directory to its owner where the platform supports POSIX modes."""
    try:
        os.chmod(Path(path), 0o700)
    except OSError:
        # Windows ACLs are deployment-managed; do not fail evidence preservation
        # merely because chmod does not map to an ACL policy there.
        pass


def restrict_file(path: str | Path) -> None:
    """Limit a retained file to its owner where the platform supports POSIX modes."""
    try:
        os.chmod(Path(path), 0o600)
    except OSError:
        pass
