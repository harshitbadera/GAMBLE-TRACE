"""Conservative cleanup for generated exports and temporary dashboard files."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict


def _expired(path: Path, cutoff: datetime) -> bool:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc) < cutoff


def _files_under(root: Path):
    if not root.is_dir():
        return
    for candidate in root.rglob("*"):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if root not in resolved.parents:
            continue
        yield candidate


def cleanup_generated_files(
    *,
    case_storage_dir: str,
    temp_dir: str,
    export_retention_days: int,
    temp_retention_days: int,
    apply: bool = False,
) -> Dict[str, int]:
    """Find or remove expired generated files, never immutable evidence/source files.

    Only `exports` folders below a case directory and the configured temporary
    directory are eligible. The caller must explicitly set ``apply=True`` to
    delete anything.
    """
    now = datetime.now(timezone.utc)
    roots = (
        (Path(case_storage_dir).resolve(), "exports", max(0, int(export_retention_days))),
        (Path(temp_dir).resolve(), None, max(0, int(temp_retention_days))),
    )
    summary = {"candidates": 0, "removed": 0, "bytes": 0}
    for root, required_parent_name, days in roots:
        cutoff = now - timedelta(days=days)
        for file_path in _files_under(root) or ():
            if required_parent_name and required_parent_name not in {parent.name for parent in file_path.parents}:
                continue
            if not _expired(file_path, cutoff):
                continue
            summary["candidates"] += 1
            summary["bytes"] += file_path.stat().st_size
            if apply:
                file_path.unlink()
                summary["removed"] += 1
    return summary
