"""Temporary download artifact helpers for the current dashboard."""

import csv
import os
import uuid
from typing import Optional, Tuple


CSV_PREFIXES = ("expanded_", "lookup_", "pivot_", "content_")


def write_download_csv(temp_dir: str, prefix: str, fieldnames: list[str], rows: list[dict]) -> str:
    """Write a dashboard CSV and return its opaque download identifier."""
    download_id = uuid.uuid4().hex[:8]
    path = os.path.join(temp_dir, f"{prefix}{download_id}.csv")
    with open(path, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(file_handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return download_id


def find_download_csv(temp_dir: str, download_id: str) -> Optional[Tuple[str, str]]:
    """Return the existing temporary CSV path and filename for an identifier."""
    for prefix in CSV_PREFIXES:
        filename = f"{prefix}{download_id}.csv"
        path = os.path.join(temp_dir, filename)
        if os.path.exists(path):
            return path, filename
    return None
