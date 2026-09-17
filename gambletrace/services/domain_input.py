"""Domain parsing plus case-source preservation for uploaded input files."""

from dataclasses import dataclass
import csv
import hashlib
import logging
import mimetypes
import os
from pathlib import Path
import uuid

from werkzeug.utils import secure_filename

from gambletrace.services.storage_security import restrict_directory, restrict_file
from utils import is_valid_domain, normalize_domain


logger = logging.getLogger(__name__)
ALLOWED_SOURCE_EXTENSIONS = {".csv", ".xlsx", ".xls", ".txt"}


@dataclass(frozen=True)
class StoredSourceUpload:
    """Metadata for an immutable seed file retained under its case directory."""

    id: str
    original_name: str
    absolute_path: str
    stored_path: str
    sha256: str
    size_bytes: int
    mime_type: str


def _add_domain_value(domains: set[str], value) -> None:
    value = str(value).strip() if value is not None else ""
    domain = normalize_domain(value)
    if domain and is_valid_domain(domain):
        domains.add(domain)


def sha256_file(path: str) -> str:
    """Return a SHA-256 digest without loading the complete file into memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_domains_from_path(path: str, original_name: str = "") -> set[str]:
    """Extract normalized domains from an already-saved allowed source file."""
    filename = original_name or os.path.basename(path)
    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_SOURCE_EXTENSIONS:
        raise ValueError("Only CSV, XLSX, XLS, and TXT seed files are supported")

    domains: set[str] = set()
    try:
        if extension in {".xlsx", ".xls"}:
            import openpyxl

            workbook = openpyxl.load_workbook(path, read_only=True, data_only=True)
            for sheet_name in workbook.sheetnames:
                worksheet = workbook[sheet_name]
                if not hasattr(worksheet, "iter_rows"):
                    continue
                for row in worksheet.iter_rows(min_row=1):
                    for cell in row:
                        _add_domain_value(domains, cell.value)
            workbook.close()
        elif extension == ".csv":
            with open(path, "r", encoding="utf-8-sig", newline="") as file_handle:
                for row in csv.reader(file_handle):
                    for value in row:
                        _add_domain_value(domains, value)
        else:
            with open(path, "r", encoding="utf-8", errors="replace") as file_handle:
                for line in file_handle:
                    value = line.strip()
                    if value and not value.startswith("#"):
                        _add_domain_value(domains, value)
    except ImportError as error:
        logger.error("Required Excel parser is not installed: %s", error)
        raise ValueError("Excel support requires openpyxl") from error
    except OSError as error:
        logger.error("Could not read uploaded source %s: %s", filename, error)
        raise ValueError("Could not read the uploaded source file") from error
    except Exception as error:
        logger.error("Could not parse uploaded source %s: %s", filename, error)
        raise ValueError("Could not parse the uploaded source file") from error

    logger.info("Extracted %s domains from uploaded source: %s", len(domains), filename)
    return domains


def store_case_source_upload(file_storage, case_storage_dir: str, case_id: str) -> StoredSourceUpload:
    """Persist an uploaded seed file, then calculate immutable source metadata."""
    original_name = os.path.basename((file_storage.filename or "").strip())
    extension = Path(original_name).suffix.lower()
    if extension not in ALLOWED_SOURCE_EXTENSIONS:
        raise ValueError("Upload a CSV, XLSX, XLS, or TXT seed file")

    safe_name = secure_filename(original_name) or f"seed_upload{extension}"
    source_id = str(uuid.uuid4())
    source_dir = Path(case_storage_dir) / case_id / "sources"
    source_dir.mkdir(parents=True, exist_ok=True)
    restrict_directory(source_dir)
    destination = source_dir / f"{source_id}_{safe_name}"
    file_storage.save(destination)
    restrict_file(destination)

    stored_path = destination.relative_to(Path(case_storage_dir)).as_posix()
    mime_type = file_storage.mimetype or mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
    return StoredSourceUpload(
        id=source_id,
        original_name=original_name,
        absolute_path=str(destination),
        stored_path=stored_path,
        sha256=sha256_file(str(destination)),
        size_bytes=destination.stat().st_size,
        mime_type=mime_type,
    )


def remove_stored_source(source: StoredSourceUpload) -> None:
    """Remove an unrecorded source file after failed validation/parsing."""
    path = Path(source.absolute_path)
    if path.exists():
        path.unlink()


def read_domains_from_upload(file_storage, temp_dir: str) -> set[str]:
    """Compatibility wrapper for non-case dashboard uploads.

    Existing one-off analysis routes parse the file from a temporary location;
    case imports use ``store_case_source_upload`` to retain the original input.
    """
    original_name = os.path.basename((file_storage.filename or "").strip())
    extension = Path(original_name).suffix.lower()
    if extension not in ALLOWED_SOURCE_EXTENSIONS:
        return set()
    temp_path = Path(temp_dir) / f"upload_{uuid.uuid4().hex}{extension}"
    file_storage.save(temp_path)
    try:
        return read_domains_from_path(str(temp_path), original_name)
    finally:
        if temp_path.exists():
            temp_path.unlink()
