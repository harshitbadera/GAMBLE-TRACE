"""Case evidence-package creation, hashing, manifesting, and verification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Any

from gambletrace.collectors.evidence import CollectionResult, serialise_rdap
from gambletrace.services.domain_input import sha256_file
from gambletrace.services.storage_security import restrict_directory, restrict_file


MANIFEST_VERSION = "1.0"


@dataclass(frozen=True)
class PreparedArtifact:
    """A retained file and its immutable acquisition metadata."""

    artifact_type: str
    absolute_path: str
    stored_path: str
    sha256: str
    size_bytes: int
    mime_type: str
    source_url: str = ""


@dataclass(frozen=True)
class PreparedEvidencePackage:
    """Files to record as part of one evidence observation transaction."""

    evidence_dir: str
    manifest: PreparedArtifact
    artifacts: tuple[PreparedArtifact, ...]


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, default=str, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _case_relative_path(case_storage_dir: str, path: Path) -> str:
    return path.relative_to(Path(case_storage_dir)).as_posix()


def _write_artifact(
    evidence_dir: Path,
    case_storage_dir: str,
    filename: str,
    content: bytes,
    artifact_type: str,
    mime_type: str,
    source_url: str = "",
) -> PreparedArtifact:
    """Write one newly acquired file and return its exact hash metadata."""
    destination = evidence_dir / filename
    destination.write_bytes(content)
    restrict_file(destination)
    return PreparedArtifact(
        artifact_type=artifact_type,
        absolute_path=str(destination),
        stored_path=_case_relative_path(case_storage_dir, destination),
        sha256=_sha256_bytes(content),
        size_bytes=len(content),
        mime_type=mime_type,
        source_url=source_url,
    )


def _screenshot_artifact(
    evidence_dir: Path,
    case_storage_dir: str,
    screenshot_path: str,
    source_url: str,
) -> PreparedArtifact | None:
    """Copy the optional browser image into immutable case-specific storage."""
    source = Path(screenshot_path)
    if not screenshot_path or not source.is_file():
        return None
    destination = evidence_dir / "screenshot.png"
    shutil.copyfile(source, destination)
    restrict_file(destination)
    return PreparedArtifact(
        artifact_type="SCREENSHOT",
        absolute_path=str(destination),
        stored_path=_case_relative_path(case_storage_dir, destination),
        sha256=sha256_file(str(destination)),
        size_bytes=destination.stat().st_size,
        mime_type="image/png",
        source_url=source_url,
    )


def prepare_evidence_package(
    case_storage_dir: str,
    case_id: str,
    observation_id: str,
    observed_at: str,
    result: CollectionResult,
    collector_version: str,
) -> PreparedEvidencePackage:
    """Materialise collected results under ``case/evidence/observation``.

    All files are written before their hashes and metadata are inserted into
    SQLite. The caller records that metadata in the same transaction as the
    immutable observation.
    """
    evidence_dir = Path(case_storage_dir) / case_id / "evidence" / observation_id
    evidence_dir.mkdir(parents=True, exist_ok=False)
    restrict_directory(evidence_dir)
    artifacts: list[PreparedArtifact] = []
    http = result.http
    source_url = http.final_url or http.request_url

    acquisition = {
        "schema_version": MANIFEST_VERSION,
        "case_id": case_id,
        "observation_id": observation_id,
        "domain": result.domain,
        "observed_at": observed_at,
        "collector_version": collector_version,
        "collection_errors": result.errors,
    }
    artifacts.append(
        _write_artifact(
            evidence_dir, case_storage_dir, "acquisition.json", _json_bytes(acquisition),
            "ACQUISITION_METADATA", "application/json", source_url,
        )
    )
    headers = {
        "request_url": http.request_url,
        "final_url": http.final_url,
        "status_code": http.status_code,
        "content_type": http.content_type,
        "body_size_bytes": http.body_size_bytes,
        "response_headers": http.response_headers,
        "collection_error": http.error,
    }
    artifacts.append(
        _write_artifact(
            evidence_dir, case_storage_dir, "http_headers.json", _json_bytes(headers),
            "HTTP_HEADERS", "application/json", source_url,
        )
    )
    fingerprint = http.content_fingerprint
    content_fingerprint = {
        "normalized_html_hash": fingerprint.normalized_html_hash,
        "visible_text_hash": fingerprint.visible_text_hash,
        "favicon_hash": fingerprint.favicon_hash,
        "favicon_source_url": fingerprint.favicon_source_url,
        "gambling_indicators": fingerprint.gambling_indicators,
        "payment_indicators": fingerprint.payment_indicators,
        "india_indicators": fingerprint.india_indicators,
    }
    artifacts.append(
        _write_artifact(
            evidence_dir, case_storage_dir, "content_fingerprint.json", _json_bytes(content_fingerprint),
            "CONTENT_FINGERPRINT", "application/json", source_url,
        )
    )
    redirects = [
        {
            "hop_number": hop.hop_number,
            "source_url": hop.source_url,
            "status_code": hop.status_code,
            "target_url": hop.target_url,
        }
        for hop in http.redirects
    ]
    artifacts.append(
        _write_artifact(
            evidence_dir, case_storage_dir, "redirect_chain.json", _json_bytes(redirects),
            "REDIRECT_CHAIN", "application/json", source_url,
        )
    )
    dns_records = [
        {"record_type": record.record_type, "record_value": record.record_value, "ttl": record.ttl}
        for record in result.dns_records
    ]
    artifacts.append(
        _write_artifact(
            evidence_dir, case_storage_dir, "dns_records.json", _json_bytes(dns_records),
            "DNS_RECORDS", "application/json", source_url,
        )
    )
    rdap_records = [
        {
            "ip_address": capture.ip_address,
            "asn_number": capture.asn_number,
            "asn_description": capture.asn_description,
            "provider_name": capture.provider_name,
            "country_code": capture.country_code,
            "network_name": capture.network_name,
            "network_cidr": capture.network_cidr,
            "status": capture.status,
            "raw_response": json.loads(serialise_rdap(capture.raw_response)),
            "collection_error": capture.error,
        }
        for capture in result.rdap_records
    ]
    artifacts.append(
        _write_artifact(
            evidence_dir, case_storage_dir, "rdap_records.json", _json_bytes(rdap_records),
            "RDAP_RESPONSE", "application/json", source_url,
        )
    )
    tls_certificates = [
        {
            "ip_address": capture.ip_address,
            "sha256_fingerprint": capture.sha256_fingerprint,
            "subject": capture.subject,
            "issuer": capture.issuer,
            "serial_number": capture.serial_number,
            "not_before": capture.not_before,
            "not_after": capture.not_after,
            "subject_alt_names": capture.subject_alt_names,
            "tls_version": capture.tls_version,
            "cipher_name": capture.cipher_name,
            "collection_error": capture.error,
        }
        for capture in result.tls_certificates
    ]
    artifacts.append(
        _write_artifact(
            evidence_dir, case_storage_dir, "tls_certificates.json", _json_bytes(tls_certificates),
            "TLS_CERTIFICATE_METADATA", "application/json", source_url,
        )
    )
    for index, capture in enumerate(result.tls_certificates, start=1):
        if capture.certificate_der:
            artifacts.append(
                _write_artifact(
                    evidence_dir,
                    case_storage_dir,
                    f"tls_certificate_{index:02d}.der",
                    capture.certificate_der,
                    "TLS_CERTIFICATE_DER",
                    "application/pkix-cert",
                    source_url,
                )
            )
    if http.body and "html" in http.content_type.lower():
        artifacts.append(
            _write_artifact(
                evidence_dir, case_storage_dir, "page.html", http.body,
                "HTML_SNAPSHOT", "text/html", source_url,
            )
        )
    if fingerprint.favicon_bytes:
        artifacts.append(
            _write_artifact(
                evidence_dir, case_storage_dir, "favicon.bin", fingerprint.favicon_bytes,
                "FAVICON", fingerprint.favicon_mime_type or "application/octet-stream",
                fingerprint.favicon_source_url,
            )
        )
    screenshot = _screenshot_artifact(
        evidence_dir, case_storage_dir, result.screenshot.stored_path, source_url
    )
    if screenshot:
        artifacts.append(screenshot)

    manifest_payload = {
        "manifest_version": MANIFEST_VERSION,
        "case_id": case_id,
        "observation_id": observation_id,
        "domain": result.domain,
        "observed_at": observed_at,
        "collector_version": collector_version,
        "artifact_count": len(artifacts),
        "artifacts": [
            {
                "artifact_type": artifact.artifact_type,
                "stored_path": artifact.stored_path,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
                "mime_type": artifact.mime_type,
                "source_url": artifact.source_url,
            }
            for artifact in artifacts
        ],
    }
    manifest = _write_artifact(
        evidence_dir, case_storage_dir, "artifact_manifest.json", _json_bytes(manifest_payload),
        "EVIDENCE_MANIFEST", "application/json", source_url,
    )
    return PreparedEvidencePackage(str(evidence_dir), manifest, tuple(artifacts))


def discard_prepared_evidence(package: PreparedEvidencePackage) -> None:
    """Remove an unrecorded, failed evidence package with its unique directory."""
    directory = Path(package.evidence_dir)
    if directory.is_dir():
        shutil.rmtree(directory)


def verify_evidence_package(case_storage_dir: str, artifacts: list[dict]) -> dict[str, list[str]]:
    """Re-hash stored artifacts and return missing or altered paths."""
    base = Path(case_storage_dir).resolve()
    missing: list[str] = []
    altered: list[str] = []
    for artifact in artifacts:
        path = (base / artifact["stored_path"]).resolve()
        if base not in path.parents or not path.is_file():
            missing.append(artifact["stored_path"])
        elif sha256_file(str(path)) != artifact["sha256"]:
            altered.append(artifact["stored_path"])
    return {"missing": missing, "altered": altered}
