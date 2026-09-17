"""Persist one complete technical collection as an immutable observation."""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Callable, Dict

from gambletrace.collectors.evidence import CollectionResult, collect_domain_evidence, serialise_rdap
from gambletrace.persistence import Database
from gambletrace.services.evidence_artifacts import (
    PreparedEvidencePackage,
    discard_prepared_evidence,
    prepare_evidence_package,
)
from gambletrace.services.observations import record_domain_observation
from gambletrace.services.monitoring import evaluate_observation_changes
from utils import normalize_domain


COLLECTOR_VERSION = "evidence-collector/1.0"
LOGGER = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _collection_state(result: CollectionResult) -> tuple[str, str, str]:
    """Translate technical collection results into current operational state."""
    if result.http.status_code is not None:
        if 200 <= result.http.status_code < 500:
            outcome, availability = "SUCCESS", "ACTIVE"
        else:
            outcome, availability = "PARTIAL", "UNKNOWN"
    elif result.ip_addresses or result.dns_records:
        outcome, availability = "PARTIAL", "UNRESOLVED"
    else:
        outcome, availability = "FAILED", "UNRESOLVED"
    error_message = "; ".join(dict.fromkeys(item for item in result.errors if item))
    return outcome, availability, error_message[:2000]


def _get_or_create_ip(connection, address: str) -> str:
    row = connection.execute(
        "SELECT id FROM ip_addresses WHERE address = ?", (address,)
    ).fetchone()
    if row:
        return row["id"]
    ip_id = str(uuid.uuid4())
    connection.execute(
        "INSERT INTO ip_addresses (id, address, version) VALUES (?, ?, ?)",
        (ip_id, address, ipaddress.ip_address(address).version),
    )
    return ip_id


def _get_or_create_asn(connection, capture) -> str | None:
    if not capture.asn_number:
        return None
    row = connection.execute(
        "SELECT id FROM asns WHERE asn_number = ?", (capture.asn_number,)
    ).fetchone()
    if row:
        return row["id"]
    asn_id = str(uuid.uuid4())
    connection.execute(
        """
        INSERT INTO asns (id, asn_number, description, provider_name, country_code, network_cidr)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            asn_id,
            capture.asn_number[:50],
            capture.asn_description[:500],
            capture.provider_name[:500],
            capture.country_code[:10],
            capture.network_cidr[:100],
        ),
    )
    return asn_id


def _get_or_create_tls_certificate(connection, capture) -> str | None:
    """Return the global certificate entity keyed by its DER SHA-256 fingerprint."""
    if not capture.sha256_fingerprint:
        return None
    row = connection.execute(
        "SELECT id FROM tls_certificates WHERE sha256_fingerprint = ?",
        (capture.sha256_fingerprint,),
    ).fetchone()
    if row:
        return row["id"]
    certificate_id = str(uuid.uuid4())
    connection.execute(
        """
        INSERT INTO tls_certificates (
            id, sha256_fingerprint, subject, issuer, serial_number, not_before, not_after
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            certificate_id, capture.sha256_fingerprint[:128], capture.subject[:1000],
            capture.issuer[:1000], capture.serial_number[:300],
            capture.not_before or None, capture.not_after or None,
        ),
    )
    return certificate_id


def _get_or_create_redirect_domain(connection, target_url: str) -> str | None:
    name = normalize_domain(target_url)
    if not name:
        return None
    row = connection.execute(
        "SELECT id FROM domains WHERE canonical_name = ?", (name,)
    ).fetchone()
    if row:
        return row["id"]
    domain_id = str(uuid.uuid4())
    connection.execute(
        "INSERT INTO domains (id, canonical_name, registrable_domain) VALUES (?, ?, ?)",
        (domain_id, name, name),
    )
    return domain_id


def _persist_evidence_artifacts(
    connection, case_id: str, observation_id: str, package: PreparedEvidencePackage
) -> None:
    """Link retained, hashed files and the signed-by-hash manifest to the observation."""
    for artifact in (*package.artifacts, package.manifest):
        connection.execute(
            """
            INSERT INTO evidence_artifacts (
                id, observation_id, artifact_type, stored_path, sha256, size_bytes, mime_type, source_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()), observation_id, artifact.artifact_type,
                artifact.stored_path, artifact.sha256, artifact.size_bytes,
                artifact.mime_type, artifact.source_url,
            ),
        )
    connection.execute(
        """
        INSERT INTO evidence_manifests (
            id, case_id, observation_id, stored_path, sha256, artifact_count, collector_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()), case_id, observation_id,
            package.manifest.stored_path, package.manifest.sha256,
            len(package.artifacts), COLLECTOR_VERSION,
        ),
    )


def _persist_content_fingerprint(connection, observation_id: str, result: CollectionResult) -> None:
    """Store normalised page/favicons and explainable indicator counts."""
    fingerprint = result.http.content_fingerprint
    connection.execute(
        """
        INSERT INTO content_fingerprints (
            id, observation_id, normalized_html_hash, visible_text_hash, favicon_hash, favicon_source_url
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()), observation_id,
            fingerprint.normalized_html_hash, fingerprint.visible_text_hash,
            fingerprint.favicon_hash, fingerprint.favicon_source_url[:2048],
        ),
    )
    for category, indicators in (
        ("GAMBLING", fingerprint.gambling_indicators),
        ("PAYMENT", fingerprint.payment_indicators),
        ("INDIA", fingerprint.india_indicators),
    ):
        for indicator, occurrences in indicators.items():
            connection.execute(
                """
                INSERT INTO content_indicators (id, observation_id, category, indicator, occurrences)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), observation_id, category, indicator[:120], occurrences),
            )


def _persist_collection_details(
    connection,
    case_id: str,
    observation_id: str,
    result: CollectionResult,
    package: PreparedEvidencePackage,
) -> None:
    """Write all structured collector rows in the parent observation transaction."""
    http = result.http
    connection.execute(
        """
        INSERT INTO http_responses (
            id, observation_id, request_url, final_url, status_code,
            response_headers_json, content_type, body_size_bytes, redirect_count,
            collection_error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()), observation_id, http.request_url[:2048],
            http.final_url[:2048], http.status_code,
            json.dumps(http.response_headers, default=str, sort_keys=True),
            http.content_type[:500], max(0, int(http.body_size_bytes)),
            len(http.redirects), http.error[:2000],
        ),
    )
    _persist_content_fingerprint(connection, observation_id, result)

    ip_ids: dict[str, str] = {}
    for address, record_type in result.ip_addresses:
        try:
            ip_id = _get_or_create_ip(connection, address)
        except ValueError:
            continue
        ip_ids[address] = ip_id
        if record_type in {"A", "AAAA"}:
            connection.execute(
                """
                INSERT OR IGNORE INTO observation_ips (observation_id, ip_id, record_type)
                VALUES (?, ?, ?)
                """,
                (observation_id, ip_id, record_type),
            )

    for record in result.dns_records:
        connection.execute(
            """
            INSERT INTO dns_records (id, observation_id, record_type, record_value, ttl)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()), observation_id, record.record_type,
                record.record_value[:2048], record.ttl,
            ),
        )

    for capture in result.rdap_records:
        try:
            ip_id = ip_ids.get(capture.ip_address) or _get_or_create_ip(
                connection, capture.ip_address
            )
        except ValueError:
            continue
        asn_id = _get_or_create_asn(connection, capture)
        if asn_id:
            connection.execute(
                """
                INSERT OR IGNORE INTO observation_asns (observation_id, ip_id, asn_id)
                VALUES (?, ?, ?)
                """,
                (observation_id, ip_id, asn_id),
            )
        connection.execute(
            """
            INSERT INTO rdap_records (
                id, observation_id, ip_id, asn_id, network_name, network_cidr,
                country_code, status, raw_response_json, collection_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()), observation_id, ip_id, asn_id,
                capture.network_name[:500], capture.network_cidr[:100],
                capture.country_code[:10], capture.status[:500],
                serialise_rdap(capture.raw_response), capture.error[:2000],
            ),
        )

    for capture in result.tls_certificates:
        try:
            ip_id = ip_ids.get(capture.ip_address) or _get_or_create_ip(
                connection, capture.ip_address
            )
        except ValueError:
            ip_id = None
        certificate_id = _get_or_create_tls_certificate(connection, capture)
        if certificate_id:
            for name in capture.subject_alt_names:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO certificate_names (id, certificate_id, name)
                    VALUES (?, ?, ?)
                    """,
                    (str(uuid.uuid4()), certificate_id, name[:253]),
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO observation_certificates (observation_id, certificate_id)
                VALUES (?, ?)
                """,
                (observation_id, certificate_id),
            )
        connection.execute(
            """
            INSERT INTO tls_handshakes (
                id, observation_id, ip_id, certificate_id, tls_version, cipher_name, collection_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()), observation_id, ip_id, certificate_id,
                capture.tls_version[:100], capture.cipher_name[:200], capture.error[:2000],
            ),
        )

    for hop in result.http.redirects:
        connection.execute(
            """
            INSERT INTO redirects (
                id, observation_id, hop_number, source_url, status_code, target_url, target_domain_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()), observation_id, hop.hop_number,
                hop.source_url[:2048], hop.status_code, hop.target_url[:2048],
                _get_or_create_redirect_domain(connection, hop.target_url),
            ),
        )

    screenshot = result.screenshot
    retained_screenshot = next(
        (artifact for artifact in package.artifacts if artifact.artifact_type == "SCREENSHOT"),
        None,
    )
    connection.execute(
        """
        INSERT INTO screenshot_captures (
            id, observation_id, stored_path, capture_status, response_status, collection_error
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()), observation_id,
            (retained_screenshot.stored_path if retained_screenshot else screenshot.stored_path)[:2048],
            screenshot.status, screenshot.response_status, screenshot.error[:2000],
        ),
    )
    _persist_evidence_artifacts(connection, case_id, observation_id, package)


def collect_case_domain(
    database: Database,
    case_id: str,
    case_domain_id: str,
    capture_screenshot: bool = False,
    collector: Callable[[str, bool], CollectionResult] = collect_domain_evidence,
    case_storage_dir: str = "",
) -> Dict:
    """Collect and atomically persist technical evidence for one case domain.

    ``collector`` is injectable so collection-to-storage behaviour can be
    verified without contacting external DNS, websites, or registry services.
    """
    with database.connect() as connection:
        row = connection.execute(
            """
            SELECT domains.canonical_name
            FROM case_domains JOIN domains ON domains.id = case_domains.domain_id
            WHERE case_domains.id = ? AND case_domains.case_id = ?
            """,
            (case_domain_id, case_id),
        ).fetchone()
    if not row:
        raise LookupError("Domain is not part of this case")

    if not case_storage_dir:
        raise ValueError("Case evidence storage is not configured")

    result = collector(row["canonical_name"], capture_screenshot)
    outcome, availability, error_message = _collection_state(result)
    observation_id = str(uuid.uuid4())
    observed_at = _utc_now()
    package = prepare_evidence_package(
        case_storage_dir=case_storage_dir,
        case_id=case_id,
        observation_id=observation_id,
        observed_at=observed_at,
        result=result,
        collector_version=COLLECTOR_VERSION,
    )
    try:
        observation = record_domain_observation(
            database,
            case_id=case_id,
            case_domain_id=case_domain_id,
            outcome=outcome,
            availability=availability,
            final_url=result.http.final_url,
            http_status=result.http.status_code,
            page_title=result.http.page_title,
            content_hash=result.http.content_hash,
            favicon_hash=result.http.content_fingerprint.favicon_hash,
            error_message=error_message,
            collector_version=COLLECTOR_VERSION,
            observation_id=observation_id,
            observed_at=observed_at,
            details_writer=lambda connection, written_observation_id: _persist_collection_details(
                connection, case_id, written_observation_id, result, package
            ),
        )
    except Exception:
        discard_prepared_evidence(package)
        raise
    try:
        alerts = evaluate_observation_changes(
            database,
            case_id=case_id,
            case_domain_id=case_domain_id,
            observation_id=observation["id"],
        )
    except Exception:
        # Collection evidence is already safely preserved at this point. A
        # monitoring failure must not invalidate that immutable package.
        LOGGER.exception("Could not evaluate historical changes for observation %s", observation["id"])
        alerts = []
    return {"observation": observation, "result": result, "alerts": alerts}
