"""Read models for domain, evidence, cluster, and timeline workspace views."""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from gambletrace.persistence import Database


def _as_dict(row) -> Optional[Dict]:
    return dict(row) if row else None


def _require_case(connection, case_id: str) -> Dict:
    row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not row:
        raise LookupError("Case not found")
    return dict(row)


def get_case_domain_detail(
    database: Database, case_id: str, case_domain_id: str
) -> Optional[Dict]:
    """Return one domain's retained observations and technical evidence."""
    with database.connect() as connection:
        case = _require_case(connection, case_id)
        row = connection.execute(
            """
            SELECT case_domains.*, domains.canonical_name, domains.registrable_domain,
                   source_files.original_name AS source_file_name
            FROM case_domains
            JOIN domains ON domains.id = case_domains.domain_id
            LEFT JOIN source_files ON source_files.id = case_domains.source_file_id
            WHERE case_domains.id = ? AND case_domains.case_id = ?
            """,
            (case_domain_id, case_id),
        ).fetchone()
        if not row:
            return None
        domain = dict(row)
        domain["case"] = case
        domain["observations"] = [
            dict(item) for item in connection.execute(
                """
                SELECT * FROM domain_observations
                WHERE case_domain_id = ?
                ORDER BY observed_at DESC, id DESC
                LIMIT 50
                """,
                (case_domain_id,),
            ).fetchall()
        ]
        latest_id = domain["observations"][0]["id"] if domain["observations"] else None
        domain["latest_observation"] = domain["observations"][0] if domain["observations"] else None
        domain["artifacts"] = [
            dict(item) for item in connection.execute(
                """
                SELECT evidence_artifacts.*, domain_observations.observed_at
                FROM evidence_artifacts
                JOIN domain_observations ON domain_observations.id = evidence_artifacts.observation_id
                WHERE domain_observations.case_domain_id = ?
                ORDER BY domain_observations.observed_at DESC, evidence_artifacts.artifact_type
                LIMIT 100
                """,
                (case_domain_id,),
            ).fetchall()
        ]
        if not latest_id:
            domain.update(
                http_response=None, dns_records=[], rdap_records=[], tls_certificates=[],
                redirects=[], indicators=[], fingerprint=None,
            )
            return {"case": case, "domain": domain}
        domain["http_response"] = _as_dict(connection.execute(
            "SELECT * FROM http_responses WHERE observation_id = ?", (latest_id,)
        ).fetchone())
        domain["dns_records"] = [
            dict(item) for item in connection.execute(
                """
                SELECT record_type, record_value, ttl FROM dns_records
                WHERE observation_id = ? ORDER BY record_type, record_value
                """,
                (latest_id,),
            ).fetchall()
        ]
        domain["rdap_records"] = [
            dict(item) for item in connection.execute(
                """
                SELECT rdap_records.*, ip_addresses.address, asns.asn_number, asns.provider_name
                FROM rdap_records
                JOIN ip_addresses ON ip_addresses.id = rdap_records.ip_id
                LEFT JOIN asns ON asns.id = rdap_records.asn_id
                WHERE rdap_records.observation_id = ?
                """,
                (latest_id,),
            ).fetchall()
        ]
        domain["tls_certificates"] = [
            dict(item) for item in connection.execute(
                """
                SELECT tls_certificates.*, tls_handshakes.tls_version, tls_handshakes.cipher_name,
                       tls_handshakes.collection_error
                FROM observation_certificates
                JOIN tls_certificates
                    ON tls_certificates.id = observation_certificates.certificate_id
                LEFT JOIN tls_handshakes
                    ON tls_handshakes.observation_id = observation_certificates.observation_id
                    AND tls_handshakes.certificate_id = tls_certificates.id
                WHERE observation_certificates.observation_id = ?
                """,
                (latest_id,),
            ).fetchall()
        ]
        domain["redirects"] = [
            dict(item) for item in connection.execute(
                """
                SELECT * FROM redirects WHERE observation_id = ? ORDER BY hop_number
                """,
                (latest_id,),
            ).fetchall()
        ]
        domain["indicators"] = [
            dict(item) for item in connection.execute(
                """
                SELECT category, indicator, occurrences FROM content_indicators
                WHERE observation_id = ? ORDER BY category, occurrences DESC, indicator
                """,
                (latest_id,),
            ).fetchall()
        ]
        domain["fingerprint"] = _as_dict(connection.execute(
            "SELECT * FROM content_fingerprints WHERE observation_id = ?", (latest_id,)
        ).fetchone())
    return {"case": case, "domain": domain}


def list_case_evidence(database: Database, case_id: str) -> Dict:
    """Return the case evidence register, grouped by artifact type for display."""
    with database.connect() as connection:
        case = _require_case(connection, case_id)
        artifacts = [
            dict(row) for row in connection.execute(
                """
                SELECT evidence_artifacts.*, case_domains.id AS case_domain_id,
                       domains.canonical_name, domain_observations.observed_at
                FROM evidence_artifacts
                JOIN domain_observations ON domain_observations.id = evidence_artifacts.observation_id
                JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
                JOIN domains ON domains.id = case_domains.domain_id
                WHERE case_domains.case_id = ?
                ORDER BY domain_observations.observed_at DESC, evidence_artifacts.artifact_type
                LIMIT 300
                """,
                (case_id,),
            ).fetchall()
        ]
        counts = [
            dict(row) for row in connection.execute(
                """
                SELECT artifact_type, COUNT(*) AS count
                FROM evidence_artifacts
                JOIN domain_observations ON domain_observations.id = evidence_artifacts.observation_id
                JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
                WHERE case_domains.case_id = ?
                GROUP BY artifact_type ORDER BY count DESC, artifact_type
                """,
                (case_id,),
            ).fetchall()
        ]
    return {"case": case, "artifacts": artifacts, "counts": counts}


def get_cluster_detail(database: Database, case_id: str, cluster_id: str) -> Optional[Dict]:
    """Return a cluster's members and the scored edges between those members."""
    with database.connect() as connection:
        case = _require_case(connection, case_id)
        cluster = connection.execute(
            "SELECT * FROM clusters WHERE id = ? AND case_id = ?", (cluster_id, case_id)
        ).fetchone()
        if not cluster:
            return None
        result = dict(cluster)
        result["case"] = case
        result["members"] = [
            dict(row) for row in connection.execute(
                """
                SELECT cluster_members.*, domains.canonical_name, case_domains.risk_score,
                       case_domains.relevance, case_domains.availability
                FROM cluster_members
                LEFT JOIN case_domains
                    ON case_domains.id = cluster_members.entity_id
                    AND cluster_members.entity_type = 'CASE_DOMAIN'
                LEFT JOIN domains ON domains.id = case_domains.domain_id
                WHERE cluster_members.cluster_id = ?
                ORDER BY case_domains.risk_score DESC, domains.canonical_name
                """,
                (cluster_id,),
            ).fetchall()
        ]
        member_ids = [member["entity_id"] for member in result["members"] if member["entity_type"] == "CASE_DOMAIN"]
        result["relationships"] = []
        if len(member_ids) > 1:
            placeholders = ",".join("?" for _ in member_ids)
            rows = connection.execute(
                f"""
                SELECT relationships.*, source_domains.canonical_name AS source_domain,
                       target_domains.canonical_name AS target_domain,
                       COUNT(relationship_evidence.artifact_id) AS evidence_count
                FROM relationships
                LEFT JOIN case_domains AS source_case_domain
                    ON source_case_domain.id = relationships.source_id
                LEFT JOIN domains AS source_domains ON source_domains.id = source_case_domain.domain_id
                LEFT JOIN case_domains AS target_case_domain
                    ON target_case_domain.id = relationships.target_id
                LEFT JOIN domains AS target_domains ON target_domains.id = target_case_domain.domain_id
                LEFT JOIN relationship_evidence ON relationship_evidence.relationship_id = relationships.id
                WHERE relationships.case_id = ?
                  AND relationships.relationship_type = 'CORRELATED_INFRASTRUCTURE'
                  AND relationships.source_id IN ({placeholders})
                  AND relationships.target_id IN ({placeholders})
                GROUP BY relationships.id
                ORDER BY relationships.confidence DESC, relationships.last_seen_at DESC
                """,
                (case_id, *member_ids, *member_ids),
            ).fetchall()
            result["relationships"] = [dict(row) for row in rows]
            for relationship in result["relationships"]:
                try:
                    explanation = json.loads(relationship["explanation"] or "{}")
                except json.JSONDecodeError:
                    explanation = {}
                factors = {
                    factor.get("code"): factor
                    for factor in explanation.get("factors", [])
                    if isinstance(factor, dict) and factor.get("code")
                }
                explanation["signals"] = [
                    factors.get(code, {"code": code, "label": str(code).replace("_", " ").title()})
                    for code in explanation.get("signals", [])
                ]
                relationship["explanation"] = explanation
    return result


def list_case_timeline(database: Database, case_id: str) -> Dict:
    """Return a unified audit and observation chronology for the case."""
    with database.connect() as connection:
        case = _require_case(connection, case_id)
        events = [
            {
                "time": row["created_at"],
                "kind": "CASE_EVENT",
                "title": row["event_type"].replace("_", " ").title(),
                "detail": row["event_data_json"],
            }
            for row in connection.execute(
                """
                SELECT created_at, event_type, event_data_json FROM audit_events
                WHERE case_id = ?
                """,
                (case_id,),
            ).fetchall()
        ]
        events.extend(
            {
                "time": row["observed_at"],
                "kind": "OBSERVATION",
                "title": f"{row['canonical_name']} · {row['outcome']}",
                "detail": f"HTTP {row['http_status'] or '-'} · {row['collector_version'] or 'manual'}",
            }
            for row in connection.execute(
                """
                SELECT domain_observations.*, domains.canonical_name
                FROM domain_observations
                JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
                JOIN domains ON domains.id = case_domains.domain_id
                WHERE case_domains.case_id = ?
                """,
                (case_id,),
            ).fetchall()
        )
    events.sort(key=lambda event: event["time"], reverse=True)
    return {"case": case, "events": events[:150]}
