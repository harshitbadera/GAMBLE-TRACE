"""Historical evidence comparison and case-scoped change alerts."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, Iterable

from gambletrace.persistence import Database


def _compact(values: Iterable[str]) -> str:
    """Store a bounded, deterministic comparison value in the alert record."""
    return json.dumps(sorted(set(item for item in values if item)), separators=(",", ":"))[:1900]


def _values(connection, observation_id: str, kind: str) -> set[str]:
    queries = {
        "DNS": """
            SELECT record_type || ':' || lower(record_value) AS value FROM dns_records
            WHERE observation_id = ? AND record_type IN ('A', 'AAAA', 'CNAME', 'NS')
        """,
        "TLS": """
            SELECT tls_certificates.sha256_fingerprint AS value
            FROM observation_certificates
            JOIN tls_certificates ON tls_certificates.id = observation_certificates.certificate_id
            WHERE observation_certificates.observation_id = ?
        """,
        "REDIRECT": """
            SELECT target_url AS value FROM redirects WHERE observation_id = ?
            UNION SELECT final_url AS value FROM http_responses WHERE observation_id = ?
        """,
        "CONTENT": """
            SELECT normalized_html_hash AS value FROM content_fingerprints WHERE observation_id = ?
            UNION SELECT favicon_hash AS value FROM content_fingerprints WHERE observation_id = ?
        """,
        "HOSTING": """
            SELECT COALESCE(asns.asn_number, '') || ':' || COALESCE(asns.provider_name, '') || ':' || COALESCE(rdap_records.network_cidr, '') AS value
            FROM rdap_records
            LEFT JOIN asns ON asns.id = rdap_records.asn_id
            WHERE rdap_records.observation_id = ?
        """,
    }
    parameters = (observation_id, observation_id) if kind in {"REDIRECT", "CONTENT"} else (observation_id,)
    return {str(row["value"] or "") for row in connection.execute(queries[kind], parameters).fetchall() if row["value"]}


CHANGE_DEFINITIONS = (
    ("DNS", "DNS_INFRASTRUCTURE_CHANGE", "MEDIUM", "DNS infrastructure changed"),
    ("TLS", "TLS_CERTIFICATE_CHANGE", "MEDIUM", "TLS certificate fingerprint changed"),
    ("REDIRECT", "REDIRECT_DESTINATION_CHANGE", "HIGH", "Redirect destination changed"),
    ("CONTENT", "CONTENT_FINGERPRINT_CHANGE", "MEDIUM", "Captured content fingerprint changed"),
    ("HOSTING", "HOSTING_ASN_CHANGE", "MEDIUM", "Hosting or ASN evidence changed"),
)


def evaluate_observation_changes(
    database: Database,
    *,
    case_id: str,
    case_domain_id: str,
    observation_id: str,
) -> list[Dict[str, Any]]:
    """Compare one completed snapshot to its predecessor and persist alerts.

    The first observation establishes a baseline. Empty-to-empty values do not
    generate noise; an empty/non-empty transition is retained because it can
    indicate collection loss, a takedown, or infrastructure mutation.
    """
    with database.connect() as connection:
        current = connection.execute(
            """
            SELECT id, observed_at, availability FROM domain_observations
            WHERE id = ? AND case_domain_id = ?
            """,
            (observation_id, case_domain_id),
        ).fetchone()
        if not current:
            raise LookupError("Observation is not part of this case domain")
        case_member = connection.execute(
            "SELECT 1 FROM case_domains WHERE id = ? AND case_id = ?",
            (case_domain_id, case_id),
        ).fetchone()
        if not case_member:
            raise LookupError("Domain is not part of this case")
        previous = connection.execute(
            """
            SELECT id, observed_at, availability FROM domain_observations
            WHERE case_domain_id = ? AND id <> ?
            ORDER BY observed_at DESC, id DESC LIMIT 1
            """,
            (case_domain_id, observation_id),
        ).fetchone()
        if not previous:
            return []

        changes: list[Dict[str, Any]] = []
        for kind, alert_type, severity, summary in CHANGE_DEFINITIONS:
            before, after = _values(connection, previous["id"], kind), _values(connection, observation_id, kind)
            if before == after:
                continue
            changes.append({
                "alert_type": alert_type,
                "severity": severity,
                "summary": summary,
                "previous_value": _compact(before),
                "current_value": _compact(after),
            })

        if previous["availability"] != current["availability"]:
            changes.append({
                "alert_type": "AVAILABILITY_CHANGE",
                "severity": "HIGH" if current["availability"] in {"OFFLINE", "BLOCKED"} else "MEDIUM",
                "summary": f"Availability changed from {previous['availability']} to {current['availability']}",
                "previous_value": previous["availability"],
                "current_value": current["availability"],
            })

        for change in changes:
            alert_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO alerts (
                    id, case_id, case_domain_id, alert_type, severity, summary,
                    previous_value, current_value
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id, case_id, case_domain_id, change["alert_type"],
                    change["severity"], change["summary"], change["previous_value"],
                    change["current_value"],
                ),
            )
            connection.execute(
                """
                INSERT INTO audit_events (id, case_id, event_type, event_data_json)
                VALUES (?, ?, 'MONITORING_ALERT_CREATED', ?)
                """,
                (str(uuid.uuid4()), case_id, json.dumps({
                    "alert_id": alert_id, "case_domain_id": case_domain_id,
                    "alert_type": change["alert_type"], "severity": change["severity"],
                }, sort_keys=True)),
            )
            change["id"] = alert_id
        return changes


def list_case_alerts(database: Database, case_id: str, limit: int = 100) -> list[Dict[str, Any]]:
    """Return alert history with domain context, newest first."""
    with database.connect() as connection:
        rows = connection.execute(
            """
            SELECT alerts.*, domains.canonical_name
            FROM alerts
            LEFT JOIN case_domains ON case_domains.id = alerts.case_domain_id
            LEFT JOIN domains ON domains.id = case_domains.domain_id
            WHERE alerts.case_id = ?
            ORDER BY CASE alerts.status WHEN 'OPEN' THEN 0 WHEN 'ACKNOWLEDGED' THEN 1 ELSE 2 END,
                     alerts.created_at DESC
            LIMIT ?
            """,
            (case_id, max(1, min(int(limit), 250))),
        ).fetchall()
    return [dict(row) for row in rows]


def update_alert_status(database: Database, case_id: str, alert_id: str, status: str) -> None:
    """Acknowledge or resolve a case-owned monitoring alert."""
    if status not in {"ACKNOWLEDGED", "RESOLVED"}:
        raise ValueError("Invalid alert status")
    with database.connect() as connection:
        row = connection.execute(
            "SELECT id FROM alerts WHERE id = ? AND case_id = ?", (alert_id, case_id)
        ).fetchone()
        if not row:
            raise LookupError("Alert not found in this case")
        connection.execute(
            """
            UPDATE alerts
            SET status = ?, acknowledged_at = CASE WHEN ? = 'ACKNOWLEDGED' THEN CURRENT_TIMESTAMP ELSE acknowledged_at END
            WHERE id = ?
            """,
            (status, status, alert_id),
        )
        connection.execute(
            """
            INSERT INTO audit_events (id, case_id, event_type, event_data_json)
            VALUES (?, ?, 'MONITORING_ALERT_STATUS_CHANGED', ?)
            """,
            (str(uuid.uuid4()), case_id, json.dumps({"alert_id": alert_id, "status": status})),
        )
