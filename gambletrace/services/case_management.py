"""Case, seed-domain, note, tag, and audit-log persistence services."""

from datetime import datetime, timezone
import json
import re
import uuid
from typing import Dict, List, Optional, Tuple

from gambletrace.models.contracts import CaseStatus
from gambletrace.persistence import Database
from gambletrace.services.domain_input import StoredSourceUpload
from gambletrace.services.observations import list_recent_observations


TAG_COLOR_PATTERN = re.compile(r"^#[0-9a-fA-F]{6}$")


def _row_to_dict(row) -> Optional[Dict]:
    return dict(row) if row else None


def _record_audit_event(connection, case_id: str, event_type: str, event_data: str = "{}") -> None:
    connection.execute(
        """
        INSERT INTO audit_events (id, case_id, event_type, event_data_json)
        VALUES (?, ?, ?, ?)
        """,
        (str(uuid.uuid4()), case_id, event_type, event_data),
    )


def _require_case(connection, case_id: str) -> None:
    """Raise a stable application error when a case ID does not exist."""
    if not connection.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone():
        raise LookupError("Case not found")


def _case_number(connection) -> str:
    year = datetime.now(timezone.utc).year
    prefix = f"GT-{year}-"
    count = connection.execute(
        "SELECT COUNT(*) FROM cases WHERE case_number LIKE ?", (f"{prefix}%",)
    ).fetchone()[0]
    return f"{prefix}{count + 1:03d}"


def create_case(
    database: Database,
    title: str,
    description: str = "",
    owner_name: str = "",
    priority: str = "MEDIUM",
    scope_note: str = "",
    authorization_note: str = "",
) -> Dict:
    """Create an open case and its first audit event."""
    title = title.strip()
    if not title:
        raise ValueError("Case title is required")
    if priority not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValueError("Invalid case priority")

    case_id = str(uuid.uuid4())
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        case_number = _case_number(connection)
        connection.execute(
            """
            INSERT INTO cases (
                id, case_number, title, description, status, priority, owner_name,
                scope_note, authorization_note
            ) VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?)
            """,
            (
                case_id, case_number, title, description.strip(), priority,
                owner_name.strip(), scope_note.strip(), authorization_note.strip(),
            ),
        )
        _record_audit_event(connection, case_id, "CASE_CREATED")
        row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    return dict(row)


def list_cases(database: Database) -> List[Dict]:
    """Return cases with compact domain, note, and alert counts."""
    with database.connect() as connection:
        rows = connection.execute(
            """
            SELECT
                cases.*,
                COUNT(DISTINCT case_domains.id) AS domain_count,
                COUNT(DISTINCT case_notes.id) AS note_count,
                COUNT(DISTINCT CASE WHEN alerts.status = 'OPEN' THEN alerts.id END) AS open_alert_count
            FROM cases
            LEFT JOIN case_domains ON case_domains.case_id = cases.id
            LEFT JOIN case_notes ON case_notes.case_id = cases.id
            LEFT JOIN alerts ON alerts.case_id = cases.id
            GROUP BY cases.id
            ORDER BY cases.updated_at DESC, cases.created_at DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def case_dashboard_summary(database: Database) -> Dict:
    """Return top-level counts for the case workspace."""
    with database.connect() as connection:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total_cases,
                SUM(CASE WHEN status IN ('OPEN', 'COLLECTING', 'TRIAGE') THEN 1 ELSE 0 END) AS active_cases,
                SUM(CASE WHEN status = 'MONITORING' THEN 1 ELSE 0 END) AS monitoring_cases,
                SUM(CASE WHEN status = 'ESCALATED' THEN 1 ELSE 0 END) AS escalated_cases
            FROM cases
            """
        ).fetchone()
    return {key: int(row[key] or 0) for key in row.keys()}


def get_case(database: Database, case_id: str) -> Optional[Dict]:
    """Return a case with its dashboard counters, tags, notes, and recent activity."""
    with database.connect() as connection:
        case = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not case:
            return None
        result = dict(case)
        counts = connection.execute(
            """
            SELECT
                COUNT(*) AS domain_count,
                SUM(CASE WHEN availability = 'ACTIVE' THEN 1 ELSE 0 END) AS active_domain_count,
                SUM(CASE WHEN relevance = 'HIGH_CONFIDENCE_SUSPECTED_GAMBLING' THEN 1 ELSE 0 END) AS high_confidence_count
            FROM case_domains WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()
        result.update({key: int(counts[key] or 0) for key in counts.keys()})
        result["observation_count"] = connection.execute(
            """
            SELECT COUNT(*) FROM domain_observations
            JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
            WHERE case_domains.case_id = ?
            """,
            (case_id,),
        ).fetchone()[0]
        result["alerts"] = [dict(row) for row in connection.execute(
            """
            SELECT alerts.*, domains.canonical_name
            FROM alerts
            LEFT JOIN case_domains ON case_domains.id = alerts.case_domain_id
            LEFT JOIN domains ON domains.id = case_domains.domain_id
            WHERE alerts.case_id = ?
            ORDER BY CASE alerts.status WHEN 'OPEN' THEN 0 WHEN 'ACKNOWLEDGED' THEN 1 ELSE 2 END,
                     alerts.created_at DESC
            LIMIT 12
            """,
            (case_id,),
        ).fetchall()]
        result["open_alert_count"] = connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE case_id = ? AND status = 'OPEN'", (case_id,)
        ).fetchone()[0]
        result["tags"] = [dict(row) for row in connection.execute(
            """
            SELECT tags.* FROM tags
            JOIN case_tags ON case_tags.tag_id = tags.id
            WHERE case_tags.case_id = ? ORDER BY tags.name
            """,
            (case_id,),
        ).fetchall()]
        result["notes"] = [dict(row) for row in connection.execute(
            "SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at DESC",
            (case_id,),
        ).fetchall()]
        result["source_files"] = [dict(row) for row in connection.execute(
            """
            SELECT * FROM source_files WHERE case_id = ?
            ORDER BY imported_at DESC
            """,
            (case_id,),
        ).fetchall()]
        result["domains"] = [dict(row) for row in connection.execute(
            """
            SELECT case_domains.*, domains.canonical_name, domains.registrable_domain,
                   source_files.original_name AS source_file_name,
                   source_files.sha256 AS source_file_sha256,
                   latest_observation.outcome AS latest_outcome,
                   latest_observation.observed_at AS latest_observed_at,
                   latest_observation.http_status AS latest_http_status
            FROM case_domains
            JOIN domains ON domains.id = case_domains.domain_id
            LEFT JOIN source_files ON source_files.id = case_domains.source_file_id
            LEFT JOIN domain_observations AS latest_observation
                ON latest_observation.id = (
                    SELECT observation.id FROM domain_observations AS observation
                    WHERE observation.case_domain_id = case_domains.id
                    ORDER BY observation.observed_at DESC, observation.id DESC LIMIT 1
                )
            WHERE case_domains.case_id = ?
            ORDER BY case_domains.first_seen_at DESC, domains.canonical_name
            LIMIT 100
            """,
            (case_id,),
        ).fetchall()]
        result["recent_observations"] = list_recent_observations(database, case_id)
        result["certificate_pivots"] = [dict(row) for row in connection.execute(
            """
            SELECT
                tls_certificates.sha256_fingerprint,
                tls_certificates.subject,
                tls_certificates.issuer,
                tls_certificates.not_after,
                COUNT(DISTINCT case_domains.id) AS domain_count,
                GROUP_CONCAT(DISTINCT domains.canonical_name) AS related_domains
            FROM tls_certificates
            JOIN observation_certificates
                ON observation_certificates.certificate_id = tls_certificates.id
            JOIN domain_observations
                ON domain_observations.id = observation_certificates.observation_id
            JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
            JOIN domains ON domains.id = case_domains.domain_id
            WHERE case_domains.case_id = ?
            GROUP BY tls_certificates.id
            ORDER BY domain_count DESC, tls_certificates.not_after ASC
            LIMIT 20
            """,
            (case_id,),
        ).fetchall()]
        result["content_indicator_summary"] = [dict(row) for row in connection.execute(
            """
            SELECT
                content_indicators.category,
                content_indicators.indicator,
                SUM(content_indicators.occurrences) AS total_occurrences,
                COUNT(DISTINCT case_domains.id) AS domain_count
            FROM content_indicators
            JOIN domain_observations ON domain_observations.id = content_indicators.observation_id
            JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
            WHERE case_domains.case_id = ?
            GROUP BY content_indicators.category, content_indicators.indicator
            ORDER BY domain_count DESC, total_occurrences DESC, content_indicators.category, content_indicators.indicator
            LIMIT 15
            """,
            (case_id,),
        ).fetchall()]
        result["risk_assessments"] = [dict(row) for row in connection.execute(
            """
            SELECT risk_assessments.*, domains.canonical_name
            FROM risk_assessments
            JOIN case_domains ON case_domains.id = risk_assessments.case_domain_id
            JOIN domains ON domains.id = case_domains.domain_id
            WHERE risk_assessments.case_id = ?
              AND risk_assessments.id = (
                SELECT latest.id FROM risk_assessments AS latest
                WHERE latest.case_domain_id = risk_assessments.case_domain_id
                ORDER BY latest.assessed_at DESC, latest.id DESC LIMIT 1
              )
            ORDER BY risk_assessments.score DESC, domains.canonical_name
            LIMIT 12
            """,
            (case_id,),
        ).fetchall()]
        for assessment in result["risk_assessments"]:
            assessment["factors"] = json.loads(assessment.pop("factors_json"))
        result["clusters"] = [dict(row) for row in connection.execute(
            """
            SELECT
                clusters.*,
                COUNT(cluster_members.id) AS member_count,
                GROUP_CONCAT(domains.canonical_name) AS member_domains
            FROM clusters
            LEFT JOIN cluster_members ON cluster_members.cluster_id = clusters.id
                AND cluster_members.entity_type = 'CASE_DOMAIN'
            LEFT JOIN case_domains ON case_domains.id = cluster_members.entity_id
            LEFT JOIN domains ON domains.id = case_domains.domain_id
            WHERE clusters.case_id = ?
            GROUP BY clusters.id
            ORDER BY clusters.last_seen_at DESC, clusters.created_at DESC
            LIMIT 12
            """,
            (case_id,),
        ).fetchall()]
        result["relationship_summary"] = {
            row["confidence"]: int(row["count"])
            for row in connection.execute(
                """
                SELECT confidence, COUNT(*) AS count
                FROM relationships
                WHERE case_id = ? AND relationship_type = 'CORRELATED_INFRASTRUCTURE'
                GROUP BY confidence
                """,
                (case_id,),
            ).fetchall()
        }
        result["activity"] = [dict(row) for row in connection.execute(
            "SELECT * FROM audit_events WHERE case_id = ? ORDER BY created_at DESC LIMIT 12",
            (case_id,),
        ).fetchall()]
    return result


def _link_seed_domains(
    connection, case_id: str, domains: set[str], source_detail: str = "", source_file_id: Optional[str] = None
) -> int:
    """Link normalized seed domains to a case inside an existing transaction."""
    added = 0
    for domain_name in sorted(domains):
        row = connection.execute(
            "SELECT id FROM domains WHERE canonical_name = ?", (domain_name,)
        ).fetchone()
        domain_id = row[0] if row else str(uuid.uuid4())
        if not row:
            connection.execute(
                """
                INSERT INTO domains (id, canonical_name, registrable_domain)
                VALUES (?, ?, ?)
                """,
                (domain_id, domain_name, domain_name),
            )
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO case_domains (
                id, case_id, domain_id, source_type, source_detail, source_file_id
            ) VALUES (?, ?, ?, 'SEED', ?, ?)
            """,
            (str(uuid.uuid4()), case_id, domain_id, source_detail[:500], source_file_id),
        )
        added += cursor.rowcount
    return added


def add_seed_domains(
    database: Database, case_id: str, domains: set[str], source_detail: str = ""
) -> Tuple[int, int]:
    """Add normalized domains to a case as seeds without a retained file source."""
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _require_case(connection, case_id)
        added = _link_seed_domains(connection, case_id, domains, source_detail)
        _record_audit_event(
            connection, case_id, "SEEDS_IMPORTED",
            json.dumps({"submitted_domains": len(domains), "new_case_domains": added}),
        )
    return added, len(domains)


def import_seed_source(
    database: Database, case_id: str, source: StoredSourceUpload, domains: set[str]
) -> Tuple[int, int]:
    """Record a retained source file and link its normalized seed domains atomically."""
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _require_case(connection, case_id)
        connection.execute(
            """
            INSERT INTO source_files (
                id, case_id, original_name, stored_path, sha256, size_bytes, mime_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source.id, case_id, source.original_name, source.stored_path,
                source.sha256, source.size_bytes, source.mime_type,
            ),
        )
        added = _link_seed_domains(
            connection, case_id, domains, source.original_name, source.id
        )
        _record_audit_event(
            connection, case_id, "SEED_SOURCE_IMPORTED",
            json.dumps({
                "source_file_id": source.id,
                "source_file": source.original_name,
                "sha256": source.sha256,
                "submitted_domains": len(domains),
                "new_case_domains": added,
            }),
        )
    return added, len(domains)


def add_case_note(database: Database, case_id: str, body: str, author_name: str = "") -> None:
    """Add an analyst note to an existing case."""
    body = body.strip()
    if not body:
        raise ValueError("Note cannot be empty")
    with database.connect() as connection:
        _require_case(connection, case_id)
        connection.execute(
            "INSERT INTO case_notes (id, case_id, body, author_name) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), case_id, body, author_name.strip()),
        )
        _record_audit_event(connection, case_id, "NOTE_ADDED")


def add_case_tag(database: Database, case_id: str, tag_name: str, color: str = "#64748b") -> None:
    """Create or reuse a tag, then attach it to a case."""
    tag_name = tag_name.strip().lower()
    if not tag_name:
        raise ValueError("Tag name is required")
    if not TAG_COLOR_PATTERN.match(color):
        color = "#64748b"
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _require_case(connection, case_id)
        row = connection.execute("SELECT id FROM tags WHERE name = ?", (tag_name,)).fetchone()
        tag_id = row[0] if row else str(uuid.uuid4())
        if not row:
            connection.execute(
                "INSERT INTO tags (id, name, color) VALUES (?, ?, ?)",
                (tag_id, tag_name, color),
            )
        connection.execute(
            "INSERT OR IGNORE INTO case_tags (case_id, tag_id) VALUES (?, ?)",
            (case_id, tag_id),
        )
        _record_audit_event(connection, case_id, "TAG_ADDED", '{"tag": "%s"}' % tag_name)


def update_case_status(database: Database, case_id: str, status: str) -> None:
    """Update a case workflow status and record its change."""
    valid_statuses = {item.value for item in CaseStatus}
    if status not in valid_statuses:
        raise ValueError("Invalid case status")
    with database.connect() as connection:
        current = connection.execute("SELECT status FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not current:
            raise LookupError("Case not found")
        connection.execute(
            """
            UPDATE cases
            SET status = ?, closed_at = CASE WHEN ? = 'CLOSED' THEN CURRENT_TIMESTAMP ELSE NULL END,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, status, case_id),
        )
        _record_audit_event(
            connection,
            case_id,
            "STATUS_CHANGED",
            '{"from": "%s", "to": "%s"}' % (current["status"], status),
        )
