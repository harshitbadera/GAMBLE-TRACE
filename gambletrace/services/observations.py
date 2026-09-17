"""Append-only domain observation services and history queries."""

from datetime import datetime, timezone
import json
import sqlite3
import uuid
from typing import Callable, Dict, List, Optional

from gambletrace.models.contracts import DomainAvailability, ObservationOutcome
from gambletrace.persistence import Database


def _utc_now() -> str:
    """Return a database-compatible UTC timestamp with second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _record_audit_event(connection, case_id: str, event_type: str, event_data: Dict) -> None:
    connection.execute(
        """
        INSERT INTO audit_events (id, case_id, event_type, event_data_json)
        VALUES (?, ?, ?, ?)
        """,
        (str(uuid.uuid4()), case_id, event_type, json.dumps(event_data)),
    )


def _clean_optional_int(value) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("HTTP status must be a whole number") from error
    if not 100 <= parsed <= 599:
        raise ValueError("HTTP status must be between 100 and 599")
    return parsed


def record_domain_observation(
    database: Database,
    case_id: str,
    case_domain_id: str,
    outcome: str,
    availability: str,
    final_url: str = "",
    http_status=None,
    page_title: str = "",
    content_hash: str = "",
    favicon_hash: str = "",
    error_message: str = "",
    collector_version: str = "manual-case-workspace",
    details_writer: Optional[Callable[[sqlite3.Connection, str], None]] = None,
    observation_id: Optional[str] = None,
    observed_at: Optional[str] = None,
) -> Dict:
    """Create one immutable domain observation and update only current case state.

    ``details_writer`` is an internal extension point for collectors that need
    their structured result rows committed atomically with the observation.
    """
    valid_outcomes = {item.value for item in ObservationOutcome}
    valid_availability = {item.value for item in DomainAvailability}
    if outcome not in valid_outcomes:
        raise ValueError("Invalid observation outcome")
    if availability not in valid_availability:
        raise ValueError("Invalid domain availability")

    observation_id = observation_id or str(uuid.uuid4())
    observed_at = observed_at or _utc_now()
    status_code = _clean_optional_int(http_status)
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        case_domain = connection.execute(
            """
            SELECT id FROM case_domains WHERE id = ? AND case_id = ?
            """,
            (case_domain_id, case_id),
        ).fetchone()
        if not case_domain:
            raise LookupError("Domain is not part of this case")
        connection.execute(
            """
            INSERT INTO domain_observations (
                id, case_domain_id, outcome, availability, observed_at, final_url, http_status,
                page_title, content_hash, favicon_hash, error_message, collector_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observation_id, case_domain_id, outcome, availability, observed_at, final_url.strip()[:2048],
                status_code, page_title.strip()[:500], content_hash[:128], favicon_hash[:128],
                error_message.strip()[:2000], collector_version[:120],
            ),
        )
        if details_writer:
            details_writer(connection, observation_id)
        # The case-domain row represents current operational state only. Historic
        # technical values remain exclusively in domain_observations.
        connection.execute(
            """
            UPDATE case_domains
            SET availability = ?, last_seen_at = ?
            WHERE id = ?
            """,
            (availability, observed_at, case_domain_id),
        )
        _record_audit_event(
            connection,
            case_id,
            "DOMAIN_OBSERVATION_RECORDED",
            {
                "observation_id": observation_id,
                "case_domain_id": case_domain_id,
                "outcome": outcome,
                "availability": availability,
            },
        )
        row = connection.execute(
            "SELECT * FROM domain_observations WHERE id = ?", (observation_id,)
        ).fetchone()
    return dict(row)


def list_recent_observations(database: Database, case_id: str, limit: int = 30) -> List[Dict]:
    """Return latest append-only observations for one case."""
    with database.connect() as connection:
        rows = connection.execute(
            """
            SELECT domain_observations.*, domains.canonical_name
            FROM domain_observations
            JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
            JOIN domains ON domains.id = case_domains.domain_id
            WHERE case_domains.case_id = ?
            ORDER BY domain_observations.observed_at DESC, domain_observations.id DESC
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]
