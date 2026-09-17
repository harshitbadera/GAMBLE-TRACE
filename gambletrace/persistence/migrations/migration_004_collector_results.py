"""Add structured HTTP, RDAP, and screenshot collection-result tables."""

import sqlite3

from gambletrace.persistence.migrations import Migration


def apply(connection: sqlite3.Connection) -> None:
    """Create tables that hold technical details for an immutable observation."""
    connection.executescript(
        """
        CREATE TABLE http_responses (
            id TEXT PRIMARY KEY,
            observation_id TEXT NOT NULL UNIQUE REFERENCES domain_observations(id) ON DELETE RESTRICT,
            request_url TEXT NOT NULL DEFAULT '',
            final_url TEXT NOT NULL DEFAULT '',
            status_code INTEGER,
            response_headers_json TEXT NOT NULL DEFAULT '{}',
            content_type TEXT NOT NULL DEFAULT '',
            body_size_bytes INTEGER NOT NULL DEFAULT 0 CHECK (body_size_bytes >= 0),
            redirect_count INTEGER NOT NULL DEFAULT 0 CHECK (redirect_count >= 0),
            collection_error TEXT NOT NULL DEFAULT '',
            collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE rdap_records (
            id TEXT PRIMARY KEY,
            observation_id TEXT NOT NULL REFERENCES domain_observations(id) ON DELETE RESTRICT,
            ip_id TEXT NOT NULL REFERENCES ip_addresses(id) ON DELETE RESTRICT,
            asn_id TEXT REFERENCES asns(id) ON DELETE RESTRICT,
            network_name TEXT NOT NULL DEFAULT '',
            network_cidr TEXT NOT NULL DEFAULT '',
            country_code TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '',
            raw_response_json TEXT NOT NULL DEFAULT '{}',
            collection_error TEXT NOT NULL DEFAULT '',
            collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (observation_id, ip_id)
        );

        CREATE TABLE screenshot_captures (
            id TEXT PRIMARY KEY,
            observation_id TEXT NOT NULL UNIQUE REFERENCES domain_observations(id) ON DELETE RESTRICT,
            stored_path TEXT NOT NULL DEFAULT '',
            capture_status TEXT NOT NULL CHECK (capture_status IN ('CAPTURED', 'NOT_CAPTURED', 'FAILED')),
            response_status INTEGER,
            collection_error TEXT NOT NULL DEFAULT '',
            captured_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX idx_http_responses_status ON http_responses(status_code);
        CREATE INDEX idx_rdap_records_ip_id ON rdap_records(ip_id);
        """
    )


migration = Migration(
    version=4,
    name="store_structured_collector_results",
    apply=apply,
)
