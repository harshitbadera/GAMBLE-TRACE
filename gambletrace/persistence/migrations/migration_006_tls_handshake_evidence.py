"""Record immutable TLS handshake context for certificate evidence."""

import sqlite3

from gambletrace.persistence.migrations import Migration


def apply(connection: sqlite3.Connection) -> None:
    """Add TLS endpoint/handshake rows alongside existing certificate entities."""
    connection.executescript(
        """
        CREATE TABLE tls_handshakes (
            id TEXT PRIMARY KEY,
            observation_id TEXT NOT NULL REFERENCES domain_observations(id) ON DELETE RESTRICT,
            ip_id TEXT REFERENCES ip_addresses(id) ON DELETE RESTRICT,
            certificate_id TEXT REFERENCES tls_certificates(id) ON DELETE RESTRICT,
            tls_version TEXT NOT NULL DEFAULT '',
            cipher_name TEXT NOT NULL DEFAULT '',
            collection_error TEXT NOT NULL DEFAULT '',
            collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX idx_tls_handshakes_observation
        ON tls_handshakes(observation_id, collected_at DESC);

        CREATE INDEX idx_tls_handshakes_certificate
        ON tls_handshakes(certificate_id);

        CREATE TRIGGER prevent_tls_handshake_update
        BEFORE UPDATE ON tls_handshakes
        BEGIN
            SELECT RAISE(ABORT, 'TLS handshake evidence is immutable');
        END;

        CREATE TRIGGER prevent_tls_handshake_delete
        BEFORE DELETE ON tls_handshakes
        BEGIN
            SELECT RAISE(ABORT, 'TLS handshake evidence is immutable and cannot be deleted');
        END;
        """
    )


migration = Migration(
    version=6,
    name="record_tls_handshake_evidence",
    apply=apply,
)
