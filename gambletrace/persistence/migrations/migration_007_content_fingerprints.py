"""Persist immutable normalized-content, favicon, and indicator evidence."""

import sqlite3

from gambletrace.persistence.migrations import Migration


def apply(connection: sqlite3.Connection) -> None:
    """Create content-fingerprint and explainable-indicator evidence tables."""
    connection.executescript(
        """
        CREATE TABLE content_fingerprints (
            id TEXT PRIMARY KEY,
            observation_id TEXT NOT NULL UNIQUE REFERENCES domain_observations(id) ON DELETE RESTRICT,
            normalized_html_hash TEXT NOT NULL DEFAULT '',
            visible_text_hash TEXT NOT NULL DEFAULT '',
            favicon_hash TEXT NOT NULL DEFAULT '',
            favicon_source_url TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE content_indicators (
            id TEXT PRIMARY KEY,
            observation_id TEXT NOT NULL REFERENCES domain_observations(id) ON DELETE RESTRICT,
            category TEXT NOT NULL CHECK (category IN ('GAMBLING', 'PAYMENT', 'INDIA')),
            indicator TEXT NOT NULL,
            occurrences INTEGER NOT NULL CHECK (occurrences > 0),
            UNIQUE (observation_id, category, indicator)
        );

        CREATE INDEX idx_content_fingerprints_normalized_hash
        ON content_fingerprints(normalized_html_hash);

        CREATE INDEX idx_content_fingerprints_favicon_hash
        ON content_fingerprints(favicon_hash);

        CREATE INDEX idx_content_indicators_category_indicator
        ON content_indicators(category, indicator);

        CREATE TRIGGER prevent_content_fingerprint_update
        BEFORE UPDATE ON content_fingerprints
        BEGIN
            SELECT RAISE(ABORT, 'Content fingerprints are immutable');
        END;

        CREATE TRIGGER prevent_content_fingerprint_delete
        BEFORE DELETE ON content_fingerprints
        BEGIN
            SELECT RAISE(ABORT, 'Content fingerprints are immutable and cannot be deleted');
        END;

        CREATE TRIGGER prevent_content_indicator_update
        BEFORE UPDATE ON content_indicators
        BEGIN
            SELECT RAISE(ABORT, 'Content indicators are immutable');
        END;

        CREATE TRIGGER prevent_content_indicator_delete
        BEFORE DELETE ON content_indicators
        BEGIN
            SELECT RAISE(ABORT, 'Content indicators are immutable and cannot be deleted');
        END;
        """
    )


migration = Migration(
    version=7,
    name="persist_content_and_favicon_fingerprints",
    apply=apply,
)
