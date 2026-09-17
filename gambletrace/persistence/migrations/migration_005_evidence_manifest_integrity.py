"""Record evidence manifests and make retained evidence metadata immutable."""

import sqlite3

from gambletrace.persistence.migrations import Migration


def apply(connection: sqlite3.Connection) -> None:
    """Add chain-of-custody manifest records and database-level protections."""
    connection.executescript(
        """
        CREATE TABLE evidence_manifests (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
            observation_id TEXT NOT NULL UNIQUE REFERENCES domain_observations(id) ON DELETE RESTRICT,
            stored_path TEXT NOT NULL UNIQUE,
            sha256 TEXT NOT NULL,
            artifact_count INTEGER NOT NULL CHECK (artifact_count >= 0),
            collector_version TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX idx_evidence_artifacts_observation
        ON evidence_artifacts(observation_id, captured_at DESC);

        CREATE INDEX idx_evidence_manifests_case
        ON evidence_manifests(case_id, created_at DESC);

        CREATE TRIGGER prevent_evidence_artifact_update
        BEFORE UPDATE ON evidence_artifacts
        BEGIN
            SELECT RAISE(ABORT, 'Evidence artifacts are immutable; preserve a new artifact instead');
        END;

        CREATE TRIGGER prevent_evidence_artifact_delete
        BEFORE DELETE ON evidence_artifacts
        BEGIN
            SELECT RAISE(ABORT, 'Evidence artifacts are immutable and cannot be deleted');
        END;

        CREATE TRIGGER prevent_evidence_manifest_update
        BEFORE UPDATE ON evidence_manifests
        BEGIN
            SELECT RAISE(ABORT, 'Evidence manifests are immutable');
        END;

        CREATE TRIGGER prevent_evidence_manifest_delete
        BEFORE DELETE ON evidence_manifests
        BEGIN
            SELECT RAISE(ABORT, 'Evidence manifests are immutable and cannot be deleted');
        END;
        """
    )


migration = Migration(
    version=5,
    name="evidence_manifest_chain_of_custody",
    apply=apply,
)
