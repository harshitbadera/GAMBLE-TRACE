"""Add source-file provenance to every imported case-domain record."""

import sqlite3

from gambletrace.persistence.migrations import Migration


def apply(connection: sqlite3.Connection) -> None:
    """Link case-domain records to their retained source file when available."""
    connection.execute(
        """
        ALTER TABLE case_domains
        ADD COLUMN source_file_id TEXT REFERENCES source_files(id) ON DELETE RESTRICT
        """
    )
    connection.execute(
        """
        CREATE INDEX idx_case_domains_source_file_id
        ON case_domains(source_file_id)
        """
    )


migration = Migration(
    version=2,
    name="link_seed_domains_to_source_files",
    apply=apply,
)
