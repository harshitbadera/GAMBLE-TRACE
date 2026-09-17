"""Enforce append-only domain observations at the SQLite layer."""

import sqlite3

from gambletrace.persistence.migrations import Migration


def apply(connection: sqlite3.Connection) -> None:
    """Prevent updates and deletes of observations once they are recorded."""
    connection.executescript(
        """
        CREATE TRIGGER prevent_domain_observation_update
        BEFORE UPDATE ON domain_observations
        BEGIN
            SELECT RAISE(ABORT, 'Domain observations are immutable; create a new observation instead');
        END;

        CREATE TRIGGER prevent_domain_observation_delete
        BEFORE DELETE ON domain_observations
        BEGIN
            SELECT RAISE(ABORT, 'Domain observations are immutable and cannot be deleted');
        END;

        CREATE INDEX idx_observations_outcome_time
        ON domain_observations(outcome, observed_at DESC);
        """
    )


migration = Migration(
    version=3,
    name="enforce_append_only_domain_observations",
    apply=apply,
)
