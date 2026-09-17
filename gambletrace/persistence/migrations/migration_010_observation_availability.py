"""Retain the observed availability state with each immutable observation."""

import sqlite3

from gambletrace.persistence.migrations import Migration


def apply(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        ALTER TABLE domain_observations
        ADD COLUMN availability TEXT NOT NULL DEFAULT 'UNKNOWN'
        """
    )


migration = Migration(version=10, name="retain_historical_observation_availability", apply=apply)
