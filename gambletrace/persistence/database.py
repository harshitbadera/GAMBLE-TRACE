"""SQLite database access and lightweight versioned migration support."""

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
import click
from flask import Flask, current_app

from gambletrace.persistence.migrations import MIGRATIONS


class Database:
    """Owns SQLite connections and applies ordered schema migrations."""

    def __init__(self, path: str):
        self.path = path

    @contextmanager
    def connect(self):
        """Yield a connection and always release its file handle afterwards."""
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
        except Exception:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()

    def migrate(self) -> int:
        """Apply every pending migration and return the resulting schema version."""
        database_dir = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(database_dir, exist_ok=True)
        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            applied_versions = {
                row["version"]
                for row in connection.execute("SELECT version FROM schema_migrations")
            }
            for migration in MIGRATIONS:
                if migration.version in applied_versions:
                    continue
                migration.apply(connection)
                connection.execute(
                    "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
                    (migration.version, migration.name),
                )
        return self.current_version()

    def current_version(self) -> int:
        """Return the latest applied migration version, or zero for a new database."""
        if not Path(self.path).exists():
            return 0
        with self.connect() as connection:
            row = connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
            ).fetchone()
        return int(row["version"])


def get_database() -> Database:
    """Return the database attached to the current Flask application."""
    return current_app.extensions["gambletrace"]["database"]


def init_database(app: Flask) -> None:
    """Attach and migrate the application database, then register its CLI command."""
    database = Database(app.config["DATABASE_PATH"])
    database.migrate()
    app.extensions["gambletrace"]["database"] = database

    @app.cli.command("migrate-db")
    def migrate_database_command() -> None:
        """Apply outstanding GambleTrace SQLite migrations."""
        version = database.migrate()
        click.echo(f"GambleTrace database migrated to version {version}: {database.path}")
