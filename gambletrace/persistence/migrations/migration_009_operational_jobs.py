"""Persist case-scoped background job status and progress."""

import sqlite3

from gambletrace.persistence.migrations import Migration


def apply(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE job_runs (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
            case_domain_id TEXT REFERENCES case_domains(id) ON DELETE RESTRICT,
            job_type TEXT NOT NULL CHECK (job_type IN (
                'COLLECT_EVIDENCE', 'DISCOVER_DOMAINS', 'SCORE_CASE', 'CORRELATE_CASE'
            )),
            status TEXT NOT NULL CHECK (status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED')),
            progress_percent INTEGER NOT NULL DEFAULT 0 CHECK (progress_percent BETWEEN 0 AND 100),
            message TEXT NOT NULL DEFAULT '',
            result_json TEXT NOT NULL DEFAULT '{}',
            error_message TEXT NOT NULL DEFAULT '',
            requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            started_at TEXT,
            finished_at TEXT
        );

        CREATE INDEX idx_job_runs_case_time
        ON job_runs(case_id, requested_at DESC);

        CREATE INDEX idx_job_runs_active_scope
        ON job_runs(case_id, case_domain_id, job_type, status);
        """
    )


migration = Migration(version=9, name="add_case_operational_jobs", apply=apply)
