"""Persist append-only explainable domain-risk assessments."""

import sqlite3

from gambletrace.persistence.migrations import Migration


def apply(connection: sqlite3.Connection) -> None:
    """Create historical scoring records and prevent later modification."""
    connection.executescript(
        """
        CREATE TABLE risk_assessments (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
            case_domain_id TEXT NOT NULL REFERENCES case_domains(id) ON DELETE RESTRICT,
            score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
            relevance TEXT NOT NULL CHECK (relevance IN (
                'HIGH_CONFIDENCE_SUSPECTED_GAMBLING',
                'MEDIUM_CONFIDENCE_SUSPECTED_GAMBLING',
                'RELATED_INFRASTRUCTURE',
                'LOW_CONFIDENCE_CANDIDATE',
                'INSUFFICIENT_EVIDENCE',
                'NOT_GAMBLING_RELATED'
            )),
            factors_json TEXT NOT NULL,
            scorer_version TEXT NOT NULL,
            assessed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX idx_risk_assessments_case_domain_time
        ON risk_assessments(case_domain_id, assessed_at DESC);

        CREATE INDEX idx_risk_assessments_case_score
        ON risk_assessments(case_id, score DESC);

        CREATE TRIGGER prevent_risk_assessment_update
        BEFORE UPDATE ON risk_assessments
        BEGIN
            SELECT RAISE(ABORT, 'Risk assessments are immutable; run a new assessment instead');
        END;

        CREATE TRIGGER prevent_risk_assessment_delete
        BEFORE DELETE ON risk_assessments
        BEGIN
            SELECT RAISE(ABORT, 'Risk assessments are immutable and cannot be deleted');
        END;
        """
    )


migration = Migration(
    version=8,
    name="persist_explainable_risk_assessments",
    apply=apply,
)
