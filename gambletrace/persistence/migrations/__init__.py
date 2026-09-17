"""Ordered SQLite schema migrations for GambleTrace."""

from dataclasses import dataclass
from typing import Callable, List

import sqlite3


@dataclass(frozen=True)
class Migration:
    """A one-way, ordered database schema migration."""

    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


from gambletrace.persistence.migrations.migration_001_initial_schema import migration as migration_001
from gambletrace.persistence.migrations.migration_002_seed_source_provenance import migration as migration_002
from gambletrace.persistence.migrations.migration_003_immutable_observations import migration as migration_003
from gambletrace.persistence.migrations.migration_004_collector_results import migration as migration_004
from gambletrace.persistence.migrations.migration_005_evidence_manifest_integrity import migration as migration_005
from gambletrace.persistence.migrations.migration_006_tls_handshake_evidence import migration as migration_006
from gambletrace.persistence.migrations.migration_007_content_fingerprints import migration as migration_007
from gambletrace.persistence.migrations.migration_008_risk_assessments import migration as migration_008
from gambletrace.persistence.migrations.migration_009_operational_jobs import migration as migration_009
from gambletrace.persistence.migrations.migration_010_observation_availability import migration as migration_010
from gambletrace.persistence.migrations.migration_011_local_accounts import migration as migration_011


MIGRATIONS: List[Migration] = [migration_001, migration_002, migration_003, migration_004, migration_005, migration_006, migration_007, migration_008, migration_009, migration_010, migration_011]
