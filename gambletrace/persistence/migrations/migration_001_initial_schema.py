"""Initial SQLite schema matching the GambleTrace logical data model."""

import sqlite3

from gambletrace.persistence.migrations import Migration


def apply(connection: sqlite3.Connection) -> None:
    """Create the initial case, evidence, intelligence, and monitoring tables."""
    connection.executescript(
        """
        CREATE TABLE cases (
            id TEXT PRIMARY KEY,
            case_number TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'COLLECTING', 'TRIAGE', 'MONITORING', 'ESCALATED', 'CLOSED')),
            priority TEXT NOT NULL DEFAULT 'MEDIUM' CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            owner_name TEXT NOT NULL DEFAULT '',
            scope_note TEXT NOT NULL DEFAULT '',
            authorization_note TEXT NOT NULL DEFAULT '',
            opened_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            closed_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE tags (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            color TEXT NOT NULL DEFAULT '#64748b',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE case_tags (
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
            tag_id TEXT NOT NULL REFERENCES tags(id) ON DELETE RESTRICT,
            PRIMARY KEY (case_id, tag_id)
        );

        CREATE TABLE case_notes (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
            body TEXT NOT NULL,
            author_name TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE audit_events (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
            event_type TEXT NOT NULL,
            actor_name TEXT NOT NULL DEFAULT '',
            event_data_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE source_files (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
            original_name TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
            mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
            imported_by TEXT NOT NULL DEFAULT '',
            imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE domains (
            id TEXT PRIMARY KEY,
            canonical_name TEXT NOT NULL UNIQUE,
            registrable_domain TEXT NOT NULL,
            first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE jobs (
            id TEXT PRIMARY KEY,
            case_id TEXT REFERENCES cases(id) ON DELETE RESTRICT,
            job_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
            progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
            parameters_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT NOT NULL DEFAULT '{}',
            error_message TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            started_at TEXT,
            finished_at TEXT
        );

        CREATE TABLE case_domains (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
            domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE RESTRICT,
            source_type TEXT NOT NULL CHECK (source_type IN ('SEED', 'MANUAL', 'GENERATED_VARIATION', 'REDIRECT_PIVOT', 'REVERSE_IP_PIVOT', 'TLS_PIVOT', 'NAMESERVER_PIVOT', 'CONTENT_PIVOT', 'IMPORT')),
            source_detail TEXT NOT NULL DEFAULT '',
            parent_case_domain_id TEXT REFERENCES case_domains(id) ON DELETE RESTRICT,
            relevance TEXT NOT NULL DEFAULT 'UNREVIEWED' CHECK (relevance IN ('UNREVIEWED', 'HIGH_CONFIDENCE_SUSPECTED_GAMBLING', 'MEDIUM_CONFIDENCE_SUSPECTED_GAMBLING', 'RELATED_INFRASTRUCTURE', 'LOW_CONFIDENCE_CANDIDATE', 'INSUFFICIENT_EVIDENCE', 'NOT_GAMBLING_RELATED')),
            availability TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK (availability IN ('UNKNOWN', 'ACTIVE', 'OFFLINE', 'UNRESOLVED', 'BLOCKED', 'PARKED')),
            risk_score REAL,
            first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TEXT,
            reviewed_by TEXT NOT NULL DEFAULT '',
            reviewed_at TEXT,
            UNIQUE (case_id, domain_id)
        );

        CREATE TABLE domain_observations (
            id TEXT PRIMARY KEY,
            case_domain_id TEXT NOT NULL REFERENCES case_domains(id) ON DELETE RESTRICT,
            job_id TEXT REFERENCES jobs(id) ON DELETE RESTRICT,
            outcome TEXT NOT NULL CHECK (outcome IN ('SUCCESS', 'PARTIAL', 'FAILED', 'SKIPPED')),
            observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            final_url TEXT NOT NULL DEFAULT '',
            http_status INTEGER,
            page_title TEXT NOT NULL DEFAULT '',
            content_hash TEXT NOT NULL DEFAULT '',
            favicon_hash TEXT NOT NULL DEFAULT '',
            error_message TEXT NOT NULL DEFAULT '',
            collector_version TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE evidence_artifacts (
            id TEXT PRIMARY KEY,
            observation_id TEXT NOT NULL REFERENCES domain_observations(id) ON DELETE RESTRICT,
            artifact_type TEXT NOT NULL,
            stored_path TEXT NOT NULL UNIQUE,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
            mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
            source_url TEXT NOT NULL DEFAULT '',
            captured_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE dns_records (
            id TEXT PRIMARY KEY,
            observation_id TEXT NOT NULL REFERENCES domain_observations(id) ON DELETE RESTRICT,
            record_type TEXT NOT NULL CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT', 'SOA')),
            record_value TEXT NOT NULL,
            ttl INTEGER
        );

        CREATE TABLE ip_addresses (
            id TEXT PRIMARY KEY,
            address TEXT NOT NULL UNIQUE,
            version INTEGER NOT NULL CHECK (version IN (4, 6)),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE observation_ips (
            observation_id TEXT NOT NULL REFERENCES domain_observations(id) ON DELETE RESTRICT,
            ip_id TEXT NOT NULL REFERENCES ip_addresses(id) ON DELETE RESTRICT,
            record_type TEXT NOT NULL CHECK (record_type IN ('A', 'AAAA')),
            PRIMARY KEY (observation_id, ip_id, record_type)
        );

        CREATE TABLE asns (
            id TEXT PRIMARY KEY,
            asn_number TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            provider_name TEXT NOT NULL DEFAULT '',
            country_code TEXT NOT NULL DEFAULT '',
            network_cidr TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE observation_asns (
            observation_id TEXT NOT NULL REFERENCES domain_observations(id) ON DELETE RESTRICT,
            ip_id TEXT NOT NULL REFERENCES ip_addresses(id) ON DELETE RESTRICT,
            asn_id TEXT NOT NULL REFERENCES asns(id) ON DELETE RESTRICT,
            PRIMARY KEY (observation_id, ip_id, asn_id)
        );

        CREATE TABLE tls_certificates (
            id TEXT PRIMARY KEY,
            sha256_fingerprint TEXT NOT NULL UNIQUE,
            subject TEXT NOT NULL DEFAULT '',
            issuer TEXT NOT NULL DEFAULT '',
            serial_number TEXT NOT NULL DEFAULT '',
            not_before TEXT,
            not_after TEXT
        );

        CREATE TABLE certificate_names (
            id TEXT PRIMARY KEY,
            certificate_id TEXT NOT NULL REFERENCES tls_certificates(id) ON DELETE RESTRICT,
            name TEXT NOT NULL,
            UNIQUE (certificate_id, name)
        );

        CREATE TABLE observation_certificates (
            observation_id TEXT NOT NULL REFERENCES domain_observations(id) ON DELETE RESTRICT,
            certificate_id TEXT NOT NULL REFERENCES tls_certificates(id) ON DELETE RESTRICT,
            PRIMARY KEY (observation_id, certificate_id)
        );

        CREATE TABLE redirects (
            id TEXT PRIMARY KEY,
            observation_id TEXT NOT NULL REFERENCES domain_observations(id) ON DELETE RESTRICT,
            hop_number INTEGER NOT NULL CHECK (hop_number >= 0),
            source_url TEXT NOT NULL,
            status_code INTEGER,
            target_url TEXT NOT NULL,
            target_domain_id TEXT REFERENCES domains(id) ON DELETE RESTRICT,
            UNIQUE (observation_id, hop_number)
        );

        CREATE TABLE relationships (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
            source_type TEXT NOT NULL,
            source_id TEXT NOT NULL,
            relationship_type TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            confidence TEXT NOT NULL CHECK (confidence IN ('LOW', 'MEDIUM', 'HIGH')),
            first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            explanation TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (case_id, source_type, source_id, relationship_type, target_type, target_id)
        );

        CREATE TABLE relationship_evidence (
            relationship_id TEXT NOT NULL REFERENCES relationships(id) ON DELETE RESTRICT,
            artifact_id TEXT NOT NULL REFERENCES evidence_artifacts(id) ON DELETE RESTRICT,
            PRIMARY KEY (relationship_id, artifact_id)
        );

        CREATE TABLE clusters (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
            cluster_key TEXT NOT NULL,
            name TEXT NOT NULL,
            confidence TEXT NOT NULL CHECK (confidence IN ('LOW', 'MEDIUM', 'HIGH')),
            summary TEXT NOT NULL DEFAULT '',
            first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (case_id, cluster_key)
        );

        CREATE TABLE cluster_members (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT '',
            confidence TEXT NOT NULL CHECK (confidence IN ('LOW', 'MEDIUM', 'HIGH')),
            added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (cluster_id, entity_type, entity_id)
        );

        CREATE TABLE alerts (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
            case_domain_id TEXT REFERENCES case_domains(id) ON DELETE RESTRICT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            summary TEXT NOT NULL,
            previous_value TEXT NOT NULL DEFAULT '',
            current_value TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            acknowledged_at TEXT
        );

        CREATE INDEX idx_case_domains_case_id ON case_domains(case_id);
        CREATE INDEX idx_case_domains_relevance ON case_domains(relevance);
        CREATE INDEX idx_observations_case_domain_time ON domain_observations(case_domain_id, observed_at DESC);
        CREATE INDEX idx_artifacts_sha256 ON evidence_artifacts(sha256);
        CREATE INDEX idx_dns_observation_id ON dns_records(observation_id);
        CREATE INDEX idx_observation_ips_ip_id ON observation_ips(ip_id);
        CREATE INDEX idx_certificate_names_name ON certificate_names(name);
        CREATE INDEX idx_redirects_target_domain ON redirects(target_domain_id);
        CREATE INDEX idx_relationships_case_source ON relationships(case_id, source_type, source_id);
        CREATE INDEX idx_relationships_case_target ON relationships(case_id, target_type, target_id);
        CREATE INDEX idx_clusters_case_id ON clusters(case_id);
        CREATE INDEX idx_alerts_case_status ON alerts(case_id, status, created_at DESC);
        """
    )


migration = Migration(
    version=1,
    name="initial_case_evidence_intelligence_schema",
    apply=apply,
)
