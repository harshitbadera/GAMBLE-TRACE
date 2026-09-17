# GambleTrace Database and Migrations

GambleTrace now uses SQLite as its local development database. The schema implements the logical model in [Case Workflow and Data Model](CASE_WORKFLOW_AND_DATA_MODEL.md).

## Database location

By default, the application creates its database at:

```text
data/gambletrace.db
```

Local SQLite database files, write-ahead logs, and shared-memory files are ignored by Git.

## Migration behaviour

The application applies outstanding schema migrations automatically when it starts. The migration ledger is stored in the `schema_migrations` table, so migrations are applied once and can be safely run again.

To run migrations explicitly:

```powershell
flask --app app migrate-db
```

## Initial schema

Migration `001_initial_schema` creates the tables needed for the next implementation stages:

- Case workflow: cases, tags, notes, and audit events
- Seed and domain tracking: source files, domains, and case-domain links
- Historical observations and jobs
- Evidence metadata and DNS/IP/ASN/TLS data
- Redirects, graph relationships, and supporting evidence
- Clusters and cluster membership
- Monitoring alerts

Migration `002_seed_source_provenance` links every imported case-domain to its preserved source file through `case_domains.source_file_id`.

Migration `003_immutable_observations` installs append-only protections for `domain_observations` and adds an outcome/time index for observation history.

Migration `004_collector_results` adds structured HTTP, RDAP, and screenshot-result rows for each technical observation.

Migration `005_evidence_manifest_integrity` adds case-linked evidence manifests and makes evidence artifact and manifest metadata append-only through SQLite triggers. Retained files are stored under `data/cases/<case-id>/evidence/<observation-id>/` and are linked by case-relative path and SHA-256 hash.

Migration `006_tls_handshake_evidence` records append-only endpoint, TLS protocol/cipher, certificate, and error details for each TLS handshake.

Migration `007_content_fingerprints` records append-only normalized HTML, visible-text, and favicon hashes plus explainable gambling, payment, and India indicator counts.

Migration `008_risk_assessments` stores append-only factor-by-factor domain risk assessments and their scorer version.

## Adding a new migration

1. Create `gambletrace/persistence/migrations/migration_009_<name>.py`.
2. Give it the next integer version and a descriptive name.
3. Add it to `MIGRATIONS` in `gambletrace/persistence/migrations/__init__.py`.
4. Test it against both a new database and a database already migrated to the previous version.
5. Do not edit an already released migration; add a new migration for every schema change.

## Current boundary

This task provides the database engine and schema only. Case creation, seed persistence, and user-facing case pages begin in Project Plan Item 4.
