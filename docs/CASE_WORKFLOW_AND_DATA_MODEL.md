# GambleTrace Case Workflow and Data Model

This document is the implementation contract for GambleTrace Item 1. It defines how a case moves through an investigation and the logical database schema that will be implemented with SQLite and migrations in Item 3.

## Design principles

- A **case** is the top-level investigation container.
- A **domain** is a globally normalized entity; the same domain may appear in more than one case.
- An **observation** is an immutable record of one collection run against a domain at a point in time.
- An **artifact** is a saved evidence file tied to one observation and protected by a SHA-256 hash.
- A **relationship** must identify its evidence source and confidence; it is an investigative lead, not an attribution claim.
- Database timestamps are stored in UTC. The UI can display local time separately.

## Case lifecycle

```text
OPEN
  -> COLLECTING
  -> TRIAGE
  -> MONITORING
  -> ESCALATED
  -> CLOSED
```

| Status | Meaning | Typical next status |
| --- | --- | --- |
| `OPEN` | Case exists; seeds, scope, and ownership are being set. | `COLLECTING`, `CLOSED` |
| `COLLECTING` | Collection jobs are gathering evidence and infrastructure data. | `TRIAGE`, `MONITORING` |
| `TRIAGE` | Analyst is reviewing findings, scores, and relationships. | `MONITORING`, `ESCALATED`, `CLOSED` |
| `MONITORING` | Case is retained for scheduled re-observation and mutation alerts. | `TRIAGE`, `ESCALATED`, `CLOSED` |
| `ESCALATED` | Findings require hand-off, reporting, or a formal response workflow. | `MONITORING`, `CLOSED` |
| `CLOSED` | Investigation is complete; evidence remains read-only and available. | `OPEN` only with a recorded reopen reason |

Every case status change creates an audit event with the actor, UTC timestamp, old status, new status, and optional reason.

## Standard labels

### Case priority

`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

Priority reflects the investigation workload and potential impact. It does not prove criminality.

### Domain source

`SEED`, `MANUAL`, `GENERATED_VARIATION`, `REDIRECT_PIVOT`, `REVERSE_IP_PIVOT`, `TLS_PIVOT`, `NAMESERVER_PIVOT`, `CONTENT_PIVOT`, `IMPORT`

### Domain relevance

`UNREVIEWED`, `HIGH_CONFIDENCE_SUSPECTED_GAMBLING`, `MEDIUM_CONFIDENCE_SUSPECTED_GAMBLING`, `RELATED_INFRASTRUCTURE`, `LOW_CONFIDENCE_CANDIDATE`, `INSUFFICIENT_EVIDENCE`, `NOT_GAMBLING_RELATED`

### Domain availability

`UNKNOWN`, `ACTIVE`, `OFFLINE`, `UNRESOLVED`, `BLOCKED`, `PARKED`

### Observation outcome

`SUCCESS`, `PARTIAL`, `FAILED`, `SKIPPED`

### Relationship confidence

`LOW`, `MEDIUM`, `HIGH`

Shared CDN/cloud infrastructure or similar naming alone should normally remain `LOW`. Direct redirects, rare shared certificates, and repeated content fingerprints can contribute to stronger confidence when corroborated by additional evidence.

### Cluster confidence

`LOW`, `MEDIUM`, `HIGH`

A cluster must retain an explanation of the contributing relationships; it must not be presented as proof of common ownership.

## Workflow

1. An analyst creates a case with a title, scope, owner, priority, and legal/authorization note.
2. Seed domains are imported; the original source file becomes a hashed source artifact.
3. Each input is normalized into a global domain record and linked to the case as a `SEED` case-domain record.
4. Collection jobs create immutable domain observations and attach evidence artifacts.
5. Discovery jobs add new domain-to-case links, preserving the discovery method and parent indicator.
6. Scoring and analyst review assign a case-specific relevance label and risk score.
7. Correlation jobs create evidence-backed relationships and cluster memberships.
8. Monitoring jobs create later observations and alerts when material attributes change.
9. Reports and IOC exports are generated from case data without modifying the underlying evidence.
10. Closing a case locks its conclusion; reopening requires an audit reason.

## Logical database schema

### Case and analyst records

| Table | Purpose | Key fields |
| --- | --- | --- |
| `cases` | Investigation container. | `id`, `case_number`, `title`, `description`, `status`, `priority`, `owner_name`, `scope_note`, `opened_at`, `closed_at`, `created_at`, `updated_at` |
| `tags` | Reusable analyst tags. | `id`, `name`, `color`, `created_at` |
| `case_tags` | Many-to-many case/tag link. | `case_id`, `tag_id` |
| `case_notes` | Analyst notes. | `id`, `case_id`, `body`, `author_name`, `created_at`, `updated_at` |
| `audit_events` | Append-only workflow and analyst activity log. | `id`, `case_id`, `event_type`, `actor_name`, `event_data_json`, `created_at` |

### Source, domain, and observation records

| Table | Purpose | Key fields |
| --- | --- | --- |
| `source_files` | Original uploaded seed files and imports. | `id`, `case_id`, `original_name`, `stored_path`, `sha256`, `size_bytes`, `mime_type`, `imported_by`, `imported_at` |
| `domains` | Global canonical domain registry. | `id`, `canonical_name`, `registrable_domain`, `first_seen_at`, `created_at` |
| `case_domains` | Case-specific state for a domain. | `id`, `case_id`, `domain_id`, `source_type`, `source_detail`, `source_file_id`, `parent_case_domain_id`, `relevance`, `availability`, `risk_score`, `first_seen_at`, `last_seen_at`, `reviewed_by`, `reviewed_at` |
| `domain_observations` | Immutable collection snapshot. | `id`, `case_domain_id`, `job_id`, `outcome`, `observed_at`, `final_url`, `http_status`, `page_title`, `content_hash`, `favicon_hash`, `error_message`, `collector_version` |

`domains.canonical_name` is unique. `case_domains` is unique for `(case_id, domain_id)`. The parent field records the specific case-domain item that produced a pivot.

### Evidence and network records

| Table | Purpose | Key fields |
| --- | --- | --- |
| `evidence_artifacts` | Metadata for files saved outside the database. | `id`, `observation_id`, `artifact_type`, `stored_path`, `sha256`, `size_bytes`, `mime_type`, `source_url`, `captured_at` |
| `dns_records` | DNS answers from an observation. | `id`, `observation_id`, `record_type`, `record_value`, `ttl` |
| `ip_addresses` | Canonical IPv4/IPv6 values. | `id`, `address`, `version`, `created_at` |
| `observation_ips` | IPs returned in an observation. | `observation_id`, `ip_id`, `record_type` |
| `asns` | ASN and network attribution. | `id`, `asn_number`, `description`, `provider_name`, `country_code`, `network_cidr` |
| `observation_asns` | ASN seen for an IP/observation. | `observation_id`, `ip_id`, `asn_id` |
| `tls_certificates` | Canonical certificate metadata. | `id`, `sha256_fingerprint`, `subject`, `issuer`, `serial_number`, `not_before`, `not_after` |
| `certificate_names` | Certificate SAN/common names. | `id`, `certificate_id`, `name` |
| `observation_certificates` | Certificate presented during an observation. | `observation_id`, `certificate_id` |
| `redirects` | Ordered redirect hops. | `id`, `observation_id`, `hop_number`, `source_url`, `status_code`, `target_url`, `target_domain_id` |

Binary evidence files are stored under the case evidence directory, not as database blobs. The database stores their metadata and integrity hash.

### Intelligence, graph, and monitoring records

| Table | Purpose | Key fields |
| --- | --- | --- |
| `relationships` | Evidence-backed graph edge. | `id`, `case_id`, `source_type`, `source_id`, `relationship_type`, `target_type`, `target_id`, `confidence`, `first_seen_at`, `last_seen_at`, `explanation`, `created_at` |
| `relationship_evidence` | Many-to-many relationship/artifact support. | `relationship_id`, `artifact_id` |
| `clusters` | Case-specific probable infrastructure cluster. | `id`, `case_id`, `cluster_key`, `name`, `confidence`, `summary`, `first_seen_at`, `last_seen_at`, `created_at` |
| `cluster_members` | Entity membership in a cluster. | `id`, `cluster_id`, `entity_type`, `entity_id`, `role`, `confidence`, `added_at` |
| `alerts` | Change or monitoring finding. | `id`, `case_id`, `case_domain_id`, `alert_type`, `severity`, `summary`, `previous_value`, `current_value`, `status`, `created_at`, `acknowledged_at` |
| `jobs` | Background collection, correlation, monitoring, or report job. | `id`, `case_id`, `job_type`, `status`, `progress`, `parameters_json`, `result_json`, `error_message`, `created_at`, `started_at`, `finished_at` |

## Relationship types

Initial supported relationship types:

```text
RESOLVES_TO
USES_NAMESERVER
PRESENTS_CERTIFICATE
HOSTED_BY_ASN
REDIRECTS_TO
SHARES_IP_WITH
SHARES_CERTIFICATE_WITH
SHARES_NAMESERVER_WITH
SHARES_CONTENT_FINGERPRINT_WITH
SHARES_FAVICON_WITH
DISCOVERED_FROM
MEMBER_OF_CLUSTER
```

## Integrity and retention rules

- Use UUIDs for all primary IDs and a human-readable `GT-YYYY-NNN` format for `case_number`.
- Store all machine timestamps in UTC using ISO 8601-compatible database types.
- Never update the technical result fields of a completed observation; create a new observation instead.
- Never modify an evidence artifact after hashing it. A correction creates a replacement artifact and audit event.
- Do not delete a case, observation, or artifact through ordinary application workflows; use an explicit retention process and log it.
- Keep authentication/analyst identity fields optional until multi-user authentication is implemented.
- Index `domains.canonical_name`, `case_domains.case_id`, `domain_observations.observed_at`, artifact hashes, certificate fingerprints, IP addresses, and relationship endpoints.

## Implementation boundary

This is a logical schema and workflow definition only. It does **not** add a database, migrations, case UI, collectors, or graph code. Those changes begin in Items 2–4 of `PROJECT_PLAN.txt`.
