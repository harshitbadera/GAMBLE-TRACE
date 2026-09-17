# Historical Domain Observations

GambleTrace now treats every domain check as an append-only observation rather than a value that overwrites an earlier result.

## Observation model

Each record in `domain_observations` represents one point-in-time collection result for a domain in a case.

```text
Case domain: examplebet.com

2026-09-15T10:00:00Z  SUCCESS  ACTIVE   HTTP 200  Initial landing page
2026-09-16T10:00:00Z  FAILED   OFFLINE  Timeout   Recheck failed
```

The original successful observation remains available after the later failure. The `case_domains` record holds only the latest operational state (`availability` and `last_seen_at`) for dashboard use.

## Stored observation fields

- Observation UUID
- Case-domain ID
- Outcome: `SUCCESS`, `PARTIAL`, `FAILED`, or `SKIPPED`
- UTC observation time
- Final URL
- HTTP status
- Page title
- Content and favicon hash placeholders for future collectors
- Error/finding message
- Collector version

## Immutability

Migration `003_immutable_observations` installs SQLite triggers that reject:

- Updates to existing `domain_observations` rows
- Deletion of existing `domain_observations` rows

Corrections and later collection results must be represented as new observations. This protects the historical timeline and supports later evidence integrity work.

## Current interface

The Case Workspace provides a manual observation form and a recent observation timeline. This supports analyst-recorded checks before automated evidence collectors are added.

## Next stages

Task 7 will have DNS, HTTP, redirect, RDAP, screenshot, and related collectors create these observations automatically. Task 8 will attach hashed evidence artifacts and manifests to them.
