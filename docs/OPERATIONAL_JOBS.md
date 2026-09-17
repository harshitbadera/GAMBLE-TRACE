# Background operations and safeguards

Task 16 moves long analyst-triggered case operations off the request thread.
The case workspace stays usable while an operation runs, and its progress is
stored in SQLite so it remains visible after a page refresh.

## Background job types

| Job type | Triggered by | Progress stages |
| --- | --- | --- |
| `COLLECT_EVIDENCE` | Technical evidence collection | Collection, artifact hashing, immutable package persistence |
| `DISCOVER_DOMAINS` | Domain discovery pivots | Pivot validation, candidate/provenance persistence |
| `SCORE_CASE` | Case risk scoring | Evidence-factor calculation, immutable assessment persistence |
| `CORRELATE_CASE` | Infrastructure correlation | Signal comparison, relationship/cluster persistence |

## Visible status

The **Operation status** panel on a case overview shows queued, running,
succeeded, and failed jobs. While a job is active, the browser polls:

```text
/cases/<case_id>/jobs
```

Only the current case's jobs are returned. Completion and failure are also
recorded in the case audit timeline.

## Rate limiting and duplicate protection

The local runner deliberately has a small worker pool (two workers by
default). It also rejects:

- an identical queued or running operation in the same case scope; and
- a repeat action inside its configured cooldown period.

Default cooldowns are 30 seconds for evidence collection, 15 seconds for
discovery, and 2 seconds for scoring/correlation. They are configured through
`JOB_COOLDOWNS` in the Flask application configuration.

## Error handling

Worker exceptions never leave a browser request hanging. The job is marked
`FAILED`, receives a safe summary error message, and creates a `JOB_FAILED`
audit event. The full exception remains in the server log for troubleshooting.

## Deployment note

This is a deliberately small in-process worker runner for the local Flask
deployment. Job state is persisted, but the executor itself is process-local;
Task 19/20 production deployment work should replace it with a durable queue
when multiple application processes are used.
