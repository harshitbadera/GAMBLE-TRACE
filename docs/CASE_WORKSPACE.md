# Case Workspace

The Case Workspace is the first investigator-facing part of GambleTrace. Open it at:

```text
http://localhost:5000/cases
```

## Available actions

- Create a case with a title, priority, owner, scope, and authorization note.
- View a register of active, monitoring, escalated, and closed cases.
- Import normalized seed domains from CSV, XLSX, XLS, or TXT files.
- Add analyst notes.
- Add reusable coloured tags.
- Move a case through its defined workflow status.
- Record manual domain observations and review their append-only timeline.
- View the first 100 case domains and recent audit activity.

## Current data behaviour

- A domain is normalized and stored once globally, then linked to the active case as a `SEED`.
- Re-importing an existing domain into the same case does not create a duplicate case-domain record.
- Seed-import events, note additions, tag additions, status changes, and case creation are recorded in the audit log.
- The original uploaded seed file is retained under the case storage directory, hashed with SHA-256, recorded in `source_files`, and linked to each newly imported seed domain.

## Route map

| Route | Purpose |
| --- | --- |
| `GET /cases` | Case workspace and investigation register |
| `GET, POST /cases/new` | Case creation |
| `GET /cases/<case_id>` | Case detail workspace |
| `POST /cases/<case_id>/seeds` | Seed-domain import |
| `POST /cases/<case_id>/notes` | Analyst note creation |
| `POST /cases/<case_id>/observations` | Append-only manual domain observation |
| `POST /cases/<case_id>/tags` | Case tag creation/attachment |
| `POST /cases/<case_id>/status` | Case workflow status update |

## Next step

Task 6 adds historical domain observations so later collection runs preserve change over time rather than overwriting prior results.
