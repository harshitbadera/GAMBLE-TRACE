# Investigation workspace

Task 14 turns the case UI into an analyst-oriented investigation console. It is
intended to make retained evidence understandable without changing the
collection, scoring, or correlation rules.

## Views

| View | Route | Purpose |
| --- | --- | --- |
| Case register | `/cases` | Find investigations and see their workflow state. |
| Case overview | `/cases/<case_id>` | Import seeds, run authorised operations, inspect domain inventory, signals, and clusters. |
| Domain evidence profile | `/cases/<case_id>/domains/<case_domain_id>` | Review technical records, collection history, artifacts, and start a new collection. |
| Evidence register | `/cases/<case_id>/evidence` | Browse hash-registered artifacts across the case and download only case-owned files. |
| Cluster detail | `/cases/<case_id>/clusters/<cluster_id>` | Review members, confidence, relationship signals, and evidence-link counts. |
| Case timeline | `/cases/<case_id>/timeline` | Combine audit activity and immutable domain observations in UTC order. |

## Analyst flow

1. Create a case and record scope and authorization.
2. Import the seed-domain source file from the case overview.
3. Open a domain profile and run authorised collection.
4. Review stored artifacts through the evidence register.
5. Run scoring and correlation after evidence exists for multiple domains.
6. Inspect each cluster's relationship signals before treating it as a lead.
7. Use the timeline to review what occurred and when.

## Integrity and access boundaries

- The frontend reads historical observations rather than replacing them.
- Artifact downloads require both the case ID and artifact ID; the server checks
  that the artifact belongs to that case and that its path remains under the
  configured case-storage directory.
- Cluster relationships are presented as investigative correlations, not proof
  of common ownership or illegality.

## Verification

Run the local UI smoke test:

```powershell
python -B -m unittest tests/test_task14_views.py
```

The test creates only synthetic domains and a temporary SQLite database. It
does not run collection or contact the network.
