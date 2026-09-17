# Evidence Relationships and Infrastructure Clusters

Task 13 turns retained case evidence into explainable domain relationships and
confidence-scored infrastructure clusters.

## Building correlations

In a case, click **Build infrastructure clusters** after collecting evidence
for two or more domains. GambleTrace compares domains within that case using:

- direct redirect links
- shared resolved IP addresses
- shared TLS certificate fingerprints
- shared nameserver records
- identical normalized HTML hashes
- shared favicon hashes
- shared ASN
- generated-variation parent links

Each domain pair becomes one Correlated Infrastructure edge. The edge stores
the exact signals, point contributions, total score, confidence, and links to
supporting retained artifacts when available.

## Confidence and clusters

Task 12 assigns points to each explicit signal. A relationship is Low,
Medium, or High confidence according to that visible score. Only Medium and
High edges join connected domains into an Infrastructure cluster.

Each cluster lists its members, confidence, and the signals that caused the
connection. A relationship is an investigative lead, not evidence of common
ownership, legal responsibility, or illegal activity.

## Current limits

To reduce false positives from broadly shared providers, shared-value groups
with more than twelve domains are ignored during automatic pair creation.
Clusters are currently derived synchronously from one case. The interactive
graph viewer, filters, and node-detail panels are part of Task 15.
