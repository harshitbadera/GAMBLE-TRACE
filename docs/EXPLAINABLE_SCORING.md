# Explainable Risk and Relationship Scoring

Task 12 adds visible, repeatable scoring. Scores prioritize what was observed
in a case; they are investigative triage aids, not proof that a website,
person, or organization is engaged in illegal activity.

## Domain risk score

Each case-domain can be scored from 0 to 100. The current score and relevance
are shown in the seed-domain table, while the Risk assessments panel lists the
factor labels and points used for each domain.

| Evidence factor | Maximum points |
| --- | ---: |
| Gambling-related words in the domain | 15 |
| Visible gambling indicators | 35 |
| Visible payment indicators | 20 |
| Visible India-targeting indicators | 15 |
| Active endpoint | 5 |
| Observed redirect behaviour | 8 |
| Pivot provenance | 8 |

Current thresholds:

| Score | Relevance |
| --- | --- |
| 65–100 | High-confidence suspected gambling |
| 35–64 | Medium-confidence suspected gambling |
| 15–34 | Low-confidence candidate |
| 0–14 | Insufficient evidence |

Click **Score case domains** after collecting evidence. Every run creates a
new immutable assessment with the factors, scorer version, timestamp, score,
and relevance. The case-domain row changes only to show the latest score and
relevance.

## Relationship confidence

The service also provides a reusable confidence calculation for Task 13.
It adds points only for explicit signals:

| Signal | Points |
| --- | ---: |
| Redirect chain | 35 |
| Shared dedicated IP | 30 |
| Identical normalized HTML | 28 |
| Shared certificate | 25 |
| Shared favicon | 15 |
| Shared nameserver | 12 |
| Domain variation | 8 |
| Same ASN | 5 |

Relationship confidence is High at 60+, Medium at 30–59, and Low below 30.
Task 13 will use this calculator to write relationship edges and build
infrastructure clusters.

## Interpretation

Technical overlap can arise from shared hosting, a common template, CDN
behaviour, or legitimate providers. The score makes the basis for review
visible; it must not be used as the sole basis for enforcement, blocking, or
attribution.
