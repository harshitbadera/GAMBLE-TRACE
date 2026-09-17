# Case Discovery Pivots

Task 10 adds analyst-triggered discovery to a specific case domain. In the
case workspace, choose a domain, select one or more pivots, and click
**Discover related domains**. Any new candidate is linked to that case with
its source type, source domain, and pivot details; it can then be collected as
ordinary technical evidence.

## Available pivots

| Pivot | What it uses | Candidate source label |
| --- | --- | --- |
| DNS-validated variants | A bounded set of transparent, seed-derived name/TLD variations | `GENERATED_VARIATION` |
| Redirect destinations | Redirect URLs retained during earlier collections | `REDIRECT_PIVOT` |
| Reverse IP | HackerTarget reverse-IP results for observed, non-CDN IPv4 addresses; name-filtered candidates only | `REVERSE_IP_PIVOT` |
| TLS SANs | Subject Alternative Names of certificates observed for the selected domain | `TLS_PIVOT` |
| Shared nameserver | Previously observed domains using the same NS record | `NAMESERVER_PIVOT` |
| Identical content hash | Previously retained observations with the exact same page-content hash | `CONTENT_PIVOT` |

## Operating limits

Discovery is intentionally synchronous and bounded at this stage:

- It runs only after an analyst selects a case domain and pivot methods.
- Variant generation is seed-derived and DNS-validated; it does not use the
  large generic brand list from the old standalone expansion script.
- Reverse IP considers up to ten observed IPv4 addresses and skips configured
  high-volume CDN/cloud ASNs.
- Nameserver and content pivots correlate already-collected GambleTrace data.

Task 16 will move longer-running work to background jobs with progress,
retries, rate limiting, and cancellation. Task 11 will add richer content and
favicon fingerprints; Task 13 will turn these candidate links into scored
relationship-graph edges and clusters.

## Interpretation

A discovery source explains why a candidate was added; it is not a conclusion
that the candidate is illegal or controlled by the same operator. Analysts
should collect evidence, review the observation history, and apply the later
scoring model before making a finding.
