# Interactive investigation graph

Task 15 adds a case-scoped interactive graph at:

```text
/cases/<case_id>/graph
```

It visualizes only persisted `CORRELATED_INFRASTRUCTURE` relationships between
case domains. The page does not perform new collection, change scores, or
create a new relationship.

## What is shown

- **Node:** one domain in the current case. Its color reflects its current
  explainable risk score: red for high, amber for medium, cyan for lower or
  unscored.
- **Edge:** an evidence-backed correlation edge created by Task 13.
  High-confidence edges are visually stronger.
- **Node detail panel:** risk, relevance, availability, discovery provenance,
  cluster names, and a direct link to the domain evidence profile.
- **Edge detail panel:** confidence score, first/last observed timestamps,
  artifact-link count, and the exact signals used by the correlation scorer.

## Filters

The browser can filter the current graph by:

- relationship confidence (high, medium, or low);
- a required correlation signal, such as shared certificate or shared IP;
- current domain risk range;
- domain-name search; and
- whether unconnected case domains are shown.

Filtering happens only in the browser. It never deletes or hides stored
evidence from the case record.

## Interpretation boundary

Graph edges are technical correlations. Shared certificates, hosting, HTML, or
nameservers may have legitimate explanations. The graph is designed to guide
review of the preserved artifacts, not to make an attribution or illegality
decision on its own.
