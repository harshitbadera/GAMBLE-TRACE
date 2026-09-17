# TLS Certificate Intelligence

Task 9 extends a technical evidence collection with direct TLS handshakes to
the domain's already-resolved, globally routable IP addresses. The original
domain is retained as SNI, while the connection goes to the observed IP rather
than performing another hostname resolution.

## Collected certificate evidence

For every reachable TLS endpoint, GambleTrace retains:

- SHA-256 fingerprint of the raw DER certificate
- subject, issuer, serial number, and validity dates
- DNS Subject Alternative Names (SANs)
- IP endpoint, negotiated TLS version, and cipher name
- raw DER certificate and TLS metadata JSON in the evidence package
- collection errors when a TLS handshake or certificate parse fails

Certificate verification is disabled only for evidence acquisition: expired,
self-signed, and otherwise untrusted certificates can still be relevant to an
investigation. The resulting certificate is not treated as trusted.

## Correlation and pivots

Certificates are de-duplicated by their SHA-256 fingerprint in
`tls_certificates`. Each observation is connected through
`observation_certificates`, and SAN values are retained in `certificate_names`.

The case workspace shows **TLS certificate pivots**, identifying case domains
that share a certificate fingerprint. Shared reuse is a technical relationship
and an investigative lead, not proof of common ownership or illegal activity.

This task correlates domains already observed in the same case. Querying
external certificate-transparency sources for new candidate domains is part of
the broader discovery work in Task 10.

## Integrity

The raw DER certificate and TLS metadata are included in the Task 8 evidence
manifest, hashed with SHA-256, and protected as immutable evidence metadata.
Migration 006 additionally records append-only TLS handshake context.
