# Historical monitoring and alerts

Task 17 makes consecutive evidence collections comparable. A domain's first
technical observation is its baseline. Each later collection is compared with
the immediately preceding immutable observation.

## Monitored evidence

| Alert type | Compared evidence | Default severity |
| --- | --- | --- |
| `DNS_INFRASTRUCTURE_CHANGE` | A, AAAA, CNAME, and nameserver records | Medium |
| `TLS_CERTIFICATE_CHANGE` | TLS certificate SHA-256 fingerprints | Medium |
| `REDIRECT_DESTINATION_CHANGE` | Redirect targets and final HTTP URL | High |
| `CONTENT_FINGERPRINT_CHANGE` | Normalized HTML and favicon fingerprints | Medium |
| `HOSTING_ASN_CHANGE` | RDAP network, ASN, and provider values | Medium |
| `AVAILABILITY_CHANGE` | Historical availability recorded with each observation | Medium or High |

An alert stores both the prior and current evidence values, the relevant case
domain, timestamp, severity, and analyst status. It is not a claim that the
change is malicious; certificates, hosting, and content can legitimately
change.

## Analyst workflow

1. Collect a technical snapshot for a case domain.
2. Collect it again later through the normal **Collect evidence** action.
3. Review any new alert from the case overview or `/cases/<case_id>/alerts`.
4. Expand **Compare retained values** and inspect the associated domain
   evidence profile.
5. Acknowledge the alert while investigating, then resolve it after recording
   the outcome in a case note or report.

Alert creation and status changes are written into the case audit timeline.

## Historical availability

Migration 010 adds availability to `domain_observations`. Existing historical
rows receive the conservative `UNKNOWN` default; new observations retain the
actual state observed at collection time.

## Verification

```powershell
python -B -m unittest tests/test_monitoring.py
```

The test creates synthetic snapshots with a DNS and availability change. It
does not perform a live collection.
