# Case reports and investigator exports

Task 18 adds the **Exports** view at:

```text
/cases/<case_id>/exports
```

Exports are generated only from data already retained in the current case.
They do not trigger fresh DNS, HTTP, browser, RDAP, or other collection.

## Available exports

| Export | Format | Contents |
| --- | --- | --- |
| Case intelligence report | Markdown | Scope, case summary, priority domains, correlation edges, monitoring alerts, and interpretation boundary. |
| IOC export | CSV | Typed domain, URL, IP, ASN, nameserver, and TLS SHA-256 indicators. |
| IOC export | JSON | The same typed indicators with source and first/last observed values. |
| Blocklist candidate | TXT | Domain, URL, and IP values for review before any enforcement use. |
| Investigation graph | JSON | Nodes, evidence-backed edges, scores, signals, and filter metadata. |
| Investigation graph | GraphML | Graph-analysis compatible node and edge data. |
| Evidence package | ZIP | Evidence and preserved seed source files plus integrity verification results. |

## Evidence ZIP verification

The package includes `evidence_verification.json`. Before a stored evidence or
source file is included, GambleTrace recomputes its SHA-256 hash and compares
it to the retained database value.

- `MATCH`: file is included and its hash matches.
- `MISSING`: expected file was not available; it is not included.
- `HASH_MISMATCH`: file did not match the retained hash; it is not included.

This makes integrity failures explicit instead of silently packaging altered
data.

## Interpretation boundary

IOC and graph exports are investigative material. Shared hosting, certificates,
or nameservers can be legitimate. Review the case evidence and applicable
authority before blocking, sharing, or escalating an indicator.

## Verification

```powershell
python -B -m unittest tests/test_case_exports.py
```

The test uses a synthetic evidence file and confirms that the ZIP contains the
artifact only after a successful hash verification.
