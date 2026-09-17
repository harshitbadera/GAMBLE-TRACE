# Evidence Artifacts and Chain of Custody

Task 8 turns each technical collection into a retained evidence package. It
builds on the immutable observation created by Task 7.

## Package layout

Files are stored under the configured case storage directory:

```text
cases/<case-id>/evidence/<observation-id>/
  acquisition.json
  http_headers.json
  redirect_chain.json
  dns_records.json
  rdap_records.json
  content_fingerprint.json
  page.html                 # only when an HTML response was collected
  favicon.bin               # only when a same-origin favicon was collected
  screenshot.png            # only when browser capture succeeded
  artifact_manifest.json
```

The screenshot is copied from the browser collector's temporary output into
the case-specific evidence directory. It is no longer dependent on that
temporary output after collection succeeds.

## Integrity record

Every retained file is SHA-256 hashed immediately after it is written. Its
type, case-relative path, hash, size, MIME type, source URL, and observation
link are recorded in `evidence_artifacts`.

`artifact_manifest.json` lists every collected artifact except itself. Its own
SHA-256 hash is also recorded in `evidence_artifacts`, and `evidence_manifests`
links that hash to the case and observation. This avoids a circular manifest
hash while allowing the manifest file itself to be verified.

SQLite triggers prevent updates or deletion of artifact and manifest metadata.
To correct an error or collect a newer page, run a new collection: it creates a
new observation and a separate package rather than changing historic evidence.

## Verification

The `verify_evidence_package` service re-hashes the stored paths against their
database values and returns lists of `missing` or `altered` artifacts. A
dedicated evidence viewer and user-facing verification action will be added in
the frontend work; the integrity service is already available for reports and
automated checks.

## Current boundary

The package preserves raw collection artifacts and their integrity metadata.
Digital signatures, encrypted evidence storage, access control, retention
rules, evidence ZIP export, and investigator-facing downloads are later tasks.
