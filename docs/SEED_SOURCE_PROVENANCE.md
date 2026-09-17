# Seed Source Provenance

Every valid seed upload in the Case Workspace is now retained as an investigation source artifact.

## Collection flow

```text
Upload seed file
  -> Validate allowed extension
  -> Save a case-specific immutable copy
  -> Calculate SHA-256 and file metadata
  -> Parse normalized domains from that saved copy
  -> Store source metadata in SQLite
  -> Link each newly imported case-domain to the source file
  -> Record a source-import audit event
```

## Stored source files

Case seed files are stored outside the SQLite database under:

```text
data/cases/<case-id>/sources/<source-id>_<sanitized-original-name>
```

The `source_files` table records:

- Source file UUID
- Original file name
- Repository-relative storage path
- SHA-256 hash
- File size in bytes
- MIME type
- Case ID
- Import timestamp

The case-domain link also records `source_file_id`, making it possible to identify which retained source introduced every seed domain.

## Supported formats

- CSV
- XLSX
- XLS
- TXT

Invalid or unsupported uploads are not recorded. A saved file that produces no valid domain is removed before it enters the database.

## Domain normalization rules

- URLs are parsed safely rather than stripped with string replacement.
- Hostnames are lower-cased, port/path/query data is removed, and trailing dots are removed.
- Internationalized names are converted to IDNA form where possible.
- Registrable domains are derived with `tldextract`.
- Plain IP addresses and IP-like hostnames are rejected before registrable-domain extraction.
- Invalid public-suffix, overlong-label, malformed, and space-containing values are rejected.

## Integrity boundary

This task establishes provenance for the **input seed file**. Full evidence manifests and hashes for website screenshots, HTML, HTTP headers, DNS, TLS, and other collected artifacts are implemented later in Items 7 and 8.
