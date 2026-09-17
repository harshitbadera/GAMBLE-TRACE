# Evidence Collection

Item 7 adds a user-triggered technical collector to the case workspace. An
analyst selects a case domain and chooses **Collect technical evidence**. The
collector creates one new, append-only observation; it never rewrites an older
collection result.

## Collection scope

Each run records the following structured results when they are available:

- DNS: A, AAAA, CNAME, NS, MX, TXT, and SOA answers with TTLs.
- HTTP: request and final URL, status, response headers, content type, body
  size, page title, SHA-256 content hash, and redirect chain.
- Infrastructure: resolved IP addresses, IP version, RDAP response, ASN,
  provider description, network name/CIDR, and country code.
- Screenshot: an optional full-page Playwright screenshot result.

The evidence is associated with the observation through `dns_records`,
`observation_ips`, `http_responses`, `rdap_records`, `redirects`, and
`screenshot_captures`. The schema migration is version 4.

## Safety and operating model

Collection is initiated by an analyst for a domain already attached to a case.
It does not run as a background monitor. Web and browser collection are skipped
when DNS does not return a globally routable IP address; DNS results and the
reason for the skip are still recorded. This is a safeguard against private or
local-address DNS responses.

Network failures are retained as partial collection evidence instead of hiding
the run. A successful HTTP response below 500 marks the current case-domain
state as `ACTIVE`; other results remain `UNKNOWN` or `UNRESOLVED` until an
analyst reviews them.

## Current boundary

This item persists technical metadata and an optional screenshot path. The
next item will retain downloaded artifacts such as HTML and header files,
calculate hashes for every file, and create an evidence manifest /
chain-of-custody record. A stored screenshot is therefore not yet a complete
forensic evidence package on its own.
