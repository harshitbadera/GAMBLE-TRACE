# GambleTrace

> A threat-intelligence and digital-evidence framework for investigating suspected illegal online gambling infrastructure.

GambleTrace starts with known or suspected gambling domains and turns them into an investigation: it discovers related infrastructure, preserves technical evidence, identifies probable operational clusters, and monitors how those networks change over time.

> **Research and authorized-investigation use only.** A technical relationship or keyword match is an investigative lead, not proof that a person, organization, or website is illegal.

## The problem

Illegal gambling operations commonly rotate domains, hosting providers, certificates, and redirect destinations. Looking at one domain in isolation makes it easy to miss the larger network.

GambleTrace is designed to answer questions such as:

- Which domains are likely related to this seed domain?
- What IPs, certificates, nameservers, redirects, and hosting providers connect them?
- Which connections are strong enough to form a probable infrastructure cluster?
- What evidence was collected, when was it collected, and has it changed over time?
- Which indicators should an investigator monitor, block, share, or review further?

## Investigation lifecycle

```text
Seed domains
  -> Validation and initial evidence
  -> Domain and infrastructure discovery
  -> Evidence acquisition and hashing
  -> Classification and prioritisation
  -> Relationship graph and clustering
  -> Historical monitoring and mutation alerts
  -> Case evidence package, IOC exports, and incident report
```

### From 30 seed domains to an investigation outcome

```text
30 seed domains
  -> active, offline, redirected, or unresolved domains
  -> DNS-valid domain variants and discovered related domains
  -> live-domain technical evidence
  -> evidence-backed relationships
  -> confidence-scored infrastructure clusters
  -> time-based monitoring of network changes
  -> investigator-ready case report and IOC set
```

The aim is not simply to produce a longer list of domains. The aim is to produce findings such as:

```text
Cluster GT-C-014 — High confidence

23 related domains
4 IP addresses
2 TLS certificates
Shared redirect behaviour
Shared content fingerprint
India-focused payment indicators

Evidence: timestamped, hashed, and attached to Case GT-2026-001
```

## Current prototype

The current Flask dashboard implements the first intelligence-collection layer:

| Step | Capability | Current output |
| --- | --- | --- |
| 1 | Generate gambling-domain variants and validate them through parallel DNS lookups | CSV of DNS-resolving domains and IPs |
| 2 | Resolve infrastructure and pivot from non-CDN IP addresses | Infrastructure CSV and reverse-IP discovery CSV |
| 3 | Check liveness, capture browser screenshots, and generate a report | DOCX liveness report |
| 4 | Inspect homepage content and search for relevant indicators | CSV with title, size, keyword, and credential-scan results |

### Current data sources and techniques

- DNS resolution: A and AAAA records through Google and Cloudflare DNS
- Infrastructure enrichment: RDAP/IPWhois for ASN, provider, and country
- Reverse-IP discovery: HackerTarget reverse-IP lookup for non-CDN infrastructure
- Web evidence: HTTP status, redirects, page title, HTML content, and screenshots
- Content indicators: gambling, India-focused, payment, and exposed-credential patterns

## Target architecture

The project will evolve from a four-step OSINT dashboard into a case-based investigation platform.

```text
Case
  |
  +-- Seed domains
  +-- Observations over time
  +-- Evidence artifacts
  +-- Indicators of compromise
  +-- Relationship graph
  +-- Infrastructure clusters
  +-- Analyst notes and actions
  +-- Final intelligence report
```

## Full workflow

### 1. Create a case and preserve the original seeds

An investigator opens a case and imports known or suspected domains.

```text
Case ID: GT-2026-001
Case name: Suspected Gambling Infrastructure Investigation
Initial seeds: 30 domains
Status: Open
```

The original seed file is preserved and hashed. Each seed receives a first-observed timestamp and a clear source label.

**Outputs**

- Case metadata
- Original seed list
- SHA-256 hash of the source file
- Audit log of collection actions

### 2. Validate and normalize every seed

Each supplied domain is normalized, deduplicated, and tested.

- Normalize URLs to registrable domains
- Validate domain format
- Resolve DNS records
- Check HTTP/HTTPS liveness
- Record HTTP status and final URL
- Capture redirect chains
- Retain offline and unresolved domains for historical tracking

**Example outcome**

```text
30 supplied seeds
  |- 22 active
  |- 4 offline
  |- 2 redirected
  `- 2 unresolved or invalid
```

### 3. Discover potentially related domains

New candidates are collected from multiple pivots.

#### Domain variation discovery

Generate brand, suffix, prefix, number, and TLD variations, then validate them through DNS.

```text
examplebet.com
  |- examplebet.in
  |- examplebet247.com
  |- playexamplebet.com
  `- examplebet.live
```

#### Redirect discovery

Record every destination in a redirect chain.

```text
examplebet.com
  -> examplebet-login.net
  -> play-example.xyz
```

#### Reverse-IP discovery

For dedicated, non-CDN IP addresses, identify other hosted domains and filter them for investigation relevance.

#### TLS-certificate discovery

Use certificate fingerprints and Subject Alternative Names to identify certificate reuse and related domains.

#### Other pivots

- Shared nameservers
- Shared dedicated IPs or hosting networks
- Shared redirect destinations
- Similar HTML, favicon, or title fingerprints
- Similar naming and registration patterns
- Similar payment and India-targeting indicators

Every discovered domain is labelled according to its source:

```text
Seed | Generated candidate | DNS-resolving | Live | Related infrastructure | Requires review
```

### 4. Acquire structured digital evidence

For each relevant domain, GambleTrace creates a timestamped evidence package.

```text
cases/
  GT-2026-001/
    evidence/
      examplebet.com/
        acquisition.json
        screenshot.png
        page.html
        headers.json
        redirect_chain.json
        dns_records.json
        tls_certificate.json
        rdap.json
        network.json
        artifact_manifest.json
```

The target evidence collection set is:

- Full-page browser screenshot
- Raw HTML snapshot
- HTTP response headers and status codes
- Redirect chain
- DNS records: A, AAAA, CNAME, NS, MX, and TXT
- IP addresses, ASN, network, country, and hosting organization
- RDAP/WHOIS response data
- TLS certificate issuer, serial number, validity, SANs, and fingerprint
- Page title, HTML hash, favicon hash, and content fingerprint
- Gambling, payment, and India-targeting indicators
- Acquisition timestamp in UTC
- SHA-256 hash for every saved artifact

The artifact manifest ties each collected file to its source URL, hash, collection time, and collector/tool version.

### 5. Classify and prioritise findings

Domains are scored using visible and explainable evidence rather than a black-box conclusion.

| Signal | Example |
| --- | --- |
| Gambling indicators | Betting, casino, slots, rummy, deposit, withdrawal |
| India targeting | INR, UPI, Paytm, PhonePe, IPL, cricket |
| Payment indicators | UPI, card payments, cryptocurrency, payout references |
| Redirect behaviour | Redirects to a known or suspected gambling domain |
| Domain similarity | Brand variation, mirror, or typo-style variation |
| Infrastructure overlap | Certificate, dedicated IP, nameserver, or hosting relationship |
| Historic behaviour | Hosting, certificate, or redirect changed after an event |

Suggested classifications:

```text
High-confidence suspected gambling
Medium-confidence suspected gambling
Related infrastructure
Low-confidence candidate
Insufficient evidence
Not gambling-related
```

### 6. Build an investigation graph

The graph is the central intelligence view. It represents entities as nodes and evidence-backed relationships as edges.

```text
examplebet.com
  |- resolves_to ----------> 185.x.x.x
  |- uses_nameserver ------> ns1.provider.net
  |- presents_certificate -> cert:abc123
  |- redirects_to ---------> playexample.xyz
  |- shares_favicon_with --> winexample.net
  `- collected_in ---------> GT-2026-001
```

**Graph nodes**

- Domains and URLs
- IP addresses
- ASNs and hosting providers
- Nameservers
- TLS certificates
- Redirect destinations
- Content and favicon fingerprints
- Payment indicators
- Evidence artifacts

**Graph edges**

Each edge stores its source, collection timestamp, supporting evidence, and confidence. This matters because a shared cloud-provider IP is weak evidence, while a direct redirect or a rare shared certificate can be strong evidence.

### 7. Form confidence-scored infrastructure clusters

The system groups domains that share multiple meaningful signals.

```text
Cluster GT-C-014
Confidence: High

23 domains
4 IP addresses
2 TLS certificates
3 nameservers
Shared HTML/favicon fingerprint
Shared redirect behaviour
India-focused payment indicators
```

A cluster must always explain *why* it was formed.

```text
Evidence supporting the cluster
- 11 domains redirect to one final destination
- 14 domains reuse the same TLS certificate
- 8 domains share a non-CDN dedicated IP
- 17 domains share a content fingerprint
```

Shared CDN IPs, common cloud hosting, or a similar domain name by themselves should be treated as weak signals, not proof of a common operator.

### 8. Monitor infrastructure mutation over time

Observations are retained historically rather than overwritten.

```text
1 Sep: examplebet.com -> 1.1.1.1
7 Sep: examplebet.com -> 2.2.2.2
8 Sep: examplebet.net -> 2.2.2.2
9 Sep: both domains present the same TLS certificate
```

The monitoring system can generate alerts for:

- DNS, ASN, or hosting changes
- TLS certificate replacement or reuse
- Redirect-destination changes
- Newly active or newly offline domains
- New domains joining an existing cluster
- Content, favicon, payment, or language changes
- Possible infrastructure migration after disruption or takedown activity

### 9. Produce investigation outputs

At the end of a case, the investigator receives:

#### Case dashboard

- Case status and analyst notes
- Seed, discovered, live, and high-priority domain counts
- High-confidence clusters
- Recent mutations and alerts
- Top IPs, ASNs, nameservers, providers, and certificates

#### Evidence package

A downloadable, structured package containing the captured artifacts, timestamps, hashes, and manifest.

#### Investigation graph

An interactive graph with filters for certificates, redirects, dedicated IPs, ASNs, countries, active status, cluster confidence, and recent changes.

#### IOC exports

```text
Domains | URLs | IPs | ASNs | Nameservers | TLS fingerprints | Redirect destinations | Content hashes
```

Planned formats include CSV, JSON, STIX-like JSON, and blocklist-ready text.

#### Incident and intelligence report

```text
Executive summary
Case scope and seed domains
Key findings and priority clusters
Observed indicators
Infrastructure relationships
Evidence and SHA-256 manifests
Timeline of observations and mutations
Recommended investigative actions
Technical appendices
```

## Project roadmap

### Phase 1 — Evidence-first investigations

- [x] Domain expansion and parallel DNS validation
- [x] Infrastructure enrichment and reverse-IP pivoting
- [x] Liveness checks and screenshot reports
- [x] Homepage content analysis
- [ ] Case creation and case metadata
- [ ] Structured evidence folders
- [ ] SHA-256 artifact hashing and manifests
- [ ] DNS, HTTP-header, redirect, and raw-HTML evidence capture

### Phase 2 — Intelligence correlation

- [ ] TLS certificate collection and pivoting
- [ ] Content, HTML, and favicon fingerprinting
- [ ] Explainable domain-risk scoring
- [ ] Relationship graph with evidence-backed edges
- [ ] Confidence-scored infrastructure clustering

### Phase 3 — Monitoring and reporting

- [ ] Historical observation database
- [ ] Infrastructure mutation detection
- [ ] Scheduled monitoring and alerts
- [ ] Analyst notes, tags, and audit trail
- [ ] IOC exports
- [ ] Case-level intelligence and incident reports

## Repository structure

```text
gambling_osint/
├── app.py                         # Flask dashboard and API endpoints
├── quick_expand.py                # Domain variation generation and DNS validation
├── screenshot_manager.py          # Playwright screenshots and DOCX reports
├── utils.py                       # Domain, Excel, CSV, and progress helpers
├── config.py                      # Paths, keywords, and operational settings
├── main2.py                       # Original one-domain infrastructure lookup CLI
├── templates/
│   └── index.html                 # Dashboard frontend
├── data/
│   └── manual_domains.txt         # Optional manually maintained domain list
├── output/                        # Generated artifacts and reports
└── requirements.txt               # Python dependencies
```

## Installation

### Prerequisites

- Python 3.9 or later

### Setup

```bash
git clone https://github.com/harshitbadera/Gambling-Sites-OSINT.git
cd Gambling-Sites-OSINT

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
playwright install chromium
```

### Run the dashboard

```bash
python app.py
```

Open `http://localhost:5000`.

### Run standalone domain expansion

```bash
python quick_expand.py
python quick_expand.py --input found.csv
python quick_expand.py --input my_seeds.xlsx
python quick_expand.py --workers 80
```

### Run the original single-domain infrastructure lookup

```bash
python main2.py
```

## Important limitations and responsible use

- DNS resolution does not prove that a domain hosts gambling content.
- Shared CDN, cloud-provider, or common nameserver infrastructure is not sufficient evidence of common ownership.
- Automated classification produces investigative leads that require analyst review.
- Reverse-IP services can be rate-limited and may return incomplete data.
- Evidence collection must be performed only with appropriate legal authority and in accordance with applicable policy.
- Captured artifacts can contain sensitive information and should be stored, shared, and retained securely.

## Future research direction

The primary research contribution is intended to be the combination of:

1. Evidence-preserving collection for suspected gambling infrastructure.
2. Explainable graph-based correlation of domains and technical infrastructure.
3. Confidence-scored identification of probable operational clusters.
4. Temporal detection of infrastructure mutation and migration.

## License

For educational, research, and authorized investigative use only.
