"""Case-scoped discovery pivots with explicit provenance for every candidate."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
import uuid
from typing import Callable, Dict, Iterable

import tldextract

from gambletrace.persistence import Database
from gambletrace.services.infrastructure import (
    GAMBLING_FILTER_KEYWORDS,
    SKIP_ASNS,
    reverse_ip_lookup,
)
from quick_expand import check_dns
from utils import is_valid_domain, normalize_domain


DISCOVERY_MODES = {
    "variants": "GENERATED_VARIATION",
    "redirects": "REDIRECT_PIVOT",
    "reverse_ip": "REVERSE_IP_PIVOT",
    "tls": "TLS_PIVOT",
    "nameserver": "NAMESERVER_PIVOT",
    "content": "CONTENT_PIVOT",
}
VARIANT_TLDS = (".com", ".in", ".net", ".live", ".online", ".bet", ".site", ".xyz")
VARIANT_SUFFIXES = ("247", "live", "online", "india", "play")
VARIANT_PREFIXES = ("play", "go", "my", "live")


def _record_audit_event(connection, case_id: str, event_type: str, payload: Dict) -> None:
    connection.execute(
        """
        INSERT INTO audit_events (id, case_id, event_type, event_data_json)
        VALUES (?, ?, ?, ?)
        """,
        (str(uuid.uuid4()), case_id, event_type, json.dumps(payload, sort_keys=True)),
    )


def _source_domain(database: Database, case_id: str, case_domain_id: str) -> Dict:
    with database.connect() as connection:
        row = connection.execute(
            """
            SELECT case_domains.id, domains.canonical_name
            FROM case_domains JOIN domains ON domains.id = case_domains.domain_id
            WHERE case_domains.id = ? AND case_domains.case_id = ?
            """,
            (case_domain_id, case_id),
        ).fetchone()
    if not row:
        raise LookupError("Domain is not part of this case")
    return dict(row)


def generate_case_variants(domain: str) -> set[str]:
    """Generate a bounded set of transparent, seed-derived domain variations."""
    extracted = tldextract.extract(domain)
    base = extracted.domain.lower()
    core = re.sub(r"(india|ind|online|live|pro|247|game|games|play)$", "", base)
    core = re.sub(r"\d+$", "", core) or base
    candidates: set[str] = set()
    for tld in VARIANT_TLDS:
        candidates.add(f"{base}{tld}")
        candidates.add(f"{core}{tld}")
    for suffix in VARIANT_SUFFIXES:
        for tld in VARIANT_TLDS[:5]:
            candidates.add(f"{core}{suffix}{tld}")
    for prefix in VARIANT_PREFIXES:
        for tld in VARIANT_TLDS[:4]:
            candidates.add(f"{prefix}{core}{tld}")
    candidates.discard(domain)
    return {candidate for candidate in candidates if is_valid_domain(candidate)}


def _validate_variants(
    domain: str,
    dns_validator: Callable[[str], tuple[str, str | None]],
) -> list[Dict]:
    candidates = generate_case_variants(domain)
    discovered: list[Dict] = []
    with ThreadPoolExecutor(max_workers=min(12, max(1, len(candidates)))) as executor:
        futures = {executor.submit(dns_validator, candidate): candidate for candidate in candidates}
        for future in as_completed(futures):
            candidate, ip_address = future.result()
            normalized = normalize_domain(candidate)
            if normalized and ip_address:
                discovered.append(
                    {
                        "domain": normalized,
                        "source_type": "GENERATED_VARIATION",
                        "detail": {"pivot": "seed_derived_variant", "resolved_ip": ip_address},
                    }
                )
    return discovered


def _redirect_candidates(database: Database, case_domain_id: str) -> list[Dict]:
    with database.connect() as connection:
        rows = connection.execute(
            """
            SELECT redirects.source_url, redirects.target_url, redirects.status_code
            FROM redirects
            JOIN domain_observations ON domain_observations.id = redirects.observation_id
            WHERE domain_observations.case_domain_id = ?
            """,
            (case_domain_id,),
        ).fetchall()
    return [
        {
            "domain": normalized,
            "source_type": "REDIRECT_PIVOT",
            "detail": {
                "pivot": "observed_redirect",
                "source_url": row["source_url"],
                "target_url": row["target_url"],
                "http_status": row["status_code"],
            },
        }
        for row in rows
        if (normalized := normalize_domain(row["target_url"]))
    ]


def _reverse_ip_candidates(
    database: Database,
    case_domain_id: str,
    lookup: Callable[[str], list[str]],
) -> tuple[list[Dict], list[str]]:
    with database.connect() as connection:
        rows = connection.execute(
            """
            SELECT DISTINCT ip_addresses.address, asns.asn_number
            FROM domain_observations
            JOIN observation_ips ON observation_ips.observation_id = domain_observations.id
            JOIN ip_addresses ON ip_addresses.id = observation_ips.ip_id
            LEFT JOIN observation_asns
                ON observation_asns.observation_id = domain_observations.id
                AND observation_asns.ip_id = ip_addresses.id
            LEFT JOIN asns ON asns.id = observation_asns.asn_id
            WHERE domain_observations.case_domain_id = ? AND ip_addresses.version = 4
            LIMIT 10
            """,
            (case_domain_id,),
        ).fetchall()
    discovered: list[Dict] = []
    errors: list[str] = []
    for row in rows:
        if row["asn_number"] in SKIP_ASNS:
            continue
        try:
            names = lookup(row["address"])
        except Exception as error:
            errors.append(f"Reverse IP {row['address']}: {error}")
            continue
        for name in names:
            normalized = normalize_domain(name)
            if not normalized or not any(word in normalized for word in GAMBLING_FILTER_KEYWORDS):
                continue
            discovered.append(
                {
                    "domain": normalized,
                    "source_type": "REVERSE_IP_PIVOT",
                    "detail": {
                        "pivot": "reverse_ip",
                        "ip_address": row["address"],
                        "asn_number": row["asn_number"] or "",
                    },
                }
            )
    return discovered, errors


def _tls_candidates(database: Database, case_domain_id: str) -> list[Dict]:
    with database.connect() as connection:
        rows = connection.execute(
            """
            SELECT DISTINCT certificate_names.name, tls_certificates.sha256_fingerprint
            FROM domain_observations
            JOIN observation_certificates
                ON observation_certificates.observation_id = domain_observations.id
            JOIN tls_certificates ON tls_certificates.id = observation_certificates.certificate_id
            JOIN certificate_names ON certificate_names.certificate_id = tls_certificates.id
            WHERE domain_observations.case_domain_id = ?
            """,
            (case_domain_id,),
        ).fetchall()
    return [
        {
            "domain": normalized,
            "source_type": "TLS_PIVOT",
            "detail": {"pivot": "certificate_san", "fingerprint": row["sha256_fingerprint"]},
        }
        for row in rows
        if (normalized := normalize_domain(row["name"]))
    ]


def _nameserver_candidates(database: Database, case_domain_id: str) -> list[Dict]:
    """Find domains in prior observations that use the selected domain's nameserver."""
    with database.connect() as connection:
        rows = connection.execute(
            """
            SELECT DISTINCT candidate_domains.canonical_name, source_dns.record_value AS nameserver
            FROM domain_observations AS source_observation
            JOIN dns_records AS source_dns ON source_dns.observation_id = source_observation.id
            JOIN dns_records AS candidate_dns
                ON candidate_dns.record_type = 'NS'
                AND lower(candidate_dns.record_value) = lower(source_dns.record_value)
            JOIN domain_observations AS candidate_observation
                ON candidate_observation.id = candidate_dns.observation_id
            JOIN case_domains AS candidate_case_domain
                ON candidate_case_domain.id = candidate_observation.case_domain_id
            JOIN domains AS candidate_domains ON candidate_domains.id = candidate_case_domain.domain_id
            WHERE source_observation.case_domain_id = ?
              AND source_dns.record_type = 'NS'
            """,
            (case_domain_id,),
        ).fetchall()
    return [
        {
            "domain": row["canonical_name"],
            "source_type": "NAMESERVER_PIVOT",
            "detail": {"pivot": "shared_nameserver", "nameserver": row["nameserver"]},
        }
        for row in rows
    ]


def _content_candidates(database: Database, case_domain_id: str) -> list[Dict]:
    """Find domains with identical normalised HTML, falling back to raw hashes."""
    with database.connect() as connection:
        rows = connection.execute(
            """
            SELECT DISTINCT
                candidate_domains.canonical_name,
                COALESCE(NULLIF(source_fingerprint.normalized_html_hash, ''), source_observation.content_hash)
                    AS fingerprint_hash,
                CASE WHEN source_fingerprint.normalized_html_hash <> ''
                    THEN 'identical_normalized_html' ELSE 'identical_raw_content' END AS pivot_type
            FROM domain_observations AS source_observation
            LEFT JOIN content_fingerprints AS source_fingerprint
                ON source_fingerprint.observation_id = source_observation.id
            JOIN domain_observations AS candidate_observation
                ON candidate_observation.id <> source_observation.id
            LEFT JOIN content_fingerprints AS candidate_fingerprint
                ON candidate_fingerprint.observation_id = candidate_observation.id
            JOIN case_domains AS candidate_case_domain
                ON candidate_case_domain.id = candidate_observation.case_domain_id
            JOIN domains AS candidate_domains ON candidate_domains.id = candidate_case_domain.domain_id
            WHERE source_observation.case_domain_id = ?
              AND COALESCE(NULLIF(source_fingerprint.normalized_html_hash, ''), source_observation.content_hash) <> ''
              AND COALESCE(NULLIF(candidate_fingerprint.normalized_html_hash, ''), candidate_observation.content_hash)
                  = COALESCE(NULLIF(source_fingerprint.normalized_html_hash, ''), source_observation.content_hash)
            """,
            (case_domain_id,),
        ).fetchall()
    return [
        {
            "domain": row["canonical_name"],
            "source_type": "CONTENT_PIVOT",
            "detail": {"pivot": row["pivot_type"], "content_hash": row["fingerprint_hash"]},
        }
        for row in rows
    ]


def _get_or_create_domain(connection, domain: str) -> str:
    row = connection.execute(
        "SELECT id FROM domains WHERE canonical_name = ?", (domain,)
    ).fetchone()
    if row:
        return row["id"]
    domain_id = str(uuid.uuid4())
    connection.execute(
        "INSERT INTO domains (id, canonical_name, registrable_domain) VALUES (?, ?, ?)",
        (domain_id, domain, domain),
    )
    return domain_id


def _link_candidates(
    database: Database,
    case_id: str,
    parent_case_domain_id: str,
    source_domain: str,
    candidates: Iterable[Dict],
) -> tuple[int, int, Dict[str, int]]:
    """Attach new candidates to the case while retaining their pivot provenance."""
    unique: dict[str, Dict] = {}
    for candidate in candidates:
        domain = candidate.get("domain", "")
        if domain == source_domain or not domain or domain in unique:
            continue
        unique[domain] = candidate
    added = 0
    existing = 0
    per_type: Dict[str, int] = {}
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        source = connection.execute(
            "SELECT 1 FROM case_domains WHERE id = ? AND case_id = ?",
            (parent_case_domain_id, case_id),
        ).fetchone()
        if not source:
            raise LookupError("Domain is not part of this case")
        for domain, candidate in unique.items():
            domain_id = _get_or_create_domain(connection, domain)
            source_type = candidate["source_type"]
            detail = json.dumps(
                {"source_domain": source_domain, **candidate["detail"]}, sort_keys=True
            )[:500]
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO case_domains (
                    id, case_id, domain_id, source_type, source_detail, parent_case_domain_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()), case_id, domain_id, source_type, detail,
                    parent_case_domain_id,
                ),
            )
            if cursor.rowcount:
                added += 1
                per_type[source_type] = per_type.get(source_type, 0) + 1
            else:
                existing += 1
        _record_audit_event(
            connection,
            case_id,
            "CASE_DISCOVERY_COMPLETED",
            {
                "source_case_domain_id": parent_case_domain_id,
                "source_domain": source_domain,
                "candidate_count": len(unique),
                "new_case_domains": added,
                "already_in_case": existing,
                "new_by_source_type": per_type,
            },
        )
    return added, existing, per_type


def run_case_discovery(
    database: Database,
    case_id: str,
    source_case_domain_id: str,
    modes: Iterable[str],
    dns_validator: Callable[[str], tuple[str, str | None]] = check_dns,
    reverse_ip_lookup_fn: Callable[[str], list[str]] = reverse_ip_lookup,
) -> Dict:
    """Run selected discovery pivots and attach evidence-labelled candidates.

    The function is intentionally synchronous for this stage. It is scoped to
    one analyst-selected domain and has bounded variant/reverse-IP inputs;
    background orchestration is introduced in Task 16.
    """
    source = _source_domain(database, case_id, source_case_domain_id)
    selected = {mode for mode in modes if mode in DISCOVERY_MODES}
    if not selected:
        raise ValueError("Select at least one discovery pivot")
    candidates: list[Dict] = []
    errors: list[str] = []
    if "variants" in selected:
        candidates.extend(_validate_variants(source["canonical_name"], dns_validator))
    if "redirects" in selected:
        candidates.extend(_redirect_candidates(database, source_case_domain_id))
    if "reverse_ip" in selected:
        reverse_candidates, reverse_errors = _reverse_ip_candidates(
            database, source_case_domain_id, reverse_ip_lookup_fn
        )
        candidates.extend(reverse_candidates)
        errors.extend(reverse_errors)
    if "tls" in selected:
        candidates.extend(_tls_candidates(database, source_case_domain_id))
    if "nameserver" in selected:
        candidates.extend(_nameserver_candidates(database, source_case_domain_id))
    if "content" in selected:
        candidates.extend(_content_candidates(database, source_case_domain_id))
    added, existing, per_type = _link_candidates(
        database, case_id, source_case_domain_id, source["canonical_name"], candidates
    )
    return {
        "source_domain": source["canonical_name"],
        "modes": sorted(selected),
        "candidates_found": len({candidate["domain"] for candidate in candidates}),
        "added": added,
        "already_in_case": existing,
        "added_by_source_type": per_type,
        "errors": errors,
    }
