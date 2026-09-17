"""Evidence-backed case-domain correlation and infrastructure clustering."""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations
import hashlib
import json
import uuid
from typing import Dict, Iterable

from gambletrace.persistence import Database
from gambletrace.services.scoring import calculate_relationship_confidence


MAX_SHARED_GROUP_SIZE = 12
SIGNAL_ARTIFACT_TYPES = {
    "REDIRECT_CHAIN": ("REDIRECT_CHAIN",),
    "SHARED_DEDICATED_IP": ("DNS_RECORDS", "RDAP_RESPONSE"),
    "SHARED_CERTIFICATE": ("TLS_CERTIFICATE_DER", "TLS_CERTIFICATE_METADATA"),
    "SHARED_NAMESERVER": ("DNS_RECORDS",),
    "IDENTICAL_NORMALIZED_HTML": ("CONTENT_FINGERPRINT", "HTML_SNAPSHOT"),
    "SHARED_FAVICON": ("FAVICON", "CONTENT_FINGERPRINT"),
    "SAME_ASN": ("RDAP_RESPONSE",),
    "DOMAIN_VARIATION": ("ACQUISITION_METADATA",),
}


def _case_domains(connection, case_id: str) -> Dict[str, str]:
    rows = connection.execute(
        """
        SELECT case_domains.id, domains.canonical_name
        FROM case_domains JOIN domains ON domains.id = case_domains.domain_id
        WHERE case_domains.case_id = ?
        """,
        (case_id,),
    ).fetchall()
    return {row["id"]: row["canonical_name"] for row in rows}


def _add_group_pairs(
    pair_signals: dict[tuple[str, str], set[str]],
    groups: Iterable[set[str]],
    signal: str,
) -> None:
    for group in groups:
        if not 1 < len(group) <= MAX_SHARED_GROUP_SIZE:
            continue
        for left, right in combinations(sorted(group), 2):
            pair_signals[(left, right)].add(signal)


def _groups_from_rows(rows, value_key: str = "value") -> list[set[str]]:
    grouped: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        value = str(row[value_key] or "").strip()
        if value:
            grouped[value].add(row["case_domain_id"])
    return list(grouped.values())


def _shared_ip_groups(connection, case_id: str) -> list[set[str]]:
    rows = connection.execute(
        """
        SELECT DISTINCT case_domains.id AS case_domain_id, ip_addresses.address AS value
        FROM case_domains
        JOIN domain_observations ON domain_observations.case_domain_id = case_domains.id
        JOIN observation_ips ON observation_ips.observation_id = domain_observations.id
        JOIN ip_addresses ON ip_addresses.id = observation_ips.ip_id
        WHERE case_domains.case_id = ?
        """,
        (case_id,),
    ).fetchall()
    return _groups_from_rows(rows)


def _shared_certificate_groups(connection, case_id: str) -> list[set[str]]:
    rows = connection.execute(
        """
        SELECT DISTINCT case_domains.id AS case_domain_id, tls_certificates.sha256_fingerprint AS value
        FROM case_domains
        JOIN domain_observations ON domain_observations.case_domain_id = case_domains.id
        JOIN observation_certificates ON observation_certificates.observation_id = domain_observations.id
        JOIN tls_certificates ON tls_certificates.id = observation_certificates.certificate_id
        WHERE case_domains.case_id = ?
        """,
        (case_id,),
    ).fetchall()
    return _groups_from_rows(rows)


def _shared_nameserver_groups(connection, case_id: str) -> list[set[str]]:
    rows = connection.execute(
        """
        SELECT DISTINCT case_domains.id AS case_domain_id, lower(dns_records.record_value) AS value
        FROM case_domains
        JOIN domain_observations ON domain_observations.case_domain_id = case_domains.id
        JOIN dns_records ON dns_records.observation_id = domain_observations.id
        WHERE case_domains.case_id = ? AND dns_records.record_type = 'NS'
        """,
        (case_id,),
    ).fetchall()
    return _groups_from_rows(rows)


def _shared_content_groups(connection, case_id: str) -> list[set[str]]:
    rows = connection.execute(
        """
        SELECT DISTINCT case_domains.id AS case_domain_id, content_fingerprints.normalized_html_hash AS value
        FROM case_domains
        JOIN domain_observations ON domain_observations.case_domain_id = case_domains.id
        JOIN content_fingerprints ON content_fingerprints.observation_id = domain_observations.id
        WHERE case_domains.case_id = ? AND content_fingerprints.normalized_html_hash <> ''
        """,
        (case_id,),
    ).fetchall()
    return _groups_from_rows(rows)


def _shared_favicon_groups(connection, case_id: str) -> list[set[str]]:
    rows = connection.execute(
        """
        SELECT DISTINCT case_domains.id AS case_domain_id, content_fingerprints.favicon_hash AS value
        FROM case_domains
        JOIN domain_observations ON domain_observations.case_domain_id = case_domains.id
        JOIN content_fingerprints ON content_fingerprints.observation_id = domain_observations.id
        WHERE case_domains.case_id = ? AND content_fingerprints.favicon_hash <> ''
        """,
        (case_id,),
    ).fetchall()
    return _groups_from_rows(rows)


def _shared_asn_groups(connection, case_id: str) -> list[set[str]]:
    rows = connection.execute(
        """
        SELECT DISTINCT case_domains.id AS case_domain_id, asns.asn_number AS value
        FROM case_domains
        JOIN domain_observations ON domain_observations.case_domain_id = case_domains.id
        JOIN observation_asns ON observation_asns.observation_id = domain_observations.id
        JOIN asns ON asns.id = observation_asns.asn_id
        WHERE case_domains.case_id = ?
        """,
        (case_id,),
    ).fetchall()
    return _groups_from_rows(rows)


def _redirect_pairs(connection, case_id: str) -> set[tuple[str, str]]:
    rows = connection.execute(
        """
        SELECT DISTINCT source_case_domain.id AS source_id, target_case_domain.id AS target_id
        FROM redirects
        JOIN domain_observations ON domain_observations.id = redirects.observation_id
        JOIN case_domains AS source_case_domain
            ON source_case_domain.id = domain_observations.case_domain_id
        JOIN case_domains AS target_case_domain
            ON target_case_domain.domain_id = redirects.target_domain_id
        WHERE source_case_domain.case_id = ?
          AND target_case_domain.case_id = ?
          AND source_case_domain.id <> target_case_domain.id
        """,
        (case_id, case_id),
    ).fetchall()
    return {tuple(sorted((row["source_id"], row["target_id"]))) for row in rows}


def _variation_pairs(connection, case_id: str) -> set[tuple[str, str]]:
    rows = connection.execute(
        """
        SELECT id, parent_case_domain_id
        FROM case_domains
        WHERE case_id = ? AND source_type = 'GENERATED_VARIATION'
              AND parent_case_domain_id IS NOT NULL
        """,
        (case_id,),
    ).fetchall()
    return {tuple(sorted((row["id"], row["parent_case_domain_id"]))) for row in rows}


def _record_relationship(
    connection,
    case_id: str,
    left_id: str,
    right_id: str,
    score: Dict,
) -> str:
    """Create or refresh one symmetric correlation edge and return its ID."""
    row = connection.execute(
        """
        SELECT id FROM relationships
        WHERE case_id = ? AND source_type = 'CASE_DOMAIN' AND source_id = ?
          AND relationship_type = 'CORRELATED_INFRASTRUCTURE'
          AND target_type = 'CASE_DOMAIN' AND target_id = ?
        """,
        (case_id, left_id, right_id),
    ).fetchone()
    explanation = json.dumps(
        {
            "score": score["score"],
            "signals": [factor["code"] for factor in score["factors"]],
            "factors": score["factors"],
        },
        sort_keys=True,
    )
    if row:
        connection.execute(
            """
            UPDATE relationships
            SET confidence = ?, last_seen_at = CURRENT_TIMESTAMP, explanation = ?
            WHERE id = ?
            """,
            (score["confidence"], explanation, row["id"]),
        )
        return row["id"]
    relationship_id = str(uuid.uuid4())
    connection.execute(
        """
        INSERT INTO relationships (
            id, case_id, source_type, source_id, relationship_type, target_type,
            target_id, confidence, explanation
        ) VALUES (?, ?, 'CASE_DOMAIN', ?, 'CORRELATED_INFRASTRUCTURE', 'CASE_DOMAIN', ?, ?, ?)
        """,
        (relationship_id, case_id, left_id, right_id, score["confidence"], explanation),
    )
    return relationship_id


def _link_relationship_evidence(
    connection,
    relationship_id: str,
    case_domain_ids: tuple[str, str],
    signals: set[str],
) -> None:
    types = sorted({item for signal in signals for item in SIGNAL_ARTIFACT_TYPES[signal]})
    if not types:
        return
    placeholders = ",".join("?" for _ in types)
    for case_domain_id in case_domain_ids:
        row = connection.execute(
            f"""
            SELECT evidence_artifacts.id
            FROM evidence_artifacts
            JOIN domain_observations ON domain_observations.id = evidence_artifacts.observation_id
            WHERE domain_observations.case_domain_id = ?
              AND evidence_artifacts.artifact_type IN ({placeholders})
            ORDER BY evidence_artifacts.captured_at DESC
            LIMIT 1
            """,
            (case_domain_id, *types),
        ).fetchone()
        if row:
            connection.execute(
                """
                INSERT OR IGNORE INTO relationship_evidence (relationship_id, artifact_id)
                VALUES (?, ?)
                """,
                (relationship_id, row["id"]),
            )


def _build_clusters(
    connection,
    case_id: str,
    domain_names: Dict[str, str],
    scored_edges: list[tuple[str, str, Dict]],
) -> int:
    """Persist connected medium/high confidence graph components as clusters."""
    adjacency: dict[str, set[str]] = defaultdict(set)
    edge_by_pair: dict[tuple[str, str], Dict] = {}
    for left_id, right_id, score in scored_edges:
        if score["confidence"] == "LOW":
            continue
        adjacency[left_id].add(right_id)
        adjacency[right_id].add(left_id)
        edge_by_pair[tuple(sorted((left_id, right_id)))] = score

    visited: set[str] = set()
    clusters_created = 0
    for start in sorted(adjacency):
        if start in visited:
            continue
        stack = [start]
        members: set[str] = set()
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            members.add(node)
            stack.extend(adjacency[node] - visited)
        if len(members) < 2:
            continue
        member_ids = sorted(members)
        key = "component:" + hashlib.sha256("|".join(member_ids).encode()).hexdigest()[:20]
        scores = [
            score for (left, right), score in edge_by_pair.items()
            if left in members and right in members
        ]
        high_edges = sum(score["confidence"] == "HIGH" for score in scores)
        confidence = "HIGH" if high_edges else "MEDIUM"
        signal_names = sorted({factor["code"] for score in scores for factor in score["factors"]})
        summary = (
            f"{len(member_ids)} domains, {len(scores)} medium/high-confidence correlations; "
            f"signals: {', '.join(signal_names)}"
        )[:2000]
        row = connection.execute(
            "SELECT id FROM clusters WHERE case_id = ? AND cluster_key = ?",
            (case_id, key),
        ).fetchone()
        cluster_id = row["id"] if row else str(uuid.uuid4())
        if row:
            connection.execute(
                """
                UPDATE clusters
                SET confidence = ?, summary = ?, last_seen_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (confidence, summary, cluster_id),
            )
        else:
            connection.execute(
                """
                INSERT INTO clusters (id, case_id, cluster_key, name, confidence, summary)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    cluster_id, case_id, key,
                    f"Infrastructure cluster {clusters_created + 1:02d}",
                    confidence, summary,
                ),
            )
        for member_id in member_ids:
            connection.execute(
                """
                INSERT OR IGNORE INTO cluster_members (
                    id, cluster_id, entity_type, entity_id, role, confidence
                ) VALUES (?, ?, 'CASE_DOMAIN', ?, 'DOMAIN', ?)
                """,
                (str(uuid.uuid4()), cluster_id, member_id, confidence),
            )
        clusters_created += 1
    return clusters_created


def correlate_case_domains(database: Database, case_id: str) -> Dict:
    """Create scored, evidence-linked relationship edges and infrastructure clusters."""
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        domain_names = _case_domains(connection, case_id)
        if not domain_names:
            if not connection.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone():
                raise LookupError("Case not found")
            return {"relationships": 0, "clusters": 0, "by_confidence": {}}

        pair_signals: dict[tuple[str, str], set[str]] = defaultdict(set)
        _add_group_pairs(pair_signals, _shared_ip_groups(connection, case_id), "SHARED_DEDICATED_IP")
        _add_group_pairs(pair_signals, _shared_certificate_groups(connection, case_id), "SHARED_CERTIFICATE")
        _add_group_pairs(pair_signals, _shared_nameserver_groups(connection, case_id), "SHARED_NAMESERVER")
        _add_group_pairs(pair_signals, _shared_content_groups(connection, case_id), "IDENTICAL_NORMALIZED_HTML")
        _add_group_pairs(pair_signals, _shared_favicon_groups(connection, case_id), "SHARED_FAVICON")
        _add_group_pairs(pair_signals, _shared_asn_groups(connection, case_id), "SAME_ASN")
        for pair in _redirect_pairs(connection, case_id):
            pair_signals[pair].add("REDIRECT_CHAIN")
        for pair in _variation_pairs(connection, case_id):
            pair_signals[pair].add("DOMAIN_VARIATION")

        scored_edges: list[tuple[str, str, Dict]] = []
        by_confidence: dict[str, int] = defaultdict(int)
        for (left_id, right_id), signals in sorted(pair_signals.items()):
            score = calculate_relationship_confidence(signals)
            relationship_id = _record_relationship(connection, case_id, left_id, right_id, score)
            _link_relationship_evidence(connection, relationship_id, (left_id, right_id), signals)
            scored_edges.append((left_id, right_id, score))
            by_confidence[score["confidence"]] += 1

        clusters = _build_clusters(connection, case_id, domain_names, scored_edges)
        summary = {
            "relationships": len(scored_edges),
            "clusters": clusters,
            "by_confidence": dict(by_confidence),
        }
        connection.execute(
            """
            INSERT INTO audit_events (id, case_id, event_type, event_data_json)
            VALUES (?, ?, 'CASE_CORRELATION_COMPLETED', ?)
            """,
            (str(uuid.uuid4()), case_id, json.dumps(summary, sort_keys=True)),
        )
    return summary
