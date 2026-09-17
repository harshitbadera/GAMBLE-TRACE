"""Case-scoped graph read model built from persisted correlation edges."""

from __future__ import annotations

import json
from typing import Any, Dict

from gambletrace.persistence import Database


def _require_case(connection, case_id: str) -> Dict[str, Any]:
    row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not row:
        raise LookupError("Case not found")
    return dict(row)


def _parse_explanation(raw: str) -> tuple[int, list[Dict[str, Any]]]:
    """Normalize older and current relationship explanations for the browser."""
    try:
        explanation = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        explanation = {}
    score = int(explanation.get("score") or 0)
    factor_by_code = {
        item.get("code"): item
        for item in explanation.get("factors", [])
        if isinstance(item, dict) and item.get("code")
    }
    signals = []
    for code in explanation.get("signals", []):
        if not isinstance(code, str):
            continue
        factor = factor_by_code.get(code, {})
        signals.append({
            "code": code,
            "label": factor.get("label") or code.replace("_", " ").title(),
            "points": int(factor.get("points") or 0),
            "detail": factor.get("detail") or "Observed technical correlation",
        })
    return score, signals


def get_investigation_graph(database: Database, case_id: str) -> Dict[str, Any]:
    """Return domains, correlation edges, and filter metadata for one case."""
    with database.connect() as connection:
        case = _require_case(connection, case_id)
        node_rows = connection.execute(
            """
            SELECT case_domains.id, domains.canonical_name, case_domains.risk_score,
                   case_domains.relevance, case_domains.availability, case_domains.source_type,
                   GROUP_CONCAT(DISTINCT clusters.name) AS cluster_names
            FROM case_domains
            JOIN domains ON domains.id = case_domains.domain_id
            LEFT JOIN cluster_members
                ON cluster_members.entity_type = 'CASE_DOMAIN'
                AND cluster_members.entity_id = case_domains.id
            LEFT JOIN clusters ON clusters.id = cluster_members.cluster_id
            WHERE case_domains.case_id = ?
            GROUP BY case_domains.id
            ORDER BY case_domains.risk_score DESC, domains.canonical_name
            """,
            (case_id,),
        ).fetchall()
        nodes = []
        for row in node_rows:
            node = dict(row)
            node["risk_score"] = float(node["risk_score"] or 0)
            node["clusters"] = [name for name in (node.pop("cluster_names") or "").split(",") if name]
            nodes.append(node)

        edge_rows = connection.execute(
            """
            SELECT relationships.*, source_domains.canonical_name AS source_name,
                   target_domains.canonical_name AS target_name,
                   COUNT(relationship_evidence.artifact_id) AS evidence_count
            FROM relationships
            JOIN case_domains AS source_case_domain
                ON source_case_domain.id = relationships.source_id
            JOIN domains AS source_domains ON source_domains.id = source_case_domain.domain_id
            JOIN case_domains AS target_case_domain
                ON target_case_domain.id = relationships.target_id
            JOIN domains AS target_domains ON target_domains.id = target_case_domain.domain_id
            LEFT JOIN relationship_evidence
                ON relationship_evidence.relationship_id = relationships.id
            WHERE relationships.case_id = ?
              AND relationships.source_type = 'CASE_DOMAIN'
              AND relationships.target_type = 'CASE_DOMAIN'
              AND relationships.relationship_type = 'CORRELATED_INFRASTRUCTURE'
            GROUP BY relationships.id
            ORDER BY relationships.confidence DESC, relationships.last_seen_at DESC
            """,
            (case_id,),
        ).fetchall()
        edges = []
        for row in edge_rows:
            edge = dict(row)
            score, signals = _parse_explanation(edge.pop("explanation", ""))
            edges.append({
                "id": edge["id"],
                "source": edge["source_id"],
                "target": edge["target_id"],
                "source_name": edge["source_name"],
                "target_name": edge["target_name"],
                "confidence": edge["confidence"],
                "score": score,
                "signals": signals,
                "evidence_count": int(edge["evidence_count"] or 0),
                "first_seen_at": edge["first_seen_at"],
                "last_seen_at": edge["last_seen_at"],
            })

    signal_codes = sorted({signal["code"] for edge in edges for signal in edge["signals"]})
    return {
        "case": case,
        "nodes": nodes,
        "edges": edges,
        "signal_codes": signal_codes,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "high_confidence_edges": sum(edge["confidence"] == "HIGH" for edge in edges),
            "clustered_nodes": sum(bool(node["clusters"]) for node in nodes),
        },
    }
