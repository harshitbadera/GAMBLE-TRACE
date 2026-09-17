"""Explainable domain-risk and relationship-confidence scoring."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
import uuid
from typing import Dict, Iterable

from gambletrace.persistence import Database


SCORER_VERSION = "explainable-risk/1.0"
DOMAIN_GAMBLING_TERMS = (
    "bet", "casino", "poker", "rummy", "satta", "matka", "teenpatti",
    "sportsbook", "bookmaker", "slot", "gambl", "wager",
)
PIVOT_WEIGHTS = {
    "REDIRECT_PIVOT": 8,
    "CONTENT_PIVOT": 8,
    "REVERSE_IP_PIVOT": 5,
    "TLS_PIVOT": 4,
    "NAMESERVER_PIVOT": 3,
    "GENERATED_VARIATION": 1,
}
RELATIONSHIP_WEIGHTS = {
    "REDIRECT_CHAIN": 35,
    "SHARED_DEDICATED_IP": 30,
    "IDENTICAL_NORMALIZED_HTML": 28,
    "SHARED_CERTIFICATE": 25,
    "SHARED_FAVICON": 15,
    "SHARED_NAMESERVER": 12,
    "DOMAIN_VARIATION": 8,
    "SAME_ASN": 5,
}


@dataclass(frozen=True)
class ScoreFactor:
    """One visible contribution to a score."""

    code: str
    label: str
    points: int
    detail: str


def _factor(code: str, label: str, points: int, detail: str) -> ScoreFactor | None:
    return ScoreFactor(code, label, points, detail) if points else None


def _domain_term_count(domain: str) -> int:
    return sum(term in domain.casefold() for term in DOMAIN_GAMBLING_TERMS)


def calculate_domain_risk(evidence: Dict) -> Dict:
    """Score one domain using only supplied, explainable technical signals."""
    factors: list[ScoreFactor] = []
    domain_terms = _domain_term_count(evidence["domain"])
    gambling_distinct = int(evidence.get("gambling_distinct", 0))
    gambling_occurrences = int(evidence.get("gambling_occurrences", 0))
    payment_distinct = int(evidence.get("payment_distinct", 0))
    payment_occurrences = int(evidence.get("payment_occurrences", 0))
    india_distinct = int(evidence.get("india_distinct", 0))
    india_occurrences = int(evidence.get("india_occurrences", 0))
    redirect_count = int(evidence.get("redirect_count", 0))

    contributions = (
        _factor(
            "DOMAIN_GAMBLING_TERMS",
            "Gambling-related domain terms",
            min(15, domain_terms * 6),
            f"{domain_terms} distinct term(s) in {evidence['domain']}",
        ),
        _factor(
            "GAMBLING_CONTENT",
            "Visible gambling indicators",
            min(35, gambling_distinct * 7 + min(gambling_occurrences, 7)),
            f"{gambling_distinct} term(s), {gambling_occurrences} total occurrence(s)",
        ),
        _factor(
            "PAYMENT_INDICATORS",
            "Visible payment indicators",
            min(20, payment_distinct * 4 + min(payment_occurrences, 4)),
            f"{payment_distinct} term(s), {payment_occurrences} total occurrence(s)",
        ),
        _factor(
            "INDIA_TARGETING",
            "Visible India-targeting indicators",
            min(15, india_distinct * 3 + min(india_occurrences, 3)),
            f"{india_distinct} term(s), {india_occurrences} total occurrence(s)",
        ),
        _factor(
            "ACTIVE_ENDPOINT",
            "Active web endpoint",
            5 if evidence.get("availability") == "ACTIVE" else 0,
            f"Current availability: {evidence.get('availability', 'UNKNOWN')}",
        ),
        _factor(
            "REDIRECT_BEHAVIOUR",
            "Observed redirect behaviour",
            min(8, redirect_count * 4),
            f"{redirect_count} recorded redirect hop(s)",
        ),
        _factor(
            f"PIVOT_{evidence.get('source_type', '')}",
            "Discovery pivot provenance",
            PIVOT_WEIGHTS.get(evidence.get("source_type", ""), 0),
            evidence.get("source_type", "SEED").replace("_", " ").title(),
        ),
    )
    factors.extend(factor for factor in contributions if factor)
    score = min(100, sum(factor.points for factor in factors))
    if score >= 65:
        relevance = "HIGH_CONFIDENCE_SUSPECTED_GAMBLING"
    elif score >= 35:
        relevance = "MEDIUM_CONFIDENCE_SUSPECTED_GAMBLING"
    elif score >= 15:
        relevance = "LOW_CONFIDENCE_CANDIDATE"
    else:
        relevance = "INSUFFICIENT_EVIDENCE"
    return {
        "score": score,
        "relevance": relevance,
        "factors": [asdict(factor) for factor in factors],
    }


def calculate_relationship_confidence(signals: Iterable[str]) -> Dict:
    """Score a relationship from explicit correlation signals for Task 13."""
    selected = sorted(set(signal for signal in signals if signal in RELATIONSHIP_WEIGHTS))
    factors = [
        asdict(
            ScoreFactor(
                code=signal,
                label=signal.replace("_", " ").title(),
                points=RELATIONSHIP_WEIGHTS[signal],
                detail="Observed technical correlation",
            )
        )
        for signal in selected
    ]
    score = min(100, sum(item["points"] for item in factors))
    confidence = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    return {"score": score, "confidence": confidence, "factors": factors}


def _domain_evidence(connection, case_domain: Dict) -> Dict:
    indicator_rows = connection.execute(
        """
        SELECT category, COUNT(DISTINCT indicator) AS distinct_count, SUM(occurrences) AS occurrence_count
        FROM content_indicators
        JOIN domain_observations ON domain_observations.id = content_indicators.observation_id
        WHERE domain_observations.case_domain_id = ?
        GROUP BY category
        """,
        (case_domain["id"],),
    ).fetchall()
    indicators = {
        row["category"]: (int(row["distinct_count"]), int(row["occurrence_count"] or 0))
        for row in indicator_rows
    }
    redirect_count = connection.execute(
        """
        SELECT COUNT(*) FROM redirects
        JOIN domain_observations ON domain_observations.id = redirects.observation_id
        WHERE domain_observations.case_domain_id = ?
        """,
        (case_domain["id"],),
    ).fetchone()[0]
    return {
        "domain": case_domain["canonical_name"],
        "availability": case_domain["availability"],
        "source_type": case_domain["source_type"],
        "redirect_count": redirect_count,
        "gambling_distinct": indicators.get("GAMBLING", (0, 0))[0],
        "gambling_occurrences": indicators.get("GAMBLING", (0, 0))[1],
        "payment_distinct": indicators.get("PAYMENT", (0, 0))[0],
        "payment_occurrences": indicators.get("PAYMENT", (0, 0))[1],
        "india_distinct": indicators.get("INDIA", (0, 0))[0],
        "india_occurrences": indicators.get("INDIA", (0, 0))[1],
    }


def score_case_domains(database: Database, case_id: str) -> Dict:
    """Create immutable risk assessments and update each domain's current score."""
    assessments: list[Dict] = []
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        domains = connection.execute(
            """
            SELECT case_domains.id, case_domains.availability, case_domains.source_type, domains.canonical_name
            FROM case_domains JOIN domains ON domains.id = case_domains.domain_id
            WHERE case_domains.case_id = ?
            ORDER BY domains.canonical_name
            """,
            (case_id,),
        ).fetchall()
        if not domains:
            case_exists = connection.execute(
                "SELECT 1 FROM cases WHERE id = ?", (case_id,)
            ).fetchone()
            if not case_exists:
                raise LookupError("Case not found")
        for row in domains:
            case_domain = dict(row)
            assessment = calculate_domain_risk(_domain_evidence(connection, case_domain))
            connection.execute(
                """
                INSERT INTO risk_assessments (
                    id, case_id, case_domain_id, score, relevance, factors_json, scorer_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()), case_id, case_domain["id"], assessment["score"],
                    assessment["relevance"], json.dumps(assessment["factors"], sort_keys=True),
                    SCORER_VERSION,
                ),
            )
            connection.execute(
                """
                UPDATE case_domains SET risk_score = ?, relevance = ?
                WHERE id = ?
                """,
                (assessment["score"], assessment["relevance"], case_domain["id"]),
            )
            assessments.append({**case_domain, **assessment})
        summary = {
            "domains_scored": len(assessments),
            "high_confidence": sum(
                item["relevance"] == "HIGH_CONFIDENCE_SUSPECTED_GAMBLING"
                for item in assessments
            ),
            "medium_confidence": sum(
                item["relevance"] == "MEDIUM_CONFIDENCE_SUSPECTED_GAMBLING"
                for item in assessments
            ),
        }
        connection.execute(
            """
            INSERT INTO audit_events (id, case_id, event_type, event_data_json)
            VALUES (?, ?, 'CASE_RISK_SCORING_COMPLETED', ?)
            """,
            (str(uuid.uuid4()), case_id, json.dumps(summary, sort_keys=True)),
        )
    return {**summary, "assessments": assessments}
