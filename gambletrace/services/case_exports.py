"""Generate case reports and evidence-derived investigator handoff exports."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
from typing import Any, Dict, Iterable
from xml.sax.saxutils import escape as xml_escape
import zipfile

from gambletrace.persistence import Database
from gambletrace.services.investigation_graph import get_investigation_graph
from gambletrace.services.monitoring import list_case_alerts
from gambletrace.services.storage_security import restrict_directory, restrict_file


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_case_label(case_number: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", case_number)


def _export_directory(case_storage_dir: str, case_id: str) -> Path:
    root = Path(case_storage_dir).resolve()
    directory = (root / case_id / "exports").resolve()
    if root not in directory.parents:
        raise ValueError("Invalid case export location")
    directory.mkdir(parents=True, exist_ok=True)
    restrict_directory(directory)
    return directory


def _case_and_domains(database: Database, case_id: str) -> tuple[Dict[str, Any], list[Dict[str, Any]]]:
    with database.connect() as connection:
        case_row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not case_row:
            raise LookupError("Case not found")
        domains = [dict(row) for row in connection.execute(
            """
            SELECT case_domains.*, domains.canonical_name, domains.registrable_domain,
                   domain_observations.observed_at AS latest_observed_at,
                   domain_observations.final_url AS latest_final_url,
                   domain_observations.http_status AS latest_http_status
            FROM case_domains
            JOIN domains ON domains.id = case_domains.domain_id
            LEFT JOIN domain_observations ON domain_observations.id = (
                SELECT latest.id FROM domain_observations AS latest
                WHERE latest.case_domain_id = case_domains.id
                ORDER BY latest.observed_at DESC, latest.id DESC LIMIT 1
            )
            WHERE case_domains.case_id = ?
            ORDER BY case_domains.risk_score DESC, domains.canonical_name
            """,
            (case_id,),
        ).fetchall()]
    return dict(case_row), domains


def _ioc_rows(database: Database, case_id: str) -> list[Dict[str, str]]:
    """Build a deduplicated, traceable IOC list from retained case evidence."""
    with database.connect() as connection:
        rows: list[Dict[str, str]] = []
        rows.extend({
            "type": "DOMAIN", "value": row["canonical_name"], "source": row["source_type"],
            "first_seen": row["first_seen_at"], "last_seen": row["last_seen_at"],
        } for row in connection.execute(
            """
            SELECT domains.canonical_name, case_domains.source_type, case_domains.first_seen_at,
                   case_domains.last_seen_at FROM case_domains
            JOIN domains ON domains.id = case_domains.domain_id WHERE case_domains.case_id = ?
            """, (case_id,)
        ).fetchall())
        ioc_queries = (
            ("URL", """
                SELECT domain_observations.final_url AS value, MIN(domain_observations.observed_at) AS first_seen,
                       MAX(domain_observations.observed_at) AS last_seen FROM domain_observations
                JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
                WHERE case_domains.case_id = ? AND domain_observations.final_url <> '' GROUP BY final_url
            """),
            ("IP", """
                SELECT ip_addresses.address AS value, MIN(domain_observations.observed_at) AS first_seen,
                       MAX(domain_observations.observed_at) AS last_seen FROM observation_ips
                JOIN ip_addresses ON ip_addresses.id = observation_ips.ip_id
                JOIN domain_observations ON domain_observations.id = observation_ips.observation_id
                JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
                WHERE case_domains.case_id = ? GROUP BY ip_addresses.address
            """),
            ("ASN", """
                SELECT asns.asn_number AS value, MIN(domain_observations.observed_at) AS first_seen,
                       MAX(domain_observations.observed_at) AS last_seen FROM observation_asns
                JOIN asns ON asns.id = observation_asns.asn_id
                JOIN domain_observations ON domain_observations.id = observation_asns.observation_id
                JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
                WHERE case_domains.case_id = ? GROUP BY asns.asn_number
            """),
            ("NAMESERVER", """
                SELECT lower(dns_records.record_value) AS value, MIN(domain_observations.observed_at) AS first_seen,
                       MAX(domain_observations.observed_at) AS last_seen FROM dns_records
                JOIN domain_observations ON domain_observations.id = dns_records.observation_id
                JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
                WHERE case_domains.case_id = ? AND dns_records.record_type = 'NS'
                GROUP BY lower(dns_records.record_value)
            """),
            ("TLS_SHA256", """
                SELECT tls_certificates.sha256_fingerprint AS value, MIN(domain_observations.observed_at) AS first_seen,
                       MAX(domain_observations.observed_at) AS last_seen FROM observation_certificates
                JOIN tls_certificates ON tls_certificates.id = observation_certificates.certificate_id
                JOIN domain_observations ON domain_observations.id = observation_certificates.observation_id
                JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
                WHERE case_domains.case_id = ? GROUP BY tls_certificates.sha256_fingerprint
            """),
        )
        for kind, query in ioc_queries:
            rows.extend({
                "type": kind, "value": str(row["value"]), "source": "RETAINED_EVIDENCE",
                "first_seen": row["first_seen"] or "", "last_seen": row["last_seen"] or "",
            } for row in connection.execute(query, (case_id,)).fetchall() if row["value"])
    seen = set()
    unique = []
    for row in rows:
        key = (row["type"], row["value"])
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return sorted(unique, key=lambda row: (row["type"], row["value"]))


def _write_csv(path: Path, rows: Iterable[Dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def generate_ioc_export(database: Database, case_id: str, case_storage_dir: str, fmt: str) -> Path:
    """Write a CSV, JSON, or blocklist-text IOC export for one case."""
    if fmt not in {"csv", "json", "txt"}:
        raise ValueError("Unsupported IOC export format")
    case, _ = _case_and_domains(database, case_id)
    rows = _ioc_rows(database, case_id)
    target = _export_directory(case_storage_dir, case_id) / f"{_safe_case_label(case['case_number'])}_iocs_{_utc_stamp()}.{fmt}"
    if fmt == "csv":
        _write_csv(target, rows, ["type", "value", "source", "first_seen", "last_seen"])
    elif fmt == "json":
        target.write_text(json.dumps({"case_number": case["case_number"], "generated_at": _utc_stamp(), "indicators": rows}, indent=2), encoding="utf-8")
    else:
        target.write_text("\n".join(row["value"] for row in rows if row["type"] in {"DOMAIN", "URL", "IP"}) + "\n", encoding="utf-8")
    restrict_file(target)
    return target


def generate_graph_export(database: Database, case_id: str, case_storage_dir: str, fmt: str) -> Path:
    """Write an interoperable JSON or GraphML representation of case correlations."""
    if fmt not in {"json", "graphml"}:
        raise ValueError("Unsupported graph export format")
    graph = get_investigation_graph(database, case_id)
    target = _export_directory(case_storage_dir, case_id) / f"{_safe_case_label(graph['case']['case_number'])}_graph_{_utc_stamp()}.{fmt}"
    if fmt == "json":
        target.write_text(json.dumps(graph, indent=2), encoding="utf-8")
        restrict_file(target)
        return target
    nodes = "\n".join(
        f'<node id="{xml_escape(node["id"])}"><data key="label">{xml_escape(node["canonical_name"])}</data><data key="risk">{node["risk_score"]}</data><data key="availability">{xml_escape(node["availability"])}</data></node>'
        for node in graph["nodes"]
    )
    edges = "\n".join(
        f'<edge id="{xml_escape(edge["id"])}" source="{xml_escape(edge["source"])}" target="{xml_escape(edge["target"])}"><data key="confidence">{xml_escape(edge["confidence"])}</data><data key="score">{edge["score"]}</data><data key="signals">{xml_escape(", ".join(signal["code"] for signal in edge["signals"]))}</data></edge>'
        for edge in graph["edges"]
    )
    target.write_text(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n"
        "<key id=\"label\" for=\"node\" attr.name=\"label\" attr.type=\"string\"/>\n"
        "<key id=\"risk\" for=\"node\" attr.name=\"risk\" attr.type=\"double\"/>\n"
        "<key id=\"availability\" for=\"node\" attr.name=\"availability\" attr.type=\"string\"/>\n"
        "<key id=\"confidence\" for=\"edge\" attr.name=\"confidence\" attr.type=\"string\"/>\n"
        "<key id=\"score\" for=\"edge\" attr.name=\"score\" attr.type=\"int\"/>\n"
        "<key id=\"signals\" for=\"edge\" attr.name=\"signals\" attr.type=\"string\"/>\n"
        f"<graph id=\"{xml_escape(graph['case']['case_number'])}\" edgedefault=\"undirected\">\n{nodes}\n{edges}\n</graph>\n</graphml>\n",
        encoding="utf-8",
    )
    restrict_file(target)
    return target


def generate_case_report(database: Database, case_id: str, case_storage_dir: str) -> Path:
    """Generate a transparent Markdown intelligence report from stored findings."""
    case, domains = _case_and_domains(database, case_id)
    graph = get_investigation_graph(database, case_id)
    alerts = list_case_alerts(database, case_id)
    high_risk = [domain for domain in domains if float(domain["risk_score"] or 0) >= 65]
    output = [
        f"# GambleTrace case report: {case['case_number']}", "",
        "## Case context", "",
        f"- **Title:** {case['title']}", f"- **Status:** {case['status']}",
        f"- **Priority:** {case['priority']}", f"- **Owner:** {case['owner_name'] or 'Not assigned'}",
        f"- **Generated (UTC):** {_utc_stamp()}",
        f"- **Scope:** {case['scope_note'] or 'Not specified'}", "",
        "## Summary", "",
        f"- Case domains: {len(domains)}", f"- High-confidence risk candidates: {len(high_risk)}",
        f"- Evidence-backed relationship edges: {graph['summary']['edge_count']}",
        f"- Infrastructure clusters represented: {graph['summary']['clustered_nodes']}",
        f"- Monitoring alerts: {len(alerts)} ({sum(alert['status'] == 'OPEN' for alert in alerts)} open)", "",
        "## Priority domains", "", "| Domain | Risk | Relevance | Availability | Last observed |", "| --- | ---: | --- | --- | --- |",
    ]
    if domains:
        output.extend(
            f"| {domain['canonical_name']} | {round(float(domain['risk_score'] or 0))}/100 | {domain['relevance']} | {domain['availability']} | {domain['latest_observed_at'] or 'Not observed'} |"
            for domain in domains[:25]
        )
    else:
        output.append("| No domains | - | - | - | - |")
    output.extend(["", "## Correlation summary", ""])
    if graph["edges"]:
        output.extend(f"- **{edge['confidence']} ({edge['score']}/100):** {edge['source_name']} ↔ {edge['target_name']} — {', '.join(signal['label'] for signal in edge['signals']) or 'no signal detail'}" for edge in graph["edges"][:25])
    else:
        output.append("- No evidence-backed correlation edges are currently retained.")
    output.extend(["", "## Monitoring alerts", ""])
    if alerts:
        output.extend(f"- **{alert['severity']} / {alert['status']}:** {alert['canonical_name'] or 'Case'} — {alert['summary']} ({alert['created_at']} UTC)" for alert in alerts[:25])
    else:
        output.append("- No historical monitoring alerts are currently retained.")
    output.extend([
        "", "## Interpretation boundary", "",
        "This report summarizes technical observations and correlations retained in this case. A domain, indicator, cluster, or infrastructure relationship is an investigative lead and not proof of illegal activity, common ownership, or attribution.",
    ])
    target = _export_directory(case_storage_dir, case_id) / f"{_safe_case_label(case['case_number'])}_report_{_utc_stamp()}.md"
    target.write_text("\n".join(output) + "\n", encoding="utf-8")
    restrict_file(target)
    return target


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def generate_evidence_zip(database: Database, case_id: str, case_storage_dir: str) -> Path:
    """Package case-owned evidence with a generated integrity-verification register."""
    case, _ = _case_and_domains(database, case_id)
    storage_root = Path(case_storage_dir).resolve()
    target = _export_directory(case_storage_dir, case_id) / f"{_safe_case_label(case['case_number'])}_evidence_{_utc_stamp()}.zip"
    with database.connect() as connection:
        artifacts = [dict(row) for row in connection.execute(
            """
            SELECT evidence_artifacts.*, domains.canonical_name, domain_observations.observed_at
            FROM evidence_artifacts
            JOIN domain_observations ON domain_observations.id = evidence_artifacts.observation_id
            JOIN case_domains ON case_domains.id = domain_observations.case_domain_id
            JOIN domains ON domains.id = case_domains.domain_id
            WHERE case_domains.case_id = ?
            ORDER BY domain_observations.observed_at, evidence_artifacts.artifact_type
            """, (case_id,)
        ).fetchall()]
        sources = [dict(row) for row in connection.execute(
            "SELECT * FROM source_files WHERE case_id = ? ORDER BY imported_at", (case_id,)
        ).fetchall()]
    verification = []
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for item, category in [*[(artifact, "evidence") for artifact in artifacts], *[(source, "sources") for source in sources]]:
            stored_path = str(item["stored_path"])
            source_path = (storage_root / stored_path).resolve()
            # Source-file paths created before Task 19 were project-relative
            # (`data/cases/...`) instead of case-storage-relative. Accept only
            # that legacy form when it still resolves back inside case storage.
            if category == "sources" and not source_path.is_file():
                legacy_path = (storage_root.parent.parent / stored_path).resolve()
                if storage_root in legacy_path.parents:
                    source_path = legacy_path
            entry = {"category": category, "stored_path": stored_path, "expected_sha256": item["sha256"], "included": False, "verification": "MISSING"}
            if storage_root in source_path.parents and source_path.is_file():
                actual_hash = _hash_file(source_path)
                entry.update({"actual_sha256": actual_hash, "included": actual_hash == item["sha256"], "verification": "MATCH" if actual_hash == item["sha256"] else "HASH_MISMATCH"})
                if actual_hash == item["sha256"]:
                    archive.write(source_path, arcname=f"{category}/{stored_path.replace(chr(92), '/')}")
            verification.append(entry)
        archive.writestr("case.json", json.dumps(case, indent=2, default=str))
        archive.writestr("evidence_verification.json", json.dumps({"case_number": case["case_number"], "generated_at": _utc_stamp(), "files": verification}, indent=2))
    restrict_file(target)
    return target
