"""API routes for the current domain intelligence workflows."""

import logging
import os
import time
import uuid

from flask import Blueprint, current_app, jsonify, request

from gambletrace.reports.liveness import generate_liveness_report
from gambletrace.services.artifacts import write_download_csv
from gambletrace.services.content_analysis import analyze_domains
from gambletrace.services.domain_input import read_domains_from_upload
from gambletrace.services.expansion import expand_domains
from gambletrace.services.infrastructure import (
    lookup_domains,
    non_cdn_ips,
    run_reverse_ip_pivot,
)


logger = logging.getLogger(__name__)
analysis_bp = Blueprint("analysis", __name__, url_prefix="/api")


def _temp_dir() -> str:
    return current_app.extensions["gambletrace"]["temp_dir"]


def _uploaded_domains():
    if "file" not in request.files:
        return None, (jsonify({"error": "No file uploaded"}), 400)
    uploaded = request.files["file"]
    if not uploaded.filename:
        return None, (jsonify({"error": "Empty filename"}), 400)
    domains = read_domains_from_upload(uploaded, _temp_dir())
    if not domains:
        return None, (jsonify({"error": "No valid domains found in file"}), 400)
    return domains, None


@analysis_bp.post("/expand")
def api_expand():
    """Generate and DNS-validate domain variations from uploaded seeds."""
    seeds, error = _uploaded_domains()
    if error:
        return error
    start_time = time.time()
    expanded = expand_domains(seeds)
    download_id = write_download_csv(
        _temp_dir(), "expanded_", ["domain", "ip_address"], expanded["main_domains"]
    )
    return jsonify({
        "success": True,
        "seeds": len(seeds),
        "candidates_checked": len(expanded["candidates"]),
        "total_resolved": len(expanded["live"]),
        "main_domains": len(expanded["main_domains"]),
        "elapsed_seconds": round(time.time() - start_time, 1),
        "download_id": download_id,
        "domains": expanded["main_domains"],
    })


@analysis_bp.post("/lookup")
def api_lookup():
    """Run infrastructure lookups and a non-CDN reverse-IP pivot."""
    domains, error = _uploaded_domains()
    if error:
        return error
    start_time = time.time()
    results = lookup_domains(domains)
    lookup_elapsed = round(time.time() - start_time, 1)
    download_id = write_download_csv(
        _temp_dir(),
        "lookup_",
        [
            "domain", "main_domain", "ipv4_addresses", "ipv6_addresses",
            "hosting_provider", "country", "asn", "asn_description",
        ],
        results,
    )

    pivot_results = run_reverse_ip_pivot(results, domains)
    pivot_download_id = None
    if pivot_results:
        pivot_download_id = write_download_csv(
            _temp_dir(),
            "pivot_",
            [
                "domain", "found_on_ip", "hosting_provider", "asn",
                "asn_description", "country", "discovered_from",
            ],
            pivot_results,
        )

    all_ipv4 = {
        ip.strip()
        for result in results
        for ip in result.get("ipv4_addresses", "").split(";")
        if ip.strip()
    }
    eligible_ips = non_cdn_ips(results)
    return jsonify({
        "success": True,
        "total_domains": len(domains),
        "elapsed_seconds": round(time.time() - start_time, 1),
        "lookup_elapsed": lookup_elapsed,
        "download_id": download_id,
        "results": results,
        "pivot_download_id": pivot_download_id,
        "pivot_results": pivot_results,
        "pivot_new_domains": len(pivot_results),
        "pivot_ips_queried": len(eligible_ips),
        "pivot_ips_skipped_cdn": len(all_ipv4 - set(eligible_ips)),
    })


@analysis_bp.post("/content_analysis")
def api_content_analysis():
    """Run concurrent homepage content analysis for uploaded domains."""
    domains, error = _uploaded_domains()
    if error:
        return error
    start_time = time.time()
    results = analyze_domains(domains)
    download_id = write_download_csv(
        _temp_dir(),
        "content_",
        [
            "domain", "is_live", "http_status", "http_title", "body_size_bytes",
            "body_size_kb", "gambling_keywords_found", "india_keywords_found",
            "payment_keywords_found", "hardcoded_credentials", "credential_count",
        ],
        results,
    )
    return jsonify({
        "success": True,
        "total_domains": len(domains),
        "live_domains": sum(item["is_live"] == "Yes" for item in results),
        "domains_with_creds": sum(item["credential_count"] > 0 for item in results),
        "elapsed_seconds": round(time.time() - start_time, 1),
        "download_id": download_id,
        "results": results,
    })


@analysis_bp.post("/screenshot_report")
def api_screenshot_report():
    """Create the current Playwright liveness and DOCX screenshot report."""
    domains, error = _uploaded_domains()
    if error:
        return error
    start_time = time.time()
    report_filename = f"liveness_report_{uuid.uuid4().hex[:8]}.docx"
    try:
        generate_liveness_report(sorted(domains), report_filename)
    except Exception as report_error:
        logger.exception("Screenshot report generation failed")
        error_message = str(report_error)
        missing_browser_markers = (
            "playwright install", "executable doesn't exist", "not installed",
        )
        if any(marker in error_message.lower() for marker in missing_browser_markers):
            return jsonify({
                "error": "Playwright Chromium is not installed. Run 'python -m playwright install chromium'."
            }), 500
        return jsonify({"error": f"Failed to generate report: {error_message}"}), 500

    return jsonify({
        "success": True,
        "total_domains": len(domains),
        "elapsed_seconds": round(time.time() - start_time, 1),
        "download_filename": report_filename,
    })
