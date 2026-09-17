"""Download routes for generated dashboard artifacts."""

import os

import config
from flask import Blueprint, current_app, jsonify, send_file

from gambletrace.services.artifacts import find_download_csv


downloads_bp = Blueprint("downloads", __name__, url_prefix="/api")


@downloads_bp.get("/download/<download_id>")
def api_download(download_id: str):
    """Download one of the temporary CSV artifacts created by the dashboard."""
    temp_dir = current_app.extensions["gambletrace"]["temp_dir"]
    found = find_download_csv(temp_dir, download_id)
    if not found:
        return jsonify({"error": "File not found"}), 404
    path, filename = found
    return send_file(path, mimetype="text/csv", as_attachment=True, download_name=filename)


@downloads_bp.get("/download_report/<filename>")
def api_download_report(filename: str):
    """Download a generated DOCX liveness report."""
    safe_filename = os.path.basename(filename)
    path = os.path.join(config.OUTPUT_DIR, "temp", safe_filename)
    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 404
    return send_file(
        path,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=safe_filename,
    )
