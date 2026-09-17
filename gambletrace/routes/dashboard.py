"""Dashboard page routes."""

from flask import Blueprint, render_template


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/")
def index():
    """Render the current intelligence-collection dashboard."""
    return render_template("index.html")
