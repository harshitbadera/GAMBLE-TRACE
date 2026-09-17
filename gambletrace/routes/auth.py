"""Local login, logout, and one-time bootstrap setup routes."""

from urllib.parse import urlparse

from flask import Blueprint, abort, current_app, redirect, render_template, request, session, url_for

from gambletrace.persistence import get_database
from gambletrace.services.authentication import (
    AuthenticationError,
    authenticate,
    begin_session,
    bootstrap_admin,
    create_user,
    end_session,
    user_count,
)


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _safe_next(value: str) -> str:
    parsed = urlparse(value or "")
    return value if value and not parsed.netloc and value.startswith("/") else url_for("cases.case_list")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if not current_app.config["AUTH_ENABLED"]:
        return redirect(url_for("cases.case_list"))
    if session.get("user_id"):
        return redirect(_safe_next(request.args.get("next", "")))
    if request.method == "GET":
        return render_template(
            "login.html",
            setup_available=user_count(get_database()) == 0 and bool(current_app.config["INITIAL_SETUP_TOKEN"]),
        )
    limiter = current_app.extensions["gambletrace"]["login_limiter"]
    source = request.remote_addr or "unknown"
    remaining = limiter.blocked_for(source)
    if remaining:
        return render_template("login.html", error=f"Too many login attempts. Retry in {remaining} seconds."), 429
    user = authenticate(get_database(), request.form.get("username", ""), request.form.get("password", ""))
    if not user:
        limiter.record_failure(source)
        return render_template("login.html", error="Invalid username or password."), 401
    limiter.clear(source)
    begin_session(user)
    return redirect(_safe_next(request.form.get("next", "")))


@auth_bp.route("/setup", methods=["GET", "POST"])
def setup():
    if not current_app.config["AUTH_ENABLED"]:
        abort(404)
    if user_count(get_database()) != 0:
        abort(404)
    setup_token = current_app.config["INITIAL_SETUP_TOKEN"]
    if not setup_token:
        return render_template("setup.html", error="Initial setup is disabled. Configure GAMBLETRACE_INITIAL_SETUP_TOKEN or bootstrap credentials."), 503
    if request.method == "GET":
        return render_template("setup.html")
    submitted_token = request.form.get("setup_token", "")
    from secrets import compare_digest
    if not compare_digest(setup_token, submitted_token):
        return render_template("setup.html", error="Invalid setup token."), 403
    try:
        user = create_user(
            get_database(), request.form.get("username", ""), request.form.get("password", ""),
            role="ADMIN", minimum_length=current_app.config["AUTH_MIN_PASSWORD_LENGTH"],
        )
    except AuthenticationError as error:
        return render_template("setup.html", error=str(error)), 400
    begin_session(user)
    return redirect(url_for("cases.case_list"))


@auth_bp.post("/logout")
def logout():
    end_session()
    return redirect(url_for("auth.login"))
