"""Application factory for the GambleTrace web application."""

from datetime import timedelta
import os
import secrets
from typing import Optional

import click
from flask import Flask, abort, jsonify, redirect, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

import config


def create_app(test_config: Optional[dict] = None) -> Flask:
    """Create and configure a GambleTrace Flask application."""
    production_mode = os.environ.get("GAMBLETRACE_ENV", "development").lower() == "production"
    configured_secret = os.environ.get("GAMBLETRACE_SECRET_KEY", "")
    if production_mode and not configured_secret:
        raise RuntimeError("GAMBLETRACE_SECRET_KEY must be set in production mode")
    app = Flask(
        __name__,
        template_folder=os.path.join(config.BASE_DIR, "templates"),
    )
    app.config.from_mapping(
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,
        SECRET_KEY=configured_secret or secrets.token_urlsafe(48),
        DATABASE_PATH=os.path.join(config.DATA_DIR, "gambletrace.db"),
        CASE_STORAGE_DIR=config.CASE_STORAGE_DIR,
        AUTH_ENABLED=os.environ.get("GAMBLETRACE_AUTH_ENABLED", "true").lower() not in {"0", "false", "no"},
        AUTH_MIN_PASSWORD_LENGTH=12,
        INITIAL_SETUP_TOKEN=os.environ.get("GAMBLETRACE_INITIAL_SETUP_TOKEN", ""),
        BOOTSTRAP_ADMIN_USERNAME=os.environ.get("GAMBLETRACE_ADMIN_USERNAME", ""),
        BOOTSTRAP_ADMIN_PASSWORD=os.environ.get("GAMBLETRACE_ADMIN_PASSWORD", ""),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=production_mode,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        FORCE_HTTPS=production_mode,
        TRUSTED_PROXY_COUNT=int(os.environ.get("GAMBLETRACE_TRUSTED_PROXY_COUNT", "0")),
        EXPORT_RETENTION_DAYS=30,
        TEMP_RETENTION_DAYS=2,
        JOB_WORKER_COUNT=2,
        JOB_COOLDOWNS={
            "COLLECT_EVIDENCE": 30,
            "DISCOVER_DOMAINS": 15,
            "SCORE_CASE": 2,
            "CORRELATE_CASE": 2,
        },
    )
    if test_config:
        app.config.update(test_config)

    trusted_proxy_count = int(app.config["TRUSTED_PROXY_COUNT"])
    if trusted_proxy_count:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=trusted_proxy_count, x_proto=trusted_proxy_count, x_host=trusted_proxy_count)

    temp_dir = app.config.get("TEMP_DIR", os.path.join(config.OUTPUT_DIR, "temp"))
    os.makedirs(temp_dir, exist_ok=True)
    app.extensions["gambletrace"] = {"temp_dir": temp_dir}

    from gambletrace.persistence import init_database

    init_database(app)
    from gambletrace.services.authentication import (
        AuthenticationError,
        LoginAttemptLimiter,
        active_user,
        bootstrap_admin,
        create_user,
        csrf_token,
        valid_csrf,
    )

    if app.config["AUTH_ENABLED"]:
        try:
            bootstrap_admin(
                app.extensions["gambletrace"]["database"],
                app.config["BOOTSTRAP_ADMIN_USERNAME"],
                app.config["BOOTSTRAP_ADMIN_PASSWORD"],
                app.config["AUTH_MIN_PASSWORD_LENGTH"],
            )
        except AuthenticationError as error:
            raise RuntimeError(f"Invalid GambleTrace bootstrap account configuration: {error}") from error
    app.extensions["gambletrace"]["login_limiter"] = LoginAttemptLimiter()
    from gambletrace.services.operational_jobs import CaseJobManager
    from gambletrace.services.retention import cleanup_generated_files

    app.extensions["gambletrace"]["jobs"] = CaseJobManager(
        app.extensions["gambletrace"]["database"],
        max_workers=app.config["JOB_WORKER_COUNT"],
        cooldowns=app.config["JOB_COOLDOWNS"],
    )

    from gambletrace.routes.analysis import analysis_bp
    from gambletrace.routes.cases import cases_bp
    from gambletrace.routes.dashboard import dashboard_bp
    from gambletrace.routes.downloads import downloads_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(downloads_bp)

    @app.context_processor
    def security_context():
        return {
            "current_user": {
                "username": session.get("username", ""),
                "role": session.get("role", ""),
            } if session.get("user_id") else None,
            "csrf_token": csrf_token,
        }

    @app.before_request
    def protect_requests():
        if app.config["FORCE_HTTPS"] and not request.is_secure:
            forwarded = request.headers.get("X-Forwarded-Proto", "").lower()
            if forwarded != "https":
                return redirect(request.url.replace("http://", "https://", 1), code=308)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not valid_csrf(submitted_token):
                abort(400, "Invalid or missing CSRF token")

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({"error": "Upload exceeds the 16 MB limit"}), 413

    @app.errorhandler(429)
    def request_rate_limited(_error):
        return jsonify({"error": "Operation is rate-limited; retry later"}), 429

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        return response

    @app.cli.command("create-user")
    @click.argument("username")
    @click.password_option(confirmation_prompt=True)
    @click.option("--role", type=click.Choice(["ADMIN", "ANALYST"]), default="ANALYST")
    def create_user_command(username: str, password: str, role: str):
        """Create a local authenticated user without exposing a web admin endpoint."""
        user = create_user(
            app.extensions["gambletrace"]["database"], username, password, role,
            app.config["AUTH_MIN_PASSWORD_LENGTH"],
        )
        click.echo(f"Created {user['role'].lower()} user: {user['username']}")

    @app.cli.command("cleanup-generated-files")
    @click.option("--apply", "apply_cleanup", is_flag=True, help="Actually remove eligible generated files.")
    def cleanup_generated_files_command(apply_cleanup: bool):
        """Preview or apply conservative export/temp retention cleanup."""
        result = cleanup_generated_files(
            case_storage_dir=app.config["CASE_STORAGE_DIR"],
            temp_dir=app.extensions["gambletrace"]["temp_dir"],
            export_retention_days=app.config["EXPORT_RETENTION_DAYS"],
            temp_retention_days=app.config["TEMP_RETENTION_DAYS"],
            apply=apply_cleanup,
        )
        action = "Removed" if apply_cleanup else "Would remove"
        click.echo(f"{action} {result['removed'] if apply_cleanup else result['candidates']} generated files ({result['bytes']} bytes).")

    return app
