"""Case workspace routes for investigation management."""

from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from gambletrace.persistence import get_database
from gambletrace.services.case_management import (
    add_case_note,
    add_case_tag,
    case_dashboard_summary,
    create_case,
    get_case,
    import_seed_source,
    list_cases,
    update_case_status,
)
from gambletrace.services.domain_input import (
    read_domains_from_path,
    remove_stored_source,
    store_case_source_upload,
)
from gambletrace.services.case_discovery import run_case_discovery
from gambletrace.services.case_exports import (
    generate_case_report,
    generate_evidence_zip,
    generate_graph_export,
    generate_ioc_export,
)
from gambletrace.services.case_views import (
    get_case_domain_detail,
    get_cluster_detail,
    list_case_evidence,
    list_case_timeline,
)
from gambletrace.services.correlation import correlate_case_domains
from gambletrace.services.evidence_collection import collect_case_domain
from gambletrace.services.investigation_graph import get_investigation_graph
from gambletrace.services.monitoring import list_case_alerts, update_alert_status
from gambletrace.services.observations import record_domain_observation
from gambletrace.services.operational_jobs import JobRejected
from gambletrace.services.scoring import score_case_domains


cases_bp = Blueprint("cases", __name__, url_prefix="/cases")


def _notice_redirect(case_id: str, notice: str):
    return redirect(url_for("cases.case_detail", case_id=case_id, notice=notice))


def _jobs():
    """Return the application-local manager for long-running case operations."""
    return current_app.extensions["gambletrace"]["jobs"]


@cases_bp.get("")
def case_list():
    """Show the case workspace and its current investigation totals."""
    database = get_database()
    return render_template(
        "cases.html",
        cases=list_cases(database),
        summary=case_dashboard_summary(database),
    )


@cases_bp.route("/new", methods=["GET", "POST"])
def new_case():
    """Create a new investigation case."""
    if request.method == "GET":
        return render_template("case_form.html")
    try:
        case = create_case(
            get_database(),
            title=request.form.get("title", ""),
            description=request.form.get("description", ""),
            owner_name=request.form.get("owner_name", ""),
            priority=request.form.get("priority", "MEDIUM"),
            scope_note=request.form.get("scope_note", ""),
            authorization_note=request.form.get("authorization_note", ""),
        )
    except ValueError as error:
        return render_template("case_form.html", error=str(error), form=request.form), 400
    return _notice_redirect(case["id"], f"Created case {case['case_number']}")


@cases_bp.get("/<case_id>")
def case_detail(case_id: str):
    """Show one case, its seed domains, notes, tags, and activity."""
    case = get_case(get_database(), case_id)
    if not case:
        abort(404)
    return render_template(
        "case_detail.html",
        case=case,
        jobs=_jobs().list_case_jobs(case_id),
        notice=request.args.get("notice", ""),
    )


@cases_bp.get("/<case_id>/jobs")
def case_jobs(case_id: str):
    """Small polling endpoint for visible background-operation status."""
    if not get_case(get_database(), case_id):
        abort(404)
    jobs = _jobs().list_case_jobs(case_id)
    return jsonify({"jobs": jobs})


@cases_bp.get("/<case_id>/domains/<case_domain_id>")
def domain_detail(case_id: str, case_domain_id: str):
    """Show all retained observations and artifacts for one case domain."""
    try:
        detail = get_case_domain_detail(get_database(), case_id, case_domain_id)
    except LookupError:
        abort(404)
    if detail is None:
        abort(404)
    return render_template("domain_detail.html", **detail, notice=request.args.get("notice", ""))


@cases_bp.get("/<case_id>/evidence")
def evidence_viewer(case_id: str):
    """Show the immutable evidence register for an investigation."""
    try:
        evidence = list_case_evidence(get_database(), case_id)
    except LookupError:
        abort(404)
    return render_template("evidence_viewer.html", **evidence)


@cases_bp.get("/<case_id>/evidence/<artifact_id>/download")
def download_evidence_artifact(case_id: str, artifact_id: str):
    """Serve a case-owned evidence file without exposing arbitrary paths."""
    database = get_database()
    with database.connect() as connection:
        artifact = connection.execute(
            """
            SELECT artifact.stored_path, artifact.mime_type
            FROM evidence_artifacts AS artifact
            JOIN domain_observations AS observation ON observation.id = artifact.observation_id
            JOIN case_domains AS domain ON domain.id = observation.case_domain_id
            WHERE artifact.id = ? AND domain.case_id = ?
            """,
            (artifact_id, case_id),
        ).fetchone()

    if artifact is None:
        abort(404)
    storage_root = Path(current_app.config["CASE_STORAGE_DIR"]).resolve()
    target = (storage_root / artifact["stored_path"]).resolve()
    if storage_root not in target.parents or not target.is_file():
        abort(404)
    return send_file(
        target,
        mimetype=artifact["mime_type"] or "application/octet-stream",
        as_attachment=True,
        download_name=target.name,
    )


@cases_bp.get("/<case_id>/clusters/<cluster_id>")
def cluster_detail(case_id: str, cluster_id: str):
    """Show the retained evidence behind one infrastructure cluster."""
    try:
        detail = get_cluster_detail(get_database(), case_id, cluster_id)
    except LookupError:
        abort(404)
    if detail is None:
        abort(404)
    return render_template("cluster_detail.html", **detail)


@cases_bp.get("/<case_id>/timeline")
def case_timeline(case_id: str):
    """Show case activity and domain observations in chronological order."""
    try:
        timeline = list_case_timeline(get_database(), case_id)
    except LookupError:
        abort(404)
    return render_template("timeline.html", **timeline)


@cases_bp.get("/<case_id>/alerts")
def case_alerts(case_id: str):
    """Show historical monitoring alerts and their analyst review status."""
    case = get_case(get_database(), case_id)
    if not case:
        abort(404)
    return render_template("alerts.html", case=case, alerts=list_case_alerts(get_database(), case_id))


@cases_bp.get("/<case_id>/exports")
def case_exports(case_id: str):
    """Show investigator handoff exports generated from retained case data."""
    case = get_case(get_database(), case_id)
    if not case:
        abort(404)
    return render_template("exports.html", case=case)


def _send_case_export(generator, case_id: str, *args):
    """Generate one bounded, case-owned export and send it as a download."""
    try:
        path = generator(get_database(), case_id, current_app.config["CASE_STORAGE_DIR"], *args)
    except LookupError:
        abort(404)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    mime_types = {
        ".csv": "text/csv", ".json": "application/json", ".txt": "text/plain",
        ".md": "text/markdown", ".graphml": "application/graphml+xml", ".zip": "application/zip",
    }
    return send_file(path, mimetype=mime_types.get(path.suffix, "application/octet-stream"), as_attachment=True, download_name=path.name)


@cases_bp.get("/<case_id>/exports/report")
def export_case_report(case_id: str):
    return _send_case_export(generate_case_report, case_id)


@cases_bp.get("/<case_id>/exports/iocs/<fmt>")
def export_case_iocs(case_id: str, fmt: str):
    return _send_case_export(generate_ioc_export, case_id, fmt)


@cases_bp.get("/<case_id>/exports/graph/<fmt>")
def export_case_graph(case_id: str, fmt: str):
    return _send_case_export(generate_graph_export, case_id, fmt)


@cases_bp.get("/<case_id>/exports/evidence.zip")
def export_case_evidence(case_id: str):
    return _send_case_export(generate_evidence_zip, case_id)


@cases_bp.post("/<case_id>/alerts/<alert_id>/status")
def change_alert_status(case_id: str, alert_id: str):
    """Record analyst acknowledgement or resolution of a monitoring alert."""
    try:
        update_alert_status(get_database(), case_id, alert_id, request.form.get("status", ""))
    except LookupError:
        abort(404)
    except ValueError as error:
        return redirect(url_for("cases.case_alerts", case_id=case_id, notice=str(error)))
    return redirect(url_for("cases.case_alerts", case_id=case_id, notice="Alert status updated"))


@cases_bp.get("/<case_id>/graph")
def investigation_graph(case_id: str):
    """Render the browser-side, evidence-backed relationship graph for a case."""
    try:
        graph = get_investigation_graph(get_database(), case_id)
    except LookupError:
        abort(404)
    for node in graph["nodes"]:
        node["detail_url"] = url_for(
            "cases.domain_detail", case_id=case_id, case_domain_id=node["id"]
        )
    return render_template("investigation_graph.html", graph=graph)


@cases_bp.post("/<case_id>/seeds")
def import_seeds(case_id: str):
    """Import seed domains into an existing case."""
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return _notice_redirect(case_id, "Select a CSV, Excel, or text file first")
    source = None
    try:
        source = store_case_source_upload(
            uploaded, current_app.config["CASE_STORAGE_DIR"], case_id
        )
        domains = read_domains_from_path(source.absolute_path, source.original_name)
        if not domains:
            remove_stored_source(source)
            return _notice_redirect(case_id, "No valid domains found in the uploaded file")
        added, submitted = import_seed_source(
            get_database(), case_id, source, domains
        )
    except LookupError:
        if source:
            remove_stored_source(source)
        abort(404)
    except ValueError as error:
        if source:
            remove_stored_source(source)
        return _notice_redirect(case_id, str(error))
    return _notice_redirect(
        case_id,
        f"Preserved {source.original_name} and imported {added} new seed domains from {submitted} valid entries",
    )


@cases_bp.post("/<case_id>/notes")
def create_note(case_id: str):
    """Add a case note."""
    try:
        add_case_note(
            get_database(),
            case_id,
            request.form.get("body", ""),
            request.form.get("author_name", ""),
        )
    except (LookupError, ValueError) as error:
        return _notice_redirect(case_id, str(error))
    return _notice_redirect(case_id, "Note added")


@cases_bp.post("/<case_id>/observations")
def create_observation(case_id: str):
    """Record a manual, append-only observation for a domain in this case."""
    try:
        observation = record_domain_observation(
            get_database(),
            case_id=case_id,
            case_domain_id=request.form.get("case_domain_id", ""),
            outcome=request.form.get("outcome", ""),
            availability=request.form.get("availability", ""),
            final_url=request.form.get("final_url", ""),
            http_status=request.form.get("http_status", ""),
            page_title=request.form.get("page_title", ""),
            error_message=request.form.get("error_message", ""),
        )
    except (LookupError, ValueError) as error:
        return _notice_redirect(case_id, str(error))
    return _notice_redirect(case_id, f"Recorded immutable observation {observation['id'][:8]}")


@cases_bp.post("/<case_id>/collect")
def collect_evidence(case_id: str):
    """Queue an authorised technical evidence collection without blocking the UI."""
    case_domain_id = request.form.get("case_domain_id", "")
    capture_screenshot = request.form.get("capture_screenshot") == "on"
    case_storage_dir = current_app.config["CASE_STORAGE_DIR"]
    database = get_database()

    def task(report):
        report(10, "Starting DNS, HTTP, RDAP, TLS, and content collection")
        collected = collect_case_domain(
            database,
            case_id=case_id,
            case_domain_id=case_domain_id,
            capture_screenshot=capture_screenshot,
            case_storage_dir=case_storage_dir,
        )
        report(88, "Hashing artifacts and writing the immutable evidence package")
        observation = collected["observation"]
        alerts = collected.get("alerts", [])
        alert_suffix = f"; {len(alerts)} monitoring alert(s) created" if alerts else ""
        return {
            "message": f"Collection completed: {observation['outcome']} observation {observation['id'][:8]}{alert_suffix}",
            "observation_id": observation["id"],
            "outcome": observation["outcome"],
            "alert_count": len(alerts),
        }

    try:
        job = _jobs().submit(
            case_id=case_id,
            case_domain_id=case_domain_id,
            job_type="COLLECT_EVIDENCE",
            task=task,
        )
    except LookupError:
        abort(404)
    except (ValueError, JobRejected) as error:
        return _notice_redirect(case_id, str(error))
    return _notice_redirect(
        case_id,
        f"Evidence collection queued as job {job.id[:8]}; progress updates below",
    )


@cases_bp.post("/<case_id>/discover")
def discover_case_domains(case_id: str):
    """Queue selected discovery pivots so the case page remains responsive."""
    case_domain_id = request.form.get("case_domain_id", "")
    modes = request.form.getlist("modes")
    database = get_database()

    def task(report):
        report(10, "Validating the selected discovery pivots")
        discovery = run_case_discovery(
            database,
            case_id=case_id,
            source_case_domain_id=case_domain_id,
            modes=modes,
        )
        report(90, "Recording discovered domains and pivot provenance")
        return {
            "message": f"Discovery found {discovery['candidates_found']} candidates and added {discovery['added']} case domains",
            "candidates_found": discovery["candidates_found"],
            "added": discovery["added"],
            "added_by_source_type": discovery["added_by_source_type"],
        }

    try:
        job = _jobs().submit(
            case_id=case_id,
            case_domain_id=case_domain_id,
            job_type="DISCOVER_DOMAINS",
            task=task,
        )
    except LookupError:
        abort(404)
    except (ValueError, JobRejected) as error:
        return _notice_redirect(case_id, str(error))
    return _notice_redirect(
        case_id,
        f"Domain discovery queued as job {job.id[:8]}; progress updates below",
    )


@cases_bp.post("/<case_id>/score")
def score_case(case_id: str):
    """Queue transparent case scoring without blocking the analyst workspace."""
    database = get_database()

    def task(report):
        report(15, "Calculating evidence-based domain risk factors")
        summary = score_case_domains(database, case_id)
        report(90, "Persisting immutable risk assessments")
        return {
            "message": f"Scored {summary['domains_scored']} domains: {summary['high_confidence']} high-confidence and {summary['medium_confidence']} medium-confidence",
            **summary,
        }

    try:
        job = _jobs().submit(case_id=case_id, job_type="SCORE_CASE", task=task)
    except LookupError:
        abort(404)
    except (ValueError, JobRejected) as error:
        return _notice_redirect(case_id, str(error))
    return _notice_redirect(case_id, f"Risk scoring queued as job {job.id[:8]}; progress updates below")


@cases_bp.post("/<case_id>/correlate")
def correlate_case(case_id: str):
    """Queue evidence correlation and cluster refresh for this case."""
    database = get_database()

    def task(report):
        report(15, "Comparing retained infrastructure and content signals")
        summary = correlate_case_domains(database, case_id)
        report(90, "Persisting relationship edges and infrastructure clusters")
        confidence = ", ".join(
            f"{level.lower()}: {count}" for level, count in sorted(summary["by_confidence"].items())
        )
        suffix = f" ({confidence})" if confidence else ""
        return {
            "message": f"Correlation created or refreshed {summary['relationships']} edges and {summary['clusters']} clusters{suffix}",
            **summary,
        }

    try:
        job = _jobs().submit(case_id=case_id, job_type="CORRELATE_CASE", task=task)
    except LookupError:
        abort(404)
    except (ValueError, JobRejected) as error:
        return _notice_redirect(case_id, str(error))
    return _notice_redirect(case_id, f"Correlation queued as job {job.id[:8]}; progress updates below")


@cases_bp.post("/<case_id>/tags")
def create_tag(case_id: str):
    """Attach a new or existing tag to a case."""
    try:
        add_case_tag(
            get_database(),
            case_id,
            request.form.get("tag_name", ""),
            request.form.get("color", "#64748b"),
        )
    except (LookupError, ValueError) as error:
        return _notice_redirect(case_id, str(error))
    return _notice_redirect(case_id, "Tag added")


@cases_bp.post("/<case_id>/status")
def change_status(case_id: str):
    """Update the workflow status for a case."""
    try:
        update_case_status(get_database(), case_id, request.form.get("status", ""))
    except LookupError:
        abort(404)
    except ValueError as error:
        return _notice_redirect(case_id, str(error))
    return _notice_redirect(case_id, "Case status updated")
