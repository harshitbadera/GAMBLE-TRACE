"""Small, case-scoped background job runner for analyst-triggered operations."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
import json
import logging
import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional

from gambletrace.persistence import Database


LOGGER = logging.getLogger(__name__)
ACTIVE_STATUSES = ("QUEUED", "RUNNING")
VALID_JOB_TYPES = {"COLLECT_EVIDENCE", "DISCOVER_DOMAINS", "SCORE_CASE", "CORRELATE_CASE"}
JobTask = Callable[[Callable[[int, str], None]], Dict[str, Any]]


class JobRejected(ValueError):
    """A job cannot be scheduled because its scope is active or rate-limited."""


class ScopeRateLimiter:
    """Thread-safe, process-local cooldowns for external or expensive case actions."""

    def __init__(self) -> None:
        self._last_accepted: dict[str, float] = {}
        self._lock = threading.Lock()

    def reserve(self, key: str, cooldown_seconds: float) -> int:
        """Reserve a scope and return remaining seconds when it is still cooling down."""
        if cooldown_seconds <= 0:
            return 0
        now = time.monotonic()
        with self._lock:
            previous = self._last_accepted.get(key)
            if previous is not None:
                remaining = cooldown_seconds - (now - previous)
                if remaining > 0:
                    return max(1, int(remaining + 0.999))
            self._last_accepted[key] = now
        return 0


@dataclass(frozen=True)
class SubmittedJob:
    id: str
    case_id: str
    case_domain_id: Optional[str]
    job_type: str


def _audit(connection, case_id: str, event_type: str, payload: Dict[str, Any]) -> None:
    connection.execute(
        """
        INSERT INTO audit_events (id, case_id, event_type, event_data_json)
        VALUES (?, ?, ?, ?)
        """,
        (str(uuid.uuid4()), case_id, event_type, json.dumps(payload, sort_keys=True)),
    )


class CaseJobManager:
    """Persisted-status jobs backed by a deliberately small local thread pool.

    This is suitable for the development deployment used by GambleTrace. Jobs
    are analyst-triggered and remain visible after a page refresh because their
    status lives in SQLite. A production multi-process deployment should later
    replace this runner with a durable queue.
    """

    def __init__(
        self,
        database: Database,
        max_workers: int = 2,
        cooldowns: Optional[Dict[str, float]] = None,
    ) -> None:
        self.database = database
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, int(max_workers)), thread_name_prefix="gambletrace-job"
        )
        self._cooldowns = cooldowns or {}
        self._rate_limiter = ScopeRateLimiter()
        self._futures: dict[str, Future] = {}
        self._future_lock = threading.Lock()

    def submit(
        self,
        *,
        case_id: str,
        job_type: str,
        task: JobTask,
        case_domain_id: Optional[str] = None,
    ) -> SubmittedJob:
        """Validate, persist, and schedule a new background operation."""
        if job_type not in VALID_JOB_TYPES:
            raise ValueError("Unsupported background job type")
        self._validate_scope(case_id, case_domain_id)
        self._reject_active_duplicate(case_id, case_domain_id, job_type)
        scope_key = f"{case_id}:{case_domain_id or 'case'}:{job_type}"
        remaining = self._rate_limiter.reserve(
            scope_key, float(self._cooldowns.get(job_type, 0))
        )
        if remaining:
            raise JobRejected(
                f"{job_type.replace('_', ' ').title()} is rate-limited for this scope; retry in {remaining}s"
            )

        job = SubmittedJob(str(uuid.uuid4()), case_id, case_domain_id, job_type)
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO job_runs (id, case_id, case_domain_id, job_type, status, progress_percent, message)
                VALUES (?, ?, ?, ?, 'QUEUED', 0, 'Waiting for an available worker')
                """,
                (job.id, job.case_id, job.case_domain_id, job.job_type),
            )
            _audit(connection, case_id, "JOB_QUEUED", {
                "job_id": job.id, "job_type": job_type, "case_domain_id": case_domain_id,
            })
        future = self._executor.submit(self._run, job, task)
        with self._future_lock:
            self._futures[job.id] = future
        return job

    def list_case_jobs(self, case_id: str, limit: int = 12) -> list[Dict[str, Any]]:
        """Return recent persisted job state for polling and page rendering."""
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT job_runs.*, domains.canonical_name
                FROM job_runs
                LEFT JOIN case_domains ON case_domains.id = job_runs.case_domain_id
                LEFT JOIN domains ON domains.id = case_domains.domain_id
                WHERE job_runs.case_id = ?
                ORDER BY job_runs.requested_at DESC, job_runs.id DESC
                LIMIT ?
                """,
                (case_id, max(1, min(int(limit), 100))),
            ).fetchall()
        jobs = []
        for row in rows:
            job = dict(row)
            try:
                job["result"] = json.loads(job.pop("result_json") or "{}")
            except json.JSONDecodeError:
                job["result"] = {}
            jobs.append(job)
        return jobs

    def wait(self, job_id: str, timeout: Optional[float] = None) -> Any:
        """Test/support helper: wait for an in-process submitted job."""
        with self._future_lock:
            future = self._futures.get(job_id)
        if future is None:
            raise LookupError("Job is not active in this application process")
        return future.result(timeout=timeout)

    def _validate_scope(self, case_id: str, case_domain_id: Optional[str]) -> None:
        with self.database.connect() as connection:
            case_exists = connection.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone()
            if not case_exists:
                raise LookupError("Case not found")
            if case_domain_id:
                domain_exists = connection.execute(
                    "SELECT 1 FROM case_domains WHERE id = ? AND case_id = ?",
                    (case_domain_id, case_id),
                ).fetchone()
                if not domain_exists:
                    raise LookupError("Domain is not part of this case")

    def _reject_active_duplicate(
        self, case_id: str, case_domain_id: Optional[str], job_type: str
    ) -> None:
        scope_clause = "case_domain_id = ?" if case_domain_id else "case_domain_id IS NULL"
        parameters: tuple[Any, ...] = (
            (case_id, case_domain_id, job_type, *ACTIVE_STATUSES)
            if case_domain_id else (case_id, job_type, *ACTIVE_STATUSES)
        )
        with self.database.connect() as connection:
            row = connection.execute(
                f"""
                SELECT id FROM job_runs
                WHERE case_id = ? AND {scope_clause} AND job_type = ?
                  AND status IN (?, ?)
                LIMIT 1
                """,
                parameters,
            ).fetchone()
        if row:
            raise JobRejected("An identical operation is already queued or running")

    def _report(self, job: SubmittedJob, progress_percent: int, message: str) -> None:
        progress = max(0, min(99, int(progress_percent)))
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE job_runs SET progress_percent = ?, message = ?
                WHERE id = ? AND status IN ('QUEUED', 'RUNNING')
                """,
                (progress, message[:500], job.id),
            )

    def _run(self, job: SubmittedJob, task: JobTask) -> Dict[str, Any]:
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE job_runs
                SET status = 'RUNNING', progress_percent = 3,
                    message = 'Operation started', started_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (job.id,),
            )
        try:
            result = task(lambda progress, message: self._report(job, progress, message)) or {}
        except Exception as error:  # Persist safe job error, while retaining full server-side logs.
            LOGGER.exception("Background job %s failed", job.id)
            message = f"{type(error).__name__}: {str(error)}"[:1000]
            with self.database.connect() as connection:
                connection.execute(
                    """
                    UPDATE job_runs
                    SET status = 'FAILED', progress_percent = 100, message = 'Operation failed',
                        error_message = ?, finished_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (message, job.id),
                )
                _audit(connection, job.case_id, "JOB_FAILED", {
                    "job_id": job.id, "job_type": job.job_type, "error": message,
                })
            return {"status": "FAILED", "error": message}

        result_json = json.dumps(result, default=str, sort_keys=True)
        final_message = str(result.get("message") or "Operation completed")[:500]
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE job_runs
                SET status = 'SUCCEEDED', progress_percent = 100, message = ?,
                    result_json = ?, finished_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (final_message, result_json, job.id),
            )
            _audit(connection, job.case_id, "JOB_SUCCEEDED", {
                "job_id": job.id, "job_type": job.job_type, "result": result,
            })
        return result
