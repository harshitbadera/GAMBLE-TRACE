"""Local account, session, CSRF, and login-throttling helpers."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import re
import secrets
import threading
import time
import uuid
from typing import Dict, Optional

from flask import session
from werkzeug.security import check_password_hash, generate_password_hash

from gambletrace.persistence import Database


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,80}$")


class AuthenticationError(ValueError):
    """A user-facing authentication or account-provisioning error."""


class LoginAttemptLimiter:
    """Small in-process brake on repeated password guesses from an address."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 900) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def blocked_for(self, key: str) -> int:
        now = time.monotonic()
        with self._lock:
            attempts = self._attempts.setdefault(key, deque())
            while attempts and now - attempts[0] >= self.window_seconds:
                attempts.popleft()
            if len(attempts) < self.max_attempts:
                return 0
            return max(1, int(self.window_seconds - (now - attempts[0])))

    def record_failure(self, key: str) -> None:
        with self._lock:
            self._attempts.setdefault(key, deque()).append(time.monotonic())

    def clear(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)


def _normalise_username(username: str) -> str:
    value = (username or "").strip()
    if not USERNAME_PATTERN.fullmatch(value):
        raise AuthenticationError("Username must be 3–80 letters, numbers, dots, dashes, or underscores")
    return value


def _validate_password(password: str, minimum_length: int) -> str:
    if len(password or "") < minimum_length:
        raise AuthenticationError(f"Password must contain at least {minimum_length} characters")
    return password


def user_count(database: Database) -> int:
    with database.connect() as connection:
        return int(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0])


def create_user(
    database: Database, username: str, password: str, role: str = "ANALYST", minimum_length: int = 12
) -> Dict:
    """Create a local account with a modern Werkzeug password hash."""
    username = _normalise_username(username)
    password = _validate_password(password, minimum_length)
    if role not in {"ADMIN", "ANALYST"}:
        raise AuthenticationError("Invalid account role")
    with database.connect() as connection:
        exists = connection.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            raise AuthenticationError("That username already exists")
        user_id = str(uuid.uuid4())
        connection.execute(
            """
            INSERT INTO users (id, username, password_hash, role)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, username, generate_password_hash(password), role),
        )
        row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row)


def bootstrap_admin(
    database: Database, username: str, password: str, minimum_length: int = 12
) -> Optional[Dict]:
    """Create a first admin only when the account table is empty."""
    if not username and not password:
        return None
    if not username or not password:
        raise AuthenticationError("Set both bootstrap admin username and password")
    if user_count(database):
        return None
    return create_user(database, username, password, role="ADMIN", minimum_length=minimum_length)


def authenticate(database: Database, username: str, password: str) -> Optional[Dict]:
    """Return an active account after password verification, otherwise None."""
    with database.connect() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1", ((username or "").strip(),)
        ).fetchone()
        if not row or not check_password_hash(row["password_hash"], password or ""):
            return None
        connection.execute("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
        refreshed = connection.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone()
    return dict(refreshed)


def active_user(database: Database, user_id: str) -> Optional[Dict]:
    with database.connect() as connection:
        row = connection.execute(
            "SELECT id, username, role, is_active FROM users WHERE id = ? AND is_active = 1", (user_id,)
        ).fetchone()
    return dict(row) if row else None


def csrf_token() -> str:
    """Return a session-bound token for state-changing browser requests."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def valid_csrf(token: str | None) -> bool:
    expected = session.get("csrf_token")
    return bool(expected and token and secrets.compare_digest(expected, token))


def begin_session(user: Dict) -> None:
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    csrf_token()
    session.permanent = True


def end_session() -> None:
    session.clear()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
