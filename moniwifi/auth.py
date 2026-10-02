"""Dashboard login (session cookie) and API bearer-token authentication.

Generate a password hash with:  python -m moniwifi.auth
"""

from __future__ import annotations

import getpass
import hmac
import ipaddress
import logging
import os
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta
from urllib.parse import urlparse

from flask import abort, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)

DEFAULT_SECRET_KEY = "dev-secret-key-change-in-production"
PUBLIC_PATHS = {"/login", "/api/health"}
MAX_FAILURES = 5
FAILURE_WINDOW = 300.0


def is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class AuthSettings:
    def __init__(self, username: str = "", password_hash: str = "", password: str = "", api_token: str = "") -> None:
        self.username = username.strip()
        if password and not password_hash:
            logger.warning("AUTH_PASSWORD is set in clear text; prefer AUTH_PASSWORD_HASH (python -m moniwifi.auth)")
            password_hash = generate_password_hash(password)
        self.password_hash = password_hash.strip()
        self.api_token = api_token.strip()

    @property
    def login_enabled(self) -> bool:
        return bool(self.username and self.password_hash)

    @property
    def enabled(self) -> bool:
        return self.login_enabled or bool(self.api_token)


class LoginThrottle:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: dict[str, deque] = defaultdict(deque)

    def blocked(self, key: str) -> bool:
        with self._lock:
            failures = self._failures[key]
            while failures and time.monotonic() - failures[0] > FAILURE_WINDOW:
                failures.popleft()
            return len(failures) >= MAX_FAILURES

    def fail(self, key: str) -> None:
        with self._lock:
            self._failures[key].append(time.monotonic())

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


def _token_ok(settings: AuthSettings) -> bool:
    header = request.headers.get("Authorization", "")
    if not settings.api_token or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[7:].strip().encode(), settings.api_token.encode())


def _same_origin() -> bool:
    origin = request.headers.get("Origin") or request.headers.get("Referer")
    if not origin:
        return True
    return urlparse(origin).netloc == request.host


def _safe_next(target: str | None) -> str:
    # Only local paths, so the login page cannot be used as an open redirect.
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/"


def init_auth(app, socketio, settings: AuthSettings, host: str, allow_unauthenticated: bool = False) -> None:
    if not settings.enabled:
        if not is_loopback(host) and not allow_unauthenticated:
            raise RuntimeError(
                f"Refusing to serve on {host} without authentication: set AUTH_USERNAME and "
                "AUTH_PASSWORD_HASH (or API_TOKEN), or ALLOW_UNAUTHENTICATED=true behind an authenticating proxy."
            )
        app.config["AUTH_ENABLED"] = False
        return

    app.config["AUTH_ENABLED"] = True
    if app.config.get("SECRET_KEY") in (None, "", DEFAULT_SECRET_KEY):
        logger.warning("SECRET_KEY is not set; using a random key (sessions end on restart)")
        app.config["SECRET_KEY"] = os.urandom(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    )
    throttle = LoginThrottle()

    def authenticated() -> bool:
        return bool(session.get("user")) or _token_ok(settings)

    @app.before_request
    def require_login():
        g.authenticated = authenticated()
        if request.path in PUBLIC_PATHS or g.authenticated:
            # Cookie sessions must not be driven by another site; bearer tokens are not sent automatically.
            if g.authenticated and request.method not in ("GET", "HEAD", "OPTIONS") and not _token_ok(settings):
                if not _same_origin():
                    abort(403, description="cross-origin request refused")
            return None
        if request.path.startswith("/api/"):
            return jsonify({"error": "authentication required"}), 401
        return redirect(url_for("login", next=request.full_path.rstrip("?")))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not settings.login_enabled:
            abort(404, description="login is disabled; use the API token")
        error = None
        if request.method == "POST":
            client = request.remote_addr or "unknown"
            if not _same_origin():
                abort(403, description="cross-origin login refused")
            if throttle.blocked(client):
                return render_template("login.html", error="Trop de tentatives. Reessayez dans quelques minutes."), 429
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            valid_user = hmac.compare_digest(username.encode(), settings.username.encode())
            # Always check the hash so response time does not reveal whether the username exists.
            valid_password = check_password_hash(settings.password_hash, password)
            if valid_user and valid_password:
                throttle.reset(client)
                session.clear()
                session["user"] = settings.username
                session.permanent = True
                return redirect(_safe_next(request.args.get("next")))
            throttle.fail(client)
            logger.warning("Failed login for %r from %s", username, client)
            error = "Identifiants invalides."
        return render_template("login.html", error=error), 401 if error else 200

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @socketio.on("connect")
    def socket_connect(auth=None):
        token = (auth or {}).get("token") if isinstance(auth, dict) else None
        token_ok = bool(settings.api_token and token and hmac.compare_digest(token.encode(), settings.api_token.encode()))
        if not (session.get("user") or token_ok or _token_ok(settings)):
            return False
        return None


def main() -> int:
    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Confirm: "):
        print("Passwords do not match", file=sys.stderr)
        return 1
    if len(password) < 10:
        print("Use at least 10 characters", file=sys.stderr)
        return 1
    print(generate_password_hash(password))
    return 0


if __name__ == "__main__":
    sys.exit(main())
