import unittest
from unittest import mock

from werkzeug.security import generate_password_hash

import config
from moniwifi.application import create_app
from moniwifi.auth import is_loopback
from tests.helpers import FakeNetwork

PASSWORD = "correct horse battery"


def auth_app(**overrides):
    settings = {
        "AUTH_USERNAME": "admin",
        "AUTH_PASSWORD_HASH": generate_password_hash(PASSWORD),
        "AUTH_PASSWORD": "",
        "API_TOKEN": "s3cret-token",
        "HOST": "0.0.0.0",
    }
    settings.update(overrides)
    with mock.patch.multiple(config, **settings):
        return create_app(db_path="", network=FakeNetwork())


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.app, self.socketio, self.monitor = auth_app()
        self.client = self.app.test_client()

    def login(self, password=PASSWORD, next_url=""):
        return self.client.post(f"/login{next_url}", data={"username": "admin", "password": password})

    def test_anonymous_requests_are_refused(self):
        self.assertEqual(self.client.get("/api/stats").status_code, 401)
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        health = self.client.get("/api/health")
        self.assertEqual(set(health.get_json()), {"status"})

    def test_login_session_and_logout(self):
        self.assertEqual(self.login("wrong").status_code, 401)
        response = self.login(next_url="?next=/api/stats")
        self.assertEqual((response.status_code, response.headers["Location"]), (302, "/api/stats"))
        self.assertEqual(self.client.get("/api/stats").status_code, 200)
        self.assertIn("threads", self.client.get("/api/health").get_json())
        self.assertIn(b'action="/logout"', self.client.get("/").data)
        self.client.post("/logout")
        self.assertEqual(self.client.get("/api/stats").status_code, 401)

    def test_open_redirect_is_blocked(self):
        response = self.login(next_url="?next=//evil.example/")
        self.assertEqual(response.headers["Location"], "/")

    def test_bearer_token(self):
        headers = {"Authorization": "Bearer s3cret-token"}
        self.assertEqual(self.client.get("/api/stats", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/stats", headers={"Authorization": "Bearer nope"}).status_code, 401)
        response = self.client.post("/api/allowlist", json={"ip": "192.168.1.5"}, headers={**headers, "Origin": "https://evil.example"})
        self.assertEqual(response.status_code, 201)  # tokens are not ambient credentials

    def test_cross_origin_session_writes_are_refused(self):
        self.login()
        response = self.client.post("/api/allowlist", json={"ip": "192.168.1.5"}, headers={"Origin": "https://evil.example"})
        self.assertEqual(response.status_code, 403)
        response = self.client.post("/api/allowlist", json={"ip": "192.168.1.5"}, headers={"Origin": "http://localhost"})
        self.assertEqual(response.status_code, 201)

    def test_login_rate_limit(self):
        for _ in range(5):
            self.login("wrong")
        self.assertEqual(self.login().status_code, 429)

    def test_socketio_requires_authentication(self):
        anonymous = self.socketio.test_client(self.app, flask_test_client=self.client)
        self.assertFalse(anonymous.is_connected())
        with_token = self.socketio.test_client(self.app, auth={"token": "s3cret-token"})
        self.assertTrue(with_token.is_connected())
        self.login()
        session_client = self.socketio.test_client(self.app, flask_test_client=self.client)
        self.assertTrue(session_client.is_connected())


class AuthConfigurationTests(unittest.TestCase):
    def test_public_bind_without_auth_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "Refusing to serve"):
            auth_app(AUTH_USERNAME="", AUTH_PASSWORD_HASH="", API_TOKEN="")

    def test_explicit_opt_out_and_loopback(self):
        with mock.patch.object(config, "ALLOW_UNAUTHENTICATED", True):
            app, _, _ = auth_app(AUTH_USERNAME="", AUTH_PASSWORD_HASH="", API_TOKEN="")
        self.assertEqual(app.test_client().get("/api/stats").status_code, 200)
        app, _, _ = auth_app(AUTH_USERNAME="", AUTH_PASSWORD_HASH="", API_TOKEN="", HOST="127.0.0.1")
        self.assertFalse(app.config["AUTH_ENABLED"])

    def test_plain_password_is_hashed(self):
        app, _, _ = auth_app(AUTH_PASSWORD_HASH="", AUTH_PASSWORD=PASSWORD)
        client = app.test_client()
        self.assertEqual(client.post("/login", data={"username": "admin", "password": PASSWORD}).status_code, 302)

    def test_token_only_mode_has_no_login_page(self):
        app, _, _ = auth_app(AUTH_USERNAME="", AUTH_PASSWORD_HASH="")
        self.assertEqual(app.test_client().get("/login").status_code, 404)

    def test_is_loopback(self):
        self.assertTrue(all(is_loopback(host) for host in ("127.0.0.1", "::1", "localhost")))
        self.assertFalse(any(is_loopback(host) for host in ("0.0.0.0", "192.168.1.2", "example.com")))


if __name__ == "__main__":
    unittest.main()
