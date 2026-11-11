"""Public login lifecycle with only the external identity transport replaced."""
import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path
import time
import unittest
from urllib.parse import parse_qs, quote_plus, urlencode, urlsplit

import requests

from hiro_app_auth import AuthError, Grant, HiroAuth, HostedConfig


class IdentityTransport:
    issuer = "https://identity.test"
    client = "synthetic + client"
    secret = "synthetic + secret"

    def __init__(self):
        self.requests = []
        self.claim = {"active": True, "sub": "synthetic-user", "client_id": self.client,
                      "aud": "urn:hiro:app:" + self.client, "scope": "openid hiro.app",
                      "exp": int(time.time()) + 3600, "iss": self.issuer}

    def __call__(self, request, **kwargs):
        self.requests.append(request)
        path = urlsplit(request.url).path
        if path == "/.well-known/openid-configuration":
            payload = {"issuer": self.issuer, **{name + "_endpoint": self.issuer + "/" + name
                       for name in ("authorization", "token", "introspection", "revocation", "userinfo")}}
        elif path == "/token":
            payload = {"access_token": "synthetic-token", "token_type": "Bearer", "scope": "openid hiro.app"}
        elif path == "/introspection":
            payload = self.claim
        elif path == "/userinfo":
            payload = {"sub": self.claim["sub"]}
        elif path == "/revocation":
            self.claim["active"] = False
            payload = {}
        else:
            raise AssertionError("Unexpected external identity endpoint")
        response = requests.Response()
        response.status_code = 200
        response.request = request
        response.url = request.url
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps(payload).encode("utf-8")
        response._content_consumed = True
        return response


class AuthStoryTests(unittest.TestCase):
    def test_login_check_revocation_and_logout(self):
        identity = IdentityTransport()
        auth = HiroAuth(HostedConfig(identity.issuer, identity.client, identity.secret, "https://app.test"),
                        transport=identity)

        def login():
            location, pending = auth.login()
            query = parse_qs(urlsplit(location).query)
            self.assertEqual(query["code_challenge_method"], ["S256"])
            self.assertEqual(query["redirect_uri"], ["https://app.test/auth/callback"])
            self.assertEqual(query["scope"], ["openid hiro.app"])
            callback = "/auth/callback?" + urlencode({"state": query["state"][0], "code": "synthetic-code"})
            session = auth.callback({"Cookie": pending.split(";", 1)[0]}, callback)
            token_request = next(request for request in reversed(identity.requests) if request.url.endswith("/token"))
            fields = parse_qs(token_request.body)
            verifier = fields["code_verifier"][0]
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            self.assertEqual(query["code_challenge"], [challenge])
            credentials = quote_plus(identity.client) + ":" + quote_plus(identity.secret)
            self.assertEqual(token_request.headers["Authorization"], "Basic " + base64.b64encode(credentials.encode()).decode())
            self.assertTrue(session.startswith("__Host-hiro-app-session="))
            self.assertIn("Path=/; Secure; HttpOnly; SameSite=Lax", session)
            self.assertNotIn("Domain=", session)
            return {"Cookie": session.split(";", 1)[0]}

        headers = login()
        before = len([request for request in identity.requests if request.url.endswith("/introspection")])
        grant = auth.authenticate(headers)
        self.assertIsInstance(grant, Grant)
        self.assertEqual(grant.owner, {"issuer": identity.issuer, "subject": "synthetic-user"})
        self.assertIs(auth.check(grant), grant)
        self.assertIs(auth.authenticate(headers), grant)
        after = len([request for request in identity.requests if request.url.endswith("/introspection")])
        self.assertEqual(after - before, 3)
        identity.claim["active"] = False
        with self.assertRaises(AuthError) as rejected:
            auth.authenticate(headers)
        self.assertEqual(rejected.exception.status, 401)
        self.assertEqual(auth.cookie(auth.SESSION_COOKIE, "", clear=True),
                         "__Host-hiro-app-session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
        with self.assertRaises(AuthError):
            auth.check(grant)
        identity.claim["active"] = True
        headers = login()
        grant = auth.authenticate(headers)
        self.assertTrue(auth.logout(headers))
        self.assertFalse(identity.claim["active"])
        with self.assertRaises(AuthError):
            auth.check(grant)
        with self.assertRaises(AuthError):
            auth.authenticate(headers)


    def test_http_browser_with_https_backchannels(self):
        identity = IdentityTransport()
        app = "http://10.23.0.10:8081"
        browser = "http://10.23.0.10:8080"
        origins = (app, browser)
        config = HostedConfig(identity.issuer, identity.client, identity.secret, app, origins, browser)
        auth = HiroAuth(config, transport=identity)
        location, pending = auth.login()
        query = parse_qs(urlsplit(location).query)
        self.assertEqual(location.split("/authorization")[0], browser)
        self.assertEqual(query["redirect_uri"], [app + "/auth/callback"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        callback = "/auth/callback?" + urlencode({"code": "synthetic-code", "state": query["state"][0]})
        headers = {"Cookie": pending.split(";", 1)[0]}
        session = auth.callback(headers, callback)
        with self.assertRaises(AuthError):
            auth.callback(headers, callback)
        token_request = next(request for request in identity.requests if request.url.endswith("/token"))
        verifier = parse_qs(token_request.body)["code_verifier"][0]
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(query["code_challenge"], [challenge])
        self.assertTrue(all(request.url.startswith(identity.issuer + "/") for request in identity.requests))
        namespace = hashlib.sha256(identity.client.encode()).hexdigest()[:32]
        self.assertTrue(session.startswith("hiro-app-" + namespace + "="))
        self.assertIn("Path=/; HttpOnly; SameSite=Lax", session)
        self.assertNotIn("Secure", session)
        session_headers = {"Cookie": session.split(";", 1)[0]}
        grant = auth.authenticate(session_headers)
        other = HiroAuth(HostedConfig(identity.issuer, "other-app", identity.secret, app, origins, browser), transport=identity)
        self.assertNotEqual(other.SESSION_COOKIE, auth.SESSION_COOKIE)
        with self.assertRaises(AuthError):
            other.authenticate(session_headers)
        for change in ("state", "duplicate", "path", "origin", "fragment"):
            location, cookie = auth.login()
            state = parse_qs(urlsplit(location).query)["state"][0]
            path = "/auth/callback?" + urlencode({"code": "synthetic-code", "state": "wrong" if change == "state" else state})
            if change == "duplicate":
                path += "&code=duplicate"
            if change == "path":
                path = path.replace("/auth/callback", "/wrong")
            if change == "origin":
                path = "http://10.23.0.10:8082" + path
            if change == "fragment":
                path += "#fragment"
            with self.assertRaises(AuthError):
                auth.callback({"Cookie": cookie.split(";", 1)[0]}, path)
            with self.assertRaises(AuthError):
                auth.callback({"Cookie": cookie.split(";", 1)[0]}, path)
        identity.claim["active"] = False
        with self.assertRaises(AuthError):
            auth.check(grant)
        self.assertNotIn("OAUTHLIB_INSECURE_TRANSPORT", os.environ)
        for invalid in ("http://8.8.8.8:8081", "http://app.example:8081", app + "/", app + "?x", app + "#x",
                        "http://user@10.23.0.10:8081", "http://10.027.0.10:8081"):
            with self.assertRaises(ValueError):
                HostedConfig(identity.issuer, identity.client, identity.secret, app, (*origins, invalid), browser)
        with self.assertRaises(ValueError):
            HostedConfig(identity.issuer, identity.client, identity.secret, app)
        with self.assertRaises(ValueError):
            HostedConfig(browser, identity.client, identity.secret, app, origins, browser)
        with tempfile.TemporaryDirectory() as directory:
            secret_file = Path(directory) / "secret"
            secret_file.write_text(identity.secret, encoding="utf-8")
            env = {"HIRO_MANAGED": "true", "APP_AUTH_ISSUER": identity.issuer,
                   "APP_AUTH_CLIENT_ID": identity.client, "APP_AUTH_CLIENT_SECRET_FILE": str(secret_file),
                   "APP_PUBLIC_ORIGIN": app, "APP_AUTH_HTTP_ORIGINS": json.dumps(origins), "APP_AUTH_BROWSER_ORIGIN": browser}
            self.assertEqual(HostedConfig.from_environment(env), config)
            for invalid in ("null", "{}", '[1]'):
                with self.assertRaises(ValueError):
                    HostedConfig.from_environment({**env, "APP_AUTH_HTTP_ORIGINS": invalid})


if __name__ == "__main__":
    unittest.main()
