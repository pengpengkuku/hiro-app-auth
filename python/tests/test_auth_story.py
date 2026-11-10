"""Public login lifecycle with only the external identity transport replaced."""
import base64
import hashlib
import json
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


if __name__ == "__main__":
    unittest.main()
