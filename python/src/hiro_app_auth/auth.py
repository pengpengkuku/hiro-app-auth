"""Hiro app login. Tokens and PKCE state live only in server memory."""
import secrets
import hashlib
import ipaddress
import json
import threading
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie, CookieError
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, urlsplit


class AuthError(Exception):
    def __init__(self, message="Authentication has expired. Sign in again.", status=401):
        self.status = status
        super().__init__(message)


def https_url(value):
    if not isinstance(value, str) or any(ord(char) < 33 for char in value):
        raise ValueError("Invalid HTTPS URL.")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("Hosted authentication requires an explicit HTTPS URL.")
    parsed.port
    return parsed


def browser_url(value, http_origins=()):
    if not isinstance(value, str) or any(ord(char) < 33 or ord(char) == 127 for char in value) or any(char in value for char in "\\?#"):
        raise ValueError("Invalid browser URL.")
    parsed = urlsplit(value)
    if parsed.scheme == "https":
        return https_url(value)
    try:
        address = ipaddress.IPv4Address(parsed.hostname)
        private = any(address in ipaddress.ip_network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"))
        if (parsed.scheme != "http" or not private or parsed.hostname != str(address)
                or parsed.username is not None or parsed.password is not None or not parsed.port
                or parsed.netloc != str(address) + ":" + str(parsed.port)
                or "http://" + parsed.netloc not in http_origins):
            raise ValueError("Unapproved HTTP origin.")
    except (ValueError, TypeError):
        raise ValueError("Unapproved HTTP origin.") from None
    return parsed


@dataclass(frozen=True)
class HostedConfig:
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    public_origin: str
    http_origins: tuple[str, ...] = ()
    browser_origin: str | None = None

    def __post_init__(self):
        https_url(self.issuer)
        if not isinstance(self.http_origins, (tuple, list)):
            raise ValueError("Invalid HTTP origins.")
        object.__setattr__(self, "http_origins", tuple(self.http_origins))
        for value in self.http_origins:
            parsed = browser_url(value, self.http_origins)
            if parsed.scheme != "http" or value != "http://" + parsed.netloc or parsed.path:
                raise ValueError("Invalid HTTP origin.")
        origin = browser_url(self.public_origin, self.http_origins)
        if self.browser_origin is not None:
            browser = browser_url(self.browser_origin, self.http_origins)
            if browser.scheme != "http" or self.browser_origin != "http://" + browser.netloc or browser.path:
                raise ValueError("Invalid browser origin.")
        if (origin.path or self.issuer.endswith("/") or not self.client_id.strip() or len(self.client_id) > 256
                or not self.client_secret or any(ord(char) < 32 for char in self.client_id + self.client_secret)):
            raise ValueError("Invalid hosted authentication configuration.")

    @classmethod
    def from_environment(cls, environment):
        names = ("APP_AUTH_ISSUER", "APP_AUTH_CLIENT_ID", "APP_AUTH_CLIENT_SECRET_FILE", "APP_PUBLIC_ORIGIN")
        managed = environment.get("HIRO_MANAGED")
        if managed is None and not any(name in environment for name in (*names, "APP_AUTH_HTTP_ORIGINS", "APP_AUTH_BROWSER_ORIGIN")):
            return None
        if managed != "true" or not all(environment.get(name) for name in names):
            raise ValueError("Hosted authentication configuration is incomplete; HIRO_MANAGED=true is required.")
        secret = Path(environment[names[2]]).read_text(encoding="utf-8").rstrip("\r\n")
        origins = json.loads(environment.get("APP_AUTH_HTTP_ORIGINS", "[]"))
        if not isinstance(origins, list) or not all(isinstance(value, str) for value in origins):
            raise ValueError("APP_AUTH_HTTP_ORIGINS must be a JSON string array.")
        return cls(environment[names[0]], environment[names[1]], secret, environment[names[3]], tuple(origins), environment.get("APP_AUTH_BROWSER_ORIGIN"))


@dataclass(frozen=True)
class Grant:
    token: str = field(repr=False)
    issuer: str
    subject: str
    expires: int

    @property
    def owner(self):
        return {"issuer": self.issuer, "subject": self.subject}


class HiroAuth:
    SESSION_COOKIE = "__Host-hiro-app-session"
    PENDING_COOKIE = "__Host-hiro-app-pending"
    LIMIT = 1024
    PENDING_SECONDS = 300

    def __init__(self, config, *, transport=None):
        from requests.auth import HTTPBasicAuth
        from requests_oauthlib import OAuth2Session
        from oauthlib.oauth2 import OAuth2Error
        endpoints = {}

        class BoundedOAuth(OAuth2Session):
            def request(self, method, url, **kwargs):
                started = time.monotonic()
                kwargs.update(timeout=5, allow_redirects=False, stream=True)
                try:
                    response = super().request(method, url, **kwargs)
                except Exception:
                    raise AuthError("The authorization service is unavailable. Try again later.", 503) from None
                try:
                    if 300 <= response.status_code < 400:
                        raise ValueError("Redirect refused")
                    content = bytearray()
                    for chunk in response.iter_content(4096):
                        content.extend(chunk)
                        if len(content) > 32768 or time.monotonic() - started > 5:
                            raise ValueError("Reply too large")
                    response._content = bytes(content)
                    response._content_consumed = True
                    if response.status_code == 400 and url == endpoints.get("token_endpoint") and response.json().get("error") in {"invalid_grant", "invalid_request", "access_denied"}:
                        return response
                    response.raise_for_status()
                    return response
                except Exception:
                    raise AuthError("The authorization service returned an invalid response. Try again later.", 503) from None
                finally:
                    response.close()

            def send(self, request, **kwargs):
                if transport is not None:
                    return transport(request, **kwargs)
                return super().send(request, **kwargs)

        self.config = config
        self.secure = urlsplit(config.public_origin).scheme == "https"
        if not self.secure:
            namespace = hashlib.sha256(config.client_id.encode()).hexdigest()[:32]
            self.SESSION_COOKIE = "hiro-app-" + namespace
            self.PENDING_COOKIE = "hiro-app-" + namespace + "-pending"
        self.oauth_type = BoundedOAuth
        self.oauth_error = OAuth2Error
        self.basic = HTTPBasicAuth(quote_plus(config.client_id), quote_plus(config.client_secret))
        self.sessions = {}
        self.pending = {}
        self.lock = threading.Lock()
        try:
            metadata = self.oauth_type().get(config.issuer + "/.well-known/openid-configuration").json()
            if metadata.get("issuer") != config.issuer:
                raise ValueError("Issuer mismatch")
            self.endpoints = endpoints
            issuer = https_url(config.issuer)
            for name in ("authorization_endpoint", "token_endpoint", "introspection_endpoint", "revocation_endpoint", "userinfo_endpoint"):
                endpoint = metadata[name]
                parsed = https_url(endpoint)
                if (parsed.scheme, parsed.netloc) != (issuer.scheme, issuer.netloc):
                    raise ValueError("Endpoint origin mismatch")
                self.endpoints[name] = endpoint
        except Exception:
            raise ValueError("Hiro discovery is unavailable or invalid.") from None

    def cookie(self, name, value, *, clear=False):
        return f"{name}={value}; Path=/;" + (" Secure;" if self.secure else "") + " HttpOnly; SameSite=Lax" + ("; Max-Age=0" if clear else "")

    @staticmethod
    def cookie_value(headers, name):
        cookie = SimpleCookie()
        try:
            raw = "; ".join(headers.get_all("Cookie", [])) if hasattr(headers, "get_all") else headers.get("Cookie", "")
            if sum(part.strip().split("=", 1)[0] == name for part in raw.split(";")) != 1:
                return ""
            cookie.load(raw)
            value = cookie[name].value if name in cookie else ""
        except CookieError:
            value = ""
        return value if len(value) == 43 and value.isascii() and all(char.isalnum() or char in "_-" for char in value) else ""

    def cleanup(self):
        current = time.time()
        self.pending = {key: item for key, item in self.pending.items() if item[0] > current}
        self.sessions = {key: grant for key, grant in self.sessions.items() if grant.expires > current}

    def login(self):
        oauth = self.oauth_type(self.config.client_id, redirect_uri=self.config.public_origin + "/auth/callback", scope=["openid", "hiro.app"], pkce="S256")
        url, _ = oauth.authorization_url(self.endpoints["authorization_endpoint"])
        if self.config.browser_origin is not None:
            authorization = urlsplit(url)
            url = self.config.browser_origin + authorization.path + "?" + authorization.query
        pending_id = secrets.token_urlsafe(32)
        with self.lock:
            self.cleanup()
            if len(self.pending) >= self.LIMIT:
                raise AuthError("Too many pending sign-ins. Try again later.", 503)
            self.pending[pending_id] = (time.time() + self.PENDING_SECONDS, oauth)
        return url, self.cookie(self.PENDING_COOKIE, pending_id)

    def callback(self, headers, path):
        pending_id = self.cookie_value(headers, self.PENDING_COOKIE)
        with self.lock:
            self.cleanup()
            pending = self.pending.pop(pending_id, None)
        if pending is None:
            raise AuthError()
        try:
            callback = urlsplit(self.config.public_origin + path)
            query = parse_qs(callback.query, keep_blank_values=True)
            origin = urlsplit(self.config.public_origin)
            oauth = pending[1]
            if (not path.startswith("/auth/callback?") or callback.path != "/auth/callback"
                    or (callback.scheme, callback.netloc) != (origin.scheme, origin.netloc) or callback.fragment
                    or len(query.get("code", [])) != 1 or not query["code"][0]
                    or len(query.get("state", [])) != 1 or not secrets.compare_digest(query["state"][0].encode(), oauth._state.encode())
                    or "error" in query):
                raise AuthError()
            token = oauth.fetch_token(self.endpoints["token_endpoint"], code=query["code"][0], auth=self.basic)
            access_token = token.get("access_token")
            if not isinstance(access_token, str) or not access_token or len(access_token) > 16384:
                raise AuthError()
            grant = self.introspect(access_token)
            userinfo = self.oauth_type(token={"access_token": access_token, "token_type": "Bearer"}).get(self.endpoints["userinfo_endpoint"]).json()
            if not isinstance(userinfo, dict) or userinfo.get("sub") != grant.subject:
                raise AuthError()
        except AuthError:
            raise
        except self.oauth_error:
            raise AuthError("Sign-in was not completed. Start again.", 401) from None
        except Exception:
            raise AuthError("The authorization service returned an invalid response. Try again later.", 503) from None
        session_id = secrets.token_urlsafe(32)
        with self.lock:
            self.cleanup()
            if len(self.sessions) >= self.LIMIT:
                raise AuthError("Session capacity has been reached. Try again later.", 503)
            self.sessions.pop(self.cookie_value(headers, self.SESSION_COOKIE), None)
            self.sessions[session_id] = grant
        return self.cookie(self.SESSION_COOKIE, session_id)

    def introspect(self, token):
        try:
            data = self.oauth_type().post(self.endpoints["introspection_endpoint"], data={"token": token, "token_type_hint": "access_token"}, auth=self.basic).json()
        except Exception:
            raise AuthError("Authorization could not be confirmed. Try again later.", 503) from None
        if not isinstance(data, dict):
            raise AuthError("The authorization service returned an invalid response.", 503)
        if data.get("active") is False:
            raise AuthError()
        exp = data.get("exp")
        scopes = data.get("scope")
        if (data.get("active") is not True or not isinstance(data.get("sub"), str) or not data["sub"].strip()
                or data.get("client_id") != self.config.client_id or data.get("aud") != "urn:hiro:app:" + self.config.client_id
                or type(exp) is not int or not 0 < exp <= 2**63 - 1 or exp <= time.time()
                or ("iss" in data and data["iss"] != self.config.issuer)):
            raise AuthError()
        if not isinstance(scopes, str) or not {"openid", "hiro.app"}.issubset(scopes.split()):
            raise AuthError("This grant does not include the required application scopes.", 403)
        return Grant(token, self.config.issuer, data["sub"], exp)

    def check(self, grant):
        with self.lock:
            self.cleanup()
            if not any(session is grant for session in self.sessions.values()):
                raise AuthError()
        current = self.introspect(grant.token)
        if current != grant:
            raise AuthError()
        with self.lock:
            if not any(session is grant for session in self.sessions.values()):
                raise AuthError()
        return grant

    def authenticate(self, headers):
        session_id = self.cookie_value(headers, self.SESSION_COOKIE)
        with self.lock:
            self.cleanup()
            grant = self.sessions.get(session_id)
        if grant is None:
            raise AuthError()
        try:
            return self.check(grant)
        except AuthError as error:
            if error.status == 401:
                with self.lock:
                    self.sessions.pop(session_id, None)
            raise

    def logout(self, headers):
        session_id = self.cookie_value(headers, self.SESSION_COOKIE)
        with self.lock:
            grant = self.sessions.pop(session_id, None)
        confirmed = False
        if grant is not None:
            try:
                self.oauth_type().post(self.endpoints["revocation_endpoint"], data={"token": grant.token, "token_type_hint": "access_token"}, auth=self.basic)
                confirmed = True
            except Exception:
                pass
        return confirmed
