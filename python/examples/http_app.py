"""Single-process integration example behind an HTTPS reverse proxy."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from hiro_app_auth import AuthError, HiroAuth, HostedConfig


def main():
    config = HostedConfig.from_environment(os.environ)
    if config is None:
        raise RuntimeError("Hosted authentication is required.")
    auth = HiroAuth(config)
    expected_host = urlsplit(config.public_origin).netloc

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def reply(self, status, body=b"", *, cookies=(), location=None, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            if location:
                self.send_header("Location", location)
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def clear_cookie(self, name):
            return auth.cookie(name, "", clear=True)

        def valid_host(self):
            if self.headers.get_all("Host", []) != [expected_host]:
                self.reply(400, b'{"error":"Invalid host"}')
                return False
            return True

        def do_GET(self):
            if not self.valid_host():
                return
            path = urlsplit(self.path).path
            pending_cookies = (self.clear_cookie(auth.PENDING_COOKIE),) if path == "/auth/callback" else ()
            try:
                if path == "/":
                    body = b'<a href="/auth/login">Sign in</a><p><a href="/api/me">Current user</a></p><form method="post" action="/auth/logout"><button>Sign out</button></form>'
                    self.reply(200, body, content_type="text/html; charset=utf-8")
                elif path == "/auth/login":
                    location, cookie = auth.login()
                    self.reply(303, cookies=(cookie,), location=location)
                elif path == "/auth/callback":
                    cookie = auth.callback(self.headers, self.path)
                    self.reply(303, cookies=(cookie, *pending_cookies), location="/")
                elif path == "/api/me":
                    grant = auth.authenticate(self.headers)
                    self.reply(200, json.dumps(grant.owner).encode("utf-8"))
                else:
                    self.reply(404, b'{"error":"Not found"}')
            except AuthError as error:
                cookies = pending_cookies
                if error.status == 401:
                    cookies += (self.clear_cookie(auth.SESSION_COOKIE),)
                self.reply(error.status, json.dumps({"error": str(error)}).encode("utf-8"), cookies=cookies)

        def do_POST(self):
            if not self.valid_host():
                return
            if self.headers.get_all("Origin", []) != [config.public_origin]:
                self.reply(403, b'{"error":"Origin rejected"}')
                return
            if self.path != "/auth/logout":
                self.reply(404, b'{"error":"Not found"}')
                return
            confirmed = auth.logout(self.headers)
            body = json.dumps({"local_session_ended": True, "revocation_confirmed": confirmed}).encode("utf-8")
            self.reply(200 if confirmed else 503, body, cookies=(
                self.clear_cookie(auth.SESSION_COOKIE), self.clear_cookie(auth.PENDING_COOKIE)))

    server = ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("APP_LISTEN_PORT", "8080"))), Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
