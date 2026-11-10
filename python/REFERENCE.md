# Python API reference

## Configuration and discovery

`HostedConfig(issuer, client_id, client_secret, public_origin)` is immutable. Its secret field is excluded from the dataclass representation. `HostedConfig.from_environment(environment)` reads the five variables in [the setup guide](README.md#configure-the-application). It returns `None` only when managed configuration is absent. Partial configuration, a value other than `HIRO_MANAGED=true`, or invalid URLs fail startup. A missing or unreadable secret file also fails startup.

`HiroAuth(config, *, transport=None)` discovers `<issuer>/.well-known/openid-configuration` at startup. The metadata issuer must match exactly. Authorization, token, introspection, revocation, and userinfo endpoints must be HTTPS on the issuer's exact origin. URL credentials, query strings, fragments, and redirects are rejected. The optional transport replaces the external HTTP send operation for controlled tests. Do not use it to disable TLS verification.

Each network operation has a five-second timeout. The client refuses redirects and limits response content to 32 KiB. Discovery failure raises `ValueError`. No local user database or previously accepted result can replace online authorization.

## Login and callback

`login()` returns `(authorization_url, pending_set_cookie)`. Send a browser redirect to that URL and write the pending cookie. The request uses scopes `openid hiro.app`, S256 PKCE, and the callback `<public_origin>/auth/callback`. Pending state expires after 300 seconds. At most 1,024 unfinished logins and 1,024 sessions are retained per instance.

`callback(headers, path)` consumes the pending cookie and state, exchanges the code using `client_secret_basic`, introspects the token, and checks that userinfo's subject matches introspection. Pass the original request path and query, not a user-supplied absolute URL. On success it returns a session `Set-Cookie` string. It replaces the old session identified by the request cookie. Always clear the pending cookie after a callback, including on failure.

Use `auth.cookie(auth.PENDING_COOKIE, "", clear=True)` to construct a clearing cookie. Use the same helper with `SESSION_COOKIE` when a response ends the local browser session. The helper only returns a string. Your handler must send it.

## Protected work and ownership

`authenticate(headers)` returns the original `Grant` for a valid session. Headers can be `http.client.HTTPMessage`-style headers with `get_all`, or a mapping whose `Cookie` key contains the request cookie string. Preserve multiple incoming Cookie headers if your server exposes them. Missing, duplicated, malformed, expired, or unknown session IDs fail authentication.

`Grant` contains `token`, `issuer`, `subject`, and `expires`. Its token field is excluded from the dataclass representation. `grant.owner` returns `{"issuer": issuer, "subject": subject}`. Store that exact pair as the owner of application resources and use it to filter every read and write. Do not expose `grant.token` to the browser, logs, or business records.

`check(grant)` rechecks an already obtained grant before protected background work or publication. It requires that exact grant to remain in this instance's sessions. It introspects again, requires the original issuer, subject, token, and expiry to remain unchanged, then rechecks local membership. Logout or a competing authentication failure cannot be replaced by a newly returned identity. Calling `check` does not automatically cancel a task or undo a supplier request.

Every `authenticate` and `check` performs online introspection. The response must have `active=true`, a nonempty subject, the configured client ID, `aud=urn:hiro:app:<client-id>`, an integer future expiry, and both required scopes. A supplied `iss` must match the configured issuer. `active=false` is 401 without an invented permission-denial reason.

## Errors and logout

`AuthError` has an HTTP `status` and an English message. Your application can map status to its own localized interface.

| Status | Meaning and handler action |
|---|---|
| 401 | Missing, expired, revoked, mismatched, or otherwise invalid authorization. End the browser session, clear the session cookie, and show login. |
| 403 | The active grant lacks required scopes. Fail closed and explain missing access. |
| 503 | Authorization could not be confirmed, or local login capacity was reached. Fail closed and allow a later retry. Do not treat this as anonymous access. |

`authenticate` removes a session when its check returns 401. It keeps a session on 403 or 503. An application that handles a failed `check(grant)` remains responsible for its response and any pending work.

`logout(headers)` removes the local session before attempting upstream revocation. It returns `True` only when the revocation request succeeds. `False` means that revocation was not confirmed, including when no local session exists. Always clear the browser session and pending cookies. Tell the user when remote revocation was not confirmed. The SDK does not claim to end Hiro's main login session.

## Application responsibilities

The SDK returns authentication results and cookie strings. Your application owns HTTP routing, trusted host and origin validation, CSRF protection for state changes, resource ownership checks, authorization before downloads and streams, user interface reset, connection cleanup, and background-work lifecycle. `SameSite=Lax` does not replace those checks. Another user's resource must not become readable through a guessed identifier or a retained connection.

Use a separate public origin per application and a single process per instance. Any move to multiple processes or shared persistence needs a separate design. This SDK does not provide provider cancellation or shared session storage.
