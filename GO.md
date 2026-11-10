# hiro-app-auth

The Go SDK is licensed under Apache-2.0. It targets Go 1.26. Version v0.1.1 uses the published module identity `github.com/pengpengkuku/hiro-app-auth`. The earlier local v0.1.0 source used a provisional module path; existing vendored consumers can retain that fixed source until they choose to upgrade.

A standard-library-only Go SDK for the approved Hiro native opaque-token profile. The source targets Go 1.26 and is suitable for a Go 1.27.2 consumer. Validation must state the actual toolchain used. There are no downloaded modules, identity signing keys, account database or token cache.

## Runtime configuration

Create a client once at startup, using deployment-owned values:

```go
client, err := appauth.New(appauth.Config{
    Issuer:           os.Getenv("APP_AUTH_ISSUER"),
    ClientID:         os.Getenv("APP_AUTH_CLIENT_ID"),
    ClientSecretFile: os.Getenv("APP_AUTH_CLIENT_SECRET_FILE"),
    CookieKeyFile:    os.Getenv("APP_AUTH_COOKIE_KEY_FILE"),
    PublicOrigin:    os.Getenv("APP_PUBLIC_ORIGIN"),
})
```

Import the package as `appauth "github.com/pengpengkuku/hiro-app-auth"`. All five strings are required. Keep the secret and exactly 32 cryptographically random cookie-key bytes in separately mounted runtime files readable only by the application. The client secret is UTF-8 text with an optional trailing CR/LF newline. The cookie key is raw binary, not base64 text. Deployments own generation, protection and rotation. Restart the app to load changed files; rotating the cookie key invalidates existing app cookies. Never print secret contents, tokens, cookies or upstream response bodies.

Issuer must exactly match discovery's issuer. Discovery is fetched from `<issuer>/.well-known/openid-configuration`. Discovered introspection and revocation endpoints must share the issuer's scheme and host/port; queries, URL credentials, fragments and redirects are rejected. HTTPS is required except for a literal loopback IP (`127.0.0.1` or `::1`) during local development. A hostname such as `localhost` is not a literal IP. PublicOrigin is an origin, without a path. Local HTTP probes do not prove HTTPS deployment readiness.

The SDK uses `client_secret_basic` with form-encoded client credentials. Network operations have a five-second default timeout; injected `HTTPClient` settings are copied, with absent or greater-than-ten-second timeouts capped at ten seconds. Redirects are always refused. The optional HTTPClient supports a trusted application transport, including a test TLS trust store. Do not disable TLS verification. Response bodies are limited to 32 KiB and decoded into typed values; unknown optional JSON fields are accepted.

## Application integration

The stable v0.1 API consists of `New(Config)`, `BindSession(ctx, accessToken)`, `RequireUser(ctx, http.Header)` and `Logout(ctx, http.Header)`. Authentication methods return `Principal{Issuer, Subject}` or an error; a rejection never returns an anonymous fallback identity. There are no framework types: HTTP handlers use `r.Header`, while native Connect/gRPC handlers pass their received HTTP headers.

1. Keep the application's existing OAuth/OIDC authorization-code callback. It owns exact redirect, state, nonce, PKCE and code validation. Only that trusted callback calls `BindSession` with the opaque access token. Check its error, write the returned cookie with `http.SetCookie`, and bind the upstream app user to the returned issuer/subject pair. Never call BindSession using a token submitted through an ordinary user API.
2. Every protected request calls `RequireUser` before reading or changing business data. It decrypts the cookie, checks its local expiry and then performs online introspection. It validates active status, subject, expected client, `aud = urn:hiro:app:<client-id>`, future expiry and both `openid` and `hiro.app` scopes. A supplied `iss` must match the configured issuer. A changed subject or expiry cannot replace the identity originally bound in the cookie. There is no allow-cache or SQL fallback.
3. The application filters every business operation by the resulting identity, including lists, search, downloads, exports, attachments and deletion. Another user's resource returns 404. An administrator receives no automatic right to business content. This SDK does not perform those filters, CSRF protection, origin checks, business CRUD or stream cleanup.
4. On logout, always write the returned clearing cookie, including when `err != nil`. A valid app cookie causes native token revocation. If revocation cannot be confirmed, report that status explicitly while ending the local session. Clear the app's old UI and connections. Ending this app session does not claim to end Hiro's main session.

Cookie contents are AES-GCM-encrypted token, trusted issuer/subject and original expiry. Random nonces and authenticated issuer/client binding prevent cross-client reuse even if cookie keys were accidentally shared. Each client has its own cookie name, with `__Host-` for HTTPS, host-only scope, Secure on HTTPS, HttpOnly, SameSite=Lax and Path=/. A complete Set-Cookie exceeding 4096 bytes is rejected. Issuer/subject are identity, not email or display name. Treat the cookie itself as a credential.

Use `errors.Is` for errors:

| Error | Application response |
|---|---|
| `ErrUnauthenticated` | 401 or a browser login transition; includes missing, invalid, expired, revoked or wrong-target credentials. |
| `ErrForbidden` | 403; an otherwise active expected identity lacks required scopes. |
| `ErrUnavailable` | Fail closed with a service-unavailable response; permission was not confirmed. On logout, still clear the cookie. |
| `ErrConfiguration` | Fail startup; do not expose deployment values. |
| `ErrCookieTooLarge` | Callback failed; do not establish a partial session. |

Native introspection's `active:false` does not carry a reliable reason. It is unauthenticated, including when the platform withdrew permission. The SDK never invents a 403 reason absent from the platform response. A failed confidential-client HTTP exchange is a service/configuration failure, not a user's permission denial.

## Fixed source and offline consumption

Install the published Go module with `go get github.com/pengpengkuku/hiro-app-auth@v0.1.1`. For offline consumers, use a source archive of the exact reviewed commit and verify its supplied SHA-256. A version identifies the API; the full SHA identifies the source.

From this repository, create and checksum the fixed source (PowerShell):

```powershell
$revision = git rev-parse HEAD
New-Item -ItemType Directory -Force dist | Out-Null
git -c core.autocrlf=false archive --format=tar --prefix=hiro-app-auth/ --output=dist/hiro-app-auth-$revision.tar $revision
Get-FileHash -Algorithm SHA256 dist/hiro-app-auth-$revision.tar
```

Transfer the archive, full SHA and SHA-256 together. Verify the checksum before extraction. For an offline consumer, extract the reviewed source into the consumer repository at `third_party/hiro-app-auth`, retain LICENSE, and use this relative module replacement:

```go
require github.com/pengpengkuku/hiro-app-auth v0.1.1
replace github.com/pengpengkuku/hiro-app-auth => ./third_party/hiro-app-auth
```

Record the exact source SHA and archive hash in the consumer's third-party source record. Commit the source as normal files and run the consumer's existing build checks. If the consumer already uses Go vendoring, run its normal `go mod vendor` step and commit the resulting vendor tree and metadata. Keep the relative source replacement available for future vendor regeneration; do not replace it with a local workstation path. Offline delivery does not require access to a module proxy.

## Verification and limits

Run `go test -timeout 30s ./...` and `go vet ./...`. The tests use a real httptest HTTP identity boundary and synthetic credentials. They cover callback/read/revoke, expiry, changed subject, client/audience/issuer isolation, cookie tampering and duplication, malformed/oversized responses, service failure, clearing on unconfirmed logout and insecure endpoint rejection. They do not prove the application filters its own resources or that the real Hiro identity deployment is connected. That final end-to-end acceptance belongs to the platform and application integration.
