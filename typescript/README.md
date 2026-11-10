# Hiro app authentication for TypeScript

Server-side Hiro login for Node.js 22.12 or later, using ESM and `openid-client` 6.8.9. JavaScript callers use the same package. The package includes compiled JavaScript and TypeScript declarations. It is distributed as a GitHub release tarball, with no npm registry publication.

```sh
npm install https://github.com/pengpengkuku/hiro-app-auth/releases/download/typescript-v0.1.0/hiro-app-auth-0.1.0.tgz
```

## Configure and run

Hiro supplies these settings to a hosted app. Keep the secret in its mounted file.

```text
HIRO_MANAGED=true
APP_AUTH_ISSUER=https://hiro.example
APP_AUTH_CLIENT_ID=your-app-id
APP_AUTH_CLIENT_SECRET_FILE=/run/secrets/hiro-app-client-secret
APP_PUBLIC_ORIGIN=https://your-app.example
```

The issuer must be an HTTPS URL without a trailing slash. The public origin must be an exact HTTPS origin without a path or trailing slash. The registered callback is `APP_PUBLIC_ORIGIN + /auth/callback`.

```ts
import { createHiroAuth, loadConfig } from '@hiro/app-auth';

const config = loadConfig(process.env);
if (!config) throw new Error('Hosted authentication is required.');
const auth = await createHiroAuth(config);
```

Create one `auth` instance per app process. Adapt the result of `login()` to an HTTP redirect and write every `setCookies` value as a separate `Set-Cookie` header. Pass the request's `Headers` and full callback `URL` to `callback()`. On callback failure, also write `clearPendingCookies()` to clear the consumed sign-in cookie.

The [native HTTP example](examples/http-app.mjs) implements `/auth/login`, `/auth/callback`, `/api/me` and `POST /auth/logout`. Run `node examples/http-app.mjs` from this package directory after setting the environment. From a checkout, first run `npm ci` and `npm run build`. The server listens on `127.0.0.1:8080`. Place it behind your app's HTTPS ingress, which must preserve the exact public Host header. Secure cookies do not work over an ordinary localhost HTTP browser connection.

The example rejects an unexpected Host and requires the exact public Origin for write requests. Your application owns its proxy trust, CSRF policy, resource ownership checks, request body limits, connection limits and deployment configuration. It must use the returned issuer and subject together when checking resource ownership. Do not trust a client-supplied principal. Never log callback URLs, codes, tokens, cookies, the configuration object or secret contents.

## API

| Export or method | Result and behavior |
| --- | --- |
| `loadConfig(environment)` | Returns a validated immutable `Config`, or `null` when all hosted auth settings are absent. Any partially declared or empty setting fails closed. Reads the UTF-8 secret file and removes trailing CR/LF. Configuration errors contain no secret data. |
| `createHiroAuth(config, { fetch? })` | Discovers and validates Hiro metadata, then returns `Promise<HiroAuth>`. Optional `fetch` replaces the external HTTP boundary for tests or an application transport. HTTPS checks, response limits and timeout still apply. |
| `auth.login()` | Returns `Promise<{ location, setCookies }>` with authorization URL and pending cookie. Uses authorization code, S256 PKCE, random state and `openid hiro.app` scopes. |
| `auth.callback(headers, url)` | Returns `Promise<{ principal, setCookies }>` after exchanging the code, introspecting the token and checking userinfo subject. A pending attempt is consumed once, even when validation fails. Logout during exchange prevents the callback from creating a session. |
| `auth.requireUser(headers)` | Returns `Promise<Principal>` after online introspection of the session grant. Rejects missing, malformed, duplicate, expired or revoked sessions. |
| `auth.check(principal)` | Rechecks the exact principal object returned by this instance for an active owned session. Use before a background operation that started with that principal. Copies and deserialized objects cannot identify a session. Membership is checked before and after the network call. |
| `auth.logout(headers)` | Removes local session and pending state before awaiting revocation. Always returns cookies to clear and `revocationConfirmed`. `false` means Hiro revocation was unavailable or there was no active local session. Apply the cookies even when revocation is unconfirmed. |
| `clearPendingCookies()` | Returns the pending-cookie clearing header for callback failure handling. |
| `AuthError` | Safe English error message and `status` of `401`, `403` or `503`. No underlying provider error, token or secret is exposed. |

`Principal` is an immutable `{ issuer: string, subject: string }`. It contains no token. `Config` contains `issuer`, `clientId`, `clientSecret` and `publicOrigin`. It contains a secret and must remain server-side.

An inactive, expired, wrong-client, wrong-audience, changed-subject or changed-expiry grant fails with `401`. Missing required scopes fail with `403`. Unavailable or malformed upstream responses fail with `503`. Every protected request contacts Hiro. There is no introspection cache or token refresh. A background `check()` cannot make a later external side effect atomic with logout; your application owns cancellation and commit boundaries.

## Operational boundaries

Pending sign-ins expire after five minutes. Each instance holds at most 1,024 pending sign-ins and 1,024 sessions. Expired entries are removed on operations. Capacity exhaustion fails with `503`. Pending state, access tokens and sessions exist only in server memory. Restarting the process requires sign-in again. Use one process per instance. Multiple workers, replicas, and shared session storage require a separate design.

Cookies are opaque random IDs with `__Host-` names, `Path=/`, `Secure`, `HttpOnly` and `SameSite=Lax`. There is no Domain attribute. Discovery and all five endpoints require HTTPS. Endpoints must share the issuer origin and cannot contain credentials, a query or a fragment. Discovery must return the exact configured issuer. Upstream redirects are refused. Every upstream request, including response streaming, has a five-second deadline and a 32 KiB response limit. Native Hiro access-token-only responses work without an ID token or JWKS URL.

No router, browser bundle, database, framework integration or production deployment is included.

## Develop

```sh
npm ci
npm test
npm run pack
```

Tests run against the compiled library and the real OAuth client. Only upstream HTTP is substituted. `npm run pack` creates `hiro-app-auth-0.1.0.tgz`, containing JavaScript, declarations, this README, the native HTTP example and the Apache-2.0 license. Keep the lockfile when building or testing. Runtime dependencies retain their respective licenses.
