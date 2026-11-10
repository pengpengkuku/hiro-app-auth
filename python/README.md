# Hiro app auth for Python

`hiro-app-auth` 0.1.0 provides the existing Hiro hosted login flow as a Python 3.11+ package. It exports `AuthError`, `HostedConfig`, `Grant`, and `HiroAuth`. It uses requests-oauthlib for authorization code exchange and S256 PKCE. It has no web framework or database dependency.

## Install the reviewed source

From the repository root, install this package into your application's virtual environment.

```sh
python -m pip install ./python
```

For a remote installation, use the published Python tag:

```sh
python -m pip install 'hiro-app-auth @ git+https://github.com/pengpengkuku/hiro-app-auth.git@python-v0.1.0#subdirectory=python'
```

For a reproducible build, replace the tag with the reviewed full commit or install the release wheel after verifying its SHA-256. Installation does not register an OAuth client or configure the identity service. The runtime dependencies are pinned in [pyproject.toml](pyproject.toml).

## Configure the application

Set these environment variables through your deployment configuration.

| Variable | Value |
|---|---|
| `HIRO_MANAGED` | `true` |
| `APP_AUTH_ISSUER` | The registered issuer's exact HTTPS URL without a trailing slash. |
| `APP_AUTH_CLIENT_ID` | The application's confidential client ID. |
| `APP_AUTH_CLIENT_SECRET_FILE` | The path to a UTF-8 secret file. |
| `APP_PUBLIC_ORIGIN` | The application's external HTTPS origin without a path or trailing slash. |

Mount the secret file read-only and allow only the application account to read it. `from_environment` reads the file once and removes trailing CR/LF characters. It does not change file permissions. Restart the application to load a changed secret. Never log the secret, access token, session cookie, or authorization callback query.

```python
import os
from hiro_app_auth import HiroAuth, HostedConfig

config = HostedConfig.from_environment(os.environ)
if config is None:
    raise RuntimeError("Hosted authentication is required.")
auth = HiroAuth(config)
```

Use one `HiroAuth` instance for one application process. Give each application its own public origin. Cookies use fixed names with host-only scope. Applications that share an origin can overwrite each other's cookies.

## Connect HTTP handlers

[The standard-library HTTP example](examples/http_app.py) serves a login page, a callback, a protected identity endpoint, and logout. Set the configuration above and run it from this directory.

```sh
python examples/http_app.py
```

The example listens on `127.0.0.1:8080`, or `APP_LISTEN_PORT`. Put it behind your deployment's HTTPS reverse proxy. Preserve the registered external `Host` header and forward the callback path and query unchanged. The SDK requires HTTPS issuer and application URLs even when the example's loopback listener uses HTTP. Python's development HTTP server is an integration reference, not a production server.

The example starts only with complete managed configuration. Open your configured external origin, select **Sign in**, complete the registered identity flow, and follow **Current user**. The endpoint returns the issuer and subject. Logout removes the local session and reports whether upstream token revocation succeeded. Local startup alone does not prove the real identity deployment works.

Use your framework's request headers directly with `authenticate(headers)`, `callback(headers, path)`, and `logout(headers)`. Preserve each `Set-Cookie` as a separate response header. See [the API and integration boundaries](REFERENCE.md) for return values and error handling.

## Sessions and migration

Session tokens, pending PKCE state, and grants stay in process memory. Browser cookies contain random IDs. Sessions expire with the original grant. Restarting the process loses every session and unfinished login. Multiple worker processes and replicas do not share sessions. This package does not add a shared store, refresh-token flow, or authorization cache.

The extracted source previously used `__Host-creajpg-session` and `__Host-creajpg-pending`. This package uses `__Host-hiro-app-session` and `__Host-hiro-app-pending`. Users must log in again after migration. Each cookie has `Path=/`, `Secure`, `HttpOnly`, and `SameSite=Lax`, without `Domain`. The application still owns cleanup of any legacy cookies on its origin.

Authentication checks current authorization online. It does not stop work already accepted by another provider. Your application owns resource isolation, CSRF checks, user interface cleanup, open connections, and cancellation of its own work.

## Verify the package

After installation, run the public lifecycle story from this directory.

```sh
python -m unittest discover -s tests -v
```

The test substitutes only the external identity transport. It exercises discovery, PKCE, callback, repeated authorization checks, revoked access, clearing-cookie construction, and logout. The consuming application's hosted HTTP stories remain the evidence for its complete user journey. No real account, signing key, or paid API is used.

The package is licensed under [Apache-2.0](LICENSE). The wheel includes this license.
