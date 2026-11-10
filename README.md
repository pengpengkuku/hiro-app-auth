# Hiro app auth

Go and Python SDKs for applications that use Hiro login and application permissions.

The SDKs verify the native opaque-token profile through online introspection. They do not require access to Hiro source code, signing keys, account tables, or business data. Application data remains private; publishing this SDK does not publish any deployed configuration or user data.

## Start here

| Task | Guide |
|---|---|
| Build a new application | [Application development guide](DEVELOPMENT.md) |
| Integrate Python | [Python setup](python/README.md), [API reference](python/REFERENCE.md), [HTTP example](python/examples/http_app.py) |
| Integrate Go | [Go setup and API](GO.md) |
| Describe an application | [Manifest example](examples/app.manifest.json) |

## Install

Python 3.11+:

```sh
python -m pip install 'hiro-app-auth @ git+https://github.com/pengpengkuku/hiro-app-auth.git@python-v0.1.0#subdirectory=python'
```

Go 1.26+:

```sh
go get github.com/pengpengkuku/hiro-app-auth@v0.1.1
```

Pin a full reviewed commit for reproducible builds. Python wheels and source archives are attached to the Python GitHub release. This package is not published to PyPI.

## What each SDK owns

| Capability | Python | Go |
|---|---|---|
| Authorization-code login and S256 PKCE | Included | Existing application callback owns it |
| Protected-request authorization | Online introspection | Online introspection |
| Session storage | Process memory; restart requires login | Encrypted host-only cookie |
| Logout | Local session removal and token revocation | Clearing cookie and token revocation |
| User-owned records, files, jobs, and CSRF | Application responsibility | Application responsibility |

The Python SDK supports one process per instance. It does not share sessions across workers or replicas. Both SDKs fail closed when authorization cannot be confirmed. Neither SDK is a generic OIDC client for arbitrary providers.

## Develop

```sh
go test -timeout 30s ./...
go vet ./...
python -m pip install ./python
python -m unittest discover -s python/tests -v
```

Run the consuming application's existing user story as well: authentication alone does not prove resource isolation. Keep substituted services at external network boundaries.

Original SDK code is licensed under [Apache-2.0](LICENSE).
