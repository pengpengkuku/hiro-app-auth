# Hiro app auth

TypeScript, Go, and Python SDKs for applications that use Hiro login and application permissions.

The SDKs verify the native opaque-token profile through online introspection. They do not require access to Hiro source code, signing keys, account tables, or business data. Application data remains private; publishing this SDK does not publish any deployed configuration or user data.

## Start here

| Task | Guide |
|---|---|
| Build a new application | [Application development guide](DEVELOPMENT.md) |
| Integrate TypeScript | [TypeScript setup and API](typescript/README.md), [HTTP example](typescript/examples/http-app.mjs) |
| Integrate Python | [Python setup](python/README.md), [API reference](python/REFERENCE.md), [HTTP example](python/examples/http_app.py) |
| Integrate Go | [Go setup and API](GO.md) |
| Describe an application | [Manifest example](examples/app.manifest.json) |

## Install

TypeScript on Node.js 22.12+:

```sh
npm install https://github.com/pengpengkuku/hiro-app-auth/releases/download/typescript-v0.2.0/hiro-app-auth-0.2.0.tgz
```

Python 3.11+:

```sh
python -m pip install 'hiro-app-auth @ git+https://github.com/pengpengkuku/hiro-app-auth.git@python-v0.2.0#subdirectory=python'
```

Go 1.26+:

```sh
go get github.com/pengpengkuku/hiro-app-auth@v0.2.0
```

Pin a full reviewed commit for reproducible builds. TypeScript packages and Python wheels are attached to their GitHub releases. Neither package is published to a package registry.

## What each SDK owns

| Capability | TypeScript | Python | Go |
|---|---|---|---|
| Authorization-code login and S256 PKCE | Included through openid-client | Included | Existing application callback owns it |
| Protected-request authorization | Online introspection | Online introspection | Online introspection |
| Session storage | Process memory | Process memory | Encrypted host-only cookie |
| Logout | Local removal and token revocation | Local removal and token revocation | Clearing cookie and token revocation |
| Shared workbench service calls | Owned-principal request method | Native HTTP with checked grant | Owned-session request method |
| User-owned resources and CSRF | Application responsibility | Application responsibility | Application responsibility |

TypeScript and Python support one process per instance. A restart requires login; sessions are not shared across workers or replicas. All SDKs fail closed when authorization cannot be confirmed. They target Hiro's native profile, not arbitrary identity providers.

## Develop

```sh
npm --prefix typescript ci
npm --prefix typescript test
go test -timeout 30s ./...
go vet ./...
python -m pip install ./python
python -m unittest discover -s python/tests -v
```

Run the consuming application's existing user story as well: authentication alone does not prove resource isolation. Keep substituted services at external network boundaries.

## Contributors

[pengpengkuku](https://github.com/pengpengkuku) contributes product direction, integration requirements, and review.

Original SDK code is licensed under [Apache-2.0](LICENSE).
