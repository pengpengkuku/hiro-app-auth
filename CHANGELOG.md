# Changelog

## TypeScript 0.1.0 (`typescript-v0.1.0`)

- Add a server-side Node.js SDK with typed configuration and principals.
- Reuse openid-client for authorization-code login, S256 PKCE, introspection, and revocation.
- Keep tokens in bounded process-local sessions and recheck current permission for protected work.
- Include a Node HTTP example and package installation through a fixed GitHub release.
- Add shared language, framework, and code recommendations. Applications retain their own stacks; security and isolation remain required.

## Python 0.1.0 (`python-v0.1.0`)

- Publish the existing hosted Python login flow as `hiro_app_auth`.
- Include S256 PKCE, online grant checks, process-local sessions, and revocation.
- Use generic host-only cookie names and English error messages. Migrating applications require a fresh login.
- Reject declared but empty authentication configuration instead of treating it as absent.
- Add setup, API reference, a minimal HTTP integration, and a developer guide with a manifest example.
- Require Python 3.11+. Support one process per instance; no shared session store or refresh-token flow.

## Go 0.1.1 (`v0.1.1`)

- Publish the Go SDK at `github.com/pengpengkuku/hiro-app-auth`.
- Retain the existing encrypted-cookie and online-introspection behavior.
- The earlier local 0.1.0 source used a provisional module path. Existing vendored consumers can keep it; new consumers use the published path.
