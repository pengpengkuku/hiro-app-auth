# Build an independent Hiro application

Use this guide when adding Hiro login to a separate application repository. The application keeps its own build, runtime, data, and release process. A compatible application update does not require merging into or restarting Hiro.

## Technology and code choices

Each application keeps its own language, framework, and release process. These choices are recommendations; the authentication, isolation, secret-handling, and data-safety requirements below are mandatory.

| Area | Recommendation |
|---|---|
| Existing applications | Keep the established stack and build process when they meet the integration requirements. |
| New web applications | Prefer TypeScript when sharing types across the frontend and backend makes the application easier to maintain. Use server-side authentication; keep credentials out of browser bundles. |
| Backend services | Consider Go for a small compiled service. Python remains supported when it fits the application or an existing codebase. |
| Frameworks and dependencies | Use maintained, supported releases. Reuse the standard library, framework features, and established packages before building an alternative. Pin dependencies and commit the appropriate lockfile. |
| User interface | Reuse the application's component system. Keep layout, actions, feedback, and keyboard behavior consistent. |
| Code | Use clear names, explicit data flow, local side effects, and small modules with one responsibility. Remove duplicate implementations and unnecessary forwarding layers. Report failures instead of swallowing them. |
| TypeScript | Enable strict checking. Treat external values as unknown until validated; avoid broad `any` and unchecked assertions. |
| Verification | Test complete user stories and important integration boundaries. Reuse existing checks and show that the protected behavior fails when its connection is deliberately broken. |
| Updates | Pin source and artifact versions. State compatibility, migrations, and recovery steps. Upgrade only the affected application. |

## 1. Agree on the connection

Obtain these values from the platform operator before connecting. Example domains and IDs in this repository are not working platform registrations.

- A stable application ID and the supported platform contract version.
- An exact HTTPS issuer, public application origin, and registered callback URL.
- A confidential client ID and a read-only runtime secret file.
- Application access grants for two test users, with a way to revoke one grant.
- Approved runtime storage, network targets, resource limits, and release owner.

Do not read Hiro's account database, session store, signing keys, or source files. Do not create a second hosted account/password system. The platform owns account management and application access; the application owns its business behavior and resource authorization.

## 2. Connect authentication

Choose [TypeScript](typescript/README.md), [Python](python/README.md), or [Go](GO.md). The SDKs expose different session designs; follow the chosen guide rather than mixing their configuration.

For TypeScript, start with the [Node HTTP example](typescript/examples/http-app.mjs). The SDK uses openid-client for the authorization-code and S256 PKCE flow. Install it only on the server. Tokens stay in process memory.

For Python, start with the [HTTP example](python/examples/http_app.py). It includes login, callback, a protected identity response, and logout. It is a single-process integration example behind HTTPS, not a production web server or a complete business application.

For Go, keep the existing trusted OAuth callback and pass its validated opaque access token to `BindSession`. The application retains responsibility for state, nonce where applicable, PKCE, and callback validation.

For all SDKs:

1. Load deployment-owned settings at startup. Missing configuration must fail startup, with configuration names rather than secret values in the error.
2. Authenticate every protected request on the server. Never accept a user ID, role, email, or identity header supplied by the browser as proof of identity.
3. Use the verified issuer and subject as the stable owner. A platform administrator does not automatically own user content.
4. Reject failed authorization. Do not fall back to a public user, a local account, or an earlier successful permission check.
5. Always send clearing cookies on logout, even if upstream revocation cannot be confirmed. Reset old page state and open connections. Ending the app session does not claim to end Hiro's main session.

## 3. Keep each user's data private

Every list, search, read, edit, task status, preview, download, export, and delete must enforce the verified owner. Another user's private resource returns 404. Hiding a button or checking only a resource ID does not protect data.

For example, use parameterized predicates on the application database:

```sql
SELECT id, body
FROM notes
WHERE id = ? AND owner_issuer = ? AND owner_subject = ?;
```

All three parameters come from the resource route and the server-verified principal. Never take owner fields from request JSON. Store an owner on files and jobs too; checking a record while leaving its download public is incomplete isolation.

Cookie-authenticated writes require CSRF protection and trusted Host/Origin handling. Use host-only cookies and separate application origins. Restrict CORS to approved origins. SameSite does not replace CSRF checks.

Keep the accepted owner with background work. Check current permission before protected publication; reject a revoked grant and prevent A's late result from appearing in B's session. The SDK does not stop work already accepted by an external provider. Declare whether that work can be cancelled, resumed, or safely retried.

## 4. Prepare the deployment

Provide a fixed Docker image or a reproducible Dockerfile, plus the application's native deployment definition. Install SDK dependencies during the build; the runtime must not clone repositories or download code at startup.

- Declare the listening port, a readiness check, and a bounded shutdown period. Keep liveness independent of a temporary shared-service outage.
- Store durable records only in declared storage. Declare migrations, restart recovery, backups, restore checks, and per-user export/deletion.
- Mount runtime secrets read-only. Keep secrets out of build arguments, image layers, browser code, URLs, responses, logs, and committed files. Rotate secrets by changing the runtime secret and restarting.
- Run without root, privileged mode, host networking, a Docker socket, or another application's directories. Declare required outbound targets and limits.
- Bound uploads, storage, concurrency, and request timeouts. Paid calls require server-side attribution and agreed limits. An uncertain provider result must not be blindly submitted again.
- Write bounded technical logs to stdout/stderr. Do not log authorization callback queries, tokens, cookies, keys, or user file contents.

If distributing a Python wheel, download the reviewed release asset during the controlled build preparation, verify its published SHA-256, and copy it into the build context. Install that exact local wheel with its declared dependencies. No repository credential is needed in the image. Dependency lockfiles belong to the consuming application.

## 5. Describe the application

Adapt [the manifest example](examples/app.manifest.json). It is a declaration to review with the platform, not an executable deployment file or a machine-validated schema. Confirm its detailed shape against the current platform contract; do not infer available APIs from it.

The workbench card has four application-owned fields:

| Field | Meaning |
|---|---|
| `display.name` | A recognizable application name. |
| `display.description` | One sentence describing what users can do. |
| `display.dataVisibility` | `private` for user-owned content. `public` requires separately approved sharing behavior. Public SDK source does not imply public application data. |
| `display.category` | `productivity` or `design`, according to the approved category definition. |

The platform generates the current user's enabled/not-enabled state from actual access grants. The application does not declare this state, health, or key readiness through card labels. Submit card metadata through the platform's agreed registration process; do not add application-specific branches to Hiro's frontend.

## 6. Verify one complete user story

Use the application's existing story tests. Replace only external boundaries when a controlled response is needed; keep internal application modules real. Expected behavior comes from the agreed story and protocol, not from copying the implementation into a test.

Walk this connected story and keep the actual result:

1. A enters from Hiro, completes the application's core action, saves, and downloads or exports the actual result.
2. B enters the same app. A's lists, search hits, resource IDs, task status, preview, download, export, edit, and deletion remain inaccessible.
3. Revoke A's application access. Protected requests fail, old page state is cleared, and late work does not publish under another user.
4. Restore access when authorized, restart the application, and verify saved data remains usable. Document the chosen SDK's session behavior.
5. Upgrade only this application using existing data. Confirm Hiro and a second application remain on their original versions. Exercise the declared recovery path if the data format changed.

Prove a necessary protection can fail: temporarily remove an ownership predicate or disconnect a result handoff in an isolated candidate, show the existing story fail, then restore it. Do not commit the deliberate defect. Do not build a parallel per-function suite or repeat unchanged platform-wide checks for every app update.

## 7. Release independently

Pin the source commit, SDK version, and final artifact digest. Publish configuration, migration, and data compatibility changes in the application's changelog. A compatible release updates only this application's artifact, configuration, and data; new platform permissions or breaking protocols need platform agreement first.

SDK releases use independent tags: `typescript-vX.Y.Z`, `vX.Y.Z` for Go, and `python-vX.Y.Z`. Do not move an existing tag. TypeScript and Python artifacts are distributed through GitHub releases. Do not publish them to npm or PyPI without a separate release decision. Retain the Apache license when vendoring source.

For SDK contributors, run the commands in [the root guide](README.md#develop) build TypeScript with `npm --prefix typescript run build`, and build Python with `python -m build python`. Inspect the wheel metadata and included license. Reuse consuming-application evidence for unchanged behavior; rerun the affected story when the SDK changes a real boundary.

The current platform's external-application contract remains authoritative for registration, deployment approval, and data handling. This public guide explains SDK integration; it does not grant access, deploy an application, or replace that contract.
