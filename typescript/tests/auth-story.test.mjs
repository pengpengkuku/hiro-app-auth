import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHiroAuth, loadConfig, AuthError, clearPendingCookies } from '../dist/index.js';

const config = Object.freeze({
  issuer: 'https://hiro.example', clientId: 'app :+id',
  clientSecret: 'secret :+value', publicOrigin: 'https://app.example',
});
const expiry = Math.floor(Date.now() / 1000) + 3600;
const metadata = {
  issuer: config.issuer,
  authorization_endpoint: config.issuer + '/authorize', token_endpoint: config.issuer + '/token',
  introspection_endpoint: config.issuer + '/introspect', revocation_endpoint: config.issuer + '/revoke',
  userinfo_endpoint: config.issuer + '/userinfo',
};
const json = (value, status = 200) => Response.json(value, { status });
const cookieHeaders = (cookies) => new Headers({ cookie: cookies.map((value) => value.split(';')[0]).join('; ') });
const formEncode = (value) => new URLSearchParams({ v: value }).toString().slice(2);
const status = (expected) => (error) => error instanceof AuthError && error.status === expected
  && !error.message.includes(config.clientSecret) && !error.message.includes('access-token');

function provider() {
  const state = {
    introspection: { active: true, sub: 'person-1', client_id: config.clientId,
      aud: 'urn:hiro:app:' + config.clientId, exp: expiry, scope: 'openid hiro.app', iss: config.issuer },
    userInfo: { sub: 'person-1' }, calls: [], challenge: '', revokeUnavailable: false,
    async beforeIntrospection() {},
    async beforeToken() {},
  };
  state.fetch = async (input, init = {}) => {
    const url = new URL(input instanceof Request ? input.url : input);
    assert.equal(init.redirect, 'manual');
    assert.ok(init.signal instanceof AbortSignal);
    state.calls.push(url.pathname);
    if (url.pathname.endsWith('/openid-configuration')) return json(metadata);
    if (['/token', '/introspect', '/revoke'].includes(url.pathname)) {
      const basic = Buffer.from(formEncode(config.clientId) + ':' + formEncode(config.clientSecret)).toString('base64');
      assert.equal(new Headers(init.headers).get('authorization'), 'Basic ' + basic);
      const body = new URLSearchParams(init.body);
      if (url.pathname === '/token') {
        await state.beforeToken();
        assert.equal(body.get('redirect_uri'), config.publicOrigin + '/auth/callback');
        assert.equal(body.get('grant_type'), 'authorization_code');
        assert.equal(createHash('sha256').update(body.get('code_verifier')).digest('base64url'), state.challenge);
        return json({ access_token: 'access-token', token_type: 'Bearer', expires_in: 3600 });
      }
      assert.equal(body.get('token'), 'access-token');
      if (url.pathname === '/revoke') return state.revokeUnavailable ? json({}, 503) : new Response(null, { status: 200 });
      await state.beforeIntrospection();
      return json(state.introspection);
    }
    if (url.pathname === '/userinfo') {
      assert.equal(new Headers(init.headers).get('authorization'), 'Bearer access-token');
      return json(state.userInfo);
    }
    throw new Error('Unexpected upstream URL');
  };
  return state;
}

async function signedIn(state = provider()) {
  const auth = await createHiroAuth(config, { fetch: state.fetch });
  const login = await auth.login();
  const location = new URL(login.location);
  assert.equal(location.searchParams.get('scope'), 'openid hiro.app');
  assert.equal(location.searchParams.get('code_challenge_method'), 'S256');
  state.challenge = location.searchParams.get('code_challenge');
  const callbackUrl = new URL('/auth/callback', config.publicOrigin);
  callbackUrl.searchParams.set('code', 'authorization-code');
  callbackUrl.searchParams.set('state', location.searchParams.get('state'));
  const pendingHeaders = cookieHeaders(login.setCookies);
  const result = await auth.callback(pendingHeaders, callbackUrl);
  return { auth, state, result, headers: cookieHeaders(result.setCookies.filter((value) => !value.includes('Max-Age=0'))), callbackUrl, pendingHeaders };
}

test('native sign-in uses real OAuth client, PKCE and encoded Basic without ID token or JWKS', async () => {
  const { auth, state, result, headers, pendingHeaders, callbackUrl } = await signedIn();
  assert.deepEqual(result.principal, { issuer: config.issuer, subject: 'person-1' });
  assert.ok(Object.isFrozen(result.principal));
  assert.equal(JSON.stringify(result).includes('access-token'), false);
  assert.match(result.setCookies[0], /__Host-hiro-app-pending=;.*Max-Age=0/u);
  assert.match(result.setCookies[1], /__Host-hiro-app-session=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Lax$/u);
  assert.equal(await auth.requireUser(headers), result.principal);
  assert.equal(await auth.check(result.principal), result.principal);
  await assert.rejects(auth.check({ ...result.principal }), status(401));
  await assert.rejects(auth.callback(pendingHeaders, callbackUrl), status(401));
  assert.equal(state.calls.includes('/jwks'), false);
  const logout = await auth.logout(headers);
  assert.equal(logout.revocationConfirmed, true);
  assert.equal(logout.setCookies.length, 2);
  await assert.rejects(auth.requireUser(headers), status(401));
  await assert.rejects(auth.check(result.principal), status(401));
});

test('wrong state and wrong callback origin consume the pending attempt', async () => {
  for (const wrong of ['state', 'origin', 'duplicate']) {
    const state = provider();
    const auth = await createHiroAuth(config, { fetch: state.fetch });
    const login = await auth.login();
    const location = new URL(login.location);
    const url = new URL('/auth/callback?code=code', config.publicOrigin);
    url.searchParams.set('state', location.searchParams.get('state'));
    const correct = new URL(url);
    if (wrong === 'state') url.searchParams.set('state', 'incorrect');
    if (wrong === 'origin') url.hostname = 'attacker.example';
    if (wrong === 'duplicate') url.searchParams.append('state', location.searchParams.get('state'));
    await assert.rejects(auth.callback(cookieHeaders(login.setCookies), url), status(401));
    await assert.rejects(auth.callback(cookieHeaders(login.setCookies), correct), status(401));
    assert.deepEqual(state.calls, ['/.well-known/openid-configuration']);
    assert.match(clearPendingCookies()[0], /Max-Age=0/u);
  }
});

test('each protected action rechecks active grant and pins client, audience, identity and expiry', async () => {
  for (const patch of [
    { active: false }, { aud: ['urn:hiro:app:' + config.clientId] }, { aud: 'wrong' },
    { client_id: 'other' }, { sub: 'person-2' }, { exp: expiry + 1 }, { exp: 1 }, { exp: 1.5 }, { iss: 'https://other.example' },
  ]) {
    const { auth, state, headers, result } = await signedIn();
    Object.assign(state.introspection, patch);
    await assert.rejects(auth.requireUser(headers), status(401));
    await assert.rejects(auth.check(result.principal), status(401));
  }
  const { auth, state, headers } = await signedIn();
  state.introspection.scope = 'openid';
  await assert.rejects(auth.requireUser(headers), status(403));
});

test('mismatched userinfo cannot establish a session', async () => {
  const state = provider();
  state.userInfo.sub = 'someone-else';
  await assert.rejects(signedIn(state), status(401));
});

test('logout prevents in-flight introspection from returning an authenticated principal', async () => {
  const { auth, state, headers, result } = await signedIn();
  let release;
  const waiting = new Promise((resolve) => { release = resolve; });
  let arrived;
  const started = new Promise((resolve) => { arrived = resolve; });
  state.beforeIntrospection = async () => { arrived(); await waiting; };
  const check = auth.check(result.principal);
  await started;
  assert.equal((await auth.logout(headers)).revocationConfirmed, true);
  release();
  await assert.rejects(check, status(401));
  await assert.rejects(auth.requireUser(headers), status(401));
});

test('unavailable revocation still clears cookies and the local session', async () => {
  const { auth, state, headers, result } = await signedIn();
  state.revokeUnavailable = true;
  const logout = await auth.logout(headers);
  assert.equal(logout.revocationConfirmed, false);
  assert.ok(logout.setCookies.every((cookie) => cookie.includes('Max-Age=0')));
  await assert.rejects(auth.check(result.principal), status(401));
});

test('duplicate and malformed session cookies cannot authenticate', async () => {
  const { auth, headers } = await signedIn();
  const raw = headers.get('cookie');
  const merged = new Headers({ cookie: raw });
  merged.append('cookie', 'other=x; ' + raw);
  await assert.rejects(auth.requireUser(merged), status(401));
  await assert.rejects(auth.requireUser(new Headers({ cookie: raw + '; ' + raw })), status(401));
  await assert.rejects(auth.requireUser(new Headers({ cookie: '__Host-hiro-app-session="' + raw.split('=')[1] + '"' })), status(401));
});

test('all HTTP replies are bounded and redirects are refused, including token endpoints', async () => {
  for (const reply of [() => new Response('x'.repeat(32769)), () => Response.redirect('https://attacker.example')]) {
    await assert.rejects(createHiroAuth(config, { fetch: async () => reply() }), status(503));
    const state = provider();
    const original = state.fetch;
    state.fetch = (input, init) => new URL(input).pathname === '/token' ? Promise.resolve(reply()) : original(input, init);
    await assert.rejects(signedIn(state), status(503));
  }
  await assert.rejects(createHiroAuth(config, { fetch: async () => json({ ...metadata, token_endpoint: 'https://attacker.example/token' }) }), status(503));
});

test('absent config is optional but every partially or empty declared config fails closed', async () => {
  assert.equal(loadConfig({}), null);
  for (const key of ['HIRO_MANAGED', 'APP_AUTH_ISSUER', 'APP_AUTH_CLIENT_ID', 'APP_AUTH_CLIENT_SECRET_FILE', 'APP_PUBLIC_ORIGIN']) {
    assert.throws(() => loadConfig({ [key]: '' }));
  }
  const dir = await mkdtemp(join(tmpdir(), 'hiro-typescript-config-'));
  try {
    const file = join(dir, 'secret');
    await writeFile(file, config.clientSecret + '\r\n');
    const env = { HIRO_MANAGED: 'true', APP_AUTH_ISSUER: config.issuer, APP_AUTH_CLIENT_ID: config.clientId,
      APP_AUTH_CLIENT_SECRET_FILE: file, APP_PUBLIC_ORIGIN: config.publicOrigin };
    assert.deepEqual(loadConfig(env), config);
    await writeFile(file, '\n');
    assert.throws(() => loadConfig(env));
    for (const patch of [{ publicOrigin: 'http://app.example' }, { publicOrigin: 'https://app.example/' }, { issuer: 'https://hiro.example/' }]) {
      await assert.rejects(createHiroAuth({ ...config, ...patch }));
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('five-second deadline covers a stalled response body and cancels its reader', async () => {
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new TextEncoder().encode('{')); },
    cancel() { cancelled = true; },
  });
  await assert.rejects(createHiroAuth(config, { fetch: async () => new Response(body) }), status(503));
  assert.equal(cancelled, true);
});

test('logout during token exchange prevents callback from creating a session', async () => {
  const state = provider();
  const auth = await createHiroAuth(config, { fetch: state.fetch });
  const login = await auth.login();
  const location = new URL(login.location);
  state.challenge = location.searchParams.get('code_challenge');
  const url = new URL('/auth/callback?code=code', config.publicOrigin);
  url.searchParams.set('state', location.searchParams.get('state'));
  const headers = cookieHeaders(login.setCookies);
  let release;
  const waiting = new Promise((resolve) => { release = resolve; });
  let arrived;
  const started = new Promise((resolve) => { arrived = resolve; });
  state.beforeToken = async () => { arrived(); await waiting; };
  const callback = auth.callback(headers, url);
  await started;
  await assert.rejects(auth.callback(headers, url), status(401));
  const logout = await auth.logout(headers);
  assert.ok(logout.setCookies.every((cookie) => cookie.includes('Max-Age=0')));
  release();
  await assert.rejects(callback, status(401));
  await assert.rejects(auth.callback(headers, url), status(401));
  await assert.rejects(auth.requireUser(headers), status(401));
});
