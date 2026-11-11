import { readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import * as oauth from 'openid-client';

export type Principal = Readonly<{ issuer: string; subject: string }>;
export type Config = Readonly<{
  issuer: string;
  clientId: string;
  clientSecret: string;
  publicOrigin: string;
  httpOrigins?: readonly string[];
  browserOrigin?: string;
}>;
export type CookieResult = Readonly<{ setCookies: readonly string[] }>;
export type LoginResult = CookieResult & Readonly<{ location: string }>;
export type CallbackResult = CookieResult & Readonly<{ principal: Principal }>;
export type LogoutResult = CookieResult & Readonly<{ revocationConfirmed: boolean }>;
export type HiroAuth = Readonly<{
  login(): Promise<LoginResult>;
  callback(headers: Headers, url: URL): Promise<CallbackResult>;
  requireUser(headers: Headers): Promise<Principal>;
  check(principal: Principal): Promise<Principal>;
  serviceRequest(principal: Principal, request: Request): Promise<Response>;
  logout(headers: Headers): Promise<LogoutResult>;
}>;

export class AuthError extends Error {
  constructor(
    message = 'Authentication has expired. Sign in again.',
    public readonly status: 401 | 403 | 503 = 401,
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

const SESSION = '__Host-hiro-app-session';
const PENDING = '__Host-hiro-app-pending';
const LIMIT = 1024;
const UNAVAILABLE = 'The authorization service is unavailable. Try again later.';
const INVALID_CONFIG = 'Hosted authentication configuration is invalid or incomplete.';
const clearCookie = (name: string): string => cookie(name, '') + '; Max-Age=0';
const tokenId = (): string => randomBytes(32).toString('base64url');
const now = (): number => Date.now() / 1000;

function cookie(name: string, value: string, secure = true): string {
  return `${name}=${value}; Path=/;${secure ? ' Secure;' : ''} HttpOnly; SameSite=Lax`;
}

/** Apply these on callback failure. A consumed or invalid sign-in cannot be retried. */
export function clearPendingCookies(config?: Config): readonly string[] {
  if (!config || browserUrl(config.publicOrigin, config.httpOrigins).protocol === 'https:') return [clearCookie(PENDING)];
  return [cookie(httpCookieName(config.clientId, 'pending'), '', false) + '; Max-Age=0'];
}

function httpCookieName(clientId: string, kind: string): string {
  return `hiro-app-${createHash('sha256').update(clientId).digest('hex').slice(0, 32)}${kind === 'pending' ? '-pending' : ''}`;
}

function browserUrl(value: string, httpOrigins: readonly string[] = []): URL {
  if (typeof value !== 'string' || /[\s\u0000-\u0020\u007f\\?#]/u.test(value)) throw new Error(INVALID_CONFIG);
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(INVALID_CONFIG); }
  if (url.protocol === 'https:') return httpsUrl(value);
  const host = url.hostname;
  const octets = host.split('.').map(Number);
  const privateIPv4 = isIP(host) === 4 && (octets[0] === 10 || (octets[0] === 172 && (octets[1] ?? -1) >= 16 && (octets[1] ?? -1) <= 31)
    || (octets[0] === 192 && octets[1] === 168) || octets[0] === 127);
  if (url.protocol !== 'http:' || !privateIPv4 || !url.port || value.split('/')[2] !== url.host
    || url.username || url.password || url.search || url.hash || !httpOrigins.includes(url.origin)) throw new Error(INVALID_CONFIG);
  return url;
}

function cookieValue(headers: Headers, name: string): string {
  const raw = headers.get('cookie') ?? '';
  if (raw.includes(',')) return '';
  const values = raw.split(';')
    .map((part) => part.trim()).filter((part) => part.split('=', 1)[0] === name);
  if (values.length !== 1) return '';
  const value = values[0]?.slice(name.length + 1) ?? '';
  return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : '';
}

function httpsUrl(value: string): URL {
  if (typeof value !== 'string' || /[\s\u0000-\u0020\u007f\\?#]/u.test(value)) {
    throw new Error(INVALID_CONFIG);
  }
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(INVALID_CONFIG); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new Error(INVALID_CONFIG);
  }
  return url;
}

function validateConfig(config: Config): Config {
  httpsUrl(config.issuer);
  if (config.httpOrigins !== undefined && (!Array.isArray(config.httpOrigins)
    || config.httpOrigins.some((value) => { const url = browserUrl(value, [value]); return url.protocol !== 'http:' || url.origin !== value; }))) throw new Error(INVALID_CONFIG);
  const origin = browserUrl(config.publicOrigin, config.httpOrigins);
  if (config.browserOrigin !== undefined) {
    const browser = browserUrl(config.browserOrigin, config.httpOrigins);
    if (browser.protocol !== 'http:' || browser.origin !== config.browserOrigin) throw new Error(INVALID_CONFIG);
  }
  if (config.issuer.endsWith('/') || origin.origin !== config.publicOrigin
    || typeof config.clientId !== 'string' || !config.clientId.trim() || config.clientId.length > 256
    || typeof config.clientSecret !== 'string' || !config.clientSecret
    || /[\u0000-\u001f\u007f]/u.test(config.clientId + config.clientSecret)) {
    throw new Error(INVALID_CONFIG);
  }
  return Object.freeze({ ...config, ...(config.httpOrigins ? { httpOrigins: Object.freeze([...config.httpOrigins]) } : {}) });
}

/** Missing auth settings return null. Any declared but incomplete settings fail closed. */
export function loadConfig(environment: Readonly<Record<string, string | undefined>>): Config | null {
  const names = ['APP_AUTH_ISSUER', 'APP_AUTH_CLIENT_ID', 'APP_AUTH_CLIENT_SECRET_FILE', 'APP_PUBLIC_ORIGIN', 'APP_AUTH_HTTP_ORIGINS', 'APP_AUTH_BROWSER_ORIGIN'];
  if (environment.HIRO_MANAGED === undefined && !names.some((name) => name in environment)) return null;
  const issuer = environment.APP_AUTH_ISSUER;
  const clientId = environment.APP_AUTH_CLIENT_ID;
  const secretFile = environment.APP_AUTH_CLIENT_SECRET_FILE;
  const publicOrigin = environment.APP_PUBLIC_ORIGIN;
  if (environment.HIRO_MANAGED !== 'true' || !issuer || !clientId || !secretFile || !publicOrigin) {
    throw new Error(INVALID_CONFIG);
  }
  let clientSecret: string;
  try { clientSecret = readFileSync(secretFile, 'utf8').replace(/[\r\n]+$/u, ''); }
  catch { throw new Error('The authentication secret file could not be read.'); }
  const httpOrigins: unknown = environment.APP_AUTH_HTTP_ORIGINS === undefined ? undefined : JSON.parse(environment.APP_AUTH_HTTP_ORIGINS);
  if (httpOrigins !== undefined && (!Array.isArray(httpOrigins) || !httpOrigins.every((value): value is string => typeof value === 'string'))) throw new Error(INVALID_CONFIG);
  return validateConfig({ issuer, clientId, clientSecret, publicOrigin,
    ...(httpOrigins === undefined ? {} : { httpOrigins }),
    ...(environment.APP_AUTH_BROWSER_ORIGIN === undefined ? {} : { browserOrigin: environment.APP_AUTH_BROWSER_ORIGIN }) });
}

type PendingLogin = Readonly<{
  phase: 'pending' | 'exchanging'; expires: number; state: string; verifier: string;
}>;
type Session = Readonly<{ token: string; principal: Principal; expires: number }>;
type Grant = Readonly<{ subject: string; expires: number }>;

function boundedFetch(transport: typeof fetch): typeof fetch {
  return async (input, init) => {
    const controller = new AbortController();
    const signal = init?.signal
      ? AbortSignal.any([init.signal, controller.signal]) : controller.signal;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new AuthError(UNAVAILABLE, 503));
      }, 5000);
    });
    const request = async (): Promise<Response> => {
      const response = await transport(input, { ...init, redirect: 'manual', signal });
      if (signal.aborted) {
        void response.body?.cancel().catch(() => {});
        throw new AuthError(UNAVAILABLE, 503);
      }
      if (response.redirected || (response.status >= 300 && response.status < 400)) {
        await response.body?.cancel();
        throw new AuthError(UNAVAILABLE, 503);
      }
      reader = response.body?.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      while (reader) {
        const next = await reader.read();
        if (next.done) break;
        size += next.value.byteLength;
        if (size > 32768) throw new AuthError(UNAVAILABLE, 503);
        chunks.push(next.value);
      }
      const body = Buffer.concat(chunks, size);
      return new Response(response.status === 204 || response.status === 205 || response.status === 304 ? null : body, {
        status: response.status, statusText: response.statusText, headers: response.headers,
      });
    };
    try { return await Promise.race([request(), deadline]); }
    catch { throw new AuthError(UNAVAILABLE, 503); }
    finally {
      clearTimeout(timer);
      controller.abort();
      void reader?.cancel().catch(() => {});
    }
  };
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new AuthError('The authorization service returned an invalid response.', 503);
  }
  return Object.fromEntries(Object.entries(value));
}

async function discover(config: Config, transport: typeof fetch): Promise<oauth.Configuration> {
  const response = await transport(config.issuer + '/.well-known/openid-configuration');
  if (!response.ok) throw new AuthError(UNAVAILABLE, 503);
  const metadata = record(await response.json());
  if (metadata.issuer !== config.issuer) throw new AuthError(UNAVAILABLE, 503);
  const endpoint = (name: string): string => {
    const value = metadata[name];
    if (typeof value !== 'string' || httpsUrl(value).origin !== new URL(config.issuer).origin) {
      throw new AuthError(UNAVAILABLE, 503);
    }
    return value;
  };
  const client = new oauth.Configuration({
    issuer: config.issuer,
    authorization_endpoint: endpoint('authorization_endpoint'),
    token_endpoint: endpoint('token_endpoint'),
    introspection_endpoint: endpoint('introspection_endpoint'),
    revocation_endpoint: endpoint('revocation_endpoint'),
    userinfo_endpoint: endpoint('userinfo_endpoint'),
  }, config.clientId, config.clientSecret, oauth.ClientSecretBasic(config.clientSecret));
  client[oauth.customFetch] = (url, init) => transport(url, {
    ...init, body: init.body instanceof Uint8Array ? new Uint8Array(init.body) : init.body ?? null,
  });
  client.timeout = 5;
  return client;
}

/** Create one instance per app process. Tokens are sent only to the configured Hiro origin. */
export async function createHiroAuth(config: Config, options: Readonly<{ fetch?: typeof fetch }> = {}): Promise<HiroAuth> {
  const settings = validateConfig(config);
  const secure = new URL(settings.publicOrigin).protocol === 'https:';
  const sessionCookie = secure ? SESSION : httpCookieName(settings.clientId, 'session');
  const pendingCookie = secure ? PENDING : httpCookieName(settings.clientId, 'pending');
  const setCookie = (name: string, value: string): string => cookie(name, value, secure);
  const clear = (name: string): string => setCookie(name, '') + '; Max-Age=0';
  const transport = options.fetch ?? globalThis.fetch;
  let client: oauth.Configuration;
  try { client = await discover(settings, boundedFetch(transport)); }
  catch { throw new AuthError('Hiro discovery is unavailable or invalid.', 503); }
  const pending = new Map<string, PendingLogin>();
  const sessions = new Map<string, Session>();
  const cleanup = (): void => {
    for (const [id, item] of pending) if (item.expires <= now()) pending.delete(id);
    for (const [id, item] of sessions) if (item.expires <= now()) sessions.delete(id);
  };
  const introspect = async (token: string): Promise<Grant> => {
    let data: Record<string, unknown>;
    try { data = record(await oauth.tokenIntrospection(client, token, { token_type_hint: 'access_token' })); }
    catch { throw new AuthError(UNAVAILABLE, 503); }
    if (data.active !== true || typeof data.sub !== 'string' || !data.sub.trim()
      || data.client_id !== settings.clientId || data.aud !== 'urn:hiro:app:' + settings.clientId
      || typeof data.exp !== 'number' || !Number.isSafeInteger(data.exp) || data.exp <= now()
      || ('iss' in data && data.iss !== settings.issuer)) throw new AuthError();
    const scopes = data.scope;
    if (typeof scopes !== 'string' || !['openid', 'hiro.app'].every((scope) => scopes.split(/\s+/u).includes(scope))) {
      throw new AuthError('This grant does not include the required application scopes.', 403);
    }
    return { subject: data.sub, expires: data.exp };
  };
  const checkSession = async (id: string, session: Session): Promise<Principal> => {
    cleanup();
    if (sessions.get(id) !== session) throw new AuthError();
    try {
      const current = await introspect(session.token);
      cleanup();
      if (sessions.get(id) !== session || current.subject !== session.principal.subject || current.expires !== session.expires) {
        throw new AuthError();
      }
      return session.principal;
    } catch (error) {
      if (error instanceof AuthError && error.status === 401 && sessions.get(id) === session) sessions.delete(id);
      throw error;
    }
  };
  return Object.freeze({
    async login(): Promise<LoginResult> {
      cleanup();
      if (pending.size >= LIMIT) throw new AuthError('Too many pending sign-ins. Try again later.', 503);
      const verifier = oauth.randomPKCECodeVerifier();
      const state = oauth.randomState();
      const challenge = await oauth.calculatePKCECodeChallenge(verifier);
      cleanup();
      if (pending.size >= LIMIT) throw new AuthError('Too many pending sign-ins. Try again later.', 503);
      const id = tokenId();
      const authorization = oauth.buildAuthorizationUrl(client, {
        redirect_uri: settings.publicOrigin + '/auth/callback', scope: 'openid hiro.app', state,
        code_challenge: challenge, code_challenge_method: 'S256',
      });
      const location = settings.browserOrigin
        ? settings.browserOrigin + authorization.pathname + authorization.search : authorization.href;
      pending.set(id, { phase: 'pending', expires: now() + 300, state, verifier });
      return { location, setCookies: [setCookie(pendingCookie, id)] };
    },
    async callback(headers: Headers, url: URL): Promise<CallbackResult> {
      cleanup();
      const id = cookieValue(headers, pendingCookie);
      const attempt = pending.get(id);
      if (!attempt || attempt.phase !== 'pending') throw new AuthError();
      const exchanging = { ...attempt, phase: 'exchanging' } satisfies PendingLogin;
      pending.set(id, exchanging);
      try {
        if (url.origin !== settings.publicOrigin || url.pathname !== '/auth/callback' || url.hash
          || url.username || url.password || url.searchParams.getAll('code').length !== 1
          || url.searchParams.getAll('state').length !== 1 || url.searchParams.get('state') !== attempt.state) throw new AuthError();
        let token: string;
        let grant: Grant;
        try {
          const tokens = await oauth.authorizationCodeGrant(client, url, {
            pkceCodeVerifier: attempt.verifier, expectedState: attempt.state, idTokenExpected: false,
          });
          token = tokens.access_token;
          if (!token || token.length > 16384) throw new AuthError();
          grant = await introspect(token);
          const userInfo = await oauth.fetchUserInfo(client, token, oauth.skipSubjectCheck);
          if (userInfo.sub !== grant.subject) throw new AuthError();
        } catch (error) {
          if (error instanceof AuthError) throw error;
          if (error instanceof oauth.AuthorizationResponseError
            || (error instanceof oauth.ResponseBodyError && ['invalid_grant', 'invalid_request', 'access_denied'].includes(error.error))) {
            throw new AuthError('Sign-in was not completed. Start again.');
          }
          throw new AuthError('The authorization service returned an invalid response. Try again later.', 503);
        }
        cleanup();
        if (pending.get(id) !== exchanging || exchanging.expires <= now() || grant.expires <= now()) throw new AuthError();
        const previousId = cookieValue(headers, sessionCookie);
        if (sessions.size >= LIMIT && !sessions.has(previousId)) {
          throw new AuthError('Session capacity has been reached. Try again later.', 503);
        }
        sessions.delete(previousId);
        const principal = Object.freeze({ issuer: settings.issuer, subject: grant.subject });
        const sessionId = tokenId();
        sessions.set(sessionId, { token, principal, expires: grant.expires });
        return { principal, setCookies: [clear(pendingCookie), setCookie(sessionCookie, sessionId)] };
      } finally {
        if (pending.get(id) === exchanging) pending.delete(id);
      }
    },
    async requireUser(headers: Headers): Promise<Principal> {
      cleanup();
      const id = cookieValue(headers, sessionCookie);
      const session = sessions.get(id);
      if (!session) throw new AuthError();
      return checkSession(id, session);
    },
    async check(principal: Principal): Promise<Principal> {
      cleanup();
      for (const [id, session] of sessions) if (session.principal === principal) return checkSession(id, session);
      throw new AuthError();
    },
    async serviceRequest(principal: Principal, request: Request): Promise<Response> {
      const origin = new URL(settings.issuer).origin;
      const endpoints = ['images/generations', 'images/edits', 'responses'];
      if (request.method !== 'POST'
        || !endpoints.some((path) => request.url === `${origin}/api/app-services/openai/v1/${path}`)
        || [...request.headers.keys()].some((name) => !['accept', 'content-type'].includes(name))) {
        throw new TypeError('Use an exact workbench service POST endpoint with only Accept and Content-Type headers.');
      }
      cleanup();
      for (const [id, session] of sessions) {
        if (session.principal !== principal) continue;
        await checkSession(id, session);
        const headers = new Headers(request.headers);
        headers.set('Authorization', `Bearer ${session.token}`);
        const outgoing = new Request(request, {
          headers, redirect: 'manual', credentials: 'omit', referrer: '', referrerPolicy: 'no-referrer',
          signal: AbortSignal.any([request.signal, AbortSignal.timeout(600_000)]),
        });
        const response = await transport(outgoing);
        if (response.redirected || (response.status >= 300 && response.status < 400)) {
          await response.body?.cancel();
          throw new Error('Workbench service redirect refused. The provider outcome may be unknown.');
        }
        return response;
      }
      throw new AuthError();
    },
    async logout(headers: Headers): Promise<LogoutResult> {
      cleanup();
      const id = cookieValue(headers, sessionCookie);
      const session = sessions.get(id);
      sessions.delete(id);
      pending.delete(cookieValue(headers, pendingCookie));
      let revocationConfirmed = false;
      if (session) {
        try {
          await oauth.tokenRevocation(client, session.token, { token_type_hint: 'access_token' });
          revocationConfirmed = true;
        } catch { /* Local logout remains effective when revocation is unavailable. */ }
      }
      return { setCookies: [clear(sessionCookie), clear(pendingCookie)], revocationConfirmed };
    },
  });
}
