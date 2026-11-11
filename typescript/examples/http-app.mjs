import { createServer } from 'node:http';
import { AuthError, clearPendingCookies, createHiroAuth, loadConfig } from '@hiro/app-auth';

const config = loadConfig(process.env);
if (!config) throw new Error('Configure hosted authentication before starting this example.');
const auth = await createHiroAuth(config);
const expectedHost = new URL(config.publicOrigin).host;

const server = createServer(async (request, response) => {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Security-Policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'");
  response.setHeader('X-Content-Type-Options', 'nosniff');
  const send = (status, body, type = 'text/plain; charset=utf-8') => {
    response.writeHead(status, { 'Content-Type': type });
    response.end(body);
  };
  const hostCount = request.rawHeaders.filter((_, index) => index % 2 === 0 && request.rawHeaders[index].toLowerCase() === 'host').length;
  if (hostCount !== 1 || request.headers.host !== expectedHost || !request.url?.startsWith('/') || request.url.startsWith('//')) {
    send(400, 'Invalid request host or target.');
    return;
  }
  const url = new URL(request.url, config.publicOrigin);
  if (url.origin !== config.publicOrigin) {
    send(400, 'Invalid request target.');
    return;
  }
  const headers = new Headers();
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    headers.append(request.rawHeaders[index], request.rawHeaders[index + 1]);
  }
  if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method) && request.headers.origin !== config.publicOrigin) {
    send(403, 'This action requires the application origin.');
    return;
  }
  try {
    if (request.method === 'GET' && url.pathname === '/auth/login') {
      const result = await auth.login();
      response.writeHead(303, { Location: result.location, 'Set-Cookie': result.setCookies });
      response.end();
    } else if (request.method === 'GET' && url.pathname === '/auth/callback') {
      const result = await auth.callback(headers, url);
      response.writeHead(303, { Location: '/', 'Set-Cookie': result.setCookies });
      response.end();
    } else if (request.method === 'GET' && url.pathname === '/api/me') {
      send(200, JSON.stringify(await auth.requireUser(headers)), 'application/json; charset=utf-8');
    } else if (request.method === 'POST' && url.pathname === '/auth/logout') {
      const result = await auth.logout(headers);
      response.setHeader('Set-Cookie', result.setCookies);
      send(result.revocationConfirmed ? 200 : 503, result.revocationConfirmed
        ? 'Signed out.' : 'Signed out locally. Hiro revocation could not be confirmed.');
    } else if (request.method === 'GET' && url.pathname === '/') {
      send(200, '<!doctype html><html lang="en"><meta charset="utf-8"><title>Hiro app</title><h1>Hiro app</h1><p><a href="/auth/login">Sign in with Hiro</a></p><p><a href="/api/me">Show my account</a></p><form method="post" action="/auth/logout"><button>Sign out</button></form></html>', 'text/html; charset=utf-8');
    } else {
      send(404, 'Not found.');
    }
  } catch (error) {
    if (url.pathname === '/auth/callback') response.setHeader('Set-Cookie', clearPendingCookies(config));
    send(error instanceof AuthError ? error.status : 503,
      error instanceof AuthError ? error.message : 'The application could not complete the request.');
  }
});

server.requestTimeout = 10000;
server.headersTimeout = 5000;
server.maxHeadersCount = 100;
server.listen(8080, '127.0.0.1');
