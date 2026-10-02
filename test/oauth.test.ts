import { env, exports } from 'cloudflare:workers';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { randomToken, hash } from '../src/security';
import { unwrap } from '../src/owner';
import { authorizationServer, maskedClientIdUrl } from '../src/oauth';

const origin = 'https://hey-mcp.example';
let loginAttempt = 0;
afterEach(() => vi.restoreAllMocks());
const request = (path: string, init?: RequestInit, baseOrigin = origin) => {
  const headers = new Headers(init?.headers);
  headers.set('Host', new URL(baseOrigin).host);
  return exports.default.fetch(`${baseOrigin}${path}`, { ...init, headers, redirect: 'manual' });
};
const textInput = (html: string, name: string) => html.match(new RegExp(`name="${name}" value="([^"]+)"`))?.[1] ?? '';
function cookies(response: Response): string {
  return response.headers.getSetCookie().map(c => c.split(';')[0]).join('; ');
}
function mergeCookies(...values: string[]): string {
  const merged = new Map<string, string>();
  for (const value of values) for (const entry of value.split('; ')) {
    if (entry.includes('=')) merged.set(entry.split('=')[0], entry);
  }
  return [...merged.values()].join('; ');
}
async function login() {
  const response = await request('/login', { method: 'POST', headers: { Origin: origin, 'CF-Connecting-IP': `192.0.2.${++loginAttempt}` },
    body: new URLSearchParams({ secret: env.ADMIN_SECRET, next: '/admin' }) });
  expect(response.status).toBe(303);
  const cookie = cookies(response);
  const admin = await request('/admin', { headers: { Cookie: cookie } });
  return { cookie, csrf: textInput(await admin.text(), 'csrf') };
}
async function setup() {
  unwrap(await env.OWNER.getByName('owner').command({ type: 'import', credentials: {
    credentials: { access_token: 'test-access', refresh_token: 'test-refresh', expires_at: 0, oauth_type: 'oauth' },
    install_id: '12345678-1234-4234-8234-123456789abc',
  } }));
  const admin = await login();
  const clientResponse = await request('/oauth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
    client_name: '<script>alert(1)</script>', redirect_uris: ['https://client.example/callback'], token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
  }) });
  expect(clientResponse.status).toBe(201);
  const client = await clientResponse.json() as { client_id: string };
  const verifier = randomToken();
  const challenge = (await hash(verifier)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  const authorize = '/authorize?' + new URLSearchParams({ client_id: client.client_id, redirect_uri: 'https://client.example/callback',
    response_type: 'code', scope: 'hey:read offline_access', resource: `${origin}/mcp`, state: 'client-state',
    code_challenge: challenge, code_challenge_method: 'S256' });
  const consent = await request(authorize, { headers: { Cookie: admin.cookie } });
  expect(consent.status).toBe(200);
  expect(consent.headers.get('Content-Security-Policy')).toContain("form-action 'self' https://client.example");
  const html = await consent.text();
  expect(html).not.toContain('<script>alert');
  expect(html).toContain('client.example');
  return { ...admin, clientId: client.client_id, verifier, cookie: mergeCookies(admin.cookie, cookies(consent)), handle: textInput(html, 'handle'), authorize };
}
async function approve(info: Awaited<ReturnType<typeof setup>>, extra: Record<string, string> = {}) {
  const response = await request('/authorize', { method: 'POST', headers: { Origin: origin, Cookie: info.cookie },
    body: new URLSearchParams({ handle: info.handle, csrf: info.csrf, name: 'Test connection', decision: 'approve', ...extra }) });
  expect(response.status).toBe(303);
  const location = new URL(response.headers.get('Location')!);
  expect(location.origin).toBe('https://client.example');
  expect(location.searchParams.get('state')).toBe('client-state');
  expect(location.searchParams.get('iss')).toBe(origin);
  return location.searchParams.get('code')!;
}
async function exchange(info: Awaited<ReturnType<typeof setup>>, code: string, verifier = info.verifier) {
  return request('/oauth/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'authorization_code',
    client_id: info.clientId, code, redirect_uri: 'https://client.example/callback', code_verifier: verifier, resource: `${origin}/mcp` }) });
}
async function refresh(clientId: string, token: string) {
  return request('/oauth/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'refresh_token',
    client_id: clientId, refresh_token: token, resource: `${origin}/mcp` }) });
}
async function mcp(token: string, method: string, params: Record<string, unknown> = {}) {
  const response = await request('/mcp', { method: 'POST', headers: {
    Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
    'MCP-Protocol-Version': '2025-06-18',
  }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const text = await response.text();
  const data = text.startsWith('event:') || text.startsWith('data:')
    ? JSON.parse(text.split('\n').find(line => line.startsWith('data:'))!.slice(5)) : JSON.parse(text);
  return { response, data };
}

describe('HTTP and OAuth boundaries', () => {
  it.each([
    ['https://client.example/oauth/metadata.json', 'https://client.example/oauth/metadata.json'],
    ['https://client.example/oauth/metadata.json?token=short&flag&token=second#hidden', 'https://client.example/oauth/metadata.json?token=***&flag=***&token=***'],
    ['https://client.example/12345678-1234-4234-8234-123456789abc/metadata.json', 'https://client.example/***/metadata.json'],
    ['https://client.example/client-12345678%2D1234%2D4234%2D8234%2D123456789abc.json', 'https://client.example/client-***.json'],
    ['https://client.example/ab12cd34ef56ab78cd90ef12ab34cd56/metadata.json', 'https://client.example/***/metadata.json'],
    ['https://client.example/aB9xK2mN7qR4sT6uV8wY1zC3/metadata.json', 'https://client.example/***/metadata.json'],
    ['https://client.example/%61B9xK2mN7qR4sT6uV8wY1zC3/metadata.json', 'https://client.example/***/metadata.json'],
    ['https://client.example/client-metadata-document-production.json?v=3', 'https://client.example/client-metadata-document-production.json?v=***'],
  ])('masks client identifier %s', (input, expected) => {
    expect(maskedClientIdUrl(input)).toBe(expected);
  });
  it('protects management, denies CSRF, and does not accept an open login redirect', async () => {
    const admin = await login();
    expect((await request('/admin')).status).toBe(200);
    expect(await (await request('/admin')).text()).toContain('管理用シークレット');
    const body = new URLSearchParams({ csrf: admin.csrf });
    expect((await request('/admin/verify', { method: 'POST', headers: { Cookie: admin.cookie, Origin: 'https://attacker.example' }, body })).status).toBe(403);
    expect((await request('/admin/verify', { method: 'POST', headers: { Cookie: admin.cookie, Origin: origin }, body: new URLSearchParams({ csrf: 'wrong' }) })).status).toBe(403);
    const response = await request('/login', { method: 'POST', headers: { Origin: origin }, body: new URLSearchParams({ secret: env.ADMIN_SECRET, next: '//attacker.example' }) });
    expect(response.headers.get('Location')).toBe('/admin');
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.get('Set-Cookie')).toContain('HttpOnly');
    expect(response.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'");
    expect(response.headers.get('Referrer-Policy')).toBe('same-origin');
    expect((await request('/login?next=http://[')).status).toBe(200);
  });
  it('advertises protected-resource and authorization metadata with PKCE', async () => {
    const denied = await request('/mcp', { method: 'POST' });
    expect(denied.status).toBe(401);
    expect(denied.headers.get('WWW-Authenticate')).toContain('resource_metadata');
    const metadata = await (await request('/.well-known/oauth-authorization-server')).json() as Record<string, unknown>;
    expect(metadata.code_challenge_methods_supported).toEqual(['S256']);
    const protectedResource = await (await request('/.well-known/oauth-protected-resource/mcp')).json() as Record<string, unknown>;
    expect(protectedResource.resource).toBe(`${origin}/mcp`);
    expect(protectedResource.scopes_supported).toEqual(['hey:read']);
  });
  it('derives OAuth metadata from each request URL and ignores forwarded hosts', async () => {
    for (const host of ['https://hey-mcp.example.workers.dev', 'https://mail.example']) {
      const headers = { 'X-Forwarded-Host': 'attacker.example', 'X-Forwarded-Proto': 'http' };
      const response = await request('/.well-known/oauth-authorization-server', { headers }, host);
      expect(response.status).toBe(200);
      const metadata = await response.json() as Record<string, unknown>;
      expect(metadata.issuer).toBe(host);
      expect(metadata.authorization_endpoint).toBe(`${host}/authorize`);
      expect(metadata.token_endpoint).toBe(`${host}/oauth/token`);
      const resource = await (await request('/.well-known/oauth-protected-resource/mcp', { headers }, host)).json() as Record<string, unknown>;
      expect(resource.resource).toBe(`${host}/mcp`);
      expect(resource.authorization_servers).toEqual([host]);
    }
  });
  it('accepts local HTTP development URLs and rejects remote HTTP', async () => {
    const local = await request('/login', undefined, 'http://localhost:9898');
    expect(local.status).toBe(200);
    expect(local.headers.has('Strict-Transport-Security')).toBe(false);
    const login = await request('/login', { method: 'POST', headers: { Origin: 'http://localhost:9898' },
      body: new URLSearchParams({ secret: env.ADMIN_SECRET }) }, 'http://localhost:9898');
    expect(login.status).toBe(303);
    const admin = await request('/admin', { headers: { Cookie: cookies(login) } }, 'http://localhost:9898');
    expect(await admin.text()).toContain('http://localhost:9898/mcp');
    const forged = await request('/logout', { method: 'POST', headers: { Origin: origin },
      body: new URLSearchParams() }, 'http://localhost:9898');
    expect(forged.status).toBe(403);
    expect((await request('/login', undefined, 'http://hey-mcp.example')).status).toBe(400);
  });
  it('requires browser-bound consent and honors denial', async () => {
    const info = await setup();
    const forged = await request('/authorize', { method: 'POST', headers: { Origin: origin, Cookie: info.cookie.split('; ')[0] },
      body: new URLSearchParams({ handle: info.handle, csrf: info.csrf, decision: 'approve', name: 'test' }) });
    expect(forged.status).toBe(400);
    const denied = await request('/authorize', { method: 'POST', headers: { Origin: origin, Cookie: info.cookie },
      body: new URLSearchParams({ handle: info.handle, csrf: info.csrf, decision: 'deny' }) });
    expect(denied.status).toBe(303);
    expect(new URL(denied.headers.get('Location')!).searchParams.get('error')).toBe('access_denied');
  });
  it('rejects wrong PKCE and resource audiences', async () => {
    const info = await setup();
    const code = await approve(info);
    const incorrect = await exchange(info, code, randomToken());
    expect(incorrect.status).toBe(400);
    const wrongResource = await request('/oauth/token', { method: 'POST', body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: info.clientId, code, redirect_uri: 'https://client.example/callback',
      code_verifier: info.verifier, resource: 'https://other.example/mcp',
    }) });
    expect(wrongResource.status).toBe(400);
  });
  it('issues separate read-only tokens, denies hidden writes, rotates refreshes and revokes both tokens', async () => {
    const info = await setup();
    const response = await exchange(info, await approve(info));
    expect(response.status).toBe(200);
    const tokens = await response.json() as { access_token: string; refresh_token: string; scope: string };
    expect(tokens.scope).toContain('hey:read');
    expect(tokens.scope).not.toContain('hey:write');
    const listing = await mcp(tokens.access_token, 'tools/list');
    expect(listing.response.status, JSON.stringify(listing.data)).toBe(200);
    expect(listing.data.result.tools.every((tool: { annotations: { readOnlyHint: boolean } }) => tool.annotations.readOnlyHint)).toBe(true);
    expect(JSON.stringify(listing.data)).not.toMatch(/(?: |, )trash_topic(?:,|\.)/);
    const write = await mcp(tokens.access_token, 'tools/call', { name: 'hey_threads', arguments: { action: 'trash_topic', params: { topicId: 1 } } });
    expect(write.data.result.isError).toBe(true);
    const refreshed = await request('/oauth/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'refresh_token',
      client_id: info.clientId, refresh_token: tokens.refresh_token, resource: `${origin}/mcp` }) });
    expect(refreshed.status).toBe(200);
    const rotated = await refreshed.json() as { access_token: string; refresh_token: string };
    expect(rotated.refresh_token).not.toBe(tokens.refresh_token);
    const otherOrigin = 'https://another-worker.example';
    expect((await request('/mcp', { headers: { Authorization: `Bearer ${tokens.access_token}` } }, otherOrigin)).status).toBe(401);
    const summary = await authorizationServer(env, origin).getOAuthApi(env).unwrapToken<{ connectionId: string }>(tokens.access_token);
    expect(summary).not.toBeNull();
    const revoked = await request('/admin/revoke', { method: 'POST', headers: { Origin: origin, Cookie: info.cookie },
      body: new URLSearchParams({ csrf: info.csrf, id: summary!.grant.props.connectionId }) });
    expect(revoked.status).toBe(200);
    for (const token of [tokens.access_token, rotated.access_token]) expect((await request('/mcp', { headers: { Authorization: `Bearer ${token}` } })).status).toBe(401);
    for (const token of [tokens.refresh_token, rotated.refresh_token]) {
      const refresh = await request('/oauth/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'refresh_token', client_id: info.clientId, refresh_token: token }) });
      expect(refresh.status).toBe(400);
    }
  });
  it('requires send permission for scheduled drafts and immediate sends over MCP', async () => {
    const info = await setup();
    const response = await exchange(info, await approve(info, { write: 'yes' }));
    const tokens = await response.json() as { access_token: string };
    for (const entry of [{}, { status: 'drafted', scheduled_delivery: 'true' }]) {
      const result = await mcp(tokens.access_token, 'tools/call', { name: 'hey_threads', arguments: { action: 'create_message',
        params: { acting_sender_id: 1, message: { subject: 'test', content: 'test' }, entry } } });
      expect(result.data.result, JSON.stringify(result.data)).toBeDefined();
      expect(result.data.result.isError).toBe(true);
      expect(JSON.stringify(result.data)).toContain('hey:send');
    }
  });
  it('revokes the connection and all its tokens on refresh token replay', async () => {
    const info = await setup();
    const initial = await exchange(info, await approve(info));
    const tokens = await initial.json() as { access_token: string; refresh_token: string };
    const first = await refresh(info.clientId, tokens.refresh_token);
    expect(first.status).toBe(200);
    const rotated = await first.json() as { access_token: string; refresh_token: string };
    const replay = await refresh(info.clientId, tokens.refresh_token);
    expect(replay.status).toBe(400);
    expect(await replay.json()).toMatchObject({ error: 'invalid_grant' });
    expect((await refresh(info.clientId, rotated.refresh_token)).status).toBe(400);
    expect((await refresh(info.clientId, tokens.refresh_token)).status).toBe(400);
    for (const token of [tokens.access_token, rotated.access_token]) {
      expect((await request('/mcp', { headers: { Authorization: `Bearer ${token}` } })).status).toBe(401);
    }
  });
  it('does not revoke a connection for a guessed or wrong-client refresh token', async () => {
    const info = await setup();
    const initial = await exchange(info, await approve(info));
    const tokens = await initial.json() as { refresh_token: string };
    const parts = tokens.refresh_token.split(':');
    parts[2] = randomToken();
    expect((await refresh(info.clientId, parts.join(':'))).status).toBe(400);
    expect((await refresh('unknown-client', tokens.refresh_token)).status).toBe(401);
    expect((await refresh(info.clientId, tokens.refresh_token)).status).toBe(200);
  });
  it('rejects simultaneous reuse even when KV reads the same current token', async () => {
    const info = await setup();
    const initial = await exchange(info, await approve(info));
    const tokens = await initial.json() as { access_token: string; refresh_token: string };
    const responses = await Promise.all([refresh(info.clientId, tokens.refresh_token), refresh(info.clientId, tokens.refresh_token)]);
    expect(responses.map(response => response.status).sort()).toEqual([200, 400]);
    const issued = await responses.find(response => response.status === 200)!.json() as { access_token: string; refresh_token: string };
    expect((await refresh(info.clientId, issued.refresh_token)).status).toBe(400);
    for (const token of [tokens.access_token, issued.access_token]) {
      expect((await request('/mcp', { headers: { Authorization: `Bearer ${token}` } })).status).toBe(401);
    }
  });
  it('detects replay of a token older than the provider previous-token slot', async () => {
    const info = await setup();
    const initial = await exchange(info, await approve(info));
    const tokens = await initial.json() as { refresh_token: string };
    const first = await refresh(info.clientId, tokens.refresh_token);
    expect(first.status).toBe(200);
    const firstRotation = await first.json() as { refresh_token: string };
    const second = await refresh(info.clientId, firstRotation.refresh_token);
    expect(second.status).toBe(200);
    const latest = await second.json() as { access_token: string; refresh_token: string };
    expect((await refresh(info.clientId, tokens.refresh_token)).status).toBe(400);
    expect((await refresh(info.clientId, latest.refresh_token)).status).toBe(400);
    expect((await request('/mcp', { headers: { Authorization: `Bearer ${latest.access_token}` } })).status).toBe(401);
  });
  it('masks CIMD URLs and upstream error details in logs', async () => {
    const admin = await login();
    const clientId = 'https://metadata.example/12345678-1234-4234-8234-123456789abc/aB9xK2mN7qR4sT6uV8wY1zC3/metadata.json?token=private-query';
    const fetcher = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error(`Failed to fetch ${clientId}: private-upstream-detail`));
    const logger = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const response = await request('/authorize?' + new URLSearchParams({ client_id: clientId, redirect_uri: 'https://client.example/callback',
      response_type: 'code', scope: 'hey:read', resource: `${origin}/mcp`, code_challenge: await hash(randomToken()), code_challenge_method: 'S256' }),
      { headers: { Cookie: admin.cookie } });
    expect(response.status).toBe(503);
    expect(fetcher).toHaveBeenCalled();
    const logs = [...logger.mock.calls, ...errors.mock.calls].map(call => call.join(' ')).join('\n');
    expect(logs).toContain('oauth_cimd_fetch_failed');
    expect(logs).toContain('https://metadata.example/***/***/metadata.json?token=***');
    expect(logs).not.toContain('clientIdHash');
    for (const privateValue of [clientId, '12345678-1234-4234-8234-123456789abc', 'aB9xK2mN7qR4sT6uV8wY1zC3', 'private-query', 'private-upstream-detail']) {
      expect(logs).not.toContain(privateValue);
    }
  });
});
