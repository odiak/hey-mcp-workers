import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { unwrap } from '../src/owner';
import type { Credentials } from '../src/hey';

const fixture = (expires = 0): Credentials => ({
  credentials: { access_token: 'synthetic-access', refresh_token: 'synthetic-refresh', expires_at: expires, oauth_type: 'oauth' },
  install_id: '12345678-1234-4234-8234-123456789abc',
});
const owner = () => env.OWNER.getByName(crypto.randomUUID());
afterEach(() => vi.restoreAllMocks());

describe('owner coordination', () => {
  it('stores only encrypted upstream credentials and hashed admin sessions', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture() }));
    const result = unwrap(await stub.command({ type: 'login', secret: env.ADMIN_SECRET, address: 'local' })) as { token: string; csrf: string };
    expect(await stub.session(result.token)).toEqual({ csrf: result.csrf });
    await runInDurableObject(stub, async (_instance, state) => {
      const stored = JSON.stringify([...await state.storage.list()]);
      expect(stored).not.toContain('synthetic-access');
      expect(stored).not.toContain('synthetic-refresh');
      expect(stored).not.toContain(fixture().install_id);
      const sessions = JSON.stringify(state.storage.sql.exec('SELECT * FROM sessions').toArray());
      expect(sessions).not.toContain(result.token);
      expect(sessions).not.toContain(env.ADMIN_SECRET);
    });
    unwrap(await stub.command({ type: 'logout', token: result.token }));
    expect(await stub.session(result.token)).toBeNull();
  });
  it('limits login attempts', async () => {
    const stub = owner();
    for (let i = 0; i < 10; i++) expect(unwrap(await stub.command({ type: 'login', secret: 'wrong', address: 'same-address' }))).toBeNull();
    expect(await stub.command({ type: 'login', secret: env.ADMIN_SECRET, address: 'same-address' })).toMatchObject({ ok: false, status: 429 });
  });
  it('rejects write calls even if the caller claims broader token scopes', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture() }));
    const id = unwrap(await stub.command({ type: 'create', clientId: 'client', name: 'test', redirectUri: 'https://client.example/callback', scopes: ['hey:read'] })) as string;
    const fetcher = vi.spyOn(globalThis, 'fetch');
    expect(await stub.command({ type: 'execute', id, scopes: ['hey:read', 'hey:write'], domain: 'threads', action: 'trash_topic', params: { topicId: 1 } })).toMatchObject({ ok: false, status: 403 });
    expect(fetcher).not.toHaveBeenCalled();
    unwrap(await stub.command({ type: 'revoke', id }));
    expect(await stub.activeConnection(id)).toBeNull();
    expect(await stub.command({ type: 'execute', id, scopes: ['hey:read'], domain: 'identity', action: 'get_identity', params: {} })).toMatchObject({ ok: false, status: 401 });
  });
  it('serializes parallel refreshes and persists the rotated token', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture(1) }));
    const calls: string[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith('/oauth/tokens')) {
        const body = new URLSearchParams(String(init?.body));
        expect(body.get('install_id')).toBe(fixture().install_id);
        expect(body.get('refresh_token')).toBe('synthetic-refresh');
        return Response.json({ access_token: 'rotated-access', refresh_token: 'rotated-refresh', expires_in: 3600 });
      }
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer rotated-access');
      return Response.json({ identity: { id: 1 } });
    });
    const results = await Promise.all([stub.command({ type: 'verify' }), stub.command({ type: 'verify' })]);
    expect(results.every(r => r.ok)).toBe(true);
    expect(calls.filter(url => url.endsWith('/oauth/tokens'))).toHaveLength(1);
    expect((await stub.status()).verifiedAt).not.toBeNull();
  });
  it('keeps credentials on transient errors and backs off', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture(1) }));
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json({ error: 'invalid_grant', secret: 'must-not-escape' }, { status: 503 }));
    expect(await stub.command({ type: 'verify' })).toMatchObject({ ok: false, status: 503 });
    expect(await stub.status()).toMatchObject({ configured: true, reauthRequired: false });
    expect(await stub.command({ type: 'verify' })).toMatchObject({ ok: false, status: 503 });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('marks invalid_grant as requiring reauthentication without retrying it', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture(1) }));
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json({ error: 'invalid_grant' }, { status: 400 }));
    expect(await stub.command({ type: 'verify' })).toMatchObject({ ok: false, status: 409 });
    expect(await stub.status()).toMatchObject({ configured: true, reauthRequired: true });
    expect(await stub.command({ type: 'verify' })).toMatchObject({ ok: false, status: 409 });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('does not replay writes after a 401, but refreshes for the next call', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture() }));
    const id = unwrap(await stub.command({ type: 'create', clientId: 'client', name: 'test', redirectUri: 'https://client.example/callback', scopes: ['hey:read', 'hey:write', 'hey:send'] })) as string;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => String(input).endsWith('/oauth/tokens')
      ? Response.json({ access_token: 'rotated', expires_in: 3600 }) : new Response(null, { status: 401 }));
    const result = await stub.command({ type: 'execute', id, scopes: ['hey:read', 'hey:write', 'hey:send'], domain: 'threads', action: 'create_message', params: { acting_sender_id: 1, message: { subject: 'test', content: 'test' } } });
    expect(result).toMatchObject({ ok: false, status: 502 });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it('deleting credentials revokes all connections', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture() }));
    const id = unwrap(await stub.command({ type: 'create', clientId: 'client', name: 'test', redirectUri: 'https://client.example/callback', scopes: ['hey:read'] })) as string;
    unwrap(await stub.command({ type: 'delete' }));
    expect(await stub.activeConnection(id)).toBeNull();
    expect((await stub.status()).configured).toBe(false);
  });
});
