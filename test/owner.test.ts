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
const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
};
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
  it('consumes a refresh hash once and revokes on concurrent reuse', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture() }));
    const id = unwrap(await stub.command({ type: 'create', clientId: 'client', name: 'test', redirectUri: 'https://client.example/callback', scopes: ['hey:read'] })) as string;
    const consumed = await Promise.all([stub.consumeRefreshToken(id, 'synthetic-hash', false), stub.consumeRefreshToken(id, 'synthetic-hash', false)]);
    expect(consumed.sort()).toEqual([false, true]);
    expect(await stub.activeConnection(id)).toBeNull();
    expect(await stub.consumeRefreshToken(id, 'another-synthetic-hash', false)).toBe(false);
  });
  it('revokes a connection when the provider recognizes the prior refresh token', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture() }));
    const id = unwrap(await stub.command({ type: 'create', clientId: 'client', name: 'test', redirectUri: 'https://client.example/callback', scopes: ['hey:read'] })) as string;
    expect(await stub.consumeRefreshToken(id, 'synthetic-hash', true)).toBe(false);
    expect(await stub.activeConnection(id)).toBeNull();
  });
  it('rejects another refresh immediately after a concurrent reuse revokes the connection', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture() }));
    const id = unwrap(await stub.command({ type: 'create', clientId: 'client', name: 'test', redirectUri: 'https://client.example/callback', scopes: ['hey:read'] })) as string;
    await runInDurableObject(stub, async instance => {
      const consumed = await Promise.all([
        instance.consumeRefreshToken(id, 'synthetic-hash', false),
        instance.consumeRefreshToken(id, 'synthetic-hash', false),
        instance.consumeRefreshToken(id, 'next-synthetic-hash', false),
      ]);
      expect(consumed).toEqual([true, false, false]);
      expect(await instance.activeConnection(id)).toBeNull();
    });
  });
  it('rejects older refresh hashes only for the matching authenticated client', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture() }));
    const id = unwrap(await stub.command({ type: 'create', clientId: 'client', name: 'test', redirectUri: 'https://client.example/callback', scopes: ['hey:read'] })) as string;
    expect(await stub.consumeRefreshToken(id, 'first-synthetic-hash', false)).toBe(true);
    expect(await stub.consumeRefreshToken(id, 'second-synthetic-hash', false)).toBe(true);
    expect(await stub.rejectRefreshTokenReuse('another-client', 'first-synthetic-hash')).toBe(false);
    expect(await stub.rejectRefreshTokenReuse('client', 'unknown-synthetic-hash')).toBe(false);
    expect(await stub.activeConnection(id)).not.toBeNull();
    expect(await stub.rejectRefreshTokenReuse('client', 'first-synthetic-hash')).toBe(true);
    expect(await stub.activeConnection(id)).toBeNull();
    expect(await stub.rejectRefreshTokenReuse('client', 'first-synthetic-hash')).toBe(true);
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
  it('does not send a write revoked while the HEY token is refreshing', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture(1) }));
    const scopes = ['hey:read', 'hey:write', 'hey:send'];
    const id = unwrap(await stub.command({ type: 'create', clientId: 'client', name: 'test', redirectUri: 'https://client.example/callback', scopes })) as string;
    await runInDurableObject(stub, async instance => {
      const started = deferred<void>();
      const refreshed = deferred<Response>();
      const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
        expect(String(input)).toContain('/oauth/tokens');
        started.resolve();
        return refreshed.promise;
      });
      const execution = instance.command({ type: 'execute', id, scopes, domain: 'threads', action: 'create_message',
        params: { acting_sender_id: 1, message: { subject: 'test', content: 'test' } } });
      await started.promise;
      unwrap(await instance.command({ type: 'revoke', id }));
      refreshed.resolve(Response.json({ access_token: 'rotated', expires_in: 3600 }));
      expect(await execution).toMatchObject({ ok: false, status: 401 });
      expect(fetcher).toHaveBeenCalledTimes(1);
    });
  });
  it('does not retry a read revoked during its 401 refresh', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture() }));
    const scopes = ['hey:read'];
    const id = unwrap(await stub.command({ type: 'create', clientId: 'client', name: 'test', redirectUri: 'https://client.example/callback', scopes })) as string;
    await runInDurableObject(stub, async instance => {
      const started = deferred<void>();
      const refreshed = deferred<Response>();
      const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
        if (!String(input).endsWith('/oauth/tokens')) return new Response(null, { status: 401 });
        started.resolve();
        return refreshed.promise;
      });
      const execution = instance.command({ type: 'execute', id, scopes, domain: 'identity', action: 'get_identity', params: {} });
      await started.promise;
      unwrap(await instance.command({ type: 'revoke', id }));
      refreshed.resolve(Response.json({ access_token: 'rotated', expires_in: 3600 }));
      expect(await execution).toMatchObject({ ok: false, status: 401 });
      expect(fetcher).toHaveBeenCalledTimes(2);
    });
  });
  it('limits executing and queued MCP operations to eight and releases slots', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture() }));
    const scopes = ['hey:read'];
    const id = unwrap(await stub.command({ type: 'create', clientId: 'client', name: 'test', redirectUri: 'https://client.example/callback', scopes })) as string;
    await runInDurableObject(stub, async instance => {
      const started = deferred<void>();
      const response = deferred<Response>();
      const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json({ identity: { id: 1 } }));
      fetcher.mockImplementationOnce(async () => { started.resolve(); return response.promise; });
      const command = { type: 'execute' as const, id, scopes, domain: 'identity', action: 'get_identity', params: {} };
      const execution = instance.command(command);
      await started.promise;
      const queued = Array.from({ length: 7 }, () => instance.command(command));
      expect(await instance.command(command)).toMatchObject({ ok: false, status: 429 });
      response.resolve(Response.json({ identity: { id: 1 } }));
      expect((await Promise.all([execution, ...queued])).every(result => result.ok)).toBe(true);
      expect(await instance.command(command)).toMatchObject({ ok: true });
      expect(fetcher).toHaveBeenCalledTimes(9);
    });
  });
  it('revokes all connections before waiting to delete credentials and blocks new approval', async () => {
    const stub = owner();
    unwrap(await stub.command({ type: 'import', credentials: fixture(1) }));
    const scopes = ['hey:read', 'hey:write'];
    const create = { type: 'create' as const, clientId: 'client', name: 'test', redirectUri: 'https://client.example/callback', scopes };
    const id = unwrap(await stub.command(create)) as string;
    await runInDurableObject(stub, async (instance, state) => {
      const started = deferred<void>();
      const refreshed = deferred<Response>();
      const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
        expect(String(input)).toContain('/oauth/tokens');
        started.resolve();
        return refreshed.promise;
      });
      const command = { type: 'execute' as const, id, scopes, domain: 'threads', action: 'trash_topic', params: { topicId: 1 } };
      const execution = instance.command(command);
      await started.promise;
      const queued = instance.command(command);
      const deletion = instance.command({ type: 'delete' });
      expect(await instance.activeConnection(id)).toBeNull();
      expect(await instance.command(create)).toMatchObject({ ok: false, status: 409 });
      // The revoke is persisted even though the token refresh still holds the queue.
      expect(JSON.parse(state.storage.sql.exec<{ data: string }>('SELECT data FROM connections WHERE id = ?', id).one().data).revokedAt).not.toBeNull();
      refreshed.resolve(Response.json({ access_token: 'rotated', expires_in: 3600 }));
      expect(await execution).toMatchObject({ ok: false, status: 401 });
      expect(await queued).toMatchObject({ ok: false, status: 401 });
      expect(await deletion).toMatchObject({ ok: true });
      expect(await instance.command(create)).toMatchObject({ ok: false, status: 409 });
      expect(await instance.status()).toMatchObject({ configured: false });
      expect(await state.storage.get('credentials')).toBeUndefined();
      expect(fetcher).toHaveBeenCalledTimes(1);
    });
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
