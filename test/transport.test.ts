import { afterEach, expect, it, vi } from 'vitest';
import { heyRequest, heyResult, refreshCredentials, type Credentials } from '../src/hey';

const credentials: Credentials = {
  credentials: { access_token: 'synthetic-access', refresh_token: 'synthetic-refresh', expires_at: 0, oauth_type: 'oauth' },
  install_id: '12345678-1234-4234-8234-123456789abc',
};

afterEach(() => vi.restoreAllMocks());

it('constructs HEY API and refresh requests with Workers runtime options', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const request = new Request(input, init);
    expect(request.redirect).toBe('manual');
    return request.url.endsWith('/oauth/tokens')
      ? Response.json({ access_token: 'rotated', expires_in: 3600 })
      : Response.json({ identity: { id: 1 } });
  });
  await heyRequest('synthetic-access', 'GET', '/identity');
  await refreshCredentials(credentials);
});

it('rejects redirected API responses without forwarding authorization', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const request = new Request(input, init);
    expect(request.url).toBe('https://app.hey.com/identity');
    expect(request.redirect).toBe('manual');
    return new Response(null, { status: 302, headers: { Location: 'https://attacker.example/collect' } });
  });
  await expect(heyResult(await heyRequest('synthetic-access', 'GET', '/identity'))).rejects.toThrow('HTTP 302');
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('rejects redirected refresh responses without forwarding the refresh token', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const request = new Request(input, init);
    expect(request.url).toBe('https://app.hey.com/oauth/tokens');
    expect(request.redirect).toBe('manual');
    return Response.json({ error: 'invalid_grant' }, { status: 307, headers: { Location: 'https://attacker.example/collect' } });
  });
  await expect(refreshCredentials(credentials)).rejects.toMatchObject({ refused: false });
  expect(fetcher).toHaveBeenCalledTimes(1);
});
