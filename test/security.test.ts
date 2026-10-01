import { describe, it, expect } from 'vitest';
import { encrypt, decrypt, secretEquals, readLimited } from '../src/security';
import { getOperation, buildRequest, requiredScopes } from '../src/catalog';
import { parseCredentials } from '../src/hey';

const key = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const credentials = { access_token: 'synthetic-access', refresh_token: 'synthetic-refresh', expires_at: 0,
  oauth_type: 'oauth', token_endpoint: 'https://app.hey.com/oauth/tokens' };
const install = '12345678-1234-4234-8234-123456789abc';

describe('credential and scope boundaries', () => {
  it('encrypts with a fresh nonce and authenticates ciphertext and key', async () => {
    const first = await encrypt(credentials, key);
    const second = await encrypt(credentials, key);
    expect(first.nonce).not.toBe(second.nonce);
    expect(JSON.stringify(first)).not.toContain('synthetic');
    expect(await decrypt(first, key)).toEqual(credentials);
    await expect(decrypt({ ...first, ciphertext: first.ciphertext.slice(0, -4) + 'AAAA' }, key)).rejects.toThrow('復号');
    await expect(decrypt(first, 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=')).rejects.toThrow('復号');
  });
  it('rejects human passwords as encryption keys', async () => {
    await expect(encrypt(credentials, 'password')).rejects.toThrow('32 bytes');
  });
  it('checks secrets without ordinary string equality', async () => {
    expect(await secretEquals('one', 'one')).toBe(true);
    expect(await secretEquals('one', 'two')).toBe(false);
    expect(await secretEquals('', 'one')).toBe(false);
  });
  it('accepts the CLI origin-indexed credential file, stripping extra fields', () => {
    const result = parseCredentials(JSON.stringify({ 'https://app.hey.com': { ...credentials, session_cookie: 'do-not-keep' } }), install + '\n');
    expect(result.credentials).toEqual(credentials);
    expect(result.install_id).toBe(install);
  });
  it('rejects a token endpoint that would exfiltrate refresh tokens', () => {
    expect(() => parseCredentials(JSON.stringify({ ...credentials, token_endpoint: 'https://attacker.example/token' }), install)).toThrow('接続先');
    expect(() => parseCredentials(JSON.stringify({ ...credentials, oauth_type: 'cookie' }), install)).toThrow();
  });
  it('limits body size even when Content-Length is absent', async () => {
    const body = new Response('too large').body;
    await expect(readLimited(body, 3)).rejects.toThrow('大きすぎ');
  });
  it('requires send permission for both immediate and scheduled deliveries', () => {
    for (const action of ['create_message', 'update_message', 'create_reply']) {
      const op = getOperation('threads', action);
      expect(requiredScopes(op, {})).toContain('hey:send');
      expect(requiredScopes(op, { entry: { status: 'drafted' } })).not.toContain('hey:send');
      expect(requiredScopes(op, { entry: { status: 'drafted', scheduled_delivery: 'true' } })).toContain('hey:send');
      expect(requiredScopes(op, { entry: { status: 'drafted', scheduled_delivery_at_hour: '0' } })).toContain('hey:send');
    }
  });
  it('rejects extra parameters rather than letting them bypass send checks', () => {
    const op = getOperation('threads', 'create_message');
    expect(() => buildRequest(op, { acting_sender_id: 1, message: { subject: 'test', content: 'test' }, 'entry[status]': 'sent' })).toThrow('入力');
  });
  it('uses cursor query parameters and the SDK account filter', () => {
    const result = buildRequest(getOperation('threads', 'get_topic_entries'), { topicId: 123, page: 'opaque+/cursor' }, 456);
    const url = new URL(result.path, 'https://app.hey.com');
    expect(url.pathname).toBe('/topics/123/entries');
    expect(url.searchParams.get('filtered_account_id')).toBe('456');
    expect(url.searchParams.get('page')).toBe('opaque+/cursor');
  });
  it('validates required fields before any network request', () => {
    expect(() => buildRequest(getOperation('threads', 'get_topic'), {})).toThrow('入力');
    expect(() => buildRequest(getOperation('threads', 'get_topic'), { topicId: '../identity' })).toThrow('入力');
  });
});
