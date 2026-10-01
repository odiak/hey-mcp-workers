import { z } from 'zod';
import { HttpError, readLimited } from './security';

export const heyOrigin = 'https://app.hey.com';
const tokenEndpoint = `${heyOrigin}/oauth/tokens`;
// Public OAuth client identifier used by hey-cli; not a secret.
const clientId = 'khMWSVDVSq78oyKA3KtxmYRv';
const userAgent = 'hey-mcp-workers/0.1.0';

const credentialSchema = z.object({
  access_token: z.string().min(1).max(8192),
  refresh_token: z.string().min(1).max(8192),
  expires_at: z.number().int().nonnegative(),
  oauth_type: z.literal('oauth'),
  token_endpoint: z.literal(tokenEndpoint).optional(),
});
const uploadSchema = z.object({
  credentials: credentialSchema,
  install_id: z.uuidv4(),
});
export type Credentials = z.infer<typeof uploadSchema>;

export function parseCredentials(text: string, installId: string): Credentials {
  let value: unknown;
  try { value = JSON.parse(text); }
  catch { throw new HttpError(400, 'credentials.jsonをJSONとして読み込めません。'); }
  if (value && typeof value === 'object' && heyOrigin in value) value = (value as Record<string, unknown>)[heyOrigin];
  const parsed = uploadSchema.safeParse({ credentials: value, install_id: installId.trim() });
  if (!parsed.success) throw new HttpError(400, 'HEY CLIのOAuth認証情報と、対応するinstall_idを指定してください。接続先はapp.hey.comに限定されます。');
  return parsed.data;
}

export class RefreshError extends Error {
  constructor(public refused: boolean, public retryAfter: number) { super('HEYの認証情報を更新できません。'); }
}

export async function refreshCredentials(current: Credentials): Promise<Credentials> {
  const response = await fetch(tokenEndpoint, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15_000),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': userAgent },
    body: new URLSearchParams({
      grant_type: 'refresh_token', client_id: clientId,
      refresh_token: current.credentials.refresh_token, install_id: current.install_id,
    }),
  });
  const text = new TextDecoder().decode(await readLimited(response.body, 64 * 1024));
  let payload: Record<string, unknown> = {};
  try { payload = JSON.parse(text) as Record<string, unknown>; } catch { /* No upstream body in errors. */ }
  if (!response.ok) {
    const header = response.headers.get('Retry-After') ?? '';
    const seconds = /^\d+$/.test(header) ? Number(header) : Math.ceil((Date.parse(header) - Date.now()) / 1000);
    const retryAfter = response.status === 429 ? Math.min(3600, Math.max(60, seconds || 60)) : 0;
    throw new RefreshError(response.status >= 400 && response.status < 500 && response.status !== 429 && payload.error === 'invalid_grant', retryAfter);
  }
  const result = z.object({
    access_token: z.string().min(1), refresh_token: z.string().min(1).optional(),
    expires_in: z.number().int().nonnegative().optional(),
  }).safeParse(payload);
  if (!result.success) throw new RefreshError(false, 60);
  return { ...current, credentials: {
    ...current.credentials, access_token: result.data.access_token,
    refresh_token: result.data.refresh_token ?? current.credentials.refresh_token,
    expires_at: result.data.expires_in ? Math.floor(Date.now() / 1000) + result.data.expires_in : 0,
  } };
}

export async function heyRequest(token: string, method: string, path: string, body?: Record<string, unknown>): Promise<Response> {
  // Paths are assembled solely from the checked-in catalog. Redirects are never followed.
  const url = new URL(path, heyOrigin);
  if (url.origin !== heyOrigin) throw new HttpError(400, '接続先が不正です。');
  return fetch(url, {
    method, redirect: 'error', signal: AbortSignal.timeout(20_000),
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Content-Type': 'application/json', 'User-Agent': userAgent },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export async function heyResult(response: Response): Promise<Record<string, unknown>> {
  if (!response.ok) {
    await response.body?.cancel();
    throw new HttpError(502, `HEYがHTTP ${response.status}を返しました。書き込み操作は自動再試行していません。`);
  }
  const text = new TextDecoder().decode(await readLimited(response.body, 2 * 1024 * 1024));
  let data: unknown = null;
  if (text.trim()) {
    try { data = JSON.parse(text); }
    catch { throw new HttpError(502, 'HEYがJSON以外の応答を返しました。'); }
  }
  const result: Record<string, unknown> = { status: response.status, data };
  if (response.headers.has('Location')) result.location = response.headers.get('Location');
  const link = response.headers.get('Link')?.split(',').find(part => /rel="next"/.test(part));
  let nextUrl = link?.match(/<([^>]+)>/)?.[1];
  if (!nextUrl && data && typeof data === 'object') {
    const record = data as Record<string, unknown>;
    nextUrl = typeof record.next_history_url === 'string' ? record.next_history_url : undefined;
    if (!nextUrl && Object.keys(record).length === 1) {
      const nested = Object.values(record)[0];
      if (nested && typeof nested === 'object' && 'next_history_url' in nested && typeof nested.next_history_url === 'string') nextUrl = nested.next_history_url;
    }
  }
  if (nextUrl) {
    const query = new URL(nextUrl, heyOrigin).searchParams;
    for (const key of ['page', 'since', 'v']) if (query.has(key)) result[`next_${key}`] = query.get(key);
  }
  return result;
}
