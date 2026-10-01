import { AuthorizationError } from '@cloudflare/workers-oauth-provider';
import { z } from 'zod';
import { authorizationServer } from './oauth';
import { resourceServer } from './mcp';
import { parseCredentials } from './hey';
import { unwrap } from './owner';
import { adminCookie, cookie, escapeHtml, HttpError, readLimited, sameOrigin, secretEquals, securityHeaders, setAdminCookie } from './security';
import { adminPage, consentPage, loginPage, page } from './ui';
export { Owner } from './owner';

function redirect(location: string, headers?: Headers): Response {
  const result = new Headers(headers);
  result.set('Location', location);
  return new Response(null, { status: 303, headers: result });
}

function nextPath(value: string | File | null): string {
  if (typeof value !== 'string') return '/admin';
  let url: URL;
  try { url = new URL(value, 'https://local.invalid'); }
  catch { return '/admin'; }
  return url.origin === 'https://local.invalid' && ['/admin', '/authorize'].includes(url.pathname)
    ? `${url.pathname}${url.search}` : '/admin';
}

async function form(request: Request): Promise<FormData> {
  try { return await request.formData(); }
  catch { throw new HttpError(400, 'フォームを読み込めません。'); }
}

async function handle(request: Request, env: CloudflareEnv, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const origin = url.origin;
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) throw new HttpError(400, 'HTTPSでアクセスしてください。HTTPはローカル開発でのみ利用できます。');
  if (!env.ADMIN_SECRET || env.ADMIN_SECRET.length < 32 || !env.ENCRYPTION_KEY) throw new HttpError(503, '2つのWorkers secretsを設定してください。管理用シークレットは32文字以上必要です。');
  if (request.method === 'POST') {
    const max = url.pathname === '/mcp' ? 1024 * 1024 : 64 * 1024;
    const body = await readLimited(request.body, max);
    request = new Request(request, { body });
  }
  const owner = env.OWNER.getByName('owner');
  const oauth = authorizationServer(env, origin).getOAuthApi(env);

  if (url.pathname === '/mcp' || url.pathname.startsWith('/.well-known/oauth-protected-resource')) return resourceServer(env, origin).fetch(request, env, ctx);
  if (url.pathname.startsWith('/.well-known/') || url.pathname.startsWith('/oauth/')) return authorizationServer(env, origin).fetch(request, env, ctx);
  if (url.pathname === '/') return redirect('/admin');
  if (!['/login', '/logout', '/admin', '/authorize'].includes(url.pathname) && !url.pathname.startsWith('/admin/')) throw new HttpError(404, 'ページが見つかりません。');
  if (!['GET', 'POST'].includes(request.method)) throw new HttpError(405, 'このHTTPメソッドは使えません。');
  if (request.method === 'POST') sameOrigin(request, origin);

  if (url.pathname === '/login') {
    if (request.method === 'GET') return loginPage(nextPath(url.searchParams.get('next')));
    const body = await form(request);
    const result = unwrap(await owner.command({ type: 'login', secret: String(body.get('secret') ?? ''), address: request.headers.get('CF-Connecting-IP') ?? 'local' }));
    if (!result) return loginPage(nextPath(body.get('next')), '管理用シークレットが違います。', 401);
    const session = z.object({ token: z.string(), csrf: z.string() }).parse(result);
    return redirect(nextPath(body.get('next')), new Headers({ 'Set-Cookie': setAdminCookie(session.token, 3600) }));
  }

  const token = cookie(request, adminCookie);
  const session = await owner.session(token);
  if (!session) {
    if (request.method === 'POST') throw new HttpError(401, 'ログインし直してください。');
    return loginPage(`${url.pathname}${url.search}`);
  }
  if (request.method === 'GET') {
    if (url.pathname === '/admin') return adminPage(session, await owner.status(), await owner.connections(), origin);
    if (url.pathname === '/authorize') {
      const parsed = await oauth.parseAuthRequest(request);
      if (!parsed.codeChallenge || parsed.codeChallengeMethod !== 'S256') throw new HttpError(400, 'PKCE S256が必要です。');
      const description = await oauth.describeConsent(parsed);
      const consent = await oauth.beginConsent(parsed);
      return consentPage(description, consent.handle, session, consent.headers);
    }
    throw new HttpError(405, 'この操作はフォームから実行してください。');
  }

  const body = await form(request);
  if (!await secretEquals(String(body.get('csrf') ?? ''), session.csrf)) throw new HttpError(403, '画面の有効期限を確認してください。');
  if (url.pathname === '/logout') {
    unwrap(await owner.command({ type: 'logout', token }));
    return redirect('/login', new Headers({ 'Set-Cookie': setAdminCookie('', 0) }));
  }
  if (url.pathname === '/authorize') {
    const handle = String(body.get('handle') ?? '');
    if (body.get('decision') === 'deny') {
      const result = await oauth.denyConsent(request, handle);
      return redirect(result.redirectTo, result.headers);
    }
    if (body.get('decision') !== 'approve') throw new HttpError(400, '承認または拒否を選んでください。');
    const approved = ['hey:read'];
    if (body.get('write') === 'yes') approved.push('hey:write');
    if (body.get('send') === 'yes') {
      if (!approved.includes('hey:write')) throw new HttpError(400, '送信を許可するには書き込みも選択してください。');
      approved.push('hey:send');
    }
    const consent = await oauth.approveConsent(request, handle, { scope: [...approved, 'offline_access'] });
    const name = z.string().trim().min(1).max(120).parse(body.get('name'));
    const connectionId = z.string().parse(unwrap(await owner.command({ type: 'create', clientId: consent.request.clientId,
      name, redirectUri: consent.request.redirectUri, scopes: approved })));
    try {
      const result = await oauth.completeAuthorization({ request: consent.request, userId: 'owner',
        scope: [...approved, 'offline_access'], metadata: { connectionId, name }, props: { connectionId }, revokeExistingGrants: false });
      return redirect(result.redirectTo, consent.headers);
    } catch (error) {
      unwrap(await owner.command({ type: 'revoke', id: connectionId }));
      throw error;
    }
  }

  let message: string;
  switch (url.pathname) {
    case '/admin/credentials': {
      const file = body.get('credentials');
      const install = body.get('install_id');
      if (!(file instanceof File) || !(install instanceof File)) throw new HttpError(400, '2つのファイルを選択してください。');
      const credentials = parseCredentials(await file.text(), await install.text());
      unwrap(await owner.command({ type: 'import', credentials }));
      message = '認証情報を暗号化して保存しました。HEYへの接続は確認ボタンで検証できます。';
      break;
    }
    case '/admin/verify':
      unwrap(await owner.command({ type: 'verify' }));
      message = 'HEYへの接続を確認しました。'; break;
    case '/admin/revoke':
      unwrap(await owner.command({ type: 'revoke', id: String(body.get('id') ?? '') }));
      message = '連携を無効にしました。access tokenとrefresh tokenの両方で新しい利用を拒否します。'; break;
    case '/admin/delete-credentials':
      if (body.get('confirm') !== 'yes') throw new HttpError(400, '削除の確認にチェックしてください。');
      unwrap(await owner.command({ type: 'delete' }));
      message = '認証情報を削除し、すべての連携を無効にしました。'; break;
    default: throw new HttpError(404, 'ページが見つかりません。');
  }
  // Render directly: the message is not put in a URL or a cookie.
  return adminPage(session, await owner.status(), await owner.connections(), origin, message);
}

export default {
  async fetch(request, env, ctx) {
    let response: Response;
    try { response = await handle(request, env, ctx); }
    catch (error) {
      if (error instanceof AuthorizationError) {
        response = error.redirectTo ? redirect(error.redirectTo) : page('承認できません', `<h1>承認できません</h1><p>${escapeHtml(error.description)}</p>`, 400);
      } else if (error instanceof HttpError) {
        response = page('操作できません', `<h1>操作できません</h1><p>${escapeHtml(error.message)}</p><p><a href="/admin">管理画面へ</a></p>`, error.status);
      } else if (error instanceof z.ZodError) {
        response = page('入力を確認', '<h1>入力を確認してください</h1><p><a href="/admin">管理画面へ</a></p>', 400);
      } else {
        console.error(JSON.stringify({ event: 'request_failed', method: request.method }));
        response = page('処理できません', '<h1>処理できません</h1><p>しばらくして再試行してください。</p>', 503);
      }
    }
    const secured = new Response(response.body, response);
    for (const [key, value] of Object.entries(securityHeaders)) {
      if (key === 'Content-Security-Policy' && secured.headers.has(key)) continue;
      secured.headers.set(key, value);
    }
    if (new URL(request.url).protocol === 'https:') secured.headers.set('Strict-Transport-Security', 'max-age=31536000');
    return secured;
  },
} satisfies ExportedHandler<CloudflareEnv>;
