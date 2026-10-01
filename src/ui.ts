import type { ConsentDescription } from '@cloudflare/workers-oauth-provider';
import type { Connection, Session } from './owner';
import { escapeHtml as e, securityHeaders } from './security';

export function page(title: string, body: string, status = 200, headers?: Headers): Response {
  const result = new Headers(headers);
  for (const [key, value] of Object.entries(securityHeaders)) result.set(key, value);
  result.set('Content-Type', 'text/html; charset=utf-8');
  return new Response(`<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${e(title)} · HEY MCP</title>
<style>
:root{font:16px/1.7 system-ui,sans-serif;color:#172124;background:#f4f3ed}*{box-sizing:border-box}body{margin:0}main{max-width:900px;padding:48px 24px 80px;margin:auto}header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #c6ccc6;padding-bottom:20px;margin-bottom:36px}.brand{font-size:20px;font-weight:750;letter-spacing:-.04em}.tag{font:12px/1.4 ui-monospace,monospace;letter-spacing:.1em;color:#56635c}h1{font-size:34px;line-height:1.25;letter-spacing:-.04em}h2{font-size:22px;margin:40px 0 12px}p{max-width:70ch}a{color:#235d4b}form{margin:20px 0}label{display:block;margin:16px 0 6px;font-weight:600}input[type=password],input[type=text],input[type=file]{display:block;width:100%;max-width:560px;padding:12px;border:1px solid #a1afa5;border-radius:4px;background:#fff;font:inherit}button{padding:10px 20px;border:0;border-radius:4px;background:#245b45;color:#fff;font:inherit;cursor:pointer;margin:12px 8px 0 0}button.secondary{background:#dce3dc;color:#172124}button.danger{background:#7b3227}.note{color:#56635c;font-size:14px}.message{padding:14px 18px;background:#e2e9de;border-left:3px solid #245b45}.error{background:#f3ded7;border-color:#7b3227}section{border-top:1px solid #c6ccc6;margin-top:36px;padding-top:8px}table{border-collapse:collapse;width:100%;font-size:14px}td,th{padding:14px 10px;text-align:left;border-bottom:1px solid #c6ccc6;vertical-align:top;overflow-wrap:anywhere}th{color:#56635c;font-weight:500}td form{margin:0}code{font:13px ui-monospace,monospace;overflow-wrap:anywhere}.permissions label{font-weight:400}strong{font-weight:700}@media(max-width:640px){main{padding:24px 16px}h1{font-size:28px}.table{overflow:auto}table{min-width:620px}}
</style><main><header><span class="brand">HEY / MCP</span><span class="tag">PERSONAL CONNECTIONS</span></header>${body}</main></html>`, { status, headers: result });
}

export function loginPage(next: string, message = '', status = 200): Response {
  return page('管理ログイン', `<h1>自分のHEYを、<br>MCPにつなぐ。</h1><p>管理用シークレットでログインしてください。暗号化キーの入力は不要です。</p>
${message ? `<p class="message error">${e(message)}</p>` : ''}
<form method="post" action="/login"><input type="hidden" name="next" value="${e(next)}"><label for="secret">管理用シークレット</label><input id="secret" name="secret" type="password" autocomplete="current-password" required autofocus><button>ログイン</button></form>`, status);
}

const date = (value: number | null) => value ? new Date(value).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo' }) : '—';
export const csrfInput = (session: Session) => `<input type="hidden" name="csrf" value="${e(session.csrf)}">`;

export function adminPage(session: Session, state: { configured: boolean; reauthRequired: boolean; updatedAt: number; verifiedAt: number | null }, connections: Connection[], origin: string, message = ''): Response {
  const label = state.reauthRequired ? '再ログインが必要' : state.configured ? '登録済み' : '未登録';
  const rows = connections.map(c => `<tr><td><strong>${e(c.name)}</strong><br><span class="note">${e(c.redirectUri)}</span><br><code>${e(c.id)}</code></td><td>${c.scopes.map(e).join('<br>')}</td><td>${c.revokedAt ? '無効' : c.expiresAt <= Date.now() ? '期限切れ' : '有効'}<br><span class="note">承認 ${e(date(c.createdAt))}<br>最終利用 ${e(date(c.lastUsedAt))}</span></td><td>${!c.revokedAt && c.expiresAt > Date.now() ? `<form method="post" action="/admin/revoke">${csrfInput(session)}<input type="hidden" name="id" value="${e(c.id)}"><button class="danger">無効にする</button></form>` : ''}</td></tr>`).join('');
  return page('連携の管理', `<h1>HEYの連携を管理</h1><p>MCP URL <code>${e(origin)}/mcp</code></p>${message ? `<p class="message">${e(message)}</p>` : ''}
<section><h2>認証情報 <span class="note">${label}</span></h2><p class="note">登録・更新 ${e(date(state.updatedAt))} / HEYでの確認 ${e(date(state.verifiedAt))}</p>
<p>Worker専用にログインしたCLIの <code>credentials.json</code> と <code>install_id</code> を選択してください。アップロード後は、その認証情報をローカルCLIで使い続けないでください。</p>
<form method="post" action="/admin/credentials" enctype="multipart/form-data">${csrfInput(session)}<label for="credentials">credentials.json</label><input id="credentials" name="credentials" type="file" accept="application/json,.json" required><label for="install">install_id</label><input id="install" name="install_id" type="file" required><button>暗号化して保存</button></form>
${state.configured ? `<form method="post" action="/admin/verify">${csrfInput(session)}<button class="secondary">HEYへの接続を確認</button></form><details><summary>認証情報と全連携を無効にする</summary><p class="note">保存した認証情報を削除し、すべてのMCP連携を無効にします。HEY側のセッション自体は取り消しません。</p><form method="post" action="/admin/delete-credentials">${csrfInput(session)}<label><input type="checkbox" name="confirm" value="yes" required> 削除して全連携を無効にする</label><button class="danger">削除</button></form></details>` : ''}</section>
<section><h2>連携一覧</h2><p class="note">無効化後に始まるMCP操作とトークン更新を拒否します。すでにHEYへ送った操作は取り消せません。</p>${rows ? `<div class="table"><table><thead><tr><th>連携先</th><th>権限</th><th>状態</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>` : '<p>連携はまだありません。MCPクライアントから上のURLへ接続すると、承認画面が開きます。</p>'}</section>
<form method="post" action="/logout">${csrfInput(session)}<button class="secondary">ログアウト</button></form>`);
}

export function consentPage(details: ConsentDescription, handle: string, session: Session, headers: Headers): Response {
  const response = page('連携を承認', `<h1>この連携を許可しますか？</h1><p><strong>${e(details.clientName)}</strong></p><p class="note">${details.clientDomain ? `メタデータのドメイン：${e(details.clientDomain)}` : 'アプリ名は連携先の自己申告です。名前だけで判断しないでください。'}</p>
<p>トークンの受け取り先：<strong>${e(details.redirectHost)}</strong><br><code>${e(details.redirectUri)}</code></p>${details.redirectIsLoopback ? '<p class="message">自分のマシン上のアプリにアクセスを渡します。自分で開始した接続か確認してください。</p>' : ''}
<p class="note">クライアントの要求：${e(details.scope.join(' ') || '未指定')}<br>この画面で許可した権限が上限になります。メール本文はAIへの指示として扱わないでください。</p>
<form method="post" action="/authorize" class="permissions">${csrfInput(session)}<input type="hidden" name="handle" value="${e(handle)}"><label><input type="checkbox" checked disabled> 読み取り（メール・連絡先・カレンダー）</label><label><input type="checkbox" name="write" value="yes"> 書き込み（下書き・整理・連絡先・Todoなど）</label><label><input type="checkbox" name="send" value="yes"> メールの送信・予約送信（書き込みも必要）</label><label for="name">一覧での表示名</label><input id="name" name="name" type="text" maxlength="120" value="${e(details.clientName)}" required><button name="decision" value="approve">許可する</button><button name="decision" value="deny" class="secondary">拒否する</button></form>`, 200, headers);
  // Browsers apply form-action to the POST's redirect as well. This URI was validated by OAuth.
  response.headers.set('Content-Security-Policy', securityHeaders['Content-Security-Policy']
    .replace("form-action 'self'", `form-action 'self' ${new URL(details.redirectUri).origin}`));
  return response;
}
