import { DurableObject } from 'cloudflare:workers';
import { buildRequest, getOperation, requiredScopes, scopes } from './catalog';
import { type Credentials, heyRequest, heyResult, RefreshError, refreshCredentials } from './hey';
import { decrypt, encrypt, type Envelope, hash, HttpError, randomToken, secretEquals } from './security';

export type Connection = {
  id: string; clientId: string; name: string; redirectUri: string; scopes: string[];
  createdAt: number; expiresAt: number; revokedAt: number | null; lastUsedAt: number | null;
};
export type Session = { csrf: string };
type CredentialState = { configured: boolean; reauthRequired: boolean; updatedAt: number; verifiedAt: number | null; refreshAfter: number };
export type Command =
  | { type: 'login'; secret: string; address: string }
  | { type: 'logout'; token: string }
  | { type: 'import'; credentials: Credentials }
  | { type: 'delete' }
  | { type: 'verify' }
  | { type: 'create'; clientId: string; name: string; redirectUri: string; scopes: string[] }
  | { type: 'revoke'; id: string }
  | { type: 'execute'; id: string; scopes: string[]; domain: string; action: string; params: Record<string, unknown>; accountId?: number };
export type Outcome = { ok: true; value: unknown } | { ok: false; status: number; message: string };

export function unwrap(result: Outcome): unknown {
  if (!result.ok) throw new HttpError(result.status, result.message);
  return result.value;
}

export class Owner extends DurableObject<CloudflareEnv> {
  private tail: Promise<unknown> = Promise.resolve();
  private pendingExecutions = 0;
  private deletingCredentials = false;

  constructor(ctx: DurableObjectState, env: CloudflareEnv) {
    super(ctx, env);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS connections (id TEXT PRIMARY KEY, data TEXT NOT NULL)`);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL, secret_hash TEXT NOT NULL)`);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, resets INTEGER NOT NULL)`);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS refresh_tokens (token_hash TEXT PRIMARY KEY, connection_id TEXT NOT NULL, expires INTEGER NOT NULL)`);
  }

  private serial<T>(work: () => Promise<T>): Promise<T> {
    const result = this.tail.then(work);
    this.tail = result.catch(() => undefined);
    return result;
  }

  // RPC does not preserve custom Error properties. Return expected failures explicitly.
  async command(command: Command): Promise<Outcome> {
    try {
      let value: unknown;
      switch (command.type) {
        case 'login': value = await this.login(command.secret, command.address); break;
        case 'logout': value = await this.logout(command.token); break;
        case 'import': value = await this.importCredentials(command.credentials); break;
        case 'delete': value = await this.deleteCredentials(); break;
        case 'verify': value = await this.verifyCredentials(); break;
        case 'create': value = await this.createConnection(command.clientId, command.name, command.redirectUri, command.scopes); break;
        case 'revoke': value = await this.revokeConnection(command.id); break;
        case 'execute': value = await this.execute(command.id, command.scopes, command.domain, command.action, command.params, command.accountId); break;
      }
      return { ok: true, value: value ?? null };
    } catch (error) {
      if (error instanceof HttpError) return { ok: false, status: error.status, message: error.message };
      console.error(JSON.stringify({ event: 'owner_command_failed', operation: command.type }));
      return { ok: false, status: 503, message: '処理に失敗しました。しばらくして再試行してください。' };
    }
  }

  async limit(key: string, maximum: number, windowSeconds: number): Promise<boolean> {
    const now = Math.floor(Date.now() / 1000);
    this.ctx.storage.sql.exec('DELETE FROM rate_limits WHERE resets <= ?', now);
    this.ctx.storage.sql.exec(`INSERT INTO rate_limits (key, count, resets) VALUES (?, 1, ?)
      ON CONFLICT(key) DO UPDATE SET count = count + 1`, key, now + windowSeconds);
    return this.ctx.storage.sql.exec<{ count: number }>('SELECT count FROM rate_limits WHERE key = ?', key).one().count <= maximum;
  }

  async login(provided: string, address: string): Promise<{ token: string; csrf: string } | null> {
    if (!await this.limit(`login:${await hash(address)}`, 10, 600)) throw new HttpError(429, 'ログイン試行が多すぎます。10分後に再試行してください。');
    if (!await secretEquals(provided, this.env.ADMIN_SECRET)) return null;
    const token = randomToken();
    const csrf = randomToken();
    const now = Math.floor(Date.now() / 1000);
    const [tokenHash, secretHash] = await Promise.all([hash(token), hash(this.env.ADMIN_SECRET)]);
    this.ctx.storage.sql.exec('DELETE FROM sessions WHERE expires <= ?', now);
    this.ctx.storage.sql.exec('INSERT INTO sessions VALUES (?, ?, ?, ?)', tokenHash, csrf, now + 3600, secretHash);
    return { token, csrf };
  }

  async session(token: string): Promise<Session | null> {
    if (!token) return null;
    const row = this.ctx.storage.sql.exec<{ csrf: string; expires: number; secret_hash: string }>(
      'SELECT csrf, expires, secret_hash FROM sessions WHERE hash = ?', await hash(token),
    ).toArray()[0];
    if (!row || row.expires <= Date.now() / 1000 || row.secret_hash !== await hash(this.env.ADMIN_SECRET)) return null;
    return { csrf: row.csrf };
  }

  async logout(token: string): Promise<void> {
    this.ctx.storage.sql.exec('DELETE FROM sessions WHERE hash = ?', await hash(token));
  }

  async status(): Promise<CredentialState> {
    return await this.ctx.storage.get<CredentialState>('credential-state') ?? {
      configured: false, reauthRequired: false, updatedAt: 0, verifiedAt: null, refreshAfter: 0,
    };
  }

  async importCredentials(value: Credentials): Promise<void> {
    return this.serial(async () => {
      const envelope = await encrypt(value, this.env.ENCRYPTION_KEY);
      await decrypt<Credentials>(envelope, this.env.ENCRYPTION_KEY);
      await this.ctx.storage.put({ credentials: envelope, 'credential-state': {
        configured: true, reauthRequired: false, updatedAt: Date.now(), verifiedAt: null, refreshAfter: 0,
      } satisfies CredentialState });
    });
  }

  async deleteCredentials(): Promise<void> {
    if (this.deletingCredentials) throw new HttpError(409, '認証情報を削除しています。');
    this.deletingCredentials = true;
    try {
      const rows = await this.connections();
      for (const row of rows) this.writeConnection({ ...row, revokedAt: row.revokedAt ?? Date.now() });
      await this.serial(async () => {
        await this.ctx.storage.delete(['credentials', 'credential-state']);
      });
    } finally {
      this.deletingCredentials = false;
    }
  }

  async connections(): Promise<Connection[]> {
    return this.ctx.storage.sql.exec<{ data: string }>('SELECT data FROM connections ORDER BY rowid DESC')
      .toArray().map(row => JSON.parse(row.data) as Connection);
  }

  private writeConnection(value: Connection): void {
    this.ctx.storage.sql.exec('INSERT OR REPLACE INTO connections (id, data) VALUES (?, ?)', value.id, JSON.stringify(value));
  }

  async createConnection(clientId: string, name: string, redirectUri: string, approved: string[]): Promise<string> {
    if (!approved.includes('hey:read') || approved.some(s => !scopes.includes(s)) || (approved.includes('hey:send') && !approved.includes('hey:write'))) throw new HttpError(400, '権限の組み合わせが不正です。');
    const state = await this.status();
    if (this.deletingCredentials || !state.configured || state.reauthRequired) throw new HttpError(409, '先にHEYの認証情報を登録してください。');
    const id = crypto.randomUUID();
    this.writeConnection({ id, clientId, name, redirectUri, scopes: approved, createdAt: Date.now(),
      expiresAt: Date.now() + 30 * 86400_000, revokedAt: null, lastUsedAt: null });
    return id;
  }

  async activeConnection(id: string): Promise<Connection | null> {
    return this.getActiveConnection(id);
  }

  private getActiveConnection(id: string): Connection | null {
    if (this.deletingCredentials) return null;
    const row = this.ctx.storage.sql.exec<{ data: string }>('SELECT data FROM connections WHERE id = ?', id).toArray()[0];
    if (!row) return null;
    const value = JSON.parse(row.data) as Connection;
    return value.revokedAt || value.expiresAt <= Date.now() ? null : value;
  }

  async revokeConnection(id: string): Promise<void> {
    const row = this.ctx.storage.sql.exec<{ data: string }>('SELECT data FROM connections WHERE id = ?', id).toArray()[0];
    if (!row) throw new HttpError(404, '連携が見つかりません。');
    this.writeConnection({ ...JSON.parse(row.data) as Connection, revokedAt: Date.now() });
  }

  async consumeRefreshToken(id: string, tokenHash: string, reused: boolean): Promise<boolean> {
    const connection = this.getActiveConnection(id);
    if (!connection) return false;
    const now = Date.now();
    this.ctx.storage.sql.exec('DELETE FROM refresh_tokens WHERE expires <= ?', now);
    const used = this.ctx.storage.sql.exec('SELECT token_hash FROM refresh_tokens WHERE token_hash = ?', tokenHash).toArray().length > 0;
    if (reused || used) {
      this.writeConnection({ ...connection, revokedAt: now });
      return false;
    }
    this.ctx.storage.sql.exec('INSERT INTO refresh_tokens VALUES (?, ?, ?)', tokenHash, id, connection.expiresAt);
    return true;
  }

  async rejectRefreshTokenReuse(clientId: string, tokenHash: string): Promise<boolean> {
    const row = this.ctx.storage.sql.exec<{ data: string }>(
      'SELECT connections.data FROM refresh_tokens JOIN connections ON connections.id = refresh_tokens.connection_id WHERE token_hash = ?', tokenHash,
    ).toArray()[0];
    if (!row) return false;
    const connection = JSON.parse(row.data) as Connection;
    if (connection.clientId !== clientId) return false;
    this.writeConnection({ ...connection, revokedAt: connection.revokedAt ?? Date.now() });
    return true;
  }

  private async credentials(): Promise<Credentials> {
    const state = await this.status();
    if (state.reauthRequired) throw new HttpError(409, 'HEYのセッションが無効です。専用ディレクトリでログインし直してアップロードしてください。');
    const envelope = await this.ctx.storage.get<Envelope>('credentials');
    if (!envelope) throw new HttpError(409, 'HEYの認証情報が未登録です。');
    return decrypt<Credentials>(envelope, this.env.ENCRYPTION_KEY);
  }

  private async refresh(value: Credentials): Promise<Credentials> {
    const state = await this.status();
    if (state.refreshAfter > Date.now()) throw new HttpError(503, 'HEYのトークン更新は待機中です。しばらくして再試行してください。');
    try {
      const updated = await refreshCredentials(value);
      await this.ctx.storage.put({ credentials: await encrypt(updated, this.env.ENCRYPTION_KEY), 'credential-state': {
        ...state, updatedAt: Date.now(), refreshAfter: 0,
      } });
      return updated;
    } catch (error) {
      if (error instanceof RefreshError) {
        await this.ctx.storage.put('credential-state', { ...state,
          reauthRequired: error.refused, refreshAfter: Date.now() + Math.max(60, error.retryAfter) * 1000,
        });
        throw new HttpError(error.refused ? 409 : 503, error.refused
          ? 'HEYがrefresh tokenを拒否しました。ログインし直して認証情報をアップロードしてください。'
          : 'HEYのトークン更新に失敗しました。認証情報は保持しています。しばらくして再試行してください。');
      }
      await this.ctx.storage.put('credential-state', { ...state, refreshAfter: Date.now() + 60_000 });
      throw new HttpError(503, 'HEYのトークン更新に失敗しました。認証情報は保持しています。');
    }
  }

  private async call(domain: string, action: string, params: Record<string, unknown>, accountId?: number, connectionId?: string) {
    const op = getOperation(domain, action);
    const { path, body } = buildRequest(op, params, accountId);
    let value = await this.credentials();
    if (value.credentials.expires_at > 0 && value.credentials.expires_at <= Date.now() / 1000 + 60) value = await this.refresh(value);
    const request = async () => {
      if (connectionId !== undefined && !this.getActiveConnection(connectionId)) throw new HttpError(401, 'この連携は無効です。');
      try { return await heyRequest(value.credentials.access_token, op.method, path, body); }
      catch { throw new HttpError(502, 'HEYへの通信に失敗しました。書き込みの成否を確認してから再実行してください。'); }
    };
    let response = await request();
    if (response.status === 401) {
      await response.body?.cancel();
      value = await this.refresh(value);
      if (!op.readonly) throw new HttpError(502, 'HEYの認証情報を更新しました。書き込みは再送していません。成否を確認してから再実行してください。');
      response = await request();
    }
    return heyResult(response);
  }

  async verifyCredentials(): Promise<Record<string, unknown>> {
    return this.serial(async () => {
      await this.call('identity', 'get_identity', {});
      const state = await this.status();
      await this.ctx.storage.put('credential-state', { ...state, verifiedAt: Date.now() });
      return { verified: true };
    });
  }

  async execute(id: string, tokenScopes: string[], domain: string, action: string, params: Record<string, unknown>, accountId?: number): Promise<Record<string, unknown>> {
    if (this.pendingExecutions >= 8) throw new HttpError(429, '操作が混み合っています。しばらくして再試行してください。');
    this.pendingExecutions++;
    try {
      return await this.serial(async () => {
        const connection = await this.activeConnection(id);
        if (!connection) throw new HttpError(401, 'この連携は無効です。');
        const required = requiredScopes(getOperation(domain, action), params);
        if (!required.every(s => connection.scopes.includes(s) && tokenScopes.includes(s))) throw new HttpError(403, 'この操作の権限がありません。送信・予約送信にはhey:sendが必要です。');
        const result = await this.call(domain, action, params, accountId, id);
        // Revocation may have happened while the upstream request was in flight.
        const latest = await this.activeConnection(id);
        if (latest) this.writeConnection({ ...latest, lastUsedAt: Date.now() });
        return result;
      });
    } finally {
      this.pendingExecutions--;
    }
  }
}
