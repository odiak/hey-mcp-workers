import { GrantType, OAuthAuthorizationServer, OAuthError } from '@cloudflare/workers-oauth-provider';
import { z } from 'zod';
import { scopes } from './catalog';
import { hash } from './security';

export const authProps = z.object({ connectionId: z.uuid() });
export type AuthProps = z.infer<typeof authProps>;

export function maskedClientIdUrl(value: string): string {
  const url = new URL(value);
  const path = url.pathname.split('/').map(segment => {
    let decoded: string;
    try { decoded = decodeURIComponent(segment); }
    catch { return '***'; }
    const masked = decoded
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '***')
      .replace(/[A-Za-z0-9_-]{24,}/g, token => {
        const random = /^[0-9a-f]+$/i.test(token)
          || (/[A-Za-z]/.test(token) && /[0-9]/.test(token))
          || (/[a-z]/.test(token) && /[A-Z]/.test(token));
        return random ? '***' : token;
      });
    return masked === decoded ? segment : encodeURIComponent(masked);
  }).join('/');
  const query = [...url.searchParams].map(([name]) => `${encodeURIComponent(name)}=***`).join('&');
  return `${url.origin}${path}${query ? `?${query}` : ''}`;
}

export function authorizationServer(env: CloudflareEnv, origin: string): OAuthAuthorizationServer<CloudflareEnv> {
  return new OAuthAuthorizationServer<CloudflareEnv>({
    issuer: origin,
    resources: [`${origin}/mcp`],
    authorizeEndpoint: '/authorize', tokenEndpoint: '/oauth/token',
    clientRegistrationEndpoint: '/oauth/register',
    clientIdMetadataDocumentEnabled: true,
    scopesSupported: [...scopes, 'offline_access'],
    accessTokenTTL: 900, refreshTokenTTL: 30 * 86400, clientRegistrationTTL: 90 * 86400,
    async clientRegistrationCallback({ request }) {
      const address = request.headers.get('CF-Connecting-IP') ?? 'local';
      if (!await env.OWNER.getByName('owner').limit(`register:${await hash(address)}`, 30, 3600)) {
        return { code: 'invalid_client_metadata', description: 'Too many registrations', status: 429 };
      }
    },
    async refreshTokenReuseCallback({ clientId, refreshTokenId, env }) {
      return env.OWNER.getByName('owner').rejectRefreshTokenReuse(clientId, refreshTokenId);
    },
    async tokenExchangeCallback({ props, env, requestedScope, clientId, grantType, refreshTokenId, refreshTokenReused }) {
      const parsed = authProps.safeParse(props);
      const connection = parsed.success ? await env.OWNER.getByName('owner').activeConnection(parsed.data.connectionId) : null;
      if (!connection || connection.clientId !== clientId) throw new OAuthError('invalid_grant', { description: 'This connection has been revoked or expired.' });
      if (requestedScope.some(s => s !== 'offline_access' && !connection.scopes.includes(s))) throw new OAuthError('invalid_scope', { description: 'Scope exceeds the approved permissions.' });
      if (grantType === GrantType.REFRESH_TOKEN) {
        // These fields come from the pinned dependency patch, after token verification.
        // Fail closed if installation skipped the patch.
        if (!refreshTokenId || typeof refreshTokenReused !== 'boolean') throw new OAuthError('temporarily_unavailable', { statusCode: 503, description: 'Refresh token verification is unavailable.' });
        if (!await env.OWNER.getByName('owner').consumeRefreshToken(connection.id, refreshTokenId, refreshTokenReused)) {
          throw new OAuthError('invalid_grant', { description: 'Refresh token reuse detected. Authorize a new connection.' });
        }
      }
    },
    // Only CIMD identifiers are logged, with query values and token-like path parts masked.
    onError({ code, status, internal }) {
      if (internal?.category === 'client-id-metadata-document' && internal.reason === 'cimd_fetch_failed' && typeof internal.detail === 'string') {
        console.warn(JSON.stringify({ event: 'oauth_cimd_fetch_failed', code, status, clientId: maskedClientIdUrl(internal.detail) }));
      } else {
        console.warn(JSON.stringify({ event: 'oauth_error', code, status }));
      }
    },
  });
}
