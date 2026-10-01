import { OAuthAuthorizationServer, OAuthError } from '@cloudflare/workers-oauth-provider';
import { z } from 'zod';
import { scopes } from './catalog';
import { hash } from './security';

export const authProps = z.object({ connectionId: z.uuid() });
export type AuthProps = z.infer<typeof authProps>;

export function authorizationServer(env: CloudflareEnv): OAuthAuthorizationServer<CloudflareEnv> {
  return new OAuthAuthorizationServer<CloudflareEnv>({
    issuer: env.PUBLIC_ORIGIN,
    resources: [`${env.PUBLIC_ORIGIN}/mcp`],
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
    async tokenExchangeCallback({ props, env, requestedScope, clientId }) {
      const parsed = authProps.safeParse(props);
      const connection = parsed.success ? await env.OWNER.getByName('owner').activeConnection(parsed.data.connectionId) : null;
      if (!connection || connection.clientId !== clientId) throw new OAuthError('invalid_grant', { description: 'This connection has been revoked or expired.' });
      if (requestedScope.some(s => s !== 'offline_access' && !connection.scopes.includes(s))) throw new OAuthError('invalid_scope', { description: 'Scope exceeds the approved permissions.' });
    },
    // Never log request URLs, props, token bodies, or upstream errors.
    onError({ code, status }) { console.warn(JSON.stringify({ event: 'oauth_error', code, status })); },
  });
}
