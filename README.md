# HEY MCP on Cloudflare Workers

English | [日本語](README.ja.md)

A personal, single-user server that connects your HEY account to MCP clients through OAuth. To use it, deploy your own instance to Cloudflare Workers in your Cloudflare account. Only connections approved by the owner using the admin secret can access the account.

## Architecture

- **Workers secrets**: `ENCRYPTION_KEY` (32 random bytes encoded as Base64) and a separate `ADMIN_SECRET` (at least 32 characters).
- **Owner Durable Object**: Encrypts HEY credentials and the install_id with AES-256-GCM. Also manages admin sessions, connection permissions, revocation, and HEY token refreshes.
- **Workers KV**: Cloudflare's OAuth library manages client registrations, authorization codes, and MCP tokens. HEY credentials are not stored here.
- **Streamable HTTP MCP**: `/mcp`, using MCP SDK v2 and the stateless handler from Agents.
- **Admin UI**: `/admin`, for uploading credentials, verifying connectivity, listing and revoking connections, and deleting credentials.

The admin UI does not ask for the encryption key. The server reads it from its secret and verifies that stored credentials can be decrypted. The admin and consent screens currently use Japanese.

## Run locally

Use Node.js 24 or later and npm.

```sh
npm ci
npm run setup:local
npm run dev
```

`setup:local` generates two independent random secrets in the Git-ignored `.dev.vars` file with permissions `0600`. It will not overwrite an existing file or print the values to the console. Open the file in a local editor to find `ADMIN_SECRET`, then sign in to the [admin UI](http://localhost:8787/admin).

## Prepare HEY credentials

On your own machine, log in interactively using a directory dedicated to the Worker, keeping these credentials separate from your usual CLI credentials.

```sh
XDG_CONFIG_HOME="$HOME/.config/hey-mcp-bootstrap" \
  HEY_NO_KEYRING=1 HEY_BASE_URL=https://app.hey.com hey auth login
```

Select these two files in the admin UI:

- `~/.config/hey-mcp-bootstrap/hey/credentials.json`
- `~/.config/hey-mcp-bootstrap/hey/install_id`

After saving, click **「HEYへの接続を確認」** (Verify HEY connection). A successful upload and successful HEY authentication are displayed as separate states.

Do not use this directory for regular local CLI operations after uploading. Refreshing the same token from both the CLI and the Worker causes a race. The locally generated credential files contain plaintext secrets; after uploading and verifying the connection, store them securely or delete them. Only `oauth_type: oauth` authentication is supported. Session cookies and custom HEY endpoints are not supported.

## Deploy to Cloudflare

This repository includes the author's deployment settings. To deploy your own instance, clone the repository locally, or fork it and clone your fork. Before deploying, follow the steps below to adapt the Worker name, KV namespace ID, and any custom domain settings in `wrangler.jsonc` to your own environment.

1. Check the target Cloudflare account and Worker name. The server derives its public URLs from the incoming request URL, so no public-origin variable is needed. For a custom domain, configure the corresponding `routes` in `wrangler.jsonc`.
2. Replace the `OAUTH_KV` namespace ID included in this repository with the ID of a namespace in your own account. For a new deployment, remove the existing ID so Wrangler can create a namespace in your account.
3. Generate and register separate production secrets, then deploy.

```sh
npm run setup:production
npx wrangler secret bulk .local/secrets-production.json
npm run types
npm run deploy
```

`secret bulk` makes changes and performs a deployment on Cloudflare. Local secrets in `.dev.vars` are not automatically transferred to production. Use `ADMIN_SECRET` from `.local/secrets-production.json` to sign in to the production admin UI. Keep secrets and HEY credentials out of Git, chats, and screenshots.

Back up the production encryption key securely. Losing it makes the stored credentials unreadable. To change the key, first log in to HEY again using the dedicated directory, register the new key, and upload the new credentials. There is no migration feature to re-encrypt existing ciphertext. Changing the admin secret invalidates existing admin sessions. Revoke MCP connections separately from the connection list.

## Connect an MCP client

Register `https://<your-worker-host>/mcp` in your client. Use the same host throughout authentication and subsequent MCP requests; tokens are bound to that URL. Authentication uses the OAuth authorization code flow with PKCE S256. After signing in as the admin, review the connection name, redirect destination, and permissions, and explicitly approve each connection.

| Scope | Allowed operations |
| --- | --- |
| `hey:read` | Read emails, search results, contacts, calendars, and other data. Granted by default. |
| `hey:write` | Save drafts, organize emails, and modify contacts, todos, and other data. Requires read access as well. |
| `hey:send` | Send and schedule emails. Requires write access as well. |

Access tokens last 15 minutes, and refresh tokens last 30 days. MCP refresh tokens rotate when used. Reusing a consumed refresh token revokes its connection. Simultaneous refreshes with the same token also count as reuse, so clients must serialize refreshes. If a refresh fails or its response is lost after the token was consumed, retrying with that token can also require reauthorization. Connections must be approved again after 30 days. Approving the same client again does not automatically revoke an earlier connection; you can revoke each one individually from the list.

Revocation blocks new MCP operations and MCP token issuance or refreshes. Even if old records remain in OAuth KV, the Durable Object rejects the revoked connection. Requests already sent to HEY cannot be canceled. The admin action **「認証情報と全連携を無効にする」** (Disable credentials and all connections) deletes the Worker's stored credentials and revokes all connections. It does not revoke the device session on HEY itself.

## Tools and usage

The server implements the same seven domains and 71 operations as the reference HEY CLI's MCP server.

| Tool | Coverage |
| --- | --- |
| `hey_boxes` | Imbox, Feed, Paper Trail, stacks, groups, and change listings |
| `hey_search` | Advanced search and search options |
| `hey_threads` | Topics, messages, drafts, replies, sending, and organization |
| `hey_contacts` | Contacts, notes, and the Screener |
| `hey_todos` | Create, update, complete, and delete todos. Read them through `hey_calendar`. |
| `hey_calendar` | Calendar listings and reading recordings |
| `hey_identity` | Identity information such as accounts, senders, and users |

Each tool accepts `action`, `params`, and an optional `account_id`. Use `action: "describe"` to list available operations. Add `params: { "action": "get_topic" }`, for example, to retrieve an operation's input schema. Action names are API operation IDs converted to snake_case. As in the SDK, `account_id` is passed as `filtered_account_id`; it is a presentation filter, not an account authorization boundary.

```json
{"action":"get_topic","params":{"topicId":123}}
```

Results have the shape `{status, data, location?, next_page?, next_since?, next_v?}`. Pagination uses cursors rather than numeric page numbers. Pass the returned cursor to the corresponding parameter, such as `page`. There is no tool for fetching arbitrary returned URLs.

Writes are not automatically retried. On a 401 response, the server refreshes the HEY credentials but does not resend the write; it asks you to check the outcome before trying again. Reads are retried once after a refresh. Network failures and 429/5xx responses do not discard credentials. A 4xx `invalid_grant` response from the refresh endpoint requires a new login.

Saving or updating a message without `hey:send` is allowed only when `entry.status: "drafted"` is set and no scheduling fields are present. `UpdateMessage` replaces fields rather than patching them: read the current draft first, and deliberately specify its subject, body, recipients, and schedule. This server exposes API operations rather than running the CLI's high-level commands. Features outside the CLI's MCP domains, such as event editing, habits, and journal entries, are not supported.

## Security scope

- AES-GCM protects against disclosure of stored data alone. An attacker with Worker execution or deployment access may still be able to decrypt it.
- Admin sessions use random tokens, with only their SHA-256 hashes stored. Cookies use Secure/HttpOnly/SameSite=Strict and expire after one hour. State-changing requests validate both Origin and a CSRF token.
- Admin login is limited to 10 attempts per IP per 10 minutes. Dynamic client registration is limited to 30 registrations per hour. MCP operations are limited to eight running or queued requests across all connections; excess requests receive 429. Disabling all connections revokes them before queued operations finish. The public DCR endpoint only registers clients; accessing HEY requires the owner's approval.
- OAuth client metadata is treated as untrusted and HTML-escaped. External logos and scripts are not loaded. Consent uses a one-time handle bound to the browser.
- HEY API and refresh endpoints are fixed. Credentials are never sent to arbitrary uploaded URLs or API redirect destinations.
- Read-only permissions are checked when listing tools, executing MCP operations, and executing operations inside the Durable Object. Email content is external data and must not be trusted as instructions to an AI.
- Application logs record event names, HTTP status codes, and similar metadata. CIMD fetch failures retain the domain and ordinary path, replacing query values, UUIDs, and long random-looking path strings with `***`. Path masking is heuristic. Email content, raw client metadata or request URLs, and upstream error details are not logged. Cloudflare logs and traces redact query strings, and invocation logs are disabled.

## Development and verification

```sh
npm run types
npm run check
npm test
npm run build
```

Tests run in Cloudflare's Workers runtime without real HEY credentials. They cover encryption, input validation, permissions, CSRF, PKCE, OAuth code exchange, refresh and revocation, and HEY refresh races and error handling. `build` is a dry run, not a production deployment.

The OAuth library is pinned to 1.2.1. The security patch in `patches/` is applied by the postinstall script during `npm install` / `npm ci`. Do not disable installation scripts. See [patches/README.md](patches/README.md) for the patch details and upgrade requirements.

To update the API model, specify a HEY CLI checkout:

```sh
npm run sync:model -- /path/to/basecamp/hey-cli
```

The source commit, SDK snapshot, and operation count are recorded in `src/model/provenance.json`. After updating the model, review changes to input schemas and the classification of operations that can send email.

## References and licenses

This project is licensed under the [MIT License](LICENSE). Copyright (c) 2026 Kaido Iwamoto.

HEY authentication, install_id, token refreshes, and MCP domains are based on [basecamp/hey-cli](https://github.com/basecamp/hey-cli). The API model is derived from the [basecamp/hey-sdk](https://github.com/basecamp/hey-sdk) snapshot included in the CLI. Upstream MIT licenses are included in `licenses/`. This project is not an official HEY hosted service.

OAuth is implemented with [workers-oauth-provider](https://github.com/cloudflare/workers-oauth-provider), and MCP transport uses the [Cloudflare Agents handler](https://developers.cloudflare.com/agents/model-context-protocol/apis/handler-api/).
