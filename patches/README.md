# OAuth provider security patch

`@cloudflare/workers-oauth-provider` is pinned to 1.2.1. `patch-package` applies
the patch during `npm install` or `npm ci` and fails installation if it cannot
apply it. Do not use `--ignore-scripts` when preparing a build.

The patch makes two small changes to the provider:

- Refresh-token callbacks expose a verified token hash and whether it is the
  previous token. A separate hook checks consumed hashes after client
  authentication, before the provider rejects tokens older than its previous
  token slot. Owner stores consumed hashes in SQLite and atomically rejects
  reuse by revoking the connection, including simultaneous refreshes. No raw
  refresh tokens are passed to Owner. If the verification fields are missing,
  the application refuses to refresh.
- CIMD fetch failures go through the application's `onError` hook, which logs a
  structured event and a masked client URL. The domain and ordinary path remain
  readable. All query values and UUIDs in the path are replaced with `***`.
  Path strings of 24 or more ASCII letters, digits, underscores, or hyphens are
  also masked if they are hexadecimal, mix letters and digits, or mix upper and
  lower case. Percent-encoded path parts are decoded for matching. This is a
  heuristic, not a guarantee that arbitrary secrets in a path will be detected.
  Upstream error details are not passed to the logger.

Keep the patch when upgrading the provider until equivalent upstream fixes are
available. Run the OAuth and Owner tests, including old-token replay,
simultaneous refresh, invalid-token handling, and CIMD log masking.
