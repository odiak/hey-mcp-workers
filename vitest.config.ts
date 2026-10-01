import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [cloudflareTest({
    wrangler: { configPath: './wrangler.jsonc' },
    miniflare: { bindings: {
      PUBLIC_ORIGIN: 'https://hey-mcp.example',
      // Synthetic, public test fixtures. Never used for a deployment.
      ENCRYPTION_KEY: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      ADMIN_SECRET: 'test-only-admin-secret-not-for-deployment',
    } },
  })],
  test: { include: ['test/**/*.test.ts'] },
});
