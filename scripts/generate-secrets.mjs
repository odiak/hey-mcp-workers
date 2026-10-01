import { randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';

const production = process.argv.includes('--production');
const values = {
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  ADMIN_SECRET: randomBytes(32).toString('base64url'),
};
const path = production ? '.local/secrets-production.json' : '.dev.vars';
if (production) await mkdir('.local', { recursive: true, mode: 0o700 });
const content = production ? JSON.stringify(values, null, 2) + '\n'
  : Object.entries(values).map(([key, value]) => `${key}="${value}"`).join('\n') + '\n';
try {
  await writeFile(path, content, { mode: 0o600, flag: 'wx' });
  console.log(`Generated two independent secrets in ${path}. Values are not printed.`);
} catch (error) {
  if (error.code === 'EEXIST') {
    console.error(`${path} already exists. It has not been overwritten.`);
    process.exitCode = 1;
  } else throw error;
}
