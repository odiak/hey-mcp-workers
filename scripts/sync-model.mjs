import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

// Only public API definitions are read; never inspect the CLI's config directory.
const repo = resolve(process.argv[2] ?? '../hey-cli');
const model = `${repo}/internal/mcpserver/model`;
const api = JSON.parse(await readFile(`${model}/openapi.json`, 'utf8'));
const behavior = JSON.parse(await readFile(`${model}/behavior-model.json`, 'utf8'));
const domains = {
  boxes: ['Boxes'], search: ['Search'], threads: ['Topics', 'Entries', 'Messages'],
  contacts: ['Contacts'], todos: ['Calendar Todos'], calendar: ['Calendars'], identity: ['Identity'],
};
function schema(value) {
  if (Array.isArray(value)) return value.map(schema);
  if (!value || typeof value !== 'object') return value;
  if (value.$ref) {
    const name = value.$ref.replace('#/components/schemas/', '');
    if (!(name in api.components.schemas)) throw new Error(`Missing schema ${name}`);
    return schema(api.components.schemas[name]);
  }
  const result = Object.fromEntries(Object.entries(value)
    .filter(([key]) => !key.startsWith('x-') && key !== 'format')
    .map(([key, child]) => [key, schema(child)]));
  if (result.type === 'object' && result.properties && result.additionalProperties === undefined) result.additionalProperties = false;
  return result;
}
const operations = [];
for (const [path, methods] of Object.entries(api.paths)) {
  for (const [method, op] of Object.entries(methods)) {
    if (!op.operationId) continue;
    const domain = Object.keys(domains).find(d => op.tags.some(t => domains[d].includes(t)));
    if (!domain) continue;
    const action = op.operationId.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
    const body = op.requestBody?.content?.['application/json']?.schema;
    const params = op.parameters ?? [];
    const input = body ? schema(body) : { type: 'object', properties: {} };
    input.additionalProperties = false;
    for (const param of params) input.properties[param.name] = schema(param.schema);
    input.required = [...new Set([...(input.required ?? []), ...params.filter(p => p.required).map(p => p.name)])];
    if (!(op.operationId in behavior.operations)) throw new Error(`Missing behavior ${op.operationId}`);
    operations.push({ domain, action, id: op.operationId, method: method.toUpperCase(), path,
      description: op.description, readonly: behavior.operations[op.operationId].readonly === true,
      params: params.map(p => ({ name: p.name, in: p.in })), hasBody: Boolean(body), input });
  }
}
await mkdir('src/model', { recursive: true });
await writeFile('src/model/operations.json', JSON.stringify(operations, null, 2) + '\n');
await writeFile('src/model/provenance.json', JSON.stringify({
  cli: 'https://github.com/basecamp/hey-cli',
  cliCommit: execFileSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
  upstream: JSON.parse(await readFile(`${model}/PROVENANCE.json`, 'utf8')),
  generatedBy: 'scripts/sync-model.mjs', domains, operations: operations.length,
}, null, 2) + '\n');
await mkdir('licenses', { recursive: true });
await writeFile('licenses/hey-cli-MIT.txt', await readFile(`${repo}/LICENSE.md`));
console.log(`Generated ${operations.length} operations in ${Object.keys(domains).length} domains.`);
