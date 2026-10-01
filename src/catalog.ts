import { Validator, type Schema } from '@cfworker/json-schema';
import catalog from './model/operations.json';
import { HttpError } from './security';

export const scopes = ['hey:read', 'hey:write', 'hey:send'];
export const domains = ['boxes', 'search', 'threads', 'contacts', 'todos', 'calendar', 'identity'];
export type Operation = typeof catalog[number];
export const operations: Operation[] = catalog;
const messageOperations = new Set(['CreateMessage', 'UpdateMessage', 'CreateReply']);

export function getOperation(domain: string, action: string): Operation {
  const op = operations.find(op => op.domain === domain && op.action === action);
  if (!op) throw new HttpError(400, '未知の操作です。describeで利用可能な操作を確認してください。');
  return op;
}

export function allowedOperations(domain: string, granted: string[]): Operation[] {
  return operations.filter(op => op.domain === domain && (op.readonly || granted.includes('hey:write')));
}

export function requiredScopes(op: Operation, params: Record<string, unknown>): string[] {
  if (op.readonly) return ['hey:read'];
  const required = ['hey:read', 'hey:write'];
  if (messageOperations.has(op.id)) {
    const entry = params.entry as Record<string, unknown> | undefined;
    // A draft with a schedule will eventually send, so that also requires hey:send.
    if (entry?.status !== 'drafted' || ['scheduled_delivery', 'scheduled_delivery_at_date', 'scheduled_delivery_at_hour']
      .some(key => entry[key] !== undefined)) required.push('hey:send');
  }
  return required;
}

export function buildRequest(op: Operation, params: Record<string, unknown>, accountId?: number) {
  // The generator resolves references; widen the inferred JSON union at this boundary.
  const input: object = op.input;
  const validation = new Validator(input as Schema).validate(params);
  if (!validation.valid) throw new HttpError(400, `入力が不正です。describeでスキーマを確認してください。${validation.errors.map(e => e.instanceLocation + ' ' + e.error).join('; ')}`);
  let path = op.path;
  const query = new URLSearchParams();
  const body = { ...params };
  for (const param of op.params) {
    const value = params[param.name];
    delete body[param.name];
    if (value === undefined) continue;
    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') throw new HttpError(400, 'URLのパラメーターは文字列・数値・真偽値に限定されます。');
    if (param.in === 'path') {
      const text = String(value);
      if (text === '.' || text === '..' || /[/\\%?#]/.test(text)) throw new HttpError(400, '不正なパスパラメーターです。');
      path = path.replace(`{${param.name}}`, encodeURIComponent(text));
    } else if (param.in === 'query') query.set(param.name, String(value));
  }
  if (accountId !== undefined) {
    if (!Number.isSafeInteger(accountId) || accountId <= 0) throw new HttpError(400, 'account_idは正の整数で指定してください。');
    // Match hey-sdk's ForAccount: this is a presentation filter, not an API prefix.
    query.set('filtered_account_id', String(accountId));
  }
  if (query.size) path += `?${query}`;
  return { path, body: op.hasBody ? body : undefined };
}
