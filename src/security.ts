export class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

const encoder = new TextEncoder();
const aad = encoder.encode("hey-mcp-credentials:v1");

export function randomToken(): string {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export async function hash(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

export async function secretEquals(a: string, b: string): Promise<boolean> {
  const [left, right] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(left, right);
}

async function encryptionKey(secret: string): Promise<CryptoKey> {
  let bytes: Uint8Array;
  try { bytes = Uint8Array.from(atob(secret), c => c.charCodeAt(0)); }
  catch { throw new HttpError(503, "ENCRYPTION_KEYの設定を確認してください。"); }
  if (bytes.byteLength !== 32) throw new HttpError(503, "ENCRYPTION_KEYは32 bytesのBase64で指定してください。");
  return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export type Envelope = { version: 1; nonce: string; ciphertext: string };

export async function encrypt(value: unknown, secret: string): Promise<Envelope> {
  const key = await encryptionKey(secret);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad }, key, encoder.encode(JSON.stringify(value)),
  );
  return {
    version: 1, nonce: btoa(String.fromCharCode(...nonce)),
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
  };
}

export async function decrypt<T>(envelope: Envelope, secret: string): Promise<T> {
  const key = await encryptionKey(secret);
  if (envelope.version !== 1) throw new HttpError(503, "保存形式が未対応です。");
  try {
    const plaintext = await crypto.subtle.decrypt({
      name: "AES-GCM", iv: Uint8Array.from(atob(envelope.nonce), c => c.charCodeAt(0)), additionalData: aad,
    }, key, Uint8Array.from(atob(envelope.ciphertext), c => c.charCodeAt(0)));
    return JSON.parse(new TextDecoder().decode(plaintext)) as T;
  } catch { throw new HttpError(503, "認証情報を復号できません。暗号化キーを確認してください。"); }
}

export async function readLimited(stream: ReadableStream<Uint8Array> | null, limit: number): Promise<Uint8Array> {
  if (!stream) return new Uint8Array();
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) {
        await reader.cancel();
        throw new HttpError(413, "データが大きすぎます。");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}

export function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
}

export function sameOrigin(request: Request, origin: string): void {
  if (request.headers.get("Origin") !== origin) throw new HttpError(403, "この画面から操作してください。");
}

export const adminCookie = "__Host-hey-admin";
export function cookie(request: Request, name: string): string {
  return request.headers.get("Cookie")?.split(";").map(c => c.trim())
    .find(c => c.startsWith(`${name}=`))?.slice(name.length + 1) ?? "";
}

export function setAdminCookie(token: string, maxAge: number): string {
  return `${adminCookie}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
}

export const securityHeaders = {
  "Cache-Control": "no-store",
  // Preserve same-origin POST Origin checks; no-referrer can turn Origin into null.
  "Referrer-Policy": "same-origin",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
};
