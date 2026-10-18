// Agent side: sign HTTP requests with Web Bot Auth (the RFC 9421 HTTP Message Signatures profile),
// so the API you call, and APIs.io, can tell the request came from your domain.
//
// You need an Ed25519 key. Publish its public half at
//   https://<your domain>/.well-known/http-message-signatures-directory
// as {"keys":[<jwk>]} (keyDirectory() builds it), keep the private half secret, and sign each request.
// The signature covers @method, @authority, @path and Signature-Agent, plus Content-Digest when
// there is a body, tagged "web-bot-auth", with keyid = the key's RFC 7638 thumbprint. Zero dependencies.
import crypto from 'node:crypto';
import { thumbprint } from './verify.mjs';

/** A new Ed25519 key pair. Store `privateKeyB64` (PKCS#8 DER, base64) as a secret. */
export function generateKey() {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKeyB64: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'), publicJwk: publicJwk(privateKey) };
}

const toKey = (k) => (k instanceof crypto.KeyObject ? k : crypto.createPrivateKey({ key: Buffer.from(String(k), 'base64'), format: 'der', type: 'pkcs8' }));

/** The public JWK for a private key (KeyObject or base64 PKCS#8). */
export function publicJwk(privateKey) {
  const j = crypto.createPublicKey(toKey(privateKey)).export({ format: 'jwk' });
  return { kty: j.kty, crv: j.crv, x: j.x };
}

/** The body to serve at /.well-known/http-message-signatures-directory (content type application/http-message-signatures-directory+json). */
export const keyDirectory = (privateKey) => ({ keys: [publicJwk(privateKey)] });

/**
 * Headers that sign one request.
 * @param {{ privateKey: crypto.KeyObject|string, agent: string, method: string, url: string, body?: string, created?: number }} p
 *        `agent` is your https origin, e.g. "https://agent.example.com".
 * @returns {Record<string,string>} signature-agent, signature-input, signature (+ content-digest, content-type with a body)
 */
export function signRequest({ privateKey, agent, method, url, body, created = Math.floor(Date.now() / 1000) }) {
  const key = toKey(privateKey);
  const keyid = thumbprint(publicJwk(key));
  const u = new URL(url);
  const headers = { 'signature-agent': `sig1="${String(agent).replace(/\/+$/, '')}"` };
  const comps = ['@method', '@authority', '@path', 'signature-agent'];
  if (body !== undefined) {
    headers['content-type'] = 'application/json';
    headers['content-digest'] = `sha-256=:${crypto.createHash('sha256').update(body).digest('base64')}:`;
    comps.push('content-digest');
  }
  const params = `(${comps.map((c) => `"${c}"`).join(' ')});created=${created};keyid="${keyid}";alg="Ed25519";tag="web-bot-auth"`;
  const base = comps.map((c) => `"${c}": ${c === '@method' ? String(method).toUpperCase() : c === '@authority' ? u.host : c === '@path' ? u.pathname : headers[c]}`)
    .concat(`"@signature-params": ${params}`).join('\n');
  headers['signature-input'] = `sig1=${params}`;
  headers.signature = `sig1=:${crypto.sign(null, Buffer.from(base), key).toString('base64')}:`;
  return headers;
}
