// Provider side: verify an APIs.io Know Your Agent attestation, and decide what you make of it.
//
// An agent asks APIs.io for an attestation addressed to you (POST https://apis.io/api/v1/kya/attest
// with {"aud": "https://your.api"}) and sends it in the `APIs-IO-Attestation` header. It is a
// ten-minute RS256 JWT (typ kya+jwt). verifyAttestation() checks, in order:
//
//   1. The signature, against the issuer's JWKS; typ, alg, iss, aud = your origin, nbf/exp.
//   2. Key binding. A key-bound attestation (cnf.jkt) only counts on a request Web Bot Auth-signed
//      (RFC 9421 profile) by that key, from the domain the attestation is about. The agent's key is
//      fetched from <its origin>/.well-known/http-message-signatures-directory. Without this check a
//      leaked attestation is a bearer token for someone else's reputation.
//   3. Replay, if you pass `seen` (accept each jti once).
//
// decide() then applies YOUR rule. APIs.io vouches for facts it can check (domain control, the
// signing key); it never tells you whom to trust. Zero dependencies; Node 20+.
import crypto from 'node:crypto';

export const ATTESTATION_HEADER = 'apis-io-attestation';
export const TIERS = ['anonymous', 'named', 'confirmed', 'anchored'];
const DEFAULTS = { issuer: 'https://apis.io', jwksUri: 'https://apis.io/.well-known/jwks.json', skewSeconds: 60, signatureMaxAgeSeconds: 300 };

export class KyaError extends Error {
  constructor(reason, message) { super(message); this.reason = reason; }
}

const b64json = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
const lower = (headers = {}) => Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(', ') : v]));

/** RFC 7638 thumbprint of an Ed25519 JWK, as Web Bot Auth uses for keyid and APIs.io for cnf.jkt. */
export const thumbprint = (jwk) => crypto.createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })).digest('base64url');

// JWKS and key directories, cached for an hour per process.
const cache = new Map();
async function getJson(url, fetchImpl, now) {
  const hit = cache.get(url);
  if (hit && now - hit.at < 3_600_000) return hit.json;
  const res = await fetchImpl(url, { redirect: 'error', signal: AbortSignal.timeout(4000), headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`${url} answered ${res.status}`);
  const json = await res.json();
  cache.set(url, { at: now, json });
  return json;
}
export const clearCache = () => cache.clear();

async function verifyJwt(token, o) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new KyaError('malformed', 'The attestation is not a JWT.');
  let head, claims;
  try { head = b64json(parts[0]); claims = b64json(parts[1]); } catch { throw new KyaError('malformed', 'The attestation does not decode.'); }
  if (head.typ !== 'kya+jwt') throw new KyaError('wrong_type', `typ must be kya+jwt, not ${head.typ}.`);
  if (head.alg !== 'RS256') throw new KyaError('wrong_alg', 'Only RS256 attestations are accepted.');
  const jwks = await getJson(o.jwksUri, o.fetch, o.now);
  const jwk = (jwks.keys || []).find((k) => k.kid === head.kid);
  if (!jwk) throw new KyaError('unknown_key', `No key ${head.kid} in ${o.jwksUri}.`);
  const ok = crypto.verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), crypto.createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(parts[2], 'base64url'));
  if (!ok) throw new KyaError('bad_signature', 'The attestation signature does not verify.');
  const t = Math.floor(o.now / 1000);
  if (claims.iss !== o.issuer) throw new KyaError('wrong_issuer', `iss must be ${o.issuer}.`);
  if (![].concat(claims.aud).includes(o.audience)) throw new KyaError('wrong_audience', `This attestation is addressed to ${claims.aud}, not ${o.audience}.`);
  if (typeof claims.exp !== 'number' || t > claims.exp + o.skewSeconds) throw new KyaError('expired', 'The attestation has expired. Ask the issuer for a fresh one.');
  if (typeof claims.nbf === 'number' && t < claims.nbf - o.skewSeconds) throw new KyaError('not_yet_valid', 'The attestation is not valid yet.');
  if (!claims.sub || !claims.jti) throw new KyaError('malformed', 'The attestation has no sub or jti.');
  return claims;
}

async function verifyBinding(req, claims, o) {
  const h = lower(req.headers);
  const agentHdr = h['signature-agent'], input = h['signature-input'], sig = h.signature;
  if (!agentHdr || !input || !sig) throw new KyaError('unbound', 'This attestation is key-bound: sign the request with Web Bot Auth using the key it is bound to.');
  const agent = (agentHdr.match(/^sig1="([^"]+)"$/) || [])[1];
  const m = input.match(/^sig1=\(([^)]*)\)(.*)$/);
  const s = (sig.match(/^sig1=:([^:]+):$/) || [])[1];
  if (!agent || !m || !s) throw new KyaError('unbound', 'The Web Bot Auth headers do not parse (expected label sig1).');
  let origin;
  try { origin = new URL(agent); } catch { throw new KyaError('unbound', 'Signature-Agent is not a URL.'); }
  if (origin.protocol !== 'https:') throw new KyaError('unbound', 'Signature-Agent must be https.');
  if (claims.sub.startsWith('wba:') && claims.sub.slice(4) !== origin.host) throw new KyaError('subject_mismatch', `The attestation is for ${claims.sub}, but the request is signed by ${origin.host}.`);
  const components = m[1].split(/\s+/).filter(Boolean).map((c) => c.replace(/^"|"$/g, ''));
  for (const need of ['@method', '@authority', '@path', 'signature-agent']) if (!components.includes(need)) throw new KyaError('unbound', `The signature must cover ${need}.`);
  const params = Object.fromEntries([...m[2].matchAll(/;(\w+)=("([^"]*)"|\d+)/g)].map((x) => [x[1], x[3] ?? Number(x[2])]));
  if (params.tag !== 'web-bot-auth') throw new KyaError('unbound', 'tag must be "web-bot-auth".');
  if (params.keyid !== claims.cnf.jkt) throw new KyaError('wrong_key', 'The request is signed with a different key than the attestation is bound to.');
  if (typeof params.created !== 'number' || Math.abs(o.now / 1000 - params.created) > o.signatureMaxAgeSeconds) throw new KyaError('stale_signature', 'The signature is too old. Sign each request fresh.');
  if (components.includes('content-digest')) {
    const want = `sha-256=:${crypto.createHash('sha256').update(req.body ?? '').digest('base64')}:`;
    if (h['content-digest'] !== want) throw new KyaError('bad_digest', 'Content-Digest does not match the body.');
  }
  const dir = await getJson(`${origin.origin}/.well-known/http-message-signatures-directory`, o.fetch, o.now);
  const jwk = (dir.keys || []).find((k) => k.kty === 'OKP' && k.crv === 'Ed25519' && thumbprint(k) === claims.cnf.jkt);
  if (!jwk) throw new KyaError('wrong_key', `${origin.host} does not publish the key this attestation is bound to.`);
  const url = new URL(req.url);
  const base = components.map((c) => {
    const v = c === '@method' ? String(req.method).toUpperCase() : c === '@authority' ? url.host : c === '@path' ? url.pathname : h[c];
    return `"${c}": ${v}`;
  }).concat(`"@signature-params": ${input.slice('sig1='.length)}`).join('\n');
  const ok = crypto.verify(null, Buffer.from(base), crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' }), Buffer.from(s, 'base64'));
  if (!ok) throw new KyaError('bad_request_signature', 'The Web Bot Auth signature does not verify.');
  return origin.host;
}

/**
 * Verify the attestation on a request.
 *
 * @param {{ method: string, url: string, headers: object, body?: string }} req  The request as received:
 *        `url` is the full URL the agent called (its host and path are what the agent signed), `body` the raw body.
 * @param {{ audience: string, token?: string, issuer?: string, jwksUri?: string, fetch?: Function, now?: number,
 *           seen?: (jti: string) => boolean | Promise<boolean> }} opts
 *        `audience` is your origin, e.g. "https://api.example.com". `token` overrides the header (e.g. a body field).
 *        `seen(jti)` returns true the first time a jti is presented, false after; omit to skip replay checks.
 * @returns {Promise<null | { ok: true, claims, bound: string|null } | { ok: false, reason: string, message: string }>}
 *          null when no attestation was sent.
 */
export async function verifyAttestation(req, opts) {
  const o = { ...DEFAULTS, fetch: globalThis.fetch, now: Date.now(), ...opts };
  if (!o.audience) throw new Error('verifyAttestation: opts.audience (your origin) is required');
  const token = o.token || lower(req.headers)[ATTESTATION_HEADER];
  if (!token) return null;
  try {
    const claims = await verifyJwt(token, o);
    const bound = claims.cnf?.jkt ? await verifyBinding(req, claims, o) : null;
    if (o.seen && !(await o.seen(claims.jti))) throw new KyaError('replayed', 'This attestation was already used. Ask for a fresh one for each presentation.');
    return { ok: true, claims, bound };
  } catch (e) {
    if (e instanceof KyaError) return { ok: false, reason: e.reason, message: e.message };
    return { ok: false, reason: 'unavailable', message: `The attestation could not be checked: ${e.message}` };
  }
}

/**
 * A simple rule: trusted at or above `trustedTier` with a verified binding (when the attestation is
 * key-bound), otherwise known. Replace it with your own; that is the point.
 */
export function decide(claims, bound, { trustedTier = 'anchored' } = {}) {
  const tier = claims.kya?.tier || 'anonymous';
  const reasons = [`issuer tier: ${tier}`];
  const atTier = TIERS.indexOf(tier) >= TIERS.indexOf(trustedTier);
  if (bound) reasons.push(`request signed by ${bound}, the key the attestation is bound to`);
  if (claims.agent?.registry) reasons.push(`registered agent: ${claims.agent.registry}`);
  if (atTier && (bound || !claims.cnf?.jkt)) return { decision: 'trusted', tier, reasons };
  if (!atTier) reasons.push(`trusted needs tier ${trustedTier}`);
  return { decision: 'known', tier, reasons };
}
