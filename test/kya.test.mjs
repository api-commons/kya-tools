import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifyAttestation, decide, thumbprint, clearCache, signRequest, generateKey, keyDirectory } from '../index.mjs';

const NOW = Date.parse('2026-10-18T12:00:00Z');
const AUD = 'https://api.example.com';
// The issuer's key (stands in for apis.io) and the agent's Web Bot Auth key, both made here.
const issuer = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const issuerJwk = { ...issuer.publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
const agent = generateKey();
const jkt = thumbprint(agent.publicJwk);
const fetch = async (url) => {
  const body = url === 'https://apis.io/.well-known/jwks.json' ? { keys: [issuerJwk] }
    : url === 'https://agent.example.org/.well-known/http-message-signatures-directory' ? keyDirectory(agent.privateKeyB64) : null;
  return { ok: !!body, status: body ? 200 : 404, json: async () => body };
};
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function attestation(over = {}) {
  const t = Math.floor(NOW / 1000);
  const claims = { iss: 'https://apis.io', sub: 'wba:agent.example.org', aud: AUD, iat: t, nbf: t - 5, exp: t + 600, jti: crypto.randomUUID(), cnf: { jkt }, kya: { tier: 'anchored' }, ...over };
  const h = b64({ alg: 'RS256', typ: 'kya+jwt', kid: 'k1' }), p = b64(claims);
  return `${h}.${p}.${crypto.sign('RSA-SHA256', Buffer.from(`${h}.${p}`), issuer.privateKey).toString('base64url')}`;
}
function request(att, { body, key = agent.privateKeyB64, created = Math.floor(NOW / 1000), url = `${AUD}/v1/accounts` } = {}) {
  const headers = { 'APIs-IO-Attestation': att, ...signRequest({ privateKey: key, agent: 'https://agent.example.org', method: 'POST', url, body, created }) };
  return { method: 'POST', url, headers, body };
}
const opts = (o = {}) => ({ audience: AUD, fetch, now: NOW, ...o });
beforeEach(() => clearCache());

test('a bound attestation on a signed request verifies and is trusted', async () => {
  const body = JSON.stringify({ name: 'agent' });
  const r = await verifyAttestation(request(attestation(), { body }), opts());
  assert.equal(r.ok, true, r.message);
  assert.equal(r.bound, 'agent.example.org');
  assert.equal(decide(r.claims, r.bound).decision, 'trusted');
});

test('no attestation → null; below the tier → known', async () => {
  assert.equal(await verifyAttestation({ method: 'GET', url: AUD, headers: {} }, opts()), null);
  const r = await verifyAttestation(request(attestation({ kya: { tier: 'named' } })), opts());
  assert.equal(decide(r.claims, r.bound).decision, 'known');
});

test('refusals: audience, expiry, forgery, wrong key, subject, unsigned, stale, digest, replay', async () => {
  const reason = async (req, o) => (await verifyAttestation(req, opts(o))).reason;
  assert.equal(await reason(request(attestation({ aud: 'https://other.example' }))), 'wrong_audience');
  assert.equal(await reason(request(attestation({ exp: Math.floor(NOW / 1000) - 120 }))), 'expired');
  const f = attestation().split('.'); f[2] = f[2].slice(0, -4) + 'AAAA';
  assert.equal(await reason(request(f.join('.'))), 'bad_signature');
  assert.equal(await reason(request(attestation(), { key: generateKey().privateKeyB64 })), 'wrong_key');
  assert.equal(await reason(request(attestation({ sub: 'wba:evil.example' }))), 'subject_mismatch');
  assert.equal(await reason({ method: 'POST', url: AUD, headers: { 'apis-io-attestation': attestation() } }), 'unbound');
  assert.equal(await reason(request(attestation(), { created: Math.floor(NOW / 1000) - 900 })), 'stale_signature');
  const tampered = request(attestation(), { body: '{"a":1}' }); tampered.body = '{"a":2}';
  assert.equal(await reason(tampered), 'bad_digest');
  const used = new Set(); const seen = (j) => (used.has(j) ? false : (used.add(j), true));
  const once = attestation();
  assert.equal((await verifyAttestation(request(once), opts({ seen }))).ok, true);
  assert.equal(await reason(request(once), { seen }), 'replayed');
});
