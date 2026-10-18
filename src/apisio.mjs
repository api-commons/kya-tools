// A small client for the APIs.io KYA routes, signed with Web Bot Auth. Used by agents (match, attest,
// disclose) and by providers (report conduct back). Docs: https://apis.io/kya/
import { signRequest } from './sign.mjs';

/**
 * @param {{ privateKey: string|import('node:crypto').KeyObject, agent: string, base?: string, fetch?: Function }} cfg
 *        `agent` is the https origin whose key directory holds the key (yours, or your API's domain when reporting).
 */
export function apisio({ privateKey, agent, base = 'https://apis.io', fetch: fetchImpl = globalThis.fetch }) {
  async function call(method, path, body) {
    const url = `${base}${path}`;
    const raw = body === undefined ? undefined : JSON.stringify(body);
    const res = await fetchImpl(url, { method, body: raw, headers: { accept: 'application/json', ...signRequest({ privateKey, agent, method, url, body: raw }) } });
    const text = await res.text();
    let json; try { json = JSON.parse(text); } catch { json = { raw: text }; }
    return { status: res.status, ...json };
  }
  return {
    /** Everything APIs.io holds about you, including who read it. */
    me: () => call('GET', '/api/v1/kya/me'),
    /** Disclose (or clear with null) fields of your record, e.g. { operator_email, abuse_contact }. */
    disclose: (fields) => call('PATCH', '/api/v1/kya/me', fields),
    /** Your record against a provider's /.well-known/api-onboarding: what is met and what is missing. */
    match: (provider) => call('GET', `/api/v1/kya/match?provider=${encodeURIComponent(provider)}`),
    /** A ten-minute attestation addressed to one provider. Send `.attestation` in the APIs-IO-Attestation header. */
    attest: (aud) => call('POST', '/api/v1/kya/attest', { aud }),
    /** Provider side: report how an agent behaved, with its basis. kind: good_standing | abuse | quota_exceeded | scope_misuse | credential_misuse | impersonation */
    report: (sub, { kind, basis, period, count }) => call('POST', `/api/v1/agents/${encodeURIComponent(sub)}/reports`, { kind, basis, period, count }),
  };
}
