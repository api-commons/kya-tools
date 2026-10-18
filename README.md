# kya-tools

**Let AI agents prove who they are to your API, and decide for yourself whether to trust them.** Zero dependencies, Node 20+, Apache-2.0.

- **API providers:** verify an [APIs.io Know Your Agent](https://apis.io/kya/) attestation, check it came from the agent it names, and apply your own rule.
- **Agent builders:** sign your requests with [Web Bot Auth](https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/) from your own domain, and get attestations for the APIs you use.

This is the code behind a flow that runs in production today. An agent discovers an API on APIs.io, reads its [`/.well-known/api-onboarding`](https://apicommons.org/onboarding/), presents an attestation, gets trusted, tops up its own balance over x402, and its human verifies one email. See every step, with the real requests and responses: **[apievangelist.com/agent-onboarding](https://apievangelist.com/agent-onboarding/)**.

## How it works

1. The agent signs its requests with an Ed25519 key whose public half it publishes at `https://<its domain>/.well-known/http-message-signatures-directory`. That anchors its APIs.io record to the domain.
2. Before signing up with your API, it asks APIs.io for an attestation addressed to you: a ten-minute RS256 JWT (`typ: kya+jwt`) carrying its tier and bound to its key (`cnf.jkt`).
3. It sends the attestation in the `APIs-IO-Attestation` header, on a request signed with that key.
4. You verify the signature against `https://apis.io/.well-known/jwks.json`, check that it's addressed to you, fresh and unused, and that the request was signed by the bound key. Then you apply **your** rule. APIs.io vouches for facts it can check; it never tells you whom to trust.
5. Optionally, you report back how the agent behaved, signed as your own domain, which builds its history for the next provider.

## For API providers

```js
import { verifyAttestation, decide } from '@api-commons/kya-tools';

// In your signup (or any) handler. `url` must be the public URL the agent called: it's what they signed.
const result = await verifyAttestation(
  { method: req.method, url: 'https://api.example.com' + req.url, headers: req.headers, body: rawBody },
  { audience: 'https://api.example.com', seen: (jti) => store.firstTime(jti) },
);

if (result === null) { /* no attestation sent: onboard as you do today */ }
else if (!result.ok) { /* refused: tell the agent result.reason and result.message (400) */ }
else {
  const { decision, reasons } = decide(result.claims, result.bound); // or your own rule
  // Store decision + reasons against the account, and say in your descriptor what "trusted" buys.
}
```

`verifyAttestation` returns `null` when nothing was sent, `{ ok: true, claims, bound }` when it checks out, or `{ ok: false, reason, message }` with one of: `malformed`, `wrong_type`, `wrong_alg`, `unknown_key`, `bad_signature`, `wrong_issuer`, `wrong_audience`, `expired`, `not_yet_valid`, `unbound`, `subject_mismatch`, `wrong_key`, `stale_signature`, `bad_digest`, `bad_request_signature`, `replayed`, `unavailable`.

Then tell agents you accept it, in your [API Onboarding Descriptor](https://apicommons.org/onboarding/):

```json
"verification": [{
  "facet": "identity_anchor", "min_grade": "verified", "blocking": false,
  "description": "Present an apis.io attestation in APIs-IO-Attestation on signup. Anchored + key-bound is recorded as trusted.",
  "vocabulary": "https://apis.io/kya/"
}]
```

A runnable server: [`examples/provider.mjs`](examples/provider.mjs). A live descriptor to copy: [yawplet.com/.well-known/api-onboarding](https://yawplet.com/.well-known/api-onboarding).

**Reporting conduct back** (sign as your API's own domain; its key directory must be served there):

```js
import { apisio } from '@api-commons/kya-tools';
const io = apisio({ privateKey: process.env.API_WBA_KEY, agent: 'https://api.example.com' });
await io.report(result.claims.sub, { kind: 'good_standing', basis: '12 requests in October within our terms, none refused.', period: '2026-10' });
```

## For agent builders

```js
import { generateKey, keyDirectory, signRequest, apisio } from '@api-commons/kya-tools';

// Once: make a key, store privateKeyB64 as a secret, and serve keyDirectory() at
// https://agent.example.com/.well-known/http-message-signatures-directory
const { privateKeyB64 } = generateKey();

const io = apisio({ privateKey: privateKeyB64, agent: 'https://agent.example.com' });
await io.disclose({ operator_name: 'Example Co', operator_email: 'ops@example.com' }); // your KYA record

// Per provider: check, attest, present on a signed request.
const { ready } = await io.match('https://api.example.com');
const { attestation } = await io.attest('https://api.example.com');
const url = 'https://api.example.com/v1/accounts', body = JSON.stringify({ name: 'my agent', accept_terms: true });
await fetch(url, { method: 'POST', body, headers: {
  'APIs-IO-Attestation': attestation,
  ...signRequest({ privateKey: privateKeyB64, agent: 'https://agent.example.com', method: 'POST', url, body }),
} });
```

Register your agent card at [apis.io/agents](https://apis.io/agents/register/) as a consumer, a provider, or both. A runnable walk-through: [`examples/agent.mjs`](examples/agent.mjs).

## Tested against production

`npm test` covers acceptance and every refusal path with locally generated keys. The same code was also run on 2026-10-18 against live apis.io and the live key directories: an agent attested and was trusted by [yawplet.com](https://yawplet.com), and a real attestation verified against the live JWKS. The four agent-first sites in that walkthrough (Yawplet, Yarnhen, Hagglebee, Eventwren) run the code this package was extracted from.

## Related

- [API Onboarding Descriptor](https://github.com/api-commons/api-onboarding) — what a provider requires, at `/.well-known/api-onboarding`
- [KYA](https://github.com/api-commons/kya) — the design behind the consumer record; live at [apis.io/kya](https://apis.io/kya/)
- [Agent onboarding, step by step](https://apievangelist.com/agent-onboarding/)

## License

Apache-2.0. Issues and pull requests welcome.
