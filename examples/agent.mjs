// An agent proving who it is to an API, end to end against the live services.
//
//   AGENT_ORIGIN=https://agent.example.com AGENT_KEY=<base64 PKCS#8 Ed25519> \
//   PROVIDER=https://yawplet.com API_KEY=<your key on that provider> node examples/agent.mjs
//
// Your key's public half must be served at $AGENT_ORIGIN/.well-known/http-message-signatures-directory.
import { apisio, signRequest } from '../index.mjs';

const agent = process.env.AGENT_ORIGIN, privateKey = process.env.AGENT_KEY, provider = process.env.PROVIDER || 'https://yawplet.com';
const io = apisio({ privateKey, agent });

const match = await io.match(provider);
console.log('match:', match.ready, match.error || '');

const { attestation, claims } = await io.attest(provider);
console.log('attested:', claims?.sub, 'tier', claims?.kya?.tier, 'expires in', claims && claims.exp - claims.iat, 's');

// Present it on a request signed with the same key. Yawplet's endpoint for an existing account:
const url = `${provider}/v1/account/kya`;
const res = await fetch(url, { method: 'POST', headers: { authorization: `Bearer ${process.env.API_KEY}`, 'APIs-IO-Attestation': attestation, ...signRequest({ privateKey, agent, method: 'POST', url }) } });
console.log('provider decided:', res.status, (await res.json()).decision);
