// A provider accepting attestations: a plain node:http server, no framework.
//
//   ORIGIN=https://api.example.com PORT=8080 node examples/provider.mjs
//
// Behind a proxy, build `url` from the public origin the agent called, since that is what it signed.
import http from 'node:http';
import { verifyAttestation, decide } from '../index.mjs';

const ORIGIN = process.env.ORIGIN || 'http://localhost:8080';
const seenJti = new Set(); // use a shared store (Redis, DynamoDB) when you run more than one process

http.createServer(async (req, res) => {
  const chunks = []; for await (const c of req) chunks.push(c);
  const body = chunks.length ? Buffer.concat(chunks).toString('utf8') : undefined;
  const result = await verifyAttestation(
    { method: req.method, url: ORIGIN + req.url, headers: req.headers, body },
    { audience: ORIGIN, seen: (jti) => (seenJti.has(jti) ? false : (seenJti.add(jti), true)) },
  );
  res.setHeader('content-type', 'application/json');
  if (!result) return res.end(JSON.stringify({ kya: 'none', how: 'Send an APIs.io attestation in the APIs-IO-Attestation header.' }));
  if (!result.ok) { res.statusCode = 400; return res.end(JSON.stringify({ kya: 'refused', reason: result.reason, detail: result.message })); }
  // Your rule goes here. Store the decision and its reasons against the account.
  res.end(JSON.stringify({ sub: result.claims.sub, ...decide(result.claims, result.bound) }));
}).listen(Number(process.env.PORT || 8080), () => console.log(`accepting attestations for ${ORIGIN}`));
