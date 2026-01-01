const fetch = require('node-fetch');
const jose = require('jose');
const crypto = require('crypto');
const https = require('https');

const ISSUER = 'https://melvincarvalho.com/';
const NSS_URL = 'https://localhost:8443/';

// Allow self-signed cert
const agent = new https.Agent({ rejectUnauthorized: false });

async function test() {
  console.log('=== Testing DPoP against local NSS ===\n');

  // Get DPoP token from our IdP
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
  const publicJwk = await jose.exportJWK(publicKey);

  const credProof = await new jose.SignJWT({
    htm: 'POST', htu: ISSUER + 'idp/credentials',
    iat: Math.floor(Date.now() / 1000), jti: crypto.randomUUID(),
  }).setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk }).sign(privateKey);

  const tokenResp = await fetch(ISSUER + 'idp/credentials', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'DPoP': credProof },
    body: JSON.stringify({ email: 'melvin', password: 'melvintest123' }),
  });
  const { access_token } = await tokenResp.json();
  console.log('Got token from melvincarvalho.com');

  // Create DPoP proof for local NSS
  const dpopProof = await new jose.SignJWT({
    htm: 'GET', htu: NSS_URL,
    iat: Math.floor(Date.now() / 1000), jti: crypto.randomUUID(),
  }).setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk }).sign(privateKey);

  console.log('Testing against local NSS:', NSS_URL);
  const resp = await fetch(NSS_URL, {
    agent,
    headers: {
      'Authorization': 'DPoP ' + access_token,
      'DPoP': dpopProof,
      'Accept': 'text/turtle',
    },
  });

  console.log('Status:', resp.status);
  const wwwAuth = resp.headers.get('www-authenticate');
  if (wwwAuth) console.log('WWW-Authenticate:', wwwAuth);
}

test().catch(console.error);
