/**
 * Simulate what NSS does to verify our token
 */
const fetch = require('node-fetch');
const jose = require('jose');
const crypto = require('crypto');

const ISSUER = 'https://melvincarvalho.com/';

async function test() {
  console.log('=== Simulating NSS Token Verification ===\n');

  // Step 1: Get a token
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
  
  // Decode token
  const parts = access_token.split('.');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  
  console.log('Token issuer:', payload.iss);
  console.log('Token webid:', payload.webid);
  console.log('Token kid:', header.kid);

  // Step 2: NSS would fetch WebID to discover issuer
  console.log('\n1. Fetching WebID profile...');
  const webidUrl = payload.webid.split('#')[0];
  const webidResp = await fetch(webidUrl, { headers: { Accept: 'text/turtle' } });
  console.log('   Status:', webidResp.status);
  const webidBody = await webidResp.text();
  const issuerMatch = webidBody.match(/oidcIssuer[^<]*<([^>]+)>/);
  console.log('   Found oidcIssuer:', issuerMatch ? issuerMatch[1] : 'NOT FOUND');

  // Step 3: NSS would fetch OIDC config
  console.log('\n2. Fetching OIDC config...');
  const configResp = await fetch(payload.iss + '.well-known/openid-configuration');
  console.log('   Status:', configResp.status);
  const config = await configResp.json();
  console.log('   jwks_uri:', config.jwks_uri);

  // Step 4: NSS would fetch JWKS
  console.log('\n3. Fetching JWKS...');
  const jwksResp = await fetch(config.jwks_uri);
  console.log('   Status:', jwksResp.status);
  const jwks = await jwksResp.json();
  console.log('   Keys:', jwks.keys.length);
  
  // Step 5: Find matching key
  console.log('\n4. Finding key for kid:', header.kid);
  const key = jwks.keys.find(k => k.kid === header.kid);
  if (key) {
    console.log('   Found key, alg:', key.alg);
    
    // Try to verify
    console.log('\n5. Verifying token signature...');
    try {
      const jwksSet = jose.createRemoteJWKSet(new URL(config.jwks_uri));
      const { payload: verified } = await jose.jwtVerify(access_token, jwksSet);
      console.log('   ✓ Signature valid!');
      console.log('   Verified webid:', verified.webid);
    } catch (err) {
      console.log('   ✗ Verification failed:', err.message);
    }
  } else {
    console.log('   ✗ Key not found!');
  }
}

test().catch(console.error);
