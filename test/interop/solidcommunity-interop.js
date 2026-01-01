/**
 * Test on solidcommunity.net to confirm DPoP auth works
 */
const fetch = require('node-fetch');
const jose = require('jose');
const crypto = require('crypto');

const ISSUER = 'https://melvincarvalho.com/';

async function test() {
  console.log('=== Confirming DPoP works on solidcommunity.net ===\n');

  const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
  const publicJwk = await jose.exportJWK(publicKey);

  const credDpopProof = await new jose.SignJWT({
    htm: 'POST',
    htu: ISSUER + 'idp/credentials',
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
    .sign(privateKey);

  const tokenResp = await fetch(ISSUER + 'idp/credentials', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'DPoP': credDpopProof },
    body: JSON.stringify({ email: 'melvin', password: 'melvintest123' }),
  });
  const tokenData = await tokenResp.json();
  const access_token = tokenData.access_token;
  console.log('Got token, webid:', tokenData.webid);

  // Parse token
  const payload = JSON.parse(Buffer.from(access_token.split('.')[1], 'base64url').toString());
  console.log('Token issuer:', payload.iss);
  console.log('Token webid:', payload.webid);
  console.log('Token cnf.jkt:', payload.cnf.jkt.substring(0, 20) + '...');

  // Test different endpoints on solidcommunity.net
  const tests = [
    { url: 'https://solidcommunity.net/', name: 'root (public)' },
    { url: 'https://melvin.solidcommunity.net/', name: 'user pod root' },
    { url: 'https://melvin.solidcommunity.net/profile/card', name: 'user profile' },
  ];

  for (const t of tests) {
    console.log('\n--- ' + t.name + ' ---');
    console.log('URL:', t.url);

    // Without auth
    const noAuthResp = await fetch(t.url, {
      headers: { 'Accept': 'text/turtle' },
    });
    console.log('Without auth:', noAuthResp.status);

    // With DPoP
    const dpopProof = await new jose.SignJWT({
      htm: 'GET',
      htu: t.url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
      .sign(privateKey);

    const authResp = await fetch(t.url, {
      headers: {
        'Authorization': 'DPoP ' + access_token,
        'DPoP': dpopProof,
        'Accept': 'text/turtle',
      },
    });
    console.log('With DPoP:', authResp.status);
    
    const wwwAuth = authResp.headers.get('www-authenticate');
    if (wwwAuth) {
      console.log('WWW-Auth:', wwwAuth);
    }
  }

  // Now compare the same tests on solidweb.org
  console.log('\n\n=== Comparison: Same tests on solidweb.org ===\n');

  const swTests = [
    { url: 'https://solidweb.org/', name: 'root (public)' },
    { url: 'https://solid-chat.solidweb.org/', name: 'solid-chat pod root' },
  ];

  for (const t of swTests) {
    console.log('\n--- ' + t.name + ' ---');
    console.log('URL:', t.url);

    // Without auth
    const noAuthResp = await fetch(t.url, {
      headers: { 'Accept': 'text/turtle' },
    });
    console.log('Without auth:', noAuthResp.status);

    // With DPoP
    const dpopProof = await new jose.SignJWT({
      htm: 'GET',
      htu: t.url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
      .sign(privateKey);

    const authResp = await fetch(t.url, {
      headers: {
        'Authorization': 'DPoP ' + access_token,
        'DPoP': dpopProof,
        'Accept': 'text/turtle',
      },
    });
    console.log('With DPoP:', authResp.status);
    
    const wwwAuth = authResp.headers.get('www-authenticate');
    if (wwwAuth) {
      console.log('WWW-Auth:', wwwAuth);
    }
  }
}

test().catch(console.error);
