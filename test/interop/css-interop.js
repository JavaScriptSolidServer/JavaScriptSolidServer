/**
 * Test against Community Solid Server (CSS) - typically more permissive
 * Also check solidweb.org configuration
 */
const fetch = require('node-fetch');
const jose = require('jose');
const crypto = require('crypto');

const ISSUER = 'https://melvincarvalho.com/';

async function test() {
  console.log('=== Checking OIDC Configuration Details ===\n');

  // Check solidweb.org OIDC config in detail
  console.log('1. solidweb.org OIDC configuration:');
  const swConfig = await fetch('https://solidweb.org/.well-known/openid-configuration');
  const swData = await swConfig.json();
  console.log('   issuer:', swData.issuer);
  console.log('   subject_types_supported:', swData.subject_types_supported);
  console.log('   id_token_signing_alg_values_supported:', swData.id_token_signing_alg_values_supported);
  console.log('   token_endpoint_auth_methods_supported:', swData.token_endpoint_auth_methods_supported);
  console.log('   claims_supported:', swData.claims_supported);

  // Check melvincarvalho.com for comparison
  console.log('\n2. melvincarvalho.com OIDC configuration:');
  const mcConfig = await fetch('https://melvincarvalho.com/.well-known/openid-configuration');
  const mcData = await mcConfig.json();
  console.log('   issuer:', mcData.issuer);
  console.log('   id_token_signing_alg_values_supported:', mcData.id_token_signing_alg_values_supported);

  // Find other known Solid servers to test
  console.log('\n3. Testing other Solid servers...');
  
  const otherServers = [
    'https://solidcommunity.net/.well-known/openid-configuration',
    'https://inrupt.net/.well-known/openid-configuration',
    'https://login.inrupt.com/.well-known/openid-configuration',
  ];

  for (const url of otherServers) {
    try {
      const resp = await fetch(url, { timeout: 5000 });
      if (resp.ok) {
        const data = await resp.json();
        console.log('   ' + url.split('/')[2] + ':');
        console.log('      issuer:', data.issuer);
        console.log('      token_types:', data.token_types_supported);
      }
    } catch (err) {
      console.log('   ' + url.split('/')[2] + ': ' + err.message);
    }
  }

  // Now test our token against solidcommunity.net (another NSS)
  console.log('\n4. Testing DPoP token against solidcommunity.net...');
  
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
  const { access_token } = await tokenResp.json();

  // Test on solidcommunity.net
  const testUrl = 'https://solidcommunity.net/';
  const dpopProof = await new jose.SignJWT({
    htm: 'GET',
    htu: testUrl,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
    .sign(privateKey);

  const testResp = await fetch(testUrl, {
    headers: {
      'Authorization': 'DPoP ' + access_token,
      'DPoP': dpopProof,
      'Accept': 'text/turtle',
    },
  });

  console.log('   Status:', testResp.status);
  const wwwAuth = testResp.headers.get('www-authenticate');
  if (wwwAuth) {
    console.log('   WWW-Auth:', wwwAuth);
  }
}

test().catch(console.error);
