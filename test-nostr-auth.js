/**
 * Test script for Nostr NIP-98 authentication
 *
 * Usage: node test-nostr-auth.js
 *
 * This script:
 * 1. Generates a Nostr keypair
 * 2. Creates a NIP-98 auth event
 * 3. Makes authenticated request to JSS
 * 4. Verifies the did:nostr identity is recognized
 */

import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools';
import { getToken } from 'nostr-tools/nip98';

const BASE_URL = process.env.TEST_URL || 'http://localhost:4000';

async function main() {
  console.log('=== Nostr NIP-98 Authentication Test ===\n');

  // Generate a new keypair
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);

  console.log('1. Generated keypair');
  console.log(`   Public key: ${pk}`);
  console.log(`   did:nostr:  did:nostr:${pk}\n`);

  // Create NIP-98 token for GET request to a public resource
  const testUrl = `${BASE_URL}/`;
  const method = 'GET';

  console.log(`2. Creating NIP-98 token for ${method} ${testUrl}`);

  const token = await getToken(testUrl, method, (event) => finalizeEvent(event, sk));

  console.log(`   Token length: ${token.length} chars\n`);

  // Make authenticated request
  console.log('3. Making authenticated request...');

  try {
    const response = await fetch(testUrl, {
      method,
      headers: {
        'Authorization': `Nostr ${token}`,
        'Accept': 'application/json'
      }
    });

    console.log(`   Status: ${response.status} ${response.statusText}`);

    // Check headers for any auth info
    const wwwAuth = response.headers.get('www-authenticate');
    if (wwwAuth) {
      console.log(`   WWW-Authenticate: ${wwwAuth}`);
    }

    // For a protected resource, we'd check if access was granted
    // For now, just verify the request went through
    if (response.ok) {
      console.log('   Request succeeded!\n');
    } else {
      const body = await response.text();
      console.log(`   Response: ${body.slice(0, 200)}\n`);
    }
  } catch (err) {
    console.error(`   Error: ${err.message}\n`);
  }

  // Test with a protected resource (if exists)
  console.log('4. Testing access to a container...');

  const containerUrl = `${BASE_URL}/demo/public/`;

  try {
    const containerToken = await getToken(containerUrl, 'GET', (event) => finalizeEvent(event, sk));

    const response = await fetch(containerUrl, {
      headers: {
        'Authorization': `Nostr ${containerToken}`,
        'Accept': 'text/turtle'
      }
    });

    console.log(`   ${containerUrl}`);
    console.log(`   Status: ${response.status} ${response.statusText}`);

    if (response.status === 200) {
      console.log('   Container accessible with Nostr auth!');
    } else if (response.status === 403) {
      console.log('   403 Forbidden - auth worked but no ACL grant for did:nostr');
      console.log(`   (Add did:nostr:${pk} to ACL to grant access)`);
    } else if (response.status === 404) {
      console.log('   404 Not Found - container does not exist');
    }
  } catch (err) {
    console.error(`   Error: ${err.message}`);
  }

  console.log('\n=== Test Complete ===');
  console.log('\nTo grant this identity access, add to an ACL file:');
  console.log(`
@prefix acl: <http://www.w3.org/ns/auth/acl#>.

<#nostrAuth>
    a acl:Authorization;
    acl:agent <did:nostr:${pk}>;
    acl:accessTo <./>;
    acl:mode acl:Read, acl:Write.
`);
}

main().catch(console.error);
