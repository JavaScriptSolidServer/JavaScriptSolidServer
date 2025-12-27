#!/usr/bin/env node
/**
 * CTH Compatibility Test Script
 *
 * Tests that JSS is configured correctly for the Solid Conformance Test Harness.
 *
 * Usage:
 *   node scripts/test-cth-compat.js [--port 3000] [--run-cth]
 */

import { createServer } from '../src/server.js';
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration
const PORT = parseInt(process.argv.find(a => a.startsWith('--port='))?.split('=')[1] || '3456');
const RUN_CTH = process.argv.includes('--run-cth');
const BASE_URL = `http://localhost:${PORT}`;
const DATA_DIR = path.join(__dirname, '../.test-cth-data');

// Test users
const ALICE = {
  name: 'alice',
  email: 'alice@test.local',
  password: 'alicepassword123',
};

const BOB = {
  name: 'bob',
  email: 'bob@test.local',
  password: 'bobpassword123',
};

// Colors for output
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const RESET = '\x1b[0m';

function log(msg, color = RESET) {
  console.log(`${color}${msg}${RESET}`);
}

function pass(msg) {
  log(`  ✓ ${msg}`, GREEN);
}

function fail(msg) {
  log(`  ✗ ${msg}`, RED);
}

function info(msg) {
  log(`  ℹ ${msg}`, CYAN);
}

async function main() {
  log('\n=== JSS CTH Compatibility Test ===\n', CYAN);

  let server;
  let passed = 0;
  let failed = 0;

  try {
    // Clean up and prepare
    await fs.remove(DATA_DIR);
    await fs.ensureDir(DATA_DIR);

    // Start server with IdP
    log('Starting server with IdP enabled...', YELLOW);
    server = createServer({
      logger: false,
      root: DATA_DIR,
      idp: true,
      idpIssuer: BASE_URL,
    });

    await server.listen({ port: PORT, host: 'localhost' });
    pass(`Server running at ${BASE_URL}`);
    passed++;

    // Test 1: OIDC Discovery
    log('\n1. OIDC Discovery', YELLOW);
    {
      const res = await fetch(`${BASE_URL}/.well-known/openid-configuration`);
      if (res.status === 200) {
        const config = await res.json();
        // Issuer has trailing slash for CTH compatibility
        if (config.issuer === BASE_URL + '/') {
          pass('/.well-known/openid-configuration returns valid config');
          passed++;
        } else {
          fail(`Issuer mismatch: expected ${BASE_URL}/, got ${config.issuer}`);
          failed++;
        }
      } else {
        fail(`OIDC discovery returned ${res.status}`);
        failed++;
      }
    }

    // Test 2: JWKS
    log('\n2. JWKS Endpoint', YELLOW);
    {
      const res = await fetch(`${BASE_URL}/.well-known/jwks.json`);
      if (res.status === 200) {
        const jwks = await res.json();
        if (jwks.keys?.length > 0) {
          pass('/.well-known/jwks.json returns keys');
          passed++;
        } else {
          fail('JWKS has no keys');
          failed++;
        }
      } else {
        fail(`JWKS returned ${res.status}`);
        failed++;
      }
    }

    // Test 3: Create Alice
    log('\n3. Create Test User: Alice', YELLOW);
    let aliceWebId, aliceToken;
    {
      const res = await fetch(`${BASE_URL}/.pods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ALICE),
      });

      if (res.status === 201) {
        const data = await res.json();
        aliceWebId = data.webId;
        pass(`Created Alice: ${aliceWebId}`);
        passed++;
      } else {
        const err = await res.text();
        fail(`Failed to create Alice: ${res.status} - ${err}`);
        failed++;
      }
    }

    // Test 4: Create Bob
    log('\n4. Create Test User: Bob', YELLOW);
    let bobWebId;
    {
      const res = await fetch(`${BASE_URL}/.pods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(BOB),
      });

      if (res.status === 201) {
        const data = await res.json();
        bobWebId = data.webId;
        pass(`Created Bob: ${bobWebId}`);
        passed++;
      } else {
        const err = await res.text();
        fail(`Failed to create Bob: ${res.status} - ${err}`);
        failed++;
      }
    }

    // Test 5: Credentials endpoint - JSON
    log('\n5. Credentials Endpoint (JSON)', YELLOW);
    {
      const res = await fetch(`${BASE_URL}/idp/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: ALICE.email, password: ALICE.password }),
      });

      if (res.status === 200) {
        const data = await res.json();
        if (data.access_token && data.webid) {
          aliceToken = data.access_token;
          pass(`Got token for Alice (type: ${data.token_type})`);
          passed++;
        } else {
          fail('Missing access_token or webid in response');
          failed++;
        }
      } else {
        const err = await res.text();
        fail(`Credentials endpoint failed: ${res.status} - ${err}`);
        failed++;
      }
    }

    // Test 6: Credentials endpoint - Form encoded
    log('\n6. Credentials Endpoint (Form-encoded)', YELLOW);
    {
      const res = await fetch(`${BASE_URL}/idp/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `email=${encodeURIComponent(BOB.email)}&password=${encodeURIComponent(BOB.password)}`,
      });

      if (res.status === 200) {
        const data = await res.json();
        if (data.access_token) {
          pass('Form-encoded credentials work');
          passed++;
        } else {
          fail('Missing access_token in response');
          failed++;
        }
      } else {
        const err = await res.text();
        fail(`Form-encoded credentials failed: ${res.status} - ${err}`);
        failed++;
      }
    }

    // Test 7: Invalid credentials
    log('\n7. Invalid Credentials Handling', YELLOW);
    {
      const res = await fetch(`${BASE_URL}/idp/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: ALICE.email, password: 'wrongpassword' }),
      });

      if (res.status === 401) {
        pass('Returns 401 for invalid password');
        passed++;
      } else {
        fail(`Expected 401, got ${res.status}`);
        failed++;
      }
    }

    // Test 8: Token authentication
    log('\n8. Token Authentication', YELLOW);
    {
      if (aliceToken) {
        const res = await fetch(`${BASE_URL}/alice/`, {
          headers: { 'Authorization': `Bearer ${aliceToken}` },
        });

        if (res.status === 200) {
          pass('Token grants access to own pod');
          passed++;
        } else {
          fail(`Token auth failed: ${res.status}`);
          failed++;
        }
      } else {
        fail('No token available to test');
        failed++;
      }
    }

    // Test 9: Write with token
    log('\n9. Write with Token', YELLOW);
    {
      if (aliceToken) {
        const res = await fetch(`${BASE_URL}/alice/public/test.json`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${aliceToken}`,
            'Content-Type': 'application/ld+json',
          },
          body: JSON.stringify({ '@id': '#test', 'http://example.org/value': 42 }),
        });

        if ([200, 201, 204].includes(res.status)) {
          pass('Can write to pod with token');
          passed++;
        } else {
          fail(`Write failed: ${res.status}`);
          failed++;
        }
      } else {
        fail('No token available to test');
        failed++;
      }
    }

    // Test 10: Public read
    log('\n10. Public Read Access', YELLOW);
    {
      const res = await fetch(`${BASE_URL}/alice/public/test.json`);

      if (res.status === 200) {
        pass('Public resources are readable');
        passed++;
      } else {
        fail(`Public read failed: ${res.status}`);
        failed++;
      }
    }

    // Summary
    log('\n=== Summary ===\n', CYAN);
    log(`Passed: ${passed}`, GREEN);
    if (failed > 0) {
      log(`Failed: ${failed}`, RED);
    }

    // Generate CTH env file
    log('\n=== CTH Configuration ===\n', CYAN);

    const envContent = `# CTH Environment for JSS
# Generated by test-cth-compat.js

SOLID_IDENTITY_PROVIDER=${BASE_URL}
RESOURCE_SERVER_ROOT=${BASE_URL}
TEST_CONTAINER=alice/public/

USERS_ALICE_WEBID=${aliceWebId || `${BASE_URL}/alice/#me`}
USERS_ALICE_USERNAME=${ALICE.email}
USERS_ALICE_PASSWORD=${ALICE.password}

USERS_BOB_WEBID=${bobWebId || `${BASE_URL}/bob/#me`}
USERS_BOB_USERNAME=${BOB.email}
USERS_BOB_PASSWORD=${BOB.password}

LOGIN_ENDPOINT=${BASE_URL}/idp/credentials

# For self-signed certs
ALLOW_SELF_SIGNED_CERTS=true
`;

    const envPath = path.join(__dirname, '../cth.env');
    await fs.writeFile(envPath, envContent);
    info(`CTH env file written to: ${envPath}`);

    log('\nTo run CTH:', YELLOW);
    log(`
  # Keep JSS running with IdP:
  JSS_PORT=${PORT} jss start --idp

  # In another terminal, run CTH:
  docker run -i --rm \\
    --network host \\
    -v "$(pwd)"/reports:/reports \\
    --env-file=cth.env \\
    solidproject/conformance-test-harness \\
    --output=/reports \\
    --target=jss
`);

    if (RUN_CTH) {
      log('\nRunning CTH (this may take a while)...', YELLOW);
      // Would spawn docker here, but keeping server running is complex
      info('CTH auto-run not implemented yet. Run manually with commands above.');
    }

  } catch (err) {
    fail(`Error: ${err.message}`);
    console.error(err);
    failed++;
  } finally {
    // Cleanup
    if (server) {
      await server.close();
    }
    await fs.remove(DATA_DIR);
  }

  // Exit with error code if any tests failed
  process.exit(failed > 0 ? 1 : 0);
}

main();
