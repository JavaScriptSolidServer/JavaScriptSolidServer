/**
 * Solid-OIDC tests
 * Tests for DPoP token verification
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as jose from 'jose';
import crypto from 'crypto';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  getBaseUrl,
  assertStatus
} from './helpers.js';
import { addTrustedIssuer, clearCaches, verifySolidOidc } from '../src/auth/solid-oidc.js';
import { getJwks } from '../src/idp/keys.js';

describe('Solid-OIDC', () => {
  let keyPair;
  let publicJwk;

  before(async () => {
    await startTestServer();
    await createTestPod('oidctest');

    // Generate a key pair for testing
    keyPair = await jose.generateKeyPair('ES256');
    publicJwk = await jose.exportJWK(keyPair.publicKey);
    publicJwk.alg = 'ES256';
  });

  after(async () => {
    await stopTestServer();
  });

  describe('DPoP Header Parsing', () => {
    // Use private folder - requires authentication
    const privatePath = '/oidctest/private/';

    it('should reject requests with DPoP auth but no DPoP proof', async () => {
      const res = await fetch(`${getBaseUrl()}${privatePath}`, {
        headers: {
          'Authorization': 'DPoP some-token'
        }
      });

      assertStatus(res, 401);
      const body = await res.json();
      assert.ok(body.message.includes('DPoP proof'), 'Should mention DPoP proof');
    });

    it('should reject invalid DPoP proof JWT', async () => {
      const res = await fetch(`${getBaseUrl()}${privatePath}`, {
        headers: {
          'Authorization': 'DPoP some-token',
          'DPoP': 'not-a-valid-jwt'
        }
      });

      assertStatus(res, 401);
    });

    it('should reject DPoP proof with wrong type', async () => {
      // Create a JWT that's not a DPoP proof (wrong typ)
      const wrongTypeJwt = await new jose.SignJWT({
        htm: 'GET',
        htu: `${getBaseUrl()}${privatePath}`,
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID()
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'JWT', jwk: publicJwk })
        .sign(keyPair.privateKey);

      const res = await fetch(`${getBaseUrl()}${privatePath}`, {
        headers: {
          'Authorization': 'DPoP some-token',
          'DPoP': wrongTypeJwt
        }
      });

      assertStatus(res, 401);
    });

    it('should reject DPoP proof with wrong HTTP method', async () => {
      const dpopProof = await createDpopProof('POST', `${getBaseUrl()}${privatePath}`);

      const res = await fetch(`${getBaseUrl()}${privatePath}`, {
        method: 'GET',
        headers: {
          'Authorization': 'DPoP some-token',
          'DPoP': dpopProof
        }
      });

      assertStatus(res, 401);
    });

    it('should reject DPoP proof with wrong URL', async () => {
      const dpopProof = await createDpopProof('GET', 'https://other-server.example/');

      const res = await fetch(`${getBaseUrl()}${privatePath}`, {
        headers: {
          'Authorization': 'DPoP some-token',
          'DPoP': dpopProof
        }
      });

      assertStatus(res, 401);
    });

    it('should reject expired DPoP proof', async () => {
      // Create a DPoP proof with old iat
      const dpopProof = await new jose.SignJWT({
        htm: 'GET',
        htu: `${getBaseUrl()}${privatePath}`,
        iat: Math.floor(Date.now() / 1000) - 600, // 10 minutes ago
        jti: crypto.randomUUID()
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
        .sign(keyPair.privateKey);

      const res = await fetch(`${getBaseUrl()}${privatePath}`, {
        headers: {
          'Authorization': 'DPoP some-token',
          'DPoP': dpopProof
        }
      });

      assertStatus(res, 401);
    });

    it('should reject DPoP proof missing jti', async () => {
      const dpopProof = await new jose.SignJWT({
        htm: 'GET',
        htu: `${getBaseUrl()}${privatePath}`,
        iat: Math.floor(Date.now() / 1000)
        // missing jti
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
        .sign(keyPair.privateKey);

      const res = await fetch(`${getBaseUrl()}${privatePath}`, {
        headers: {
          'Authorization': 'DPoP some-token',
          'DPoP': dpopProof
        }
      });

      assertStatus(res, 401);
    });
  });

  describe('Access Token Verification', () => {
    const privatePath = '/oidctest/private/';

    it('should reject token with invalid issuer (unreachable)', async () => {
      // Create a valid DPoP proof
      const dpopProof = await createDpopProof('GET', `${getBaseUrl()}${privatePath}`);

      // Create a fake access token with unreachable issuer
      const fakeToken = await new jose.SignJWT({
        webid: 'https://example.com/user#me',
        sub: 'https://example.com/user#me',
        iss: 'https://nonexistent-idp.example.com',
        aud: 'solid',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
      })
        .setProtectedHeader({ alg: 'ES256' })
        .sign(keyPair.privateKey);

      const res = await fetch(`${getBaseUrl()}${privatePath}`, {
        headers: {
          'Authorization': `DPoP ${fakeToken}`,
          'DPoP': dpopProof
        }
      });

      assertStatus(res, 401);
    });

    it('verifies tokens from a trusted self issuer without remote discovery fetch', async () => {
      clearCaches();

      const issuer = 'https://pivot-test.local:4443';
      addTrustedIssuer(issuer);

      const dpopKeyPair = await jose.generateKeyPair('ES256');
      const dpopPublicJwk = await jose.exportJWK(dpopKeyPair.publicKey);
      dpopPublicJwk.alg = 'ES256';
      const thumbprint = await jose.calculateJwkThumbprint(dpopPublicJwk, 'sha256');

      const serverJwks = await getJwks();
      const signingKey = serverJwks.keys.find((key) => key.alg === 'RS256') || serverJwks.keys[0];
      const privateKey = await jose.importJWK(signingKey, signingKey.alg);

      const accessToken = await new jose.SignJWT({
        webid: 'https://alice.pivot-test.local:4443/profile/card#me',
        sub: 'https://alice.pivot-test.local:4443/profile/card#me',
        iss: issuer,
        aud: 'solid',
        cnf: { jkt: thumbprint },
      })
        .setProtectedHeader({ alg: signingKey.alg, kid: signingKey.kid })
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      const dpopProof = await new jose.SignJWT({
        htm: 'GET',
        htu: 'https://alice.pivot-test.local:4443/private/',
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(),
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: dpopPublicJwk })
        .sign(dpopKeyPair.privateKey);

      const originalFetch = global.fetch;
      global.fetch = async () => {
        throw new Error('trusted self issuer should not use fetch');
      };

      try {
        const result = await verifySolidOidc({
          method: 'GET',
          protocol: 'https',
          hostname: 'alice.pivot-test.local:4443',
          url: '/private/',
          headers: {
            authorization: `DPoP ${accessToken}`,
            dpop: dpopProof,
          },
        });

        assert.strictEqual(result.error, null);
        assert.strictEqual(result.webId, 'https://alice.pivot-test.local:4443/profile/card#me');
      } finally {
        global.fetch = originalFetch;
        clearCaches();
      }
    });
  });

  describe('Bearer Token Fallback', () => {
    it('should still accept simple Bearer tokens', async () => {
      // This should work with our simple token system
      const res = await request('/oidctest/public/', { auth: 'oidctest' });
      assertStatus(res, 200);
    });

    it('should still accept simple Bearer tokens for writes', async () => {
      const res = await request('/oidctest/public/solid-oidc-test.txt', {
        method: 'PUT',
        body: 'test content',
        auth: 'oidctest'
      });
      assertStatus(res, 201);
    });
  });

  // Helper to create DPoP proofs
  async function createDpopProof(method, uri) {
    return new jose.SignJWT({
      htm: method,
      htu: uri,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID()
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
      .sign(keyPair.privateKey);
  }
});
