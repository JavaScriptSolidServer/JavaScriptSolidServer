/**
 * WebID Profile tests
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  assertStatus,
  assertHeader,
  assertHeaderContains,
} from './helpers.js';

describe('WebID Profile', () => {
  let baseUrl;
  let podInfo;

  before(async () => {
    const result = await startTestServer();
    baseUrl = result.baseUrl;
    podInfo = await createTestPod('webidtest');
  });

  after(async () => {
    await stopTestServer();
  });

  describe('Profile Document', () => {
    // Profile is now a plain JSON-LD doc at /pod/profile/card.jsonld.
    const profilePath = '/webidtest/profile/card.jsonld';

    it('should serve profile as JSON-LD', async () => {
      const res = await request(profilePath);

      assertStatus(res, 200);
      assertHeaderContains(res, 'Content-Type', 'application/ld+json');
    });

    it('should be valid JSON-LD with @context and @id', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      assert.ok(jsonLd['@context'], 'Should have @context');
      assert.ok(jsonLd['@id'], 'Should have @id');
    });

    it('should have correct WebID URI', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      assert.ok(jsonLd['@id'].endsWith('/webidtest/profile/card.jsonld#me'),
        `WebID should end with /profile/card.jsonld#me, got ${jsonLd['@id']}`);
    });

    it('should have foaf:name', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      assert.strictEqual(jsonLd['foaf:name'], 'webidtest');
    });

    it('should have solid:oidcIssuer', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      assert.ok(jsonLd['oidcIssuer'], 'Should have oidcIssuer');
    });

    it('should have pim:storage pointing to pod', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      assert.ok(jsonLd['storage'].endsWith('/webidtest/'), 'Storage should point to pod');
    });

    it('should have ldp:inbox', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      assert.ok(jsonLd['inbox'].endsWith('/webidtest/inbox/'), 'Should have inbox');
    });

    it('should have mainEntityOfPage pointing to the document', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      // Empty string is a relative URI reference to the document itself (JSON-LD)
      assert.strictEqual(jsonLd['mainEntityOfPage'], '', 'mainEntityOfPage should be "" (self)');
    });

    it('should have isPrimaryTopicOf pointing to the document', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      // Empty string is a relative URI reference to the document itself (JSON-LD)
      assert.strictEqual(jsonLd['isPrimaryTopicOf'], '', 'isPrimaryTopicOf should be "" (self)');
    });

    // LWS 1.0 Controlled Identifier alignment (#320).
    // These assertions live alongside the WebID predicate assertions — both
    // must continue to hold since the profile is dual-write.
    it('should emit a CID service[] with an lws:OpenIdProvider entry', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();
      assert.ok(Array.isArray(jsonLd.service), 'profile should have a service array');
      const oidc = jsonLd.service.find((s) => s.type === 'lws:OpenIdProvider');
      assert.ok(oidc, 'service[] must include an lws:OpenIdProvider entry');
    });

    it('lws:OpenIdProvider service.serviceEndpoint mirrors oidcIssuer', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();
      const oidc = jsonLd.service.find((s) => s.type === 'lws:OpenIdProvider');
      assert.strictEqual(
        oidc.serviceEndpoint,
        jsonLd.oidcIssuer,
        'serviceEndpoint must equal the existing oidcIssuer value'
      );
    });

    it('lws:OpenIdProvider service.id is a fragment on the profile document', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();
      const oidc = jsonLd.service.find((s) => s.type === 'lws:OpenIdProvider');
      const docUrl = jsonLd['@id'].split('#')[0];
      assert.strictEqual(oidc.id, `${docUrl}#oidc`,
        'service entry id should be `<profile-doc>#oidc`');
    });
  });

  describe('WebID Resolution', () => {
    const profilePath = '/webidtest/profile/card.jsonld';

    it('should return LDP headers', async () => {
      const res = await request(profilePath);

      assertHeaderContains(res, 'Link', 'ldp#Resource');
      assertHeader(res, 'WAC-Allow');
    });

    it('should return CORS headers', async () => {
      const res = await request(profilePath, {
        headers: { 'Origin': 'https://example.com' }
      });

      assertHeader(res, 'Access-Control-Allow-Origin');
    });
  });
});
