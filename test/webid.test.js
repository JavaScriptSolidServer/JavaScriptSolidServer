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
  extractJsonLdFromHtml
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
    // Profile is at /pod/profile/card following Solid convention
    const profilePath = '/webidtest/profile/card';

    it('should serve profile as HTML', async () => {
      const res = await request(profilePath);

      assertStatus(res, 200);
      assertHeaderContains(res, 'Content-Type', 'text/html');
    });

    it('should contain JSON-LD structured data', async () => {
      const res = await request(profilePath);
      const html = await res.text();

      const jsonLd = extractJsonLdFromHtml(html);
      assert.ok(jsonLd['@context'], 'Should have @context');
      // Profile uses flat structure, not @graph
      assert.ok(jsonLd['@id'], 'Should have @id');
    });

    it('should have correct WebID URI', async () => {
      const res = await request(profilePath);
      const html = await res.text();
      const jsonLd = extractJsonLdFromHtml(html);

      // Profile is a flat structure with the person as the main entity
      assert.ok(jsonLd['@id'].endsWith('/webidtest/profile/card#me'), 'WebID should end with /profile/card#me');
    });

    it('should have foaf:name', async () => {
      const res = await request(profilePath);
      const html = await res.text();
      const jsonLd = extractJsonLdFromHtml(html);

      assert.strictEqual(jsonLd['foaf:name'], 'webidtest');
    });

    it('should have solid:oidcIssuer', async () => {
      const res = await request(profilePath);
      const html = await res.text();
      const jsonLd = extractJsonLdFromHtml(html);

      assert.ok(jsonLd['oidcIssuer'], 'Should have oidcIssuer');
    });

    it('should have pim:storage pointing to pod', async () => {
      const res = await request(profilePath);
      const html = await res.text();
      const jsonLd = extractJsonLdFromHtml(html);

      assert.ok(jsonLd['storage'].endsWith('/webidtest/'), 'Storage should point to pod');
    });

    it('should have ldp:inbox', async () => {
      const res = await request(profilePath);
      const html = await res.text();
      const jsonLd = extractJsonLdFromHtml(html);

      assert.ok(jsonLd['inbox'].endsWith('/webidtest/inbox/'), 'Should have inbox');
    });

    it('should have mainEntityOfPage', async () => {
      const res = await request(profilePath);
      const html = await res.text();
      const jsonLd = extractJsonLdFromHtml(html);

      // Check for mainEntityOfPage which links to the profile document
      assert.ok(jsonLd['mainEntityOfPage'], 'Should have mainEntityOfPage');
    });
  });

  describe('WebID Resolution', () => {
    it('should return LDP headers', async () => {
      const res = await request('/webidtest/profile/card');

      assertHeaderContains(res, 'Link', 'ldp#Resource');
      assertHeader(res, 'WAC-Allow');
    });

    it('should return CORS headers', async () => {
      const res = await request('/webidtest/profile/card', {
        headers: { 'Origin': 'https://example.com' }
      });

      assertHeader(res, 'Access-Control-Allow-Origin');
    });
  });
});
