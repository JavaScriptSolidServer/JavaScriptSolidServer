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
    it('should serve profile as HTML at pod root', async () => {
      const res = await request('/webidtest/');

      assertStatus(res, 200);
      assertHeaderContains(res, 'Content-Type', 'text/html');
    });

    it('should contain JSON-LD structured data', async () => {
      const res = await request('/webidtest/');
      const html = await res.text();

      const jsonLd = extractJsonLdFromHtml(html);
      assert.ok(jsonLd['@context'], 'Should have @context');
      assert.ok(jsonLd['@graph'], 'Should have @graph');
    });

    it('should have correct WebID URI', async () => {
      const res = await request('/webidtest/');
      const html = await res.text();
      const jsonLd = extractJsonLdFromHtml(html);

      // Find the Person in the graph
      const person = jsonLd['@graph'].find(node =>
        Array.isArray(node['@type'])
          ? node['@type'].includes('foaf:Person')
          : node['@type'] === 'foaf:Person'
      );

      assert.ok(person, 'Should have a foaf:Person');
      assert.ok(person['@id'].endsWith('/webidtest/#me'), 'WebID should end with /#me');
    });

    it('should have foaf:name', async () => {
      const res = await request('/webidtest/');
      const html = await res.text();
      const jsonLd = extractJsonLdFromHtml(html);

      const person = jsonLd['@graph'].find(node =>
        Array.isArray(node['@type'])
          ? node['@type'].includes('foaf:Person')
          : node['@type'] === 'foaf:Person'
      );

      assert.strictEqual(person['foaf:name'], 'webidtest');
    });

    it('should have solid:oidcIssuer', async () => {
      const res = await request('/webidtest/');
      const html = await res.text();
      const jsonLd = extractJsonLdFromHtml(html);

      const person = jsonLd['@graph'].find(node =>
        Array.isArray(node['@type'])
          ? node['@type'].includes('foaf:Person')
          : node['@type'] === 'foaf:Person'
      );

      assert.ok(person['oidcIssuer'], 'Should have oidcIssuer');
    });

    it('should have pim:storage pointing to pod', async () => {
      const res = await request('/webidtest/');
      const html = await res.text();
      const jsonLd = extractJsonLdFromHtml(html);

      const person = jsonLd['@graph'].find(node =>
        Array.isArray(node['@type'])
          ? node['@type'].includes('foaf:Person')
          : node['@type'] === 'foaf:Person'
      );

      assert.ok(person['storage'].endsWith('/webidtest/'), 'Storage should point to pod');
    });

    it('should have ldp:inbox', async () => {
      const res = await request('/webidtest/');
      const html = await res.text();
      const jsonLd = extractJsonLdFromHtml(html);

      const person = jsonLd['@graph'].find(node =>
        Array.isArray(node['@type'])
          ? node['@type'].includes('foaf:Person')
          : node['@type'] === 'foaf:Person'
      );

      assert.ok(person['inbox'].endsWith('/webidtest/inbox/'), 'Should have inbox');
    });

    it('should have PersonalProfileDocument', async () => {
      const res = await request('/webidtest/');
      const html = await res.text();
      const jsonLd = extractJsonLdFromHtml(html);

      const doc = jsonLd['@graph'].find(node =>
        node['@type'] === 'foaf:PersonalProfileDocument'
      );

      assert.ok(doc, 'Should have PersonalProfileDocument');
      assert.ok(doc['foaf:maker'], 'Should have foaf:maker');
      assert.ok(doc['foaf:primaryTopic'], 'Should have foaf:primaryTopic');
    });
  });

  describe('WebID Resolution', () => {
    it('should return LDP headers', async () => {
      const res = await request('/webidtest/');

      assertHeaderContains(res, 'Link', 'ldp#Resource');
      assertHeader(res, 'WAC-Allow');
    });

    it('should return CORS headers', async () => {
      const res = await request('/webidtest/', {
        headers: { 'Origin': 'https://example.com' }
      });

      assertHeader(res, 'Access-Control-Allow-Origin');
    });
  });
});
