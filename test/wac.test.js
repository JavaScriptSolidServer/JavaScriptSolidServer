/**
 * WAC (Web Access Control) tests
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
  getBaseUrl
} from './helpers.js';
import { parseAcl, AccessMode, generateOwnerAcl, serializeAcl } from '../src/wac/parser.js';
import { checkAccess, getRequiredMode } from '../src/wac/checker.js';

describe('WAC Parser', () => {
  describe('parseAcl', () => {
    it('should parse a simple ACL', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@graph': [{
          '@id': '#owner',
          '@type': 'acl:Authorization',
          'acl:agent': { '@id': 'https://alice.example/#me' },
          'acl:accessTo': { '@id': 'https://alice.example/resource' },
          'acl:mode': [{ '@id': 'acl:Read' }, { '@id': 'acl:Write' }]
        }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/.acl');

      assert.strictEqual(auths.length, 1);
      assert.ok(auths[0].agents.includes('https://alice.example/#me'));
      assert.ok(auths[0].modes.includes(AccessMode.READ));
      assert.ok(auths[0].modes.includes(AccessMode.WRITE));
    });

    it('should parse top-level JSON-LD array format', async () => {
      // ACL as top-level array (without @graph wrapper)
      const acl = [
        {
          '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
          '@id': '#owner',
          '@type': 'acl:Authorization',
          'acl:agent': { '@id': 'https://alice.example/#me' },
          'acl:accessTo': { '@id': 'https://alice.example/resource' },
          'acl:mode': [{ '@id': 'acl:Read' }, { '@id': 'acl:Write' }, { '@id': 'acl:Control' }]
        },
        {
          '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#', 'foaf': 'http://xmlns.com/foaf/0.1/' },
          '@id': '#public',
          '@type': 'acl:Authorization',
          'acl:agentClass': { '@id': 'foaf:Agent' },
          'acl:accessTo': { '@id': 'https://alice.example/resource' },
          'acl:mode': [{ '@id': 'acl:Read' }]
        }
      ];

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/.acl');

      assert.strictEqual(auths.length, 2);
      // Check owner authorization
      const ownerAuth = auths.find(a => a.agents.includes('https://alice.example/#me'));
      assert.ok(ownerAuth, 'Should have owner authorization');
      assert.ok(ownerAuth.modes.includes(AccessMode.READ));
      assert.ok(ownerAuth.modes.includes(AccessMode.WRITE));
      assert.ok(ownerAuth.modes.includes(AccessMode.CONTROL));
      // Check public authorization
      const publicAuth = auths.find(a => a.agentClasses.includes('foaf:Agent'));
      assert.ok(publicAuth, 'Should have public authorization');
      assert.ok(publicAuth.modes.includes(AccessMode.READ));
    });

    it('should parse public access', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#', 'foaf': 'http://xmlns.com/foaf/0.1/' },
        '@graph': [{
          '@id': '#public',
          '@type': 'acl:Authorization',
          'acl:agentClass': { '@id': 'foaf:Agent' },
          'acl:accessTo': { '@id': 'https://alice.example/public/' },
          'acl:mode': [{ '@id': 'acl:Read' }]
        }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/public/.acl');

      assert.strictEqual(auths.length, 1);
      assert.ok(auths[0].agentClasses.includes('foaf:Agent'));
      assert.ok(auths[0].modes.includes(AccessMode.READ));
    });

    it('should parse default authorizations for containers', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@graph': [{
          '@id': '#default',
          '@type': 'acl:Authorization',
          'acl:agent': { '@id': 'https://alice.example/#me' },
          'acl:default': { '@id': 'https://alice.example/folder/' },
          'acl:mode': [{ '@id': 'acl:Read' }]
        }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/folder/.acl');

      assert.strictEqual(auths.length, 1);
      assert.ok(auths[0].default.includes('https://alice.example/folder/'));
    });

    it('should handle invalid JSON gracefully', async () => {
      const auths = await parseAcl('not valid json', 'https://example.com/.acl');
      assert.strictEqual(auths.length, 0);
    });

    it('should parse Turtle ACL format', async () => {
      const turtleAcl = `
@prefix acl: <http://www.w3.org/ns/auth/acl#>.

<#owner>
    a acl:Authorization;
    acl:agent <did:nostr:abc123>;
    acl:accessTo <https://example.com/resource>;
    acl:mode acl:Read, acl:Write.
`;

      const auths = await parseAcl(turtleAcl, 'https://example.com/.acl');

      assert.strictEqual(auths.length, 1);
      assert.ok(auths[0].agents.includes('did:nostr:abc123'));
      assert.ok(auths[0].modes.includes(AccessMode.READ));
      assert.ok(auths[0].modes.includes(AccessMode.WRITE));
    });

    it('should resolve relative accessTo URLs', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@id': '#owner',
        '@type': 'acl:Authorization',
        'acl:agent': { '@id': 'https://alice.example/#me' },
        'acl:accessTo': { '@id': './' },
        'acl:mode': [{ '@id': 'acl:Read' }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/folder/.acl');

      assert.strictEqual(auths.length, 1);
      assert.ok(auths[0].accessTo.includes('https://alice.example/folder/'),
        `Expected accessTo to include 'https://alice.example/folder/', got: ${auths[0].accessTo}`);
    });

    it('should resolve relative default URLs', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@id': '#owner',
        '@type': 'acl:Authorization',
        'acl:agent': { '@id': 'https://alice.example/#me' },
        'acl:accessTo': { '@id': './' },
        'acl:default': { '@id': './' },
        'acl:mode': [{ '@id': 'acl:Read' }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/folder/.acl');

      assert.strictEqual(auths.length, 1);
      assert.ok(auths[0].default.includes('https://alice.example/folder/'),
        `Expected default to include 'https://alice.example/folder/', got: ${auths[0].default}`);
    });

    it('should resolve parent-relative URLs like ../other/', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@id': '#owner',
        '@type': 'acl:Authorization',
        'acl:agent': { '@id': 'https://alice.example/#me' },
        'acl:accessTo': { '@id': '../other/' },
        'acl:mode': [{ '@id': 'acl:Read' }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/folder/.acl');

      assert.strictEqual(auths.length, 1);
      assert.ok(auths[0].accessTo.includes('https://alice.example/other/'),
        `Expected accessTo to include 'https://alice.example/other/', got: ${auths[0].accessTo}`);
    });

    it('should keep absolute URLs unchanged', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@id': '#owner',
        '@type': 'acl:Authorization',
        'acl:agent': { '@id': 'https://alice.example/#me' },
        'acl:accessTo': { '@id': 'https://other.example/resource' },
        'acl:mode': [{ '@id': 'acl:Read' }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/folder/.acl');

      assert.strictEqual(auths.length, 1);
      assert.ok(auths[0].accessTo.includes('https://other.example/resource'),
        `Expected accessTo to include 'https://other.example/resource', got: ${auths[0].accessTo}`);
    });
  });

  describe('generateOwnerAcl', () => {
    it('should generate owner ACL with public read', () => {
      const acl = generateOwnerAcl('https://alice.example/', 'https://alice.example/#me', true);

      assert.ok(acl['@graph'].length >= 2);

      // Find owner auth
      const ownerAuth = acl['@graph'].find(a => a['@id'] === '#owner');
      assert.ok(ownerAuth);
      assert.strictEqual(ownerAuth['acl:agent']['@id'], 'https://alice.example/#me');

      // Find public auth
      const publicAuth = acl['@graph'].find(a => a['@id'] === '#public');
      assert.ok(publicAuth);
    });
  });
});

describe('WAC Checker', () => {
  describe('getRequiredMode', () => {
    it('should return READ for GET', () => {
      assert.strictEqual(getRequiredMode('GET'), AccessMode.READ);
    });

    it('should return READ for HEAD', () => {
      assert.strictEqual(getRequiredMode('HEAD'), AccessMode.READ);
    });

    it('should return APPEND for POST', () => {
      assert.strictEqual(getRequiredMode('POST'), AccessMode.APPEND);
    });

    it('should return WRITE for PUT', () => {
      assert.strictEqual(getRequiredMode('PUT'), AccessMode.WRITE);
    });

    it('should return WRITE for DELETE', () => {
      assert.strictEqual(getRequiredMode('DELETE'), AccessMode.WRITE);
    });
  });
});

describe('WAC Integration', () => {
  let baseUrl;

  before(async () => {
    const result = await startTestServer();
    baseUrl = result.baseUrl;
    await createTestPod('wactest');
  });

  after(async () => {
    await stopTestServer();
  });

  describe('ACL Files', () => {
    it('should create root .acl on pod creation', async () => {
      // ACL files require Control permission - must be authenticated as pod owner
      const res = await request('/wactest/.acl', { auth: 'wactest' });

      assertStatus(res, 200);
      const content = await res.json();
      assert.ok(content['@graph'], 'Should be JSON-LD');
    });

    it('should deny unauthenticated access to .acl files', async () => {
      // Security: ACL files must require authentication
      const res = await request('/wactest/.acl');
      assertStatus(res, 401);
    });

    it('should create private folder .acl', async () => {
      const res = await request('/wactest/private/.acl', { auth: 'wactest' });

      assertStatus(res, 200);
      const content = await res.json();
      assert.ok(content['@graph']);

      // Should only have owner, no public
      const hasPublic = content['@graph'].some(a =>
        a['acl:agentClass'] && a['acl:agentClass']['@id'] === 'foaf:Agent'
      );
      assert.ok(!hasPublic, 'Private folder should not have public access');
    });

    it('should create inbox .acl with public append', async () => {
      const res = await request('/wactest/inbox/.acl', { auth: 'wactest' });

      assertStatus(res, 200);
      const content = await res.json();

      // Should have public append
      const publicAuth = content['@graph'].find(a =>
        a['acl:agentClass'] && a['acl:agentClass']['@id'] === 'foaf:Agent'
      );
      assert.ok(publicAuth, 'Inbox should have public access');

      const modes = publicAuth['acl:mode'].map(m => m['@id']);
      assert.ok(modes.includes('acl:Append'), 'Public should have Append');
      assert.ok(!modes.includes('acl:Read'), 'Public should not have Read');
    });
  });

  describe('WAC-Allow Header', () => {
    it('should return WAC-Allow header for public container', async () => {
      const res = await request('/wactest/public/');

      assertHeader(res, 'WAC-Allow');
      const wacAllow = res.headers.get('WAC-Allow');
      assert.ok(wacAllow.includes('public='), 'Should have public permissions');
    });
  });
});
