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
import {
  parseAcl,
  AccessMode,
  generateOwnerAcl,
  generatePrivateAcl,
  generateInboxAcl,
  generatePublicFolderAcl,
  generatePublicReadAcl,
  serializeAcl,
  relativizeOwnerWebId
} from '../src/wac/parser.js';
import { checkAccess, getRequiredMode } from '../src/wac/checker.js';
import * as storage from '../src/storage/filesystem.js';
import { createLedger, setBalance, getBalance, LEDGER_PATH } from '../src/webledger.js';

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

    it('should resolve relative agent URIs against ACL URL', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@id': '#owner',
        '@type': 'acl:Authorization',
        'acl:agent': { '@id': './#me' },
        'acl:accessTo': { '@id': './' },
        'acl:mode': [{ '@id': 'acl:Read' }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/.acl');

      assert.strictEqual(auths.length, 1);
      assert.ok(auths[0].agents.includes('https://alice.example/#me'),
        `Expected agents to include 'https://alice.example/#me', got: ${auths[0].agents}`);
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

  // Phase 1 of #427 (#428): generators should preserve relative resourceUrls
  // verbatim so callers can emit host-portable ACLs. The parser already
  // resolves them at check time against the .acl's URL.
  describe('relative resourceUrl portability (#428)', () => {
    const webId = 'https://alice.example/profile/card.jsonld#me';

    it('generateOwnerAcl preserves "./" in accessTo and default', () => {
      const acl = generateOwnerAcl('./', webId, true);
      const owner = acl['@graph'].find(a => a['@id'] === '#owner');
      const pub = acl['@graph'].find(a => a['@id'] === '#public');
      assert.strictEqual(owner['acl:accessTo']['@id'], './');
      assert.strictEqual(owner['acl:default']['@id'], './');
      assert.strictEqual(pub['acl:accessTo']['@id'], './');
      // #public intentionally has no default — child resources require auth
      assert.strictEqual(pub['acl:default'], undefined);
    });

    it('generatePrivateAcl preserves "./"', () => {
      const acl = generatePrivateAcl('./', webId);
      const owner = acl['@graph'][0];
      assert.strictEqual(owner['acl:accessTo']['@id'], './');
      assert.strictEqual(owner['acl:default']['@id'], './');
    });

    it('generateInboxAcl preserves "./"', () => {
      const acl = generateInboxAcl('./', webId);
      for (const auth of acl['@graph']) {
        assert.strictEqual(auth['acl:accessTo']['@id'], './');
        assert.strictEqual(auth['acl:default']['@id'], './');
      }
    });

    it('generatePublicFolderAcl preserves "./"', () => {
      const acl = generatePublicFolderAcl('./', webId);
      for (const auth of acl['@graph']) {
        assert.strictEqual(auth['acl:accessTo']['@id'], './');
        assert.strictEqual(auth['acl:default']['@id'], './');
      }
    });

    it('generatePublicReadAcl preserves a relative resource basename', () => {
      const acl = generatePublicReadAcl('./publicTypeIndex.jsonld');
      assert.strictEqual(
        acl['@graph'][0]['acl:accessTo']['@id'],
        './publicTypeIndex.jsonld'
      );
    });

    // Phase 2 of #427 (#430): generators should also preserve a relative
    // ownerWebId verbatim, so the on-disk pod is host-portable for the
    // owner half of the rule too. The parser already resolves relative
    // agents (PR #65 / #64) — this just exercises the writer side.
    it('generateOwnerAcl preserves a relative ownerWebId (#430)', () => {
      const acl = generateOwnerAcl('./', './profile/card.jsonld#me', true);
      const owner = acl['@graph'].find(a => a['@id'] === '#owner');
      assert.strictEqual(owner['acl:agent']['@id'], './profile/card.jsonld#me');
    });

    it('generatePrivateAcl preserves a relative ownerWebId (#430)', () => {
      const acl = generatePrivateAcl('./', '../profile/card.jsonld#me');
      assert.strictEqual(acl['@graph'][0]['acl:agent']['@id'], '../profile/card.jsonld#me');
    });

    it('generateInboxAcl preserves a relative ownerWebId (#430)', () => {
      const acl = generateInboxAcl('./', '../profile/card.jsonld#me');
      const owner = acl['@graph'].find(a => a['@id'] === '#owner');
      assert.strictEqual(owner['acl:agent']['@id'], '../profile/card.jsonld#me');
    });

    it('generatePublicFolderAcl preserves a relative ownerWebId (#430)', () => {
      const acl = generatePublicFolderAcl('./', './card.jsonld#me');
      const owner = acl['@graph'].find(a => a['@id'] === '#owner');
      assert.strictEqual(owner['acl:agent']['@id'], './card.jsonld#me');
    });

    it('round-trip: relative ownerWebId resolves to .acl base URL on parse (#430)', async () => {
      // Same ACL document, two hosts — agent should resolve to whichever
      // host asked, just like accessTo. This is what makes the on-disk
      // pod portable for the owner half.
      const generated = generateOwnerAcl('./', './profile/card.jsonld#me', true);
      const wire = serializeAcl(generated);
      const auths1 = await parseAcl(wire, 'http://localhost:4444/.acl');
      const auths2 = await parseAcl(wire, 'http://0.0.0.0:4444/.acl');
      const owner1 = auths1.find(a => a.id === '#owner');
      const owner2 = auths2.find(a => a.id === '#owner');
      assert.ok(owner1.agents.includes('http://localhost:4444/profile/card.jsonld#me'),
        `Expected localhost agent, got: ${JSON.stringify(owner1.agents)}`);
      assert.ok(owner2.agents.includes('http://0.0.0.0:4444/profile/card.jsonld#me'),
        `Expected 0.0.0.0 agent, got: ${JSON.stringify(owner2.agents)}`);
    });

    // The relativizeOwnerWebId helper drives the Phase 2 callers. Cover
    // the layouts Copilot asked about so callers don't need to hardcode.
    describe('relativizeOwnerWebId helper', () => {
      const podUri = 'http://h/alice/';

      it('emits "./<tail>" from the pod root', () => {
        assert.strictEqual(
          relativizeOwnerWebId(`${podUri}profile/card.jsonld#me`, podUri, ''),
          './profile/card.jsonld#me'
        );
      });

      it('emits "../<tail>" from an immediate child folder', () => {
        assert.strictEqual(
          relativizeOwnerWebId(`${podUri}profile/card.jsonld#me`, podUri, 'private/'),
          '../profile/card.jsonld#me'
        );
      });

      it('handles legacy /profile/card#me layout', () => {
        // Pre-#282 pods used extensionless `profile/card`. The helper just
        // slices the tail, so any layout works.
        assert.strictEqual(
          relativizeOwnerWebId(`${podUri}profile/card#me`, podUri, ''),
          './profile/card#me'
        );
        assert.strictEqual(
          relativizeOwnerWebId(`${podUri}profile/card#me`, podUri, 'private/'),
          '../profile/card#me'
        );
      });

      it('handles a custom (non-profile/) WebID shape', () => {
        assert.strictEqual(
          relativizeOwnerWebId(`${podUri}me#me`, podUri, ''),
          './me#me'
        );
        assert.strictEqual(
          relativizeOwnerWebId(`${podUri}me#me`, podUri, 'public/'),
          '../me#me'
        );
      });

      it('returns the absolute WebID unchanged for foreign owners', () => {
        const foreign = 'https://other.example/profile/card.jsonld#me';
        assert.strictEqual(
          relativizeOwnerWebId(foreign, podUri, ''),
          foreign
        );
        assert.strictEqual(
          relativizeOwnerWebId(foreign, podUri, 'private/'),
          foreign
        );
      });

      it('round-trips through the parser back to the absolute WebID', async () => {
        // Helper output is correct iff parsing it under the same pod URI
        // yields the original absolute WebID. Covers both modern and
        // legacy layouts, from root and from a child folder.
        const cases = [
          { web: `${podUri}profile/card.jsonld#me`, base: '',         acl: `${podUri}.acl` },
          { web: `${podUri}profile/card.jsonld#me`, base: 'private/', acl: `${podUri}private/.acl` },
          { web: `${podUri}profile/card#me`,        base: '',         acl: `${podUri}.acl` },
          { web: `${podUri}profile/card#me`,        base: 'private/', acl: `${podUri}private/.acl` },
          { web: `${podUri}me#me`,                  base: 'public/',  acl: `${podUri}public/.acl` }
        ];
        for (const { web, base, acl } of cases) {
          const rel = relativizeOwnerWebId(web, podUri, base);
          const generated = generateOwnerAcl('./', rel, true);
          const wire = serializeAcl(generated);
          const auths = await parseAcl(wire, acl);
          const owner = auths.find(a => a.id === '#owner');
          assert.ok(
            owner.agents.includes(web),
            `Round-trip failed for ${web} from ${base}: relative=${rel}, resolved=${JSON.stringify(owner.agents)}`
          );
        }
      });
    });

    it('round-trip: relative ownerWebId from a child folder resolves correctly (#430)', async () => {
      // /pod/private/.acl with agent '../profile/card.jsonld#me'
      // should resolve to /pod/profile/card.jsonld#me, not into the
      // pod root or escape it.
      const generated = generatePrivateAcl('./', '../profile/card.jsonld#me');
      const wire = serializeAcl(generated);
      const auths = await parseAcl(wire, 'http://localhost:4444/alice/private/.acl');
      const owner = auths.find(a => a.id === '#owner');
      assert.ok(owner.agents.includes('http://localhost:4444/alice/profile/card.jsonld#me'),
        `Expected resolution to /alice/profile/card.jsonld#me, got: ${JSON.stringify(owner.agents)}`);
    });

    it('round-trip: relative "./" resolves to the .acl base URL on parse', async () => {
      const generated = generateOwnerAcl('./', webId, true);
      const wire = serializeAcl(generated);

      // Parse the same .acl document under two different host URLs and
      // assert accessTo resolves to whichever host asked. This is what
      // makes the on-disk pod portable across interfaces.
      const auths1 = await parseAcl(wire, 'http://localhost:4444/.acl');
      const auths2 = await parseAcl(wire, 'http://0.0.0.0:4444/.acl');

      const pub1 = auths1.find(a => a.agentClasses.includes('foaf:Agent'));
      const pub2 = auths2.find(a => a.agentClasses.includes('foaf:Agent'));
      assert.ok(pub1.accessTo.includes('http://localhost:4444/'),
        `Expected localhost resolution, got: ${JSON.stringify(pub1.accessTo)}`);
      assert.ok(pub2.accessTo.includes('http://0.0.0.0:4444/'),
        `Expected 0.0.0.0 resolution, got: ${JSON.stringify(pub2.accessTo)}`);
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

  describe('Cross-host ACL portability (#428)', () => {
    // The .acl is written with a relative `./` so the public-read rule
    // matches whichever host the request comes in on. Before #428, the
    // .acl baked the bind-time host into accessTo and any other host
    // returned 401. We exercise this by varying the Host: header.
    it('serves public-read resources regardless of Host header', async () => {
      // Profile is public-read by default (#427 Phase 1).
      const baseHost = new URL(getBaseUrl()).host;
      const profileUrl = `${getBaseUrl()}/wactest/profile/`;
      const hostsToTry = [baseHost, 'localhost:9999', 'pod.example:443', 'pod.invalid'];

      for (const host of hostsToTry) {
        const res = await fetch(profileUrl, { headers: { Host: host } });
        assert.strictEqual(
          res.status, 200,
          `Public-read should succeed for Host: ${host} (got ${res.status})`
        );
      }
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

describe('WAC Conditions', () => {
  describe('parseAcl with conditions', () => {
    it('should parse a PaymentCondition', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@graph': [{
          '@id': '#paid',
          '@type': 'acl:Authorization',
          'acl:agentClass': { '@id': 'acl:AuthenticatedAgent' },
          'acl:accessTo': { '@id': 'https://alice.example/premium/article.jsonld' },
          'acl:mode': [{ '@id': 'acl:Read' }],
          'acl:condition': {
            '@type': 'PaymentCondition',
            'amount': '1000',
            'currency': 'sats'
          }
        }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/premium/.acl');

      assert.strictEqual(auths.length, 1);
      assert.strictEqual(auths[0].conditions.length, 1);
      assert.strictEqual(auths[0].conditions[0].type, 'PaymentCondition');
      assert.strictEqual(auths[0].conditions[0].amount, '1000');
      assert.strictEqual(auths[0].conditions[0].currency, 'sats');
    });

    it('should parse multiple conditions', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@graph': [{
          '@id': '#restricted',
          '@type': 'acl:Authorization',
          'acl:agent': { '@id': 'https://bob.example/#me' },
          'acl:accessTo': { '@id': 'https://alice.example/resource' },
          'acl:mode': [{ '@id': 'acl:Read' }],
          'acl:condition': [
            { '@type': 'PaymentCondition', 'amount': '500', 'currency': 'sats' },
            { '@type': 'ClientCondition', 'client': 'https://trusted.app/pane.js' }
          ]
        }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/.acl');

      assert.strictEqual(auths[0].conditions.length, 2);
      assert.strictEqual(auths[0].conditions[0].type, 'PaymentCondition');
      assert.strictEqual(auths[0].conditions[1].type, 'ClientCondition');
    });

    it('should parse authorization without conditions', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@graph': [{
          '@id': '#public',
          '@type': 'acl:Authorization',
          'acl:agentClass': { '@id': 'http://xmlns.com/foaf/0.1/Agent' },
          'acl:accessTo': { '@id': 'https://alice.example/public/' },
          'acl:mode': [{ '@id': 'acl:Read' }]
        }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/.acl');

      assert.strictEqual(auths[0].conditions.length, 0);
    });
  });

  describe('fail-closed conditions', () => {
    it('should parse unsupported condition types', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@graph': [{
          '@id': '#restricted',
          '@type': 'acl:Authorization',
          'acl:agent': { '@id': 'https://bob.example/#me' },
          'acl:accessTo': { '@id': 'https://alice.example/resource' },
          'acl:mode': [{ '@id': 'acl:Read' }],
          'acl:condition': {
            '@type': 'UnknownFutureCondition',
            'foo': 'bar'
          }
        }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/.acl');

      assert.strictEqual(auths[0].conditions.length, 1);
      assert.strictEqual(auths[0].conditions[0].type, 'UnknownFutureCondition');
    });

    it('should parse zero-cost PaymentCondition', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@graph': [{
          '@id': '#gate',
          '@type': 'acl:Authorization',
          'acl:agentClass': { '@id': 'acl:AuthenticatedAgent' },
          'acl:accessTo': { '@id': 'https://alice.example/members/' },
          'acl:mode': [{ '@id': 'acl:Read' }],
          'acl:condition': {
            '@type': 'PaymentCondition',
            'amount': '0',
            'currency': 'sats'
          }
        }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/members/.acl');
      const condition = auths[0].conditions[0];

      assert.strictEqual(condition.type, 'PaymentCondition');
      assert.strictEqual(condition.amount, '0');
    });

    it('should parse PaymentCondition with all fields', async () => {
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@graph': [{
          '@id': '#paid',
          '@type': 'acl:Authorization',
          'acl:agentClass': { '@id': 'acl:AuthenticatedAgent' },
          'acl:accessTo': { '@id': 'https://alice.example/premium/article.jsonld' },
          'acl:mode': [{ '@id': 'acl:Read' }],
          'acl:condition': {
            '@type': 'PaymentCondition',
            'amount': '1000',
            'currency': 'sats',
            'protocol': 'lightning'
          }
        }]
      };

      const auths = await parseAcl(JSON.stringify(acl), 'https://alice.example/premium/.acl');
      const condition = auths[0].conditions[0];

      assert.strictEqual(condition.type, 'PaymentCondition');
      assert.strictEqual(condition.amount, '1000');
      assert.strictEqual(condition.currency, 'sats');
      assert.strictEqual(condition.protocol, 'lightning');
    });
  });
});

describe('WAC PaymentCondition noDebit (secondary/guard checks must not charge)', () => {
  let baseUrl;
  const AGENT = 'https://payer.example/profile/card#me';
  const COST = 5;
  const RESOURCE_PATH = '/paygate/resource';

  before(async () => {
    const result = await startTestServer();
    baseUrl = result.baseUrl;
  });

  after(async () => {
    await stopTestServer();
  });

  // Seed a ledger balance for AGENT and an ACL granting AGENT Control on the
  // protected resource, gated behind a positive-cost PaymentCondition.
  async function seed(balance) {
    const ledger = createLedger();
    setBalance(ledger, AGENT, balance, 'sat');
    await storage.write(LEDGER_PATH, Buffer.from(JSON.stringify(ledger)));

    const resourceUrl = `${baseUrl}${RESOURCE_PATH}`;
    const acl = {
      '@context': { acl: 'http://www.w3.org/ns/auth/acl#' },
      '@graph': [{
        '@id': '#paid',
        '@type': 'acl:Authorization',
        'acl:agent': { '@id': AGENT },
        'acl:accessTo': { '@id': resourceUrl },
        'acl:mode': [{ '@id': 'acl:Control' }],
        'acl:condition': { '@type': 'PaymentCondition', amount: String(COST), currency: 'sat' }
      }]
    };
    await storage.write(`${RESOURCE_PATH}.acl`, Buffer.from(JSON.stringify(acl)));
    return resourceUrl;
  }

  async function balanceNow() {
    const raw = await storage.read(LEDGER_PATH);
    return getBalance(JSON.parse(raw.toString()), AGENT, 'sat');
  }

  it('debits the ledger on a normal (primary) Control check', async () => {
    const resourceUrl = await seed(100);
    const res = await checkAccess({
      resourceUrl,
      resourcePath: RESOURCE_PATH,
      isContainer: false,
      agentWebId: AGENT,
      requiredMode: AccessMode.CONTROL
    });
    assert.strictEqual(res.allowed, true);
    assert.strictEqual(res.paid, COST);
    assert.strictEqual(await balanceNow(), 100 - COST, 'primary check should debit');
  });

  it('does NOT debit when noDebit is set (guard/secondary check)', async () => {
    const resourceUrl = await seed(100);
    const res = await checkAccess({
      resourceUrl,
      resourcePath: RESOURCE_PATH,
      isContainer: false,
      agentWebId: AGENT,
      requiredMode: AccessMode.CONTROL,
      noDebit: true
    });
    assert.strictEqual(res.allowed, false, 'paid grant is not satisfied without charging');
    assert.ok(res.paymentRequired, 'should surface paymentRequired instead of debiting');
    assert.strictEqual(await balanceNow(), 100, 'balance must be unchanged');
  });
});
