/**
 * Unit tests for src/utils/url.js
 *
 * Focus: getPodName() resolution across the four supported deployment modes.
 * Regression guard for #278 (single-user root-pod PUT → ENOTDIR).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { getPodName, getContentType } from '../src/utils/url.js';

describe('getPodName', () => {
  describe('subdomain mode', () => {
    it('returns request.podName when the subdomain is recognized', () => {
      const req = { subdomainsEnabled: true, podName: 'alice', url: '/profile/card' };
      assert.strictEqual(getPodName(req), 'alice');
    });

    it('returns null on base-domain access (no recognized subdomain)', () => {
      const req = { subdomainsEnabled: true, podName: null, url: '/anything' };
      assert.strictEqual(getPodName(req), null);
    });
  });

  describe('single-user mode', () => {
    it("returns '.' for a root pod (singleUserName empty)", () => {
      const req = { singleUser: true, singleUserName: '', url: '/index.html' };
      assert.strictEqual(getPodName(req), '.');
    });

    it("returns '.' for a root pod (singleUserName '/')", () => {
      const req = { singleUser: true, singleUserName: '/', url: '/index.html' };
      assert.strictEqual(getPodName(req), '.');
    });

    it("returns '.' for a root pod (singleUserName null — #348 default)", () => {
      // server.js normalizes '/' and '' to null at the top of
      // createServer, so most root-pod requests now reach getPodName
      // with singleUserName === null. Pin that path explicitly.
      const req = { singleUser: true, singleUserName: null, url: '/index.html' };
      assert.strictEqual(getPodName(req), '.');
    });

    it('returns singleUserName for a named pod, regardless of URL', () => {
      const req = { singleUser: true, singleUserName: 'me', url: '/index.html' };
      assert.strictEqual(getPodName(req), 'me');
    });

    it('does not mistake a URL segment for a pod in single-user mode', () => {
      // Regression for #278: PUT /index.html previously produced pod
      // "index.html", making the quota sidecar path <dataRoot>/index.html/.quota.json.
      const req = { singleUser: true, singleUserName: '', url: '/index.html' };
      assert.notStrictEqual(getPodName(req), 'index.html');
    });
  });

  describe('path-based multi-pod (default)', () => {
    it('returns the first URL segment as the pod name', () => {
      const req = { url: '/alice/profile/card' };
      assert.strictEqual(getPodName(req), 'alice');
    });

    it('returns null for requests at /', () => {
      const req = { url: '/' };
      assert.strictEqual(getPodName(req), null);
    });

    it('skips system paths beginning with a dot', () => {
      const req = { url: '/.well-known/openid-configuration' };
      assert.strictEqual(getPodName(req), null);
    });
  });

  describe('string-form input', () => {
    it('extracts pod name from a URL path string', () => {
      assert.strictEqual(getPodName('/alice/foo'), 'alice');
    });

    it('returns null for the root path', () => {
      assert.strictEqual(getPodName('/'), null);
    });
  });
});

// Regression coverage for #294 — .acl and .meta must be recognised as RDF
// resources so content negotiation kicks in for Turtle-native clients.
describe('getContentType', () => {
  describe('extension-based mapping (existing)', () => {
    it('maps .jsonld → application/ld+json', () => {
      assert.strictEqual(getContentType('/x/card.jsonld'), 'application/ld+json');
    });
    it('maps .ttl → text/turtle', () => {
      assert.strictEqual(getContentType('/x/card.ttl'), 'text/turtle');
    });
    it('falls back to application/octet-stream for unknown extensions', () => {
      assert.strictEqual(getContentType('/x/file.xyz'), 'application/octet-stream');
    });
  });

  describe('Solid convention dotfiles (#294)', () => {
    it('treats .acl as application/ld+json (the format JSS writes it in)', () => {
      assert.strictEqual(getContentType('/alice/public/.acl'), 'application/ld+json');
      assert.strictEqual(getContentType('.acl'), 'application/ld+json');
    });

    it('treats .meta as application/ld+json', () => {
      assert.strictEqual(getContentType('/alice/public/.meta'), 'application/ld+json');
      assert.strictEqual(getContentType('.meta'), 'application/ld+json');
    });

    it('does not mistake non-dotfile paths containing .acl for ACL files', () => {
      // A regular file that happens to have "acl" in its name/path stays
      // classified by extension, not by coincidence.
      assert.strictEqual(getContentType('/alice/notes/my-acl-plan.md'), 'text/markdown');
    });
  });

  describe('.acl / .meta as extensions (#297)', () => {
    it('treats *.acl (extension) as application/ld+json', () => {
      assert.strictEqual(getContentType('/settings/publicTypeIndex.jsonld.acl'), 'application/ld+json');
      assert.strictEqual(getContentType('/alice/private/secret.json.acl'), 'application/ld+json');
    });

    it('treats *.meta (extension) as application/ld+json', () => {
      assert.strictEqual(getContentType('/alice/resource.meta'), 'application/ld+json');
    });
  });
});
