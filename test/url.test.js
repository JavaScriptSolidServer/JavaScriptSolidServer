/**
 * Unit tests for src/utils/url.js
 *
 * Focus: getPodName() resolution across the four supported deployment modes.
 * Regression guard for #278 (single-user root-pod PUT → ENOTDIR).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import { getPodName, getContentType, urlToPath, urlToPathWithPod } from '../src/utils/url.js';

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
      // .zzz is not in the mime-types db (unlike .xyz → chemical/x-xyz)
      assert.strictEqual(getContentType('/x/file.zzz'), 'application/octet-stream');
    });
  });

  describe('media types via mime-types db (#533)', () => {
    it('maps .mp3 → audio/mpeg (was octet-stream → forced download)', () => {
      assert.strictEqual(getContentType('/music/song.mp3'), 'audio/mpeg');
    });
    it('maps common audio extensions to audio/*', () => {
      for (const f of ['a.ogg', 'a.wav', 'a.m4a', 'a.flac', 'a.opus', 'a.aac']) {
        assert.ok(getContentType(f).startsWith('audio/'), f + ' should be audio/*, got ' + getContentType(f));
      }
    });
    it('maps video and other common types', () => {
      assert.strictEqual(getContentType('v.mp4'), 'video/mp4');
      assert.strictEqual(getContentType('d.pdf'), 'application/pdf');
    });
    it('keeps Solid overrides ahead of the mime-types db', () => {
      assert.strictEqual(getContentType('card.ttl'), 'text/turtle');
      assert.strictEqual(getContentType('x.jsonld'), 'application/ld+json');
      assert.strictEqual(getContentType('p.m3u'), 'audio/mpegurl');
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

describe('urlToPath / urlToPathWithPod (#131 — leading-slash normalization)', () => {
  // Bot probes hammer JSS with `//foo`, `///wp-admin/...`, etc. Without
  // multi-slash stripping these used to escape dataRoot via path.resolve
  // (which treats `/foo` as absolute) and 500 with "Path traversal detected"
  // instead of the expected 404.

  // Save/restore DATA_ROOT — other test suites mutate process.env.DATA_ROOT
  // (via createServer's root option) and don't always restore it. Pinning
  // to './data' keeps the assertions stable across run order.
  let originalDataRoot;
  before(() => {
    originalDataRoot = process.env.DATA_ROOT;
    delete process.env.DATA_ROOT;  // forces getDataRoot() default of './data'
  });
  after(() => {
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
  });

  const dataRoot = path.resolve('./data');

  describe('urlToPath', () => {
    it('resolves a normal path inside dataRoot', () => {
      assert.strictEqual(urlToPath('/alice/profile/card'), path.join(dataRoot, 'alice/profile/card'));
    });

    it('handles double leading slash without throwing (#131)', () => {
      assert.strictEqual(urlToPath('//about.php'), path.join(dataRoot, 'about.php'));
    });

    it('handles many leading slashes (#131)', () => {
      assert.strictEqual(urlToPath('////wp-admin/index.php'), path.join(dataRoot, 'wp-admin/index.php'));
    });

    it('still rejects real `..` traversal that escapes after normalization', () => {
      // Security must be preserved: `/../etc/passwd` → strip leading slash →
      // `../etc/passwd` → strip `..` → `/etc/passwd` (absolute residue) →
      // path.resolve escapes dataRoot → guard fires.
      assert.throws(() => urlToPath('/../etc/passwd'), /Path traversal/);
    });
  });

  describe('urlToPathWithPod', () => {
    it('resolves into the pod dir', () => {
      assert.strictEqual(urlToPathWithPod('/profile/card', 'alice'), path.join(dataRoot, 'alice/profile/card'));
    });

    it('handles double leading slash (#131)', () => {
      assert.strictEqual(urlToPathWithPod('//about.php', 'alice'), path.join(dataRoot, 'alice/about.php'));
    });
  });
});
