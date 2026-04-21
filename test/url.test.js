/**
 * Unit tests for src/utils/url.js
 *
 * Focus: getPodName() resolution across the four supported deployment modes.
 * Regression guard for #278 (single-user root-pod PUT → ENOTDIR).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { getPodName } from '../src/utils/url.js';

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
